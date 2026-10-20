// Package ci is consumer #1 of the sandbox pool: it runs a pipeline of steps,
// each inside its own governed cell, with release-class steps held for a human
// approval (fail-closed). It is the "turn a machine into a CI runner" piece -
// the runner is the pool, each job is a cell, and the release step is the
// held, approved action. The RunRecord it emits is the signed-ish execution
// record the operator's Releases page reads.
package ci

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/interposed/interpose-sandbox/pkg/cell"
	"github.com/interposed/interpose-sandbox/pkg/pool"
	"github.com/interposed/interpose-sandbox/pkg/procbox"
)

const maxCapturedOutput = 8 << 10 // 8 KiB of stdout/stderr kept per step in the record

// Step is one pipeline step.
type Step struct {
	Name    string   `json:"name"`
	Run     []string `json:"run"`               // argv; Run[0] resolved via PATH inside the cell
	Release bool     `json:"release,omitempty"` // release-class: held for approval before it runs
}

// Pipeline is an ordered list of steps run in one repo workdir.
type Pipeline struct {
	Name     string   `json:"name"`
	Workdir  string   `json:"workdir"`            // repo checkout dir; the cell's RW root
	Runtimes []string `json:"runtimes,omitempty"` // procbox runtime groups (node/python/go/rust)
	Net      string   `json:"net,omitempty"`      // off (default) | all | tcp
	Steps    []Step   `json:"steps"`
}

// Meta binds a run to its source so a release approval can't be replayed.
type Meta struct {
	RunID  string `json:"run_id"`
	Commit string `json:"commit,omitempty"`
	Digest string `json:"digest,omitempty"`
	// Repo is the source repository the run builds (GITHUB_REPOSITORY, "owner/name"); used to
	// resolve repo-scoped supply-chain pins. Empty outside a forge.
	Repo string `json:"-"`
	// Env is the curated environment every step's cell receives (non-secret CI context
	// only). Set by the caller via CuratedEnv; it does NOT come from the pipeline JSON,
	// and cells never inherit the process environment - so a mapped secret or a runner
	// token in interpose-ci's env cannot leak into a governed step.
	Env []string `json:"-"`
	// Stream, when set, ALSO writes each step's output to it live (e.g. os.Stdout, so it
	// appears in the forge's job log). Default nil = sovereign: step output is captured
	// into the run record only, read in the operator, never streamed to the forge.
	Stream io.Writer `json:"-"`
	// RunURL is the forge's job/run URL (e.g. the GitHub Actions run), so the operator can
	// link straight to it. Built by the caller from the CI env; empty when not in a forge.
	RunURL string `json:"-"`
	// CacheDir is a persistent, host-managed root where each runtime's package/build cache
	// is kept, OUTSIDE the ephemeral workspace. Set by the caller (interpose-ci, from
	// INTERPOSE_CI_DIR). Empty = caches stay under the workspace (the pre-fix behavior that
	// corrupts the next checkout via Go's read-only module cache). See cacheRedirect.
	CacheDir string `json:"-"`
}

// CuratedEnv returns the ALLOW-LISTED, non-secret CI context to hand to cells, filtered
// from the process environment. This is the ONLY CI context that crosses into a governed
// step. Anything not on the allow-list - mapped secrets, GITHUB_TOKEN, ACTIONS_* runtime
// tokens, registration tokens, arbitrary vars - is dropped. Deny-by-default for env, the
// same stance the cell takes for filesystem and network.
func CuratedEnv(parent []string) []string {
	allow := map[string]bool{
		"CI":                      true,
		"GITHUB_SHA":              true,
		"GITHUB_REF":              true,
		"GITHUB_REF_NAME":         true,
		"GITHUB_REF_TYPE":         true,
		"GITHUB_REPOSITORY":       true,
		"GITHUB_REPOSITORY_OWNER": true,
		"GITHUB_RUN_ID":           true,
		"GITHUB_RUN_NUMBER":       true,
		"GITHUB_RUN_ATTEMPT":      true,
		"GITHUB_WORKFLOW":         true,
		"GITHUB_JOB":              true,
		"GITHUB_ACTION":           true,
		"GITHUB_ACTOR":            true,
		"GITHUB_EVENT_NAME":       true,
		"GITHUB_SERVER_URL":       true,
		"GITHUB_API_URL":          true,
		"GITHUB_GRAPHQL_URL":      true,
		"RUNNER_OS":               true,
		"RUNNER_ARCH":             true,
		"RUNNER_NAME":             true,
	}
	var out []string
	for _, e := range parent {
		if k, _, ok := strings.Cut(e, "="); ok && allow[k] {
			out = append(out, e)
		}
	}
	return out
}

// Decision is an approval outcome.
type Decision string

const (
	Approved Decision = "approved"
	Denied   Decision = "denied"
)

// ReleaseRequest is what an Approver is asked to decide, bound to the run. The
// json tags must match the operator's PendingReleaseDTO so a pending-release
// file written here is read correctly on the Releases page.
type ReleaseRequest struct {
	Pipeline string `json:"pipeline"`
	Step     string `json:"step"`
	RunID    string `json:"run_id"`
	Commit   string `json:"commit,omitempty"`
	Digest   string `json:"digest,omitempty"`
}

// Approver decides whether a release-class step may run. In production this is
// the operator approval ceremony over the factor model; here we ship two
// trivial ones for dev/tests.
type Approver interface {
	Approve(ctx context.Context, req ReleaseRequest) (Decision, error)
}

// AutoApprove approves every release (dev only).
type AutoApprove struct{}

func (AutoApprove) Approve(context.Context, ReleaseRequest) (Decision, error) { return Approved, nil }

// DenyAll denies every release (proves fail-closed).
type DenyAll struct{}

func (DenyAll) Approve(context.Context, ReleaseRequest) (Decision, error) { return Denied, nil }

// StepResult records what happened to one step.
type StepResult struct {
	Name       string    `json:"name"`
	Release    bool      `json:"release,omitempty"`
	Held       bool      `json:"held,omitempty"`     // release step that went through approval
	Decision   Decision  `json:"decision,omitempty"` // approval outcome for a release step
	ExitCode   int       `json:"exit_code"`
	Skipped    bool      `json:"skipped,omitempty"`
	SkipReason string    `json:"skip_reason,omitempty"`
	Output     string    `json:"output,omitempty"` // captured stdout+stderr (truncated)
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
}

// RunRecord is the execution record for one pipeline run. It is what the
// operator Releases page lists and what a later signer would attest.
type RunRecord struct {
	RunID    string       `json:"run_id"`
	Pipeline string       `json:"pipeline"`
	Commit   string       `json:"commit,omitempty"`
	Digest   string       `json:"digest,omitempty"`
	Repo     string       `json:"repo,omitempty"`    // source repository (owner/name): per-repo pins + display
	RunURL   string       `json:"run_url,omitempty"` // forge job/run URL (link out from the operator)
	OK       bool         `json:"ok"`
	Started  time.Time    `json:"started"`
	Finished time.Time    `json:"finished"`
	Steps    []StepResult `json:"steps"`
	// SupplyChain is the observe-mode dependency record for the run (the depsec add-on):
	// the modules this run pulled, cross-checked against the lockfile. nil when the runner
	// policy does not enable it. Observe only - it never affects OK. See supplychain.go.
	SupplyChain *SupplyChain `json:"supply_chain,omitempty"`
}

// Run executes the pipeline. Steps run in order; the pipeline stops at the
// first failing step or denied release (fail-closed). A nil error means the
// run completed its bookkeeping - inspect RunRecord.OK for success.
func Run(ctx context.Context, p Pipeline, pl *pool.Pool, appr Approver, meta Meta) (RunRecord, error) {
	if meta.RunID == "" {
		meta.RunID = fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	if appr == nil {
		appr = DenyAll{} // safe default: no approver means no releases
	}
	rec := RunRecord{
		RunID:    meta.RunID,
		Pipeline: p.Name,
		Commit:   meta.Commit,
		Digest:   meta.Digest,
		Repo:     meta.Repo,
		RunURL:   meta.RunURL,
		Started:  time.Now(),
		OK:       true,
	}

	// Redirect runtime caches out of the ephemeral workspace once per run; the
	// resulting RW dirs and env apply uniformly to every step's cell.
	cacheRW, cacheEnv := cacheRedirect(meta.CacheDir, p.Runtimes)
	stepRW := append([]string{p.Workdir}, cacheRW...)
	stepEnv := append(append([]string{}, meta.Env...), cacheEnv...)

	for _, step := range p.Steps {
		sr := StepResult{Name: step.Name, Release: step.Release, Started: time.Now()}

		if step.Release {
			sr.Held = true
			dec, err := appr.Approve(ctx, ReleaseRequest{
				Pipeline: p.Name, Step: step.Name, RunID: meta.RunID, Commit: meta.Commit, Digest: meta.Digest,
			})
			if err != nil {
				dec = Denied
			}
			sr.Decision = dec
			if dec != Approved {
				sr.Skipped = true
				sr.SkipReason = "release denied (fail-closed)"
				sr.Finished = time.Now()
				rec.Steps = append(rec.Steps, sr)
				rec.OK = false
				break // fail closed: stop the pipeline
			}
		}

		var buf bytes.Buffer
		var stepOut io.Writer = &buf
		if meta.Stream != nil {
			fmt.Fprintf(meta.Stream, "\n== %s ==\n", step.Name)
			stepOut = io.MultiWriter(&buf, meta.Stream) // record AND live stream
		}
		spec := cell.Spec{
			ID:      meta.RunID + "-" + sanitize(step.Name),
			Cmd:     step.Run,
			Workdir: p.Workdir,
			Env:     stepEnv, // curated CI context + cache redirect; the cell adds PATH/HOME/TMPDIR
			Policy:  cell.Policy(stepRW, nil, p.Runtimes, netMode(p.Net)),
			Stdout:  stepOut,
			Stderr:  stepOut,
		}
		res, err := pl.Run(ctx, spec)
		sr.ExitCode = res.ExitCode
		sr.Output = truncate(buf.String(), maxCapturedOutput)
		sr.Finished = time.Now()
		rec.Steps = append(rec.Steps, sr)

		if err != nil || res.ExitCode != 0 {
			rec.OK = false
			break // fail the pipeline at the first failing step
		}
	}

	rec.Finished = time.Now()
	return rec, nil
}

func netMode(s string) procbox.NetMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "all":
		return procbox.NetAll
	case "tcp":
		return procbox.NetTCP
	default:
		return procbox.NetOff
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...[truncated]"
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "step"
	}
	return b.String()
}
