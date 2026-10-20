package ci

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// RunnerPolicy is the machine-level governance the operator writes onto a CI runner. It
// OVERRIDES what a repo's workflow asks for, so a repo author cannot opt out of governance:
// the workflow's interpose-ci flags are a request, this policy is the ceiling.
//
// It is read from a root-owned file on the runner (DefaultRunnerPolicyPath). A workflow
// step runs on the host before interpose-ci, so true non-bypassability also needs the
// runner to run as a NON-root user (so it cannot rewrite the policy file) - that is layer 2
// of the enforcement model (see docs/releases/release-integrations-plan.md section 10b).
// This type is layer 1: the override mechanism itself.
type RunnerPolicy struct {
	// Approve, when set, FORCES the release-approval mode regardless of --approve. Use
	// "file" to force the held-for-operator-approval path (so a workflow can't set
	// "auto" and skip the human gate) or "deny" to force fail-closed. Empty = no override.
	Approve string `json:"approve,omitempty"`
	// Stream, when non-nil, FORCES step-output streaming on/off regardless of --stream.
	// false keeps runs sovereign (logs in the record/operator, never the forge log).
	Stream *bool `json:"stream,omitempty"`
	// MaxTimeout caps the release-approval wait (--timeout), e.g. "30m". Empty = no cap.
	MaxTimeout string `json:"max_timeout,omitempty"`
	// SupplyChain makes interpose-ci attach a dependency supply-chain record to the run (the
	// module@version set it pulled, cross-checked against the lockfile, plus an osv-scanner pass).
	// "observe" records only; "enforce" additionally fails the run BEFORE the build when a pinned
	// module is fetched at an unapproved digest (see Pins). Empty = off. Gated on the depsec
	// add-on: the daemon writes this only when the org is entitled.
	SupplyChain string `json:"supply_chain,omitempty"` // "" | "observe" | "enforce"
	// Pins maps a module/package path to its approved content digest (go h1: / npm sri). With
	// SupplyChain "enforce", a dependency this run fetches whose path is pinned but whose digest
	// differs fails the run before the build; with "observe" the mismatch is only recorded. Empty =
	// no pins. The daemon writes these from the org's signed pin set (promoted from observe).
	Pins map[string]string `json:"pins,omitempty"`
}

// DefaultRunnerPolicyPath is where the operator writes the machine policy. Root-owned on a
// real runner so a workflow step can't rewrite it (with the non-root runner of layer 2).
const DefaultRunnerPolicyPath = "/etc/interpose/ci-policy.json"

// RunnerPolicyPath resolves the policy file: the fixed default when it exists (so a workflow
// cannot redirect it via the environment), else $INTERPOSE_CI_POLICY for dev/testing.
func RunnerPolicyPath() string {
	if _, err := os.Stat(DefaultRunnerPolicyPath); err == nil {
		return DefaultRunnerPolicyPath
	}
	if p := strings.TrimSpace(os.Getenv("INTERPOSE_CI_POLICY")); p != "" {
		return p
	}
	return DefaultRunnerPolicyPath
}

// LoadRunnerPolicy reads the policy from path. A missing file is NOT an error - it means no
// machine policy, so the workflow's requests stand (an unmanaged runner). A malformed file
// IS an error, so a broken policy fails loud rather than silently un-governing.
func LoadRunnerPolicy(path string) (RunnerPolicy, error) {
	var p RunnerPolicy
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p, nil
}

// Effective applies the policy over a request and returns the enforced values plus a list of
// human-readable notes for each override (so the log shows what the machine changed). The
// request is approve/stream/timeout as parsed from the CLI; the return is what must be used.
func (p RunnerPolicy) Effective(approve string, stream bool, timeout time.Duration) (string, bool, time.Duration, []string) {
	var notes []string
	if a := strings.TrimSpace(p.Approve); a != "" && a != approve {
		notes = append(notes, "runner policy: approval mode forced to "+a+" (workflow requested "+approve+")")
		approve = a
	}
	if p.Stream != nil && *p.Stream != stream {
		state := "off"
		if *p.Stream {
			state = "on"
		}
		notes = append(notes, "runner policy: step-output streaming forced "+state)
		stream = *p.Stream
	}
	if m := strings.TrimSpace(p.MaxTimeout); m != "" {
		if d, err := time.ParseDuration(m); err == nil && timeout > d {
			notes = append(notes, "runner policy: approval timeout capped to "+m+" (workflow requested "+timeout.String()+")")
			timeout = d
		}
	}
	return approve, stream, timeout, notes
}
