package ci

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/interposed/interpose-sandbox/pkg/cell"
	"github.com/interposed/interpose-sandbox/pkg/pool"
)

// fakePool builds a pool whose cells don't really sandbox: the runner writes a
// marker to stdout and fails any step whose argv contains "FAIL". This keeps
// the pipeline logic tests hermetic (no backend needed).
func fakePool() *pool.Pool {
	return pool.New(pool.Config{MaxConcurrent: 2, Runner: func(ctx context.Context, spec cell.Spec) (cell.Result, error) {
		if spec.Stdout != nil {
			fmt.Fprintf(spec.Stdout, "ran: %s", strings.Join(spec.Cmd, " "))
		}
		for _, a := range spec.Cmd {
			if a == "FAIL" {
				return cell.Result{ExitCode: 1}, nil
			}
		}
		return cell.Result{ExitCode: 0}, nil
	}})
}

func TestPipelineAllStepsPass(t *testing.T) {
	p := Pipeline{Name: "build", Workdir: t.TempDir(), Steps: []Step{
		{Name: "install", Run: []string{"echo", "install"}},
		{Name: "test", Run: []string{"echo", "test"}},
	}}
	rec, err := Run(context.Background(), p, fakePool(), AutoApprove{}, Meta{RunID: "r1"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !rec.OK {
		t.Fatalf("expected OK, got %+v", rec)
	}
	if len(rec.Steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(rec.Steps))
	}
	if !strings.Contains(rec.Steps[0].Output, "ran: echo install") {
		t.Fatalf("output not captured: %q", rec.Steps[0].Output)
	}
}

// captureApprover records the request it was asked to decide, so we can assert the
// approver sees the run's supply-chain risk (and does not approve blind).
type captureApprover struct {
	got ReleaseRequest
	dec Decision
}

func (c *captureApprover) Approve(_ context.Context, req ReleaseRequest) (Decision, error) {
	c.got = req
	return c.dec, nil
}

func TestReleaseRequestCarriesSupplyChainRisk(t *testing.T) {
	sc := &SupplyChain{
		Mode:       "enforce",
		Ecosystem:  "go",
		Undeclared: []ObservedModule{{Path: "evil.test/pkg", Version: "v1.0.0", Ecosystem: "go"}},
		Scan:       &ScanResult{Tool: "osv-scanner", Ran: true, Findings: []VulnFinding{{Package: "golang.org/x/text", IDs: []string{"GO-2020-0015"}, Severity: "MODERATE"}}},
	}
	p := Pipeline{Name: "deploy", Workdir: t.TempDir(), Steps: []Step{
		{Name: "build", Run: []string{"echo", "build"}},
		{Name: "release", Run: []string{"echo", "release"}, Release: true},
	}}
	appr := &captureApprover{dec: Approved}
	if _, err := Run(context.Background(), p, fakePool(), appr, Meta{RunID: "rsc", SupplyChain: sc}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if appr.got.SupplyChain == nil {
		t.Fatal("approver saw no supply-chain summary — approval would be blind")
	}
	if n := len(appr.got.SupplyChain.Undeclared); n != 1 {
		t.Fatalf("want 1 undeclared on the request, got %d", n)
	}
	if appr.got.SupplyChain.Scan == nil || len(appr.got.SupplyChain.Scan.Findings) != 1 {
		t.Fatalf("vuln findings did not reach the approver: %+v", appr.got.SupplyChain.Scan)
	}
}

func TestReleaseStepApprovedRuns(t *testing.T) {
	p := Pipeline{Name: "deploy", Workdir: t.TempDir(), Steps: []Step{
		{Name: "build", Run: []string{"echo", "build"}},
		{Name: "push", Run: []string{"echo", "docker-push"}, Release: true},
	}}
	rec, err := Run(context.Background(), p, fakePool(), AutoApprove{}, Meta{RunID: "r2", Commit: "abc123", Digest: "sha256:deadbeef"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !rec.OK {
		t.Fatalf("expected OK, got %+v", rec)
	}
	rel := rec.Steps[1]
	if !rel.Held || rel.Decision != Approved || rel.Skipped {
		t.Fatalf("release step not held+approved+run: %+v", rel)
	}
	if !strings.Contains(rel.Output, "docker-push") {
		t.Fatalf("approved release did not run: %q", rel.Output)
	}
}

func TestReleaseDeniedFailsClosed(t *testing.T) {
	p := Pipeline{Name: "deploy", Workdir: t.TempDir(), Steps: []Step{
		{Name: "build", Run: []string{"echo", "build"}},
		{Name: "push", Run: []string{"echo", "docker-push"}, Release: true},
		{Name: "notify", Run: []string{"echo", "notify"}},
	}}
	rec, err := Run(context.Background(), p, fakePool(), DenyAll{}, Meta{RunID: "r3"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.OK {
		t.Fatal("denied release must make the run not OK")
	}
	if len(rec.Steps) != 2 {
		t.Fatalf("fail-closed should stop after the denied release; got %d steps", len(rec.Steps))
	}
	rel := rec.Steps[1]
	if !rel.Held || rel.Decision != Denied || !rel.Skipped {
		t.Fatalf("denied release not held+denied+skipped: %+v", rel)
	}
	if strings.Contains(rel.Output, "docker-push") {
		t.Fatalf("denied release MUST NOT run: %q", rel.Output)
	}
}

func TestFailingStepStopsPipeline(t *testing.T) {
	p := Pipeline{Name: "build", Workdir: t.TempDir(), Steps: []Step{
		{Name: "ok", Run: []string{"echo", "ok"}},
		{Name: "boom", Run: []string{"sh", "FAIL"}},
		{Name: "never", Run: []string{"echo", "never"}},
	}}
	rec, err := Run(context.Background(), p, fakePool(), AutoApprove{}, Meta{RunID: "r4"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.OK {
		t.Fatal("a failing step must make the run not OK")
	}
	if len(rec.Steps) != 2 {
		t.Fatalf("pipeline should stop after the failing step; got %d steps", len(rec.Steps))
	}
	if rec.Steps[1].ExitCode != 1 {
		t.Fatalf("failing step exit = %d, want 1", rec.Steps[1].ExitCode)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rec := RunRecord{RunID: "r5", Pipeline: "p", OK: true}
	if _, err := rec.WriteJSON(dir); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadRecords(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1 || got[0].RunID != "r5" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestCuratedEnvDropsSecretsKeepsContext pins the env boundary policy: non-secret CI
// context crosses into a governed step; secrets, tokens and arbitrary vars do not.
func TestCuratedEnvDropsSecretsKeepsContext(t *testing.T) {
	parent := []string{
		"GITHUB_SHA=abc123",
		"CI=true",
		"RUNNER_NAME=ci-runner-ubuntu-4gb",
		"GITHUB_TOKEN=ghs_supersecret",
		"ACTIONS_RUNTIME_TOKEN=sensitive",
		"FAKE_SECRET=leakme",
		"MY_API_KEY=nope",
		"AWS_SECRET_ACCESS_KEY=nope",
		"PATH=/usr/bin",
	}
	got := CuratedEnv(parent)
	has := func(s string) bool {
		for _, e := range got {
			if e == s {
				return true
			}
		}
		return false
	}
	for _, keep := range []string{"GITHUB_SHA=abc123", "CI=true", "RUNNER_NAME=ci-runner-ubuntu-4gb"} {
		if !has(keep) {
			t.Errorf("CuratedEnv dropped safe CI context %q", keep)
		}
	}
	for _, drop := range []string{
		"GITHUB_TOKEN=ghs_supersecret", "ACTIONS_RUNTIME_TOKEN=sensitive",
		"FAKE_SECRET=leakme", "MY_API_KEY=nope", "AWS_SECRET_ACCESS_KEY=nope", "PATH=/usr/bin",
	} {
		if has(drop) {
			t.Errorf("CuratedEnv LEAKED %q (must be deny-by-default)", drop)
		}
	}
}
