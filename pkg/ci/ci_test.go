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
