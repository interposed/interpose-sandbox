package ci

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFileApproverApproved(t *testing.T) {
	dir := t.TempDir()
	pend := filepath.Join(dir, "pending")
	dec := filepath.Join(dir, "decisions")
	a := FileApprover{PendingDir: pend, DecisionDir: dec, Timeout: 3 * time.Second, Poll: 20 * time.Millisecond}
	req := ReleaseRequest{Pipeline: "p", Step: "push", RunID: "rX"}

	// An "operator" approves shortly after the request appears.
	go func() {
		time.Sleep(60 * time.Millisecond)
		// the request should be listable as pending
		if ps, _ := ListPending(pend); len(ps) == 1 && ps[0].Step == "push" {
			_ = WriteDecision(dec, req.RunID, req.Step, Approved, "tester")
		}
	}()

	got, err := a.Approve(context.Background(), req)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got != Approved {
		t.Fatalf("want Approved, got %v", got)
	}
}

func TestFileApproverTimesOutFailClosed(t *testing.T) {
	dir := t.TempDir()
	a := FileApprover{
		PendingDir:  filepath.Join(dir, "pending"),
		DecisionDir: filepath.Join(dir, "decisions"),
		Timeout:     120 * time.Millisecond,
		Poll:        20 * time.Millisecond,
	}
	got, err := a.Approve(context.Background(), ReleaseRequest{RunID: "rY", Step: "push"})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got != Denied {
		t.Fatalf("no decision must fail closed (Denied), got %v", got)
	}
}

func TestFileApproverDenied(t *testing.T) {
	dir := t.TempDir()
	pend := filepath.Join(dir, "pending")
	dec := filepath.Join(dir, "decisions")
	a := FileApprover{PendingDir: pend, DecisionDir: dec, Timeout: 3 * time.Second, Poll: 20 * time.Millisecond}
	go func() {
		time.Sleep(40 * time.Millisecond)
		_ = WriteDecision(dec, "rZ", "push", Denied, "tester")
	}()
	got, err := a.Approve(context.Background(), ReleaseRequest{RunID: "rZ", Step: "push"})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got != Denied {
		t.Fatalf("want Denied, got %v", got)
	}
}
