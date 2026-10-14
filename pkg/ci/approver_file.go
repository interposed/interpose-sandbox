package ci

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// FileApprover is the governance seam between the CI runner and an approver
// (the operator). On a release-class step it writes a pending request to a
// mailbox directory and waits for a decision file to appear, up to Timeout.
// No decision in time -> Denied (fail-closed). This is deliberately a plain
// filesystem contract so the operator, a CLI, or a relay bridge can all drive
// it without linking this package.
type FileApprover struct {
	PendingDir  string        // pending requests are written here (operator reads)
	DecisionDir string        // decisions are read from here (operator writes)
	Timeout     time.Duration // wait budget; 0 -> 2 minutes
	Poll        time.Duration // poll interval; 0 -> 500ms
}

// PendingRelease is a request awaiting a decision (what the operator lists).
type PendingRelease struct {
	ReleaseRequest
	RequestedAt time.Time `json:"requested_at"`
}

// ReleaseDecision is an approver's answer (what the operator writes).
type ReleaseDecision struct {
	RunID     string    `json:"run_id"`
	Step      string    `json:"step"`
	Decision  Decision  `json:"decision"`
	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at"`
}

func releaseKey(runID, step string) string { return sanitize(runID) + "--" + sanitize(step) }

// Approve implements Approver.
func (a FileApprover) Approve(ctx context.Context, req ReleaseRequest) (Decision, error) {
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	poll := a.Poll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	key := releaseKey(req.RunID, req.Step)

	if err := os.MkdirAll(a.PendingDir, 0o755); err != nil {
		return Denied, err
	}
	pending := filepath.Join(a.PendingDir, key+".json")
	decision := filepath.Join(a.DecisionDir, key+".json")
	if b, err := json.MarshalIndent(PendingRelease{ReleaseRequest: req, RequestedAt: time.Now()}, "", "  "); err == nil {
		_ = os.WriteFile(pending, b, 0o644)
	}
	defer os.Remove(pending)

	deadline := time.After(timeout)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if d, ok := readDecision(decision); ok {
			_ = os.Remove(decision)
			if d.Decision == Approved {
				return Approved, nil
			}
			return Denied, nil
		}
		select {
		case <-ctx.Done():
			return Denied, ctx.Err()
		case <-deadline:
			return Denied, nil // fail-closed on timeout
		case <-ticker.C:
		}
	}
}

func readDecision(path string) (ReleaseDecision, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ReleaseDecision{}, false
	}
	var d ReleaseDecision
	if json.Unmarshal(b, &d) != nil {
		return ReleaseDecision{}, false
	}
	return d, true
}

// ListPending returns the release requests currently awaiting a decision.
// This is what the operator's Releases page lists under "pending".
func ListPending(pendingDir string) ([]PendingRelease, error) {
	entries, err := os.ReadDir(pendingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []PendingRelease
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(pendingDir, e.Name()))
		if err != nil {
			continue
		}
		var p PendingRelease
		if json.Unmarshal(b, &p) == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// WriteDecision records an approver's answer for a pending release. The
// operator calls this when a human approves or denies (after the factor-model
// ceremony); the waiting runner picks it up and proceeds or fails closed.
func WriteDecision(decisionDir, runID, step string, d Decision, by string) error {
	if err := os.MkdirAll(decisionDir, 0o755); err != nil {
		return err
	}
	rec := ReleaseDecision{RunID: runID, Step: step, Decision: d, DecidedBy: by, DecidedAt: time.Now()}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(decisionDir, releaseKey(runID, step)+".json"), b, 0o644)
}
