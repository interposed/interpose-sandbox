package ci

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func boolp(b bool) *bool { return &b }

// TestRunnerPolicyOverridesWorkflow pins the keystone: a runner policy forces the held
// approval and sovereign streaming regardless of what the workflow asked for.
func TestRunnerPolicyOverridesWorkflow(t *testing.T) {
	// A repo tries to skip the gate (auto) and leak logs (stream on) with a long timeout.
	pol := RunnerPolicy{Approve: "file", Stream: boolp(false), MaxTimeout: "30m"}
	approve, stream, timeout, notes := pol.Effective("auto", true, 2*time.Hour)

	if approve != "file" {
		t.Errorf("approve: policy must force file, got %q", approve)
	}
	if stream {
		t.Error("stream: policy must force off")
	}
	if timeout != 30*time.Minute {
		t.Errorf("timeout: policy must cap to 30m, got %v", timeout)
	}
	if len(notes) != 3 {
		t.Errorf("want 3 override notes (approve, stream, timeout), got %d: %v", len(notes), notes)
	}

	// An empty policy changes nothing and emits no notes (an unmanaged runner).
	a, s, to, n := RunnerPolicy{}.Effective("file", false, 10*time.Minute)
	if a != "file" || s != false || to != 10*time.Minute || len(n) != 0 {
		t.Errorf("empty policy altered the request: %q %v %v %v", a, s, to, n)
	}

	// A timeout under the cap is left alone.
	if _, _, to2, _ := (RunnerPolicy{MaxTimeout: "30m"}).Effective("file", false, 5*time.Minute); to2 != 5*time.Minute {
		t.Errorf("timeout under cap should be unchanged, got %v", to2)
	}
}

// TestLoadRunnerPolicy: a missing file is no-policy (not an error); a valid file parses.
func TestLoadRunnerPolicy(t *testing.T) {
	if p, err := LoadRunnerPolicy(filepath.Join(t.TempDir(), "nope.json")); err != nil || p.Approve != "" {
		t.Fatalf("missing policy must be empty + no error, got %+v err=%v", p, err)
	}
	f := filepath.Join(t.TempDir(), "ci-policy.json")
	if err := os.WriteFile(f, []byte(`{"approve":"file","stream":false,"max_timeout":"30m"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadRunnerPolicy(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Approve != "file" || p.Stream == nil || *p.Stream != false || p.MaxTimeout != "30m" {
		t.Fatalf("parsed policy wrong: %+v", p)
	}
}
