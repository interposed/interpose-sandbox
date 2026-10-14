//go:build linux || darwin

package cell

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/interposed/interpose-sandbox/pkg/procbox"
)

// TestMain doubles as the cell shim: when INTERPOSE_CELL_SPEC is set the test
// binary is being re-exec'd AS a cell, so it runs Shim() (which exits) instead
// of the test suite. This is the same self-re-exec trick the procbox escape
// suite uses, and it lets the tests run without a separately built shim.
func TestMain(m *testing.M) {
	if os.Getenv(shimEnv) != "" {
		Shim() // never returns
		return
	}
	os.Exit(m.Run())
}

func backendOrSkip(t *testing.T) {
	t.Helper()
	b, err := procbox.Current()
	if err != nil {
		t.Skipf("no procbox backend on this host: %v", err)
	}
	t.Logf("backend: %s", b.Name())
}

// A cell can run a command and write inside its own workdir.
func TestCellRunsAllowedCommand(t *testing.T) {
	backendOrSkip(t)
	work := t.TempDir()
	var out bytes.Buffer
	res, err := Run(context.Background(), Spec{
		ID:      "test-allowed",
		Cmd:     []string{"/bin/sh", "-c", "echo hi > out.txt && cat out.txt"},
		Workdir: work,
		Policy:  Policy([]string{work}, nil, nil, procbox.NetOff),
		Stdout:  &out,
		Stderr:  &out,
		Shim:    os.Args[0],
	})
	if err != nil {
		t.Fatalf("run: %v (out=%q)", err, out.String())
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d out=%q notes=%v", res.ExitCode, out.String(), res.Notes)
	}
	if got := strings.TrimSpace(out.String()); got != "hi" {
		t.Fatalf("stdout: want %q, got %q", "hi", got)
	}
	if b, _ := os.ReadFile(filepath.Join(work, "out.txt")); strings.TrimSpace(string(b)) != "hi" {
		t.Fatalf("workdir file not written: %q", b)
	}
}

// A cell MUST NOT inherit the parent process environment. A secret in the caller's
// env (a mapped CI secret, a runner/registration token) must never reach a governed
// step - only the curated Spec.Env (plus the PATH/HOME base) crosses the boundary.
func TestCellDoesNotLeakParentEnv(t *testing.T) {
	backendOrSkip(t)
	t.Setenv("LEAK_ME_SECRET", "topsecret")
	work := t.TempDir()
	var out bytes.Buffer
	res, err := Run(context.Background(), Spec{
		ID:      "test-env-leak",
		Cmd:     []string{"/bin/sh", "-c", "echo L=[$LEAK_ME_SECRET] A=[$ALLOWED_VAR]"},
		Workdir: work,
		Env:     []string{"ALLOWED_VAR=yes"},
		Policy:  Policy([]string{work}, nil, nil, procbox.NetOff),
		Stdout:  &out,
		Stderr:  &out,
		Shim:    os.Args[0],
	})
	if err != nil {
		t.Fatalf("run: %v (out=%q)", err, out.String())
	}
	got := strings.TrimSpace(out.String())
	if strings.Contains(got, "topsecret") {
		t.Fatalf("parent env LEAKED into the cell: %q", got)
	}
	if want := "L=[] A=[yes]"; got != want {
		t.Fatalf("env: want %q, got %q (exit=%d)", want, got, res.ExitCode)
	}
}

// A cell MUST NOT read a secret outside its allow-list (~/.ssh).
func TestCellDeniesOutsideRead(t *testing.T) {
	backendOrSkip(t)
	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Skipf("cannot stage ~/.ssh probe: %v", err)
	}
	secret := filepath.Join(sshDir, "id_cell_escape_test")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0o600); err != nil {
		t.Skipf("cannot write ~/.ssh probe: %v", err)
	}
	defer os.Remove(secret)

	work := t.TempDir()
	var out bytes.Buffer
	res, err := Run(context.Background(), Spec{
		ID:      "test-denied",
		Cmd:     []string{"/bin/sh", "-c", "cat " + secret},
		Workdir: work,
		Policy:  Policy([]string{work}, nil, nil, procbox.NetOff),
		Stdout:  &out,
		Stderr:  &out,
		Shim:    os.Args[0],
	})
	if err != nil {
		t.Fatalf("run setup: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("reading ~/.ssh from a cell MUST fail, but it succeeded: out=%q", out.String())
	}
}

// Resource caps apply where the host allows cgroup v2 delegation. Tolerant:
// the cell must still run; the Limited assertion is skipped where the host
// does not delegate controllers.
func TestCellResourceCaps(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cgroup v2 resource caps are Linux-only")
	}
	backendOrSkip(t)
	if os.Geteuid() != 0 {
		t.Skip("cgroup caps need root")
	}
	work := t.TempDir()
	res, err := Run(context.Background(), Spec{
		ID:      "test-caps",
		Cmd:     []string{"/bin/sh", "-c", "true"},
		Workdir: work,
		Policy:  Policy([]string{work}, nil, nil, procbox.NetOff),
		Limits:  Limits{PidsMax: 64, MemMaxBytes: 128 << 20, CPUMax: "50000 100000"},
		Stdout:  io.Discard,
		Stderr:  io.Discard,
		Shim:    os.Args[0],
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d notes=%v", res.ExitCode, res.Notes)
	}
	if !res.Limited {
		t.Skipf("host did not delegate cgroup controllers (cell still ran): %v", res.Notes)
	}
	t.Logf("cgroup caps applied at %s", res.CgroupPath)
}

// TestSystemBaselineExposesResolverConfigForDNS pins the DNS fix: on
// systemd-resolved hosts /etc/resolv.conf is a symlink into
// /run/systemd/resolve, which the sandbox resolves at open time. If the
// baseline does not cover that target, every real dependency fetch (go get,
// pip, npm) fails with EAI_AGAIN inside a cell - which is exactly the gap the
// first real-dependency CI runs hit. Allowing /etc alone is not enough.
func TestSystemBaselineExposesResolverConfigForDNS(t *testing.T) {
	const resolver = "/run/systemd/resolve"

	found := false
	for _, p := range SystemBaselineRO() {
		if p == resolver {
			found = true
		}
		if p == "/run" {
			t.Fatalf("baseline exposes all of /run (%q) - scope to the resolver dir, not its sockets/secrets", p)
		}
	}
	if !found {
		t.Fatalf("SystemBaselineRO missing %q: resolv.conf symlink target is unreadable in cells, DNS dies with EAI_AGAIN", resolver)
	}

	// The resolver dir must also survive composition into the real cell policy.
	pol := Policy(nil, nil, nil, procbox.NetAll)
	got := false
	for _, p := range pol.FS.RO {
		if p == resolver {
			got = true
		}
	}
	if !got {
		t.Fatalf("Policy did not carry %q into FS.RO: %v", resolver, pol.FS.RO)
	}
}

// TestCellBaseEnvDefaultsTmpdirToWorkdir pins that a cell's TMPDIR points at the
// workdir (the only writable surface) unless the caller set it. Without this,
// go build (and other compilers) fail with "mkdir /tmp/...: permission denied"
// because system /tmp is deliberately not in the RW baseline - the exact gap
// the first real `go build` in a governed cell hit.
func TestCellBaseEnvDefaultsTmpdirToWorkdir(t *testing.T) {
	env := cellBaseEnv("/work/job", nil)
	want := "TMPDIR=/work/job/.interpose-tmp"
	found := false
	for _, e := range env {
		if e == want {
			found = true
		}
		// TMPDIR must be a SUBDIR, never the workdir root: go refuses a module
		// rooted at the system temp root, so TMPDIR==workdir breaks go build.
		if e == "TMPDIR=/work/job" {
			t.Fatalf("TMPDIR is the workdir root; go build will reject a module at the temp root")
		}
	}
	if !found {
		t.Fatalf("cellBaseEnv did not default TMPDIR to a workdir subdir; got %v", env)
	}

	// A caller-provided TMPDIR must win (no duplicate, no override).
	env = cellBaseEnv("/work/job", []string{"TMPDIR=/work/job/.scratch"})
	n := 0
	for _, e := range env {
		if strings.HasPrefix(e, "TMPDIR=") {
			n++
			if e != "TMPDIR=/work/job/.scratch" {
				t.Fatalf("caller TMPDIR overridden: %q", e)
			}
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one TMPDIR, got %d in %v", n, env)
	}
}
