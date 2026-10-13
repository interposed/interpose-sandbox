// Package cell runs a single command inside an isolated, deny-default
// execution unit - a "cell". v1 isolation is the shared-kernel tier: procbox
// (Landlock on Linux) for the filesystem/network allow-list, plus best-effort
// cgroup v2 resource caps. One cell = one job; the pool spawns many.
//
// Model: procbox.Apply() self-restricts the current process and the
// restriction is inherited across execve, so a cell is a tiny shim
// (cmd/interpose-cell, or Shim() re-exec'd) that Apply()s the policy then
// exec()s the job. Run() in the parent builds the cgroup and launches the shim.
//
// This is the shared-kernel tier only (MachineDoctor "standard"): good for a
// team's own repos and agents, not hostile multi-tenant. Hardware isolation
// (the "full" tier, microVM) is a separate, bare-metal, KVM-only backend.
package cell

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/interposed/interpose-sandbox/pkg/procbox"
)

// shimEnv carries the JSON cell spec to the shim process.
const shimEnv = "INTERPOSE_CELL_SPEC"

// Limits are best-effort cgroup v2 resource caps. Zero values mean "no cap".
type Limits struct {
	CPUMax      string // cgroup cpu.max: "max" or "<quota_us> <period_us>" (e.g. "50000 100000" = 50% of one CPU)
	MemMaxBytes int64  // cgroup memory.max in bytes
	PidsMax     int64  // cgroup pids.max
}

// Spec describes one cell to run.
type Spec struct {
	ID      string             // stable id (cgroup leaf + audit); generated if empty
	Cmd     []string           // argv; Cmd[0] resolved via PATH before the sandbox closes
	Workdir string             // cell cwd; must be inside Policy.FS.RW
	Env     []string           // extra env appended to the job's environment
	Policy  procbox.PolicySpec // the deny-default allow-list applied inside the cell
	Limits  Limits             // resource caps (best-effort)
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	// Shim overrides the interpose-cell binary path. Empty = discover
	// "interpose-cell" beside the current executable, then on $PATH.
	Shim string
}

// Result reports what happened. ExitCode is the job's exit (-1 if it never ran).
type Result struct {
	ExitCode   int
	Backend    string   // procbox backend that will apply ("landlock" | "nono")
	CgroupPath string   // empty when no cgroup was created
	Limited    bool     // at least one resource cap was applied
	Notes      []string // best-effort downgrades (cgroup/sandbox)
}

// Run launches the cell and waits for the job to exit. The returned error is
// non-nil only for setup failures (bad spec, shim missing, start failed); a
// job that runs and exits non-zero returns a Result with that ExitCode and a
// nil error.
func Run(ctx context.Context, s Spec) (Result, error) {
	var res Result
	if len(s.Cmd) == 0 {
		return res, errors.New("cell: empty Cmd")
	}
	shim, err := resolveShim(s.Shim)
	if err != nil {
		return res, err
	}
	if b, err := procbox.Current(); err == nil {
		res.Backend = b.Name()
	}

	specJSON, err := json.Marshal(shimSpec{Cmd: s.Cmd, Policy: s.Policy})
	if err != nil {
		return res, fmt.Errorf("cell: marshal spec: %w", err)
	}

	cmd := exec.CommandContext(ctx, shim)
	cmd.Dir = s.Workdir
	if s.Stdin != nil {
		cmd.Stdin = s.Stdin
	}
	cmd.Stdout = s.Stdout
	cmd.Stderr = s.Stderr
	cmd.Env = append(append([]string{}, os.Environ()...), s.Env...)
	cmd.Env = append(cmd.Env, shimEnv+"="+string(specJSON))

	cg, limited, notes := prepCgroup(cmd, s.ID, s.Limits)
	res.Limited = limited
	res.Notes = append(res.Notes, notes...)
	if cg != nil {
		res.CgroupPath = cg.path()
		defer cg.remove()
	}

	if err := cmd.Start(); err != nil {
		if cg != nil {
			cg.closeFD()
		}
		return res, fmt.Errorf("cell: start: %w", err)
	}
	if cg != nil {
		cg.closeFD() // the child is already born into the cgroup via CgroupFD
	}
	res.ExitCode = exitCode(cmd.Wait())
	return res, nil
}

// shimSpec is the minimal payload the shim needs.
type shimSpec struct {
	Cmd    []string           `json:"cmd"`
	Policy procbox.PolicySpec `json:"policy"`
}

// Shim is the cell child entry point: it resolves the command, applies the
// sandbox policy to itself, then exec()s the job (replacing this process so the
// Landlock restriction and the cgroup placement carry straight into the job).
// cmd/interpose-cell calls this; tests re-exec the test binary into it.
func Shim() {
	raw := os.Getenv(shimEnv)
	if raw == "" {
		fmt.Fprintln(os.Stderr, "interpose-cell: not a cell invocation (missing "+shimEnv+")")
		os.Exit(2)
	}
	var sp shimSpec
	if err := json.Unmarshal([]byte(raw), &sp); err != nil {
		fmt.Fprintln(os.Stderr, "cell: bad spec:", err)
		os.Exit(2)
	}
	if len(sp.Cmd) == 0 {
		fmt.Fprintln(os.Stderr, "cell: empty command")
		os.Exit(2)
	}
	// Resolve the binary BEFORE the sandbox closes - PATH lookup + the exec
	// target must be readable, and we want a clear 127 if it is simply absent.
	bin, err := exec.LookPath(sp.Cmd[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "cell: command not found:", sp.Cmd[0])
		os.Exit(127)
	}
	if _, err := procbox.Apply(sp.Policy); err != nil {
		fmt.Fprintln(os.Stderr, "cell: sandbox apply:", err)
		os.Exit(126)
	}
	env := dropEnv(os.Environ(), shimEnv)
	if err := execInto(bin, sp.Cmd, env); err != nil {
		fmt.Fprintln(os.Stderr, "cell: exec:", err)
		os.Exit(126)
	}
}

// resolveShim finds the interpose-cell binary.
func resolveShim(override string) (string, error) {
	if override == "" {
		override = os.Getenv("INTERPOSE_CELL_BIN")
	}
	if override != "" {
		return override, nil
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "interpose-cell")
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand, nil
		}
	}
	if p, err := exec.LookPath("interpose-cell"); err == nil {
		return p, nil
	}
	return "", errors.New("cell: interpose-cell shim not found (set Spec.Shim)")
}

// exitCode extracts a process exit code from an *exec.ExitError.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// dropEnv returns env without the KEY=... entry.
func dropEnv(env []string, key string) []string {
	out := make([]string, 0, len(env))
	pfx := key + "="
	for _, e := range env {
		if len(e) >= len(pfx) && e[:len(pfx)] == pfx {
			continue
		}
		out = append(out, e)
	}
	return out
}
