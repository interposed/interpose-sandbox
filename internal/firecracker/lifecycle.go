// Lifecycle management for Firecracker VMs.
//
// v0.1 deliberately ships a foreground-only model: Start writes vmconfig
// to stateDir, spawns firecracker as a child process with stdin/stdout
// inherited from the calling terminal, and blocks until firecracker
// exits. The operator sees the boot log live, types into the auto-login
// serial-console shell, and Ctrl-C terminates the VM.
//
// Why not background + attach in v0.1? Backgrounding firecracker while
// keeping the serial console reachable later (for an `interpose-sandbox
// run` attach) requires either a socat/PTY wrapper or a firecracker-side
// console fanout. Both are bug surface we don't want to ship under time
// pressure. v0.2 adds the wrapper and ls/run/rm subcommands.
package firecracker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// VM is the foreground-only handle returned by Start. Once Wait returns,
// the VM is gone — there is no detach/reattach in v0.1.
type VM struct {
	StateDir       string
	VMConfigPath   string
	APISockPath    string
	cmd            *exec.Cmd
}

// Start spawns firecracker as a child of the current process, with
// stdin/stdout/stderr inherited so the operator interacts with the VM's
// serial console directly. Blocks via VM.Wait.
//
// Caller is responsible for:
//   - Ensuring `firecracker` is on PATH (interpose-sandbox doctor checks this).
//   - Ensuring stateDir exists and is writable.
//   - Ensuring the kernelPath + rootfsPath referenced in cfg exist.
//
// Files written to stateDir:
//   vmconfig.json — the rendered VMConfig
//   api.sock      — created by firecracker for control-plane requests
//
// Note: api.sock is created on firecracker startup; it's available for
// process-external control (e.g. shutdown via REST) once the VM is up.
// v0.1 doesn't use it — Ctrl-C is the shutdown path.
func Start(cfg VMConfig, stateDir string) (*VM, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir state: %w", err)
	}

	cfgPath := filepath.Join(stateDir, "vmconfig.json")
	bytes, err := Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal vmconfig: %w", err)
	}
	if err := os.WriteFile(cfgPath, bytes, 0o644); err != nil {
		return nil, fmt.Errorf("write vmconfig: %w", err)
	}

	apiSock := filepath.Join(stateDir, "api.sock")
	// Firecracker refuses to start if the api socket file already
	// exists (defensive against stale state from a crashed prior run).
	_ = os.Remove(apiSock)

	cmd := exec.Command("firecracker",
		"--api-sock", apiSock,
		"--config-file", cfgPath,
	)
	// Inherit stdio so the operator's terminal IS the serial console.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn firecracker: %w", err)
	}
	return &VM{
		StateDir:     stateDir,
		VMConfigPath: cfgPath,
		APISockPath:  apiSock,
		cmd:          cmd,
	}, nil
}

// Wait blocks until firecracker exits. The exit status from firecracker
// is returned as the second value; the error is non-nil only on actual
// wait-syscall failures, not on non-zero VM exits.
func (v *VM) Wait() (int, error) {
	if v.cmd == nil || v.cmd.Process == nil {
		return -1, fmt.Errorf("VM not started")
	}
	state, err := v.cmd.Process.Wait()
	if err != nil {
		return -1, err
	}
	return state.ExitCode(), nil
}

// PID returns the firecracker process ID, or 0 if not started.
func (v *VM) PID() int {
	if v.cmd == nil || v.cmd.Process == nil {
		return 0
	}
	return v.cmd.Process.Pid
}
