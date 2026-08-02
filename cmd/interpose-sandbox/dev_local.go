package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/creack/pty"
	"github.com/interposehq/interpose-sandbox/internal/registry"
)

// Local PTY dev-mode (env INTERPOSE_SANDBOX_LOCAL_PTY=1). A verification harness
// for the operator↔daemon PTY relay that removes the KVM/vsock requirement:
//
//	new   → registers a sandbox WITHOUT booting a microVM
//	exec  → records an agent WITHOUT a guest launch over vsock
//	attach→ streams a LOCAL login shell in a PTY instead of the guest's
//
// It exercises the full operator → daemon → `attach` → PTY → xterm → keystroke
// loop on a plain Linux VM (no /dev/kvm needed); only the vsock↔guest hop is
// stubbed. Gated entirely behind the env var, so production boots never hit it.
func localPTYMode() bool {
	switch os.Getenv("INTERPOSE_SANDBOX_LOCAL_PTY") {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// newLocalSandbox is the non-booting registry stub `new --json` records in
// local-pty mode (mirrors the fields bootDetached sets, minus the VM handles).
func newLocalSandbox(name, profile, workspace string) registry.Sandbox {
	return registry.Sandbox{
		ID:        newID("sbx"),
		Name:      name,
		Status:    "ready",
		Profile:   profile,
		Workspace: workspace,
		CreatedAt: time.Now(),
	}
}

// attachLocalShell streams a local interactive shell over stdin/stdout in a PTY.
// The daemon's ptyRelay pumps this identically to the guest PTY, so keystrokes
// and output travel the real Noise path to the operator's embedded xterm.
func attachLocalShell() {
	// Host-agent terminal: when the daemon sets INTERPOSE_SANDBOX_PTY_CMD, run
	// THAT command in the PTY instead of a login shell — this is how
	// `interpose run pi` (a host agent under enforcement) streams to the
	// operator's xterm. The command inherits our env, so the agent's API key
	// (set by the daemon alongside PTY_CMD) reaches it.
	var cmd *exec.Cmd
	if hostCmd := os.Getenv("INTERPOSE_SANDBOX_PTY_CMD"); hostCmd != "" {
		cmd = exec.Command("/bin/sh", "-c", hostCmd)
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	} else {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/bash"
		}
		cmd = exec.Command(shell, "-i")
		cmd.Env = append(os.Environ(), "PS1=sandbox$ ", "TERM=xterm-256color")
	}
	// Full-screen TUIs (the yeet observation dashboards, pi) place their cursor and
	// selection highlight against the reported window size, so the PTY must be born
	// with a real size, not creack/pty's default 0x0 — at 0x0 a program falls back
	// to a fixed 80x24 and its interactive layout lands in the wrong place relative
	// to the operator's actual terminal. Start with a sane default; the daemon then
	// streams the operator's true cols/rows over the winch control fd below.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		die("local pty: %v", err)
	}
	defer func() { _ = ptmx.Close() }()
	// Window-resize channel: the daemon passes a control pipe as an extra fd (its
	// number in INTERPOSE_SANDBOX_PTY_WINCH_FD) and writes one "rows cols\n" line
	// per operator resize. Apply each as TIOCSWINSZ on the master, which also sends
	// SIGWINCH to the child so the TUI re-lays-out. Absent (older daemon) → no-op.
	if fd := os.Getenv("INTERPOSE_SANDBOX_PTY_WINCH_FD"); fd != "" {
		if n, perr := strconv.Atoi(fd); perr == nil && n >= 0 {
			go watchWinch(os.NewFile(uintptr(n), "winch"), ptmx)
		}
	}
	if os.Getenv("INTERPOSE_SANDBOX_PTY_CMD") == "" {
		fmt.Fprintln(ptmx, "echo '[local-pty dev-mode] live shell — this is NOT a real sandbox'")
	}
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, ptmx)
	_ = cmd.Wait()
}

// watchWinch reads newline-delimited "rows cols" resize messages from the daemon's
// control pipe and applies each to the PTY master. It returns when the pipe closes.
func watchWinch(ctl *os.File, ptmx *os.File) {
	if ctl == nil {
		return
	}
	defer func() { _ = ctl.Close() }()
	sc := bufio.NewScanner(ctl)
	for sc.Scan() {
		if ws, ok := parseWinch(sc.Text()); ok {
			_ = pty.Setsize(ptmx, ws)
		}
	}
}

// parseWinch parses a "rows cols" control line into a Winsize, rejecting anything
// out of a sane range (0 or absurdly large) so a malformed frame can't drive the
// PTY to a degenerate size. Pure and total: the sole decision, so it is unit-tested.
func parseWinch(line string) (*pty.Winsize, bool) {
	f := strings.Fields(line)
	if len(f) != 2 {
		return nil, false
	}
	rows, err1 := strconv.Atoi(f[0])
	cols, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil {
		return nil, false
	}
	if rows < 1 || cols < 1 || rows > 2000 || cols > 2000 {
		return nil, false
	}
	return &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}, true
}
