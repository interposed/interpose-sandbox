package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
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
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	cmd := exec.Command(shell, "-i")
	cmd.Env = append(os.Environ(), "PS1=sandbox$ ", "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		die("local pty: %v", err)
	}
	defer func() { _ = ptmx.Close() }()
	fmt.Fprintln(ptmx, "echo '[local-pty dev-mode] live shell — this is NOT a real sandbox'")
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, ptmx)
	_ = cmd.Wait()
}
