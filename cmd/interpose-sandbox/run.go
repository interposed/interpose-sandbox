package main

func runRun(args []string) {
	// v0.1: sandboxes are foreground via `new`, so there's no separate
	// "attach to existing" path. Once we have backgrounded sandboxes
	// in v0.2 (PTY/socat-wrapped firecracker), `run <name>` will be a
	// thin socat into the per-sandbox console.sock.
	notImplemented("run (v0.2 — requires background sandboxes)")
}
