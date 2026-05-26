package main

func runLs(args []string) {
	// v0.1 ships foreground-only sandboxes (see new.go) — there is
	// nothing to "list" because `new` blocks for the lifetime of the VM
	// and Ctrl-C terminates it. Persistent / background sandboxes need
	// a PTY or socat wrapper around firecracker's serial console;
	// scheduled for v0.2 along with `ls`, `rm`, and `run` proper.
	notImplemented("ls (v0.2 — requires background sandboxes)")
}
