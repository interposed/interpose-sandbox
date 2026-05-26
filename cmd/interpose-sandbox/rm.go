package main

func runRm(args []string) {
	// v0.1: sandboxes are foreground (Ctrl-C terminates the VM and
	// returns control to the shell), so there's nothing to "remove."
	// State directories under $XDG_STATE_HOME/interpose-sandbox/ persist
	// between runs for post-mortem inspection — `rm -rf` them manually
	// for now. v0.2 turns this into a proper subcommand alongside
	// background sandboxes.
	notImplemented("rm (v0.2 — requires background sandboxes)")
}
