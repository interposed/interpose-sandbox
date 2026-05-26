package main

func runRm(args []string) {
	// Planned v0.1:
	//   interpose-sandbox rm <name>
	//
	// Sends SIGTERM to the Firecracker process (PID from state dir),
	// waits for clean shutdown (or escalates to SIGKILL), removes the
	// sandbox's state directory + virtual disk images.
	notImplemented("rm")
}
