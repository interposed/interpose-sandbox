package main

func runRun(args []string) {
	// Planned v0.1:
	//   interpose-sandbox run <name>
	//
	// Attaches to the named sandbox's serial console (Firecracker exposes
	// it as a Unix socket). Drops the operator into a shell inside the VM
	// where interpose serve is already running on localhost:7421.
	notImplemented("run")
}
