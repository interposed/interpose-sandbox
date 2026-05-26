package main

func runNew(args []string) {
	// Planned v0.1:
	//   interpose-sandbox new <agent> <workspace-path> [--name NAME] [--memory 2g] [--cpus 2]
	//
	// Generates a Firecracker vmconfig.json from internal/firecracker/config.go,
	// downloads the interpose-kernel image if missing, mounts the workspace
	// path into the VM via virtio-fs, and starts the Firecracker process in
	// the background. Records sandbox metadata under
	// $XDG_STATE_HOME/interpose-sandbox/<name>/ so `ls`, `run`, `rm` can find it.
	notImplemented("new")
}
