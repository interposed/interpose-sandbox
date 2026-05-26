package firecracker

// Lifecycle management for Firecracker VMs.
//
// Planned v0.1 surface (sketch only — see docs/roadmap.md):
//
//   // Start spawns a Firecracker process with the given config and waits
//   // for the API socket to come up. Returns a handle for later Stop /
//   // Status calls.
//   func Start(cfg VMConfig, stateDir string) (*VM, error)
//
//   // Stop sends a Firecracker REST API shutdown request, falls back to
//   // SIGTERM, then SIGKILL.
//   func (v *VM) Stop(graceful time.Duration) error
//
//   // Console returns the path to the Unix socket Firecracker uses for
//   // the guest's serial console — caller can `socat - UNIX-CONNECT:...`
//   // to attach.
//   func (v *VM) Console() string
//
//   // Status returns "running" if the process is alive and the API
//   // socket is reachable, else "stopped".
//   func (v *VM) Status() string
//
// Until v0.1, this file is intentionally empty so the package compiles
// with just config.go.
