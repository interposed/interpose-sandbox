package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
)

// runRm destroys a sandbox: kills its firecracker process, wipes its state
// directory, and drops it from the registry.
func runRm(args []string) {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		die("usage: interpose-sandbox rm <id>")
	}
	id := fs.Arg(0)
	reg := openRegistry()
	sb := mustGet(reg, id)
	if sb.PID > 0 && pidAlive(sb.PID) {
		_ = syscall.Kill(sb.PID, syscall.SIGKILL)
	}
	if sb.StateDir != "" {
		_ = os.RemoveAll(sb.StateDir)
	}
	if err := reg.Remove(id); err != nil {
		die("registry remove: %v", err)
	}
	fmt.Printf("removed %s\n", sb.Name)
}
