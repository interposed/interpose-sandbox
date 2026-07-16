package main

import (
	"flag"
	"fmt"
)

// runLs lists sandboxes from the registry. With --json it emits the shape the
// interpose daemon forwards to the operator over the Noise bridge:
// {"sandboxes":[{id,name,status,profile,workspace,uptime_sec,agents:[…]}]}.
//
// It reconciles liveness on read: a sandbox whose firecracker PID is gone is
// reported "stopped" (so a crashed VM doesn't linger as "ready").
func runLs(args []string) {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit machine-readable JSON (consumed by the interpose daemon)")
	_ = fs.Parse(args)

	reg := openRegistry()
	list, err := reg.List()
	if err != nil {
		die("registry list: %v", err)
	}

	wire := make([]wireSandbox, 0, len(list))
	for _, sb := range list {
		if sb.Status != "paused" && sb.PID > 0 && !pidAlive(sb.PID) {
			sb.Status = "stopped"
		}
		wire = append(wire, toWire(sb))
	}

	if *asJSON {
		printJSON(map[string]any{"sandboxes": wire})
		return
	}
	if len(wire) == 0 {
		fmt.Println("No sandboxes. Create one with: interpose-sandbox new --profile <p>")
		return
	}
	for _, w := range wire {
		fmt.Printf("%-18s %-8s %-28s %d agents\n", w.Name, w.Status, w.Profile, len(w.Agents))
	}
}
