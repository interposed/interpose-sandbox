package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/interposehq/interpose-sandbox/internal/firecracker"
	"github.com/interposehq/interpose-sandbox/internal/guestclient"
	"github.com/interposehq/interpose-sandbox/internal/registry"
	"github.com/interposehq/interpose-sandbox/internal/vsockproto"
)

// runPause freezes a running sandbox via the Firecracker API.
func runPause(args []string) {
	id := arg0(args, "pause")
	reg := openRegistry()
	sb := mustGet(reg, id)
	if err := firecracker.Pause(sb.APISock); err != nil {
		die("pause: %v", err)
	}
	_ = reg.Update(id, func(s *registry.Sandbox) error { s.Status = "paused"; return nil })
	fmt.Printf("paused %s\n", sb.Name)
}

// runResume unfreezes a paused sandbox.
func runResume(args []string) {
	id := arg0(args, "resume")
	reg := openRegistry()
	sb := mustGet(reg, id)
	if err := firecracker.Resume(sb.APISock); err != nil {
		die("resume: %v", err)
	}
	_ = reg.Update(id, func(s *registry.Sandbox) error { s.Status = "ready"; return nil })
	fmt.Printf("resumed %s\n", sb.Name)
}

// runFork branches a running sandbox via a Firecracker snapshot — it inherits
// the source's live memory + agents (the "branch the running computer" trick).
// See forkVM in new.go.
func runFork(args []string) {
	id := arg0(args, "fork")
	reg := openRegistry()
	src := mustGet(reg, id)
	sb, err := forkVM(src, src.Name+"-fork")
	if err != nil {
		die("fork: %v", err)
	}
	if err := reg.Add(sb); err != nil {
		die("registry: %v", err)
	}
	printJSON(toWire(sb))
}

// runExec drops an agent into a sandbox: interpose-sandbox exec <sandbox> <kind>.
func runExec(args []string) {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		die("usage: interpose-sandbox exec <sandbox> <kind>")
	}
	id, kind := fs.Arg(0), fs.Arg(1)
	reg := openRegistry()
	sb := mustGet(reg, id)
	if localPTYMode() {
		// No guest to launch into — record the agent so the operator can list
		// and Open it; `attach` will serve a local shell.
		ag := registry.Agent{ID: newID("agt"), Kind: kind, Status: "ready", CreatedAt: time.Now(), Last: "started (local-pty)"}
		if err := reg.Update(id, func(s *registry.Sandbox) error {
			s.Agents = append(s.Agents, ag)
			return nil
		}); err != nil {
			die("registry: %v", err)
		}
		printJSON(map[string]any{"id": ag.ID, "kind": ag.Kind, "status": ag.Status})
		return
	}
	// Launch the agent INSIDE the VM under `interpose run` via the guest-agent
	// over vsock. The guest keeps it alive (with scrollback); `attach` streams
	// its PTY later. The guest assigns the id we record, so attach can find it.
	conn, rep, err := guestclient.Dial(sb.VsockUDS, vsockproto.Request{Op: "start", Agent: kind})
	if err != nil {
		die("launch %s in VM: %v", kind, err)
	}
	_ = conn.Close() // detach — the agent keeps running in the VM
	ag := registry.Agent{ID: rep.ID, Kind: kind, Status: "ready", CreatedAt: time.Now(), Last: "started"}
	if err := reg.Update(id, func(s *registry.Sandbox) error {
		s.Agents = append(s.Agents, ag)
		return nil
	}); err != nil {
		die("registry: %v", err)
	}
	printJSON(map[string]any{"id": ag.ID, "kind": ag.Kind, "status": ag.Status})
}

// runAttach streams an agent's live terminal (PTY) both ways over vsock. The
// interpose daemon runs this and pipes it over the Noise bridge to the
// operator's embedded terminal; a human at a raw TTY drives it directly.
func runAttach(args []string) {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		die("usage: interpose-sandbox attach <sandbox> <agent>")
	}
	id, agID := fs.Arg(0), fs.Arg(1)
	if localPTYMode() {
		attachLocalShell()
		return
	}
	reg := openRegistry()
	sb := mustGet(reg, id)
	conn, _, err := guestclient.Dial(sb.VsockUDS, vsockproto.Request{Op: "attach", ID: agID})
	if err != nil {
		die("attach: %v", err)
	}
	defer conn.Close()
	go func() { _, _ = io.Copy(conn, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, conn)
}

// runSession returns the Open-an-agent view. HONEST: no fabricated transcript —
// the live terminal (PTY over vsock) isn't wired yet, so it says so plainly.
func runSession(args []string) {
	fs := flag.NewFlagSet("session", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		die("usage: interpose-sandbox session [--json] <sandbox> <agent>")
	}
	id, agID := fs.Arg(0), fs.Arg(1)
	reg := openRegistry()
	sb := mustGet(reg, id)
	var kind, status string
	found := false
	for _, a := range sb.Agents {
		if a.ID == agID {
			kind, status, found = a.Kind, a.Status, true
		}
	}
	if !found {
		die("agent %q not found in %s", agID, sb.Name)
	}
	view := map[string]any{
		"sandbox_id": id, "agent_id": agID, "kind": kind,
		"sandbox": sb.Name, "profile": sb.Profile, "ssh": "ssh " + sb.Name,
		"transcript": []map[string]string{
			{"kind": "agent", "text": "● " + kind + " — " + status},
			{"kind": "dim", "text": "Live terminal not wired yet: the PTY stream over vsock lands with the guest agent."},
		},
		"pending":  nil,
		"timeline": []any{},
	}
	if *asJSON {
		printJSON(view)
		return
	}
	fmt.Printf("%s/%s: %s\n", sb.Name, kind, status)
}

// runAgent handles per-agent actions:
// interpose-sandbox agent <approve|deny|stop> <sandbox> <agent>.
func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 3 {
		die("usage: interpose-sandbox agent <approve|deny|stop> <sandbox> <agent>")
	}
	action, id, agID := fs.Arg(0), fs.Arg(1), fs.Arg(2)
	reg := openRegistry()
	err := reg.Update(id, func(s *registry.Sandbox) error {
		for i := range s.Agents {
			if s.Agents[i].ID != agID {
				continue
			}
			switch action {
			case "approve":
				s.Agents[i].Approvals++
				s.Agents[i].Last = "approved"
			case "deny":
				s.Agents[i].Last = "denied"
			case "stop":
				s.Agents = append(s.Agents[:i], s.Agents[i+1:]...)
			default:
				return fmt.Errorf("unknown agent action %q", action)
			}
			return nil
		}
		return fmt.Errorf("agent %q not found", agID)
	})
	if err != nil {
		die("agent %s: %v", action, err)
	}
	fmt.Printf("%s %s\n", action, agID)
}
