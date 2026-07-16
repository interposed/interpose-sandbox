package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/interposehq/interpose-sandbox/internal/registry"
)

// sandboxStateRoot is the base dir holding per-sandbox state + registry.json.
func sandboxStateRoot() (string, error) {
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "interpose-sandbox"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "interpose-sandbox"), nil
}

func openRegistry() *registry.Store {
	root, err := sandboxStateRoot()
	if err != nil {
		die("state dir: %v", err)
	}
	st, err := registry.Open(root)
	if err != nil {
		die("open registry: %v", err)
	}
	return st
}

// newID returns a short unique id like "sbx-1718...".
func newID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func printJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		die("encode json: %v", err)
	}
	fmt.Println(string(b))
}

// pidAlive reports whether pid is a live process (signal 0 probe; Unix).
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, syscall.Signal(0)) == nil
}

// mustGet fetches a sandbox by id or exits with a clear error.
func mustGet(reg *registry.Store, id string) registry.Sandbox {
	sb, ok, err := reg.Get(id)
	if err != nil {
		die("registry: %v", err)
	}
	if !ok {
		die("sandbox %q not found", id)
	}
	return sb
}

// arg0 parses flags and returns the single required positional (a sandbox id).
func arg0(args []string, cmd string) string {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		die("usage: interpose-sandbox %s <id>", cmd)
	}
	return fs.Arg(0)
}

// --- wire shapes: the JSON the interpose daemon → operator expects. Distinct
// from registry.Sandbox (on-disk) so the two can evolve independently. ---

type wireAgent struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	UptimeSec int    `json:"uptime_sec"`
	Approvals int    `json:"approvals"`
	Last      string `json:"last"`
}

type wireSandbox struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Machine   string      `json:"machine"` // filled by the operator from the daemon fp
	Status    string      `json:"status"`
	Profile   string      `json:"profile"`
	Workspace string      `json:"workspace"`
	UptimeSec int         `json:"uptime_sec"`
	Agents    []wireAgent `json:"agents"`
}

func uptimeSec(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	return int(time.Since(t).Seconds())
}

func toWire(sb registry.Sandbox) wireSandbox {
	w := wireSandbox{
		ID: sb.ID, Name: sb.Name, Status: sb.Status, Profile: sb.Profile,
		Workspace: sb.Workspace, UptimeSec: uptimeSec(sb.CreatedAt), Agents: []wireAgent{},
	}
	for _, a := range sb.Agents {
		w.Agents = append(w.Agents, wireAgent{
			ID: a.ID, Kind: a.Kind, Status: a.Status,
			UptimeSec: uptimeSec(a.CreatedAt), Approvals: a.Approvals, Last: a.Last,
		})
	}
	return w
}
