// Command sbxrun runs a single command inside one governed cell (the process /
// sandlock tier) and reports what the sandbox applied. It is a diagnostic for
// proving the deny-default allow-list bites on a host - not the production path
// (that is the pool + interpose-ci).
//
// Usage:
//
//	sbxrun --rw <dir>[,<dir>...] [--ro a,b] [--runtimes go,node] [--net off|all] -- <cmd...>
//
// The first --rw dir is the cell's workdir. The interpose-cell shim must sit
// beside this binary or be named by INTERPOSE_CELL_BIN.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/interposed/interpose-sandbox/pkg/cell"
	"github.com/interposed/interpose-sandbox/pkg/procbox"
)

func splitComma(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	fs := flag.NewFlagSet("sbxrun", flag.ExitOnError)
	rw := fs.String("rw", "", "comma-separated read-write paths; the first is the workdir")
	ro := fs.String("ro", "", "comma-separated extra read-only paths")
	runtimes := fs.String("runtimes", "", "comma-separated runtime groups (go,node,python,...)")
	net := fs.String("net", "off", "network mode: off|all|tcp")
	// Find the "--" separator; everything after is the command.
	args := os.Args[1:]
	var cmd []string
	for i, a := range args {
		if a == "--" {
			cmd = args[i+1:]
			args = args[:i]
			break
		}
	}
	_ = fs.Parse(args)
	if len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "sbxrun: missing command (use `-- <cmd...>`)")
		os.Exit(2)
	}

	rwPaths := splitComma(*rw)
	workdir := ""
	if len(rwPaths) > 0 {
		workdir = rwPaths[0]
		if err := os.MkdirAll(workdir, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, "sbxrun: workdir:", err)
			os.Exit(1)
		}
	}

	pol := cell.Policy(rwPaths, splitComma(*ro), splitComma(*runtimes), procbox.NetMode(*net))
	res, err := cell.Run(context.Background(), cell.Spec{
		Cmd:     cmd,
		Workdir: workdir,
		Policy:  pol,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbxrun: setup:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[sbxrun] backend=%s exit=%d limited=%v notes=%v\n",
		res.Backend, res.ExitCode, res.Limited, res.Notes)
	os.Exit(res.ExitCode)
}
