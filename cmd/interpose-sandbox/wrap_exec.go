package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/interposehq/interpose-sandbox/pkg/procbox"
)

// wrapExec self-restricts THIS process (nono applies the kernel allow-list —
// Landlock on Linux, Seatbelt on macOS), then execs the command in place so
// the sandboxed image replaces the wrapper. The command and every child
// inherit the irrevocable ruleset — no un-sandboxed parent survives.
func wrapExec(policy procbox.PolicySpec, command []string) (int, error) {
	res, err := procbox.Apply(policy)
	if err != nil {
		return 1, err
	}
	for _, n := range res.Notes {
		fmt.Fprintln(os.Stderr, "wrap: note:", n)
	}
	path, err := lookPath(command[0])
	if err != nil {
		return 127, err
	}
	if err := syscall.Exec(path, command, os.Environ()); err != nil {
		return 126, fmt.Errorf("exec %s: %w", command[0], err)
	}
	return 0, nil // unreachable on success
}

func lookPath(name string) (string, error) {
	if len(name) > 0 && (name[0] == '/' || name[0] == '.') {
		return name, nil
	}
	for _, dir := range splitPath(os.Getenv("PATH")) {
		cand := dir + "/" + name
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand, nil
		}
	}
	return "", fmt.Errorf("command not found: %s", name)
}

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == ':' {
			if i > start {
				out = append(out, p[start:i])
			}
			start = i + 1
		}
	}
	return out
}
