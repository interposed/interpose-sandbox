// Command interpose-sandbox is a microVM-based agent sandbox runner.
// It wraps Firecracker + the interpose-kernel image to give operators a
// `sbx`-equivalent UX for spinning up sandboxes with the interpose LSM-BPF
// enforcer preloaded.
//
// See README.md for the architecture and docs/roadmap.md for what's
// shipping vs. what's coming.
package main

import (
	"fmt"
	"os"
)

const usage = `interpose-sandbox — Firecracker-based agent sandboxes with kernel enforcement

USAGE:
    interpose-sandbox <command> [flags]

COMMANDS:
    doctor     audit Firecracker host prerequisites (KVM, firecracker binary, kernel image)
    new        create a new sandbox (TODO — pending v0.1)
    run        attach to a running sandbox's shell (TODO — pending v0.1)
    ls         list sandboxes (TODO — pending v0.1)
    rm         remove a sandbox (TODO — pending v0.1)
    help       show this message

Run "interpose-sandbox <command> -h" for command-specific flags.

EXAMPLES:
    interpose-sandbox doctor                       # check Firecracker host prereqs
    interpose-sandbox new shell . --name proj1     # planned v0.1
    interpose-sandbox run proj1                    # planned v0.1
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "doctor":
		runDoctor(args)
	case "fix":
		runFix(args)
	case "new", "create":
		runNew(args)
	case "run":
		runRun(args)
	case "ls", "list":
		runLs(args)
	case "rm", "remove":
		runRm(args)
	case "fork":
		runFork(args)
	case "pause":
		runPause(args)
	case "resume":
		runResume(args)
	case "exec":
		runExec(args)
	case "attach":
		runAttach(args)
	case "session":
		runSession(args)
	case "agent":
		runAgent(args)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func notImplemented(cmd string) {
	fmt.Fprintf(os.Stderr,
		"interpose-sandbox %s: not yet implemented (v0.1 milestone). See docs/roadmap.md.\n", cmd)
	os.Exit(2)
}
