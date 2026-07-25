package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/interposehq/interpose-sandbox/pkg/procbox"
)

// wrapUsage documents the free, unprivileged process-tier CLI — the "Instant"
// tier's entry point. No account, no daemon, no VM.
const wrapUsage = `interpose-sandbox wrap — run a command in an instant process sandbox

  interpose-sandbox wrap [flags] -- <command> [args...]

The command runs under a kernel-native allow-list (Landlock on Linux, Seatbelt
on macOS): it can work in the current directory but cannot read your secrets
(~/.ssh, cloud creds, keychains) or write outside its allowed dirs. The sandbox
is unprivileged and inherited by every child process.

Flags:
  --rw <dir>        add a read-write directory (repeatable; default: cwd)
  --ro <dir>        add a read-only directory (repeatable)
  --net <mode>      off | all   (default: off)
  --runtime <name>  auto-allow a toolchain's paths: node|python|go|rust (repeatable)
  --profile <file>  load a JSON PolicySpec instead of the flags above
  --print-policy    print the resolved policy and exit (no run)

Examples:
  interpose-sandbox wrap -- claude
  interpose-sandbox wrap --net all --runtime node -- npm test
`

func runWrap(args []string) int {
	// Split at "--": our flags before, the command after.
	cmdStart := -1
	for i, a := range args {
		if a == "--" {
			cmdStart = i
			break
		}
	}
	var flags []string
	var command []string
	if cmdStart >= 0 {
		flags = args[:cmdStart]
		command = args[cmdStart+1:]
	} else {
		flags = args
	}

	policy := procbox.PolicySpec{
		FS:  procbox.FSPolicy{DenyDefault: true},
		Net: procbox.NetPolicy{Mode: procbox.NetOff},
	}
	var profileFile string
	printPolicy := false

	for i := 0; i < len(flags); i++ {
		switch flags[i] {
		case "-h", "--help":
			fmt.Print(wrapUsage)
			return 0
		case "--rw":
			i++
			policy.FS.RW = append(policy.FS.RW, need(flags, i, "--rw"))
		case "--ro":
			i++
			policy.FS.RO = append(policy.FS.RO, need(flags, i, "--ro"))
		case "--net":
			i++
			policy.Net.Mode = procbox.NetMode(need(flags, i, "--net"))
		case "--runtime":
			i++
			policy.Runtimes = append(policy.Runtimes, need(flags, i, "--runtime"))
		case "--profile":
			i++
			profileFile = need(flags, i, "--profile")
		case "--print-policy":
			printPolicy = true
		default:
			fmt.Fprintf(os.Stderr, "wrap: unknown flag %q\n\n%s", flags[i], wrapUsage)
			return 2
		}
	}

	if profileFile != "" {
		raw, err := os.ReadFile(profileFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wrap: read profile: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(raw, &policy); err != nil {
			fmt.Fprintf(os.Stderr, "wrap: parse profile: %v\n", err)
			return 1
		}
	}
	// Default the RW set to the current directory when nothing was given.
	if len(policy.FS.RW) == 0 {
		if cwd, err := os.Getwd(); err == nil {
			policy.FS.RW = []string{cwd}
		}
	}

	if printPolicy {
		out, _ := json.MarshalIndent(policy, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if len(command) == 0 {
		fmt.Fprintf(os.Stderr, "wrap: no command — put it after `--`\n\n%s", wrapUsage)
		return 2
	}

	code, err := wrapExec(policy, command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wrap: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func need(flags []string, i int, name string) string {
	if i >= len(flags) {
		fmt.Fprintf(os.Stderr, "wrap: %s needs a value\n", name)
		os.Exit(2)
	}
	return flags[i]
}
