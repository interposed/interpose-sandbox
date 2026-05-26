package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/interposehq/interpose-sandbox/internal/firecracker"
	"github.com/interposehq/interpose-sandbox/internal/kernel"
	"github.com/interposehq/interpose-sandbox/internal/rootfs"
)

// runNew implements `interpose-sandbox new <agent> [workspace]`.
//
// v0.1 scope: spawns a Firecracker microVM with interpose-kernel + Alpine
// rootfs, drops the operator into a serial-console shell. Foreground only —
// Ctrl-C terminates the VM. Background mode + ls/run/rm in v0.2.
//
// The only supported agent in v0.1 is "shell" — drop into Alpine /bin/sh.
// Agent runtimes (claude, codex, etc.) layer in v0.3.
func runNew(args []string) {
	fs := flag.NewFlagSet("interpose-sandbox new", flag.ExitOnError)
	name := fs.String("name", "", "sandbox name (default: timestamp-derived)")
	kernelTag := fs.String("kernel-image", kernel.DefaultTag,
		"interpose-kernel image tag to boot")
	memMiB := fs.Int("memory", 1024, "VM memory in MiB")
	vcpus := fs.Int("cpus", 2, "VM vCPU count")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: interpose-sandbox new <agent> [workspace] [flags]

v0.1 supported agents: shell

flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
examples:
  interpose-sandbox new shell                    # default 1GiB / 2 cpus
  interpose-sandbox new shell --memory=2048      # 2 GiB
  interpose-sandbox new shell --name=test-1
`)
	}
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	agent := fs.Arg(0)
	if agent != "shell" {
		die("v0.1 only supports the 'shell' agent; got %q. Agent runtimes ship in v0.3.", agent)
	}
	// workspace arg recorded but unused in v0.1 (virtio-fs bind-mount
	// lands in v0.2 with the broker integration).
	_ = fs.Arg(1)

	sandboxName := *name
	if sandboxName == "" {
		sandboxName = "sb-" + time.Now().UTC().Format("20060102-150405")
	}

	cacheDir, err := userCacheDir()
	if err != nil {
		die("cache dir: %v", err)
	}
	stateDir, err := userStateDir(sandboxName)
	if err != nil {
		die("state dir: %v", err)
	}

	fmt.Fprintf(os.Stderr, "==> sandbox: %s\n", sandboxName)
	fmt.Fprintf(os.Stderr, "    state:   %s\n", stateDir)
	fmt.Fprintf(os.Stderr, "    kernel:  %s\n", *kernelTag)
	fmt.Fprintln(os.Stderr)

	fmt.Fprintln(os.Stderr, "==> pulling/extracting kernel image")
	kpath, info, err := kernel.Extract(*kernelTag, cacheDir)
	if err != nil {
		die("kernel extract: %v", err)
	}
	fmt.Fprintf(os.Stderr, "    flavor=%s version=%s arch=%s\n",
		info.Flavor, info.KernelVersion, info.Arch)

	fmt.Fprintln(os.Stderr, "==> building Alpine rootfs (cached on subsequent runs)")
	rpath, err := rootfs.Build(cacheDir)
	if err != nil {
		die("rootfs build: %v", err)
	}
	fmt.Fprintf(os.Stderr, "    rootfs:  %s\n", rpath)

	cfg := firecracker.Defaults(kpath, rpath, *vcpus, *memMiB)
	// Trust the kernel image's documented boot args (`lsm=...,bpf` etc.)
	cfg.BootSource.BootArgs = info.BootArgs()

	fmt.Fprintln(os.Stderr, "==> starting Firecracker (Ctrl-C to terminate)")
	fmt.Fprintln(os.Stderr, "    once 'login:' or '#' prompt appears, you have a sandbox shell.")
	fmt.Fprintln(os.Stderr, "    try: cat /sys/kernel/security/lsm")
	fmt.Fprintln(os.Stderr, "------------------------------------------------------------")

	vm, err := firecracker.Start(cfg, stateDir)
	if err != nil {
		die("firecracker.Start: %v", err)
	}
	exitCode, err := vm.Wait()
	if err != nil {
		die("firecracker.Wait: %v", err)
	}
	fmt.Fprintf(os.Stderr,
		"\n------------------------------------------------------------\n"+
			"==> firecracker exited (code %d). State preserved at %s\n",
		exitCode, stateDir)
}

// userCacheDir returns $XDG_CACHE_HOME/interpose-sandbox (or platform
// equivalent: ~/Library/Caches on macOS, ~/.cache on Linux).
func userCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "interpose-sandbox"), nil
}

// userStateDir returns $XDG_STATE_HOME/interpose-sandbox/<name>. Falls
// back to ~/.local/state on platforms without XDG_STATE_HOME.
func userStateDir(name string) (string, error) {
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "interpose-sandbox", name), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "interpose-sandbox", name), nil
}
