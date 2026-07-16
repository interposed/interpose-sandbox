package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/interposehq/interpose-sandbox/internal/firecracker"
	"github.com/interposehq/interpose-sandbox/internal/kernel"
	"github.com/interposehq/interpose-sandbox/internal/registry"
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
	profile := fs.String("profile", "", "trust/quarantine profile to seal into the sandbox")
	workspace := fs.String("workspace", "", "workspace: repo @ branch (recorded)")
	asJSON := fs.Bool("json", false, "boot detached, register, and print JSON (used by the interpose daemon)")
	rootfsImage := fs.String("rootfs-image", rootfs.DefaultAgentImage, "agent OCI image to boot (empty → build a shell-only Alpine rootfs)")
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

	// Detached/registered path — how the interpose daemon spins a sandbox.
	// Boots firecracker in the background, records it in the registry, and
	// prints the sandbox JSON. Agents are added afterward with `exec`.
	if *asJSON {
		sbName := *name
		if sbName == "" {
			sbName = "sb-" + time.Now().UTC().Format("20060102-150405")
		}
		sb, err := bootDetached(sbName, *profile, *workspace, *rootfsImage)
		if err != nil {
			die("boot: %v", err)
		}
		reg := openRegistry()
		if err := reg.Add(sb); err != nil {
			die("registry: %v", err)
		}
		printJSON(toWire(sb))
		return
	}

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

// bootDetached boots a background sandbox VM and returns its registry entry.
// KVM-gated: firecracker only actually boots on a host with /dev/kvm. Shared by
// `new --json` and `fork`.
func bootDetached(name, profile, workspace, imageTag string) (registry.Sandbox, error) {
	cacheDir, err := userCacheDir()
	if err != nil {
		return registry.Sandbox{}, err
	}
	root, err := sandboxStateRoot()
	if err != nil {
		return registry.Sandbox{}, err
	}
	stateDir := filepath.Join(root, name)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return registry.Sandbox{}, err
	}
	kpath, info, err := kernel.Extract(kernel.DefaultTag, cacheDir)
	if err != nil {
		return registry.Sandbox{}, fmt.Errorf("kernel extract: %w", err)
	}
	// Base rootfs: the published agent image (interpose + pi + guest-agent baked
	// in) when a tag is set, else a runtime shell-only Alpine build.
	var base string
	if imageTag != "" {
		base, err = rootfs.AgentRootfs(imageTag, cacheDir)
		if err != nil {
			return registry.Sandbox{}, fmt.Errorf("agent image: %w", err)
		}
	} else {
		base, err = rootfs.Build(cacheDir)
		if err != nil {
			return registry.Sandbox{}, fmt.Errorf("rootfs build: %w", err)
		}
	}
	// Per-sandbox writable rootfs copy: each VM must own its ext4 (two VMs
	// writing one image corrupts it), and fork copies this file.
	sbxRootfs := filepath.Join(stateDir, "rootfs.ext4")
	if err := copyFile(base, sbxRootfs); err != nil {
		return registry.Sandbox{}, fmt.Errorf("copy rootfs: %w", err)
	}
	cfg := firecracker.Defaults(kpath, sbxRootfs, 2, 1024)
	cfg.BootSource.BootArgs = info.BootArgs()
	// vsock: the guest-agent (interpose-guest) listens inside the VM; the host
	// reaches it through this UDS to launch agents + stream their PTYs.
	vsockUDS := filepath.Join(stateDir, "vsock.sock")
	cfg.Vsock = &firecracker.Vsock{GuestCID: 3, UDSPath: vsockUDS}
	if workspace != "" {
		attachWorkspace(&cfg, stateDir, workspace)
	}
	d, err := firecracker.StartDetached(cfg, stateDir)
	if err != nil {
		return registry.Sandbox{}, err
	}
	return registry.Sandbox{
		ID: newID("sbx"), Name: name, Status: "ready", Profile: profile, Workspace: workspace,
		StateDir: d.StateDir, APISock: d.APISock, VsockUDS: vsockUDS, PID: d.PID, CreatedAt: time.Now(),
		Agents: []registry.Agent{},
	}, nil
}

// forkVM branches a running sandbox via Firecracker snapshot: pause the source,
// snapshot it, resume the source, copy its rootfs, then boot a fresh firecracker
// and load the snapshot. The fork inherits the source's live memory + agents —
// the "branch a running computer" trick.
func forkVM(src registry.Sandbox, name string) (registry.Sandbox, error) {
	root, err := sandboxStateRoot()
	if err != nil {
		return registry.Sandbox{}, err
	}
	stateDir := filepath.Join(root, name)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return registry.Sandbox{}, err
	}
	snapPath := filepath.Join(stateDir, "snapshot.state")
	memPath := filepath.Join(stateDir, "snapshot.mem")

	// 1. Pause source → snapshot → resume source (the source keeps running).
	if err := firecracker.Pause(src.APISock); err != nil {
		return registry.Sandbox{}, fmt.Errorf("pause source: %w", err)
	}
	if err := firecracker.CreateSnapshot(src.APISock, snapPath, memPath); err != nil {
		_ = firecracker.Resume(src.APISock)
		return registry.Sandbox{}, fmt.Errorf("snapshot: %w", err)
	}
	if err := firecracker.Resume(src.APISock); err != nil {
		return registry.Sandbox{}, fmt.Errorf("resume source: %w", err)
	}

	// 2. Copy the source rootfs so the fork writes its own ext4.
	if src.StateDir != "" {
		if err := copyFile(filepath.Join(src.StateDir, "rootfs.ext4"), filepath.Join(stateDir, "rootfs.ext4")); err != nil {
			return registry.Sandbox{}, fmt.Errorf("copy rootfs: %w", err)
		}
	}

	// 3. Boot a bare firecracker and load the snapshot into it.
	d, err := firecracker.StartBare(stateDir)
	if err != nil {
		return registry.Sandbox{}, err
	}
	if err := firecracker.LoadSnapshot(d.APISock, snapPath, memPath, true); err != nil {
		return registry.Sandbox{}, fmt.Errorf("load snapshot: %w", err)
	}
	return registry.Sandbox{
		ID: newID("sbx"), Name: name, Status: "ready", Profile: src.Profile, Workspace: src.Workspace,
		StateDir: stateDir, APISock: d.APISock, PID: d.PID, CreatedAt: time.Now(),
		Agents: append([]registry.Agent(nil), src.Agents...), // inherit live agents
	}, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// attachWorkspace gives the sandbox a writable /workspace by attaching a raw
// block device the guest formats + mounts on boot.
//
// Firecracker has NO virtio-fs — it ships a deliberately minimal device set
// (block, net, vsock, balloon, rng), so a live host bind-mount isn't available.
// The workspace is therefore a block device: the agent clones/works in
// /workspace inside the VM, and results leave via git push or a copy-out on
// destroy. The guest rootfs init (internal/rootfs) mkfs+mounts /dev/vdb at
// /workspace on first boot.
func attachWorkspace(cfg *firecracker.VMConfig, stateDir, workspace string) {
	wsImg := filepath.Join(stateDir, "workspace.ext4")
	if f, err := os.Create(wsImg); err == nil {
		_ = f.Truncate(2 << 30) // 2 GiB sparse; the guest formats it
		_ = f.Close()
	}
	cfg.Drives = append(cfg.Drives, firecracker.Drive{
		DriveID:      "workspace",
		PathOnHost:   wsImg,
		IsRootDevice: false,
		IsReadOnly:   false,
	})
}
