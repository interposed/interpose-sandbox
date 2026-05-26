package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// runDoctor audits the Firecracker host prerequisites: KVM device,
// firecracker binary on PATH, user has /dev/kvm access (i.e. is in
// the `kvm` group or running as root), and the interpose-kernel image
// is available locally or pullable.
//
// Companion to `interpose doctor --sandbox`, which audits the guest
// kernel from INSIDE the sandbox. This runs on the HOST before spinning
// any sandbox up.
//
// Exit codes match the other tools in this stack:
//
//	0 = ready              (every required check passes)
//	1 = patchable          (Warns but no Fails — small runtime tweaks)
//	2 = rebuild-required   (one or more Fails — install/fix needed)
func runDoctor(args []string) {
	fs := flag.NewFlagSet("interpose-sandbox doctor", flag.ExitOnError)
	_ = fs.Parse(args)

	if runtime.GOOS != "linux" {
		fmt.Println("interpose-sandbox doctor — host capability audit")
		fmt.Println("------------------------------------------------------------")
		fmt.Printf("  [WARN] non-Linux host (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
		fmt.Println("         Firecracker requires KVM and runs on Linux only.")
		fmt.Println("         On macOS, use Lima (cd ../interpose && make fresh-vm) — same kernel image.")
		fmt.Println()
		fmt.Println("Verdict: not-applicable (Firecracker is Linux-only)")
		os.Exit(1)
	}

	results := []check{
		checkKVMDevice(),
		checkKVMReadable(),
		checkFirecrackerInstalled(),
		checkInterposeKernelAvailable(),
		checkInterposeBinaryAvailable(),
	}

	fmt.Println("interpose-sandbox doctor — host capability audit")
	fmt.Println("------------------------------------------------------------")
	for _, r := range results {
		switch r.status {
		case "OK":
			fmt.Printf("  [OK]   %s\n", r.detail)
		case "WARN":
			fmt.Printf("  [WARN] %s\n", r.detail)
		case "FAIL":
			fmt.Printf("  [FAIL] %s\n", r.detail)
		}
	}

	var (
		fails int
		warns int
	)
	for _, r := range results {
		switch r.status {
		case "FAIL":
			fails++
		case "WARN":
			warns++
		}
	}

	fmt.Println()
	switch {
	case fails > 0:
		fmt.Println("Verdict: install-required")
		fmt.Println()
		fmt.Println("Next steps:")
		for _, r := range results {
			if r.status == "FAIL" && r.fix != "" {
				fmt.Printf("  - %s\n", r.fix)
			}
		}
		os.Exit(2)
	case warns > 0:
		fmt.Println("Verdict: patchable")
		fmt.Println()
		fmt.Println("Recommended:")
		for _, r := range results {
			if r.status == "WARN" && r.fix != "" {
				fmt.Printf("  - %s\n", r.fix)
			}
		}
		os.Exit(1)
	default:
		fmt.Println("Verdict: ready")
	}
}

type check struct {
	status string // "OK" | "WARN" | "FAIL"
	detail string
	fix    string
}

func checkKVMDevice() check {
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return check{
			status: "FAIL",
			detail: "/dev/kvm missing — kernel doesn't expose KVM",
			fix:    "ensure the host has KVM enabled (modprobe kvm + kvm_intel|kvm_amd; CONFIG_KVM=y in kernel build)",
		}
	}
	return check{status: "OK", detail: "/dev/kvm present"}
}

func checkKVMReadable() check {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return check{
			status: "FAIL",
			detail: fmt.Sprintf("/dev/kvm not openable for RW: %v", err),
			fix:    "add your user to the 'kvm' group: sudo usermod -aG kvm $USER && newgrp kvm",
		}
	}
	_ = f.Close()
	return check{status: "OK", detail: "/dev/kvm openable (RW)"}
}

func checkFirecrackerInstalled() check {
	path, err := exec.LookPath("firecracker")
	if err != nil {
		return check{
			status: "FAIL",
			detail: "firecracker binary not on PATH",
			fix:    "install Firecracker: see https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md",
		}
	}
	out, _ := exec.Command(path, "--version").CombinedOutput()
	return check{
		status: "OK",
		detail: fmt.Sprintf("firecracker at %s (%s)", path, firstLine(string(out))),
	}
}

func checkInterposeKernelAvailable() check {
	// Stub: in v0.1 this consults `docker images` or the local
	// $XDG_CACHE_HOME/interpose-sandbox/kernels/ directory. For now,
	// emit a WARN so doctor still reports a sensible verdict during scaffold.
	return check{
		status: "WARN",
		detail: "interpose-kernel image: presence check not yet implemented",
		fix:    "v0.1: will check `docker images | grep interpose-kernel` and offer to pull",
	}
}

func checkInterposeBinaryAvailable() check {
	if _, err := exec.LookPath("interpose"); err == nil {
		return check{status: "OK", detail: "interpose binary on PATH (will be embedded in sandbox rootfs)"}
	}
	return check{
		status: "WARN",
		detail: "interpose binary not on PATH — sandboxes will use whichever interpose is in the kernel image",
		fix:    "install interpose: go install github.com/interposehq/interpose/cmd/interpose@latest",
	}
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}
