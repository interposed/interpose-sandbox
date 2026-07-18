package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// sandboxHostGuideURL is the in-operator/docs explainer the probe points at when
// a host can't run sandboxes. Placeholder until the docs page ships.
const sandboxHostGuideURL = "https://interposed.ai/docs/sandbox-hosts"

// runDoctor audits whether THIS host can run sandbox microVMs and, with --json,
// emits a structured report the daemon relays to the operator (Machine.SandboxDoctor).
//
// The verdict answers the machine-level question "can I spin up a sandbox here?":
//
//	ready          every hard check passes, runtime present            → can_sandbox=true
//	setup          KVM ok, but firecracker/kernel-image not installed  → can_sandbox=true (auto-provisionable)
//	fix            hardware virt present but KVM not usable yet         → can_sandbox=false (user action)
//	unsupported    no hardware virt on a virtualized host              → can_sandbox=false (use bare metal)
//	not-applicable non-Linux host
//
// Exit codes: 0 ready · 1 setup · 2 fix · 3 unsupported · 1 not-applicable.
func runDoctor(args []string) {
	fs := flag.NewFlagSet("interpose-sandbox doctor", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the structured capability report (used by the interpose daemon)")
	_ = fs.Parse(args)

	if runtime.GOOS != "linux" {
		rep := doctorReport{
			OS: runtime.GOOS, Arch: runtime.GOARCH, Verdict: "not-applicable", CanSandbox: false,
			Summary:  "Sandboxes run on Linux hosts with KVM; this host is " + runtime.GOOS + ".",
			GuideURL: sandboxHostGuideURL,
		}
		if *asJSON {
			printJSON(rep)
			return
		}
		fmt.Println("interpose-sandbox doctor — host capability audit")
		fmt.Println("  [WARN] non-Linux host — Firecracker requires KVM and runs on Linux only.")
		fmt.Println("Verdict: not-applicable")
		os.Exit(1)
	}

	rep := auditHost()

	if *asJSON {
		printJSON(rep)
		return
	}

	fmt.Println("interpose-sandbox doctor — host capability audit")
	fmt.Println("------------------------------------------------------------")
	for _, r := range rep.Checks {
		mark := map[string]string{"OK": "[OK]  ", "WARN": "[WARN]", "FAIL": "[FAIL]", "INFO": "[INFO]"}[r.Status]
		fmt.Printf("  %s %s\n", mark, r.Detail)
	}
	fmt.Println()
	fmt.Printf("Verdict: %s — %s\n", rep.Verdict, rep.Summary)
	if !rep.CanSandbox {
		fmt.Println()
		fmt.Println("Next steps:")
		for _, r := range rep.Checks {
			if r.Status == "FAIL" && r.Fix != "" {
				fmt.Printf("  - %s\n", r.Fix)
			}
		}
		if rep.Verdict == "unsupported" {
			fmt.Printf("  - see %s\n", rep.GuideURL)
		}
	}
	os.Exit(map[string]int{"ready": 0, "setup": 1, "fix": 2, "unsupported": 3}[rep.Verdict])
}

type check struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Status    string `json:"status"`   // OK | WARN | FAIL | INFO
	Severity  string `json:"severity"` // hard | soft | tier | info
	Detail    string `json:"detail"`
	Fix       string `json:"fix,omitempty"`
	FixURL    string `json:"fix_url,omitempty"`
	FixAction string `json:"fix_action,omitempty"` // remediable via `interpose-sandbox fix <id>` (Machine.Fix)
}

// grubBPFLSMDropin is the GRUB drop-in that `fix enable-bpf-lsm` writes.
const grubBPFLSMDropin = "/etc/default/grub.d/99-bpf-lsm.cfg"

type hostFacts struct {
	IsVM        bool    `json:"is_vm"`
	Virt        string  `json:"virt"`
	CPUs        int     `json:"cpus"`
	MemGiB      float64 `json:"mem_gib"`
	DiskFreeGiB float64 `json:"disk_free_gib"`
	Kernel      string  `json:"kernel"`
	BPFLSMActive bool   `json:"bpf_lsm_active"` // bpf in the active LSM list → host enforcer can attach
	Sleepable    bool   `json:"sleepable"`      // kernel >= 6.12 → sleepable-LSM path available
	KOLoaded     bool   `json:"ko_loaded"`      // interpose.ko present → sleepable round-trip live
}

type doctorReport struct {
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	// Tier is the machine's protection level (rollup of host + settings):
	//   unprotected  bpf-lsm not active — the LSM enforcer can't attach
	//   standard     bpf-lsm active — host LSM-BPF enforcement (synchronous EPERM)
	//   strong       standard + sleepable path (kernel >= 6.12 AND interpose.ko loaded)
	//   full         strong + can host sandbox microVMs (KVM) → adds isolation
	Tier       string    `json:"tier"`
	TierReason string    `json:"tier_reason"`
	Verdict    string    `json:"verdict"`     // sandbox-hosting verdict (ready|setup|fix|unsupported)
	CanSandbox bool      `json:"can_sandbox"`
	Summary    string    `json:"summary"`
	Host       hostFacts `json:"host"`
	Checks     []check   `json:"checks"`
	GuideURL   string    `json:"guide_url,omitempty"`
}

// auditHost gathers the facts, builds the checklist, and classifies the verdict.
func auditHost() doctorReport {
	hasVirt, virtCores := cpuVirt()
	isVM, virt := detectVirt()
	kernel := kernelRelease()
	h := hostFacts{
		IsVM:         isVM,
		Virt:         virt,
		CPUs:         runtime.NumCPU(),
		MemGiB:       round1(memGiB()),
		DiskFreeGiB:  round1(diskFreeGiB(userStateRoot())),
		Kernel:       kernel,
		BPFLSMActive: bpfLSMActive(),
		Sleepable:    kernelAtLeast(kernel, 6, 12),
		KOLoaded:     interposeKoLoaded(),
	}

	checks := []check{
		checkBPFLSM(h),
		checkSleepable(h),
		checkCPUVirt(hasVirt, virtCores),
		checkKVMDevice(),
		checkFirecrackerInstalled(),
		checkInterposeKernelAvailable(),
		checkResources(h),
		virtInfo(isVM, virt),
	}
	// Only probe /dev/kvm access if the device exists (else it's redundant noise).
	if _, err := os.Stat("/dev/kvm"); err == nil {
		checks = append(checks[:4], append([]check{checkKVMReadable()}, checks[4:]...)...)
	}

	verdict, summary, can := classify(checks, h)
	tier, tierReason := classifyTier(h, can)
	return doctorReport{
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		Tier: tier, TierReason: tierReason,
		Verdict: verdict, CanSandbox: can, Summary: summary,
		Host: h, Checks: checks, GuideURL: sandboxHostGuideURL,
	}
}

// classify rolls the checklist into a single machine-level verdict.
func classify(checks []check, h hostFacts) (verdict, summary string, can bool) {
	var hardFail, virtAbsent, softFail bool
	for _, c := range checks {
		switch {
		case c.Status == "FAIL" && c.Severity == "hard":
			hardFail = true
			if c.ID == "cpu.virt" {
				virtAbsent = true
			}
		case c.Status == "FAIL" && c.Severity == "soft":
			softFail = true
		}
	}
	switch {
	case hardFail && virtAbsent && h.IsVM:
		return "unsupported", "This machine can't host sandboxes: it's a virtualized host (" + h.Virt +
			") with no nested virtualization, so /dev/kvm can't exist. Sandboxes need bare-metal or a host with nested virt enabled.", false
	case hardFail && virtAbsent:
		return "fix", "Hardware virtualization is disabled. Enable VT-x / AMD-V in the BIOS/UEFI, then re-check.", false
	case hardFail:
		return "fix", "KVM isn't usable yet — load the module and grant access, then re-check.", false
	case softFail:
		return "setup", "Can host sandboxes after a one-time setup (install Firecracker + pull the kernel image).", true
	default:
		return "ready", "Ready to host sandboxes.", true
	}
}

func checkCPUVirt(has bool, cores int) check {
	if !has {
		return check{
			ID: "cpu.virt", Label: "Hardware virtualization", Status: "FAIL", Severity: "hard",
			Detail: "no VT-x / AMD-V (vmx/svm) flags — hardware virtualization not available to this host",
			Fix:    "run on bare-metal, or enable virtualization (BIOS) / nested virt on the hypervisor",
			FixURL: sandboxHostGuideURL,
		}
	}
	return check{ID: "cpu.virt", Label: "Hardware virtualization", Status: "OK", Severity: "hard",
		Detail: fmt.Sprintf("VT-x / AMD-V present (%d cores)", cores)}
}

func checkKVMDevice() check {
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return check{
			ID: "kvm.device", Label: "/dev/kvm", Status: "FAIL", Severity: "hard",
			Detail: "/dev/kvm missing — the kernel isn't exposing KVM",
			Fix:    "sudo modprobe kvm && sudo modprobe kvm_intel (or kvm_amd); needs hardware virt",
		}
	}
	return check{ID: "kvm.device", Label: "/dev/kvm", Status: "OK", Severity: "hard", Detail: "/dev/kvm present"}
}

func checkKVMReadable() check {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return check{
			ID: "kvm.access", Label: "/dev/kvm access", Status: "FAIL", Severity: "hard",
			Detail: fmt.Sprintf("/dev/kvm not openable RW: %v", err),
			Fix:    "sudo usermod -aG kvm $USER && newgrp kvm (or run the daemon as root)",
		}
	}
	_ = f.Close()
	return check{ID: "kvm.access", Label: "/dev/kvm access", Status: "OK", Severity: "hard", Detail: "/dev/kvm openable (RW)"}
}

func checkFirecrackerInstalled() check {
	path, err := exec.LookPath("firecracker")
	if err != nil {
		return check{
			ID: "firecracker", Label: "Firecracker", Status: "FAIL", Severity: "soft",
			Detail: "firecracker binary not on PATH",
			Fix:    "install Firecracker (interpose can provision this)",
			FixURL: "https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md",
		}
	}
	out, _ := exec.Command(path, "--version").CombinedOutput()
	return check{ID: "firecracker", Label: "Firecracker", Status: "OK", Severity: "soft",
		Detail: fmt.Sprintf("firecracker at %s (%s)", path, firstLine(string(out)))}
}

// checkInterposeKernelAvailable verifies at least one interpose-kernel image is
// in the local Docker cache. Audit only — no pull side-effect.
func checkInterposeKernelAvailable() check {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return check{ID: "kernel.image", Label: "interpose-kernel image", Status: "FAIL", Severity: "soft",
			Detail: "docker not on PATH — needed to pull/cache the kernel image",
			Fix:    "install docker (interpose can provision this)"}
	}
	out, err := exec.Command(dockerPath, "images", "--format", "{{.Repository}}:{{.Tag}}").Output()
	if err != nil {
		return check{ID: "kernel.image", Label: "interpose-kernel image", Status: "WARN", Severity: "soft",
			Detail: fmt.Sprintf("`docker images` failed: %v", err), Fix: "ensure the docker daemon is running"}
	}
	var matches []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Contains(line, "interpose-kernel") && strings.Contains(line, "bpf-lsm") {
			matches = append(matches, line)
		}
	}
	if len(matches) == 0 {
		return check{ID: "kernel.image", Label: "interpose-kernel image", Status: "FAIL", Severity: "soft",
			Detail: "no interpose-kernel:*-bpf-lsm-* image cached",
			Fix:    "docker pull startaworldpeace/interpose-kernel:ubuntu-24.04-bpf-lsm-v0.1.0"}
	}
	return check{ID: "kernel.image", Label: "interpose-kernel image", Status: "OK", Severity: "soft",
		Detail: "cached: " + matches[0]}
}

func checkResources(h hostFacts) check {
	if h.MemGiB > 0 && h.MemGiB < 2 {
		return check{ID: "resources", Label: "Resources", Status: "WARN", Severity: "soft",
			Detail: fmt.Sprintf("%d vCPU · %.1f GiB RAM · %.1f GiB free — low memory for a microVM", h.CPUs, h.MemGiB, h.DiskFreeGiB),
			Fix:    "a sandbox VM defaults to ~1 GiB; leave headroom for the host + concurrent sandboxes"}
	}
	return check{ID: "resources", Label: "Resources", Status: "OK", Severity: "soft",
		Detail: fmt.Sprintf("%d vCPU · %.1f GiB RAM · %.1f GiB free", h.CPUs, h.MemGiB, h.DiskFreeGiB)}
}

func virtInfo(isVM bool, virt string) check {
	if isVM {
		return check{ID: "virt.type", Label: "Host type", Status: "INFO", Severity: "info",
			Detail: "this host is itself a virtual machine (" + virt + ")"}
	}
	return check{ID: "virt.type", Label: "Host type", Status: "INFO", Severity: "info", Detail: "bare-metal host"}
}

// checkBPFLSM / checkSleepable feed the enforcement TIER, not the sandbox verdict,
// so they carry severity "tier" (classify() ignores them; classifyTier uses the facts).
func checkBPFLSM(h hostFacts) check {
	if h.BPFLSMActive {
		return check{ID: "enforcement.lsm", Label: "BPF-LSM enforcement", Status: "OK", Severity: "tier",
			Detail: "bpf is in the active LSM list — host enforcer can attach"}
	}
	// Config written but not yet active → the enable-bpf-lsm fix ran; only a reboot is left.
	if _, err := os.Stat(grubBPFLSMDropin); err == nil {
		return check{ID: "enforcement.lsm", Label: "BPF-LSM enforcement", Status: "WARN", Severity: "tier",
			Detail:    "BPF-LSM configured in GRUB — reboot the host to activate it",
			Fix:       "reboot the host to activate bpf-lsm", FixAction: "reboot"}
	}
	return check{ID: "enforcement.lsm", Label: "BPF-LSM enforcement", Status: "FAIL", Severity: "tier",
		Detail:    "bpf not in the active LSM list — the host LSM-BPF enforcer can't attach",
		Fix:       "add bpf to the LSM boot list (writes a GRUB drop-in; reboot to apply)",
		FixAction: "enable-bpf-lsm"}
}

func checkSleepable(h hostFacts) check {
	switch {
	case h.Sleepable && h.KOLoaded:
		return check{ID: "enforcement.sleepable", Label: "Sleepable LSM", Status: "OK", Severity: "tier",
			Detail: "kernel >= 6.12 + interpose.ko loaded — sleepable round-trip live"}
	case h.Sleepable:
		return check{ID: "enforcement.sleepable", Label: "Sleepable LSM", Status: "WARN", Severity: "tier",
			Detail: "kernel supports sleepable LSM but interpose.ko not loaded — synchronous-EPERM fallback",
			Fix:    "build + load interpose.ko for the running kernel to enable the sleepable path"}
	default:
		return check{ID: "enforcement.sleepable", Label: "Sleepable LSM", Status: "WARN", Severity: "tier",
			Detail: "kernel < 6.12 — sleepable LSM unavailable (synchronous-EPERM enforcement only)"}
	}
}

// classifyTier rolls host + settings into the protection tier. PROPOSED mapping —
// adjust the thresholds to match the product definition.
func classifyTier(h hostFacts, canSandbox bool) (tier, reason string) {
	if !h.BPFLSMActive {
		return "unprotected", "bpf isn't in the active LSM list — the host enforcer can't attach. Enable it to reach 'standard'."
	}
	strong := h.Sleepable && h.KOLoaded
	switch {
	case canSandbox:
		return "full", "host LSM-BPF enforcement + isolated sandbox microVMs (KVM)."
	case strong:
		return "strong", "host LSM-BPF enforcement with the sleepable path (interpose.ko on a >= 6.12 kernel)."
	default:
		return "standard", "host LSM-BPF enforcement (synchronous EPERM). Add interpose.ko on a >= 6.12 kernel for 'strong', or KVM for 'full'."
	}
}

// --- host fact helpers ---

func bpfLSMActive() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, s := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if s == "bpf" {
			return true
		}
	}
	return false
}

// kernelAtLeast parses a release like "7.0.0-15-generic" and compares maj.min.
func kernelAtLeast(release string, maj, min int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	kmaj, err1 := strconv.Atoi(parts[0])
	kmin, err2 := strconv.Atoi(strings.SplitN(parts[1], "-", 2)[0])
	if err1 != nil || err2 != nil {
		return false
	}
	if kmaj != maj {
		return kmaj > maj
	}
	return kmin >= min
}

func interposeKoLoaded() bool {
	if b, err := os.ReadFile("/proc/modules"); err == nil && strings.Contains(string(b), "interpose ") {
		return true
	}
	if _, err := os.Stat("/sys/kernel/security/interpose"); err == nil {
		return true
	}
	return false
}

func cpuVirt() (bool, int) {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false, 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "flags") || strings.HasPrefix(line, "Features") {
			if strings.Contains(line, " vmx") || strings.Contains(line, " svm") {
				n++
			}
		}
	}
	return n > 0, n
}

func detectVirt() (bool, string) {
	if p, err := exec.LookPath("systemd-detect-virt"); err == nil {
		out, _ := exec.Command(p).Output() // exits 1 on "none" but still prints it
		v := strings.TrimSpace(string(out))
		if v == "" || v == "none" {
			return false, "none"
		}
		return true, v
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil && strings.Contains(string(b), "hypervisor") {
		return true, "vm"
	}
	return false, "none"
}

func memGiB() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			if f := strings.Fields(line); len(f) >= 2 {
				kb, _ := strconv.ParseFloat(f[1], 64)
				return kb / 1024 / 1024
			}
		}
	}
	return 0
}

func diskFreeGiB(path string) float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return float64(uint64(st.Bavail)*uint64(st.Bsize)) / (1024 * 1024 * 1024)
}

func userStateRoot() string {
	if d, err := os.UserHomeDir(); err == nil && d != "" {
		return d
	}
	return "/"
}

func kernelRelease() string {
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
