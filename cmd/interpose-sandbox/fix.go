package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runFix applies a named host remediation. The interpose daemon invokes it as
// `interpose-sandbox fix <action> --json` behind the tap-gated Machine.Fix
// mutation. Actions are deliberately narrow + declared — never a generic shell.
//
//	enable-bpf-lsm  write a GRUB drop-in adding `bpf` to lsm= (reboot to apply)
//	reboot          reboot the host (scheduled so the RPC can return first)
func runFix(args []string) {
	fs := flag.NewFlagSet("interpose-sandbox fix", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the structured result (used by the interpose daemon)")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		die("usage: interpose-sandbox fix <enable-bpf-lsm|reboot> [--json]")
	}
	res := applyFix(fs.Arg(0))
	if *asJSON {
		printJSON(res)
		if !res.OK {
			os.Exit(1)
		}
		return
	}
	if res.OK {
		fmt.Println(res.Message)
		if res.RebootRequired {
			fmt.Println("Reboot the host to activate.")
		}
		return
	}
	die("%s", res.Error)
}

type fixResult struct {
	OK             bool   `json:"ok"`
	Action         string `json:"action"`
	Message        string `json:"message,omitempty"`
	RebootRequired bool   `json:"reboot_required"`
	Error          string `json:"error,omitempty"`
}

func applyFix(action string) fixResult {
	switch action {
	case "enable-bpf-lsm":
		return fixEnableBPFLSM()
	case "reboot":
		return fixReboot()
	default:
		return fixResult{Action: action, Error: "unknown fix action: " + action}
	}
}

// fixEnableBPFLSM writes a GRUB drop-in that appends the CURRENT active LSM list
// plus `bpf` to lsm=, regenerates GRUB, then schedules a reboot — BPF-LSM only
// takes effect after one, so the operator exposes this as a single confirmed
// "Enable BPF-LSM & reboot" action.
func fixEnableBPFLSM() fixResult {
	list := strings.TrimSpace(readFile("/sys/kernel/security/lsm"))
	if list == "" {
		list = "lockdown,capability,landlock,yama,apparmor"
	}
	if !strings.Contains(","+list+",", ",bpf,") {
		list += ",bpf"
	}
	content := fmt.Sprintf("GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE_LINUX_DEFAULT lsm=%s\"\n", list)
	if err := os.MkdirAll("/etc/default/grub.d", 0o755); err != nil {
		return fixResult{Action: "enable-bpf-lsm", Error: "mkdir grub.d: " + err.Error()}
	}
	if err := os.WriteFile(grubBPFLSMDropin, []byte(content), 0o644); err != nil {
		return fixResult{Action: "enable-bpf-lsm", Error: "write drop-in: " + err.Error()}
	}
	gen := "update-grub"
	if _, err := exec.LookPath(gen); err != nil {
		gen = "grub2-mkconfig" // non-Debian fallback
	}
	if out, err := exec.Command(gen).CombinedOutput(); err != nil {
		return fixResult{Action: "enable-bpf-lsm", Error: gen + ": " + strings.TrimSpace(string(out)) + ": " + err.Error()}
	}
	scheduleReboot()
	return fixResult{OK: true, Action: "enable-bpf-lsm",
		Message: "GRUB updated: lsm=" + list + " — rebooting to activate BPF-LSM.", RebootRequired: true}
}

// scheduleReboot triggers a reboot a few seconds out so the Machine.Fix RPC can
// return success before the host (and daemon) go down.
func scheduleReboot() {
	if err := exec.Command("systemd-run", "--on-active=3s", "systemctl", "reboot").Run(); err != nil {
		// fallback if systemd-run is unavailable
		_ = exec.Command("sh", "-c", "(sleep 3; systemctl reboot || reboot) >/dev/null 2>&1 &").Start()
	}
}

func fixReboot() fixResult {
	scheduleReboot()
	return fixResult{OK: true, Action: "reboot", Message: "Rebooting the host…"}
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}
