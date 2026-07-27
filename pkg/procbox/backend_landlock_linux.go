//go:build linux

package procbox

import (
	"fmt"

	"github.com/landlock-lsm/go-landlock/landlock"
	lsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// The Linux fallback is OURS — pure-Go go-landlock (BSD), no external engine.
// It's the CGO-disabled / nono-unavailable path (priority below the nono
// backend), and the sovereign hedge. Real deny-default allow-list via the
// kernel; sits beside the daemon's BPF-LSM path and never touches it.
func init() { register(&landlockBackend{}, 50) }

type landlockBackend struct{}

func (b *landlockBackend) Name() string { return "landlock" }

func (b *landlockBackend) Available() (bool, string) {
	// A tiny probe: an empty best-effort restriction succeeds on any kernel
	// (it degrades to a no-op below 5.13), so we instead report the ABI the
	// host actually supports. abiLevel() returns 0 when Landlock is absent.
	if abiLevel() == 0 {
		return false, "kernel has no Landlock support (need >= 5.13)"
	}
	return true, ""
}

func (b *landlockBackend) Apply(p PolicySpec) (Result, error) {
	abi := abiLevel()
	res := Result{Backend: b.Name(), ABI: abi}
	if abi == 0 {
		if p.reportMode() == ReportStrict {
			return res, fmt.Errorf("landlock: unsupported kernel and report=strict")
		}
		res.Degraded = true
		res.Notes = append(res.Notes, "no Landlock on this kernel — process NOT sandboxed")
		return res, nil // best-effort: nothing applied, honestly reported
	}

	// Filesystem rules. Runtime groups expand to RO paths.
	var rules []landlock.Rule
	roPaths := append(existing(p.FS.RO), runtimePaths(p.Runtimes)...)
	if len(roPaths) > 0 {
		rules = append(rules, landlock.RODirs(dirsOnly(roPaths)...))
		if files := filesOnly(roPaths); len(files) > 0 {
			rules = append(rules, landlock.ROFiles(files...))
		}
	}
	if rw := existing(p.FS.RW); len(rw) > 0 {
		rules = append(rules, landlock.RWDirs(dirsOnly(rw)...))
		if files := filesOnly(rw); len(files) > 0 {
			rules = append(rules, landlock.RWFiles(files...))
		}
	}

	// Config: best-effort unless strict. Net handled/scoped only when asked.
	cfg := landlock.V9
	if p.reportMode() != ReportStrict {
		cfg = cfg.BestEffort()
	}

	if err := cfg.RestrictPaths(rules...); err != nil {
		if p.reportMode() == ReportStrict {
			return res, fmt.Errorf("landlock: restrict paths: %w", err)
		}
		res.Degraded = true
		res.Notes = append(res.Notes, "path restriction degraded: "+err.Error())
	}

	// Network (Landlock ABI4+/kernel >= 6.7). scoped TCP; "off" means no
	// allowed ports (deny all TCP); "all" skips net restriction entirely.
	switch p.Net.Mode {
	case NetAll, "":
		// no network restriction
	case NetOff, NetTCP:
		var netRules []landlock.Rule
		if p.Net.Mode == NetTCP {
			for _, port := range p.Net.ConnectPorts {
				netRules = append(netRules, landlock.ConnectTCP(uint16(port)))
			}
			for _, port := range p.Net.BindPorts {
				netRules = append(netRules, landlock.BindTCP(uint16(port)))
			}
		}
		if err := cfg.RestrictNet(netRules...); err != nil {
			if p.reportMode() == ReportStrict {
				return res, fmt.Errorf("landlock: restrict net: %w", err)
			}
			res.Degraded = true
			res.Notes = append(res.Notes, "network restriction unavailable (needs kernel >= 6.7): "+err.Error())
		}
	case NetDomains:
		// Domain filtering needs a userspace proxy (governed tier), not the
		// kernel backend. Here we can only deny/allow at the port layer.
		res.Notes = append(res.Notes, "net=domains needs the governed-tier proxy; kernel backend applied no domain filter")
	}

	return res, nil
}

// abiLevel returns the Landlock ABI version the host kernel supports, or 0
// when Landlock is unavailable. Uses the kernel's own LANDLOCK_CREATE_RULESET
// version query (the canonical probe).
func abiLevel() int {
	v, err := lsyscall.LandlockGetABIVersion()
	if err != nil || v < 0 {
		return 0
	}
	return v
}
