// Package doctor probes what a host can actually do and picks the sandbox tier
// to run. It answers one question the control plane and the CLI both need:
// given this machine, do we run a hardware-isolated microVM or the shared-kernel
// process (sandlock) tier?
//
// The rule that matters: a microVM is impossible without /dev/kvm, so a microVM
// request on a host without KVM falls back to the process tier rather than
// failing. On a plain cloud VM (no nested virt) that means sandlock, every time.
//
// Honesty note (built vs rolled out): the Firecracker microVM backend is not
// wired yet (microVMBuilt == false). The doctor still *detects* KVM capability
// so a host can be labelled correctly, but it will not *select* microVM to run
// while the backend is absent - today every selection resolves to the process
// tier. When the backend lands, flip microVMBuilt and the selection follows.
package doctor

import (
	"fmt"

	"github.com/interposed/interpose-sandbox/pkg/procbox"
)

// Tier names a sandbox isolation level.
type Tier string

const (
	TierAuto    Tier = ""        // caller has no preference: use the best available
	TierMicroVM Tier = "microvm" // hardware isolation (Firecracker + own kernel), needs /dev/kvm
	TierProcess Tier = "process" // shared-kernel: procbox (Landlock/seccomp, sandlock class)
	TierNone    Tier = "none"    // no usable backend
)

// microVMBuilt reports whether the Firecracker backend is wired. It is false
// until that work lands; see the package note.
const microVMBuilt = false

// Capability is what a host can do, as probed.
type Capability struct {
	KVM              bool     `json:"kvm"`               // /dev/kvm present and usable
	ProcessAvailable bool     `json:"process_available"` // a procbox backend runs here
	ProcessBackend   string   `json:"process_backend"`   // "landlock" | "nono" | ""
	Notes            []string `json:"notes,omitempty"`
}

// Probe inspects the current host.
func Probe() Capability {
	c := Capability{}

	ok, reason := kvmUsable()
	c.KVM = ok
	if !ok && reason != "" {
		c.Notes = append(c.Notes, "no microVM tier: "+reason)
	}

	if b, err := procbox.Current(); err == nil {
		if avail, why := b.Available(); avail {
			c.ProcessAvailable = true
			c.ProcessBackend = b.Name()
		} else if why != "" {
			c.Notes = append(c.Notes, "process tier unavailable: "+why)
		}
	} else {
		c.Notes = append(c.Notes, "process tier: "+err.Error())
	}
	return c
}

// MicroVMCapable reports whether the host *could* run a microVM (has KVM),
// independent of whether the backend is wired yet. Useful for labelling a
// workspace's ceiling.
func (c Capability) MicroVMCapable() bool { return c.KVM }

// BestTier is the strongest tier that will actually run on this host now.
func (c Capability) BestTier() Tier {
	if c.KVM && microVMBuilt {
		return TierMicroVM
	}
	if c.ProcessAvailable {
		return TierProcess
	}
	return TierNone
}

// SelectTier resolves the tier to run, given what the caller wants and what the
// host can do. The second return reports whether a requested microVM fell back
// to the process tier (so the caller/audit can say so).
//
//	want == TierAuto     -> BestTier()
//	want == TierMicroVM  -> microVM when possible, else process (fellBack), else error
//	want == TierProcess  -> process when available, else error
func SelectTier(want Tier, c Capability) (tier Tier, fellBack bool, err error) {
	switch want {
	case TierAuto:
		t := c.BestTier()
		if t == TierNone {
			return TierNone, false, errNoBackend(c)
		}
		return t, false, nil

	case TierMicroVM:
		if c.KVM && microVMBuilt {
			return TierMicroVM, false, nil
		}
		// No KVM (or backend not wired): fall back to the sandlock tier.
		if c.ProcessAvailable {
			return TierProcess, true, nil
		}
		return TierNone, false, errNoBackend(c)

	case TierProcess:
		if c.ProcessAvailable {
			return TierProcess, false, nil
		}
		return TierNone, false, errNoBackend(c)

	default:
		return TierNone, false, fmt.Errorf("doctor: unknown tier %q", want)
	}
}

func errNoBackend(c Capability) error {
	if len(c.Notes) > 0 {
		return fmt.Errorf("doctor: no usable sandbox tier (%s)", c.Notes[len(c.Notes)-1])
	}
	return fmt.Errorf("doctor: no usable sandbox tier on this host")
}
