// Package procbox is interpose's process-tier sandbox — the "Instant"
// enforcement flavor (diagnostic level: process). It applies a kernel-native
// allow-list to the current process before exec: Landlock on Linux/WSL2,
// Seatbelt on macOS. Unprivileged, irrevocable once applied, inherited by
// every child. No daemon, no VM.
//
// This is flavor #2 of interpose-sandbox, beside the Firecracker microVM
// ("Sealed") flavor. It is strictly additive: nothing here touches the
// microVM path or the daemon's BPF-LSM ("Ambient") enforcer.
//
// The package owns ONE interface (Backend) with per-OS implementations
// behind build tags. Exactly one of those files may import an external
// engine (macOS Seatbelt via nono-go); everything else is ours.
package procbox

// PolicySpec is our sandbox vocabulary — one schema across every backend and
// every rung. Backends translate it to their native form (a Landlock ruleset,
// a Seatbelt profile). Keep it small: richer policy lives in the daemon's
// engine, which the governed tier layers on top.
type PolicySpec struct {
	// FS is the filesystem allow-list. Everything not listed is denied when
	// DenyDefault is true (the norm).
	FS FSPolicy `json:"fs"`

	// Net controls network egress.
	Net NetPolicy `json:"net"`

	// Runtimes names language toolchains whose standard paths (binaries,
	// caches, module dirs) should be auto-allowed read access — e.g.
	// "node", "python", "go", "rust". Backends expand these to concrete
	// paths so profiles stay portable and short.
	Runtimes []string `json:"runtimes,omitempty"`

	// Approval is the opt-in hardware-root mode (none | tap-to-start |
	// supervised). Enforced by the caller/daemon, not the kernel backend;
	// recorded here so it rides the policy and its audit hash.
	Approval Approval `json:"approval,omitempty"`

	// Report decides behavior when the host can't honor the full policy
	// (e.g. an older Landlock ABI): "strict" refuses, "best-effort" applies
	// the strongest available subset and records the downgrade.
	Report ReportMode `json:"report,omitempty"`
}

// FSPolicy is a read/read-write allow-list of paths.
type FSPolicy struct {
	RW          []string `json:"rw,omitempty"`  // read + write (+ dir ops)
	RO          []string `json:"ro,omitempty"`  // read-only
	DenyDefault bool     `json:"deny_default"`  // deny everything not listed
}

// NetMode is the network posture.
type NetMode string

const (
	NetOff     NetMode = "off"     // no network
	NetAll     NetMode = "all"     // unrestricted
	NetTCP     NetMode = "tcp"     // scoped TCP (Landlock ABI4+/kernel ≥6.7); else best-effort
	NetDomains NetMode = "domains" // allow only Domains (requires a userspace proxy; governed tier)
)

// NetPolicy controls egress.
type NetPolicy struct {
	Mode         NetMode  `json:"mode"`
	ConnectPorts []int    `json:"connect_ports,omitempty"`
	BindPorts    []int    `json:"bind_ports,omitempty"`
	Domains      []string `json:"domains,omitempty"`
	// ProxyPort is the 127.0.0.1 port of the supervised CONNECT proxy that a
	// NetDomains sandbox must transit; the kernel rule is bound to it.
	ProxyPort int `json:"proxy_port,omitempty"`
}

// Approval is the opt-in hardware-root level.
type Approval string

const (
	ApprovalNone       Approval = ""            // no hardware gate
	ApprovalTapToStart Approval = "tap-to-start" // operator tap before the sandbox launches (all OS)
	ApprovalSupervised Approval = "supervised"   // + mid-run tap-gated access (Linux seccomp-notify)
)

// ReportMode chooses refuse-vs-degrade on a host that can't honor the policy.
type ReportMode string

const (
	ReportStrict     ReportMode = "strict"
	ReportBestEffort ReportMode = "best-effort" // default
)

func (p PolicySpec) reportMode() ReportMode {
	if p.Report == ReportStrict {
		return ReportStrict
	}
	return ReportBestEffort
}
