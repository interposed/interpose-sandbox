//go:build (darwin || linux) && cgo

package procbox

import (
	"fmt"

	nono "github.com/always-further/nono-go"
)

// The nono-go backend is the PRIMARY process-tier engine: nono's kernel core
// applies a correct deny-default allow-list — Landlock on Linux/WSL2,
// Seatbelt (sandbox_init) on macOS — the part that's impractical to hand-roll
// on modern macOS. It is the ONLY file that imports the external engine
// (blast-radius: a CI lint rule fails the build if any other file does).
//
// Our value lives ABOVE this: the policy schema, profiles, hardware-tap
// approvals, identity, and signed audit — "they sandbox, we govern."
func init() { register(&nonoBackend{}, 100) }

type nonoBackend struct{}

func (b *nonoBackend) Name() string { return "nono" }

func (b *nonoBackend) Available() (bool, string) {
	if !nono.IsSupported() {
		info := nono.SupportInfo()
		return false, fmt.Sprintf("nono unsupported on this host (%+v)", info)
	}
	return true, ""
}

func (b *nonoBackend) Apply(p PolicySpec) (Result, error) {
	res := Result{Backend: b.Name()}
	caps := nono.New()
	defer caps.Close()

	// Filesystem: deny-default is nono's model — we only add allows. First the
	// system baseline (read-only paths every process needs to launch), then
	// runtime groups, then the caller's declared paths. Missing paths are
	// dropped (nono/Landlock reject rulesets naming absent paths).
	sysRO, sysFiles, sysRW := systemBaseline()
	for _, path := range existing(sysRO) {
		if err := caps.AllowPath(path, nono.AccessRead); err != nil {
			return res, fmt.Errorf("nono: system baseline %s: %w", path, err)
		}
	}
	for _, path := range existing(sysFiles) {
		if err := caps.AllowFile(path, nono.AccessRead); err != nil {
			res.Notes = append(res.Notes, "baseline file skipped: "+path)
		}
	}
	for _, path := range existing(sysRW) {
		if err := allowOne(caps, path, nono.AccessReadWrite); err != nil {
			res.Notes = append(res.Notes, "baseline rw skipped: "+path)
		}
	}
	roPaths := append(existing(p.FS.RO), runtimePaths(p.Runtimes)...)
	for _, path := range roPaths {
		if err := allowOne(caps, path, nono.AccessRead); err != nil {
			return res, err
		}
	}
	for _, path := range existing(p.FS.RW) {
		if err := allowOne(caps, path, nono.AccessReadWrite); err != nil {
			return res, err
		}
	}

	// Network.
	switch p.Net.Mode {
	case NetOff:
		if err := caps.SetNetworkMode(nono.NetworkBlocked); err != nil {
			return res, fmt.Errorf("nono: set network blocked: %w", err)
		}
	case NetDomains:
		// Domain filtering runs through nono's proxy (governed tier wires the
		// proxy + port); here we set proxy-only so egress must transit it.
		if err := caps.SetNetworkMode(nono.NetworkProxyOnly); err != nil {
			return res, fmt.Errorf("nono: set network proxy-only: %w", err)
		}
		res.Notes = append(res.Notes, "net=domains: proxy-only set; the governed tier supplies the L7 proxy")
	case NetAll, "", NetTCP:
		if err := caps.SetNetworkMode(nono.NetworkAllowAll); err != nil {
			return res, fmt.Errorf("nono: set network: %w", err)
		}
		if p.Net.Mode == NetTCP {
			res.Notes = append(res.Notes, "net=tcp: per-port scoping is a governed-tier feature; allowed outbound here")
		}
	}

	// Apply — irreversible. This process and all children are now bound.
	if err := nono.Apply(caps); err != nil {
		return res, fmt.Errorf("nono: apply: %w", err)
	}
	return res, nil
}

// allowOne adds a path with the right granularity (dir vs file) — nono has
// AllowPath (dirs, subtree) and AllowFile (single file).
func allowOne(caps *nono.CapabilitySet, path string, mode nono.AccessMode) error {
	if isDir(path) {
		if err := caps.AllowPath(path, mode); err != nil {
			return fmt.Errorf("nono: allow dir %s: %w", path, err)
		}
		return nil
	}
	if err := caps.AllowFile(path, mode); err != nil {
		return fmt.Errorf("nono: allow file %s: %w", path, err)
	}
	return nil
}
