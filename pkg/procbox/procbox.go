package procbox

import (
	"fmt"
	"runtime"
	"sort"
)

// Result reports what a backend actually applied — including any downgrade
// from the requested policy (best-effort mode). It rides into the daemon's
// audit as the sandbox.applied entry.
type Result struct {
	Backend  string   // "nono" | "landlock"
	ABI      int      // Landlock ABI level applied (0 for Seatbelt/nono-mac)
	Degraded bool     // some requested capability wasn't available
	Notes    []string // human-readable downgrade notes
}

// Backend applies a PolicySpec to the current process. The apply is
// irrevocable — after Apply returns nil, the process and all its children are
// bound by the allow-list at the kernel level (deny-default), and the
// restriction can only be tightened, never loosened.
type Backend interface {
	Name() string
	// Available reports whether this backend can run on the current host,
	// with a reason when it can't (so the doctor can explain).
	Available() (ok bool, reason string)
	// Apply restricts the current process to the policy.
	Apply(p PolicySpec) (Result, error)
}

// Registry: backends self-register in init() with a priority. Current()
// returns the highest-priority Available backend, so the strong engine
// (nono-go, priority 100) wins when present and the pure-Go go-landlock
// fallback (priority 50) covers CGO-disabled Linux builds.
type registered struct {
	b        Backend
	priority int
}

var backends []registered

func register(b Backend, priority int) {
	backends = append(backends, registered{b, priority})
	sort.SliceStable(backends, func(i, j int) bool { return backends[i].priority > backends[j].priority })
}

// Current returns the best available process-tier backend for this host, or an
// error when none can run (the doctor renders that as "Unmanaged").
func Current() (Backend, error) {
	for _, r := range backends {
		if ok, _ := r.b.Available(); ok {
			return r.b, nil
		}
	}
	// Surface the most specific reason if a backend exists but isn't usable.
	if len(backends) > 0 {
		_, reason := backends[0].b.Available()
		return nil, fmt.Errorf("procbox: no usable backend on %s/%s: %s", runtime.GOOS, runtime.GOARCH, reason)
	}
	return nil, fmt.Errorf("procbox: no process-tier backend compiled for %s/%s", runtime.GOOS, runtime.GOARCH)
}

// Apply resolves the host backend and applies the policy to the current
// process (irreversible).
func Apply(p PolicySpec) (Result, error) {
	b, err := Current()
	if err != nil {
		return Result{}, err
	}
	return b.Apply(p)
}
