package ci

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Supply-chain observation - the depsec add-on, observe mode. After a run, interpose-ci
// records which dependency modules the run actually pulled, read from the bytes on disk in the
// module cache (not from what the toolchain reports), and cross-checks them against the
// lockfile. A module that landed but is not in the lockfile is the dependency-confusion /
// injected-dependency signal. This is observe only: it never fails a step or changes a run's
// outcome; it writes a record a human reads in the operator.
//
// Covers Go (module cache) and npm (_cacache). The caches are shared and persistent across runs
// (see cacheRedirect), so "what THIS run pulled" is a before/after diff, not a point-in-time list.

// ObservedModule is one package@version seen in a dependency cache, with its content hash.
type ObservedModule struct {
	Path      string `json:"path"`
	Version   string `json:"version"`
	Hash      string `json:"hash,omitempty"`      // go module h1: / npm integrity (sri)
	Ecosystem string `json:"ecosystem,omitempty"` // "go" | "npm"
}

// key is the "path@version" identity shared by the cache and the lockfile.
func (m ObservedModule) key() string { return m.Path + "@" + m.Version }

// SupplyChain is the observe-mode dependency record attached to a RunRecord.
type SupplyChain struct {
	Mode          string           `json:"mode"`                     // "observe"
	Ecosystem     string           `json:"ecosystem"`                // "go" (v1)
	Observed      []ObservedModule `json:"observed"`                 // module@version this run pulled
	Declared      int              `json:"declared"`                 // modules pinned in the lockfile
	Undeclared    []ObservedModule `json:"undeclared,omitempty"`     // pulled but absent from the lockfile
	Scan          *ScanResult      `json:"scan,omitempty"`           // dependency vuln scan (osv-scanner)
	PinViolations []PinViolation   `json:"pin_violations,omitempty"` // pinned path fetched at an unapproved digest
	Note          string           `json:"note,omitempty"`
}

// PinViolation is a module whose path is pinned to a specific approved digest but which this run
// fetched at a different one - an unapproved version/digest for a pinned dependency. In enforce
// mode this fails the run before the build; in observe mode it is only recorded.
type PinViolation struct {
	Package   string `json:"package"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Got       string `json:"got"`  // the digest actually fetched
	Want      string `json:"want"` // the approved (pinned) digest
}

// VulnFinding is one vulnerable package reported by a dependency scan.
type VulnFinding struct {
	Package  string   `json:"package"`
	Version  string   `json:"version,omitempty"`
	IDs      []string `json:"ids"`                // OSV / CVE / GHSA ids
	Severity string   `json:"severity,omitempty"` // tool-reported, e.g. HIGH or a CVSS score
	Summary  string   `json:"summary,omitempty"`
}

// ScanResult is the dependency vulnerability scan folded into the supply-chain record.
// Observe only: it records what the scanner found, it never fails the run.
type ScanResult struct {
	Tool     string        `json:"tool"`               // "osv-scanner"
	Ran      bool          `json:"ran"`                // false = tool absent / errored / timed out
	Findings []VulnFinding `json:"findings,omitempty"` // vulnerable packages (empty = clean)
	Note     string        `json:"note,omitempty"`
}

// ObserveSupplyChain builds the observe record for a finished run across the pipeline's
// ecosystems (go, node): the packages added to the caches during the run (after minus before),
// cross-checked against the lockfiles (go.sum, package-lock.json). Best-effort and non-fatal -
// any trouble yields a record carrying a Note rather than failing the run. before is the pre-run
// snapshot from SnapshotModules(cacheDir, runtimes); pass nil if none was taken.
func ObserveSupplyChain(before map[string]ObservedModule, cacheDir, workdir string, runtimes []string, pins map[string]string, mode string) *SupplyChain {
	after := SnapshotModules(cacheDir, runtimes)
	declared := map[string]bool{}
	declaredN := 0
	var ecos []string
	if hasRuntime(runtimes, "go") {
		d, n := declaredGoSum(workdir)
		for k := range d {
			declared[k] = true
		}
		declaredN += n
		ecos = append(ecos, "go")
	}
	if hasRuntime(runtimes, "node") {
		d, n := declaredPackageLock(workdir)
		for k := range d {
			declared[k] = true
		}
		declaredN += n
		ecos = append(ecos, "npm")
	}
	sc := supplyChainRecord(before, after, declared, declaredN)
	sc.Ecosystem = strings.Join(ecos, "+") // "", "go", "npm", or "go+npm"
	sc.Scan = runDepScan(workdir)
	if mode != "" {
		sc.Mode = mode // "observe" | "enforce"
		sc.PinViolations = VerifyPins(before, after, pins)
	}
	return sc
}

// VerifyPins reports the modules THIS run fetched (after minus before) whose path is pinned to a
// specific approved digest but whose fetched digest differs - an unapproved version/digest for a
// pinned dependency. Pure: the caller decides what to do (block in enforce, record in observe). A
// module whose path is not pinned passes (pins are an allow-by-digest set, adopted gradually).
func VerifyPins(before, after map[string]ObservedModule, pins map[string]string) []PinViolation {
	if len(pins) == 0 {
		return nil
	}
	var out []PinViolation
	for k, m := range after {
		if _, seen := before[k]; seen {
			continue // already cached before this run
		}
		if want, ok := pins[m.Path]; ok && want != m.Hash {
			out = append(out, PinViolation{Package: m.Path, Version: m.Version, Ecosystem: m.Ecosystem, Got: m.Hash, Want: want})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

// FetchSteps returns the per-ecosystem dependency-fetch steps for the enforce pre-check: they
// populate the caches from the lockfiles so the pin verify sees exactly what the build will use,
// BEFORE the build runs. Bare tool names resolve on the cell's base PATH.
func FetchSteps(runtimes []string) []Step {
	var steps []Step
	if hasRuntime(runtimes, "go") {
		steps = append(steps, Step{Name: "supply-chain:fetch:go", Run: []string{"sh", "-c", "go mod download all"}})
	}
	if hasRuntime(runtimes, "node") {
		steps = append(steps, Step{Name: "supply-chain:fetch:npm", Run: []string{"sh", "-c", "npm ci --no-audit --no-fund --loglevel=error || npm install --no-audit --no-fund --loglevel=error"}})
	}
	return steps
}

// hasRuntime reports whether a runtime group (e.g. "go", "node") is in the pipeline's list.
func hasRuntime(runtimes []string, name string) bool {
	for _, r := range runtimes {
		if strings.EqualFold(strings.TrimSpace(r), name) {
			return true
		}
	}
	return false
}

// SnapshotModules returns what is present in the dependency caches for the run's ecosystems,
// keyed path@version. Take one snapshot before the run and one after; the difference is what the
// run pulled (the caches are shared across runs). Best-effort: absent caches yield an empty map.
func SnapshotModules(cacheDir string, runtimes []string) map[string]ObservedModule {
	out := map[string]ObservedModule{}
	if hasRuntime(runtimes, "go") {
		for k, m := range SnapshotGoModules(cacheDir) {
			out[k] = m
		}
	}
	if hasRuntime(runtimes, "node") {
		for k, m := range SnapshotNpmModules(cacheDir) {
			out[k] = m
		}
	}
	return out
}

// runDepScan scans the workdir's dependencies for known vulnerabilities with osv-scanner and
// folds the result into the record. Best-effort and observe-only: a missing scanner, a scan
// error, or a timeout yields Ran=false with a Note, never a failure. osv-scanner exits
// non-zero WHEN IT FINDS vulnerabilities, which is a successful scan for us, so its output is
// parsed regardless of exit code.
func runDepScan(workdir string) *ScanResult {
	bin, err := exec.LookPath("osv-scanner")
	if err != nil {
		return &ScanResult{Tool: "osv-scanner", Ran: false, Note: "osv-scanner not installed"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "--format", "json", "-r", workdir).Output()
	if ctx.Err() == context.DeadlineExceeded {
		return &ScanResult{Tool: "osv-scanner", Ran: false, Note: "osv-scanner timed out"}
	}
	if len(out) == 0 {
		return &ScanResult{Tool: "osv-scanner", Ran: false, Note: "osv-scanner produced no output"}
	}
	findings, perr := parseOSVReport(out)
	if perr != nil {
		return &ScanResult{Tool: "osv-scanner", Ran: false, Note: "parse osv-scanner output: " + perr.Error()}
	}
	return &ScanResult{Tool: "osv-scanner", Ran: true, Findings: findings, Note: fmt.Sprintf("%d vulnerable package(s)", len(findings))}
}

// parseOSVReport extracts the vulnerable packages from osv-scanner's --format json output. Pure
// (no I/O), so the tests pin it against a real osv-scanner document. A package with no
// vulnerabilities is skipped; severity prefers the per-vuln database_specific.severity, then
// the group's max_severity (a CVSS score).
func parseOSVReport(b []byte) ([]VulnFinding, error) {
	var doc struct {
		Results []struct {
			Packages []struct {
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID               string `json:"id"`
					Summary          string `json:"summary"`
					DatabaseSpecific struct {
						Severity string `json:"severity"`
					} `json:"database_specific"`
				} `json:"vulnerabilities"`
				Groups []struct {
					MaxSeverity string `json:"max_severity"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []VulnFinding
	for _, res := range doc.Results {
		for _, p := range res.Packages {
			if len(p.Vulnerabilities) == 0 {
				continue
			}
			f := VulnFinding{Package: p.Package.Name, Version: p.Package.Version}
			for _, v := range p.Vulnerabilities {
				f.IDs = append(f.IDs, v.ID)
				if f.Summary == "" {
					f.Summary = v.Summary
				}
				if f.Severity == "" && v.DatabaseSpecific.Severity != "" {
					f.Severity = v.DatabaseSpecific.Severity
				}
			}
			if f.Severity == "" {
				for _, g := range p.Groups {
					if g.MaxSeverity != "" {
						f.Severity = g.MaxSeverity
						break
					}
				}
			}
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out, nil
}

// supplyChainRecord is the pure decision: diff the snapshots to find what the run pulled, then
// flag the pulled modules the lockfile does not declare. No I/O - this is what the tests pin.
func supplyChainRecord(before, after map[string]ObservedModule, declared map[string]bool, declaredN int) *SupplyChain {
	hasLock := declaredN > 0
	var observed, undeclared []ObservedModule
	for k, m := range after {
		if _, seen := before[k]; seen {
			continue // already cached before this run - a prior run pulled it
		}
		observed = append(observed, m)
		// Only flag "undeclared" when there is a lockfile to check against. With none, the
		// cross-check is skipped (see Note) rather than flagging every module as a finding.
		if hasLock && !declared[k] {
			undeclared = append(undeclared, m)
		}
	}
	sort.Slice(observed, func(i, j int) bool { return observed[i].key() < observed[j].key() })
	sort.Slice(undeclared, func(i, j int) bool { return undeclared[i].key() < undeclared[j].key() })
	sc := &SupplyChain{
		Mode:       "observe",
		Ecosystem:  "go",
		Observed:   observed,
		Declared:   declaredN,
		Undeclared: undeclared,
	}
	if !hasLock {
		sc.Note = "no lockfile in the workdir; undeclared cross-check skipped"
	}
	return sc
}

// SnapshotGoModules lists the modules present in the Go download cache under cacheDir
// (<cacheDir>/go/pkg/mod/cache/download), keyed "path@version". The cache is shared across
// runs, so take one snapshot before the run and one after; the difference is what the run
// pulled. Best-effort: an unreadable or absent cache yields an empty map, never an error.
func SnapshotGoModules(cacheDir string) map[string]ObservedModule {
	out := map[string]ObservedModule{}
	if strings.TrimSpace(cacheDir) == "" {
		return out
	}
	root := filepath.Join(cacheDir, "go", "pkg", "mod", "cache", "download")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".ziphash") {
			return nil
		}
		// layout: <root>/<escaped module path>/@v/<escaped version>.ziphash
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 3 || parts[len(parts)-2] != "@v" {
			return nil
		}
		modPath := decodeModule(strings.Join(parts[:len(parts)-2], "/"))
		version := decodeModule(strings.TrimSuffix(parts[len(parts)-1], ".ziphash"))
		if modPath == "" || version == "" {
			return nil
		}
		m := ObservedModule{Path: modPath, Version: version, Ecosystem: "go"}
		if b, e := os.ReadFile(p); e == nil {
			m.Hash = strings.TrimSpace(string(b))
		}
		out[m.key()] = m
		return nil
	})
	return out
}

// SnapshotNpmModules lists the packages present in the npm content-addressed cache under cacheDir
// (<cacheDir>/npm/_cacache/index-v5), keyed name@version, with the npm integrity (sri) as hash.
// Each index entry's key is a tarball-cache request URL (.../<name>/-/<base>-<version>.tgz) that
// names exactly the package@version that was fetched. Best-effort: an absent cache yields {}.
func SnapshotNpmModules(cacheDir string) map[string]ObservedModule {
	out := map[string]ObservedModule{}
	if strings.TrimSpace(cacheDir) == "" {
		return out
	}
	root := filepath.Join(cacheDir, "npm", "_cacache", "index-v5")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		// each line: "<hash>\t<json>" where json = {"key":"...tarball url...","integrity":"..."}
		for _, line := range strings.Split(string(b), "\n") {
			tab := strings.IndexByte(line, '\t')
			if tab < 0 {
				continue
			}
			var ent struct {
				Key       string `json:"key"`
				Integrity string `json:"integrity"`
			}
			if json.Unmarshal([]byte(line[tab+1:]), &ent) != nil {
				continue
			}
			name, version, ok := parseNpmTarballKey(ent.Key)
			if !ok {
				continue
			}
			m := ObservedModule{Path: name, Version: version, Hash: ent.Integrity, Ecosystem: "npm"}
			out[m.key()] = m
		}
		return nil
	})
	return out
}

// parseNpmTarballKey pulls name@version out of an npm _cacache key, e.g.
// "make-fetch-happen:request-cache:https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz".
// Non-tarball entries (metadata requests, no "/-/…​.tgz") return ok=false.
func parseNpmTarballKey(key string) (name, version string, ok bool) {
	u := key
	if i := strings.Index(key, "request-cache:"); i >= 0 {
		u = key[i+len("request-cache:"):]
	}
	if !strings.HasSuffix(u, ".tgz") {
		return "", "", false
	}
	sep := strings.Index(u, "/-/")
	if sep < 0 {
		return "", "", false
	}
	left, right := u[:sep], u[sep+3:] // left=…/@scope/pkg  right=pkg-1.2.3.tgz
	if p := strings.Index(left, "://"); p >= 0 {
		left = left[p+3:] // host/@scope/pkg
	}
	slash := strings.IndexByte(left, '/')
	if slash < 0 {
		return "", "", false
	}
	name = left[slash+1:]                     // @scope/pkg | pkg
	base := strings.TrimSuffix(right, ".tgz") // pkg-1.2.3
	last := name
	if k := strings.LastIndexByte(name, '/'); k >= 0 {
		last = name[k+1:] // pkg
	}
	version = strings.TrimPrefix(base, last+"-")
	if version == "" || version == base {
		return "", "", false
	}
	return name, version, true
}

// declaredPackageLock parses workdir/package-lock.json (v2/v3 "packages" map) and returns the set
// of "name@version" it pins plus the count. A key is "node_modules/<name>" (nested keys end in
// "node_modules/<name>" too); the name is the segment after the last "node_modules/". A missing or
// v1-only lockfile returns an empty set and 0 (cross-check then skipped).
func declaredPackageLock(workdir string) (map[string]bool, int) {
	set := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(workdir, "package-lock.json"))
	if err != nil {
		return set, 0
	}
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return set, 0
	}
	for k, v := range doc.Packages {
		if k == "" || v.Version == "" {
			continue // "" is the root project
		}
		name := k
		if i := strings.LastIndex(k, "node_modules/"); i >= 0 {
			name = k[i+len("node_modules/"):]
		}
		set[name+"@"+v.Version] = true
	}
	return set, len(set)
}

// declaredGoSum parses workdir/go.sum and returns the set of "path@version" it pins plus the
// count of distinct modules. go.sum has two lines per module ("<path> <version> h1:..." and
// "<path> <version>/go.mod h1:..."); both fold to the same path@version key. A missing go.sum
// returns an empty set and 0.
func declaredGoSum(workdir string) (map[string]bool, int) {
	set := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(workdir, "go.sum"))
	if err != nil {
		return set, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		path, version := f[0], strings.TrimSuffix(f[1], "/go.mod")
		set[path+"@"+version] = true
	}
	return set, len(set)
}

// decodeModule reverses the Go module cache's "!"-escaping of upper-case letters (BurntSushi
// becomes !burnt!sushi on disk), so a cache path/version matches its go.sum spelling.
func decodeModule(enc string) string {
	if !strings.Contains(enc, "!") {
		return enc
	}
	var b strings.Builder
	for i := 0; i < len(enc); i++ {
		if enc[i] == '!' && i+1 < len(enc) && enc[i+1] >= 'a' && enc[i+1] <= 'z' {
			i++
			b.WriteByte(enc[i] - 'a' + 'A')
			continue
		}
		b.WriteByte(enc[i])
	}
	return b.String()
}
