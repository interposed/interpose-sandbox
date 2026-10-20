package ci

import (
	"os"
	"path/filepath"
	"testing"
)

// The decision: observed = what the run added to the cache (after minus before); undeclared =
// those additions the lockfile does not pin. A module already cached before the run is NOT
// attributed to this run, and a declared module is not flagged.
func TestSupplyChainRecordFlagsOnlyRunPulledUndeclared(t *testing.T) {
	before := map[string]ObservedModule{
		"golang.org/x/text@v0.3.0": {Path: "golang.org/x/text", Version: "v0.3.0"},
	}
	after := map[string]ObservedModule{
		"golang.org/x/text@v0.3.0": {Path: "golang.org/x/text", Version: "v0.3.0"}, // pre-existing
		"golang.org/x/mod@v0.42.0": {Path: "golang.org/x/mod", Version: "v0.42.0"}, // pulled + declared
		"evil.example/pwn@v1.0.0":  {Path: "evil.example/pwn", Version: "v1.0.0"},  // pulled + NOT declared
	}
	declared := map[string]bool{
		"golang.org/x/text@v0.3.0": true,
		"golang.org/x/mod@v0.42.0": true,
	}

	sc := supplyChainRecord(before, after, declared, len(declared))

	if sc.Mode != "observe" || sc.Ecosystem != "go" {
		t.Fatalf("mode/ecosystem = %q/%q, want observe/go", sc.Mode, sc.Ecosystem)
	}
	if len(sc.Observed) != 2 {
		t.Fatalf("observed = %d, want 2 (the two modules this run pulled, not the pre-existing one): %+v", len(sc.Observed), sc.Observed)
	}
	if len(sc.Undeclared) != 1 || sc.Undeclared[0].Path != "evil.example/pwn" {
		t.Fatalf("undeclared = %+v, want only evil.example/pwn", sc.Undeclared)
	}
	if sc.Declared != 2 {
		t.Fatalf("declared count = %d, want 2", sc.Declared)
	}
}

// With no lockfile the cross-check cannot run, so nothing is flagged undeclared and the record
// says why. Observe must never manufacture a finding it cannot justify.
func TestSupplyChainRecordNoLockfileSkipsCrossCheck(t *testing.T) {
	after := map[string]ObservedModule{
		"evil.example/pwn@v1.0.0": {Path: "evil.example/pwn", Version: "v1.0.0"},
	}
	sc := supplyChainRecord(nil, after, map[string]bool{}, 0)
	if len(sc.Observed) != 1 {
		t.Fatalf("observed = %d, want 1", len(sc.Observed))
	}
	if len(sc.Undeclared) != 0 {
		t.Fatalf("undeclared = %d, want 0 when there is no lockfile to check against", len(sc.Undeclared))
	}
	if sc.Note == "" {
		t.Fatalf("want a Note explaining the skipped cross-check")
	}
}

// SnapshotGoModules reads the module@version actually on disk, decoding the cache's "!"-escaped
// upper-case letters so it matches go.sum spelling, and lifts the h1: hash from .ziphash.
func TestSnapshotGoModulesReadsCacheWithDecodingAndHash(t *testing.T) {
	cache := t.TempDir()
	// github.com/BurntSushi/toml is escaped on disk as github.com/!burnt!sushi/toml.
	dir := filepath.Join(cache, "go", "pkg", "mod", "cache", "download", "github.com", "!burnt!sushi", "toml", "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "v1.2.0.ziphash"), []byte("h1:abc123=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// a .info without a .ziphash must not be listed (no bytes landed to attest).
	if err := os.WriteFile(filepath.Join(dir, "v1.3.0.info"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := SnapshotGoModules(cache)
	m, ok := got["github.com/BurntSushi/toml@v1.2.0"]
	if !ok {
		t.Fatalf("want decoded key github.com/BurntSushi/toml@v1.2.0, got %+v", got)
	}
	if m.Hash != "h1:abc123=" {
		t.Fatalf("hash = %q, want h1:abc123=", m.Hash)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 module (the .info-only one must be ignored), got %d", len(got))
	}
}

func TestSnapshotGoModulesMissingCacheIsEmptyNotError(t *testing.T) {
	if got := SnapshotGoModules(filepath.Join(t.TempDir(), "nope")); len(got) != 0 {
		t.Fatalf("missing cache should yield an empty map, got %+v", got)
	}
}

// parseOSVReport pulls vulnerable packages out of osv-scanner's JSON: it skips clean packages,
// collects the ids, and takes severity from database_specific first, then the group max.
func TestParseOSVReport(t *testing.T) {
	doc := `{"results":[{"source":{"path":"/w/go.sum","type":"lockfile"},"packages":[
	  {"package":{"name":"golang.org/x/text","version":"v0.3.0","ecosystem":"Go"},
	   "vulnerabilities":[{"id":"GHSA-5rcv-m4m3-hfh7","aliases":["CVE-2020-14040"],"summary":"loop in x/text","database_specific":{"severity":"HIGH"}}],
	   "groups":[{"ids":["GHSA-5rcv-m4m3-hfh7"],"max_severity":"7.5"}]},
	  {"package":{"name":"rsc.io/quote","version":"v1.5.2","ecosystem":"Go"},"vulnerabilities":[]},
	  {"package":{"name":"example.com/foo","version":"v1.0.0","ecosystem":"Go"},
	   "vulnerabilities":[{"id":"GHSA-xxxx","summary":"bad"}],
	   "groups":[{"ids":["GHSA-xxxx"],"max_severity":"9.8"}]}
	]}]}`

	findings, err := parseOSVReport([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 vulnerable packages (clean one skipped), got %d: %+v", len(findings), findings)
	}
	// sorted by package name: example.com/foo, golang.org/x/text
	foo, text := findings[0], findings[1]
	if foo.Package != "example.com/foo" || foo.Severity != "9.8" {
		t.Fatalf("foo: want example.com/foo sev 9.8 (from group max), got %+v", foo)
	}
	if text.Package != "golang.org/x/text" || text.Severity != "HIGH" {
		t.Fatalf("text: want golang.org/x/text sev HIGH (from database_specific), got %+v", text)
	}
	if len(text.IDs) != 1 || text.IDs[0] != "GHSA-5rcv-m4m3-hfh7" {
		t.Fatalf("text ids: %+v", text.IDs)
	}
	if text.Summary == "" {
		t.Fatalf("want a summary carried through")
	}
}

func TestParseOSVReportEmpty(t *testing.T) {
	findings, err := parseOSVReport([]byte(`{"results":[]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("want no findings, got %+v", findings)
	}
}

// declaredGoSum folds the "/go.mod" line into the same path@version key and counts distinct
// modules.
func TestDeclaredGoSumFoldsGoModLine(t *testing.T) {
	wd := t.TempDir()
	sum := "golang.org/x/mod v0.42.0 h1:aaa=\n" +
		"golang.org/x/mod v0.42.0/go.mod h1:bbb=\n" +
		"golang.org/x/text v0.3.0 h1:ccc=\n" +
		"golang.org/x/text v0.3.0/go.mod h1:ddd=\n"
	if err := os.WriteFile(filepath.Join(wd, "go.sum"), []byte(sum), 0o644); err != nil {
		t.Fatal(err)
	}
	set, n := declaredGoSum(wd)
	if n != 2 {
		t.Fatalf("declared count = %d, want 2 distinct modules", n)
	}
	if !set["golang.org/x/mod@v0.42.0"] || !set["golang.org/x/text@v0.3.0"] {
		t.Fatalf("set missing expected keys: %+v", set)
	}
}
