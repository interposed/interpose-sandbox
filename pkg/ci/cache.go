package ci

import (
	"os"
	"path/filepath"
	"strings"
)

// cacheRedirect moves each runtime's package/build cache OUT of the ephemeral
// workspace into a persistent, host-managed cache root, and returns the extra
// RW dirs to allow-list in the cell plus the env vars that point the tools at
// them.
//
// Why this exists: a cell runs with HOME=workdir, so Go (GOPATH=HOME/go,
// GOCACHE=HOME/.cache/go-build), npm, and pip all write their caches UNDER the
// workspace. Go in particular marks its module cache files read-only, so the
// next run's `actions/checkout` cleanup chokes on them and leaves a corrupt,
// partial checkout - the job then fails before interpose-ci can even read the
// pipeline. Relocating the caches keeps the workspace clean between runs and,
// as a bonus, makes them persistent so dependencies are not re-downloaded every
// run. Caches are content-addressed (go.sum / package-lock integrity / pip
// hashes), so sharing a root across the owner's repos is safe; per-repo
// namespacing is a later refinement for multi-tenant runners.
//
// Each dir is created up front (while still outside the sandbox); a dir we
// cannot create is simply left out, so the step falls back to the in-workspace
// default rather than failing. cacheRoot == "" disables the whole thing.
func cacheRedirect(cacheRoot string, runtimes []string) (rw, env []string) {
	if strings.TrimSpace(cacheRoot) == "" {
		return nil, nil
	}
	add := func(sub string, envKeys ...string) {
		dir := filepath.Join(cacheRoot, sub)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return // best-effort: fall back to the in-workspace default
		}
		rw = append(rw, dir)
		for _, k := range envKeys {
			env = append(env, k+"="+dir)
		}
	}
	for _, rt := range runtimes {
		switch strings.ToLower(strings.TrimSpace(rt)) {
		case "go":
			add("go", "GOPATH")       // module cache (pkg/mod) + installed bins
			add("go-build", "GOCACHE") // compile cache (default HOME/.cache/go-build)
		case "node":
			add("npm", "npm_config_cache")
		case "python":
			add("pip", "PIP_CACHE_DIR")
		case "rust":
			add("cargo", "CARGO_HOME")
		}
	}
	return rw, env
}
