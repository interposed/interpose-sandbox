package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCacheRedirectMovesCachesOutOfWorkspace pins the fix for the re-run
// corruption: each runtime's cache must be redirected to the host cache root
// (never left under the workspace), the env must point the tools there, and the
// dirs must actually be created so the cell can allow-list them RW.
func TestCacheRedirectMovesCachesOutOfWorkspace(t *testing.T) {
	root := t.TempDir()
	rw, env := cacheRedirect(root, []string{"go", "node", "python"})

	wantEnv := map[string]string{
		"GOPATH":           filepath.Join(root, "go"),
		"GOCACHE":          filepath.Join(root, "go-build"),
		"npm_config_cache": filepath.Join(root, "npm"),
		"PIP_CACHE_DIR":    filepath.Join(root, "pip"),
	}
	got := map[string]string{}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		got[k] = v
	}
	for k, want := range wantEnv {
		if got[k] != want {
			t.Fatalf("env %s = %q, want %q", k, got[k], want)
		}
		if !strings.HasPrefix(want, root) {
			t.Fatalf("%s points outside the cache root: %q", k, want)
		}
	}

	// Every RW dir must live under the cache root (so none lands in a workspace)
	// and must exist (else existing() drops it and the tool can't write).
	for _, d := range rw {
		if !strings.HasPrefix(d, root) {
			t.Fatalf("cache RW dir outside root: %q", d)
		}
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			t.Fatalf("cache RW dir not created: %q (err=%v)", d, err)
		}
	}

	// Disabled when no cache root is configured.
	if rw, env := cacheRedirect("", []string{"go"}); rw != nil || env != nil {
		t.Fatalf("empty cacheRoot should disable redirect, got rw=%v env=%v", rw, env)
	}
}
