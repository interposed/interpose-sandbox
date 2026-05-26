package rootfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBuild_RealAlpine(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}
	cacheDir := filepath.Join(t.TempDir(), "cache")

	path, err := Build(cacheDir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat rootfs: %v", err)
	}
	// We requested 512M; ext4 image should be exactly that on disk.
	expected := int64(512 * 1024 * 1024)
	if st.Size() != expected {
		t.Errorf("rootfs size: got %d, want %d", st.Size(), expected)
	}
	if !Cached(cacheDir) {
		t.Error("Cached() false after Build()")
	}
	t.Logf("built %s (%d MiB)", path, st.Size()/1024/1024)
}
