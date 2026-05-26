package kernel

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExtract_RealImage exercises Extract end-to-end against a locally
// cached interpose-kernel image. Skipped if docker isn't on PATH or the
// default image isn't already pulled — this is a smoke test for dev
// machines, not a hermetic CI test.
func TestExtract_RealImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	cacheDir := filepath.Join(t.TempDir(), "cache")

	kpath, info, err := Extract(DefaultTag, cacheDir)
	if err != nil {
		t.Skipf("Extract failed (image not cached locally?): %v", err)
	}

	st, err := os.Stat(kpath)
	if err != nil {
		t.Fatalf("stat kernel: %v", err)
	}
	if st.Size() < 1_000_000 {
		t.Errorf("kernel suspiciously small: %d bytes", st.Size())
	}
	if info.Flavor == "" {
		t.Error("Flavor empty in parsed info")
	}
	if info.KernelVersion == "" {
		t.Error("KernelVersion empty")
	}
	if !Cached(DefaultTag, cacheDir) {
		t.Error("Cached() returned false after successful Extract()")
	}
	t.Logf("extracted kernel %d bytes, flavor=%s version=%s arch=%s",
		st.Size(), info.Flavor, info.KernelVersion, info.Arch)
}

func TestParseInfo(t *testing.T) {
	infoFile := filepath.Join(t.TempDir(), "info")
	content := "FLAVOR=ubuntu\n" +
		"KERNEL_VERSION=6.8.0-117-generic\n" +
		"KERNEL_PACKAGE_VERSION=6.8.0-117.117\n" +
		"ARCH=arm64\n" +
		"BUILD_TIMESTAMP=2026-05-26T19:00:00Z\n"
	if err := os.WriteFile(infoFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := ParseInfo(infoFile)
	if err != nil {
		t.Fatalf("ParseInfo: %v", err)
	}
	if info.Flavor != "ubuntu" {
		t.Errorf("Flavor: got %q want ubuntu", info.Flavor)
	}
	if info.KernelVersion != "6.8.0-117-generic" {
		t.Errorf("KernelVersion: got %q", info.KernelVersion)
	}
	if info.Arch != "arm64" {
		t.Errorf("Arch: got %q want arm64", info.Arch)
	}
}
