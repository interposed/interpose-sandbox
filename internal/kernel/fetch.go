// Package kernel pulls + extracts the interpose-kernel OCI image and
// caches the artifacts ready to feed into a Firecracker vmconfig.
//
// interpose-kernel v0.1.0+ ships as a standard OCI image with this
// top-level layout:
//
//	/kernel              — vmlinuz binary (boots directly)
//	/kernel.tar          — /lib/modules/${VER}/ contents
//	/kernel-dev.tar      — kernel headers (for compiling BPF programs)
//	/System.map          — symbol map
//	/config              — the kernel .config used at build time
//	/kernel-source-info  — provenance: flavor, version, package version, arch, build timestamp
//
// For v0.1 we extract just /kernel and /kernel-source-info. The rest
// stays in the image until the in-VM enforcer needs them (loading modules,
// compiling LSM-BPF programs at runtime).
//
// Implementation shells out to `docker pull` / `docker create` / `docker cp`
// rather than re-implementing OCI registry pulls in Go. Avoids dragging in
// a registry client dependency. Trade-off: requires docker on the host.
// We may add a pure-Go OCI pull path in v0.2 for operators who want to
// run Firecracker without Docker installed.
package kernel

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultTag is what `interpose-sandbox new` pulls when --kernel-image
// is not specified. Tracks the currently-recommended interpose-kernel
// release.
const DefaultTag = "startaworldpeace/interpose-kernel:ubuntu-24.04-bpf-lsm-v0.1.0"

// Info captures /kernel-source-info from a pulled interpose-kernel image.
// Field names mirror the key=value pairs the build emits.
type Info struct {
	Flavor               string // "ubuntu" | "debian" | "rocky"
	KernelVersion        string // e.g. "6.8.0-117-generic"
	KernelPackageVersion string // e.g. "6.8.0-117.117"
	Arch                 string // "arm64" | "amd64"
	BuildTimestamp       string // ISO 8601 UTC
}

// BootArgs returns the kernel command-line interpose-sandbox should boot
// this kernel with. Returns the same string for Ubuntu and Debian; the
// `lsm=...,bpf` segment is required on Ubuntu and harmless on Debian
// (Debian already has bpf in its default LSM chain).
func (i Info) BootArgs() string {
	return "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda " +
		"lsm=lockdown,capability,landlock,yama,apparmor,bpf"
}

// Pull downloads the image if it isn't already present in the local
// Docker daemon. Safe to call repeatedly. We check local presence first
// so locally-built-but-not-yet-pushed images Just Work (interpose-kernel
// images during development, registries that require auth, etc.).
func Pull(tag string) error {
	if err := requireDocker(); err != nil {
		return err
	}
	if localExists(tag) {
		return nil
	}
	cmd := exec.Command("docker", "pull", tag)
	cmd.Stdout = os.Stderr // surface progress on stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker pull %s: %w", tag, err)
	}
	return nil
}

// localExists returns true if the image tag is already in the local
// Docker daemon. `docker image inspect` exits 0 on present, non-zero on
// missing — no network round-trip.
func localExists(tag string) bool {
	return exec.Command("docker", "image", "inspect", tag).Run() == nil
}

// Cached reports whether the given tag has already been extracted under
// cacheDir. Returns true iff the kernel file exists at the canonical
// path for this tag.
func Cached(tag, cacheDir string) bool {
	_, err := os.Stat(KernelPath(tag, cacheDir))
	return err == nil
}

// KernelPath returns the absolute path where Extract puts (or would put)
// the kernel binary for the given tag. Deterministic — same input always
// yields the same path.
func KernelPath(tag, cacheDir string) string {
	return filepath.Join(tagDir(tag, cacheDir), "kernel")
}

// InfoPath returns the absolute path where Extract puts the
// kernel-source-info file for the given tag.
func InfoPath(tag, cacheDir string) string {
	return filepath.Join(tagDir(tag, cacheDir), "kernel-source-info")
}

// Extract copies /kernel and /kernel-source-info out of the image into
// cacheDir and parses Info. Pulls the image first if it isn't present.
// Returns the absolute path to the kernel binary ready to hand to
// Firecracker's boot-source.kernel_image_path.
func Extract(tag, cacheDir string) (string, Info, error) {
	if err := requireDocker(); err != nil {
		return "", Info{}, err
	}
	if err := Pull(tag); err != nil {
		return "", Info{}, err
	}

	dir := tagDir(tag, cacheDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", Info{}, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Create a throwaway container; we never start it — `docker cp`
	// works against created-but-not-running containers.
	//
	// interpose-kernel images are FROM scratch with no CMD or ENTRYPOINT,
	// so `docker create <tag>` alone fails with "no command specified".
	// We force a placeholder entrypoint (/kernel — a file we know exists
	// in the image). Docker only validates this at container-start time,
	// and we never start the container.
	cidBytes, err := exec.Command("docker", "create", "--entrypoint=/kernel", tag).Output()
	if err != nil {
		return "", Info{}, fmt.Errorf("docker create %s: %w", tag, err)
	}
	cid := strings.TrimSpace(string(cidBytes))
	defer exec.Command("docker", "rm", cid).Run() //nolint:errcheck

	kernelPath := KernelPath(tag, cacheDir)
	infoPath := InfoPath(tag, cacheDir)

	if err := dockerCp(cid, "/kernel", kernelPath); err != nil {
		return "", Info{}, err
	}
	if err := dockerCp(cid, "/kernel-source-info", infoPath); err != nil {
		return "", Info{}, err
	}

	info, err := ParseInfo(infoPath)
	if err != nil {
		return "", Info{}, fmt.Errorf("parse kernel-source-info: %w", err)
	}
	return kernelPath, info, nil
}

// ParseInfo reads a kernel-source-info file (KEY=VALUE lines) into Info.
func ParseInfo(path string) (Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return Info{}, err
	}
	defer f.Close()

	kv := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		kv[line[:eq]] = line[eq+1:]
	}
	if err := scanner.Err(); err != nil {
		return Info{}, err
	}
	return Info{
		Flavor:               kv["FLAVOR"],
		KernelVersion:        kv["KERNEL_VERSION"],
		KernelPackageVersion: kv["KERNEL_PACKAGE_VERSION"],
		Arch:                 kv["ARCH"],
		BuildTimestamp:       kv["BUILD_TIMESTAMP"],
	}, nil
}

// requireDocker returns an error if `docker` isn't on PATH. We surface
// this early with a clear hint rather than getting a cryptic exec error
// deeper in the call chain.
func requireDocker() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found on PATH (interpose-sandbox uses it to pull the kernel image)")
	}
	return nil
}

func dockerCp(cid, srcInContainer, destOnHost string) error {
	cmd := exec.Command("docker", "cp", cid+":"+srcInContainer, destOnHost)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker cp %s:%s -> %s: %w (%s)",
			cid, srcInContainer, destOnHost, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// tagDir computes a deterministic per-tag subdirectory under cacheDir.
// We hash the tag because tags contain `/` and `:` that aren't ideal as
// directory components, and a single deterministic hash keeps the path
// short regardless of tag length. The image tag itself lives in the
// kernel-source-info file inside the directory, so the hash is purely
// for filesystem hygiene.
func tagDir(tag, cacheDir string) string {
	sum := sha256.Sum256([]byte(tag))
	return filepath.Join(cacheDir, "kernels", hex.EncodeToString(sum[:8]))
}
