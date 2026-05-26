// Package kernel pulls + extracts the interpose-kernel OCI image from
// Docker Hub (or any OCI registry) and caches the artifacts ready to feed
// into a Firecracker vmconfig.
//
// interpose-kernel v0.1.0+ ships as a standard OCI image — there is no
// linuxkit dependency. Each image carries a top-level layout:
//
//	/kernel              — vmlinuz binary (boots directly)
//	/kernel.tar          — /lib/modules/${VER}/ contents
//	/kernel-dev.tar      — kernel headers (for compiling BPF programs)
//	/System.map          — symbol map
//	/config              — the kernel .config used at build time
//	/kernel-source-info  — provenance: flavor, version, package version, arch, build timestamp
//
// We extract just `/kernel` for Firecracker boot; the rest is kept around
// the cache directory for the in-VM enforcer to use later (loading modules,
// compiling LSM-BPF programs at runtime, etc.).
//
// Planned v0.1 surface:
//
//	// Pull downloads the interpose-kernel image for the given tag. If
//	// already present locally, this is a no-op. Honors INTERPOSE_KERNEL_IMAGE
//	// env override for testing against a non-default registry/tag.
//	func Pull(ctx context.Context, tag string) error
//
//	// Extract turns a pulled image into a (kernelPath, kernelInfoPath) pair
//	// under $XDG_CACHE_HOME/interpose-sandbox/kernels/<digest>/.
//	// Returns the absolute path to /kernel ready to hand to Firecracker.
//	func Extract(tag, cacheDir string) (kernelPath string, info Info, err error)
//
//	// Cached returns true if the image's /kernel artifact already exists
//	// under cacheDir.
//	func Cached(tag, cacheDir string) bool
//
// Info captures /kernel-source-info — flavor, kernel version, package
// version, arch, build timestamp — so callers can pick the right boot_args
// (Ubuntu needs `lsm=...,bpf`; Debian doesn't but it's harmless to include).
//
// Implementation note: shell out to `docker pull` + `docker create` +
// `docker cp` rather than re-implementing OCI registry pulls. Avoids
// dragging in a registry client dependency (~MBs of code) when the host
// already has Docker as a prereq for Firecracker development. We can
// revisit and add a pure-Go OCI pull path in v0.2 if operators want to
// run without Docker installed on the host (Firecracker itself does not
// require Docker — just KVM).
package kernel

// Type sketches — implementations land in chunk C of v0.1.

// Info captures /kernel-source-info from a pulled interpose-kernel image.
// Fields match the key=value pairs the build emits.
type Info struct {
	Flavor                string // "ubuntu" | "debian" | "rocky"
	KernelVersion         string // e.g. "6.8.0-117-generic"
	KernelPackageVersion  string // e.g. "6.8.0-117.117"
	Arch                  string // "arm64" | "amd64"
	BuildTimestamp        string // ISO 8601 UTC
}

// DefaultTag is what `interpose-sandbox new` pulls when --kernel-image
// is not specified. Tracks the currently-recommended interpose-kernel
// release.
const DefaultTag = "startaworldpeace/interpose-kernel:ubuntu-24.04-bpf-lsm-v0.1.0"
