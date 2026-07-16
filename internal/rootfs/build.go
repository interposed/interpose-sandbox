// Package rootfs builds the Alpine-based ext4 rootfs that interpose-sandbox
// boots Firecracker with.
//
// v0.1 design: one default rootfs (Alpine 3.21 + busybox/openrc + a serial
// getty that auto-logs as root). No agent-runtime baking — that's v0.3
// (`interpose-sandbox new claude .` etc.). The v0.1 rootfs gets you a
// shell on the serial console; agents come later.
//
// Implementation: shell out to `docker run alpine:3.21` which has both
// `apk` (to populate /rootfs) and `e2fsprogs` (for `mkfs.ext4 -d`). This
// keeps the host requirements identical to internal/kernel (just Docker)
// and works cross-platform.
//
// The build is reproducible-ish: pinned Alpine version, fixed inittab,
// no network state baked in. mtime/randomness in mkfs makes the output
// not byte-identical across runs, but the boot behavior is stable.
package rootfs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const (
	// AlpineVersion is pinned for reproducibility. Bump deliberately
	// when shipping a new interpose-sandbox release; document why.
	AlpineVersion = "3.21"

	// DefaultSize is the size of the ext4 image. 512M gives Alpine
	// (~50M installed) plenty of headroom for /tmp, /var/log, and any
	// runtime files the agent leaves behind during a session.
	DefaultSize = "512M"
)

// Path returns the absolute path where Build puts (or would put) the
// rootfs ext4 image for the current host architecture. Deterministic.
func Path(cacheDir string) string {
	return filepath.Join(cacheDir, "rootfs",
		fmt.Sprintf("alpine-%s-%s.ext4", AlpineVersion, runtime.GOARCH))
}

// Cached returns true iff Build has already produced an ext4 image at Path.
func Cached(cacheDir string) bool {
	_, err := os.Stat(Path(cacheDir))
	return err == nil
}

// Build produces an Alpine rootfs ext4 image under cacheDir, returning
// the absolute path. No-op if already present. Requires `docker` on PATH.
//
// The resulting image, when booted by Firecracker with our kernel,
// auto-logs root into /bin/sh on the serial console — the operator's
// `interpose-sandbox run <name>` attaches directly into that shell.
func Build(cacheDir string) (string, error) {
	out := Path(cacheDir)
	if _, err := os.Stat(out); err == nil {
		return out, nil
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker not found on PATH (interpose-sandbox uses it to build the rootfs)")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", fmt.Errorf("mkdir rootfs cache: %w", err)
	}

	// We mount the parent dir of the output path into /out inside the
	// container, then write to /out/<basename>. Mounting just the
	// (not-yet-existing) file would fail.
	outDir := filepath.Dir(out)
	outName := filepath.Base(out)

	dockerPlatform := "linux/" + runtime.GOARCH
	script := buildScript(outName)

	cmd := exec.Command("docker", "run", "--rm",
		"--platform="+dockerPlatform,
		"-v", outDir+":/out",
		"alpine:"+AlpineVersion,
		"sh", "-c", script)
	cmd.Stdout = os.Stderr // progress to stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Clean up partial output so a retry starts fresh.
		_ = os.Remove(out)
		return "", fmt.Errorf("docker run alpine builder: %w", err)
	}
	return out, nil
}

// buildScript returns the shell script run inside the Alpine builder
// container. It installs alpine-base into /rootfs, rewrites /etc/inittab
// so the serial console (ttyS0) spawns an auto-login root shell, then
// formats the whole thing as an ext4 image at /out/<outName>.
func buildScript(outName string) string {
	return `set -eux
apk add --no-cache e2fsprogs

mkdir -p /rootfs
# Note: --no-cache + --initdb breaks repository discovery for the child
# rootfs (the new /rootfs/etc/apk/repositories starts empty). Either drop
# --no-cache and let apk write the cache (and inherit /etc/apk/repositories
# into the rootfs), or pass -X explicitly. We use -X so the build is
# deterministic regardless of the builder image's repo config.
apk --root /rootfs --initdb \
    -X https://dl-cdn.alpinelinux.org/alpine/v` + AlpineVersion + `/main \
    -X https://dl-cdn.alpinelinux.org/alpine/v` + AlpineVersion + `/community \
    --allow-untrusted \
    add alpine-base e2fsprogs

# Serial console: respawn an auto-login root shell on ttyS0 so the
# operator's "interpose-sandbox run" socat into Firecracker's console
# socket drops directly into a usable shell. No login prompt — the
# sandbox itself IS the security boundary; the operator's host owns
# whatever passkey/yubikey gating happens via the interpose broker.
# Workspace mount helper: format (first boot) + mount the /dev/vdb block device
# at /workspace. Firecracker has no virtio-fs, so the workspace is a block device.
cat > /rootfs/sbin/interpose-workspace <<'EOF'
#!/bin/sh
[ -b /dev/vdb ] || exit 0
blkid /dev/vdb >/dev/null 2>&1 || mkfs.ext4 -q -F /dev/vdb
mkdir -p /workspace
mount /dev/vdb /workspace
EOF
chmod +x /rootfs/sbin/interpose-workspace

# NOTE: /sbin/interpose-guest (the vsock guest-agent that launches agents under
# interpose + streams their PTYs) is baked into the published AGENT IMAGE in CI
# (a deployed host has no Go toolchain to compile it at runtime). This fallback
# Alpine rootfs ships without it — the inittab line below no-ops (sleeps) if it's
# absent, so this image still boots to a serial shell.
cat > /rootfs/etc/inittab <<'EOF'
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::sysinit:/sbin/interpose-workspace
::wait:/sbin/openrc default
::respawn:/bin/sh -c '[ -x /sbin/interpose-guest ] && exec /sbin/interpose-guest || sleep 3600'
ttyS0::respawn:/sbin/getty -L -n -l /bin/sh 115200 ttyS0 vt100
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
EOF

# Minimal /etc/hostname so prompts look right.
echo interpose-sandbox > /rootfs/etc/hostname

# Hello banner that proves to the operator they're inside the sandbox.
cat > /rootfs/etc/motd <<'EOF'
================================================================
You are inside an interpose-sandbox microVM.
Kernel: interpose-kernel (BPF-LSM enabled)
Workspace: /workspace (host bind-mount, v0.2)
Broker:    vsock to host (interpose daemon, v0.2)
================================================================
EOF

# Size + format. -F skips the "this is not a block device" prompt.
truncate -s ` + DefaultSize + ` /out/` + outName + `
mkfs.ext4 -d /rootfs -F /out/` + outName + `

# Report what we made.
ls -la /out/` + outName + `
echo "rootfs build complete"
`
}
