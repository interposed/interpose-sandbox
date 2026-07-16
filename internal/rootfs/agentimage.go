package rootfs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultAgentImage is the OCI tag `interpose-sandbox new` pulls for its rootfs
// when no --rootfs-image is given. Empty until the agent image is published —
// while empty, boot falls back to the runtime Alpine Build (a shell-only rootfs
// without interpose/pi baked in). Set to the published tag, e.g.
// "startaworldpeace/interpose-agent:ubuntu-24.04-arm64-v0.1.0".
const DefaultAgentImage = ""

// AgentRootfs pulls the agent OCI image (built by image/build.sh — a FROM-scratch
// image with /agent-rootfs.ext4) and extracts the ext4 into cacheDir, returning
// its path. This is the "everything baked in" rootfs: interpose enforcer +
// vsock guest-agent + node + pi. Mirrors internal/kernel.Extract.
func AgentRootfs(tag, cacheDir string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker not found on PATH (needed to pull the agent image)")
	}
	out := agentRootfsPath(tag, cacheDir)
	if _, err := os.Stat(out); err == nil {
		return out, nil // cached
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", fmt.Errorf("mkdir agent cache: %w", err)
	}
	// Pull if not already local (locally-built-but-unpushed images Just Work).
	if exec.Command("docker", "image", "inspect", tag).Run() != nil {
		cmd := exec.Command("docker", "pull", tag)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("docker pull %s: %w", tag, err)
		}
	}
	// FROM-scratch image with no CMD → force an entrypoint we know exists so
	// `docker create` succeeds; we never start it.
	cidBytes, err := exec.Command("docker", "create", "--entrypoint=/agent-rootfs.ext4", tag).Output()
	if err != nil {
		return "", fmt.Errorf("docker create %s: %w", tag, err)
	}
	cid := strings.TrimSpace(string(cidBytes))
	defer exec.Command("docker", "rm", cid).Run() //nolint:errcheck

	cp := exec.Command("docker", "cp", cid+":/agent-rootfs.ext4", out)
	if o, err := cp.CombinedOutput(); err != nil {
		return "", fmt.Errorf("docker cp agent rootfs: %w (%s)", err, strings.TrimSpace(string(o)))
	}
	return out, nil
}

// agentRootfsPath is the deterministic per-tag cache path for the extracted ext4.
func agentRootfsPath(tag, cacheDir string) string {
	sum := sha256.Sum256([]byte(tag))
	return filepath.Join(cacheDir, "agents", hex.EncodeToString(sum[:8]), "agent-rootfs.ext4")
}
