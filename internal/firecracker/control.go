package firecracker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Detached is a handle to a background Firecracker VM. Unlike Start (foreground,
// blocks on the serial console), the detached spawns put firecracker in its own
// session with stdio redirected to a log file, then return — the VM keeps
// running after the interpose-sandbox process exits. The registry records PID +
// APISock so later subcommands (pause/resume/snapshot/rm) can reach it.
//
// KVM-gated: these only actually boot a VM on a host with /dev/kvm + firecracker.
type Detached struct {
	PID      int
	APISock  string
	StateDir string
	LogPath  string
}

// spawnFirecracker starts a detached firecracker with the given extra args
// (beyond --api-sock). Shared by StartDetached (adds --config-file) and StartBare
// (no config — waits for an API snapshot-load).
func spawnFirecracker(stateDir string, extraArgs ...string) (*Detached, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir state: %w", err)
	}
	apiSock := filepath.Join(stateDir, "api.sock")
	_ = os.Remove(apiSock) // firecracker refuses to start over a stale socket

	logPath := filepath.Join(stateDir, "firecracker.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	defer logf.Close() // the child dups its own fd on Start; our handle is done after

	args := append([]string{"--api-sock", apiSock}, extraArgs...)
	cmd := exec.Command("firecracker", args...)
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	// Setsid detaches firecracker into its own session so it outlives this CLI.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn firecracker: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release() // don't reap/track the detached child

	return &Detached{PID: pid, APISock: apiSock, StateDir: stateDir, LogPath: logPath}, nil
}

// StartDetached writes vmconfig and boots firecracker in the background.
func StartDetached(cfg VMConfig, stateDir string) (*Detached, error) {
	cfgPath := filepath.Join(stateDir, "vmconfig.json")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir state: %w", err)
	}
	b, err := Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal vmconfig: %w", err)
	}
	if err := os.WriteFile(cfgPath, b, 0o644); err != nil {
		return nil, fmt.Errorf("write vmconfig: %w", err)
	}
	return spawnFirecracker(stateDir, "--config-file", cfgPath)
}

// StartBare boots a detached firecracker with only the API socket (no config),
// ready to receive a snapshot load. Used by fork.
func StartBare(stateDir string) (*Detached, error) {
	return spawnFirecracker(stateDir)
}

// Pause freezes a running VM via the Firecracker API (PATCH /vm Paused).
func Pause(apiSock string) error { return patchVMState(apiSock, "Paused") }

// Resume unfreezes a paused VM (PATCH /vm Resumed).
func Resume(apiSock string) error { return patchVMState(apiSock, "Resumed") }

func patchVMState(apiSock, state string) error {
	body := fmt.Sprintf(`{"state":%q}`, state)
	return apiDo(apiSock, http.MethodPatch, "/vm", body)
}

// apiDo performs one HTTP request against the Firecracker control socket.
func apiDo(apiSock, method, path, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := apiClient(apiSock).Do(req)
	if err != nil {
		return fmt.Errorf("firecracker api %s: %w", apiSock, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("firecracker %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// apiClient dials the Firecracker control socket (HTTP over a unix domain socket).
func apiClient(apiSock string) *http.Client {
	return &http.Client{
		Timeout: 32 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", apiSock)
			},
		},
	}
}
