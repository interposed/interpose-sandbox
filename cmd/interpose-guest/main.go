//go:build linux

// interpose-guest is the in-VM agent for the microVM sandbox tier. It runs as
// PID 1 inside a Firecracker guest: it brings up the essential mounts, then
// listens on vsock port 1024 and, per connection, runs a command in a PTY and
// streams the raw terminal bytes back over the connection.
//
// Wire protocol (fresh, minimal): the host sends ONE newline-terminated JSON
// request, then the connection carries raw PTY bytes in both directions:
//
//	{"op":"start","cmd":["/bin/sh","-l"],"cols":120,"rows":40}\n
//	<raw stdin bytes ...>        (host -> guest, into the PTY)
//	<raw stdout/stderr bytes...> (guest -> host, from the PTY)
//
// This is the guest half of the hybrid dataplane: the daemon's session
// supervisor (host side) will speak this over the Firecracker vsock UDS, the
// same way the process tier drives a local PTY. Resize is a follow-up op.
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

// vsockPort is the guest listen port; the host reaches it via the Firecracker
// vsock UDS with a "CONNECT 1024" handshake. controlPort carries out-of-band
// control messages (resize) so the main stream stays raw PTY bytes.
const (
	vsockPort   = 1024
	controlPort = 1025
)

// activePTY is the most-recently-started session PTY, resized by the control
// listener. One PTY per VM in the session model, so "most recent" is it.
var (
	activeMu  sync.Mutex
	activePTY *os.File
)

type request struct {
	Op   string   `json:"op"`
	Cmd  []string `json:"cmd"`
	Env  []string `json:"env,omitempty"` // extra "KEY=VALUE" vars (e.g. the provider token); set RAM-only on the child, never written to the rootfs
	Cols int      `json:"cols"`
	Rows int      `json:"rows"`
}

// bringUpMounts mounts the pseudo-filesystems a governed guest needs: proc/sys
// for general operation, devpts for PTYs, and cgroup2 + bpffs so the in-guest
// interpose enforcer (added later) has its BPF-LSM substrate. Best-effort: a
// failure on any one must not stop the agent from serving.
func bringUpMounts() {
	_ = os.MkdirAll("/dev", 0o755)
	// devtmpfs first so /dev/ptmx, /dev/null, /dev/console exist (PTY needs ptmx).
	_ = unix.Mount("devtmpfs", "/dev", "devtmpfs", 0, "")
	for _, d := range []string{"/proc", "/sys", "/dev/pts", "/sys/fs/cgroup", "/sys/fs/bpf", "/run", "/tmp"} {
		_ = os.MkdirAll(d, 0o755)
	}
	_ = unix.Mount("proc", "/proc", "proc", 0, "")
	_ = unix.Mount("sysfs", "/sys", "sysfs", 0, "")
	_ = os.MkdirAll("/sys/kernel/security", 0o755)
	_ = unix.Mount("securityfs", "/sys/kernel/security", "securityfs", 0, "")
	_ = unix.Mount("devpts", "/dev/pts", "devpts", 0, "ptmxmode=0666")
	_ = unix.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, "")
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")
	_ = unix.Mount("tmpfs", "/run", "tmpfs", 0, "")
	_ = unix.Mount("tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID, "mode=1777")

	// Writable ephemeral layers over a READ-ONLY shared base image. The rootfs
	// drive is the same file for every VM (no per-session copy); the workload and
	// the in-guest enforcer write only to these tmpfs layers, which are RAM-only
	// and discarded on teardown. The license lives under /var/lib/interpose, so
	// read it before shadowing that dir and restore it onto the fresh tmpfs.
	lic, _ := os.ReadFile("/var/lib/interpose/license.json")
	for _, d := range []string{"/root", "/var/tmp", "/var/log", "/var/lib/interpose", "/home"} {
		_ = os.MkdirAll(d, 0o755)
		_ = unix.Mount("tmpfs", d, "tmpfs", 0, "")
	}
	if len(lic) > 0 {
		_ = os.WriteFile("/var/lib/interpose/license.json", lic, 0o600)
	}
}

// startEnforcer launches the in-guest interpose daemon so processes in this VM
// are governed by the BPF-LSM enforcer running ON our guest kernel (the host's
// BPF cannot see in-VM processes, so enforcement must live here). Best-effort:
// if the binary or kernel support is missing, the agent still serves. The box
// has no YubiKey, so --no-seal; the license is staged in the rootfs.
func startEnforcer() {
	if _, err := os.Stat("/usr/local/bin/interpose"); err != nil {
		return
	}
	cmd := exec.Command("/usr/local/bin/interpose", "serve", "--no-seal", "--enforcer=auto")
	cmd.Env = append(os.Environ(), "HOME=/root", "PATH=/bin:/sbin:/usr/bin:/usr/sbin")
	if f, err := os.Create("/run/interpose-serve.log"); err == nil {
		cmd.Stdout, cmd.Stderr = f, f
	}
	if err := cmd.Start(); err == nil {
		time.Sleep(1500 * time.Millisecond) // let the enforcer attach its programs
	}
}

func main() {
	// PID 1 inherits no PATH, so exec.Command("bash"/"claude") would fail its
	// LookPath. Set a sane PATH on the agent itself so bare template commands
	// from the host resolve.
	_ = os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/bin:/sbin:/usr/bin:/usr/sbin")
	bringUpMounts()
	startEnforcer()

	l, err := vsock.Listen(vsockPort, nil)
	if err != nil {
		os.Stderr.WriteString("interpose-guest: vsock listen failed: " + err.Error() + "\r\n")
		select {} // PID 1 must not exit, or the kernel panics.
	}
	os.Stdout.WriteString("interpose-guest: listening on vsock port 1024\r\n")
	go serveControl()

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go serve(c)
	}
}

// serveControl handles out-of-band control (resize) on a second vsock port so
// the main attach stream stays raw PTY bytes. One JSON line per connection.
func serveControl() {
	cl, err := vsock.Listen(controlPort, nil)
	if err != nil {
		return
	}
	for {
		c, err := cl.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			line, err := bufio.NewReader(c).ReadBytes('\n')
			if err != nil {
				return
			}
			var r struct {
				Cols uint16 `json:"cols"`
				Rows uint16 `json:"rows"`
			}
			if json.Unmarshal(line, &r) != nil || r.Cols == 0 || r.Rows == 0 {
				return
			}
			activeMu.Lock()
			p := activePTY
			activeMu.Unlock()
			if p != nil {
				_ = pty.Setsize(p, &pty.Winsize{Cols: r.Cols, Rows: r.Rows})
			}
		}(c)
	}
}

// serve handles one attach: read the start request, run the command in a PTY,
// and bridge raw bytes until the command exits.
func serve(c io.ReadWriteCloser) {
	defer c.Close()

	br := bufio.NewReader(c)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil || len(req.Cmd) == 0 {
		req.Cmd = []string{"/bin/sh", "-l"}
	}
	if req.Cols == 0 {
		req.Cols = 120
	}
	if req.Rows == 0 {
		req.Rows = 40
	}

	cmd := exec.Command(req.Cmd[0], req.Cmd[1:]...)
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color", "HOME=/root",
		"PATH=/usr/local/sbin:/usr/local/bin:/bin:/sbin:/usr/bin:/usr/sbin",
	)
	cmd.Env = append(cmd.Env, req.Env...) // token etc., RAM-only on the child
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(req.Cols), Rows: uint16(req.Rows)})
	if err != nil {
		_, _ = c.Write([]byte("interpose-guest: start failed: " + err.Error() + "\r\n"))
		return
	}
	defer func() { _ = ptmx.Close() }()
	activeMu.Lock()
	activePTY = ptmx
	activeMu.Unlock()

	// host -> PTY (drain anything buffered past the request line first)
	go func() {
		if n := br.Buffered(); n > 0 {
			if b, e := br.Peek(n); e == nil {
				_, _ = ptmx.Write(b)
				_, _ = br.Discard(n)
			}
		}
		_, _ = io.Copy(ptmx, br)
	}()
	// PTY -> host
	_, _ = io.Copy(c, ptmx)
	_ = cmd.Wait()
}
