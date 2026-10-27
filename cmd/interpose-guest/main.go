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
	"os"
	"os/exec"

	"github.com/creack/pty"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

// vsockPort is the guest listen port; the host reaches it via the Firecracker
// vsock UDS with a "CONNECT 1024" handshake.
const vsockPort = 1024

type request struct {
	Op   string   `json:"op"`
	Cmd  []string `json:"cmd"`
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
}

func main() {
	bringUpMounts()

	l, err := vsock.Listen(vsockPort, nil)
	if err != nil {
		os.Stderr.WriteString("interpose-guest: vsock listen failed: " + err.Error() + "\r\n")
		select {} // PID 1 must not exit, or the kernel panics.
	}
	os.Stdout.WriteString("interpose-guest: listening on vsock port 1024\r\n")

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go serve(c)
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
		"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
	)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(req.Cols), Rows: uint16(req.Rows)})
	if err != nil {
		_, _ = c.Write([]byte("interpose-guest: start failed: " + err.Error() + "\r\n"))
		return
	}
	defer func() { _ = ptmx.Close() }()

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
