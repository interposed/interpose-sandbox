//go:build linux

package cell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// cgHandle is a created cgroup v2 leaf for one cell.
type cgHandle struct {
	dir string
	fd  int
}

func (h *cgHandle) path() string { return h.dir }

func (h *cgHandle) closeFD() {
	if h != nil && h.fd >= 0 {
		syscall.Close(h.fd)
		h.fd = -1
	}
}

func (h *cgHandle) remove() {
	if h != nil && h.dir != "" {
		_ = os.Remove(h.dir)
	}
}

// prepCgroup creates a cgroup v2 leaf, writes best-effort resource caps, and
// wires the child to be born directly into it (clone3 CLONE_INTO_CGROUP via
// SysProcAttr.CgroupFD). Everything here is best-effort: if cgroup v2 is not
// available or a controller is not delegated, the cell still runs, just
// without that cap, and the reason is returned as a note.
func prepCgroup(cmd *exec.Cmd, id string, lim Limits) (*cgHandle, bool, []string) {
	if (lim == Limits{}) {
		return nil, false, nil
	}
	const base = "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(base, "cgroup.controllers")); err != nil {
		return nil, false, []string{"cgroup v2 unified not mounted; running without resource caps"}
	}
	parent := filepath.Join(base, "interpose-cells")
	_ = os.Mkdir(parent, 0o755)
	// Best-effort: delegate the controllers we use to child cgroups.
	_ = os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0o644)

	if id == "" {
		id = fmt.Sprintf("cell-%d", os.Getpid())
	}
	dir := filepath.Join(parent, sanitizeID(id))
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		return nil, false, []string{"cgroup create failed: " + err.Error()}
	}

	var notes []string
	applied := false
	write := func(file, val string) {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(val), 0o644); err == nil {
			applied = true
		} else {
			notes = append(notes, file+": "+err.Error())
		}
	}
	if lim.MemMaxBytes > 0 {
		write("memory.max", strconv.FormatInt(lim.MemMaxBytes, 10))
	}
	if lim.PidsMax > 0 {
		write("pids.max", strconv.FormatInt(lim.PidsMax, 10))
	}
	if lim.CPUMax != "" {
		write("cpu.max", lim.CPUMax)
	}

	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = os.Remove(dir)
		return nil, false, append(notes, "cgroup open: "+err.Error())
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = fd
	return &cgHandle{dir: dir, fd: fd}, applied, notes
}

// sanitizeID keeps a cgroup leaf name to a safe charset so an id can never
// escape the parent directory.
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		out = "cell"
	}
	return out
}
