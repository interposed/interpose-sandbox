//go:build !linux

package cell

import "os/exec"

// cgHandle is a no-op outside Linux; cgroup v2 resource caps are Linux-only.
type cgHandle struct{}

func (h *cgHandle) path() string { return "" }
func (h *cgHandle) closeFD()     {}
func (h *cgHandle) remove()      {}

func prepCgroup(cmd *exec.Cmd, id string, lim Limits) (*cgHandle, bool, []string) {
	if (lim == Limits{}) {
		return nil, false, nil
	}
	return nil, false, []string{"cgroup v2 resource caps are only available on Linux"}
}
