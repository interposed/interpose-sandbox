//go:build linux

package doctor

import (
	"errors"
	"os"
)

// kvmUsable reports whether this host can run a Firecracker microVM: /dev/kvm
// must exist and be openable for read/write. On a cloud VM without nested virt
// the node simply has no /dev/kvm, so this returns false and the caller uses the
// process (sandlock) tier.
func kvmUsable() (ok bool, reason string) {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return true, ""
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, "/dev/kvm not present (no hardware virtualization)"
	}
	if errors.Is(err, os.ErrPermission) {
		return false, "/dev/kvm present but not accessible (permissions)"
	}
	return false, "/dev/kvm: " + err.Error()
}
