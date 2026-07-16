package firecracker

import "fmt"

// CreateSnapshot captures a paused VM's full state (device state + guest memory)
// to disk. The VM MUST be Paused first (call Pause). This is the first half of
// the "branch a running computer" fork.
//
// snapshotPath gets the device/vCPU state; memPath gets the guest RAM image.
func CreateSnapshot(apiSock, snapshotPath, memPath string) error {
	body := fmt.Sprintf(`{"snapshot_type":"Full","snapshot_path":%q,"mem_file_path":%q}`,
		snapshotPath, memPath)
	return apiDo(apiSock, "PUT", "/snapshot/create", body)
}

// LoadSnapshot restores a VM from a snapshot into a FRESH firecracker (started
// via StartBare, never configured/booted). With resume=true the restored VM
// runs immediately.
//
// KVM caveat (validate on a real host): the restored VM's block/net devices
// resume against the paths + MACs recorded IN the snapshot. For an isolated fork
// you must give the fork its own writable rootfs copy and, if networking is used,
// a fresh tap/MAC — otherwise two VMs write the same ext4. Our default config has
// no network iface (serial + vsock only), so the outstanding item is the rootfs
// copy, handled by the fork caller (forkVM). Older firecracker builds don't remap
// drive paths on load; if the copied-rootfs path differs from the snapshot's, a
// PATCH /drives may be required before resume.
func LoadSnapshot(apiSock, snapshotPath, memPath string, resume bool) error {
	body := fmt.Sprintf(
		`{"snapshot_path":%q,"mem_backend":{"backend_type":"File","backend_path":%q},"resume_vm":%t}`,
		snapshotPath, memPath, resume)
	return apiDo(apiSock, "PUT", "/snapshot/load", body)
}
