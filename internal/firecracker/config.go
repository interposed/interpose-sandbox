// Package firecracker builds Firecracker vmconfig.json payloads for
// interpose-sandbox. The format is what `firecracker --config-file ...`
// expects on start, NOT what the in-process API server accepts (those
// are similar but not identical — separate endpoints in their REST API).
package firecracker

import "encoding/json"

// VMConfig is the JSON shape Firecracker's --config-file flag consumes.
// We only model the subset interpose-sandbox uses; Firecracker accepts
// many more knobs which we leave at defaults.
//
// Reference: https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml
type VMConfig struct {
	BootSource    BootSource     `json:"boot-source"`
	Drives        []Drive        `json:"drives"`
	MachineConfig MachineConfig  `json:"machine-config"`
	NetworkIfaces []NetworkIface `json:"network-interfaces,omitempty"`
	Vsock         *Vsock         `json:"vsock,omitempty"`
}

type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
	InitrdPath      string `json:"initrd_path,omitempty"`
}

type Drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type MachineConfig struct {
	VCPUCount  int  `json:"vcpu_count"`
	MemSizeMiB int  `json:"mem_size_mib"`
	SMT        bool `json:"smt"`
}

type NetworkIface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac,omitempty"`
	HostDevName string `json:"host_dev_name"`
}

type Vsock struct {
	GuestCID int    `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// Defaults returns a sensible starting config. Caller adjusts as needed.
//
// The boot_args here boots cleanly with our interpose-kernel image:
//   - console=ttyS0  — serial console (Firecracker UART)
//   - reboot=k panic=1 pci=off  — minimal microVM hygiene
//   - lsm=...,bpf  — ensure bpf LSM is in the active list (interpose-kernel
//     ships with this in cmdline by default but we set it explicitly so
//     a future kernel image without that default still works)
//   - root=/dev/vda  — rootfs is the first virtio block device
func Defaults(kernelPath, rootfsPath string, vcpus, memMiB int) VMConfig {
	return VMConfig{
		BootSource: BootSource{
			KernelImagePath: kernelPath,
			BootArgs: "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda " +
				"lsm=lockdown,capability,landlock,yama,apparmor,bpf",
		},
		Drives: []Drive{
			{
				DriveID:      "rootfs",
				PathOnHost:   rootfsPath,
				IsRootDevice: true,
				IsReadOnly:   false,
			},
		},
		MachineConfig: MachineConfig{
			VCPUCount:  vcpus,
			MemSizeMiB: memMiB,
			SMT:        false,
		},
	}
}

// Marshal serializes to the JSON shape Firecracker's --config-file
// expects. Pretty-printed for human auditability — Firecracker doesn't
// care about whitespace.
func Marshal(c VMConfig) ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
