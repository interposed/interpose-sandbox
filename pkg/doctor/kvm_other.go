//go:build !linux

package doctor

// kvmUsable is always false off Linux: Firecracker is Linux/KVM only, so macOS
// and Windows hosts run the process (sandlock/Seatbelt) tier.
func kvmUsable() (ok bool, reason string) {
	return false, "microVM tier is Linux/KVM only"
}
