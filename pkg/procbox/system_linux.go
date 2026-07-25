//go:build linux

package procbox

// systemBaseline are the read-only paths every Linux process needs to launch
// and run — interpreters, shared libraries, and a few /etc + /dev entries.
// Our maintained equivalent of nono's "system group". On Linux the Landlock
// deny-default still hides everything else (notably $HOME secrets).
func systemBaseline() (ro []string, roFiles []string, rw []string) {
	ro = []string{
		"/bin", "/sbin", "/usr", "/lib", "/lib64", "/lib32",
		"/etc", "/opt",
		"/proc/self", "/sys",
	}
	roFiles = []string{
		"/dev/zero", "/dev/random", "/dev/urandom",
		"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
	}
	rw = []string{"/dev/null", "/dev/tty", "/dev/pts", "/dev/ptmx"}
	return
}
