//go:build darwin

package procbox

// systemBaseline are the read-only paths every macOS process needs to launch
// and run — interpreters, system frameworks, the dyld shared cache (incl. the
// modern Cryptex locations), and a few devices. This is our maintained
// equivalent of nono's "system group". Read-only + secrets live in $HOME, so
// allowing these broadly is safe; the deny-default still hides everything else.
func systemBaseline() (ro []string, roFiles []string, rw []string) {
	ro = []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
		"/System", "/Library",
		"/private/var/select", "/private/var/db/dyld",
		"/System/Volumes/Preboot/Cryptexes", "/System/Cryptexes",
		"/opt/homebrew/bin", "/opt/homebrew/lib", "/opt/homebrew/opt",
		"/etc", "/private/etc",
	}
	roFiles = []string{
		"/dev/zero", "/dev/random", "/dev/urandom", "/dev/dtracehelper",
	}
	// IO devices need write (stdout/stderr/tty). /dev holds the terminal
	// (/dev/ttysNNN) + pipes; allowing it is safe — devices aren't secrets and
	// fs isolation is about $HOME/project files.
	rw = []string{"/dev"}
	return
}
