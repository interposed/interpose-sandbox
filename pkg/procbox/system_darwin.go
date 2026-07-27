//go:build darwin

package procbox

// systemBaseline are the read-only paths every macOS process needs to launch
// and run — interpreters, system frameworks, the dyld shared cache (incl. the
// modern Cryptex locations), and a few devices. This is our maintained
// equivalent of nono's "system group". Read-only + secrets live in $HOME, so
// allowing these broadly is safe; the deny-default still hides everything else.
func systemBaseline() (ro []string, roFiles []string, rw []string) {
	// Broad read-only over the OS tree — matching nono's system group. This is
	// safe: user secrets live in $HOME (/Users/<me>), which stays denied, and
	// the keychain is blocked via mach-lookup. A narrow enumerated list breaks
	// real runtimes (they read /usr/share, /private/var/db, dyld closures, …);
	// reading the read-only OS gives nothing away.
	ro = []string{
		"/bin", "/sbin", "/usr", "/System", "/Library", "/opt", "/etc",
		"/System/Volumes/Preboot/Cryptexes", "/System/Cryptexes",
		"/private", // var (db, run, select), etc, tmp reads — no $HOME here
	}
	roFiles = []string{
		"/dev/zero", "/dev/random", "/dev/urandom", "/dev/dtracehelper",
	}
	// IO devices + system temp need write. /dev holds the terminal + pipes.
	// /private/tmp (=/tmp) and /private/var/folders (the per-user temp + cache
	// tree, incl. $TMPDIR and DARWIN_USER_CACHE_DIR) are where runtimes stage
	// work — Bun transpile caches, unix sockets, lockfiles. Every real runtime
	// needs them; they're ephemeral scratch, not the $HOME secrets we protect.
	// Without these, static tools run but Node/Bun/Python agents fail.
	rw = []string{"/dev", "/private/tmp", "/private/var/folders"}
	return
}

// agentPlatformRules is the macOS operation baseline — the non-filesystem
// Seatbelt permissions a real runtime needs: fork/exec, mach services, sysctls,
// POSIX shared memory, signals, ptys, sockets. nono's own agent profile allows
// exactly these (deny-default still blocks the filesystem); we mirror it via
// AddPlatformRule so a Bun/Node/Python agent runs, not just a static tool.
//
// The trailing denies are nono's anti-exfil hardening: even with mach-lookup
// open, the keychain / security daemons stay unreachable. Seatbelt is
// last-match-wins, so these must follow the general (allow mach-lookup).
func agentPlatformRules() []string {
	return []string{
		"(allow process-fork)",
		"(allow process-exec*)",
		"(allow process-info*)",
		// JIT runtimes (Bun, V8) write compiled code to their cache and map it
		// executable; without this the kernel SIGKILLs them. Deny-default still
		// limits which files are readable/mappable to the allow-list.
		"(allow file-map-executable)",
		"(allow signal)",
		"(allow sysctl-read)",
		"(allow system-info)",
		"(allow system-fsctl)",
		"(allow system-socket)",
		"(allow ipc-posix-sem*)",
		"(allow ipc-posix-shm-read-data)",
		"(allow ipc-posix-shm-write-create)",
		"(allow ipc-posix-shm-write-data)",
		"(allow pseudo-tty)",
		`(allow file-ioctl (literal "/dev/tty"))`,
		`(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))`,
		"(allow mach-lookup)",
		"(allow mach-per-user-lookup)",
		"(allow mach-task-name)",
		`(deny mach-lookup (global-name "com.apple.securityd"))`,
		`(deny mach-lookup (global-name "com.apple.SecurityServer"))`,
		`(deny mach-lookup (global-name "com.apple.security.agent"))`,
		`(deny mach-lookup (global-name "com.apple.security.keychaind"))`,
		`(deny mach-lookup (global-name "com.apple.secd"))`,
	}
}
