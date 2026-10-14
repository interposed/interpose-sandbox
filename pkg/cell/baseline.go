package cell

import "github.com/interposed/interpose-sandbox/pkg/procbox"

// SystemBaselineRO is the read-only set a cell needs so an exec'd command can
// find its interpreter, shared libraries and system config. The backend drops
// paths that don't exist, so listing broadly is safe.
//
// Note: /proc is included for tooling that reads /proc/self, but in the
// shared-kernel tier it is the host's procfs (no PID namespace yet) - one more
// reason this tier is "standard", not hardware isolation.
//
// /run/systemd/resolve is here for DNS: on systemd-resolved hosts (Ubuntu,
// Fedora, most distros) /etc/resolv.conf is a symlink to
// /run/systemd/resolve/stub-resolv.conf, and Landlock/nono resolve the symlink
// at open time - so allowing /etc alone leaves the resolver config unreadable
// and every real dependency fetch (go get, pip, npm) dies with EAI_AGAIN. We
// scope to the resolver dir, not all of /run, to avoid exposing its sockets and
// secrets. Dropped on hosts without it.
func SystemBaselineRO() []string {
	return []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/etc", "/opt", "/proc", "/run/systemd/resolve"}
}

// SystemBaselineRW is the device nodes a typical command expects to write.
func SystemBaselineRW() []string {
	return []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"}
}

// Policy composes a deny-default cell policy: the system baseline plus the
// caller's read-write (workdir belongs here) and read-only paths, the named
// runtime groups, and the network mode. Best-effort report mode.
func Policy(rw, ro, runtimes []string, net procbox.NetMode) procbox.PolicySpec {
	return procbox.PolicySpec{
		FS: procbox.FSPolicy{
			RW:          append(append([]string{}, SystemBaselineRW()...), rw...),
			RO:          append(append([]string{}, SystemBaselineRO()...), ro...),
			DenyDefault: true,
		},
		Net:      procbox.NetPolicy{Mode: net},
		Runtimes: runtimes,
		Report:   procbox.ReportBestEffort,
	}
}
