//go:build linux || darwin

package cell

import "syscall"

// execInto replaces the current process image with the job, keeping the
// Landlock restriction and cgroup placement that are already in effect.
func execInto(bin string, argv, env []string) error {
	return syscall.Exec(bin, argv, env)
}
