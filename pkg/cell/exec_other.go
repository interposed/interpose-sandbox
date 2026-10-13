//go:build !linux && !darwin

package cell

import "errors"

func execInto(bin string, argv, env []string) error {
	return errors.New("cell: exec not supported on this platform")
}
