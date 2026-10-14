//go:build linux || darwin

// Command interpose-cell is the cell shim: a tiny binary the pool exec()s per
// job. It applies the deny-default sandbox policy to itself, then exec()s the
// job, so the Landlock restriction and the cgroup placement carry into the job.
// It is not meant to be run by hand; cell.Run sets it up and passes the spec
// via the INTERPOSE_CELL_SPEC environment variable.
package main

import "github.com/interposed/interpose-sandbox/pkg/cell"

func main() { cell.Shim() }
