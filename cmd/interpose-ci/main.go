// Command interpose-ci runs a pipeline of steps, each inside a governed cell,
// with release-class steps held for approval (fail-closed). It is the minimal
// "turn a machine into a CI runner" front-end: the runner is the sandbox pool,
// each step is a cell, and the run record is written for the operator's
// Releases page to read.
//
// Usage:
//
//	interpose-ci run <pipeline.json> [flags]
//	  --approve auto|deny   approver for release-class steps (default deny)
//	  --records <dir>       where to write the run record (default ./.interpose-ci/records)
//	  --max <n>             max concurrent cells (default 4)
//	  --commit <sha>        bind the run to a commit
//	  --digest <digest>     bind the run to an artifact digest
//
// The interpose-cell shim must sit beside this binary, or be named by
// INTERPOSE_CELL_BIN.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/interposed/interpose-sandbox/pkg/ci"
	"github.com/interposed/interpose-sandbox/pkg/pool"
)

// ciDir is the canonical CI data root the operator's Releases page syncs from:
// ~/.interpose/ci/{records,pending,decisions}. Both sides must agree.
func ciDir(sub string) string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".interpose", "ci", sub)
	}
	return filepath.Join(".interpose-ci", sub)
}

func main() {
	if len(os.Args) < 3 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: interpose-ci run <pipeline.json> [--approve auto|deny] [--records dir] [--max n] [--commit sha] [--digest d]")
		os.Exit(2)
	}
	path := os.Args[2]
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	approve := fs.String("approve", "deny", "approver for release steps: auto|deny|file")
	records := fs.String("records", ciDir("records"), "directory for run records")
	pending := fs.String("pending", ciDir("pending"), "pending-release mailbox (--approve file)")
	decisions := fs.String("decisions", ciDir("decisions"), "decision mailbox (--approve file)")
	timeout := fs.Duration("timeout", 2*time.Minute, "release approval wait (--approve file)")
	maxc := fs.Int("max", 4, "max concurrent cells")
	commit := fs.String("commit", "", "commit SHA to bind the run to")
	digest := fs.String("digest", "", "artifact digest to bind the run to")
	_ = fs.Parse(os.Args[3:])

	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ci: read pipeline:", err)
		os.Exit(1)
	}
	var p ci.Pipeline
	if err := json.Unmarshal(raw, &p); err != nil {
		fmt.Fprintln(os.Stderr, "ci: parse pipeline:", err)
		os.Exit(1)
	}

	var appr ci.Approver = ci.DenyAll{}
	switch *approve {
	case "auto":
		appr = ci.AutoApprove{}
	case "file":
		appr = ci.FileApprover{PendingDir: *pending, DecisionDir: *decisions, Timeout: *timeout}
	}

	pl := pool.New(pool.Config{MaxConcurrent: *maxc})
	rec, err := ci.Run(context.Background(), p, pl, appr, ci.Meta{Commit: *commit, Digest: *digest})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ci: run:", err)
		os.Exit(1)
	}

	if rpath, err := rec.WriteJSON(*records); err == nil {
		fmt.Printf("record: %s\n", rpath)
	}

	// Human summary.
	fmt.Printf("\npipeline %q  run %s  ok=%v\n", rec.Pipeline, rec.RunID, rec.OK)
	for _, s := range rec.Steps {
		status := fmt.Sprintf("exit=%d", s.ExitCode)
		switch {
		case s.Release && s.Skipped:
			status = "HELD " + string(s.Decision) + " (skipped, fail-closed)"
		case s.Release:
			status = "HELD " + string(s.Decision) + fmt.Sprintf(", exit=%d", s.ExitCode)
		case s.Skipped:
			status = "skipped: " + s.SkipReason
		}
		fmt.Printf("  - %-14s %s\n", s.Name, status)
	}
	if !rec.OK {
		os.Exit(1)
	}
}
