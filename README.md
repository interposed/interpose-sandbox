# interpose-sandbox

[![govulncheck](https://github.com/interposed/interpose-sandbox/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/interposed/interpose-sandbox/actions/workflows/govulncheck.yml)

The sandbox product of the interposed.ai stack: run an agent, a command, or a whole
CI pipeline inside a deny-default box on a machine you own, and govern what it may do.
No proprietary runtime.

The only external enforcement dependency is [go-landlock](https://github.com/landlock-lsm/go-landlock)
(BSD), the Go binding for the Linux kernel's Landlock LSM. Everything else is ours.

## What's here

- **`pkg/procbox`** - the sandbox itself. It applies a kernel-native Landlock
  allow-list to the current process before `exec`: deny-default, inherited by every
  child, and irrevocable once applied (the restriction can only ever be tightened).
  Unprivileged - no daemon, no VM.
- **`pkg/cell` + `pkg/pool`** - run a single command inside its own deny-default cell
  (a procbox allow-list plus cgroup v2 resource caps); the pool runs many at once,
  bounded. One cell = one job.
- **`pkg/ci` + `cmd/interpose-ci`** - the governed CI runner, built on the pool (see
  below).

## Governed CI

`cmd/interpose-ci` turns a machine you own into a governed CI runner. It runs a
pipeline of steps, each inside its own cell, and **holds release-class steps for an
operator's approval before anything ships** - fail-closed, so no decision in time
means denied.

```bash
interpose-ci run <pipeline.json> \
  --approve auto|deny     # approver for release-class steps (default: deny)
  --records <dir>         # where the run record is written
  --max <n>               # max concurrent cells (default 4)
  --workdir <dir>         # run against a forge checkout
  --commit <sha> --digest <digest>   # bind the run to a commit / artifact
```

The approval contract is a plain filesystem mailbox (`pkg/ci`, `FileApprover`): the
runner writes a pending request and waits for a decision file, so an operator, a CLI,
or a relay bridge can drive it without linking this package. The runner enforces its
own policy over whatever a workflow asks for, every run is recorded, and runtime
caches are relocated out of the ephemeral workspace so re-runs stay clean.

This is what powers governed pipelines in the interposed Operator: register a machine
as a runner and its CI runs on your box, sandboxed step by step, with releases held
for your word.

We use it ourselves: interposed registers its own machines as governed runners and
runs CI on them through this sandbox - each step in a cell, release-class steps held
for a tap - dogfooding the same release flow we ship.

## Quick start

```bash
make build                             # builds the binaries into ./bin

# a governed pipeline needs only a modern Linux kernel with Landlock
interpose-ci run <pipeline.json> --approve deny
```

## Repository layout

```
interpose-sandbox/
├── cmd/
│   ├── interpose-ci/        # governed CI runner: run a pipeline, hold releases
│   └── interpose-cell/      # per-job cell shim (the pool exec()s it; not run by hand)
├── pkg/
│   ├── procbox/             # the sandbox: pure-Go Landlock allow-list
│   ├── cell/                # one command in a deny-default cell (procbox + cgroup v2)
│   ├── pool/                # bounded scheduler of cells
│   └── ci/                  # pipeline engine + file-mailbox approval seam
├── deploy/ci-runner/        # the runner job-started hook (enforcement layer)
├── go.mod · Makefile · LICENSE (Apache 2.0)
└── README.md
```

## Status

**v0.5.0** - the sandbox runs on pure-Go [Landlock](https://github.com/landlock-lsm/go-landlock),
with an escape suite as the CI gate (a cell can work in its allowed dir but cannot
read secrets or write outside it). The CI runner executes real pipelines with real
dependency fetches inside governed cells, holds release-class steps for approval, and
is validated on Ubuntu and Fedora.

Releases are tags; see `git tag` for the history.

## Roadmap

Directions, not promises - the shipping state is the Status above.

- **Harder cells.** PID and mount namespaces per cell (today a cell shares the host's
  procfs), with tighter process and resource caps.
- **Network allow-listing in-process.** Landlock's newer ABI can gate TCP bind/connect;
  wiring that into procbox would let a cell deny egress by default, not only the
  filesystem.
- **Richer Landlock via the Rust library.** The upstream Rust `landlock` crate tracks
  new ABI versions (network rules, best-effort negotiation) ahead of the Go binding.
  We may drive enforcement through a small Rust helper where it buys a stronger ruleset,
  while keeping the Go API and the sovereign, no-proprietary-engine stance.
- **Fuller forge support.** Gitea and Forgejo runners beside GitHub for governed CI.

## Related repos

```
interpose          ← the daemon: LSM-BPF enforcer, broker, policy, audit
interpose-operator ← the desktop console that registers runners and approves releases
```

## License

Apache 2.0. See [LICENSE](LICENSE).
