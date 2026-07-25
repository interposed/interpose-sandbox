# Process tier ("Instant") — build notes

Branch: `nono-integration`. Status: **PT0+ complete — nono-go engine wired.**
Additive flavor #2 beside the Firecracker microVM ("Sealed") flavor; the
daemon's BPF-LSM ("Ambient") path is untouched.

## Decision: nono-go is the engine, we govern on top

We deliver everything nono gives — kernel-native deny-default allow-list
(Landlock on Linux/WSL2, Seatbelt on macOS), profiles, network modes,
credential protection — **through our own sandbox**, and layer our
differentiation above it: identity, opt-in hardware-tap approvals, signed
audit, entitlement, and the ladder up to Sealed & Ambient. "They sandbox,
we govern."

### Why nono-go and not our own Seatbelt

PT0 spike finding (recorded for posterity): a hand-rolled default-deny
Seatbelt profile that scopes `file-read*` **SIGABRTs almost any binary at
launch** on current macOS — dyld/amfi read from version-specific paths
(Cryptexes, dyld closures) that are impractical to enumerate by hand. A
blocklist ("deny ~/.ssh, ~/.aws, …") works but is the wrong model
(enumerate-every-secret, not least-privilege). nono-go's core already solved
the correct allowlist. Proven on this Mac: `AllowPath(cwd, RW)` +
`SetNetworkMode(Blocked)` → cwd read/write works, `~/.ssh` read denied
("operation not permitted"), `$HOME` invisible — no hardcoded list.

## Architecture

```
pkg/procbox/                         OUR interface + policy schema
  procbox.go        Backend registry (priority): Current() picks best available
  policy.go         PolicySpec — one schema across backends
  backend_nono.go   PRIMARY (priority 100), //go:build (darwin||linux)&&cgo.
                    The ONLY file importing nono-go (blast-radius: lint-gated).
  backend_landlock_linux.go  FALLBACK (priority 50), pure-Go go-landlock —
                    the CGO-disabled / sovereign-hedge path. Real deny-default.
  system_darwin.go / system_linux.go   our maintained "system group": the
                    read-only baseline every process needs to launch (system
                    libs, interpreters, dyld cache incl. Cryptexes) + IO devices.
  paths.go          $HOME/$CWD/~ expansion, runtime groups (node/python/go/rust),
                    existence filtering.
  escape_test.go    CI gate — re-exec pattern: a sandboxed child proves it can
                    work in cwd but can't read ~/.ssh or write $HOME.

cmd/interpose-sandbox/
  wrap.go / wrap_exec.go   `interpose-sandbox wrap [flags] -- cmd` — the FREE,
                    unprivileged CLI. Self-restricts via procbox.Apply, then
                    syscall.Exec so the sandboxed image replaces the wrapper
                    (child inherits the irrevocable ruleset).
```

Backend selection: nono-go (100) wins when CGO + supported; go-landlock (50)
covers CGO-disabled Linux and the sovereign hedge. macOS requires the nono
backend (Xcode CLT provides the C toolchain).

## Verified (this Mac, macOS · nono engine)

- `wrap -- sh -c 'echo hi > f && cat f && ls'` → works (fs read/write in cwd).
- `wrap -- cat ~/.ssh/id` → **denied** ("operation not permitted").
- `wrap -- ls ~` → **denied** ($HOME invisible).
- pipes + file redirection both work (`wrap -- echo x | cat`).
- escape suite passes; `go vet` clean; nocgo Linux build compiles (fallback).

## "All that nono gives" — mapping to PT phases

| nono capability            | where it lands |
|---|---|
| kernel deny-default allow-list | **PT0+ done** (nono-go engine) |
| composable JSON profiles + security groups | PT1 — our parser over nono's format + runtime groups (started) |
| network allowlists / domain filtering | PT2 governed tier (proxy) |
| credential protection (inject at boundary) | PT2 — via our Vault-brokering |
| audit trail | PT2 — OUR signed audit (daemon-direct) |
| runtime supervisor (dynamic expansion) | PT3 — wired to OUR hardware-tap approval (opt-in) |
| registry (`nono search`) | PT4 — curated in-repo profiles, nono-format compatible |

Hardware approval is **opt-in** at every level (`approval: none | tap-to-start
| supervised`). The free wrap tier can later be gated behind Personal — a
flag, not a rework.

## Do-not-break

Nothing in the microVM or daemon BPF-LSM path was touched. `wrap` + `pkg/procbox`
are new; existing commands (doctor/new/run/…) are unchanged.
