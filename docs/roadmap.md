# interpose-sandbox — roadmap

**Status:** v0.1.0 shipped (2026-05-26). Foreground sandbox spawn works end-to-end on KVM-capable Linux hosts; backgrounded sandboxes + ls/run/rm ship in v0.2.

## v0.1.0 — first running sandbox (SHIPPED 2026-05-26)

- [x] `interpose-sandbox doctor` audits /dev/kvm, /dev/kvm R/W, firecracker on PATH, interpose-kernel image presence (via `docker images`), interpose binary presence
- [x] `internal/kernel` pulls + extracts interpose-kernel OCI images (local-first; `docker cp /kernel` works around the scratch image having no CMD by passing `--entrypoint=/kernel`)
- [x] `internal/rootfs` builds Alpine 3.21 ext4 with auto-login getty on ttyS0 — single docker-run shellout, 512 MiB output, cached under $XDG_CACHE_HOME
- [x] `internal/firecracker.Start` foreground spawn with inherited stdio
- [x] `interpose-sandbox new shell` end-to-end: kernel.Extract → rootfs.Build → firecracker.Start (boot args from `kernel.Info.BootArgs()`)
- [x] Tagged `v0.1.0`

**Scope cuts that made v0.1 shippable today:**
- Foreground-only. `ls`/`run`/`rm` ship in v0.2 once we have the PTY/socat wrapper around firecracker's serial console. Trying to ship those in v0.1 would have meant 1-2 extra hours of bug-surface work for a UX nicety.
- No virtio-fs workspace mount. v0.1's `new shell [workspace]` accepts the workspace argument but doesn't mount it; v0.2 adds the bind.
- No baked-in agent runtimes. v0.1 only supports `new shell` (drops into Alpine /bin/sh); claude / codex / opencode bake in v0.3.

**Host constraint that surfaced during D3 smoke test:**
- Firecracker requires KVM. Apple Silicon Lima cannot expose KVM to the guest (no nested virt on M1/M2 via Apple VZ; Lima's VZ backend doesn't surface M3+'s hardware support either). So interpose-sandbox cannot run on a Mac dev environment. See README "Where you can actually run this" for the host matrix.

**Built on:** interpose-kernel v0.1.0 (`startaworldpeace/interpose-kernel:ubuntu-24.04-bpf-lsm-v0.1.0` + `debian-12-bpf-lsm-v0.1.0`, both pushed to Docker Hub 2026-05-26).

## v0.2 — interpose preloaded

- [ ] Sandbox spawns with `interpose serve --enforcer linux` already running
- [ ] Host-side port-forward for `localhost:7422` so the operator's host browser can complete the WebAuthn ceremony
- [ ] Passkey re-use: if the operator already registered an interpose passkey on the host, the sandbox reads it from a mounted credentials directory (vs. requiring fresh registration per sandbox)
- [ ] Documentation: end-to-end demo guide (mirrors interpose's `docs/demo.md` Milestone 1 but in Firecracker instead of Lima)

## v0.3 — agent integrations

- [ ] `interpose-sandbox new claude .` — pre-baked claude-code inside, wired to interpose-sdk-go via MCP
- [ ] `interpose-sandbox new codex .`, `opencode`, etc. — match SBX's vendor list
- [ ] Each agent runs cooperatively against interpose by default; agent-specific config lives in the kernel image's overlay

## v0.4 — multi-sandbox UX

- [ ] `ls` shows uptime, current activity, audit log tail
- [ ] `run <name> --attach` keeps prior shell history
- [ ] `template save/load` analogous to `sbx template`
- [ ] State directory layout documented + supports backup/restore

## v0.5 — production polish

- [ ] systemd unit for hosting "sandbox-as-a-service" on a Linux server
- [ ] mTLS or SSH-forwarded API for remote operators (sandbox host elsewhere, operator on laptop)
- [ ] Resource limits enforced (cgroups within Firecracker's own limits)
- [ ] Tested on AWS EC2 (since AWS hosts run Firecracker natively for Lambda; nested-KVM scenarios)

## v1.0

- [ ] Migration to `interposehq/` Docker Hub namespace
- [ ] First external operator running interpose-sandbox in production
- [ ] Documented in the main interpose repo as "the Linux production deployment story"

## Out of scope (deliberate)

- **Mac support** for the runtime itself. Lima is the Mac story — same kernel image, different VM tech (Apple VZ vs KVM). `interpose-sandbox doctor` on macOS politely refuses and points at Lima.
- **Windows support.** Same reason — Windows has WSL2 (which can run Firecracker), but the host-side UX would be substantially different. Out of v1 scope.
- **K8s integration.** Use Kata Containers if you want OCI/K8s shape — Kata is itself a microVM stack purpose-built for that. We don't compete with it.
- **Multi-tenant SaaS.** Single-host, single-operator. Multi-host scenarios are interpose's M3 (mesh) territory, not this repo.
