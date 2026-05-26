# interpose-sandbox — roadmap

**Status:** scaffold. Skeleton + working `doctor` + vmconfig generator + stub commands.

## v0.1 — first running sandbox

- [ ] `interpose-sandbox doctor` validated on a real Linux host with KVM + Firecracker installed; `checkInterposeKernelAvailable()` queries the local Docker daemon for an `interpose-kernel:*-bpf-lsm-*` tag and offers to `docker pull` if missing.
- [ ] `internal/kernel/Pull` + `Extract` implemented (plain `docker pull` + `docker create` + `docker cp /kernel` — no linuxkit dependency, the image is a standard OCI artifact since interpose-kernel v0.1.0)
- [ ] Alpine minirootfs baked into an `ext4` image — `internal/rootfs/build.go` (or similar) downloads + assembles. v0.1 ships one default rootfs (Alpine 3.21 + busybox + a getty); the agent runtimes (Claude Code, Codex, etc.) layer in v0.3.
- [ ] `internal/firecracker/Start` + `Stop` + `Status` implemented (process spawn + Unix-socket API client; vsock socket opened for v0.2's host-broker bridge)
- [ ] `interpose-sandbox new shell .` spawns a Firecracker VM, mounts cwd via virtio-fs at `/workspace`, drops you into a shell on the console
- [ ] `interpose-sandbox run <name>`, `ls`, `rm` work end-to-end
- [ ] Tag `v0.1.0`

**Unblocked:** interpose-kernel v0.1.0 shipped (2026-05-26) with both Ubuntu 24.04 (`ubuntu-24.04-bpf-lsm-v0.1.0`) and Debian 12 (`debian-12-bpf-lsm-v0.1.0`) flavors validated and userspace-confirmed BPF-LSM-active. Default flavor for v0.1: Ubuntu (smaller — 137 MB vs 201 MB).

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
