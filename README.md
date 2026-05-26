# interpose-sandbox

A microVM-based agent sandbox that runs interpose's kernel enforcer **with the kernel itself under our control**. Built on [Firecracker](https://firecracker-microvm.github.io/). Open source, no proprietary runtime dependency.

In one sentence: **the parts of Docker SBX we couldn't change, in a stack where we can.**

## Why this exists

- **Docker SBX** (`docker/sbx-releases`) is brand-recognition for AI-agent sandboxing — but it ships a stripped-down proprietary kernel without `CONFIG_BPF_LSM=y` or `CONFIG_DEBUG_INFO_BTF=y`. interpose's LSM-BPF enforcer can't load inside SBX. Verified 2026-05-26 with `interpose doctor --sandbox` (5/10 required checks fail).
- **Lima** works (proven end-to-end in interpose Milestone 1) and is the right answer for **Mac developer** workstations — Apple-VZ native, fast.
- **Firecracker** is the right answer for **Linux server / CI / production** deployments — open source, AWS-grade, total kernel control, sub-second boot, tiny footprint.

This repo is the Firecracker glue: a CLI + library that spins up microVMs running our [`interpose-kernel`](https://github.com/interposehq/interpose-kernel) image with interpose preloaded. Same UX shape as `sbx`, ours top to bottom.

## Status

**v0.1.0** — `interpose-sandbox new shell` boots a Firecracker microVM from an `interpose-kernel` image and drops the operator into an auto-login Alpine shell on the serial console. Foreground only; `ls`/`run`/`rm` ship in v0.2 once we have a PTY/socat wrapper around firecracker's serial console.

End-to-end pieces in place:

| Piece | Status |
|---|---|
| `interpose-sandbox doctor` (host audit) | ✅ — checks /dev/kvm, firecracker binary, interpose-kernel image, etc. |
| `internal/kernel` (pull + extract from OCI) | ✅ — local-first, `docker cp /kernel` works against scratch-based interpose-kernel images |
| `internal/rootfs` (Alpine ext4 builder) | ✅ — docker-run shellout, 512 MiB image, serial getty auto-login |
| `internal/firecracker` (lifecycle) | ✅ — foreground spawn with inherited stdio |
| `interpose-sandbox new shell` | ✅ — end-to-end on a KVM-capable Linux host |
| `interpose-sandbox new claude .` (agent baked in) | 🚧 v0.3 |
| `ls` / `run` / `rm` (background sandboxes) | 🚧 v0.2 |
| Host port-forward for WebAuthn ceremony | 🚧 v0.2 |

## Where you can actually run this

**This is critical.** Firecracker requires KVM, which means a Linux host with hardware virtualization exposed to the kernel. Concretely:

| Host | KVM available? | interpose-sandbox runs? |
|---|---|---|
| Linux laptop / desktop / server (any distro with KVM module loaded) | ✅ | ✅ |
| EC2 c6g/c7g/m6g/c5/c6/m5 (any non-`t3` family) | ✅ | ✅ |
| EC2 `*.metal` instances | ✅ | ✅ |
| Hetzner Cloud CAX / CCX, DigitalOcean droplets, Linode | ✅ (most) | ✅ |
| **Apple Silicon Mac via Lima (Apple VZ backend)** | ❌ | ❌ — no nested virt on M1/M2; M3+ has hardware support but Lima's VZ backend doesn't surface it |
| Apple Silicon Mac via Lima (QEMU backend) | ❌ | ❌ — software emulation only |
| Intel Mac via UTM/Parallels Linux VM | usually ✅ | ✅ |
| WSL2 | ⚠️ (nested-KVM dependent) | not v0.1 scope |

If you're on Apple Silicon and want to validate `interpose-kernel` itself (just the kernel, not the sandbox), see the QEMU/HVF smoke test recipe in [`interpose-kernel/docs/where-this-fits.md#validation-evidence`](https://github.com/interposehq/interpose-kernel/blob/main/docs/where-this-fits.md#validation-evidence) — that path works on Mac.

For interpose-sandbox itself, plan to deploy to a real Linux host. Cheapest realistic targets:

- **Hetzner CAX11** — €4/month, arm64, KVM-capable. ~5 min to provision.
- **EC2 c6g.medium** — ~$0.03/hr if you're already an AWS user.
- **Your existing Linux laptop/server** — if you have one.

## Demo: `doctor` on a host that's NOT ready

Running `interpose-sandbox doctor` on a fresh Apple-Silicon Lima Ubuntu VM (no KVM, no Firecracker, no Docker) shows what a non-ready host looks like — note the explicit "install-required" verdict with line-by-line fixes:

```
$ interpose-sandbox doctor
interpose-sandbox doctor — host capability audit
------------------------------------------------------------
  [FAIL] /dev/kvm missing — kernel doesn't expose KVM
  [FAIL] /dev/kvm not openable for RW: open /dev/kvm: no such file or directory
  [FAIL] firecracker binary not on PATH
  [WARN] docker not on PATH — can't audit local interpose-kernel image cache
  [WARN] interpose binary not on PATH — sandboxes will use whichever interpose is in the kernel image

Verdict: install-required

Next steps:
  - ensure the host has KVM enabled (modprobe kvm + kvm_intel|kvm_amd; CONFIG_KVM=y in kernel build)
  - add your user to the 'kvm' group: sudo usermod -aG kvm $USER && newgrp kvm
  - install Firecracker: see https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
```

Exits with code 2 (`install-required`). On a Linux host with KVM + Firecracker + Docker installed and an interpose-kernel image pulled, it exits 0 (`ready`).

## Quick use (when v0.1 lands)

```bash
# Host-side prereqs (Linux only — Firecracker needs KVM)
interpose-sandbox doctor

# Spin a sandbox with shell + interpose preloaded
interpose-sandbox new shell .          # mounts cwd inside the VM
interpose-sandbox run <name>           # attach to the agent's shell
interpose-sandbox ls
interpose-sandbox rm <name>
```

For the Mac path, keep using Lima:

```bash
# interpose's own dev VM, Apple-VZ-native
cd ../interpose && make fresh-vm
```

`interpose-sandbox` and Lima both consume the same `interpose-kernel` image; we just don't need a Firecracker wrapper on Mac because Lima already gives us a great microVM with Apple VZ acceleration.

## Architecture

```
                    ┌────────────────────────────────┐
   host (Linux):    │   interpose-sandbox CLI        │
                    │  - Firecracker process mgmt    │
                    │  - vmconfig generation         │
                    │  - host port-forward for auth  │
                    └──────────┬─────────────────────┘
                               │ spawns
                               ▼
              ┌────────────────────────────────────┐
              │   Firecracker microVM              │
              │  ┌──────────────────────────────┐  │
              │  │  interpose-kernel (our img)  │  │
              │  │  - CONFIG_BPF_LSM=y          │  │
              │  │  - CONFIG_DEBUG_INFO_BTF=y   │  │
              │  └──────────────────────────────┘  │
              │  ┌──────────────────────────────┐  │
              │  │  rootfs                       │  │
              │  │  - /usr/local/bin/interpose  │  │
              │  │  - getty for shell access    │  │
              │  │  - /workspace = host mount   │  │
              │  └──────────────────────────────┘  │
              └────────────────────────────────────┘
```

Each sandbox is one Firecracker process, isolated by KVM. interpose runs as a daemon inside, listening on `localhost:7421` (broker) and `localhost:7422` (browser auth, port-forwarded to the host so the operator's Mac/Linux laptop browser handles the WebAuthn ceremony).

## Repository layout

```
interpose-sandbox/
├── cmd/interpose-sandbox/      # CLI
│   ├── main.go                 # dispatch
│   ├── doctor.go               # Firecracker host prereqs check
│   ├── new.go                  # create a sandbox (stub)
│   ├── run.go                  # attach to a sandbox (stub)
│   ├── ls.go                   # list sandboxes (stub)
│   └── rm.go                   # remove a sandbox (stub)
├── internal/
│   ├── firecracker/            # Firecracker lifecycle + vmconfig gen
│   └── kernel/                 # fetch + extract interpose-kernel from Docker Hub
├── examples/firecracker/       # sample vmconfig.json
├── docs/
│   ├── architecture.md
│   └── roadmap.md
├── go.mod
├── Makefile
├── LICENSE                     # Apache 2.0
└── README.md                   # this file
```

## Related repos

```
interpose             ← daemon, LSM-BPF programs, AAuth broker, audit log
interpose-sdk-go      ← cooperative-agent client (Go)
interpose-kernel      ← distro-repackaged kernel images (Ubuntu/Debian) with BPF-LSM + BTF
interpose-sandbox     ← THIS REPO: Firecracker wrapper using interpose-kernel
```

## License

Apache 2.0. See [LICENSE](LICENSE).
