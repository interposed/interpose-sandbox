# interpose-sandbox — architecture

This document captures the runtime architecture and the design constraints behind it. See [`roadmap.md`](roadmap.md) for shipping order and [`README.md`](../README.md) for the elevator pitch.

## Why Firecracker (and not Docker, runc, Kata, Cloud Hypervisor, QEMU)

| Runtime | Why not the right fit |
|---|---|
| Plain Docker (runc) | Containers share the host kernel. We need our own kernel (with BPF-LSM enabled). No good. |
| Kata Containers | Right tech (microVMs), but OCI/K8s-shaped. Operator-targeted "spin up a sandbox for an agent" is heavier than necessary. |
| Cloud Hypervisor | Solid alternative to Firecracker; we'd consider it for v2 if there's a reason. Slightly larger surface, less battle-tested at scale. |
| QEMU direct | Too heavy; slow boot; awkward UX for the single-sandbox-per-agent use case. |
| **Firecracker** | Built for one-VM-per-workload, sub-second boot, tiny memory footprint, runs at production AWS scale (Lambda). Open source, Apache 2.0, total kernel control. |

## Process and filesystem model

```
host (Linux):

  $ interpose-sandbox new shell ./my-project
              │
              │ writes vmconfig.json under ~/.local/state/interpose-sandbox/<name>/
              │ spawns:
              ▼
       ┌─────────────────────────────────────────────┐
       │   firecracker --config-file vmconfig.json   │  (one process per sandbox)
       │                                             │
       │   ┌─────────────────────────────────────┐   │
       │   │ KVM virtualization                   │   │
       │   │ ┌─────────────────────────────────┐ │   │
       │   │ │ interpose-kernel guest          │ │   │
       │   │ │  - LSM-BPF enabled               │ │   │
       │   │ │  - BTF + securityfs              │ │   │
       │   │ │ ┌─────────────────────────────┐ │ │   │
       │   │ │ │ rootfs (/)                  │ │ │   │
       │   │ │ │  - /usr/local/bin/interpose │ │ │   │
       │   │ │ │  - getty for shell          │ │ │   │
       │   │ │ ┃ virtio-fs mounts:           │ │ │   │
       │   │ │ ┃  /workspace ← host ./my-project│ │   │
       │   │ │ ┃  /etc/interpose ← passkey credentials│ │
       │   │ │ └─────────────────────────────┘ │ │   │
       │   │ └─────────────────────────────────┘ │   │
       │   └─────────────────────────────────────┘   │
       └─────────────────────────────────────────────┘
              │
              ├── serial console exposed via Unix socket: ~/.local/state/.../console.sock
              ├── Firecracker API exposed via Unix socket: ~/.local/state/.../api.sock
              ├── interpose broker port-forwarded: host:7421 → guest:7421
              └── interpose auth port-forwarded: host:7422 → guest:7422 (for WebAuthn)
```

## State directory layout

One directory per sandbox, under `$XDG_STATE_HOME/interpose-sandbox/<name>/`:

```
<name>/
├── vmconfig.json     # what we passed to Firecracker
├── api.sock          # Firecracker REST API
├── console.sock      # guest serial console
├── firecracker.pid   # for ls / status / signal
├── kernel            # symlink to extracted kernel from interpose-kernel image
├── rootfs.ext4       # cloned-on-write from the base rootfs (sandbox-local writes)
└── stdout / stderr   # Firecracker process logs
```

Sandboxes are independent — removing `<name>/` and killing the PID fully cleans up.

## Boot sequence

1. `interpose-sandbox new` parses CLI args, picks/generates a sandbox name.
2. Checks `interpose-kernel` is cached locally (`internal/kernel.Cached`). If not, pulls via `linuxkit pkg get`.
3. Creates state directory, COW-clones the base rootfs into it.
4. Generates `vmconfig.json` from `internal/firecracker.Defaults(...)`, customized with the mount paths + memory/cpu.
5. Spawns `firecracker --config-file <path>` as a child process, redirects stdout/stderr to state-dir files, writes the PID file.
6. Polls the Firecracker API socket until it accepts connections (~50ms typically).
7. Calls `PUT /actions { "action_type": "InstanceStart" }` to boot the guest.
8. Returns immediately. Guest is now booting; operator uses `interpose-sandbox run <name>` to attach to the console.

Inside the guest:

1. Kernel boots, mounts rootfs.
2. linuxkit's getty service starts on the serial console.
3. (v0.2+) interpose's daemon starts via a systemd unit baked into the rootfs.

## Auth flow (v0.2+)

The interpose daemon inside the guest binds `localhost:7421` (broker) and `localhost:7422` (browser auth). interpose-sandbox sets up host-side port-forwards via Firecracker's network interface (virtio-net + a host-side tap device).

The operator's host browser hits `http://localhost:7422/...` → routes through the tap → reaches the guest's auth listener → WebAuthn ceremony → broker installs preauth in the guest's BPF map → guest syscall proceeds.

Same logical shape as Lima with port-forwarding (Milestone 1 in interpose's `docs/demo.md`). Just Firecracker doing the microVM work instead of Apple VZ.

## What lives where

| Code path | Responsibility |
|---|---|
| `cmd/interpose-sandbox/*.go` | CLI dispatch + UX |
| `internal/firecracker/config.go` | vmconfig.json generation |
| `internal/firecracker/lifecycle.go` | spawn + signal + Firecracker API client (v0.1) |
| `internal/kernel/fetch.go` | Pull + extract interpose-kernel from Docker Hub |
| (planned) `internal/network/` | tap-device setup, port-forward management |
| (planned) `internal/state/` | $XDG_STATE_HOME directory management, atomic operations |

Tight, single-purpose packages. No frameworks; standard library + Firecracker REST API.
