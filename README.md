# interpose-sandbox

A microVM-based agent sandbox that runs interpose's kernel enforcer **with the kernel itself under our control**. Built on [Firecracker](https://firecracker-microvm.github.io/). Open source, no proprietary runtime dependency.

In one sentence: **the parts of Docker SBX we couldn't change, in a stack where we can.**

## Why this exists

- **Docker SBX** (`docker/sbx-releases`) is brand-recognition for AI-agent sandboxing — but it ships a stripped-down proprietary kernel without `CONFIG_BPF_LSM=y` or `CONFIG_DEBUG_INFO_BTF=y`. interpose's LSM-BPF enforcer can't load inside SBX. Verified 2026-05-26 with `interpose doctor --sandbox` (5/10 required checks fail).
- **Lima** works (proven end-to-end in interpose Milestone 1) and is the right answer for **Mac developer** workstations — Apple-VZ native, fast.
- **Firecracker** is the right answer for **Linux server / CI / production** deployments — open source, AWS-grade, total kernel control, sub-second boot, tiny footprint.

This repo is the Firecracker glue: a CLI + library that spins up microVMs running our [`interpose-kernel`](https://github.com/interposehq/interpose-kernel) image with interpose preloaded. Same UX shape as `sbx`, ours top to bottom.

## Status

🚧 **Scaffold.** CLI dispatch + Firecracker `doctor` checks + vmconfig generation are sketched in. The `new` / `run` / `ls` / `rm` commands return "not yet — see docs/roadmap.md" pending Firecracker host validation.

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
