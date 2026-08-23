# Protofire Kernel

[English](./README.md) | [简体中文](./README.zh-CN.md)

This is a bare-metal `#![no_std]` monolithic kernel written in Rust, targeting x86_64, AArch64, and RISC-V 64. It provides a file-oriented userspace ABI with preemptive multi-threading, a native TCP/IP stack, a transactional in-memory filesystem (SimpleFs), NUMA-aware scheduling, virtio-gpu accelerated display, MSI/MSI-X interrupt support, per-thread stack canary protection, and a shared `src/user/shared/` library for both kernel and userspace programs.

## Build & Test

### Prerequisites

- Rust stable toolchain with `x86_64-unknown-none`, `aarch64-unknown-none`, and
  `riscv64gc-unknown-none-elf` targets installed
- QEMU (for `make run`, `make run-aarch64` and `make run-riscv64`)

### Quick Start

```bash
# Host-side type-check (all targets)
make check

# Host-side unit + integration tests (requires demo-disk feature)
make test

# Fast-turnaround test subsets
make test-fast          # path, I/O, syscall, user integration regressions
make test-concurrency   # scheduler, input, condvar concurrency regressions
make test-storage       # filesystem, recovery, fault-injection regressions

# Multi-tier verification gate
make verify             # default P3 gate (fmt + clippy + test + cross-check)
make verify-p0          # fastest: fmt + clippy
make verify-p1          # p0 + host unit tests + target checks
make verify-p2          # p1 + integration tests
make verify-p3          # p2 + full cross-target build

# Bare-metal build
make build
make build-aarch64
make build-riscv64

# Run under QEMU
make run
make run-aarch64
make run-riscv64

# Clippy (all targets, warnings as errors on critical lints)
make clippy
```

## Structure

```text
├── src/
│   ├── abi/               # Shared ABI records (syscall encodings, process/file/network wire shapes)
│   ├── arch/              # Architecture backends (x86_64, AArch64, RISC-V)
│   ├── kernel/            # Kernel core (VFS, drivers, network, process, memory, syscall, sync)
│   ├── user/              # Userspace support (ELF loader, program mgmt, shell dispatch, demo payloads)
│   │   ├── demo/          # Demo ELF artifact builder (elf_builder)
│   │   └── shared/        # Shared shell/user runtime logic (ABI types, syscall wrappers, builtins)
│   └── util/              # Utility helpers (debug, formatting, crypto helpers)
├── tests/                 # Host-side integration tests (fs, io, memory, net, process, simplefs, sync, syscall)
├── docs/                  # Architecture and subsystem documentation
├── Makefile               # Build, test, check, clippy, verification gates
├── Cargo.toml
├── build.rs               # Linker script selection
├── linker.ld              # x86_64 linker script
├── linker-aarch64.ld      # AArch64 linker script
└── linker-riscv64.ld      # RISC-V linker script
```

## Feature Flags

| Feature | Purpose |
|---------|---------|
| `demo-disk` | In-memory demo filesystem volumes, demo kernel workers, demo user programs |
| `fs_profiler` | Filesystem operation profiling counters |
| `net_profiler` | Network packet/throughput profiling counters |
| `alloc_profiler` | Kernel heap allocation profiling counters |
| `fault_profiler` | Page-fault profiling counters |
| `educational_networking` | Verbose debug logging in the network stack |

## Architecture Support

| Target | Boot Protocol | Status |
|--------|--------------|--------|
| `x86_64-unknown-none` | Multiboot2 (GRUB) / QEMU PVH | Full |
| `aarch64-unknown-none` | QEMU direct `-kernel` | Full |
| `riscv64gc-unknown-none-elf` | QEMU direct `-kernel` | Partial |

## Documentation

Please refer to the `docs/` directory for the complete design documentation, API manual, and porting guide.

## Contributing

All contributions are welcome — code, documentation, tests, issue reports, or
design discussion. Issues and PRs may be written in English or Simplified
Chinese. See:

- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide (build, test, code style, syscall ABI rules)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — code of conduct
- [SECURITY.md](SECURITY.md) — security policy & vulnerability reporting
- [ROADMAP.md](ROADMAP.md) — project roadmap
- [MAINTAINERS.md](MAINTAINERS.md) — maintainer list
- [NOTICE](NOTICE) — copyright notice

## License

[Apache-2.0](LICENSE)