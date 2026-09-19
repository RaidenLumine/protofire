# Protofire Kernel

This is a bare-metal `#![no_std]` monolithic kernel written in Rust, targeting x86_64, AArch64, and RISC-V 64. It provides a file-oriented userspace ABI with preemptive multi-threading, a native TCP/IP stack, a transactional in-memory filesystem (SimpleFs), NUMA-aware scheduling, virtio-gpu accelerated display, MSI/MSI-X interrupt support, per-thread stack canary protection, and a shared `src/user/shared/` library for both kernel and userspace programs.

## Kernel Name

| Chinese (zh) | English (en) |
| :-: | :-: |
| 源火 | Protofire |

## Environment Setup

The repository is self-contained — there are no external crates to fetch — but
it does need a pinned Rust toolchain and GNU make. QEMU is required only by the
`make run*` targets. Check the result at any time with `make doctor`.

### 1. Rust toolchain

Install [rustup](https://rustup.rs/) and then run any command inside the
repository:

```bash
rustup show     # downloads the pinned toolchain on first use
```

[`rust-toolchain.toml`](rust-toolchain.toml) pins the channel
(`nightly-2026-08-24`), the components (`rustfmt`, `clippy`,
`llvm-tools-preview`) and the three bare-metal targets — `x86_64-unknown-none`,
`aarch64-unknown-none` and `riscv64gc-unknown-none-elf` — so rustup installs all
of them automatically. The first command therefore downloads a few hundred
megabytes; no separate `rustup target add` step is needed.

### 2. Build tools and QEMU

| Platform | Command |
|----------|---------|
| Debian / Ubuntu | `sudo apt install make gcc qemu-system-x86 qemu-system-arm qemu-system-misc` |
| Fedora / RHEL | `sudo dnf install make gcc qemu-system-x86 qemu-system-aarch64 qemu-system-riscv` |
| Arch | `sudo pacman -S base-devel qemu-system-x86 qemu-system-aarch64 qemu-system-riscv` |
| macOS | `brew install make qemu`, then invoke `gmake` — the Makefile needs GNU make, and the `make` on macOS is BSD make |
| Windows | MSYS2 or Git Bash for `make` and `sh` (`pacman -S make` in MSYS2, or `choco install make`), plus QEMU from the [Windows installer](https://www.qemu.org/download/#windows) or `choco install qemu` / `scoop install qemu` |

QEMU provides `qemu-system-x86_64`, `qemu-system-aarch64` and
`qemu-system-riscv64`; only the run targets and `make check-aarch64-runtime`
need it. `grub-mkrescue` and `xorriso` are optional — no target builds a
bootable ISO image yet.

Line endings are pinned to LF by [`.gitattributes`](.gitattributes), so a
Windows checkout still produces scripts, the Makefile, and the assembly
payloads in the form `sh`, GNU make and rustc expect — even with
`core.autocrlf=true`.

### 3. Check the environment

```bash
make doctor     # lists every tool and Rust target, and flags what is missing
```

### Useful make variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PROFILE` | `debug` | `debug` or `release` build profile |
| `TARGET` | `x86_64-unknown-none` | bare-metal target used by `check-target` and `build-x8664` |
| `TARGET_DIR` | `target` | Cargo artifact directory |
| `CARGO_FLAGS` | `--offline` | passed to every cargo invocation; with no dependencies the default keeps builds hermetic, override it (e.g. `make test CARGO_FLAGS=`) to let cargo reach the network |
| `VERIFY_TIER` | `p3` | tier used by `make verify` (`p0` … `p3`) |

### Host support

The bare-metal cross-builds do not depend on the host. The host-side checks are
x86_64-only: the demo payloads are hand-written ELF assembly, so a host that
produces COFF or Mach-O objects cannot assemble them.

| Host | `make check` / `make clippy` / `make build*` | `make test` |
|------|----------------------------------------------|-------------|
| Linux x86_64 | supported | supported — the reference host, and what CI runs |
| Windows x86_64 (MSYS2 / Git Bash) | supported | not yet: the payload-dependent host tests fail on an empty demo payload — run `make test` under WSL2 |
| macOS x86_64 | supported (`gmake`) | not yet, same reason as Windows |
| aarch64 host (Apple Silicon, Windows on Arm) | not supported — the host-side code paths are x86_64-only | not supported |

## Build & Test

The commands below assume the environment above is in place (`make doctor` is
clean).

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
make verify-p0          # fastest: fmt + checks + header coverage
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

- [`docs/kernel-introduction/`](docs/kernel-introduction/README.md) — architecture
  overview and subsystem documentation (boot, memory, process, filesystem,
  network, syscall, shared user runtime), plus the per-subsystem
  [status](docs/kernel-introduction/current-status.md).
- [`docs/fmts/`](docs/fmts/README.md) — the contributor specifications: code
  style, comments, `unsafe` discipline, testing, the syscall ABI contract, and
  commit messages.

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
