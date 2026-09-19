# Protofire Kernel

This is a bare-metal `#![no_std]` monolithic kernel written in Rust, targeting x86_64, AArch64, and RISC-V 64. It provides a file-oriented userspace ABI with preemptive multi-threading, a native TCP/IP stack, a transactional in-memory filesystem (SimpleFs), NUMA-aware scheduling, virtio-gpu accelerated display, MSI/MSI-X interrupt support, per-thread stack canary protection, and a shared `src/user/shared/` library for both kernel and userspace programs.

## Kernel Name

| Chinese (zh) | English (en) |
| :-: | :-: |
| 源火 | Protofire |

## Environment Setup

Everything the build needs is either pinned in this repository or checked by
one command:

```bash
make doctor
```

`make doctor` prints one line per tool and Rust target, exits non-zero when
something the build depends on is missing, and is the same command CI runs on
Linux, Windows and macOS.

What the repository cannot pin is a short list — rustup, GNU make with a POSIX
shell, QEMU for the run targets, and your platform's own linker for host-side
binaries — so the rest of this section is only that list, and the versions the
files already pin are not repeated here.

### What the repository already pins

- **Toolchain and targets.** [`rust-toolchain.toml`](rust-toolchain.toml) is the
  single source of truth for the channel, the `rustfmt` / `clippy` /
  `llvm-tools-preview` components, and the three bare-metal targets. Install
  [rustup](https://rustup.rs/) and run any command inside the repository: the
  first one downloads the pinned toolchain with its targets, so there is no
  `rustup target add` step to remember. Do not trust a version written in
  prose — read that file.
- **No cross compiler.** All three `*-none` targets link with the `rust-lld`
  that ships inside the toolchain, so cross-compiling needs no
  `gcc-aarch64-*`, no `gcc-riscv64-*`, no `*-none-elf` binutils, and no
  `bootimage`-style helper. `make build`, `make build-aarch64` and
  `make build-riscv64` work from any host.
- **Line endings.** LF everywhere, enforced by
  [`.gitattributes`](.gitattributes); a `core.autocrlf=true` checkout still
  gives `sh`, GNU make and rustc the files they expect.
- **Host linker.** Host-side targets — the tests, build scripts and the
  `mkimage` helper — are ordinary native binaries, so they use the platform's
  own linker: `cc` on Linux, the Xcode command line tools on macOS, and the
  Visual Studio C++ build tools on an MSVC Windows host. `make check` and
  `make clippy` do not link, so they do not need any of it.

### What you install

| Platform | Command |
|----------|---------|
| Debian / Ubuntu | `sudo apt install make qemu-system-x86 qemu-system-arm qemu-system-misc` |
| Fedora / RHEL | `sudo dnf install make qemu-system-x86 qemu-system-aarch64 qemu-system-riscv` |
| Arch | `sudo pacman -S base-devel qemu-system-x86 qemu-system-aarch64 qemu-system-riscv` |
| macOS | nothing for make — Apple ships GNU Make 3.81, and the Makefile stays within it; `brew install qemu` for the run targets, or `brew install make` if you would rather have a current GNU make (it installs as `gmake`) |
| Windows | `choco install make` (or MSYS2: `pacman -S make`), then run the Makefile from Git Bash so `sh` is on `PATH`; QEMU from the [Windows installer](https://www.qemu.org/download/#windows), or `choco install qemu` / `scoop install qemu` |

QEMU provides `qemu-system-x86_64`, `qemu-system-aarch64` and
`qemu-system-riscv64`, and only the run targets and
`make check-aarch64-runtime` need it. `grub-mkrescue` and `xorriso` are
optional — no target builds a bootable ISO image yet.

### Host requirements

The bare-metal builds and the QEMU run targets are host-independent. Host-side
checks are x86_64-only, for two reasons: the demo payloads are hand-written ELF
assembly, which a host producing COFF or Mach-O objects cannot assemble, and
the host-side code paths (`ptrace`, user address space, payload disassembly)
are `cfg(target_arch = "x86_64")`.

| Host | `make doctor` / `check` / `clippy` / `build*` | `make test` |
|------|-----------------------------------------------|-------------|
| Linux x86_64 | supported — the reference host, covered by CI | supported, and what CI runs |
| Windows x86_64 | supported, covered by CI | not yet: the payload-dependent tests need an ELF payload, which this host does not build — use WSL2 |
| macOS x86_64 (Intel) | supported, covered by CI | not yet, same reason as Windows |
| arm64 host (Apple Silicon, Windows on Arm) | not supported: the host-side code is x86_64-only. An x86_64 container (`docker run --platform linux/amd64`) or an x86_64 machine is the way in | not supported |

An Apple Silicon Mac is the case worth calling out: it cross-builds the
bare-metal targets and runs QEMU fine, but the host-side checks need an
emulated x86_64 environment.

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

### Useful make variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PROFILE` | `debug` | `debug` or `release` build profile |
| `TARGET` | `x86_64-unknown-none` | bare-metal target used by `check-target` and `build-x8664` |
| `TARGET_DIR` | `target` | Cargo artifact directory |
| `CARGO_FLAGS` | `--offline` | passed to every cargo invocation; with no dependencies the default keeps builds hermetic — override it (e.g. `make test CARGO_FLAGS=`) to let cargo reach the network |
| `VERIFY_TIER` | `p3` | tier used by `make verify` (`p0` … `p3`) |

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
