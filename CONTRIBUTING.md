# Contributing to the kernel

[English](./CONTRIBUTING.md) | [简体中文](./CONTRIBUTING.zh-CN.md)

Thank you for considering contributing to **Protofire** — a bare-metal `#![no_std]`
monolithic kernel written in Rust, targeting x86_64, AArch64, and RISC-V 64. All
contributions are welcome: code, documentation, tests, issue reports, bug fixes,
benchmarks, and design discussion.

By participating in this project, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

---

## Quick Reference

| Task | Command |
|------|---------|
| Host-side type-check (all targets) | `make check` |
| Fast test subset (path, I/O, syscall, user integration) | `make test-fast` |
| Full host unit + integration tests | `make test` |
| Full verification gate (fmt + clippy + test + cross-build) | `make verify` / `make verify-p3` |
| Bare-metal builds | `make build` / `make build-aarch64` / `make build-riscv64` |
| Run under QEMU | `make run` / `make run-aarch64` / `make run-riscv64` |
| Clippy (critical lints are errors) | `make clippy` |

See [README.md](README.md) for the complete build/test matrix.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Where to Start](#where-to-start)
3. [Communication & Discussion](#communication-discussion)
4. [Code Style & Conventions](#code-style--conventions)
5. [Verification Gate](#verification-gate)
6. [Adding or Modifying a Syscall](#adding-or-modifying-a-syscall)
7. [Documentation](#documentation)
8. [Submitting Changes](#submitting-changes)
9. [PR Review Process](#pr-review-process)
10. [Contributor Recognition](#contributor-recognition)

---

## Development Setup

### Prerequisites

- **Rust toolchain:** the repository pins the exact channel, components, and
  targets in [`rust-toolchain.toml`](rust-toolchain.toml) (currently `1.94.1`).
  The file installs the three `*-none` targets automatically:
  - `x86_64-unknown-none`
  - `aarch64-unknown-none`
  - `riscv64gc-unknown-none-elf`
- **QEMU** — required for `make run`, `make run-aarch64`, `make run-riscv64`,
  and for the interactive demo shell.
- `rustfmt` and `clippy` (both listed in the toolchain file).

### First Build

```bash
make check          # fast host-side type-check
make verify-p3      # full gate: fmt + clippy + tests + cross-target build
make run            # boot x86_64 under QEMU (demo shell with ~40 builtins)
```

---

## Where to Start

- Read the [docs](docs/) first
  [`docs/en/README.md`](docs/en/README.md) (architecture overview),
  [`docs/en/syscall.md`](docs/en/syscall.md) (ABI), and
  [`docs/en/current-status.md`](docs/en/current-status.md) (subsystem status).
- Good first tasks are usually marked with the `good first issue` label on
  GitHub; if none exist, the "known gaps" in `current-status.md` are excellent
  starting points.
- If you are unsure where a change belongs, ask in an issue before starting —
  it saves rework.

Layout of the kernel crate:

| Path | Purpose |
|------|---------|
| `src/abi/` | Shared ABI records (syscall encodings, process/file/network wire shapes) |
| `src/arch/` | Architecture backends (`x86_64/`, `aarch64/`, `riscv64/`) |
| `src/kernel/` | Kernel core (VFS, drivers, network, process, memory, syscall, sync) |
| `src/user/` | Userspace support: `demo/` (ELF builders) and `shared/` (shell + ABI runtime) |
| `src/user/shared/` | **Single source of truth for the syscall ABI** |
| `src/util/` | Utility helpers |
| `tests/` | Host-side integration tests (fs, io, memory, net, process, simplefs, sync, syscall) |
| `docs/` | Bilingual architecture & subsystem docs (`en/` and `zh-CN/`) |

---

## Communication & Discussion

- **GitHub Issues**: for bug reports, feature requests, and design discussions.
- **Real-time chat**: for quick questions and collaboration, please reach out via email: <2557597107@qq.com>.

---

## Code Style & Conventions

The codebase is ~240,000 lines of Rust across 530+ files; consistency matters.

- **Formatting:** run `cargo fmt`. The gate treats formatting as mandatory.
- **Lints:** run `make clippy` (all targets). Critical lints are warnings-as-errors.
- **`no_std`:** kernel code is `#![no_std]` and `panic = "abort"`. No `std`,
  no dynamic `Box::new` in IRQ/atomic paths beyond the kernel heap.
- **`unsafe` discipline:** keep `unsafe` minimal, local, and documented — each
  block needs a `// SAFETY:` comment explaining the invariants it preserves.
  User memory is always validated before access (never speculatively copied).
- **Error handling:** return `Result`/`Option`; avoid `panic!` in core paths.
  Prefer the kernel's established error types over `expect`.
- **Naming & idiom:** match the surrounding code — same comment density, naming
  conventions, and structure. Follow a change's neighbors, not your habits.
- **Feature gating:** optional subsystems live behind Cargo features (see the
  feature table in [README.md](README.md)). Gate new work appropriately.
- **Tests:** add unit tests with new modules and integration coverage under
  `tests/` when behaviour is user-visible.

---

## Verification Gate

The Makefile provides a multi-tier verification gate. Every PR must pass at
least the full gate before it can be merged:

| Gate | Contents |
|------|----------|
| `make verify-p0` | `cargo fmt --check` + clippy |
| `make verify-p1` | p0 + host-side unit tests + target checks |
| `make verify-p2` | p1 + integration tests |
| `make verify-p3` | p2 + full cross-target build (all three architectures) |

CI runs `make check`, `make verify-p0`, and `make clippy` on every push and
pull request (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

For kernel-behaviour changes, also boot the demo-disk shell under QEMU on the
affected architecture to confirm runtime behaviour:

```bash
cargo build --features demo-disk          # x86_64
cargo build --features demo-disk --target aarch64-unknown-none
cargo build --features demo-disk --target riscv64gc-unknown-none-elf
```

---

## Adding or Modifying a Syscall

The syscall ABI is **the** compatibility boundary of this kernel. Follow these
rules strictly:

1. **Numbering lives in one place only:** `src/user/shared/abi/syscall.rs`.
   The kernel's `SyscallNumber` enum and every userspace wrapper compile against
   the same manifest — numbering cannot drift.
2. **Append-only.** Never renumber, never reuse a freed slot, never insert in
   the middle.
3. **Stability classes:** slots `0–120` are **Stable** (frozen). New syscalls
   are assigned in the **Experimental** range `121–189` until they mature.
4. **Versioning:** bump `SYSCALL_ABI_VERSION_MINOR` for additive changes and
   `SYSCALL_ABI_VERSION_MAJOR` for breaking ones.
5. **Register the handler** in the dispatch table and add the handler module in
   the appropriate `src/kernel/syscall/` category.
6. **Validate user pointers** through the central `SYSCALL_POINTER_SPECS`
   table — never dereference user addresses without validation.
7. **Add typed wrapper(s)** in `src/user/shared/syscall.rs`.
8. **Update the docs:** `docs/en/syscall.md` and `docs/zh-CN/syscall.md`.
9. **Add tests:** unit tests for the handler and, where user-visible,
   integration coverage in `tests/syscall/`.

---

## Documentation

- Docs are bilingual: `docs/en/` (English) and `docs/zh-CN/` (Simplified Chinese).
  When you change a subsystem, update the matching docs in **both** directories
  and the status document `docs/<lang>/current-status.md`.
- Keep the index at [`docs/README.md`](docs/README.md) in sync.
- Code comments should be written in English.

---

## Submitting Changes

1. **Fork & branch.** Create a topic branch from `main` (e.g. `fix/ata-timeouts`).
2. **One logical change per PR.** Keep diffs small and reviewable.
3. **Commit messages:** concise imperative summary line, optional body
   explaining *why*; reference issue numbers when relevant.
4. **Open a pull request** using
   [the PR template](.github/PULL_REQUEST_TEMPLATE/pull_request_template.md)
   and complete the checklist.
5. **Keep CI green.** Ensure `make check`, `make verify-p0`, and `make clippy`
   pass (or the full `make verify-p3` locally for behavioural changes).
6. **Language:** issues and pull requests may be written in **English or
   Simplified Chinese**.

---

## PR Review Process

1. **Automated checks**: CI will automatically run `make verify-p0` and `make clippy` — all must pass.
2. **Human review**: at least **one module maintainer** approval is required (see [MAINTAINERS.md](MAINTAINERS.md)).
3. **Review timeline**: maintainers will provide initial feedback within **1 week**; if overdue, feel free to ping a core maintainer by @mention in the PR.
4. **Updates after review**: after addressing feedback, you may either `git commit --amend` or add fixup commits — the final merge will squash them.
5. **Merge**: a core maintainer or module maintainer will merge the PR into the `main` branch.

---

## Contributor Recognition

- We value every contributor's effort. All code contributors will be listed in the [AUTHORS](AUTHORS) file at the project root.
- By contributing code to this project, you agree to be listed in the [AUTHORS](AUTHORS) file. The list is periodically generated from `git log --format='%aN <%aE>' | sort -u`.
- Contributions are not limited to code — documentation, tests, design discussions, and bug reports are equally appreciated.