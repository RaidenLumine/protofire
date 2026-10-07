# Contributing to the kernel

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
3. [Communication & Discussion](#communication--discussion)
4. [Code Style & Conventions](#code-style--conventions)
5. [Verification Gate](#verification-gate)
6. [Design Documents (RFCs)](#design-documents-rfcs)
7. [Adding or Modifying a Syscall](#adding-or-modifying-a-syscall)
8. [Documentation](#documentation)
9. [Submitting Changes](#submitting-changes)
10. [Commit Message Guidelines](#commit-message-guidelines)
11. [PR Review Process](#pr-review-process)
12. [Contributor Recognition](#contributor-recognition)

---

## Development Setup

### Prerequisites

- **Rust toolchain:** the repository pins the exact channel, components, and
  targets in [`rust-toolchain.toml`](rust-toolchain.toml).
  The file installs the three `*-none` targets automatically:
  - `x86_64-unknown-none`
  - `aarch64-unknown-none`
  - `riscv64gc-unknown-none-elf`
- **QEMU** — required for `make run`, `make run-aarch64`, `make run-riscv64`,
  and for the interactive demo shell.
- `rustfmt` and `clippy` (both listed in the toolchain file).

Per-platform install commands (GNU make, QEMU, the host linker), the host
support matrix, and the useful make variables live in
[README.md § Environment Setup](README.md#environment-setup) and
[README.md § Build & Test](README.md#build--test). `make doctor` reports what
is still missing on your machine and fails when a required tool is absent.

### First Build

```bash
make check          # fast host-side type-check
make verify-p3      # full gate: fmt + clippy + tests + cross-target build
make run            # boot x86_64 under QEMU (drops into the demo shell)
```

---

## Where to Start

- Read the [kernel documentation](docs/kernel/README.md) — the mechanism of
  each subsystem, starting with [`syscalls.md`](docs/kernel/syscalls.md) —
  and [`docs/status.md`](docs/status.md), the per-module census of what
  exists and what is missing.
- Good first tasks are usually marked with the `good first issue` label on
  GitHub; if none exist, the missing column in `docs/status.md` is an
  excellent place to look.
- If you are unsure where a change belongs, ask in an issue before starting —
  it saves rework.

Layout of the kernel crate:

| Path | Purpose |
|------|---------|
| `src/abi/` | Shared ABI records (syscall encodings, process/file/network wire shapes) |
| `src/arch/` | Architecture backends (`x86_64/`, `aarch64/`, `riscv64/`) |
| `src/drivers/` | Device drivers (block, network, display, input, audio, USB) |
| `src/fs/` | VFS, the native filesystem, and every filesystem driver |
| `src/kernel/` | Kernel core (boot, scheduler, process model, sync, IPC, security) |
| `src/memory/` | Frame allocator, TLSF heap, page tables |
| `src/network/` | The kernel's own TCP/IP stack and its protocols |
| `src/syscall/` | Syscall dispatch table and per-category handlers |
| `src/user/` | Userspace support: `demo/` (ELF builders) and `shared/` (shell + ABI runtime) |
| `src/user/shared/` | **Single source of truth for the syscall ABI** |
| `src/util/` | Utility helpers |
| `tests/` | Host-side integration tests (fs, io, memory, net, process, simplefs, sync, syscall) |
| `docs/` | Subsystem mechanism (`kernel/`), status (`status.md`), specifications (`fmts/`) and design documents (`rfcs/`) |

---

## Communication & Discussion

- **GitHub Issues**: for bug reports, feature requests, and design discussions.
- **Real-time chat**: for quick questions and collaboration, please reach out via email: <2557597107@qq.com>.

---

## Code Style & Conventions

The codebase is a large, long-lived Rust tree; consistency matters.

- **Formatting:** run `make fmt`, or `make fmt-all` when you also touched
  `tools/` — its crates are packages of their own, so `cargo fmt` in the root
  does not reach them, and `make fmt-check` checks both. The gate treats
  formatting as mandatory.
- **File headers:** every `.rs` file opens with `//! <repo-relative-path>` on
  line 1 and a bare `//!` on line 2, followed by the `//!` description lines.
  A blank line must separate the whole `//!` header block from the first body
  line, so the header is visually distinct from the code that follows. Enforced
  by `check_source_headers` inside `make verify` (see `scripts/verify.sh`).
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

The list above is the short form. The full specifications — rationale, enforced
checks, and worked examples — live in [`docs/fmts/`](docs/fmts/README.md):

| Specification | Covers |
|---------------|--------|
| [`code-style.md`](docs/fmts/code-style.md) | Formatting, naming, module layout, imports, error handling, feature gating |
| [`comments.md`](docs/fmts/comments.md) | File headers, module and item documentation, `// SAFETY:`, markers |
| [`unsafe-and-safety.md`](docs/fmts/unsafe-and-safety.md) | `unsafe` discipline, MMIO, user-memory validation, panic policy |
| [`testing.md`](docs/fmts/testing.md) | Test placement, registration, fault injection, fuzzing |
| [`syscall-abi.md`](docs/fmts/syscall-abi.md) | Numbering, stability classes, pointer specs, wrappers |

---

## Verification Gate

The Makefile provides a multi-tier verification gate. Every PR must pass at
least the full gate before it can be merged:

| Gate | Contents |
|------|----------|
| `make verify-p0` | repo integrity + documentation citations + fmt-check + host/x86_64 checks + aarch64 check + x86_64/aarch64 build + source header coverage |
| `make verify-p1` | p0 + host unit tests (`test-lib`, concurrency, fast regressions) |
| `make verify-p2` | p1 + storage/recovery/fault-matrix regressions (`test-storage`) |
| `make verify-p3` | p2 + clippy (all targets) + the optional QEMU smokes and the boot-work baseline |

CI runs `make check`, `make verify-p0`, and `make clippy` on every push and
pull request (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

For kernel-behaviour changes, also boot the demo-disk shell under QEMU on the
affected architecture to confirm runtime behaviour:

```bash
cargo build --features demo-disk          # x86_64
cargo build --features demo-disk --target aarch64-unknown-none
cargo build --features demo-disk --target riscv64gc-unknown-none-elf
```

For a change that touches a hot path, `make check-perf-baseline` boots the demo
with the profilers on and compares the work that boot did against the counters
recorded in `scripts/perf-baseline.txt` — frames, page-table maps, blocks read,
packets answered.  The gate compares counters rather than seconds, so it says
whether a change did more or less work and does not depend on how busy the host
was.  If the change moves a counter on purpose, re-record it with
`sh scripts/check-perf-baseline.sh --record`, which keeps each row's tolerance.

The single-CPU boot cannot see the work a second CPU does, so
`make check-perf-baseline-smp` boots the same demo on four CPUs and compares it
against `scripts/perf-baseline-smp.txt`.  A baseline describes one machine
shape, and each file names its own in a header line: a boot of another shape is
refused rather than compared, because the counters of a one-CPU boot and a
four-CPU boot are answers to different questions.  Re-record the multi-CPU one
with `SMP_CPUS=4 BASELINE=scripts/perf-baseline-smp.txt
TARGET_LABEL=check-perf-baseline-smp sh scripts/check-perf-baseline.sh --record`,
and expect to set a tolerance by hand for a counter the schedule moves that a
single-CPU boot never moved — `ipis` is one.

### Moving code between modules: clear the incremental cache first

The bare-metal targets build with incremental compilation on, and Cargo's
cache for a target is keyed by the code that produced it.  Moving a module to
another file changes which codegen unit defines what, and the objects reused
from the previous build then refer to symbols the new build emitted somewhere
else — as *hidden* ones, which the linker cannot resolve:

```
rust-lld: error: undefined hidden symbol: protofire::kernel::topology::GLOBAL_TOPOLOGY
```

The names in that error have nothing to do with the file that moved, which is
what makes it worth recognising: it is not a real unresolved reference, it is
a stale cache.  Clear the target's artefacts and rebuild, and the link
succeeds:

```bash
cargo clean --target x86_64-unknown-none -p protofire
# ... and the same for aarch64-unknown-none / riscv64gc-unknown-none-elf
```

`cargo clean -p protofire` without `--target` only clears the host's
artefacts, so a large move still needs the per-target one.

---

## Design Documents (RFCs)

A change that is too large to argue inside a pull request needs a design
document first. That is a change which adds or changes an interface between
subsystems, starts a new subsystem or a new machine or bus path, changes a
format that outlives a boot, or moves a policy a document states as settled.
The documents live under [`docs/rfcs/`](docs/rfcs/README.md), which also
states the process and the lifecycle; each one is a numbered Markdown file
copied from [`docs/rfcs/0000-template.md`](docs/rfcs/0000-template.md).

The point is not ceremony. The part of a design a diff cannot carry is the
reasoning: which options were really considered and why the others lost. An
RFC is opened as a pull request like any other document, and once it is
decided the code that implements it refers back to it. If you think your
change needs one, read [`docs/rfcs/README.md`](docs/rfcs/README.md) first —
and if you are not sure, open an issue and ask.

---

## Releasing

A release is the source, the artifacts, and the ability to check one against
the other.  The artifacts are reproducible by gate, and each one is signed
with a key that has never signed anything else:

```bash
make verify-p3                                   # the release gate
make check-reproducible-build                    # same source, same bytes
make release                                     # build, name, sign, and verify the bundle
```

`make release` builds the four artifacts the reproducibility gate builds, gives
each the name it ships under, signs each with a fresh one-time key, verifies
every signature with the verifier a user would use, and writes `SHA256SUMS`.
It lands in `dist/<version>/` (override with `RELEASE_DIR`), and it refuses to
sign a version twice, because a key that signs a second artifact is no longer
a key that signed one.  The single-step commands are still there when a
specific artifact needs one:

```bash
cargo run -- sign-release <artifact> <key-id>    # a fresh one-time key each time
cargo run -- verify-signature <artifact> <artifact>.sig <key-id>.public.toml
```

The signature and the key record go with the artifact in the release; the
private half of a Lamport key must not, and must never sign a second artifact
(the command generates a fresh key every time for exactly that reason).

What `make release` deliberately does not do is tag or publish, and it does
not choose the version: it reads `Cargo.toml`, where a bump is a deliberate
act — a 1.x version is a promise about the ABI, not a milestone marker.  The
release itself is the tag, the uploaded bundle, and the key records published
beside it, in that order:

1. `make verify-p3` green, and `PROFILE=release make check-reproducible-build`
   if the release artifacts were built with `PROFILE=release` (they are).
2. Bump the version in `Cargo.toml`, commit, and tag it.
3. `make release`, then upload everything under `dist/<version>/` — artifacts,
   signatures, key records, and `SHA256SUMS` — to the release.

What that buys a user is the check no publisher can fake: rebuild the artifact
from the tagged source, and verify the bytes you produced against the
signature and the published key — the same string the kernel verifies in a
launch manifest, so an installed program and a released image are checked the
same way.

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
   the appropriate `src/syscall/` category.
6. **Validate user pointers** through the central `SYSCALL_POINTER_SPECS`
   table — never dereference user addresses without validation.
7. **Add typed wrapper(s)** in `src/user/shared/syscall.rs`.
8. **Update the docs:** `docs/kernel/syscalls.md`.
9. **Add tests:** unit tests for the handler and, where user-visible,
   integration coverage in `tests/syscall/`.

The full procedure — including the pointer-spec table, the handler shape, and
the review checklist — is in [`docs/fmts/syscall-abi.md`](docs/fmts/syscall-abi.md).

---

## Documentation

- Docs are written in English.  Mechanism lives in
  [`docs/kernel/`](docs/kernel/README.md), the per-module census in
  [`docs/status.md`](docs/status.md), and the roadmap in
  [`ROADMAP.md`](ROADMAP.md); when you change a subsystem, update the
  matching document and the rows in the census it changes.
- Contributor specifications live under `docs/fmts/`; start at
  [`docs/fmts/README.md`](docs/fmts/README.md). If your change alters a
  convention, update the specification in the same PR.
- Design documents live under `docs/rfcs/`; a change large enough to need one
  (see [Design Documents (RFCs)](#design-documents-rfcs)) links the accepted
  RFC from the code it implements.
- What a document cites has to exist. A `src/...` path or a relative link must
  resolve; a bare filename must exist somewhere under `src/`, `tests/`, or the
  repository root; and a line-number citation (`<file>.rs:<line>`) is refused —
  cite the file and name the symbol, because a number rots and a name does not.
  [`scripts/check-docs.sh`](scripts/check-docs.sh) enforces this in `verify-p0`,
  and it also covers the other direction: describe an absent module by name, not
  by filename, since a document cannot cite a ghost without looking like it
  meant to.
- The Makefile declares its targets three times: in the rules, in `.PHONY`, and
  in `make help` (the index of what can be run). All three have to name the same
  set, in both directions, and all three drift — fifteen targets had fallen out
  of the help list and eleven out of `.PHONY`, where a missing entry is worse: a
  target that is not `.PHONY` is skipped, silently and with a zero exit, when a
  file of its name exists. Adding a target means adding it to both lists, and
  [`scripts/check-make-targets.sh`](scripts/check-make-targets.sh) is what says
  you did (`verify-p0`).
- Code comments should be written in English.

---

## Submitting Changes

1. **Fork & branch.** Create a topic branch from `main` (e.g. `fix/ata-timeouts`).
2. **One logical change per PR.** Keep diffs small and reviewable.
3. **Commit messages:** follow the
   [Commit Message Guidelines](#commit-message-guidelines) below — enforced
   locally by `make install-hooks` and by CI.
4. **Open a pull request** using
   [the PR template](.github/PULL_REQUEST_TEMPLATE/pull_request_template.md)
   and complete the checklist.
5. **Keep CI green.** Ensure `make check`, `make verify-p0`, and `make clippy`
   pass (or the full `make verify-p3` locally for behavioural changes).
6. **Language:** issues and pull requests may be written in **English or
   Simplified Chinese**.

---

## Commit Message Guidelines

Protofire follows this spirit: a commit message is a message to future readers,
not a receipt for the diff. Two rules of thumb — keep it short, and say *why*,
not *what* (the diff already shows what).

**Subject line (first line):**

- Imperative mood, capitalised: `Fix ATA timeouts on cold boot` — not `fixed`,
  `Fixes`, or `Fixing`.
- At most 72 characters.
- No trailing period.
- A `<type>:` prefix is required: `feat:`, `fix:`, `refactor:`, `chore:`,
  `docs:`, `test:`, `style:`. Release markers like `Protofire 0.3.0` are the one
  exception. A scope is optional — `fix(ata): ...`.
- `Merge ...` and `Revert "..."` lines generated by git are exempt.

**Body (blank line, then paragraphs):**

- Explain **why** the change is needed and, when relevant, what alternatives
  were considered. Do not restate the diff.
- One logical change per commit; if the body grows past a few lines, consider
  splitting the commit.
- Reference issues/PRs when relevant (`Fixes #123`).

**Attribution trailers:**

Attribution has three fixed roles — the people who own the work, and the tools
that helped — and the trailer categories never cross between them.

| Trailer | For | Notes |
|---------|-----|-------|
| `Signed-off-by:` | the primary developer | **Required on every commit.** Certifies the Developer's Certificate of Origin: you authored or received the change and submit it under the project's license. People only — AI tools must never sign. `git commit -s` adds it. |
| `Co-authored-by:` | collaborating people | One trailer per human co-author, `Name <email>`. GitHub renders these on the commit. |
| `Co-developed-by:` | collaborating people | Linux-style co-development; each co-developer also adds their own `Signed-off-by:`. |
| `Assisted-by:` | AI tools | `AGENT:MODEL [TOOLS]` — no email, tools have none. Follows the Linux kernel coding-assistants policy, e.g. `Assisted-by: Claude:claude-3-opus coccinelle sparse`. |

The usage object of each trailer is fixed: `Co-developed-by:` names a person,
`Assisted-by:` names a tool, and the two can never be swapped. Do not credit a
person with `Assisted-by:`, and do not credit a tool with
`Co-developed-by:` or `Co-authored-by:`.

A complete example for an AI-assisted commit:

    Fix ATA timeouts on cold boot

    Explain why, not what.

    Signed-off-by: Ada Kernelson <ada@example.com>
    Co-authored-by: Bob Lin <bob@example.com>
    Assisted-by: Claude:claude-sonnet-4.5 coccinelle

Trailer lines are exempt from the 72-character body wrap; keep them on one line.

**Enforcement:** `scripts/hooks/commit-msg` validates the subject, body, and the
required `Signed-off-by:` trailer on every `git commit` (install once with
`make install-hooks`) and again on every pull request in CI. If your message is
rejected, read the error and `git commit --amend` — the check is fast and
precise.

The exact semantics of that hook — the check order, its exemptions, the cases it
cannot see at all, and how to write a commit message in Chinese — are specified
in [`docs/fmts/commits.md`](docs/fmts/commits.md).

---

## PR Review Process

1. **Scope**: a change large enough to need a design document needs one
   accepted before the code is reviewed — see
   [Design Documents (RFCs)](#design-documents-rfcs).
2. **Automated checks**: CI will automatically run `make verify-p0` and `make clippy` — all must pass.
3. **Human review**: at least **one module maintainer** approval is required (see [MAINTAINERS.md](MAINTAINERS.md)).
4. **Review timeline**: maintainers will provide initial feedback within **1 week**; if overdue, feel free to ping a core maintainer by @mention in the PR.
5. **Updates after review**: after addressing feedback, you may either `git commit --amend` or add fixup commits — the final merge will squash them.
6. **Merge**: a core maintainer or module maintainer will merge the PR into the `main` branch.

---

## Contributor Recognition

- We value every contributor's effort. All code contributors will be listed in the [AUTHORS](AUTHORS) file at the project root.
- By contributing code to this project, you agree to be listed in the [AUTHORS](AUTHORS) file. The list is periodically generated from `git log --format='%aN <%aE>' | sort -u`.
- Contributions are not limited to code — documentation, tests, design discussions, and bug reports are equally appreciated.
