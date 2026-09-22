# Code Style Specification

> **Status:** normative, except where a rule is marked *convention*.
> **Applies to:** `src/`, `tests/`, `build.rs`.

The repository is roughly 215,000 lines of Rust across 600+ files, written over
time by more than one hand. Consistency is what keeps that readable: a
contributor should be able to open an unfamiliar module — a filesystem driver, a
network protocol, the scheduler — and recognise the shape of it without learning
a new author's habits first.

The rules below are the ones this codebase actually follows. Where a rule is
mechanical it says so, and you should let the tool do the work; where it is a
convention, it says that too, and it is on you and your reviewer.

| Rule set | Enforced by |
|----------|-------------|
| Formatting (§2) | `cargo fmt` / `make fmt-check`, part of `make verify-p0` |
| Everything else | Review |

---

## 1. Match the neighborhood

This is the rule the rest of the document elaborates, and it outranks any
stylistic preference you brought with you.

When you edit a module, follow **its** conventions — the same comment density,
the same naming, the same structure — even where this document would permit
something else. A change that is locally consistent and globally slightly
idiosyncratic is a much smaller cost than a diff that reformats a file to a new
standard while claiming to fix a bug. Do not mix a refactor into a behavioural
change; if the style of a file genuinely needs to change, that is its own PR
with its own justification.

---

## 2. Formatting

`cargo fmt` is mandatory and its output is the standard. The configuration is
[`.rustfmt.toml`](../../.rustfmt.toml); it pins `required_version = 1.10.0` and
sets `unstable_features = true`, so it needs the nightly toolchain that
[`rust-toolchain.toml`](../../rust-toolchain.toml) provides. Run `make fmt`
rather than a bare `cargo fmt` if you are unsure which toolchain is active.

```bash
make fmt          # format the tree
make fmt-check    # what the gate runs — must be clean
```

Settings worth knowing before you fight the formatter:

| Setting | Value | Effect |
|---------|-------|--------|
| `max_width` | `100` | Line width; wider than the usual 80, which is why separator rules fill to ~100. |
| `comment_width` | `80` | Comments wrap narrower than code. |
| `wrap_comments` | `true` | The formatter reflows your comment text — write comments as prose and let it wrap. |
| `imports_granularity` | `Item` | One `use` per item; it will not merge them. |
| `binop_separator` | `Front` | A wrapped expression breaks *before* the operator. |
| `trailing_comma` | `Vertical` | Multi-line lists get a trailing comma. |
| `merge_derives` | `true` | Multiple `#[derive]` attributes are merged. |

Two things the formatter does **not** do, and which are therefore yours to get
right: it does not reorder `use` groups (§5), and it does not format the contents
of string literals (`format_strings = false`).

---

## 3. Naming

| Item | Convention | Example |
|------|-----------|---------|
| Types, structs, enums, traits | `UpperCamelCase` | `MemoryManager`, `SyscallDispatch` |
| Enum variants | `UpperCamelCase` | `InvalidArgument`, `ReturnFromException` |
| Functions, methods, locals | `snake_case` | `install_global_unchecked`, `try_read_byte` |
| Constants, statics | `SCREAMING_SNAKE_CASE` | `SYSCALL_COUNT`, `GLOBAL_TABLE`, `PERCPU_OFFSET_SCHEDULER` |
| Modules and files | `snake_case` | `boot_report.rs`, `interrupt_controller.rs` |

Files are named after what they contain, in `snake_case`, with no camel case
anywhere in the tree. A module directory with no `mod.rs` of its own uses
`#[path = "..."]` from its parent instead — see §4.

### Established suffixes

These suffixes carry meaning, and a reader will assume them:

| Suffix / shape | Means |
|----------------|-------|
| `install_global` / `install_global_unchecked` / `global()` | The global-singleton pattern — see §8. `_unchecked` marks the variant that skips the lifetime requirement and is therefore `unsafe`. |
| `_locked` | Requires the caller to already hold the relevant lock. Almost always `pub(crate)`, and always documented as such. Examples: `resolve_path_locked`, `allocate_locked`. |
| `try_*` | A non-blocking or fallible attempt. Returns `Option<T>`, `Result<T>`, or `bool` — never a bare value. Examples: `try_read_byte`, `try_consume_send_nonce`. |
| `raw_*` | Hands back an underlying handle or un-wrapped object rather than a safe abstraction. Examples: `raw_sockets`, `raw_socket_object`. |
| `*_count`, `*_initialized`, `*_probed` | Counter and status-flag statics. |

### The `GLOBAL_*` singleton convention

Process-wide singletons are `SCREAMING_SNAKE_CASE` statics whose names read
`GLOBAL_<THING>`: `GLOBAL_TABLE`, `GLOBAL_FS`, `GLOBAL_MEMORY_MANAGER`,
`GLOBAL_STACK`, `GLOBAL_AUDIT_BUFFER`, `GLOBAL_ALLOCATOR`. Subsystems that are
not "the" global of their kind are named for what they hold instead
(`VOLUME_RECOVERY_SUMMARY`, `BOOT_REPORT`, `WORKER_REGISTRY`).

### Names the compiler dictates

A handful of symbols come from outside and must not be renamed.
`__stack_chk_guard` is the stack-canary symbol the compiler emits references to,
and it legitimately violates `SCREAMING_SNAKE_CASE`. Such cases are declared with
a targeted `#[allow(non_upper_case_globals)]` on the item rather than a
module-wide allow.

---

## 4. Module and file layout

The crate roots declare their modules alphabetically. `src/lib.rs` is the
shortest example:

```rust
pub mod abi;
pub mod arch;
pub mod kernel;
pub mod user;
pub mod util;
```

`src/kernel/mod.rs` and every other large `mod.rs` continue the same way —
`audit`, `boot_report`, `compression`, `config`, `console`, … — with
feature-gated modules carrying their `#[cfg]` and a note explaining the gate.

The rest of a `mod.rs` follows this order:

1. The `//!` file header (§[comments.md](comments.md#2-the-file-header)).
2. `pub mod` declarations, alphabetical.
3. `use` imports, grouped per §5.
4. `pub use` re-exports.
5. `const` and `static` items.
6. Types, then their `impl` blocks, then free functions.
7. `#[cfg(test)] mod tests` at the end of the file.

A file that would otherwise need a `mod.rs` in a subdirectory may instead be
declared from its parent with `#[path]`, which is how `src/kernel/syscall/`
organises its handler categories:

```rust
#[path = "fs/metadata.rs"]
mod fs_metadata;
```

Use that when a directory would hold a single file and the extra `mod.rs` would
be a level of indirection with nothing in it. Where a directory genuinely has
several files (`src/kernel/fs/simplefs/`, `src/kernel/network/tcp/`), a normal
`mod.rs` is the right shape.

Re-export deliberately rather than wholesale: `pub use` in a `mod.rs` is how a
subsystem presents a flat surface (`process::HANDLE_RIGHT_READ`) while its
implementation lives in submodules. If a `pub use` exists to make a sibling
module's imports read better, say so in a comment — a bare re-export with no
consumer is hard to justify later.

---

## 5. Imports

[`.rustfmt.toml`](../../.rustfmt.toml) sets `imports_granularity = "Item"` and
`reorder_imports = true`, but `group_imports = "Preserve"` — meaning rustfmt
sorts *within* a group and leaves *which group an import is in* to you. The
grouping is therefore a convention you have to maintain by hand, and it has
three tiers separated by blank lines:

1. **External crates** — `core::`, then `alloc::`, each internally sorted.
2. **Crate-absolute paths** — `crate::…`, sorted.
3. **Parent-relative paths** — `super::…`, sorted, last.

```rust
use alloc::sync::Arc;

use crate::kernel::process::Scheduler;
use crate::kernel::process::Thread;
use crate::kernel::process::ThreadWaitOutcome;

use super::wait::plan_timed_wait;
use super::wait::TimedWaitPlan;
use super::Mutex;
use super::MutexGuard;
use super::WaitQueue;
use super::WaitTimeoutCleanupRef;
```

Because granularity is `Item`, a single type imported from a deep path gets its
own line rather than being nested:

```rust
use crate::kernel::fs::DirectoryEntry;
use crate::kernel::fs::FileMetadata;
use crate::kernel::fs::NodeKind;
```

Prefer `super::` over `crate::` when the item is genuinely in the parent module
— it keeps a module readable in isolation. Reach for `crate::` when crossing
subsystems. `#[cfg]`-gated imports sit in the group they belong to, on their own
line.

A small number of files place a `super::` import before the `crate::` group
(`src/arch/x86_64/interrupts.rs` is one). Follow the three-tier order in new
code; do not take those files as the model.

---

## 6. Visibility

**Start private, widen reluctantly.** The default for an internal helper is
`pub(crate)`; the tree uses it over 2,400 times, and `pub(super)` — for items
that exist only for the parent module, like syscall handlers — around 370 times.

- **`pub(crate)`** — shared across the kernel but not part of any public
  surface. This is the normal choice for a helper that another subsystem needs.
- **`pub(super)`** — visible only to the parent, typically a handler reached via
  a registry table. Syscall handlers are `pub(super)` for exactly this reason:
  they are callable through `SYSCALL_REGISTRY` and nowhere else.
- **`pub`** — reserved for the ABI (`src/abi/`), types genuinely shared between
  the kernel and ring-3 code (`src/user/shared/`), and the small set of kernel
  entry points. A `pub` item in `src/kernel/` should be defensible as a
  deliberate surface, not a habit.

A `pub fn` reachable from nowhere but its own module is a defect that review
should catch; there is no `dead_code` lint standing in for that judgement in
the kernel build.

The same judgement, applied to `#[allow(dead_code)]`: it says the compiler
cannot prove what you can, and it is worth less the longer it lives.  A
module-wide one has to carry **why** the item is unread and **when** the line
goes.  The two file-level allows this rule was written for had both gone
stale — one covered an unused skeleton whose consumers had existed for months,
the other a "no caller yet" set that had six callers — and nothing in the tree
said so.  Prefer the narrowest form that silences exactly what is
intentionally unread: an attribute on the item, a `#[cfg]` gate naming the
targets that do read it, or `#[cfg(test)]` for a surface only tests use.
Deleting the line and reading what the compiler names is the cheapest audit
available, so reach for it before reading the code.

---

## 7. Error handling

### The types

There is one core error type, `Error`, defined in [`src/lib.rs`](../../src/lib.rs)
with a companion alias:

```rust
pub type Result<T> = core::result::Result<T, Error>;
```

Use `crate::Result<T>` in signatures. Domain-specific errors are separate enums
named `<Domain>Error` (`ConfigError`, `FuseError`, `VirglCommandError`),
converted at the boundary into `Error` — they do not replace it, and they do not
leak into the syscall surface.

### Human-readable text: `as_str`, not `Display`

`Error` and the domain error enums expose `pub const fn as_str(self) -> &'static str`
rather than implementing `fmt::Display`. Follow that. `Display` in this tree is
for types that are *formatted* (`MacAddress`, `IpAddress`, `ThreadState`), not
for errors; adding a `Display` impl to an error type so it can be `{}`-printed
breaks the pattern and, in `const` contexts, is not usable where `as_str` is.

### Propagation

Use `?`. It is used thousands of times across the tree and is the expected way
to move an error up. Handlers return `Result`; syscall handlers return
`Result<SyscallDispatch>` so the dispatch value and the error travel together.

The kernel/ring-3 encoding lives in `src/abi/syscall.rs` (`encode_error` /
`decode_result`), with `Error::from_syscall_code` on the receiving side. Do not
invent a second encoding.

### When a panic is acceptable

`panic!` appears about 30 times in the entire tree, and the rule that produces
that number is: **panic only for a violated invariant that indicates the kernel
is already corrupt or the build is wrong.** It is never a way to reject input.

The legitimate cases, all of which are assertions about the code rather than
about the data:

- Layout assertions checked at startup — `PerCpuData must be exactly 64 bytes`,
  `PerCpuData.cpu_id must be at offset 0`.
- Heap-integrity checks in the TLSF allocator (corruption, misalignment,
  invalid size).
- An unreachable `match` arm on a value the type system cannot narrow.

Exhausted resources, bad arguments, and unparseable input are **errors**, not
panics. Remember that `panic = "abort"` is set for every profile in
[`Cargo.toml`](../../Cargo.toml): a panic is not a recoverable event, it is the
end of the machine.

### `unwrap` and `expect`

Production paths prefer a fallback (`unwrap_or`, `unwrap_or_default`) over a
bare `unwrap()`, and prefer an explicit error over `expect`. The large counts of
`unwrap`/`expect` in the tree are concentrated in `#[cfg(test)]` code and demo
scaffolding, where panicking is the point. `expect` with a message is a last
resort, not a substitute for propagating an error — if the compiler is telling
you a value could be `None`, the question is whether that is a bug or a case you
should handle, and the answer is only rarely "abort the kernel".

`assert!`/`assert_eq!` are used freely in tests and host-side code. In kernel
paths, prefer `debug_assert!` for expensive checks that hold by construction —
`debug_assert!` is compiled out of release builds, so it must never be load-
bearing.

---

## 8. Globals: the install pattern

Most subsystems are owned by the `Kernel` struct but must also be reachable from
interrupt handlers, worker threads, and syscall paths that hold no reference to
it. The established answer is a static slot with a fixed trio of functions:

```rust
static GLOBAL_TABLE: AtomicPtr<Table> = AtomicPtr::new(ptr::null_mut());

/// Install a `'static` table.  Prefer this whenever a `'static` reference is
/// available.
pub fn install_global(table: &'static Table) { /* store */ }

/// # Safety
///
/// The caller must guarantee `table` outlives every future `global()` access.
pub unsafe fn install_global_unchecked(table: &Table) { /* store */ }

pub fn global() -> Option<&'static Table> { /* load */ }
```

Rules that make this pattern safe to read:

- **`install_global` takes `&'static` and is safe.** `install_global_unchecked`
  takes a plain reference, ignores lifetimes, and is therefore `unsafe` with a
  `# Safety` section naming the outlives obligation. Prefer the safe one; the
  `unsafe` variant exists for the kernel's own init path, where the owner is a
  field of a `'static`-lived `Kernel` and the borrow checker cannot see it.
- **`global()` returns `Option<&'static T>`.** It can legitimately be `None`
  before initialization. Callers handle that; they do not `unwrap` it in a path
  reachable before init.
- **Implement `Drop` to clear the slot** (`compare_exchange` back to null), so a
  dropped owner does not leave a dangling pointer behind for tests or for a
  re-init.
- **Provide an `uninstall_global` when tests need one.** Test code must be able
  to tear down what it installed.
- **Every call site carries a `// SAFETY:`** when it uses the unchecked form.
  `Kernel::init` is the canonical example, and each of its installs is
  annotated with the reason the reference outlives the process.

Do not add a fourth variant or a new global without a reason the existing three
cannot express. And do not reach for a global to avoid threading a parameter —
the pattern exists for things interrupt handlers must find, not for convenience.

---

## 9. Feature gating

Features are declared in [`Cargo.toml`](../../Cargo.toml) and documented in
[README.md](../../README.md). The set today is `demo-disk`, `runtime`,
`fs_profiler`, `net_profiler`, `alloc_profiler`, `fault_profiler`, and
`educational_networking`. The default set is empty; the bare-metal kernel builds
with no features, and the demo shell and most tests are built with `demo-disk`.

There is **no central `cfg` convergence point** — gates are written at the
definition and use site. The shapes in use:

```rust
// The common demo-disk gate: the module is also available in host tests and on
// a non-bare-metal host build.
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub mod demo;

// Tightest form: bare-metal only, and only with the demo disk or under test.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
```

Guidance:

- **Profiler features gate counters and recording points, not logic.** With the
  feature off the code must behave identically — that is what makes the profile
  trustworthy.
- **`target_arch` / `target_os` gates outnumber feature gates.** Architecture
  dispatch is done with `#[cfg(target_arch = "...")]` behind a facade (see
  `src/arch/mod.rs`), not with runtime branching. New architecture-specific code
  goes through that facade.
- **Register a new feature in three places:** `Cargo.toml`, the feature table in
  `README.md`, and any Makefile target that needs to pass it. An undocumented
  feature is invisible to everyone who did not write it.
- **A feature must not be required to build the kernel.** `make build` with no
  features has to keep working on all three targets; that is what `make
  verify-p0` checks.

---

## 10. Derives and representation

The overwhelmingly common derive set is
`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`, and the guidance is simple:
derive `Debug` on everything, add `Clone`/`Copy` when the type is small and
value-like, and add `PartialEq`/`Eq` when there is a real comparison — usually
for tests.

Two types use `#[repr(usize)]` because they cross an ABI or storage boundary
whose layout is load-bearing: `Error` and `SyscallNumber`. Add a `repr` when the
numeric layout is part of a contract (ABI encoding, on-disk format, register
file, a struct whose size is asserted at startup) and document the contract in
the item's doc comment. Do not add one for ordinary in-memory types.

---

## 11. `no_std` and bare-metal constraints

The kernel is `#![no_std]` with `panic = "abort"`. Consequences that show up in
everyday code:

- **`core` and `alloc` only.** There is no `std`. `Box`, `Vec`, `Arc`, and
  `String` come from the kernel heap, which is initialized partway through
  `Kernel::init()` — so allocation is available only *after* that point, and not
  at all in the earliest boot path.
- **No floating point** in kernel paths, and no `libm`.
- **Be careful with `format!` in hot paths.** It allocates. In an interrupt
  handler, in a scheduler path, or in anything reachable from a lock, prefer
  fixed buffers and the `util::debug` helpers.
- **Do not block in an interrupt context.** Allocating, taking a `Mutex`, or
  waiting on a `Condvar` from an ISR is a deadlock waiting for a quiet moment.

---

## 12. Review checklist

- [ ] `make fmt-check` is clean.
- [ ] Naming follows §3, including the established suffixes.
- [ ] New modules are declared alphabetically; `mod.rs` follows the §4 order.
- [ ] `use` blocks keep the three-tier grouping.
- [ ] New items default to `pub(crate)` / `pub(super)` unless they are genuinely
      part of a public surface.
- [ ] Errors propagate via `Result`/`?`; any new `panic!`/`unwrap` is justified
      under §7.
- [ ] New globals follow the install pattern exactly, including `Drop` cleanup
      and `# Safety` on the unchecked variant.
- [ ] New feature flags are registered in `Cargo.toml`, `README.md`, and the
      Makefile.
- [ ] `make verify-p3` is green.

---

## Related documents

- [docs/fmts/comments.md](comments.md) — file headers, doc comments, `// SAFETY:`
- [docs/fmts/unsafe-and-safety.md](unsafe-and-safety.md) — what is allowed in an
  `unsafe` block
- [docs/fmts/testing.md](testing.md) — test layout and registration
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — the short form of these rules
