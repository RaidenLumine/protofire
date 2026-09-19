# Comment & Documentation Comment Specification

> **Status:** normative, except where a rule is marked *convention*.
> **Applies to:** every `.rs` file in the repository, including `tests/` and
> `build.rs`.

Comments in this kernel are not decoration. A driver that pokes a device
register, a page-table walk that depends on an alignment invariant, or a lock
that must be held across a call is not self-explanatory from the code alone —
and the reader is usually someone debugging a triple fault at 3 a.m., with no
other documentation open. Write for that reader.

This document defines what comments look like and what they must say. The
enforcement status of each rule differs, and the difference matters:

| Rule | Enforced by |
|------|-------------|
| File header shape (§2) | `check_source_headers` in [`scripts/verify.sh`](../../scripts/verify.sh), part of `make verify-p0` |
| Everything else | Review. There is no lint for `// SAFETY:` or for header prose. |

---

## 1. Language

**Code comments are written in English.** Module docs, item docs, block
comments, `// SAFETY:` arguments, `TODO` markers — all of them. Documentation
under `docs/` is English too.

Non-ASCII text does appear in the tree, but only where it is *data* rather than
prose: encoding tables in the `unicode` and `gb18030` codepaths, and UTF-8 test
fixtures. That is not a licence to write explanatory comments in another
language.

The one thing worse than a comment in the wrong language is a garbled one. If
you are not comfortable writing an English comment that says what you mean,
write the comment in your review thread and ask a maintainer to help — the rule
is about the comment being correct, so it is fine to iterate on it before the
commit lands.

---

## 2. The file header

Every `.rs` file opens with a `//!` header. The shape is exact, and it is
checked on every `make verify-p0`:

```
//! <repo-relative path>
//!
//! <description>
```

### The rules

1. **Line 1 is exactly `//! ` followed by the path relative to the repository
   root** — `//! src/kernel/fs/mod.rs`, `//! tests/fat32.rs`, `//! build.rs`.
   Forward slashes, no leading `./`, and relative to the repository root, **not**
   to `src/`. The checker compares the whole line as a string.
2. **Line 2 is exactly `//!`** — a bare marker with nothing after it.
3. **Description lines follow**, also prefixed with `//!`.
4. **One blank line separates the header block from the first body line.** The
   header must not run straight into `use` statements or `#![...]` attributes.

These four checks are performed by `check_source_headers()` in
[`scripts/verify.sh`](../../scripts/verify.sh), which reports coverage as
`path=<n> blank=<n> separated=<n> total=<n>` and fails the gate unless all three
counts equal the file count. It applies to every `.rs` file outside `target/`.

### What the checker does not check

The script validates the *shape*, not the *content*. It will happily accept an
empty description, and it does not look past line 2. The following are therefore
on you, not on the gate:

- Actually writing a description. A header with no prose is a defect even though
  it passes.
- Keeping the path accurate if a file moves. The check compares against the
  file's current location, so a stale path fails the gate — but a file that was
  copied rather than moved can carry a wrong path that still happens to match.
- The single-header rule. `src/main.rs` currently carries two consecutive `//!`
  blocks because only lines 1–2 are examined; do not take it as a model.

### Writing the description

Lead with what the module *is* and what it is *for*, in one or two sentences.
Then add structure if the module has any:

- **A blank `//!` line starts a new paragraph.** Use it to separate a one-line
  summary from the detail.
- **A short title line is a common and accepted pattern** — a single sentence,
  then a blank `//!`, then the fuller description. Both of these are correct:

  ```
  //! src/arch/x86_64/serial.rs
  //!
  //! x86_64 COM1 serial backend used by early logging.
  ```

  ```
  //! src/lib.rs
  //!
  //! Protofire Kernel Library
  //!
  //! This is the main library crate for the Protofire kernel.
  //! It provides the core error types, module structure, and logging macros used
  //! throughout the kernel and shared ring-3 library.
  ```

- **Use markdown.** Module docs are rendered as documentation and are expected
  to use it: backticked identifiers, `[`intra-doc links`]`, bullet lists, and
  occasional `#` headings where a module documents a protocol or a set of
  rules. A `mod.rs` that owns several submodules conventionally lists them:

  ```
  //! src/kernel/network/mod.rs
  //!
  //! Kernel-owned TCP connectivity abstraction used by syscall and
  //! remote-download paths.
  //!
  //! Sub-module organisation:
  //! - `link/`     — Link-layer: `device` (NIC trait), `ethernet` (framing)
  ```

- **Do not invent a tag vocabulary.** There is no `//! Module:`, `//! Author:`,
  `//! File:`, `//! License:`, or `//! Status:` convention in `.rs` files, and
  no `.rs` file carries one. (The `# File:` / `# Purpose:` headers you will see
  in `Makefile`, `Cargo.toml`, and the shell scripts are a separate convention
  for non-Rust files — see §8.)

---

## 3. Item documentation (`///`)

Public API is documented. `///` is the most common comment form in the tree by a
wide margin, and the expectation is that a reader can understand a module's
surface without reading its body.

**Document the contract, not the implementation.** The signature already says
the name, the argument types, and the return type; repeating them wastes the
reader's attention. What earns a line is:

- the invariant the caller must hold,
- the meaning of a non-obvious argument (a `usize` that is an index vs. a
  handle vs. a byte count),
- what a plain `usize` return actually counts,
- which error a caller should expect and when.

### Section tags

These tags are in use and are the accepted set:

| Tag | Use | Notes |
|-----|-----|-------|
| `# Safety` | `unsafe fn` and other caller-obligation APIs | The most common tag by far. State the invariant the caller must uphold — this is the contract that makes the `unsafe` callable at all. |
| `# Errors` | Functions returning `Result` | Name the conditions that produce an `Err`. |
| `# Panics` | Functions that can panic | Say exactly what triggers it. |
| `# Examples` | Where a usage example earns its space | Should compile as a doc test where the host target allows. |

`# Returns` and `# Arguments` are **not** used in this codebase. Do not
introduce them: prose in the first line of the doc comment covers the same
ground without a heading that the reader has to scan past.

```rust
/// # Safety
///
/// This is a bare-metal instruction; calling it under a host kernel is UB.
pub unsafe fn cpuid(leaf: u32, sub_leaf: u32) -> CpuidResult {
```

```rust
/// # Errors
///
/// Returns `InvalidArgument` if `data.len()` is not 4096, or
/// propagates device errors from the underlying block device.
```

---

## 4. Block and line comments (`//`)

Use `//` inside function bodies to explain **why**, at the point where the
reason is not recoverable from the code. The dense cases are exactly the ones
this kernel is full of:

- a magic number that came off a device register description,
- the order two writes must happen in,
- why a lock is dropped before a call rather than after,
- why an apparently redundant check is load-bearing.

Do not narrate the code. `// increment the counter` above `counter += 1` costs
the reader a line and returns nothing. If a block needs a comment to say what it
does, that is usually a signal to extract a named function.

Trailing comments are used sparingly, mostly on constants and struct fields
where a short note fits better beside the value than above it.

---

## 5. The `SAFETY` comment

Every `unsafe` block is preceded by a comment arguing why the operation is
sound. This is the single most important comment convention in the kernel: it
is what turns an `unsafe` block from an assertion of authority into something a
reviewer can check.

### Format

- **`// SAFETY:` — all caps, colon, one space.**
- Placed **immediately before** the `unsafe` block it justifies. For a multi-line
  block the variants `// SAFETY: <reason>` followed by `unsafe {`, and
  `unsafe { // SAFETY: ...` on the opening line, are both in use; prefer the
  line above.
- The body states the **invariant and why it holds here** — not "this is unsafe
  because it's a pointer". Name what makes *this* call sound.

```rust
// SAFETY: `base` is verified to be valid MMIO during initialisation.
let seconds: u32 = unsafe { core::ptr::read_volatile((base + PL031_DR) as *const u32) };
```

```rust
// SAFETY: All RTC register indices read below are valid CMOS registers
// (0x00–0x0B, 0x32).  The update-in-progress flag has been checked via
// rtc_wait_while_updating() so the register values are consistent.
// CMOS port access is single-threaded during this function.
```

Note what these do: they are checkable. A reviewer can go and confirm that the
base address was validated, or that the update-in-progress flag really is
checked. "SAFETY: this is fine" is not a comment, it is a hope.

### Capitalisation is not optional

The mixed-case `// Safety:` form used to appear in around 30 blocks, mostly in
`src/arch/x86_64/i8042.rs` and the virtio drivers. Those have been migrated, and
the tree now has no occurrences left: `// SAFETY:` is the only accepted spelling.
A new `// Safety:` is a defect, not a style preference — it reads as a different
marker to anyone grepping for the convention, which is exactly how the block
that most needs a safety argument goes unnoticed in review.

### Nothing enforces this

There is no `#![deny(clippy::undocumented_unsafe_blocks)]`, no
`#![deny(unsafe_op_in_unsafe_fn)]` companion, and no lint configuration for
unsafe documentation anywhere in the tree. The convention holds because
reviewers hold it. Expect a review comment asking for the argument if you skip
it, and treat "the block is obviously fine" as a reason to write the comment
rather than to omit it — obviousness is what makes an invariant worth recording.

---

## 6. Section separators

Long files are divided into labelled sections with a rule made of Unicode box
drawing characters. This is the dominant style in the tree — around 285 files
use it — and it is what new code should follow:

```rust
// ── Syscall number ─────────────────────────────────────────────────────────
// ── Rule actions ──────────────────────────────────────────────────────────
// ── Public API ────────────────────────────────────────────────────────────
```

- Use `─` (U+2500, light horizontal). A double-line variant built from `═`
  (U+2550) exists for major divisions in a handful of files; it is not needed
  in new code.
- **Two leading dashes, one space, the label, one space, then fill to roughly
  the 100-column limit** configured in [`.rustfmt.toml`](../../.rustfmt.toml).
  The exact fill length does not matter; lining several separators up does.
- Section names are short and noun-like: `Constants`, `Public API`,
  `Tests`, `Request codes`.

ASCII rules made of `=` or `-` characters survive in about 36 older files,
mostly under `src/arch/` and `src/kernel/drivers/`. They are **legacy**: do not
copy them into new code, and prefer the box-drawing form when you touch a file
that mixes both.

---

## 7. Markers: `TODO` and `NOTE`

Only two markers are in use, and both are rare — a handful of each across the
whole tree. Sparse is the point: a marker that appears everywhere is noise, and
a `TODO` that never gets resolved is a lie about intent.

- **`// TODO: <what should happen>`** — a known gap with a clear owner-agnostic
  description of the missing work. Say what is missing and, where relevant, what
  would need to change; not "fix this later".
- **`// NOTE: <why this is the way it is>`** — a non-obvious decision that a
  reader would otherwise be tempted to "clean up". Kinds of things worth a
  `NOTE`: an intentional deviation from the surrounding pattern, a workaround
  for a specific device's behaviour, an ordering that looks arbitrary but is not.

A topical tag in parentheses — `// NOTE(utf-8): ...`, `// TODO(init): ...` —
appears a couple of times and is acceptable when a module has several threads of
notes. It is not required; do not invent a taxonomy of tags.

**There is no `FIXME`, `XXX`, `HACK`, or `WARNING` in this codebase**, and new
ones should not be introduced — `TODO:` and `NOTE:` cover the same ground with
less ceremony. If you need to flag something as dangerous, that is what the
review thread and an issue are for; a comment cannot block a merge and an issue
can.

---

## 8. Non-Rust files

Build tooling — `Makefile`, `Cargo.toml`, the CI workflow, and most of the
scripts under [`scripts/`](../../scripts/) — opens with a two-line header:

```sh
# File: scripts/hooks/commit-msg
# Purpose: git commit-msg hook — enforce the Protofire commit message rules.
```

Use that shape when editing those files: `# File: <repo-relative path>` followed
by `# Purpose: <one line>`. Nothing checks it, so a short script that starts
straight in on its logic is not a defect worth fixing — but new files under
`scripts/` should carry it, and a file that already has one should keep it
accurate.

---

## 9. Review checklist

- [ ] The file header matches the enforced shape, and the path is the file's
      real location.
- [ ] The header description says what the module is for — not that it exists.
- [ ] Every `unsafe` block has a `// SAFETY:` above it that states a checkable
      invariant, in caps.
- [ ] Public items have doc comments that describe the contract, not the
      signature.
- [ ] `# Errors` on `Result`-returning functions; `# Panics` where a panic is
      reachable; no `# Returns` / `# Arguments`.
- [ ] Section separators use `// ──`, not ASCII `=` / `-` rules.
- [ ] New `TODO` / `NOTE` markers name something actionable; no new `FIXME`,
      `XXX`, `HACK`, or `WARNING`.
- [ ] All comments are in English.

---

## Related documents

- [docs/fmts/code-style.md](code-style.md) — naming, layout, error handling
- [docs/fmts/unsafe-and-safety.md](unsafe-and-safety.md) — what belongs in an
  `unsafe` block in the first place
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — the short form of these rules
