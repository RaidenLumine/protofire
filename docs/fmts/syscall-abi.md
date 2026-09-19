# Syscall ABI Specification

> **Status:** normative. Changes to this document require maintainer review.
> **Applies to:** `src/abi/`, `src/kernel/syscall/`, `src/user/shared/`,
> `tests/syscall/`.

The syscall ABI is the compatibility boundary of Protofire. Ring-3 programs are
self-contained ELF files that talk to the kernel exclusively through this
interface; there is no dynamic linker and no shared library to absorb a change.
A number that moves, a struct that grows, or a pointer that is validated one way
in the kernel and another way in the wrapper is a silent breakage of every
already-built program.

This document is the detailed contract. [CONTRIBUTING.md](../../CONTRIBUTING.md)
carries the short version; where the two disagree, this document wins.

---

## 1. Principles

1. **ABI stability first.** Stable slots are frozen. Correctness and
   compatibility outrank convenience, naming taste, and consolidation.
2. **One source of truth.** A syscall number is written down exactly once. The
   kernel enum and the userspace wrapper are both derived from the same
   manifest; they cannot drift because they do not hold independent copies.
3. **Append-only.** Numbers are assigned once and never change meaning — not
   even to reclaim a slot nobody uses.
4. **Validate before you touch.** A user pointer is never dereferenced on the
   strength of being non-null. Every pointer is checked against the user
   address window before the handler reads or writes it.
5. **Every change is documented and tested in the same PR.** Numbering rules are
   only real if a test fails when they are broken.

---

## 2. The number manifest

[`src/user/shared/abi/syscall.rs`](../../src/user/shared/abi/syscall.rs) is the
single source of truth. It defines:

| Item | Meaning |
|------|---------|
| `SYSCALL_ABI_VERSION_MAJOR` / `SYSCALL_ABI_VERSION_MINOR` | ABI version, reported to userspace |
| `SYSCALL_COUNT` | Number of defined public syscalls (currently `190`) |
| `MAX_SYSCALLS` | Size of the kernel dispatch table (currently `256`) |
| `SYS_*` constants | The number of each syscall, `0..SYSCALL_COUNT` |
| `SyscallStability` + `syscall_stability(n)` | Stable / Experimental classification |
| `syscall_name(n)` | Human-readable name, for audit trails and tests |

Consumers, none of which may re-declare a number:

- [`src/kernel/syscall/table.rs`](../../src/kernel/syscall/table.rs) — the
  `SyscallNumber` enum, `SYSCALL_REGISTRY`, and `PUBLIC_SYSCALL_COUNT`
  (derived as the highest assigned number plus one).
- [`src/user/shared/syscall.rs`](../../src/user/shared/syscall.rs) — the typed
  ring-3 wrappers.
- [`src/kernel/syscall/memory/user.rs`](../../src/kernel/syscall/memory/user.rs)
  — `SYSCALL_POINTER_SPECS`, indexed by number.

Note the direction of the dependency: this manifest lives under `src/user/`, but
the kernel depends on it, not the other way round. Treat edits to it as kernel
edits.

---

## 3. Numbering rules

These are hard rules. Each one exists because breaking it breaks programs that
are already shipped on the demo disk.

### 3.1 Append-only

- **Never renumber** an existing syscall.
- **Never reuse** a number whose syscall was removed. If a syscall must go, its
  number is retired permanently — rename the constant to `SYS_RESERVED_<n>` and
  leave the slot empty. Slots 141 and 142 (`SYS_RESERVED_141`,
  `SYS_RESERVED_142`) are live examples: they are numbered, never reused, and
  still classified as Experimental "until assigned".
- **Never insert** in the middle of the range to keep a group tidy. The file is
  ordered by number because numbering is historical, not thematic.
- New syscalls take the **next unused number** at the end of the defined range,
  and `SYSCALL_COUNT` is raised to `new_number + 1` in the same edit.

### 3.2 Stability classes

| Range | Class | Contract |
|-------|-------|----------|
| `0..=120` | **Stable** | Frozen. Semantics, argument order, and record layouts do not change. Additive *optional* behaviour is the only permitted change. |
| `121..=189` | **Experimental** | May still be adjusted. Behaviour, arguments, and record layouts may change on a **minor** version bump. |

New syscalls are always assigned in the Experimental range until they have
matured and a maintainer graduates them. The classification is computed, not
hand-maintained: `syscall_stability(n)` returns `Stable` for `n <= 120` and
`Experimental` otherwise, and its unit test pins both boundaries. Graduating a
syscall means changing that boundary deliberately — never editing one entry in
isolation.

Beyond `SYSCALL_COUNT` and up to `MAX_SYSCALLS`, slots exist but are unassigned.
The dispatch table must leave them empty; a test asserts the first unassigned
slot is `None`.

---

## 4. Versioning

Bump the ABI version in [`src/user/shared/abi/syscall.rs`](../../src/user/shared/abi/syscall.rs)
as part of the same change that alters the ABI:

| Change | Bump |
|--------|------|
| New syscall appended, new flag bit, new optional field at the end of a record | `SYSCALL_ABI_VERSION_MINOR` |
| Changed semantics of an existing syscall, changed argument order, changed or reordered fields in a record, removed syscall | `SYSCALL_ABI_VERSION_MAJOR` |

A major bump is a **last resort**. If the change can be expressed additively —
a new syscall alongside the old one, a new flag, a field appended to a
fixed-size record — do that instead. The existing unit test pins the current
version constants; update it in the same commit, and make sure the commit
message says why the bump is warranted.

Userspace can read the version at runtime through the `abi_info` syscall, so
programs that must support both sides of a change have a way to detect it.

---

## 5. Adding or modifying a syscall

Work through this list in order. Every item is part of the change, not a
follow-up.

1. **Assign the number.** Add `pub const SYS_YOUR_CALL: usize = <next>;` to
   [`src/user/shared/abi/syscall.rs`](../../src/user/shared/abi/syscall.rs),
   raise `SYSCALL_COUNT`, and add the name to `syscall_name`. Add its stability
   automatically — do not special-case it.
2. **Mirror it in the kernel enum.** Add the variant to `SyscallNumber` in
   [`src/kernel/syscall/table.rs`](../../src/kernel/syscall/table.rs). The
   variant must be *derived from* the manifest constant, never a literal.
3. **Declare its pointers.** Add the entry to `SYSCALL_POINTER_SPECS` in
   [`src/kernel/syscall/memory/user.rs`](../../src/kernel/syscall/memory/user.rs),
   at the index matching the syscall number. An empty slice (`&[]`) is a
   declaration that the syscall takes no pointer arguments or validates them
   entirely itself — not a way to skip the step.
4. **Write the handler** in the appropriate category module under
   `src/kernel/syscall/` (see §6).
5. **Register the handler** in `SYSCALL_REGISTRY`
   ([`src/kernel/syscall/table.rs`](../../src/kernel/syscall/table.rs)).
6. **Add the typed wrapper** in
   [`src/user/shared/syscall.rs`](../../src/user/shared/syscall.rs) so ring-3
   callers never build raw register arguments.
7. **Bump the ABI version** if the change is not purely additive (§4).
8. **Document it** in
   [`docs/kernel-introduction/syscall.md`](../kernel-introduction/syscall.md)
   and, if the change is user-visible, in
   [`current-status.md`](../kernel-introduction/current-status.md).
9. **Test it** — see §9.

**Modifying an existing syscall** follows the same list, minus step 1, plus a
compatibility argument in the PR description: say which range the syscall is in
and why the change is permitted there.

---

## 6. Kernel handler conventions

Handlers live in category modules under `src/kernel/syscall/` (`misc.rs`,
`io_fd.rs`, `fs/`, `network/`, `process/`, `memory/`, and so on). Pick the module
that matches the subsystem the syscall acts on; a new file is justified when a
new category appears, not for a single handler.

The shape is fixed:

```rust
pub(super) fn your_call(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let buffer_ptr = context.arg(1) as *mut u8;
    let length = context.arg(2);

    super::validate_zeroed_args(context, 3)?;
    super::user_memory::with_optional_output_slice(buffer_ptr, length, |buffer| {
        // ... write into `buffer` ...
        Ok(written)
    })?;
    Ok(super::SyscallDispatch::complete(written))
}
```

Rules that this shape encodes:

- **Visibility is `pub(super)`.** Handlers are reachable only through
  `SYSCALL_REGISTRY`; they are not a public API.
- **Return `Result<SyscallDispatch>`,** never a bare `usize`. The dispatch value
  carries the return value *and* any control-flow action the trap path must
  take.
- **Use the `SyscallDispatch` constructors** — `complete(value)`,
  `yield_now()`, `exit(status)`, `return_from_exception(fp)` — rather than
  building the struct by hand. Do not invent a new `SyscallAction` variant
  without understanding the trap path that consumes it.
- **Reject unused arguments explicitly** with `validate_zeroed_args(context, n)`,
  where `n` is the first unused argument index. Silent acceptance of garbage in
  unused slots makes future additions ambiguous; flag arguments go through
  `validate_known_flags`.
- **Return errors, never panic.** `Error::InvalidArgument`,
  `Error::NotFound`, `Error::PermissionDenied` and friends are the vocabulary
  (`src/lib.rs`). A `panic!`/`unwrap` in a handler takes down the whole kernel
  because of a user mistake.
- **Do the work in the smallest scope that holds the validated slice.** Do not
  retain a user pointer past the closure.

---

## 7. Pointer validation

Two mechanisms, and they are not interchangeable.

**`SYSCALL_POINTER_SPECS` is the declaration.** Each entry is a slice of
`SyscallPointerSpec` descriptions built with `SyscallPointerSpec::input(arg,
size_arg, fixed_size)` or `::output(...)`. The central validation path consults
this table *before* the handler runs, so a syscall whose layout is declared here
is protected even if the handler forgets.

Two tests hold the table honest and must keep passing:

- `pointer_spec_table_covers_every_syscall` — the table length equals
  `PUBLIC_SYSCALL_COUNT`. Adding a syscall without a spec entry fails the build.
- `pointer_specs_use_valid_arg_indices` — every `arg_index` and `size_arg_index`
  is in `0..6`.

**`user_memory` helpers are the access.** Handlers reach user memory through
`with_optional_input_slice` / `with_optional_output_slice` (and their siblings
in `src/kernel/syscall/memory/user.rs`), which validate the range against the
user/kernel boundary and reject anything straddling it. Never cast a `usize`
argument to a raw pointer and read it directly; every user access in the tree
goes through this module, and new code is expected to as well.

Three semantics of these helpers are worth knowing precisely, because handlers
depend on them:

- **A zero length short-circuits.** The helper does not inspect the pointer at
  all; it passes an empty slice to the closure. A null pointer with length `0`
  is therefore a valid "no buffer" argument, and so is any other value — a
  zero-length call can never fault.
- **A non-zero length validates first.** The range is checked against the user
  address window before any dereference, so a null or out-of-range pointer with
  a non-zero length becomes `Error::InvalidArgument`.
- **Validation happens outside the SMAP guard, deliberately.** The page-table
  walk is a kernel-internal operation and must not run with AC set; the guard
  wraps only the dereference and the closure. Keep it that way if you add a new
  helper — and note the closure is where user memory is actually touched, so do
  not capture a raw pointer out of it for later use.

---

## 8. Userspace wrappers

[`src/user/shared/syscall.rs`](../../src/user/shared/syscall.rs) exposes the ABI
to ring-3 code in three layers, in this order in the file:

1. **Number re-exports** — the `SYS_*` constants, taken from the manifest.
2. **Raw entry points** — the architecture-specific trap instruction, private
   to the module.
3. **Typed wrappers** — `pub fn sys_<name>(...) -> Result<T, isize>`, the layer
   programs actually call.

Wrapper conventions:

- Name them `sys_` + the syscall's name (`sys_open`, `sys_read`, `sys_stat`).
- Convert the raw return into a typed `Result`; the error side is the negated
  kernel error code as `isize`. Do not leak raw register values to callers.
- Take Rust types in the signature (`&str`, `&mut [u8]`) and do the
  pointer/length packing here — that is the whole point of the layer.
- The wrapper must not re-derive a syscall number arithmetically. Import the
  constant.

---

## 9. Tests

A syscall change is not complete without all three, to the extent they apply:

| Layer | Location | What it pins |
|-------|----------|--------------|
| Manifest | `src/user/shared/abi/syscall.rs` (`mod tests`) | Number, name, stability, version constants |
| Handler | `mod tests` in the handler's module | Argument validation, error cases, boundary conditions |
| Integration | [`tests/syscall/`](../../tests/syscall/) | End-to-end behaviour through the table |
| Fuzz | [`tests/syscall/fuzz.rs`](../../tests/syscall/fuzz.rs) | Malformed/random argument handling (add cases for new pointer layouts) |

Register a new integration test binary in `Cargo.toml` (`[[test]]` with an
explicit `name` and `path`) — the `tests/` tree is not auto-discovered by
directory.

Pointer-validation changes are the highest-risk edits in the tree: a bug here is
a kernel memory-safety bug reachable from ring 3. Test both the accepting and
the rejecting side, including ranges that straddle the user/kernel boundary.

---

## 10. Review checklist

Before requesting review of a syscall change, confirm each line:

- [ ] The number is appended, never renumbered, never reused.
- [ ] `SYSCALL_COUNT` and `syscall_name` are updated.
- [ ] `SyscallNumber` derives from the manifest constant, not a literal.
- [ ] `SYSCALL_POINTER_SPECS` has an entry at the right index.
- [ ] The handler is registered in `SYSCALL_REGISTRY`.
- [ ] The handler returns `Result<SyscallDispatch>`, has no `panic!`/`unwrap`
      on user-controlled input, and validates unused arguments.
- [ ] User memory is reached only through the `user_memory` helpers.
- [ ] A typed `sys_*` wrapper exists and packs pointers itself.
- [ ] The ABI version is bumped for a non-additive change, with the reason in
      the commit message.
- [ ] `docs/kernel-introduction/syscall.md` is updated.
- [ ] `make verify-p3` is green.

---

## Related documents

- [CONTRIBUTING.md](../../CONTRIBUTING.md) — the short-form syscall rules
- [docs/kernel-introduction/syscall.md](../kernel-introduction/syscall.md) —
  the ABI catalog and dispatch internals
- [docs/fmts/code-style.md](code-style.md) — error handling and module layout
- [docs/fmts/testing.md](testing.md) — where tests go and how to register them
