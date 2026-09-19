# Unsafe & Safety Specification

> **Status:** normative.
> **Applies to:** every `unsafe` block, `unsafe fn`, and `unsafe impl` in
> `src/` and `tests/`.

In a bare-metal kernel, `unsafe` is not a smell — it is the point. There is no
operating system underneath to validate a device register write, no MMU
abstraction to catch a bad pointer, and no process boundary to contain the
consequences. When a kernel dereferences a user-supplied address without
checking it, the result is not a segfault in a sandboxed process; it is the
machine.

The tree contains roughly 1,300 `unsafe` blocks, 260 `unsafe fn` declarations,
65 `unsafe impl`s, 190 inline-asm blocks, and 300 volatile MMIO accesses. None of
it is checked by a lint — there is no `#![deny(clippy::undocumented_unsafe_blocks)]`
and no equivalent anywhere in the configuration. What keeps this sound is a
convention, applied consistently, and reviewed carefully. This document is that
convention.

---

## 1. What `unsafe` is for

`unsafe` is justified when the operation is something the Rust type system
cannot express at all. In this codebase that means four categories, and very
little else:

| Category | Examples | Where |
|----------|----------|-------|
| **MMIO and port I/O** | `read_volatile` / `write_volatile` on a device BAR, `in`/`out` instructions | `src/kernel/drivers/`, `src/arch/*/` |
| **Inline assembly** | Context switch, trap entry/exit, `stac`/`clac`, cache and TLB maintenance | `src/arch/*/`, `src/user/shared/` |
| **Raw pointer structures** | Page-table walks, the frame bitmap, linked free lists, per-CPU areas | `src/kernel/memory/`, `src/kernel/percpu.rs` |
| **Global singleton slots** | The `install_global_unchecked` pattern (see [code-style.md §8](code-style.md#8-globals-the-install-pattern)) | Throughout |

Plus `unsafe impl` for `Send`/`Sync` on types that are shared across CPUs and
are safe to share **by an argument you have to write down** — see §5.

## 2. What `unsafe` is not for

- **Silencing the borrow checker.** If the compiler will not let you hold two
  references, the answer is a different data layout, an index instead of a
  reference, or a cell type — not a raw pointer. The borrow checker is usually
  reporting a real aliasing question, and `unsafe` does not answer it.
- **Avoiding a bounds check in a hot path.** Only after a profile says so, and
  then with the invariant documented and, if possible, asserted.
- **Reaching a static.** The `install` pattern exists for this; take the
  existing route rather than inventing a new pointer cast.
- **Casting between representations as a shortcut.** Arithmetic on numbers, `as`
  casts between integer widths, and `from_le_bytes`-style conversions are all
  safe and are the expected tools. `transmute` appears only a handful of times in
  the tree — punning a `#[repr(C)]` wire or on-disk struct into the byte array it
  serialises to (`ScsiRw10Cdb` → `[u8; 10]` in the USB mass-storage driver). That
  is a legitimate use *because the sizes are pinned by the protocol*, and those
  call sites say so. Representation-level punning anywhere else needs the same
  justification plus a comment explaining why the layouts are guaranteed to
  agree; do not reach for `transmute` to move between types that merely look
  similar.

If the reason for an `unsafe` block is "otherwise it does not compile", the
block is wrong.

---

## 3. The two-part contract: `// SAFETY:` and `# Safety`

Every `unsafe` operation carries an argument, in one of two places depending on
who is responsible for the invariant.

**Inside a function**, the `// SAFETY:` comment above the block states the
invariant and why *this* call site satisfies it. The full format is specified in
[comments.md §5](comments.md#5-the-safety-comment); the property that
matters here is that the reason must be **checkable**:

```rust
// SAFETY: All RTC register indices read below are valid CMOS registers
// (0x00–0x0B, 0x32).  The update-in-progress flag has been checked via
// rtc_wait_while_updating() so the register values are consistent.
// CMOS port access is single-threaded during this function.
```

**On an `unsafe fn`**, responsibility belongs to the caller, so the obligation is
documented with a `# Safety` section in the doc comment — and the *function body*
is then free to assume it holds:

```rust
/// # Safety
///
/// Must only be called after CR4.SMAP is written successfully.
pub(crate) unsafe fn set_smap_active() {
```

Both halves are required, and they are not interchangeable. An `unsafe fn` with
no `# Safety` section hides the contract; a `// SAFETY:` comment that restates
the signature instead of arguing the invariant provides no information.

**Prefer a safe wrapper.** An `unsafe fn` is a last resort — the usual shape is
an `unsafe` block *inside* a safe function that has established the precondition
itself. `with_user_access_guard` is the model: the caller gets a safe closure API
and never sees the `stac`/`clac` window. Expose an `unsafe fn` only when the
precondition genuinely cannot be established at the call boundary (a layout the
caller knows and the callee does not, an initialisation ordering the caller
controls).

---

## 4. Writing the block

- **Keep it small.** An `unsafe` block wraps the one operation that needs it, not
  the surrounding logic. A 60-line block hides which line actually depended on
  the invariant.
- **Do not widen the window.** In particular, never hold a raw pointer across a
  call that could yield, block, or re-enter the kernel — the invariant you
  checked may not survive it.
- **Do not put an `unsafe` block inside a loop to save an annotation.** If the
  invariant holds for one iteration it holds for all of them; hoist the block.
- **Assert the cheap invariants** you cannot express in the type. A
  `debug_assert!` on alignment or range is compiled out of release builds but
  documents and tests the reasoning. Where the check is free (a shift width, a
  table bound), a real `assert!` is better.
- **Scope the `unsafe` to the operation**, not the statement. `unsafe { read() }`
  is right; `let v = unsafe { read() } + unsafe { read() };` is two windows where
  one would do.

---

## 5. `unsafe impl Send` / `Sync`

An `unsafe impl` asserts something about every future use of the type. Before
writing one, be able to state:

1. **What is shared** — the exact fields, and which of them are not `Send`/`Sync`.
2. **How concurrent access is serialised** — the lock, the atomic, the
   interrupt-disable, or the argument that the field is never mutated after
   init.
3. **Why the accessors cannot violate it** — including via `&self` methods that
   hand out interior references.

Put that argument in a `// SAFETY:` comment on the `impl`, and keep the type's
mutable surface `pub(crate)` or narrower. The `SyncUnsafeCell` wrapper
([`src/util/sync_unsafe_cell.rs`](../../src/util/sync_unsafe_cell.rs)) and the
per-CPU data in [`src/kernel/percpu.rs`](../../src/kernel/percpu.rs) are the
existing, reviewed shapes for this — extend them rather than adding a new way to
share mutable statics.

---

## 6. The ring-3 boundary

This is the highest-risk surface in the kernel and the one place where a mistake
is reachable by any user program. The rules are stricter here than anywhere
else.

### Never dereference a user address on trust

Every user pointer arrives as a `usize` in a syscall argument. It is validated
against the user address window before it is touched — always through the
helpers in [`src/kernel/syscall/memory/user.rs`](../../src/kernel/syscall/memory/user.rs),
never by casting and reading. The mechanisms (`SYSCALL_POINTER_SPECS` and the
`with_*_slice` helpers) are described in
[syscall-abi.md §7](syscall-abi.md#7-pointer-validation); what matters here is
the discipline:

- **Validate the range, not just the pointer.** A buffer that starts in user
  space and ends in kernel space must be rejected, not truncated.
- **A zero length is not a licence to skip a pointer, but it does mean the
  pointer is never read.** The helpers short-circuit on `length == 0` and the
  closure sees an empty slice — so a zero-length call cannot fault regardless of
  the pointer value. Do not add validation that contradicts this, and do not
  assume a zero-length call tells you anything about the pointer's validity.
- **Never retain a user pointer past the closure.** Read the data into kernel
  memory and work from that. The closure is the entire valid lifetime of the
  reference.
- **Re-validate if you re-read.** A kernel data structure or page table that is
  user-writable can change the mapping underneath you; do not cache a validated
  range across a point where the address space could have been modified.

### The SMAP / PAN / SUM window

x86_64 SMAP, AArch64's PAN, and RISC-V's SUM all forbid supervisor access to
user pages unless a flag is set. The kernel does not disable these protections;
it brackets the access instead:

- `with_user_access_guard` (`src/kernel/syscall/memory/user.rs`) is the portable
  entry point. On host test targets it is a plain call of the closure.
- Per architecture, the implementations live in
  `src/arch/{x86_64,aarch64,riscv64}/user_access.rs`. The x86_64 version wraps
  `stac`/`clac` in a RAII `UserAccessGuard` and tracks an `SMAP_ACTIVE` flag,
  because those instructions raise `#UD` on hardware without SMAP.
- **Validation happens outside the guard.** The page-table walk is a
  kernel-internal operation and must not run with AC set. If you add a new
  access helper, keep that ordering.

Never open the window by hand around a region of code — a `stac` without a
matching `clac` on every exit path, including the error paths, leaves the kernel
able to read user memory for the rest of the time slice.

---

## 7. MMIO and device registers

- **Always use `read_volatile` / `write_volatile`.** A plain read of a MMIO
  address may be elided, reordered, or merged by the optimiser. There are no
  exceptions in this tree.
- **Respect access width.** A device that expects a 32-bit register read may
  fault or return garbage on a narrower one. Cast to the width the datasheet
  specifies, and comment the register's name and meaning.
- **Watch ordering and barriers.** Where a write must reach the device before the
  next one, or a read must complete before dependent work, that is a barrier
  (`fence`, `dsb`, `mfence`) — and a comment saying which ordering is required
  and why.
- **Assume the address is identity-mapped device memory**, as established during
  probe. Do not assume the mapping is cached or that a read is free.
- **Do not busy-wait without a bound.** Polling loops need a timeout or an
  escape; a device that never becomes ready must not hang the kernel forever.

---

## 8. Locking, interrupts, and re-entrancy

Most `unsafe` bugs in a kernel are really concurrency bugs wearing a pointer
costume. Two rules prevent the common ones:

- **Nothing that can block belongs in an interrupt context.** No heap
  allocation, no `Mutex` acquisition, no `Condvar` wait from an ISR. A
  `SpinLock` is the exception, and only if the same lock is never taken with
  interrupts disabled elsewhere in a way that creates a cycle.
- **Disable interrupts around a critical section that an ISR also enters**, or
  use a lock type that does it for you. Document the choice where it is not
  obvious.

Context-switch and trap-entry assembly is the one place where the usual advice
inverts; those paths follow their own discipline and should be read in full
before being modified.

---

## 9. Panics

`panic = "abort"` is set for every profile. There is no unwinding, no `catch_unwind`,
and no supervisor to catch the result: a panic in the kernel stops the machine.
Consequently:

- **No `panic!`, `unwrap`, or `expect` on a value derivable from user input or
  device state.** Return an `Error`.
- **A panic in an `unsafe` path is worse than elsewhere**, because it may leave a
  lock held, a device mid-transaction, or AC set. If a panic is genuinely
  reachable there, the surrounding state must already be safe to abandon.
- **Assertions about code invariants are fine** — that is the pattern described
  in [code-style.md §7](code-style.md#7-error-handling). Assertions about data
  from outside the kernel are not.

---

## 10. Review checklist

For every `unsafe` block in the diff:

- [ ] It falls into one of the four categories in §1.
- [ ] A `// SAFETY:` comment states a checkable invariant — not a restatement of
      what the code does.
- [ ] The block is scoped to the operation, not to a region of logic.
- [ ] No raw pointer or reference escapes the block's invariant window.
- [ ] For an `unsafe fn`: a `# Safety` section names the caller's obligation, and
      a safe wrapper was considered first.
- [ ] For an `unsafe impl`: the argument covers what is shared, how it is
      serialised, and why the accessors preserve it.
- [ ] No `panic!`/`unwrap` reachable on external input.
- [ ] User memory is validated through the `user_memory` helpers, with
      validation outside the SMAP/PAN/SUM guard.
- [ ] MMIO accesses are volatile, correctly sized, and ordered where required.
- [ ] `make verify-p3` is green.

---

## Related documents

- [docs/fmts/comments.md](comments.md) — the `// SAFETY:` format in full
- [docs/fmts/syscall-abi.md](syscall-abi.md) — the ring-3 boundary and pointer
  validation machinery
- [docs/fmts/code-style.md](code-style.md) — error handling and the global
  install pattern
- [docs/kernel-introduction/memory.md](../kernel-introduction/memory.md) —
  paging and allocator internals
