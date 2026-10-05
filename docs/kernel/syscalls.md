# Syscall Interface

How a ring-3 program enters the kernel, how a call gets from the trap frame to
its handler, and how the answer gets back.  The contract itself — the numbering
rules, the frozen range, the pointer specifications and the procedure for
adding a call — is [syscall-abi.md](../fmts/syscall-abi.md)'s.  This document is
about the machinery that enforces it.

## Entering the kernel

Each architecture has one trap that carries a syscall, and one register
convention.  The trap stubs are in `src/arch/<machine>/trap.S` (AArch64 and
RISC-V) and `src/arch/x86_64/idt/` (x86_64); each builds the same
`SyscallContext`:

| | x86_64 | AArch64 | RISC-V 64 |
|---|---|---|---|
| trap | `int 0x80` | `svc #0` | `ecall` |
| number | `rax` | `x8` | `a7` |
| arguments | `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` | `x0`-`x5` | `a0`-`a5` |
| result | `rax` | `x0` | `a0` |

`SyscallContext` (`src/syscall/table.rs`) carries the number, the arguments and
the calling thread's pid:

```rust
pub struct SyscallContext {
    pub number: usize,
    pub args: [usize; syscall_abi::ARG_COUNT],
    pub caller_pid: Option<u32>,
}
```

`ARG_COUNT` is owned by `src/user/shared/abi/syscall.rs`, which both the kernel
and the shared user tree compile against.  Unused trailing arguments must be
zero, and `validate_zeroed_args` enforces it before a handler runs: a call that
passes a stray value in an argument the syscall does not take is refused rather
than ignored, because the ignored value is the one a future version of the
syscall will read.

## Return values and errors

A handler answers with a `SyscallDispatch`: a `usize` value that the trap stub
places in the result register, and an action (below).  Errors travel the same
way, encoded as status words at the top of the `usize` range — the shared tree
decodes them with `decode`, which treats a negative `isize` as the error and
everything else as a value:

```rust
// src/user/shared/syscall.rs
fn decode(status: isize) -> Result<usize, isize> {
    if status < 0 { Err(status) } else { Ok(status as usize) }
}
```

The encoding is defined by `ERROR_STATUS_FLOOR` and `encode_error` in
`src/user/shared/abi/syscall.rs`, so the kernel's error type and the user-side
decoder are derived from one definition rather than two conventions.

## Numbering

A syscall's number is its `SyscallNumber` discriminant in
`src/syscall/table.rs`.  Two things make that numbering a contract rather than
a convention:

- `tests/syscall/abi_golden.rs` holds a snapshot of every number→name row.  A
  change in the frozen range fails outright; an addition or renumbering in the
  experimental range fails unless the ABI minor moves with it.
- `scripts/check-abi-mirror.sh` compares the kernel's ABI records with the
  vendored copy under `src/user/shared/abi/`, so the two sides of the boundary
  cannot drift apart.

This document does not repeat the table.  The enum is the table, and the golden
test is what stops it moving by accident.

## The dispatch table

The table is `src/syscall/table.rs`'s `Table`: a fixed-size array
(`MAX_SYSCALLS`) of `Option<SyscallHandler>`, where a handler is

```rust
pub type SyscallHandler = fn(&mut SyscallContext) -> Result<SyscallDispatch>;
```

`Table::init` registers one handler per public syscall by name, so the call
graph from a number to its implementation is readable in one function instead
of a match arm per family.  `PUBLIC_SYSCALL_COUNT` is derived from the highest
discriminant in the enum, and a test in the same file requires every slot below
it to be filled and the slot at it to be empty — a syscall added to the enum
and forgotten in the table fails there.

The installed table is reachable from the trap paths through
`syscall::install_global_unchecked`, which is called once during boot.
Dispatch itself is per-architecture code: each trap path validates, calls
`syscall::dispatch_with_action`, and then applies the action it gets back.

## What happens after the handler

Most syscalls just return a value.  The ones that change the thread's execution
say so with `SyscallAction`:

| Action | The trap path does |
|--------|--------------------|
| `None` | Returns the value |
| `Yield` | Puts the current thread back on the ready queue |
| `Exit { status }` | Terminates the thread with a reason |
| `ExecProcess` | Applies the new image's user context to the trap frame |
| `ReturnFromException { frame_pointer }` | Resumes an on-user-exception context |
| `SigReturn` | Applies the context `sigreturn` restored from the signal frame |

Which of those needs the *live* trap frame copied back into the thread's saved
user context — and which must not — is one policy shared by all three
architectures in `src/arch/syscall_trap.rs`: capture before the action, capture
after `ExecProcess` has replaced the image, or capture nothing because the
handler already installed the context (`SigReturn`).  The distinction is not
bookkeeping: capturing the frame during a `sigreturn` would overwrite the
context the handler had just restored and send the thread back into its
trampoline.

## Pointer validation

A syscall that takes a pointer declares what it points at in
`SYSCALL_POINTER_SPECS` (`src/syscall/memory/user.rs`), a table indexed by
syscall number whose entries say, per argument, whether the kernel reads it,
writes it, or both, and which arguments bound another one's length.
`validate_syscall_pointers` runs before the handler: an address outside the
caller's address space, or a length that would run past the buffer it names, is
refused with an error rather than discovered later by a copy.

Reading and writing user memory happens through the guards in the same file,
which open the architecture's user-access window (SMAP on x86_64, PAN on
AArch64, SUM on RISC-V) for the duration of one copy.  The window is scoped:
holding it across a blocking operation would clear another thread's access when
that thread closes its own window, so paths that can block stage their data in
kernel memory first and hold the window only for the copy.

## The ring-3 side

`src/user/shared/syscall.rs` is the other end: it declares `extern` entry points
(`__shell_syscall0` … `__shell_syscall6`) and builds the typed wrappers on top
of them, so a program written against the shared tree has one function per
syscall and no inline assembly of its own.

Those externs are satisfied twice, because the shared tree runs in two places:

- in ring 3 payloads, by the payload's own runtime, which traps directly
  (`define_<arch>_payload_runtime!` in `src/user/syscall/payload.rs`), and
- in the kernel's own shell build, by
  `src/user/program/shell/syscall_bridge.rs`, which calls the dispatch table
  the same way the trap path does.

That is what lets one shell, written once, run either side of the boundary.  The
two implementations must agree on the ABI records, which is what
`make check-abi-mirror` checks.

## Layout

`src/syscall/` holds the table (`table.rs`), one module per family
(`epoll.rs`, `event_fd.rs`, `fcntl.rs`, `io_uring.rs`, `mq.rs`, `posix_timer.rs`,
`signal_fd.rs`, `timer_fd.rs`, `tls.rs`, …) and subdirectories for the families
that need more than one file (`fs/`, `memory/`, `misc/`, `network/`,
`process/`).  A syscall's implementation lives with its family; the table only
named it.

## See also

- [syscall-abi.md](../fmts/syscall-abi.md) — the contract, the stability
  classes, and the procedure for adding a call
- the user-runtime document, once `src/user/shared/` is written up
