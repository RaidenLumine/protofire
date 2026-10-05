# The Shared User Runtime

`src/user/shared/` is the code that both sides of the syscall boundary
compile: the kernel's built-in shell runs it in ring 0, and a program built
from the same sources runs it in ring 3.  It holds three things — the ABI
record types, the syscall wrappers, and the shell library that the built-in
shell is made of — and it is `no_std` with `alloc` only, so the same text
compiles into both.

The kernel half of the boundary — the trap, the dispatch table, pointer
validation — is [syscalls.md](syscalls.md)'s subject.  This document is the
user side of that contract: what the records are, how a wrapper reaches the
kernel, and what else lives in the shared tree.

## The records, and the mirror that keeps two copies one

An ABI record exists twice on purpose.  `src/abi/` is the kernel's copy and
`src/user/shared/abi/` is the vendored one a user program can take with it;
a copy is only as good as the check that compares them, so
`scripts/check-abi-mirror.sh` holds three rules:

- every file in `src/abi/` is declared by `src/abi/mod.rs`, and every record
  has its mirror;
- the two bodies are byte-identical below the header, and the mirror's
  header is what records the origin (`//! src/abi/<name>.rs`).  A pair that
  is deliberately different is listed in `scripts/abi-mirror-baseline.txt`
  with its reason, and a row whose difference has gone fails;
- the vendored tree and the demo payload modules reach the ABI through
  `crate::user::shared::abi::`, never through `crate::abi::` — a payload is
  copied out of this crate, so it cannot name a path that stays behind.

The records themselves are `#[repr(C)]` with explicit field order, and the
one place a layout constant matters states it as `offset_of!` rather than as
a number (`src/user/shared/abi/exception.rs`).  Sizes are pinned by test:
`documented_record_sizes_match_the_records` in `src/abi/fs.rs` asserts the
wire sizes of the file and process records against the types.

The syscall numbers have their own single source: `SYSCALL_COUNT` and the
`SYS_*` constants in `src/user/shared/abi/syscall.rs`, which both the
kernel's `SyscallNumber` enum and the wrappers resolve through.  The frozen
range is pinned by `tests/syscall/abi_golden.rs`.

## How a wrapper reaches the kernel

`src/user/shared/syscall.rs` declares seven entry points,
`__shell_syscall0` through `__shell_syscall6`, as `extern "Rust"`.  Each
environment supplies them:

| Environment | Who defines them |
|---|---|
| Kernel and host tests | `src/user/program/shell/syscall_bridge.rs`, wrapping `SyscallContext` and `syscall::dispatch` |
| Ring-3 program | `src/user/shared/runtime.rs`, which is where the standalone bridge is meant to live |

The declarations are `safe` deliberately: a syscall is an erring operation,
not an unchecked memory access.  The kernel validates every address before
it touches it, and the `unsafe` and its argument stay at that first
dereference (`src/syscall/memory/user.rs`), not on the hundred and fifty
call sites above it.

One word comes back.  Success is the value; failure is `usize::MAX - code`
for a small code (`ERROR_STATUS_FLOOR` and `ERROR_CODE_MAX` in
`abi/syscall.rs`), which leaves the top of the range for errors and every
ordinary value usable.  The typed `decode` helper answers `Err(status)` for
anything negative, and the kernel-side bridge produces exactly that shape
from the kernel's `Error`.

On top of the raw entry points sit the typed wrappers — 152 `sys_*`
functions — which take `&str` and slices rather than `(pointer, length)`
pairs, and return `Result<usize, isize>` or `Result<(), isize>`.  A path
argument is always `ptr` and `len` as two words, which is why the wrapper
exists at all.

## What else the shared tree holds

| Module | What it is |
|---|---|
| `abi` | The `#[repr(C)]` records and the syscall-number source |
| `syscall` | The raw entry points, the `SYS_*` re-exports and the typed wrappers |
| `runtime` | Where a ring-3 build's bridge belongs (see the scope note below) |
| `dispatch` | Command-name to function dispatch |
| `commands` | The builtin implementations |
| `control_flow`, `pipeline` | `if`/`for`/`while`, `&&`/`\|\|`, pipes and redirects |
| `tokenizer`, `expand`, `glob` | Words, `$VAR` expansion and pattern matching |
| `history`, `jobs`, `passwd` | History, job bookkeeping, and a small passwd reader |
| `config` | The TOML subset both sides read (`/system/rc.d`, manifests) |
| `path_util`, `types` | Path resolution, and `CmdResult` |
| `signal` | The cooperative signal API a program calls |

The shell's own structure lives one level up,
`src/user/program/shell/`, which re-exports the same names and adds the
entry loop and terminal I/O.  Its state — working directory, environment,
aliases, jobs — is passed explicitly rather than kept in globals, which is
what lets one implementation serve a kernel thread and a program.

## Signals from the user side

The kernel's signal model is cooperative: a pending signal waits in the
process queue until the program asks for it.  `src/user/shared/signal.rs`
is that asking, in two shapes:

- **Wait** — `wait_signal(timeout)` and `wait_signal_forever()` return the
  next `ProcessSignalRecord` (signal, sender pid, payload); `poll_signal()`
  is the non-blocking probe.  The shell's dispatch loop is built on this.
- **Mask** — `block_signal`, `unblock_signal` and `set_signal_mask` read
  and write the process's mask, which is a `u32`: signals 1 through 31, one
  bit each.  `SIGKILL` and `SIGSTOP` ignore the mask.

The other delivery path — a handler entered asynchronously through the
architecture's trampoline, and `sigreturn` putting the interrupted context
back — is the kernel's half and belongs to [process.md](process.md).  The
shared library only ever consumes a record.

## What is not here

- **No libc.** There is no POSIX compatibility layer to link against; a
  program that wants these calls links this module.
- **No allocator.** The tree does not ship one for ring 3 — an earlier
  document named a `BrkAllocator`, and no such type is in the tree — so a
  freestanding program brings its own.
- **No standalone bridge, then.** `src/user/shared/runtime.rs` contains its
  module documentation and no code: the kernel build uses
  `syscall_bridge.rs` (it is compiled when the `runtime` feature is off),
  and the ring-3 build that would need the other one is not built in this
  repository.
- **No group database.** The shared passwd reader parses user records; there
  is no group file to parse.
- **Jobs are bookkeeping.** The shell tracks them itself, because the kernel
  has no process group.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/user/shared/abi/syscall.rs` | The syscall numbers and the status encoding |
| `src/user/shared/abi/fs.rs`, `process.rs`, `io.rs`, `exception.rs` | The record families |
| `src/abi/mod.rs`, `scripts/abi-mirror-baseline.txt` | The kernel-side records and the mirror's exceptions |
| `src/user/shared/syscall.rs` | The entry points and the typed wrappers |
| `src/user/program/shell/syscall_bridge.rs` | The kernel-side bridge |
| `src/user/shared/runtime.rs` | The ring-3 bridge's placeholder |
| `src/user/shared/signal.rs` | The cooperative wait/mask API |
| `src/user/shared/commands/`, `dispatch.rs`, `pipeline.rs` | The shell library |
| `scripts/check-abi-mirror.sh`, `tests/syscall/abi_golden.rs` | What keeps the two sides in step |

## See also

- [syscalls.md](syscalls.md) — the kernel half of the boundary
- [process.md](process.md) — the kernel's signals, handles and threads
- [security.md](security.md) — launch integrity, which reads the manifest these records describe
