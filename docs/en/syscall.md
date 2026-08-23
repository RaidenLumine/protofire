# Syscall ABI

The kernel exposes a register-based syscall interface. This document
covers the ABI contract, numbering scheme, dispatch pipeline, pointer
validation, error encoding, and the shared-user bridge layer (`src/user/shared/`).

## ABI Contract

Arguments and results pass through general-purpose registers. The exact register
mapping is architecture-specific and defined in `src/abi/syscall.rs` (re-exported
as `crate::kernel::syscall::abi`).

### Argument Passing

| Parameter | Register    |
|-----------|-------------|
| syscall number | `%rax` (x86_64) / `x8` (aarch64) |
| arg[0]         | `%rdi` (x86_64) / `x0` (aarch64) |
| arg[1]         | `%rsi` / `x1`                     |
| arg[2]         | `%rdx` / `x2`                     |
| arg[3]         | `%r10` / `x3`                     |
| arg[4]         | `%r8`  / `x4`                     |
| arg[5]         | `%r9`  / `x5`                     |

All six argument slots are packed into the kernel's `SyscallContext`:

```rust
// src/kernel/syscall/table.rs
pub struct SyscallContext {
    pub number: usize,
    pub args: [usize; syscall_abi::ARG_COUNT],  // always 6
    pub caller_pid: Option<u32>,
}
```

The constant `syscall_abi::ARG_COUNT` is `6`. Unused trailing argument slots
must be zero -- the helper `validate_zeroed_args()` enforces this by scanning
`args[start..]` and returning `Error::InvalidArgument` on non-zero entries.

### Return Value

On success, the handler stores a `usize` result value in
`SyscallDispatch::value`. The architecture trap stub places this value in the
designated return register (`%rax` / `x0`).

Errors are encoded as large unsigned values near `usize::MAX`. The shared
`decode()` function converts these to `isize` for sign-based discrimination:

```rust
// src/user/shared/syscall.rs
fn decode(status: isize) -> Result<usize, isize> {
    if status < 0 {
        Err(status)        // negative errno
    } else {
        Ok(status as usize)
    }
}
```

The internal `Error` enum provides `Error::as_str()` for diagnostic messages
and maps to the negative-errno convention at the ABI boundary.

## Syscall Numbering

Every public syscall has a fixed number defined in the `SyscallNumber` enum in
`src/kernel/syscall/table.rs`. Numbers are assigned sequentially with gaps
reserved for Dup2 (69) and GetTimeOfDay (70).

```rust
#[repr(usize)]
pub enum SyscallNumber {
    Yield                  = 0,
    WriteDebug             = 1,
    Open                   = 2,
    Exit                   = 3,
    ReadConsole            = 4,
    Read                   = 5,
    Write                  = 6,
    Close                  = 7,
    Dup                    = 8,
    Seek                   = 9,
    ArgCount               = 10,
    // ...
    Dup2                   = 69,
    GetTimeOfDay           = 70,
    // ...
    ShmCtl                 = 103,
}
```

### Current Allocations (0-150, 151 syscalls)

| Range  | Category                     |
|--------|------------------------------|
| 0-9    | Core I/O (yield, open, read, write, close, dup, seek) |
| 10-18  | Launch metadata (args, env, app info, cwd) |
| 19-21  | Filesystem mutation (mkdir, setlen, remove) |
| 22-23  | Exception handling           |
| 24-26  | Process lifecycle (wait, spawn, exec) |
| 27-36  | Filesystem query (stat, readdir, rename, *-at variants) |
| 37-38  | TCP network                  |
| 39     | ABI info                     |
| 40-41  | Signal send/wait             |
| 42-47  | Access control & permission metadata |
| 48     | FD flags                     |
| 49-53  | Diagnostic (sleep, list, kernel log, system info) |
| 54-55  | Sync (fsync, fdatasync)      |
| 56-60  | TCP listen/accept, UDP       |
| 61     | Process faults               |
| 62-63  | Fork, ReclaimPages           |
| 64     | Pipe                         |
| 65-66  | Mount, Umount                |
| 67-68  | Mmap, Munmap                 |
| 69     | Dup2                         |
| 70-72  | Time, hostname               |
| 73-74  | Socket name / peer name      |
| 75     | GetRandom                    |
| 76-80  | Raw sockets + sockopt        |
| 81-84  | Identity (pid, ppid, uid, gid) |
| 85     | SetCurrentDir                |
| 86-87  | Mount/block device listing   |
| 88     | SetSecurityDescriptor        |
| 89-91  | User management              |
| 92     | Brk                          |
| 93     | ResolveHostname              |
| 94     | SetSignalMask                |
| 95     | RepairVolume                 |
| 96     | Poll                         |
| 97-99  | Unix domain sockets          |
| 100-103| SystV shared memory          |
| 104    | SetSignalHandler              |
| 105    | FUSE mount                    |
| 106    | Futex                         |
| 107-109| eventfd, signalfd, timerfd    |
| 110-111| sched_setaffinity, sched_getaffinity |
| 112-117| POSIX message queues           |
| 118-120| epoll (create, ctl, wait)      |
| 121-125| (reserved for expansion)       |
| 126-127| io_uring (setup, submit_and_wait) |
| 128    | ptrace                         |
| 129    | seccomp                        |
| 130    | prctl                          |
| 131-132| mlock, munlock                 |
| 133    | madvise                        |
| 134    | sigreturn                      |
| 135    | sigsuspend                     |
| 136    | restart_syscall                |
| 137-140| POSIX timers (timer_create/settime/gettime/delete) |
| 141-142| (reserved: WireGuard)          |
| 143-144| Audit (audit_set_enable, audit_read_log) |
| 145-149| CPU frequency scaling (cpufreq_get/set/get_range/set_governor/get_temp) |
| 150    | Memory defragmentation (compact_memory) |

### PUBLIC_SYSCALL_COUNT

```rust
// src/kernel/syscall/table.rs
pub(crate) const PUBLIC_SYSCALL_COUNT: u32 = SyscallNumber::CompactMemory as u32 + 1;
```

This constant is derived from the highest enum discriminant (`CompactMemory = 150`).
It is used in tests to verify that every slot in the dispatch table is
populated:

```rust
#[test]
fn table_init_registers_every_public_syscall_slot() {
    let mut table = Table::new();
    table.init();
    for number in 0..PUBLIC_SYSCALL_COUNT as usize {
        assert!(table.entries[number].is_some(),
                "syscall slot {number} should be registered");
    }
}
```

## Dispatch Mechanism

### Table Structure

The dispatch table is a fixed-size array of 256 slots (`MAX_SYSCALLS = 256`):

```rust
pub struct Table {
    entries: [Option<SyscallHandler>; MAX_SYSCALLS],
}
```

Handlers have the signature:

```rust
pub type SyscallHandler = fn(&mut SyscallContext) -> Result<SyscallDispatch>;
```

### Registry

The static `SYSCALL_REGISTRY` slice maps `usize` numbers to handler functions:

```rust
const SYSCALL_REGISTRY: &[(usize, SyscallHandler)] = &[
    (SyscallNumber::Yield as usize, misc::yield_now),
    (SyscallNumber::WriteDebug as usize, misc::write_debug),
    (SyscallNumber::Open as usize, fs_path_ops::open),
    // ...
];
```

`Table::init()` iterates the registry and calls `register()` for each entry.

### Dispatch Flow

```
User trap (int 0x80 / svc #0)
       |
       v
Trap stub: unpack registers → SyscallContext
       |
       v
validate_syscall_pointers(number, args)   ← pre-validation from SYSCALL_POINTER_SPECS
       |
       v
table.dispatch_with_action(context)
       |
       v
Lookup entries[number] → handler(context)
       |
       v
handler returns Result<SyscallDispatch>
       |
       v
Trap stub: apply SyscallAction (yield, exit, exec, return-from-exception)
            then write SyscallDispatch::value to return register
```

### SyscallDispatch

The handler's return value carries both the result and a side-action flag:

```rust
pub struct SyscallDispatch {
    pub value: usize,
    pub action: SyscallAction,
}

pub enum SyscallAction {
    None,
    Yield,
    Exit { status: usize },
    ReturnFromException { frame_pointer: usize },
    ExecProcess,
}
```

Constructors provide ergonomic shorthand:

- `SyscallDispatch::complete(value)` -- normal return, no side action.
- `SyscallDispatch::yield_now()` -- yields the current thread after setting value.
- `SyscallDispatch::exit(status)` -- terminates the current process.
- `SyscallDispatch::return_from_exception(fp)` -- resumes at a saved exception frame.
- `SyscallDispatch::exec_process()` -- triggers an exec redirect.

### Global Table Installation

The module `src/kernel/syscall/mod.rs` manages a single atomic global table:

```rust
static GLOBAL_TABLE: AtomicPtr<Table> = AtomicPtr::new(ptr::null_mut());

pub fn install_global(table: &'static Table) { /* ... */ }
pub fn global() -> Option<&'static Table> { /* ... */ }
pub fn dispatch(context: &mut SyscallContext) -> Result<usize> { /* ... */ }
pub fn dispatch_with_action(context: &mut SyscallContext) -> Result<SyscallDispatch> { /* ... */ }
```

The `Drop` impl for `Table` atomically clears the global pointer if this table
was the one installed, preventing use-after-free.

## Pointer Validation

### Defense-in-Depth

Every syscall that accepts user-space pointers is subject to two layers of
validation:

1. **Pre-validation** (before handler runs) -- based on the static
   `SYSCALL_POINTER_SPECS` table in `src/kernel/syscall/memory/user.rs`.
2. **Handler-level validation** -- the handler itself validates pointers using
   helpers in the same module.

### SyscallPointerSpec

```rust
struct SyscallPointerSpec {
    arg_index: usize,             // which ABI slot (0-5) holds the pointer
    direction: PointerDirection,  // In, Out, or InOut
    size_arg_index: Option<usize>, // which ABI slot carries the byte length
    fixed_size: Option<usize>,     // exact size for fixed-size structs
}
```

The static `SYSCALL_POINTER_SPECS` table has exactly `PUBLIC_SYSCALL_COUNT`
entries. Each syscall number maps to a slice of specs; an empty slice means
no pre-validation. A test enforces this:

```rust
#[test]
fn pointer_spec_table_covers_every_syscall() {
    assert_eq!(SYSCALL_POINTER_SPECS.len(), PUBLIC_SYSCALL_COUNT as usize);
}
```

Example entry for syscall 6 (Write):

```rust
// arg1 = data pointer (input), arg2 = length
&[SyscallPointerSpec::input(1, Some(2), None)],
```

### Validation Function

```rust
pub(crate) fn validate_syscall_pointers(number: usize, args: &[usize; 6]) -> Result<()>
```

This reads the spec, resolves the byte length (from `fixed_size` or the
`size_arg_index` argument), and calls:

- `validate_current_process_user_input_buffer` -- for `PointerDirection::In`
- `validate_current_process_user_output_buffer` -- for `PointerDirection::Out`

Both check null, kernel-half address range, and canonical hole boundaries
(`USER_ADDRESS_MAX = 0x0000_7FFF_FFFF_FFFF`). On bare-metal x86_64/aarch64
they additionally walk the page tables via `validate_user_mapping()` to verify
the range is mapped with the required permissions (READ for input, WRITE for
output).

### SMAP/PAN Handling

On x86_64 with SMAP (or aarch64 PAN equivalent), user memory accesses require
EFLAGS.AC to be set. The module wraps every dereference in
`with_user_access_guard()`:

```rust
fn with_user_access_guard<T>(f: impl FnOnce() -> T) -> T {
    // On bare-metal: stac → f() → clac
    // On host tests: no-op
}
```

Closure-based helpers (`with_optional_input_slice`,
`with_optional_output_slice`) validate the pointer range *before* entering the
SMAP guard so page-table walk errors (kernel-internal operations) do not run
with AC set.

## Shared Wrappers (`src/user/shared/syscall.rs`)

The syscall bridge now lives in the kernel crate as `src/user/shared/syscall.rs`.
It is the single source of truth for the user-space ABI: constants, raw entry
points, and typed wrappers.

### Constants

Each public syscall gets a `SYS_*` constant, re-exported from
`src/user/shared/abi/syscall` (which shares the canonical definitions with the
kernel's `SyscallNumber` enum):

```rust
pub const SYS_OPEN: usize = 2;
pub const SYS_EXIT: usize = 3;
pub const SYS_READ: usize = 5;
// ... (96 constants total, matching SyscallNumber)
```

### Raw Entry Points

Seven `extern "Rust"` functions (one per argument count, 0-6) are declared in
`src/user/shared/syscall.rs` and implemented per environment:

```rust
extern "Rust" {
    fn __shell_syscall0(number: usize) -> isize;
    fn __shell_syscall1(number: usize, a0: usize) -> isize;
    // ... through __shell_syscall6
}
```

In the kernel these resolve to `src/user/program/shell/syscall_bridge.rs`, which
wraps `UserSyscall + syscall::dispatch()`. A standalone ring3 runtime can
instead wire them to `int 0x80` / `svc #0` by enabling the `runtime` feature
(`src/user/shared/runtime.rs`). The extern declarations are unconditional so
host-side unit tests resolve against the same `#[no_mangle]` bridge — no
separate test stubs are needed.

### Typed Wrappers

Higher-level `sys_*()` functions provide safe typed interfaces:

```rust
pub fn sys_open(path: &str, flags: usize) -> Result<usize, isize>;
pub fn sys_read(fd: usize, buf: &mut [u8], timeout_ticks: u64) -> Result<usize, isize>;
pub fn sys_write(fd: usize, data: &[u8]) -> Result<usize, isize>;
pub fn sys_close(fd: usize) -> Result<(), isize>;
pub fn sys_exit(code: usize) -> !;
// ... 40+ wrappers total
```

Each wrapper calls `decode()` on the raw `isize` return value, converting it
to `Result<usize, isize>`.

## Adding a New Syscall

The full workflow spans four locations:

1. **Kernel enum variant** in `src/kernel/syscall/table.rs`
   ```rust
   pub enum SyscallNumber {
       // ...
       MyNewSyscall = 104,
   }
   ```

2. **Handler function** in an appropriate handler module (e.g.,
   `src/kernel/syscall/fs/metadata.rs`), with signature:
   ```rust
   pub(super) fn my_handler(ctx: &mut SyscallContext) -> Result<SyscallDispatch>;
   ```
   Then register it in `SYSCALL_REGISTRY`:
   ```rust
   (SyscallNumber::MyNewSyscall as usize, my_module::my_handler),
   ```

3. **Pointer spec** in `SYSCALL_POINTER_SPECS` within
   `src/kernel/syscall/memory/user.rs`. The table must have exactly
   `PUBLIC_SYSCALL_COUNT` entries -- add a new entry at the end (empty `&[]`
   if no pointer arguments).

4. **Shared constant + wrapper** in `src/user/shared/syscall.rs`
   ```rust
   pub const SYS_MY_NEW_SYSCALL: usize = 104;
   pub fn sys_my_new_syscall(...) -> Result<usize, isize> { ... }
   ```

5. **PUBLIC_SYSCALL_COUNT** updates automatically from the enum discriminant
   as long as the highest-numbered variant is the new one.

## Module Layout

| File | Role |
|------|------|
| `src/kernel/syscall/mod.rs` | Global table installation, `dispatch()`, `dispatch_with_action()` |
| `src/kernel/syscall/table.rs` | `SyscallNumber`, `Table`, `SyscallContext`, `SyscallDispatch`, `SYSCALL_REGISTRY` |
| `src/kernel/syscall/memory/user.rs` | `SYSCALL_POINTER_SPECS`, `validate_syscall_pointers()`, user-memory access helpers |
| `src/user/shared/syscall.rs` | `SYS_*` constants, `__shell_syscallN` entry points, `sys_*()` wrappers |
| `src/user/program/shell/syscall_bridge.rs` | Kernel-side `#[no_mangle]` implementations of `__shell_syscallN` |

---

## See Also

- [Subsystem overview](../en/syscall.md) — high-level syscall ABI description
- [Shared user runtime reference](../en/shared-user-runtime.md) — syscall wrapper conventions, dual-environment dispatch
- [Documentation index](../README.md) — complete document tree
