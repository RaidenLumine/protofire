# Shared User Runtime — `src/user/shared/`

## Purpose

`src/user/shared/` is a `#![no_std]`-compatible module that defines the **ABI boundary between the kernel (ring0) and userspace programs (ring3)**:

- **In the kernel** — the built-in shell uses this module for command dispatch, tokenization, and shell logic.
- **In ring3 binaries** — a standalone runtime (not built in this repo) can link against the kernel crate and enable the `runtime` feature for the syscall bridge, the `BrkAllocator`, and signal handling.

The module lives at `src/user/shared/` inside the kernel crate.

### Key design constraint

All modules depend only on `alloc` (the `core` + `alloc` crate pair). No `std`, no platform-specific libc. This lets the same code compile into the kernel image and (with the `runtime` feature) into freestanding ring3 ELF binaries.

---

## Module Map

Source: `src/user/shared/mod.rs`

The module exports the following public submodules:

| Module | File | Responsibility |
|---|---|---|
| `abi` | `abi/mod.rs` | `#[repr(C)]` ABI record types shared across the kernel/userspace boundary |
| `commands` | `commands/mod.rs` | ~45 shell builtin command implementations |
| `control_flow` | `control_flow.rs` | `if`/`for`/`while` parsing and execution |
| `crypto` | `crypto.rs` | Cryptographic primitives (hash, random) |
| `dispatch` | `dispatch.rs` | Command-name-to-function dispatch table |
| `expand` | `expand.rs` | Environment variable expansion (`$VAR`, `${VAR}`) |
| `glob` | `glob.rs` | Glob pattern matching (`*`, `?`, `[...]` character classes) |
| `history` | `history.rs` | Command history: add, expand, common-prefix search |
| `jobs` | `jobs.rs` | Background job tracking |
| `version` | `version.rs` | Natural version-string comparison (`compare_natural_version_strings`) |
| `net` | `net.rs` | HTTP/1.1 client (URL parsing, GET fetch), TCP server framework |
| `passwd` | `passwd.rs` | Minimal `/data/etc/passwd` file parser |
| `path_util` | `path_util.rs` | `resolve_path()` and `normalize_path_segments()` |
| `pipeline` | `pipeline.rs` | `&&` / `||` conditional chaining, pipe splitting, redirect parsing |
| `runtime` | `runtime.rs` | Architecture-dependent syscall bridge, `BrkAllocator`, argument parsing, panic handler |
| `signal` | `signal.rs` | Cooperative signal handling: wait, send, mask (u64), sigsuspend, dispatch loop |
| `syscall` | `syscall.rs` | `SYS_*` constants (~80 syscall numbers) + `sys_*()` typed wrappers (~50 functions) |
| `tokenizer` | `tokenizer.rs` | Shell word tokenizer (quotes, escapes, whitespace) |
| `types` | `types.rs` | `CmdResult` — the structured return type for all shell commands |

---

## Syscall Wrappers (`syscall.rs`)

File: `src/user/shared/syscall.rs`

This module provides two layers:

### Layer 1 — Raw entry points

Seven `extern "Rust"` functions (`__shell_syscall0` through `__shell_syscall6`) that the environment must implement:

```rust
extern "Rust" {
    fn __shell_syscall3(number: usize, a0: usize, a1: usize, a2: usize) -> isize;
    // ... 0-arg through 6-arg variants
}
```

- **In the kernel**: the declarations are satisfied by `src/user/program/shell/syscall_bridge.rs`, which wires them to `UserSyscall` + `syscall::dispatch()`.
- **In ring3 binaries**: the `runtime` module provides `#[no_mangle]` implementations (via the `runtime` feature) that emit `int 0x80` (x86_64) or `svc #0` (AArch64).
- **In host tests**: the same `#[no_mangle]` kernel bridge resolves the extern declarations — no separate test stubs are needed.

The `decode()` helper converts the raw `isize` return value: negative indicates an error, non-negative is a success value.

### Layer 2 — Typed wrapper functions

Each wrapper follows the pattern:

```rust
pub fn sys_open(path: &str, flags: usize) -> Result<usize, isize>
```

Functions accept `&str` for string arguments and return `Result<usize, isize>` or `Result<(), isize>`. The caller pattern is always `path.as_ptr() as usize, path.len()` passed as two separate arguments.

### Syscall number constants

Many `SYS_*` constants are defined, covering these categories:

| Category | Examples |
|---|---|
| **File I/O** | `SYS_OPEN` (2), `SYS_READ` (5), `SYS_WRITE` (6), `SYS_CLOSE` (7), `SYS_STAT` (27), `SYS_READ_DIR` (28), `SYS_SET_LENGTH` (20) |
| **Filesystem** | `SYS_CURRENT_DIR` (14), `SYS_CREATE_DIR` (19), `SYS_REMOVE_PATH` (21), `SYS_RENAME` (29) |
| **Process** | `SYS_SPAWN_PROCESS` (25), `SYS_EXIT` (3), `SYS_WAIT_PROCESS` (24), `SYS_GETPID` (81), `SYS_GETPPID` (82) |
| **Network** | `SYS_NETWORK_STATUS` (37), `SYS_CONNECT_TCP` (38), `SYS_LISTEN_TCP` (56), `SYS_ACCEPT_TCP` (57), `SYS_BIND_UDP` (58), `SYS_SENDTO_UDP` (59), `SYS_RECVFROM_UDP` (60), `SYS_RESOLVE_HOSTNAME` (93), `SYS_CREATE_RAW_SOCKET` (76) |
| **Memory** | `SYS_BRK` (92), `SYS_SHMGET` (100), `SYS_SHMAT` (101), `SYS_SHMDT` (102), `SYS_SHMCTL` (103) |
| **Security** | `SYS_ACCESS_QUERY` (42), `SYS_PERMISSION_METADATA` (45), `SYS_SET_SECURITY_DESCRIPTOR` (88), `SYS_ADD_USER` (89), `SYS_REMOVE_USER` (90), `SYS_SET_USER_PASSWORD` (91) |
| **Signals** | `SYS_SEND_SIGNAL` (40), `SYS_WAIT_SIGNAL` (41), `SYS_SET_SIGNAL_MASK` (94), `SYS_SET_SIGNAL_HANDLER` (104), `SYS_SIGSUSPEND` (135), `SYS_RESTART_SYSCALL` (136) |
| **Diagnostics** | `SYS_LIST_PROCESSES` (50), `SYS_LIST_THREADS` (51), `SYS_KERNEL_LOG` (52), `SYS_SYSTEM_INFO` (53), `SYS_LIST_MOUNTS` (86), `SYS_LIST_BLOCK_DEVICES` (87), `SYS_REPAIR_VOLUME` (95) |
| **Unix sockets** | `SYS_BIND_LOCAL` (97), `SYS_CONNECT_LOCAL` (98), `SYS_ACCEPT_LOCAL` (99) |

Special-purpose helpers include `sys_repair_volume()` which returns a `VolumeRepairReport` struct, `sys_poll()` with its `PollFd` struct, and `sys_exit()` which is `fn(sys_exit(code: usize) -> !` (never returns).

### Network status flags

```rust
pub const NETWORK_STATUS_FLAG_AVAILABLE: u32 = 1 << 0;
pub const NETWORK_STATUS_FLAG_TCP_CONNECT: u32 = 1 << 2;
pub const NETWORK_STATUS_FLAG_STREAM_IO: u32 = 1 << 3;
pub const NETWORK_STATUS_FLAG_TCP_LISTEN: u32 = 1 << 6;
pub const NETWORK_STATUS_FLAG_IPV6: u32 = 1 << 8;
// ... and others
```

The function `network_supports_tcp_stream_transport()` checks the minimum capability set for TCP-based HTTP downloads.

---

## ABI Types (`abi/`)

File: `src/user/shared/abi/mod.rs`

Five submodules, all `#[repr(C)]` — layouts must remain binary-stable across kernel revisions:

### `abi/fs.rs` — Filesystem ABI

| Type | Size | Purpose |
|---|---|---|
| `FileStat` | 16 bytes | `kind` (0=unknown, 1=dir, 2=file, 3=device, 4=symlink) + `size` |
| `AccessQueryRecord` | 8 bytes | `required_access`, `granted_mode_bits`, `flags` |
| `PermissionMetadataRecord` | 12 bytes | `owner_uid`, `owner_gid`, `mode`, `reserved` |
| `DirectoryEntryRecord` | 32 bytes | Header for `read_dir`: `kind`, `size`, `name_offset`, `name_len` |
| `MountInfoRecord` | 356 bytes | `path[256]`, `fs_name[32]`, `device[64]`, `flags` |
| `BlockDeviceInfoRecord` | 88 bytes | `name[64]`, `block_size`, `block_count`, `read_only` |

Constants: `FILE_KIND_DIRECTORY`, `FILE_KIND_FILE`, `FILE_KIND_DEVICE`, `AT_FDCWD`, `OPEN_FLAG_READ`, `OPEN_FLAG_WRITE`, `OPEN_FLAG_CREATE`, and access bit flags.

### `abi/process.rs` — Process ABI

| Type | Size | Purpose |
|---|---|---|
| `ProcessTerminationRecord` | 40 bytes | `kind` (exit/exception/none), `status`, `vector`, `error_code`, `fault_address` |
| `ProcessSignalRecord` | 24 bytes | `signal`, `sender_pid`, `payload` |
| `ProcessSpawnOptions` | 56 bytes | Launch options: `flags`, `argv`, `argc`, `env`, `envc`, `working_dir` |
| `ProcessSpawnStringRef` | 16 bytes | `ptr`, `len` — string descriptor for spawn options |

Spawn flags: `PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS`, `PROCESS_SPAWN_FLAG_INHERIT_STDIO`, `PROCESS_SPAWN_FLAG_INHERIT_FDS`, `PROCESS_SPAWN_FLAG_START_SUSPENDED`, etc.

### `abi/io.rs` — I/O ABI

Open flags: `OPEN_FLAG_READ` (1), `OPEN_FLAG_WRITE` (2), `OPEN_FLAG_CREATE` (4), and their combinations.

### `abi/shm.rs` — Shared Memory ABI

`ShmInfo` struct and IPC constants: `IPC_PRIVATE`, `IPC_CREAT`, `IPC_EXCL`, `IPC_RMID`, `IPC_STAT`, `IPC_SET`, `SHM_RDONLY`.

### `abi/diagnostic.rs` — Diagnostic ABI

Records for system introspection:
- `ProcessInfoRecord` — `pid`, `ppid`, `name[64]`, `state`, `thread_count`, `priority`, `cpu_ticks`
- `ThreadInfoRecord` — `tid`, `priority`, `cpu_ticks`, `state`
- `SystemInfoRecord` — scheduler counters (uptime, dispatch, preempt, etc.)
- `AllocProfilerRecord` — heap and frame allocator counters
- `FaultProfilerRecord` — page fault, exception, and termination counters
- `FsProfilerRecord` / `NetProfilerRecord` / `PerCpuRecord` — per-subsystem stats
- `BootReportRecord` — boot timing, physical memory, subsystem init status
- `SystemHealthRecord` — aggregated health counters
- `FaultRecordAbi` — exception details for ring3

State constants: `PROCESS_STATE_READY`, `PROCESS_STATE_RUNNING`, `PROCESS_STATE_WAITING`, `THREAD_STATE_*`, `THREAD_PRIORITY_*`. System info selectors: `SYSTEM_INFO_SCHEDULER` (0) through `SYSTEM_INFO_PER_CPU` (8).

---

## Runtime (`runtime.rs`)

File: `src/user/shared/runtime.rs`

This module provides the bare-metal runtime that standalone ring3 binaries need, gated behind `feature = "runtime"`. In the kernel build the feature is off (the kernel provides its own `#[no_mangle]` bridge in `syscall_bridge.rs`).

### Architecture-dependent syscall (`runtime::arch`)

Two implementations, selected by `#[cfg(target_arch)]`:

```
x86_64:
  inlateout("rax") number => status
  in("rdi") arg0, in("rsi") arg1, in("rdx") arg2
  in("rcx") arg3, in("r8") arg4, in("r9") arg5
  int 0x80

AArch64:
  in("x8") number
  inlateout("x0") arg0 => status
  in("x1") arg1 ... in("x5") arg5
  svc #0
```

Each arch module provides: `syscall_raw()`, `exit()`, `write()`, `read()`, `current_dir()`, `arg_count()`, `arg_value()`, `brk()`.

### Syscall bridge (`__shell_syscall0`..`__shell_syscall6`)

`#[no_mangle] extern "Rust"` functions that implement the symbols declared in `syscall.rs`. These are compiled once in `runtime.rs` (feature `runtime`) rather than being duplicated across every ring3 binary. The `decode_for_bridge()` helper maps the kernel's `Error` enum encoding to negative `isize` values:

| Kernel Error | `isize` |
|---|---|
| `InvalidArgument` | -1 |
| `NotFound` | -2 |
| `AlreadyExists` | -3 |
| `PermissionDenied` | -4 |
| `OutOfMemory` | -5 |
| `DeviceError` | -6 |
| `Busy` | -7 |
| `TimedOut` | -8 |
| `Unsupported` | -9 |
| `NotImplemented` | -10 |
| `InternalError` | -11 |
| `InvalidCredential` | -12 |

### BrkAllocator

A simple bump allocator backed by the `brk` syscall:

```rust
pub struct BrkAllocator {
    current: AtomicUsize,
}

unsafe impl GlobalAlloc for BrkAllocator { ... }
```

- First allocation queries the current program break (default 0x40_2000).
- Subsequent allocations bump the break upward.
- `dealloc()` is a no-op — memory is never returned to the kernel.

### Argument parsing

`read_argv()` reads process arguments via `SYS_ARG_COUNT` / `SYS_ARG_VALUE` syscalls, returning `Vec<String>`. `read_cwd()` reads the current working directory as a `String`.

### Panic handler helper

`write_panic(prefix, info)` writes a formatted panic message to stdout and calls `arch::exit(2)`. Each ring3 binary's `#[panic_handler]` delegates to this function.

---

## Shell Dispatch (`dispatch.rs`)

File: `src/user/shared/dispatch.rs`

Two entry points:

```rust
pub fn dispatch_single_command(cmd_line: &str, ...) -> CmdResult
pub fn dispatch_tokens(tokens: &[String], ...) -> CmdResult
```

`dispatch_single_command` tokenizes the input line first, then calls `dispatch_tokens`. `dispatch_tokens` takes pre-tokenized argv for callers that do their own alias/glob expansion.

The dispatch table matches command names to the `cmd_*` functions from `commands/`. Unknown commands return exit code 127.

State is passed explicitly through parameters (no globals), making dispatching work identically in ring0 (kernel `Mutex` statics) and ring3 (local variables):

```rust
pub fn dispatch_single_command(
    cmd_line: &str,
    cwd: &mut String,
    stdin: Option<&str>,
    home_dir: Option<&str>,
    env_vars: &mut Vec<(String, String)>,
    aliases: &mut Vec<(String, String)>,
    history: &[String],
    positional_params: &mut Vec<String>,
    source_depth: &mut u32,
    read_line_fn: impl FnMut() -> Option<String>,
    exec_fn: impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult
```

`SOURCE_MAX_DEPTH` (16) prevents infinite recursion for `source` commands.

### Command implementations (`commands/`)

File: `src/user/shared/commands/mod.rs`

~45 builtin commands organized into submodules:

**`commands/fs.rs`** — Filesystem commands: `cmd_pwd`, `cmd_cd`, `cmd_ls`, `cmd_cat`, `cmd_mkdir`, `cmd_rm`, `cmd_touch`, `cmd_cp`, `cmd_mv`, `cmd_chmod`, `cmd_du`, `cmd_df`.

**`commands/text.rs`** — Text processing: `cmd_grep`, `cmd_find`, `cmd_head`, `cmd_tail`, `cmd_wc`, `cmd_sort`, `cmd_uniq`, `cmd_diff`, `cmd_edit`, `cmd_hexdump`.

**`commands/system.rs`** — System commands: `cmd_help`, `cmd_echo`, `cmd_clear`, `cmd_sleep`, `cmd_sysinfo`, `cmd_top`, `cmd_dmesg`, `cmd_uname`, `cmd_uptime`, `cmd_test`.

**`commands/process.rs`** — Process commands: `cmd_ps`, `cmd_kill`, `cmd_true`, `cmd_false`.

**`commands/state.rs`** — Shell state: `cmd_export`, `cmd_alias`, `cmd_history`, `cmd_read`, `cmd_shift`, `cmd_source`.

**`commands/perf.rs`** — `cmd_perf`.

All commands return `CmdResult` (defined in `types.rs`):

```rust
pub struct CmdResult {
    pub exit_code: i32,
    pub output: String,
}
```

---

## Package management

Package management is not a kernel responsibility. The Linux kernel itself
contains no package manager (apt/dnf/pacman all live in user space); the kernel
only provides the exec primitive for loading programs from paths. protofire's
package manager (install/uninstall/upgrade/rollback, remote repositories,
transaction logs, file associations, signing keys, appctl/app-center) has
therefore been removed from the kernel crate. The kernel retains the launch
chain `/apps/current → /apps/catalog → /apps/packages → ELF`, implemented in
`crate::user::program::launch_reference`.

---

## Signal Handling (`signal.rs`)

File: `src/user/shared/signal.rs`

### Cooperative signal model

The kernel delivers signals **cooperatively**: a process must explicitly call `wait_signal()` to receive the next pending signal. There is no asynchronous preemption.

### Signal mask

The signal mask is now a **64-bit** bitfield (`u64`), supporting up to 64 signal
slots. The kernel currently uses slots 0-42, including 11 real-time signals
(SIGRTMIN=32 through SIGRTMAX=42).

Core API:

| Function | Description |
|---|---|
| `wait_signal(timeout_ticks)` | `Option<ProcessSignalRecord>` — blocks up to `WAIT_FOREVER`, or passes `0` for poll |
| `wait_signal_forever()` | Blocks infinitely, returns the next signal record |
| `poll_signal()` | Non-blocking check for pending signal |
| `send_signal(pid, signal, payload)` | `Result<(), isize>` — deliver a signal |
| `sigsuspend(mask)` | `Result<(), isize>` — atomically set mask and suspend (syscall #135) |
| `set_signal_mask(mask)` / `signal_mask()` | Get/set the **64-bit** signal mask |
| `block_signal(signal)` / `unblock_signal(signal)` | Convenience mask helpers |
| `signal_dispatch_loop(handlers)` | `!` — infinite loop dispatching to registered handlers |

Signal constants re-exported: `SIGHUP` (1), `SIGINT` (2), `SIGQUIT` (3),
`SIGKILL` (9), `SIGTERM` (15), `SIGCHLD` (17), `SIGCONT` (18), `SIGSTOP` (19),
`SIGTSTP` (20). Additionally, `SIGRTMIN` (32) and `SIGRTMAX` (42) constants
are available for real-time signal range operations. `SA_SIGINFO` and
`SA_RESTART` flag constants are defined for use with the `SetSignalHandler`
syscall `sa_flags` parameter.

The `sigsuspend()` wrapper calls the `SYS_SIGSUSPEND` syscall (135) which
atomically replaces the signal mask and suspends the calling thread until a
signal arrives, then restores the original mask.

Usage pattern:

```rust
loop {
    let sig = signal::wait_signal_forever();
    match sig.signal {
        SIGTERM | SIGINT => syscall::sys_exit(0),
        SIGCHLD => { /* reap children */ }
        _ => {}
    }
}
```

---

## Network (`net.rs`)

File: `src/user/shared/net.rs`

### HTTP client

`fetch_http_url_bytes(url)` and `fetch_http_url_text(url)` provide HTTP/1.1 GET:
1. Parse URL via `parse_http_url()` (supports `http://` and `https://` — HTTPS is rejected at fetch time)
2. Check `sys_network_status()` capabilities
3. Connect via `sys_connect_tcp()`
4. Send `GET` request
5. Read response (handles `Content-Length` and chunked transfer-encoding)
6. Close connection

Limitations: HTTP only (no TLS), no redirect following, no persistent connections, no custom headers.

### HTTP server

`HttpServer` provides a single-threaded listener:

```rust
let mut server = HttpServer::new(8080)?;
server.route("/api/v1/status", HttpMethod::GET, status_handler);
server.set_server_data("/var/www");
server.serve()?; // never returns
```

Route handlers are `fn(&HttpRequest, Option<&str>) -> HttpResponse` function pointers (no closures, for `no_std` compatibility).

### URL support

`fetch_url_bytes()` handles both `http://` and `file://` schemes. The `file://` path reads local files via syscalls with percent-decoding.

---

## Key Conventions

1. **`no_std` + `alloc` only** — No libc dependency. All modules compile into the kernel image (and, with the `runtime` feature, freestanding ELF binaries).

2. **`Result` errors are `String`** — Lower-level syscall wrappers return `Result<_, isize>` (raw kernel errno), but command implementations and public APIs convert errno values to human-readable `String` messages.

3. **`&str` for string parameters** — Wherever possible, typed wrapper functions accept `&str` rather than `(ptr, len)` tuples, converting internally with `.as_ptr() as usize, path.len()`.

4. **`#[repr(C)]` at the ABI boundary** — Every struct that crosses the kernel/userspace boundary is `#[repr(C)]` with explicit field ordering. Offsets are checked with `offset_of!()` at compile time.

5. **`extern "Rust"` bridge** — The syscall module declares `extern "Rust"` functions that each environment implements. This avoids `extern "C"` ABI overhead while keeping the implementation swappable.

6. **Feature-gated runtime** — The `runtime` feature controls whether the standalone bare-metal syscall bridge, allocator, and panic handler are compiled. The kernel build leaves it off: the kernel's `syscall_bridge.rs` provides the `__shell_syscallN` implementations, and host-side tests resolve against that same bridge.

7. **Explicit state passing** — The dispatch function takes all state as mutable references (`cwd`, `env_vars`, `aliases`, etc.) rather than using globals or thread-locals, making it usable from both ring0 (kernel statics) and ring3 (stack variables).

8. **Error-to-exit-code mapping** — The kernel's `Error` enum is encoded as negative `isize` values at the syscall boundary (-1 = InvalidArgument through -12 = InvalidCredential), which command implementations map to POSIX-style exit codes via `CmdResult`.

---

## See Also

- [Syscall ABI reference](../en/syscall.md) — SyscallNumber enum, dispatch table, pointer specs
- [Documentation index](../README.md) — complete document tree
