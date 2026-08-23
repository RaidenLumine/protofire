# Process and Thread Model

This document describes the process and thread architecture of the kernel.
Source files live under `src/kernel/process/` and arch-specific context-switch code
lives in `src/arch/{x86_64,aarch64,riscv64}/context.rs`.

---

## Process / Thread Relationship

A `Process` (`src/kernel/process/process/mod.rs`) owns zero or more threads,
a handle table, file-descriptor table, address space, signal state, and
security credentials. A `Thread` (`src/kernel/process/thread/mod.rs`) is the
schedulable unit of execution and always belongs to exactly one process.

```
  ┌───────────────┐       1:N       ┌──────────────────────┐
  │   Process     │ ──────────────> │    Thread            │
  │               │                 │                      │
  │  pid: u32     │                 │  tid: u32            │
  │  handle_table │                 │  process: Arc        │
  │  fd_table     │                 │  context: Cell       │
  │  security_tok │                 │  priority            │
  │  addr_space   │                 │  state               │
  │  signal_state │                 │  kernel_stack        │
  │               │                 │  canary: AtomicU64   │
  │               │                 │  restart_block       │
  └───────────────┘                 └──────────────────────┘
```

- The scheduler operates on `Thread` objects, not `Process` objects.
- All threads in a process share its address space, file descriptors, and
  signal handlers.
- Process termination occurs when the last live thread terminates.

---

## Process States and Lifecycle

The `ProcessState` enum (`src/kernel/process/process/types.rs`) has five states:

```
  New ──> Ready ──> Running ──> Terminated
               \──> Waiting ──> Ready
```

- **New**: Process constructed but not yet dispatched. Used for
  `PROCESS_SPAWN_FLAG_START_SUSPENDED` -- the thread is stored in
  `suspended_thread` until the parent calls `resume_suspended_process`.
- **Ready**: At least one thread is runnable. The scheduler will select the
  highest-priority thread.
- **Running**: A thread is currently executing on a CPU.
- **Waiting**: All threads are blocked (sleep, signal wait, I/O).
- **Terminated**: Process is dead, resources are released. The parent reaps it via
  `Scheduler::reap_process()`. The exit reason is recorded through
  `TerminationReason::Exit { status }` or `TerminationReason::Exception(...)`.

### Lifecycle hooks (`src/kernel/process/process/lifecycle.rs`)

```rust
fn complete_termination(&self, reason: Option<TerminationReason>)
```

This function:
1. Sets state to `Terminated` and records the reason.
2. Calls `release_termination_resources()` which clears handle table, fd table,
   signal handlers, children list, and moves the user address space into
   `deferred_user_address_space_drop`.
3. Signals `termination_event` to wake waiters.
4. The scheduler sends `SIGCHLD` to the parent process if running on bare metal
   (`src/kernel/process/scheduler/terminate.rs`).

Reaping (`Scheduler::reap_process()` in `src/kernel/process/scheduler/process.rs`)
drops the deferred address space, removes the process from its parent's children
list, recycles the PID, and returns the termination record.

---

## Thread States

The `ThreadState` enum (`src/kernel/process/thread/types.rs`):

- **Ready**: On a scheduler ready queue, waiting for a CPU.
- **Running**: Currently executing.
- **Waiting**: Blocked on a `WaitQueue`, `Event`, or timer.
- **Stopped**: Suspended by `SIGSTOP`/`SIGTSTP`.
- **Terminated**: Execution finished.

---

## Stack Canary

Each thread carries a per-thread random stack canary for runtime buffer-overrun
detection. The canary is a 64-bit random value generated during thread creation
via `random::random_u64()` and stored in the `Thread` struct's `canary` field
(`AtomicU64`).

### Initialisation (`src/kernel/process/thread/lifecycle.rs`)

During `new_inner()`, after the kernel stack is allocated:
1. A random 64-bit canary value is generated.
2. The canary is written to the bottom of the kernel stack via
   `core::ptr::write_unaligned()`.
3. The `Thread::canary` field is set to the same value.

### Verification (`check_stack_canary()`)

The `Thread::check_stack_canary()` method reads the canary value from the
kernel stack bottom and compares it with the stored `Thread::canary`. If they
differ, it panics with a stack corruption diagnostic.

### Context Switch Update

In `schedule_bare_metal()` (`src/kernel/process/scheduler/dispatch.rs`):
1. **After preemption** — `check_stack_canary()` is called on the thread that
   just yielded back to the scheduler (after `process_deferred_dying()`).
2. **Before dispatch** — the next thread's `canary` value is read and stored
   into the global `__stack_chk_guard` (`AtomicUsize` at `src/lib.rs`) before
   the `arch::switch_context()` call.

### Global Guard Symbol

```rust
// src/lib.rs
#[no_mangle]
pub static __stack_chk_guard: AtomicUsize = AtomicUsize::new(0);

#[no_mangle]
pub extern "C" fn __rustc_stack_protector() -> *mut usize {
    &__stack_chk_guard as *const AtomicUsize as *mut usize
}
```

The `__rustc_stack_protector()` function provides the compiler-inserted canary
reference point. On each context switch, `__stack_chk_guard` is updated to the
new thread's canary value. Because each CPU runs at most one thread at a time,
a single global guard is sufficient.

---

## Scheduler

The `Scheduler` struct (`src/kernel/process/scheduler/mod.rs`) is the core
scheduling engine. There is one scheduler per CPU (SMP); each scheduler
maintains its own ready queues and current thread slot.

### Ready Queues

Four priority levels are defined (`ThreadPriority` in `types.rs`):

| Level      | Value | Description              |
|------------|-------|--------------------------|
| Idle       | 0     | Only the idle thread     |
| Normal     | 1     | Default user threads     |
| High       | 2     | Priority-boosted threads |
| Realtime   | 3     | Real-time threads        |

Threads are dispatched from highest priority downward, and within a priority
level, round-robin (FIFO policy threads go to the front on preemption).

### Scheduling Policy

Two policies are supported (`ThreadSchedPolicy`):

- `SchedDefault`: Round-robin within priority. Preempted at time-slice expiry
  (`TIME_SLICE_TICKS = 2` timer ticks).
- `SchedFifo`: Run to completion -- not preempted on time-slice expiry.

### Priority Boosting (`src/kernel/process/scheduler/timer.rs`)

A starvation-prevention mechanism: Normal-priority threads that wait longer than
`BOOST_THRESHOLD_TICKS` (50 ticks) are promoted to High priority for
`BOOST_DURATION_TICKS` (8 ticks), then demoted back.

### Preemption

- **Timer-based preemption**: `on_timer_tick_with_preemption()` in
  `src/kernel/process/scheduler/api.rs` is called from the timer interrupt.
  Every `TIME_SLICE_TICKS` ticks, the current thread is preempted and
  re-queued via `preempt_current_thread_from_interrupt()`.
- **Voluntary yield**: `yield_current()` -> `yield_current_thread()` in
  `src/kernel/process/scheduler/dispatch.rs`.
- **Sleep**: `sleep_current(ticks)` blocks the current thread on the waiting
  queue with a wake deadline.

### Context Switch (`src/kernel/process/scheduler/dispatch.rs`)

The core loop is `schedule_bare_metal()`:

```
loop {
    // Move dying thread to deferred-drop slot
    if no reschedule needed and current exists -> return
    next = take_next_dispatchable_thread(&ready_queues)
    if no next -> restore kernel address space and return
    prepare_thread_address_space(&next)
    next.restore_context()
    self.current = Some(next)
    arch::switch_context(dispatch_context, next.context_ptr())
    // Returns here when the thread traps or is preempted
}
```

The `arch::switch_context()` function is defined per architecture:

- **x86_64** (`src/arch/x86_64/context.rs`): Inline assembly saves/restores
  RSP, RBP, RBX, R12-R15, RFLAGS, and XMM0-XMM15 into the `Context` struct.
  Jump to the next thread's saved instruction pointer.
- **AArch64** (`src/arch/aarch64/context.rs`): Saves X19-X30, SP, DAIF, and
  Q8-Q15. Loads the next thread's context and branches.
- **RISC-V 64** (`src/arch/riscv64/context.rs`): Same contract, architecture-
  specific register set.

The `Context` struct (`src/kernel/process/context.rs`) contains:
`instruction_pointer`, `stack_pointer`, `flags`, 16 general-purpose registers,
and SIMD registers (16 for x86_64, 8 for AArch64/RISC-V).

User-mode entry uses `arch::enter_user_mode_with_context()` which builds an
`iretq` frame (x86_64) or programs `ELR_EL1`/`SPSR_EL1` (AArch64) and executes
`eret`.

### APC / Per-CPU Schedulers

On SMP systems, each CPU has its own `Scheduler` instance. Threads get a
`cpu_affinity` assigned round-robin at spawn time
(`register_spawned_thread()` in `src/kernel/process/scheduler/spawn.rs`).
Reschedule IPIs are sent to remote CPUs when a higher-priority thread is
spawned.

---

## Spawn API (`src/kernel/process/scheduler/spawn.rs`)

The scheduler provides typed spawn entry points:

| Function | Description |
|----------|-------------|
| `spawn_kernel_named(name, entry_fn)` | Kernel-mode thread, ring 0 |
| `spawn_user_named(name, start_descriptor)` | User-mode thread, ring 3 |
| `try_spawn_user_named_with_security_token(...)` | User thread with explicit security token |

All spawn paths:
1. Allocate a PID via `allocate_pid()` (reuses freed PIDs, wraps at u32 max).
2. Create a `Process` in `Ready` (or `New` if `start_suspended`).
3. Create the `Thread` via `Thread::new()` or `Thread::try_new_user()`.
4. Call `register_spawned_thread()` which assigns CPU affinity and enqueues the
   thread on the target CPU's ready queue.
5. Optionally sends a reschedule IPI to the target CPU.

### Init Program

The first user-space process (PID 1) is spawned using
`spawn_from_launch_reference()`, which parses the boot image manifest,
constructs a `LaunchContext` (catalog ID, manifest path, image path, version,
working directory, arguments, environment), and sets up the user address space
via `ProcessUserAddressSpace::from_prepared_process()`.

### Fork (`src/kernel/process/process/fork.rs`)

`Process::fork()` creates a child process with a Copy-on-Write address space.
The child inherits file descriptors (reopened as independent handles), launch
context, CWD, and home directory. Only single-threaded processes may fork.

---

## Security Model (`src/kernel/process/process/security.rs`)

Each process carries a `SecurityToken`:

```rust
pub struct SecurityToken {
    pub user_id: UserId,
    pub primary_group_id: GroupId,
    pub integrity: IntegrityLevel,
    elevated: bool,
    pub recovery: bool,
    pub supplementary_group_ids: &'static [GroupId],
    authenticated: bool,
}
```

### Integrity Levels

| Level  | Value | Usage                |
|--------|-------|----------------------|
| System | 0     | Kernel threads only  |
| High   | 1     | Root/admin processes |
| Medium | 2     | Guest / normal users |
| Low    | 3     | Sandboxed processes  |

An integrity level *dominates* another if its numeric value is <= the other's.

### Key Queries

- `may_bypass_discretionary_permissions()`: System tokens always bypass;
  user tokens require both superuser/admin-mode and password-based
  authentication (`is_authenticated()`).
- `may_manage_system_tree()`: Requires admin mode (elevated or system).
- `is_admin_mode()`: True if `elevated` or `integrity == System`.
- `may_bypass_read_only_mounts()`: Recovery mode only.
- `belongs_to_group()`: Checks primary + supplementary group IDs.

### Authentication Flow

- `SecurityToken::system()`: Kernel-internal, always privileged, no auth flag.
- `SecurityToken::root()`: High integrity, elevated, unauthenticated by default.
- `SecurityToken::guest()`: Medium integrity, unprivileged.
- `with_authentication()`: Called after password-based login; gates
  `may_bypass_discretionary_permissions()` for user-mode admin tokens.

---

## Signal Delivery (`src/kernel/process/process/lifecycle.rs`)

The signal subsystem provides POSIX-like signal semantics with 43 signal slots
(0-42), including 11 real-time signals (32-42). The signal mask is a 64-bit
bitfield, and async delivery supports SA_SIGINFO and SA_RESTART flags on all
three architectures.

### Architecture

```
            ┌──────────────────────────────────┐
            │ Process                           │
            │  signal_handlers: [Option;43]     │
            │  signal_sa_flags: [u32; 43]       │
            │  signal_mask: u64 bitfield         │
            │  signal_queue: WaitQueue           │
            └──────────────────────────────────┘
                        │
            ┌───────────┴───────────┐
            │ Thread                │
            │  restart_block:       │
            │   RestartBlock        │
            └───────────────────────┘
```

### Real-Time Signals (RT)

Real-time signals (SIGRTMIN = 32 through SIGRTMAX = 42) provide 11 queued
signal slots with POSIX-like delivery semantics. Each RT signal carries a
`SignalInfo` (siginfo_t-compatible) payload with `si_signo`, `si_code`,
`sender_pid`, `sender_uid`, `si_value`, and `si_addr`. RT signals are queued
individually — unlike standard signals, multiple instances of the same RT
signal can be pending simultaneously. The `PROCESS_SIGNAL_MAX` constant is
now 42 (up from 31).

### Handler Installation

Signal handler arrays are sized to 43 slots (indices 0-42). The per-slot
`signal_sa_flags` field stores the `sa_flags` from `sigaction`, supporting
the SA_SIGINFO and SA_RESTART flags:

- **SA_SIGINFO**: When set, async signal delivery writes a `SignalInfo`
  structure onto the user stack alongside the signal frame. The handler
  receives `si_signo`, `si_code`, `si_pid`, `si_uid`, `si_value`, and
  `si_addr` populated with the sender process's identity and the signal
  payload value.
- **SA_RESTART**: When set, signal delivery marks the interrupted thread's
  `RestartBlock` with the interrupted syscall context. On sigreturn, the
  arch-specific trap dispatch rewinds the instruction pointer to retry the
  syscall (2 bytes on x86_64 `int 0x80`, 4 bytes on AArch64 `svc #0`,
  4 bytes on RISC-V `ecall`). The `restart_syscall` syscall (#136) is
  invoked to re-execute the interrupted operation.

### RestartBlock (`src/kernel/process/thread/types.rs`)

```rust
pub struct RestartBlock {
    /// Whether a restart is pending.
    pub pending: bool,
    /// The syscall number that was interrupted and should be restarted.
    pub syscall_number: usize,
    /// Saved arguments for re-invocation.
    pub args: [usize; 6],
}
```

Each thread stores a `RestartBlock` in its `Thread` struct (in
`src/kernel/process/thread/mod.rs`). When a signal handler with SA_RESTART
returns, the arch trap dispatch checks this block and rewinds the
instruction pointer to trigger a re-execution of the interrupted system
call.

### Enqueue (`enqueue_signal(sender_pid, signal, payload)`)

1. POSIX signals (SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGKILL, SIGSTOP, etc.)
   are checked first:
   - SIGKILL and SIGSTOP always trigger the default action immediately.
   - Other POSIX signals: if no handler is installed and the signal is not
     blocked, the default action applies (terminate for SIGHUP/SIGINT/SIGQUIT/
     SIGTERM; stop for SIGSTOP/SIGTSTP; continue for SIGCONT).
2. If the signal has a handler or is blocked, it is enqueued into the
   `PendingProcessSignalState` (capacity 64).
3. A waiting thread is dequeued and woken, if any.

### Wait (`wait_for_signal()`, `wait_for_signal_timeout(ticks)`)

The calling thread blocks on the process's `signal_queue` WaitQueue until
a signal arrives or the timeout elapses. The `ThreadWaitOutcome` is set to
`Completed` (signal received) or `TimedOut`.

### sigsuspend (`src/kernel/syscall/process/sigsuspend.rs`)

The `sigsuspend` syscall (#135) provides the POSIX `sigsuspend()` semantic:
atomically replace the process signal mask with a caller-provided mask,
then suspend the calling thread until a signal arrives. On return, the
original signal mask is restored. The u64 signal mask is passed as a
single register argument. Implementation:
1. Save the current signal mask.
2. Replace the process mask with the caller's mask.
3. Suspend the current thread on the signal WaitQueue.
4. On wake (signal arrival), restore the original mask and return.

### Handlers (`src/kernel/process/process/constants.rs`)

```rust
pub type SignalHandler = fn(i32);
```

A process installs handlers via `Process::install_signal_handler()` (in
`src/kernel/process/process/fork.rs`). 43 slots indexed by signal number.
Signal masks are manipulated via `block_signal()`, `unblock_signal()`, and
`set_signal_mask()`, all operating on u64 bitfields.

### Default Actions (`apply_default_signal_action()`)

| Signal     | Action                           |
|------------|----------------------------------|
| SIGHUP     | Terminate                        |
| SIGINT     | Terminate                        |
| SIGQUIT    | Terminate                        |
| SIGTERM    | Terminate                        |
| SIGKILL    | Terminate (always, never blocked)|
| SIGSTOP    | Stop thread execution            |
| SIGTSTP    | Stop thread execution            |
| SIGCONT    | Resume thread execution          |
| SIGCHLD    | Ignored (default)                |

---

## Job Control (`src/kernel/process/scheduler/process.rs`)

Job control is implemented at the scheduler level:

- `stop_process(pid)`: Scans all per-CPU schedulers, removes threads from
  ready/waiting queues, and sets their state to `Stopped`.
- `continue_process(pid)`: Scans all schedulers and resumes stopped threads.
- `SIGSTOP`/`SIGCONT`/`SIGTSTP` trigger these paths through `send_signal()`.

---

## Handle Table (`src/kernel/process/process/types.rs`)

Each process maintains a `BTreeMap<Handle, HandleEntry>` (the handle table) and
a `BTreeMap<FileDescriptor, Handle>` (the fd table). Standard fds (0=stdin,
1=stdout, 2=stderr) are stored in a separate `standard_handles` array.

### KernelObject Enum

```rust
pub enum KernelObject {
    File(OpenFile),
    Directory(String),
    Device(String),
    Network(TcpConnection),
    TcpListener(TcpListener),
    UdpSocket(UdpSocket),
    RawSocket(RawSocketHandle),
    LocalSocket(Arc<LocalSocket>),
    TlsConnection(Arc<TlsWrappedConnection>),
    Process(ProcessId),
    Thread(ThreadId),
}
```

### HandleEntry

```rust
pub struct HandleEntry {
    pub object: KernelObject,
    pub rights: u32,          // HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE
}
```

### Handle Operations (`src/kernel/process/process/handle_entry.rs`)

- `read_stream(buffer, timeout)`: Dispatches to `Device::read`,
  `TcpConnection::read`, `OpenFile::read`, etc. based on `KernelObject` variant.
- `write_stream(buffer)`: Dispatches similarly for writes.
- `is_readable()` / `is_writable()`: Returns readiness status without blocking.
  File and Device always report readable/writable; network objects delegate to
  the underlying connection or socket.
- `public_file_stat_record()`: Produces an `fs_abi::FileStat` for stat-like
  queries.
- `reopen_handle_in(process)` / `reopen_descriptor_in(process)`: Duplicates the
  handle into another process's table.

### FD Table Operations (`src/kernel/process/process/handle_ops.rs`)

- `open_handle()` / `open_descriptor()`: Insert a new object.
- `close_fd(fd)`: Removes the fd binding and releases the handle if no other
  reference exists.
- `duplicate_fd(fd)` / `duplicate_fd_to(fd, newfd)`: POSIX dup/dup2 semantics.
- `bind_standard_handle(fd, handle)`: Sets a stdio slot (0/1/2).
- `inherit_fds_from(source)`: Copies non-CLOEXEC fds from another process
  (used during spawn).
- `close_cloexec_fds()`: Closes all fds with `FD_CLOEXEC` flag (used during
  exec).
- `set_fd_flags(fd, set, clear)`: Manipulates per-fd flags like CLOEXEC.
- `redirect(from, to)`: Dup2-style redirection between standard fds.

---

## Process Lifecycle Hooks

### On Exit (`src/kernel/process/scheduler/terminate.rs`)

`finish_current_thread()`:

1. Removes the current thread from the scheduler's current slot.
2. Calls `terminate_sibling_threads()` to kill all other threads of the same
   process that are in ready/waiting queues.
3. Terminates the current thread, which signals `termination_event`.
4. Sends `SIGCHLD` to the parent process (bare-metal only).
5. Moves the thread into `dying_thread` so its `KernelStack` and `Arc` are
   dropped later, after the context switch onto the scheduler's own stack.

### Parent Notification

When the last thread terminates, `complete_termination()` is called. The
scheduler sends `SIGCHLD` with `payload = child_pid` to the parent. The parent
can then call `Scheduler::reap_process()` which:

1. Calls `process.reap_termination_reason()` to consume the one-shot reason.
2. Removes the child from the parent's children list.
3. Drops the deferred user address space (page tables) with interrupts enabled.
4. Recycles the PID.

### SHM Cleanup (`src/kernel/process/process/lifecycle.rs`)

The `Process` tracks shared-memory attachments in `shm_attachments:
Vec<ProcessShmAttachment>`. During `release_termination_resources()`,
`collect_shm_attachments()` returns all attachments for the SHM subsystem to
detach, then `clear_shm_attachments()` removes them.

### Reparenting

Orphaned processes are reparented to PID 1 via `set_parent_pid()` when the
original parent terminates before the child.

---

## See Also

- [Subsystem overview](../en/process.md) — high-level process and thread model description
- [Documentation index](../README.md) — complete document tree
