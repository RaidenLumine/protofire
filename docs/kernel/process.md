# Processes, Threads and the Scheduler

A `Process` owns resources; a `Thread` is what runs.  The split is the whole
design: the address space, the handle table, the file descriptors, the signal
state and the credentials belong to the process, and the scheduler never looks
at any of them — it dispatches threads, and a thread reaches its process through
an `Arc` (`src/kernel/process/process/mod.rs`, `src/kernel/process/thread/mod.rs`).

## Lifecycle

A process is created in `New` (which is where a spawn that asked to start
suspended stays until its parent resumes it), becomes `Ready` when it has a
runnable thread, is `Running` while one of its threads is on a CPU, `Waiting`
while every thread is blocked, and `Terminated` when the last one ends.  A
thread is `Ready`, `Running`, `Waiting` on a wait queue or a timer, `Stopped` by
a job-control signal, or `Terminated`.  The two enums are `ProcessState`
(`src/kernel/process/process/types.rs`) and `ThreadState`
(`src/kernel/process/thread/types.rs`); a state is never inferred from
timestamps, so a process that looks stuck can be asked which state it is in.

## The scheduler

There is one `Scheduler` per CPU.  Each holds its own ready queues and its own
current thread, and the per-CPU registry
(`src/kernel/process/scheduler/registry.rs`) is where a CPU joins — that
registration is what "online" means for the rest of the kernel.

**Priorities.**  `ThreadPriority` has four levels, from the idle thread up
through normal threads to boosted and real-time ones.  Dispatch takes the
highest level that has anything runnable, and within a level it is round-robin
through `scheduler/queue.rs`.

**Policies.**  `ThreadSchedPolicy` is the thread's answer to "may I be
preempted": the default policy is preempted when its time slice
(`TIME_SLICE_TICKS`) expires, and a FIFO thread runs until it blocks or exits.
Long-waiting normal threads are boosted so they are not starved by the
real-time ones, and demoted again after a bounded time
(`BOOST_THRESHOLD_TICKS`/`BOOST_DURATION_TICKS` in `scheduler/timer.rs`).

**Preemption** comes from the timer tick, which calls
`on_timer_tick_with_preemption` (`scheduler/api.rs`): when the slice is up the
current thread goes back on its queue and the scheduler picks again.  The other
two ways off a CPU are voluntary — `yield_current` and `sleep_current`.

**The switch** itself is `schedule_bare_metal`
(`src/kernel/process/scheduler/dispatch.rs`): take the next dispatchable
thread, switch the address space if it belongs to another process, save the
current thread's callee-saved state and restore the next one through
`arch::switch_context`.  Each architecture implements that in its own
`src/arch/<machine>/context.rs`, and each has its own `Context` shape — the
registers a thread must keep across a switch are the machine's answer, not a
neutral one.  Entering user mode is the same idea one level down:
`arch::enter_user_mode_with_context` builds whatever the architecture returns
through (an `iretq` frame, `ELR_EL1`/`SPSR_EL1`, …).

**Across CPUs**, a thread is given a `cpu_affinity` when it is spawned
(`scheduler/spawn.rs`), the scheduler keeps a registry of schedulers by CPU id,
and a thread made runnable on another CPU is reached with that architecture's
IPI.  Work stealing (below) moves threads between CPUs when one is busy and
another is idle.

**Work stealing** (`try_steal_work`, `scheduler/dispatch.rs`) picks the online
CPU with the most ready threads, not the nearest one: half of that victim's
ready queue moves to the stealing CPU.  Nothing reads NUMA topology here — see
[memory.md](memory.md) for what the topology is used for.

## Spawning and waiting

The typed spawn entry points are `spawn_kernel_named` (a ring-0 thread),
`spawn_user_named` (a ring-3 thread started from an `UserThreadStart`), and
`try_spawn_user_named_with_security_token` when the caller wants to name the
credentials rather than inherit them.  A spawn that asks for
`PROCESS_SPAWN_FLAG_START_SUSPENDED` leaves the thread parked so the parent can
register a wait before the child can fault; `resume_suspended_process` is what
releases it.  `Process::fork` is the other way a process appears: the parent's
address space is copied, its handles are inherited, and one thread continues in
the child.

A thread that blocks does so on a `WaitQueue`, and the answer it gets back is a
`ThreadWaitOutcome`: the event happened, the deadline passed, or the thread was
interrupted.  Every blocking syscall is built on that one shape, which is why
timeouts and signal wakes behave the same wherever a thread parks.

## Signals

A process has a 32-slot handler table (slot 0 unused), a `u32` mask, and a
bounded queue of pending signals (`PendingProcessSignalState`, whose capacity is
`PENDING_PROCESS_SIGNAL_CAPACITY` in `process/constants.rs`).  Signals are
1–31: there is no real-time range, and `PROCESS_SIGNAL_MAX` is the bound every
entry point checks.

Two delivery models share that state.  A program can *poll* for the next signal
(`wait_signal`, which is what the shared runtime's `signal_dispatch_loop` does),
or install a handler with `SetSignalHandler` and let the kernel enter it: the
delivery path writes a signal frame on the user stack and rewrites the trap
frame so that the handler runs, and the trampoline the program supplied hands
that frame back to `SIGRETURN`.  The frame, the trampoline contract and what
`sigreturn` restores are [syscalls.md](syscalls.md)'s and
[RFC 0002](../rfcs/0002-signal-frame-carries-the-context.md)'s subject; the
process side owns the table, the mask and the queue.

`SA_RESTART` is the only handler flag the kernel accepts.  When it is set, the
interrupted syscall's identity and arguments are kept in the thread's
`RestartBlock` (`thread/types.rs`), and the return from the handler re-issues
the call through `restart_syscall` — the trap path rewinds the instruction
pointer to the syscall instruction, which is why the rewind is per-architecture
(2 bytes of `int 0x80`, 4 of `svc #0`, 4 of `ecall`).

Signals with no handler follow the POSIX defaults
(`apply_default_signal_action`): terminate for the fatal ones, stop for
`SIGSTOP`/`SIGTSTP`, continue for `SIGCONT`.  `SIGKILL` and `SIGSTOP` ignore
the mask, and the job-control signals are what move a process between `Running`
and `Stopped` in the scheduler (`scheduler/process.rs`).

## Handles

Everything a process holds beyond its memory is a handle: a `KernelObject`
(file, pipe, socket, event, timer, …) plus the rights the process has on it, in
a `HandleEntry` (`process/types.rs`).  The important part is the *shape* table:
`process/object_shape.rs` declares, per object kind, how an object is closed,
inherited and described, so a new kind of object is one entry rather than a
match arm in every operation (`handle_entry.rs`, `handle_ops.rs`).  File
descriptors are handles with an extra flags word (`fd_flags`), which is why
`dup`, inheritance and `F_DUPFD` are the same code path.

## Termination and reaping

`complete_termination` (`process/fork.rs`) is the one place a process stops
being able to run: it records the reason, releases the handle table, the
descriptor table, the signal handlers and the children list, moves the address
space to a deferred-drop slot — a thread may still be inside it at this point,
so freeing it here would be a use-after-free — and wakes anything waiting on
the process.  The scheduler then notifies the parent with `SIGCHLD`
(`scheduler/terminate.rs`).

The parent reaps with `reap_process` (`scheduler/process.rs`), which drops the
deferred address space, removes the process from the parent's children,
recycles the pid and hands back the termination record.  Until it does, the
process is a zombie: no threads, no resources a new process could collide with,
and still addressable.  A child whose parent has died is reparented rather than
left waiting for a reaper that will never come, and a process's shared-memory
attachments are dropped in the same pass as its handles.

## Overrun detection

Two mechanisms are often confused here, and this kernel has one of them.

The **heap's block canary** is real: `src/memory/heap/tlsf.rs` writes a canary
at the end of each block's payload and checks it, so an overrun is attributed to
the allocation that caused it rather than to the next block's corruption.

The **stack protector** is prepared but not wired.  `Thread::canary` exists and
is initialised with a random value, and `src/lib.rs` exposes the
`__stack_chk_guard` ABI a `-C stack-protector` build needs — but nothing writes
the guard on a context switch, nothing checks it, and the build does not enable
the protector.  The field's own comment says the sync is planned.  A kernel
stack overflow today is caught by the stack's guard *page*
([memory.md](memory.md)), not by a canary.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/kernel/process/process/` | `Process`: lifecycle, handles, forking, object shapes |
| `src/kernel/process/thread/` | `Thread`: context, states, priorities, wait bookkeeping |
| `src/kernel/process/scheduler/` | Queues, dispatch, preemption, spawn, terminate, per-CPU registry |
| `src/kernel/process/context.rs` | The architecture-neutral `Context` and the switch contract |
| `src/arch/<machine>/context.rs` | The switch itself, per architecture |
| `src/kernel/process/wait/` | Wait queues and outcomes |
| `src/kernel/process/posix_timer.rs` | POSIX timers' per-process state |
| `src/kernel/process/ptrace.rs`, `seccomp.rs` | The debugging and filter entry points |

## See also

- [memory.md](memory.md) — the stacks and address spaces threads use
- [syscalls.md](syscalls.md) — how a thread enters the kernel, and `sigreturn`
- [RFC 0002](../rfcs/0002-signal-frame-carries-the-context.md) — what a signal
  frame carries and why
