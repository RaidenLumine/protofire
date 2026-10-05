# IPC and Synchronization

Two layers sit under this name.  The first is how the kernel serialises its
own state: a spinlock, and a mutex built on it, in `src/kernel/sync/`.  The
second is how threads and processes wait for each other and hand data across:
the wait queue in `src/kernel/process/wait/`, the pipe in
`src/kernel/ipc/pipe.rs`, and the descriptor-shaped facilities the syscall
layer hands out — eventfd, signalfd, timerfd, message queues, futex, epoll,
io_uring and System V shared memory.

The boundaries are deliberate.  Signals and the handle table belong to
[process.md](process.md); a pipe presents the filesystem's `VNode` interface
and that half is [fs.md](fs.md)'s; local sockets are the same-machine
rendezvous in [network.md](network.md).  What is here is the machinery they
share.

## Locking kernel state

`SpinLock` (`src/kernel/sync/spinlock.rs`) is the base.  `lock` disables
interrupts on the calling CPU before it spins — a thread preempted by its own
local interrupt while holding one could never be rescheduled — and the RAII
guard restores whatever the interrupt state was.  The spin itself has
exponential backoff: a short spin while the lock reads busy, then a retry of
the compare-and-swap, so a contended lock on a multi-core machine does not
hammer the cache line.

`Mutex` (`src/kernel/sync/mutex.rs`) is a `SpinLock` with an RAII surface and
a `try_lock`.  It is a *spin* mutex: it never parks the waiter, so a critical
section is a bounded piece of work with no device I/O and no second lock held
across it.  That is a property every caller has to keep rather than something
the type enforces, and it is why the filesystem and network code release
their locks before touching a device — the comments where they do say so.

`Mutex` is also where the lock-discipline escape hatch lives: `try_lock`
answers `None` instead of waiting, which lets a test assert that a lock is
*not* held where holding it would serialise unrelated work.

## The wait queue

`WaitQueue<T>` (`src/kernel/process/wait/queue.rs`) is what everything that
parks a thread is built on.  It holds a piece of state and a queue of
`Arc<Thread>` waiters.

Blocking is `block_current_if(prepare)`: the queue runs the caller's
predicate under its own lock — push the waiter, or consume the permit, or
observe the event — and only then marks the thread blocked and registers it
with the scheduler (`park_thread`).  The registration is not bookkeeping
alone: a thread parked on a queue is otherwise indistinguishable from a
thread the scheduler has lost, and the placement watchdog depends on being
able to tell those apart.

Waking selects under the queue lock and calls `Scheduler::wake_thread` after
releasing it, so the queue lock and the scheduler's internals are never held
at the same time.  A woken thread is enqueued on its affinity CPU's ready
queue, and the wake side sends a reschedule IPI
(`crate::kernel::smp::send_reschedule_ipi`) when that CPU is another core —
otherwise a wake would wait for that core's next timer tick.

Timeouts are a plan, not an ad-hoc deadline: `plan_timed_wait` answers
"unavailable", "zero timeout" or a deadline, and the timed block registers
that deadline with the scheduler and a `WaitTimeoutCleanup` with the queue,
so a wake that arrives after the timer fired cannot be delivered twice.  A
finished wait records a `ThreadWaitOutcome` (`Pending`/`Completed`/`TimedOut`)
on the thread, which is how the caller tells a wake from a timeout.

Stale waiters are pruned by identity (`WaiterIdentity`: pid plus tid) whenever
the queue is touched, so a thread that exited while queued does not have to be
removed by hand.

## The three primitives

Over that queue:

- `Condvar` (`condvar.rs`) with `notify_one`/`notify_all`, and a wait that
  hands the mutex guard back for the duration and re-acquires it after.  It is
  the primitive the drivers use — the console, serial, keyboard, mouse and
  VirtIO net each have one.
- `Event` (`event.rs`) with a manual or auto reset mode; a termination event
  is how a process or thread lifecycle exposes "this is done".
- `Semaphore` (`semaphore.rs`) with a permit count and blocking or
  `try_acquire` acquisition.  The tree exercises it from the process stress
  and scheduler tests; nothing in the kernel calls it yet.

They sit beside the scheduler in `kernel::process::wait` rather than in
`kernel::sync` on purpose: parking a thread *is* a scheduler act, and keeping
them here leaves one dependency direction — the wait module names the
scheduler, and `kernel::sync` stays a leaf that names no thread at all.

## Pipes

`src/kernel/ipc/pipe.rs` is an anonymous pipe: a byte ring buffer shared by a
read end and a write end, each a `VNode` so the pair can sit in the namespace.
`pipe_channel` returns the two ends; the `Pipe` syscall creates a pair and
installs two consecutive descriptors.

The ends block on two condition variables — a reader when the buffer is
empty, a writer when it is full — and dropping an end changes the other's
result: dropping the write end wakes readers, whose reads then return 0 (EOF);
dropping the read end wakes writers, whose writes fail.

The buffer is resizable through `fcntl(F_SETPIPE_SZ)` (`PipeChannel::resize`),
bounded by `PIPE_MIN_SIZE` and `PIPE_MAX_SIZE`, and a resize preserves the
buffered bytes.  Each end carries its own non-blocking flag
(`fcntl(F_SETFL, O_NONBLOCK)`); in that mode an operation that would block
answers `Busy` instead.

The module lives under `kernel::ipc` rather than under `fs` because blocking
is what it does when the buffer is empty or full, and the filesystem is
storage.  It borrows the `VNode` interface rather than the filesystem
depending on it.

## Descriptor-shaped facilities

Everything below becomes a `KernelObject` variant in the per-process handle
table, so the same `read`, `write`, `close`, `poll`/`epoll` and `io_uring`
paths reach it.  The readiness half of that seam is
`HandleEntry::is_readable`/`is_writable`
(`src/kernel/process/process/handle_entry.rs`), which `epoll_wait` consults
when it probes its interest list.

| Facility | Syscalls | Mechanism |
|---|---|---|
| eventfd | `EventFd` | A `u64` counter: a read returns it and resets it (or decrements it under `EFD_SEMAPHORE`), a write adds to it, `POLLIN` is the counter being non-zero and `POLLOUT` is always ready. `EFD_NONBLOCK` makes a zero read `Busy`. |
| signalfd | `SignalFd` | A descriptor that dequeues pending signals matching its mask, instead of `wait_signal`. The signals themselves are [process.md](process.md)'s subject. |
| timerfd | `TimerFd` | Becomes readable when a kernel timer expires; one-shot or periodic. A global list of active timerfds is checked on each timer tick. |
| message queue | `MqOpen`…`MqUnlink` | Named queues (`MqState`) with a capacity and fixed message size, a `WaitQueue` for senders and one for receivers, and an optional signal notification. |
| futex | `Futex` | `FUTEX_WAIT` and `FUTEX_WAKE` over a userspace `u32`. Wait queues are keyed by `(pid, uaddr)` and pruned once the last waiter leaves. |
| epoll | `EpollCreate`, `EpollCtl`, `EpollWait` | An interest list of file descriptors plus the events to watch; a wait collects readiness through the handle table and sleeps in short intervals until one of them is ready or the timeout passes. |
| io_uring | `IoUringSetup`, `IoUringEnter` | Submission and completion queues in shared memory; the recognised operations are `NOP`, `READ`, `WRITE`, `POLL_ADD` and `TIMEOUT`, executed inline when they can complete and parked on a wait queue when they cannot. |

`epoll` and `io_uring` are the two that are not a single mechanism: both
describe readiness of other objects and both are built on the same
`is_readable`/`is_writable` answer rather than on their own idea of "ready".

## Shared memory

`src/kernel/shm.rs` implements the System V shape.  `shmget` creates a segment
under an IPC key — physical frames allocated and zeroed up front, rounded to
pages — or returns the existing one, with `IPC_CREAT`/`IPC_EXCL` deciding what
happens when the key is taken.  `shmat` maps the segment's frames into the
calling process with `READ`/`READ_WRITE` permissions, falling back to
detaching everything it mapped if any page fails, and records the attachment
on the process so exit and fork can clean it up.  `shmdt` unmaps and drops
the attachment.

`shmctl` supports `IPC_RMID` and `IPC_STAT`/`IPC_SET`.  Removal is deferred:
the segment is marked deleted, new attaches are refused, and the frames are
freed when the last process detaches.  The registry entry is a second step:
`reap_deleted_segments` is written to drop it, and has no live call site
today, so a removed segment's id and key stay taken until something calls it.
There is no POSIX `shm_open` name in the filesystem, which is the difference
the status table notes.

## What is not here

- **No named pipes.** A pipe has no name in the namespace and there is no FIFO
  node kind, so two unrelated processes cannot meet at one.
- **No descriptor passing.** A pipe carries bytes, not handles: there is no
  `SCM_RIGHTS`-shaped send.
- **No futex requeue or priority inheritance.** `FUTEX_REQUEUE` and the PI
  operations have no handler.
- **No kernel process groups.** Job control is the shell's own bookkeeping.
- **No contention baseline.** The primitives are tested for correctness under
  the process stress tests; lock contention and signal storms have no
  throughput or latency baseline.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/kernel/sync/spinlock.rs`, `src/kernel/sync/mutex.rs` | The interrupt-aware spinlock and the spin mutex over it |
| `src/kernel/process/wait/` | The wait queue, and the condvar, event and semaphore over it |
| `src/kernel/ipc/pipe.rs` | The anonymous pipe |
| `src/syscall/io_fd.rs` | The `Pipe` handler, and the read/write/close/dup paths |
| `src/syscall/event_fd.rs`, `signal_fd.rs`, `timer_fd.rs` | The notification descriptors |
| `src/syscall/futex.rs`, `mq.rs`, `epoll.rs`, `io_uring.rs` | Waiting, queues and readiness |
| `src/kernel/shm.rs`, `src/syscall/memory/shm_handlers.rs` | System V shared memory |
| `src/kernel/process/process/handle_entry.rs` | Kernel-object readiness, the seam poll/epoll/io_uring read |

## See also

- [process.md](process.md) — threads, the scheduler, signals and the handle table
- [fs.md](fs.md) — the `VNode` interface a pipe presents
- [network.md](network.md) — local sockets and the receive paths
