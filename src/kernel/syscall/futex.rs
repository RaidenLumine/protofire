//! src/kernel/syscall/futex.rs
//!
//! Futex syscall handler — fast userspace mutex.
//!
//! `Futex = 106`:
//! - `arg(0)` = `uaddr: *const u32` — userspace futex word address
//! - `arg(1)` = `op` — `FUTEX_WAIT` (0) or `FUTEX_WAKE` (1)
//! - `arg(2)` = `val: u32` — expected word value (WAIT only)
//! - `arg(3)` = `timeout_ticks: u64` — wait budget (WAIT only)
//!
//! Returns 0 on a successful wait, the number of threads woken on wake,
//! or an error on failure.  The wait queues are keyed by `(pid, uaddr)` and
//! lazily pruned once their last waiter leaves.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::sync::Weak;

use super::runtime;
use super::user_memory;
use crate::kernel::process::ThreadWaitOutcome;
use crate::kernel::sync::wait::WaitQueue;
use crate::kernel::sync::Mutex;
use crate::kernel::syscall::SyscallContext;
use crate::kernel::syscall::SyscallDispatch;
use crate::Error;
use crate::Result;

/// Block while `*uaddr == val`, until `timeout_ticks` elapse.
pub const FUTEX_WAIT: usize = 0;
/// Wake up to `val` waiters blocked on `uaddr`.
pub const FUTEX_WAKE: usize = 1;

/// Registry of live futex wait queues, keyed by `(pid, uaddr)`.
type FutexQueueRegistry = Mutex<BTreeMap<(u32, u64), Weak<WaitQueue<()>>>>;
static FUTEX_QUEUES: FutexQueueRegistry = Mutex::new(BTreeMap::new());

/// Return the wait queue for `(pid, uaddr)`, creating it if necessary.
fn get_or_create_queue(pid: u32, uaddr: u64) -> Arc<WaitQueue<()>> {
    let key = (pid, uaddr);
    let mut queues = FUTEX_QUEUES.lock();
    if let Some(existing) = queues.get(&key).and_then(Weak::upgrade) {
        return existing;
    }
    let queue = Arc::new(WaitQueue::new());
    queues.insert(key, Arc::downgrade(&queue));
    queue
}

/// Drop the queue for `(pid, uaddr)` once it no longer holds any waiters
/// and the only remaining strong reference is the caller's own `wq`.
fn maybe_prune_queue(pid: u32, uaddr: u64, wq: &Arc<WaitQueue<()>>) {
    if wq.waiter_count() != 0 {
        return;
    }

    let key = (pid, uaddr);
    let mut queues = FUTEX_QUEUES.lock();
    if let Some(entry) = queues.get(&key) {
        // `strong_count() == 1` means only `wq` itself still references the
        // queue — no other thread can be about to wait on it.
        if entry.strong_count() == 1 {
            queues.remove(&key);
        }
    }
}

/// FUTEX_WAIT — block the calling thread until `*uaddr != val`, a wake
/// arrives, or `timeout_ticks` elapse.
fn futex_wait(uaddr: *const u32, val: u32, timeout_ticks: u64) -> Result<usize> {
    // 1. Read the current value from userspace.
    let current_val = user_memory::read_user_value::<u32>(uaddr as *const u8, 4, 4)?;
    if current_val != val {
        // Value changed before we could block — userspace must retry.
        return Err(Error::Busy);
    }

    // 2. Get the current process id for keying.
    let pid = runtime::current_process_pid()?;
    let uaddr_u64 = uaddr as u64;

    // 3. Classify the timeout.
    if timeout_ticks == 0 {
        // Not willing to wait at all.
        return Err(Error::TimedOut);
    }

    // 4. Get or create the wait queue.
    let wq = get_or_create_queue(pid, uaddr_u64);

    // 5. Determine the wait strategy and block.
    let scheduler = runtime::global_scheduler()?;

    if timeout_ticks == u64::MAX {
        // Wait indefinitely.
        wq.block_current_if(|_, waiters, thread| {
            waiters.push_back(thread.clone());
            true
        });
    } else {
        // Wait with deadline.
        let deadline = scheduler.current_tick().saturating_add(timeout_ticks);
        wq.block_current_until_if(deadline, |_, waiters, thread| {
            waiters.push_back(thread.clone());
            true
        });
    }

    // 6. Check the wait outcome.
    let outcome = runtime::with_current_thread(|thread| Ok(thread.wait_outcome()))?;

    // 7. Lazily prune the queue if it's now empty.
    maybe_prune_queue(pid, uaddr_u64, &wq);

    match outcome {
        ThreadWaitOutcome::Completed => Ok(0),
        ThreadWaitOutcome::TimedOut => Err(Error::TimedOut),
        // Pending or other states — treat as a normal wake (spurious).
        _ => Ok(0),
    }
}

/// FUTEX_WAKE — wake up to `max_wake` threads blocked on `uaddr`.
///
/// Returns the number of threads woken.
fn futex_wake(uaddr: *const u32, max_wake: usize) -> Result<usize> {
    let pid = runtime::current_process_pid()?;
    let uaddr_u64 = uaddr as u64;

    let queues = FUTEX_QUEUES.lock();
    let Some(queue) = queues.get(&(pid, uaddr_u64)).and_then(Weak::upgrade) else {
        // No waiters — nothing to wake.
        return Ok(0);
    };

    let mut woke = 0;
    let mut remaining = max_wake;
    while remaining > 0 && queue.wake_one() {
        woke += 1;
        remaining -= 1;
    }
    Ok(woke)
}

/// Handler for the `Futex` syscall (#106).
pub fn futex(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    let uaddr = ctx.arg(0) as *const u32;
    let op = ctx.arg(1);

    match op {
        FUTEX_WAIT => {
            let val = ctx.arg(2) as u32;
            let timeout_ticks = ctx.arg(3) as u64;
            futex_wait(uaddr, val, timeout_ticks)?;
            Ok(SyscallDispatch::complete(0))
        }
        FUTEX_WAKE => {
            let max_wake = ctx.arg(2);
            let woke = futex_wake(uaddr, max_wake)?;
            Ok(SyscallDispatch::complete(woke))
        }
        _ => Err(Error::InvalidArgument),
    }
}
