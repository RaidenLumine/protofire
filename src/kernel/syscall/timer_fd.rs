//! src/kernel/syscall/timer_fd.rs
//!
//! timerfd — timer expiration notification file descriptor.
//!
//! Provides a file descriptor that becomes readable when a kernel timer
//! expires.  Supports both one-shot and periodic timers.
//!
//! # Syscall
//!
//! `TimerFd = 109`
//! - `arg(0)` = `expiry_delta: u64` — number of ticks from now to first expiry
//! - `arg(1)` = `interval_ticks: u64` — periodic interval (0 = one-shot)
//! - `arg(2)` = `flags: u32` — reserved (pass 0)

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::runtime;
use crate::kernel::process::process::types::TimerFdState;
use crate::kernel::process::{KernelObject, HANDLE_RIGHT_READ};
use crate::kernel::sync::wait::WaitQueue;
use crate::kernel::sync::Mutex;
use crate::kernel::syscall::SyscallContext;
use crate::Result;

/// Global list of active timerfds, checked on each timer tick.
///
/// Stale entries (upgrade fails — timerfd was dropped) are cleaned up
/// lazily during iteration.
static ACTIVE_TIMERFDS: Mutex<alloc::vec::Vec<alloc::sync::Weak<TimerFdState>>> =
    Mutex::new(alloc::vec::Vec::new());

/// Handler for `TimerFd` syscall (#109).
///
/// Creates a timerfd, arms it with the given expiry and interval, and
/// returns a file descriptor.
pub fn timerfd(ctx: &mut SyscallContext) -> Result<crate::kernel::syscall::SyscallDispatch> {
    let expiry_delta = ctx.arg(0) as u64;
    let interval_ticks = ctx.arg(1) as u64;
    let _flags = ctx.arg(2) as u32;

    let current_tick = if let Some(sched) = crate::kernel::process::Scheduler::global() {
        sched.current_tick()
    } else {
        0
    };
    let expiry = if expiry_delta == 0 {
        0 // disarmed
    } else {
        current_tick.saturating_add(expiry_delta)
    };

    let state = Arc::new(TimerFdState {
        expiry: AtomicU64::new(expiry),
        interval: AtomicU64::new(interval_ticks),
        expirations: AtomicU64::new(0),
        wait_queue: WaitQueue::new(),
    });

    // Register in the global active list so the tick handler can check it.
    if expiry > 0 {
        ACTIVE_TIMERFDS.lock().push(Arc::downgrade(&state));
    }

    let process = runtime::current_process()?;
    let fd = process.open_descriptor(KernelObject::TimerFd(state), HANDLE_RIGHT_READ)?;

    Ok(crate::kernel::syscall::SyscallDispatch::complete(fd))
}

/// Called from the scheduler's timer tick to advance expiring timerfds.
///
/// Iterates the global active list, increments `expirations` for any
/// timer whose expiry tick has passed, and wakes one waiter per expired
/// timer.  Waking happens *outside* the global list lock to avoid lock
/// ordering inversions with the scheduler.
pub fn check_expired_timerfds(current_tick: u64) {
    // Phase 1: collect expired timer Arcs (under the global list lock).
    let expired: alloc::vec::Vec<Arc<TimerFdState>> = {
        let mut list = ACTIVE_TIMERFDS.lock();
        let mut expired = alloc::vec::Vec::new();

        list.retain(|weak| {
            let Some(timer) = weak.upgrade() else {
                return false; // timerfd was dropped
            };

            let expiry = timer.expiry.load(Ordering::Acquire);
            if expiry == 0 || current_tick < expiry {
                return true; // not yet expired
            }

            // Timer has expired — bump the expiration count.
            timer.expirations.fetch_add(1, Ordering::Release);

            let interval = timer.interval.load(Ordering::Acquire);
            if interval > 0 {
                // Periodic: advance expiry by one interval.
                timer
                    .expiry
                    .store(expiry.saturating_add(interval), Ordering::Release);
                expired.push(timer.clone());
                true // keep in active list
            } else {
                // One-shot: disarm and remove from active list.
                timer.expiry.store(0, Ordering::Release);
                expired.push(timer);
                false // remove
            }
        });

        expired
    };

    // Phase 2: wake waiters outside the global list lock.
    for timer in &expired {
        timer.wait_queue.wake_one();
    }
}
