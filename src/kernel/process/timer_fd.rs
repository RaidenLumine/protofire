//! src/kernel/process/timer_fd.rs
//!
//! timerfd expiry, driven by the scheduler tick.
//!
//! A timerfd is process state: its descriptor belongs to a process and its
//! wait queue is parked through the scheduler.  The tick that expires it is
//! the scheduler's, so the expiry check lives beside `posix_timer` rather than
//! in the syscall module.  It used to be in `src/syscall/timer_fd.rs`, and the
//! scheduler reached into `crate::syscall` for it — the one edge that made
//! `process` depend on `syscall`, the consumer that depends on `process` 166
//! ways.
//!
//! The syscall module still owns *creating* one: it is a syscall's job to make
//! a timer, attach it to a descriptor, and register it here.

use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::kernel::process::process::types::TimerFdState;
use crate::kernel::sync::Mutex;

/// Timerfds whose expiry the tick has to watch.
///
/// Stale entries (an `upgrade` that fails because the timerfd was dropped) are
/// cleaned up lazily during the walk.
static ACTIVE_TIMERFDS: Mutex<Vec<Weak<TimerFdState>>> = Mutex::new(Vec::new());

/// Hand a newly armed timerfd to the tick.
///
/// A timer with no expiry is not registered: it is disarmed, and the list
/// exists to be walked.
pub fn register(state: &Arc<TimerFdState>) {
    ACTIVE_TIMERFDS.lock().push(Arc::downgrade(state));
}

/// Advance the ticking timerfds, waking one reader per expiry.
///
/// Called from the scheduler's timer tick.  Iterating the global list,
/// incrementing `expirations` for a timer whose expiry has passed, and waking
/// a waiter: the wake happens *outside* the list lock, because a wake takes
/// the scheduler's own lock and the two orders must not cross.
pub fn check_expired(current_tick: u64) {
    // Phase 1: collect expired timer Arcs (under the global list lock).
    let expired: Vec<Arc<TimerFdState>> = {
        let mut list = ACTIVE_TIMERFDS.lock();
        let mut expired = Vec::new();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::process::wait::WaitQueue;
    use core::sync::atomic::AtomicU64;

    /// A one-shot timer expires once and leaves the list; a periodic one
    /// re-arms itself and stays.
    ///
    /// The expiry walk moved out of the syscall module, so this is the test
    /// that says the move did not change what it does: the count advances on
    /// the tick that reaches the expiry and only then, and a periodic timer's
    /// next expiry is one interval further on rather than the same tick again.
    #[test]
    fn an_expired_timer_counts_once_and_a_periodic_one_rearms() {
        let one_shot = Arc::new(TimerFdState {
            expiry: AtomicU64::new(10),
            interval: AtomicU64::new(0),
            expirations: AtomicU64::new(0),
            wait_queue: WaitQueue::new(),
        });
        let periodic = Arc::new(TimerFdState {
            expiry: AtomicU64::new(10),
            interval: AtomicU64::new(5),
            expirations: AtomicU64::new(0),
            wait_queue: WaitQueue::new(),
        });
        register(&one_shot);
        register(&periodic);

        // Before the expiry tick nothing happens.
        check_expired(9);
        assert_eq!(one_shot.expirations.load(Ordering::Acquire), 0);
        assert_eq!(periodic.expirations.load(Ordering::Acquire), 0);

        check_expired(10);
        assert_eq!(one_shot.expirations.load(Ordering::Acquire), 1);
        assert_eq!(periodic.expirations.load(Ordering::Acquire), 1);
        assert_eq!(
            one_shot.expiry.load(Ordering::Acquire),
            0,
            "a one-shot timer disarms itself"
        );
        assert_eq!(
            periodic.expiry.load(Ordering::Acquire),
            15,
            "a periodic timer moves to the next interval"
        );

        // A one-shot timer is not counted again by a later tick; the periodic
        // one is, once per interval.
        check_expired(11);
        assert_eq!(one_shot.expirations.load(Ordering::Acquire), 1);
        assert_eq!(periodic.expirations.load(Ordering::Acquire), 1);
        check_expired(15);
        assert_eq!(periodic.expirations.load(Ordering::Acquire), 2);
    }
}
