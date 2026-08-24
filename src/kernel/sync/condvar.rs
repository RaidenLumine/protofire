//! src/kernel/sync/condvar.rs
//!
//! Condition variable primitive built on wait queues and mutex handoff patterns.

use alloc::sync::Arc;

use crate::kernel::process::{Scheduler, Thread, ThreadWaitOutcome};

use super::{
    wait::{plan_timed_wait, TimedWaitPlan},
    Mutex, MutexGuard, WaitQueue, WaitTimeoutCleanupRef,
};

pub struct Condvar {
    wait_queue: WaitQueue<()>,
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CondvarWait<'a, T> {
    state: CondvarWaitState<'a, T>,
    thread: Option<Arc<Thread>>,
    blocked: bool,
}

enum CondvarWaitState<'a, T> {
    Held(MutexGuard<'a, T>),
    Unlocked {
        mutex: &'a Mutex<T>,
        interrupts_were_enabled: bool,
    },
}

impl Condvar {
    pub fn new() -> Self {
        Self {
            wait_queue: WaitQueue::new(),
        }
    }

    pub fn waiter_count(&self) -> usize {
        self.wait_queue.waiter_count()
    }

    pub fn notify_one(&self) -> bool {
        self.wait_queue.wake_one()
    }

    pub fn notify_all(&self) -> usize {
        self.wait_queue.wake_all()
    }

    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> CondvarWait<'a, T> {
        let thread = Scheduler::global().and_then(|scheduler| scheduler.current_thread());
        // Release mutex before parking so producers can make progress.
        let (mutex, interrupts_were_enabled) = guard.unlock_without_restore();

        let blocked = self.wait_queue.block_current_if(|_, waiters, current| {
            waiters.push_back(current.clone());
            true
        });

        CondvarWait {
            state: if blocked {
                CondvarWaitState::Unlocked {
                    mutex,
                    interrupts_were_enabled,
                }
            } else {
                let mut guard = mutex.lock();
                guard.set_interrupt_restore_state(interrupts_were_enabled);
                CondvarWaitState::Held(guard)
            },
            thread,
            blocked,
        }
    }

    pub fn wait_timeout<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout_ticks: u64,
    ) -> CondvarWait<'a, T> {
        self.wait_timeout_with_cleanup(guard, timeout_ticks, None)
    }

    pub(crate) fn wait_timeout_observed<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout_ticks: u64,
        timeout_observer: WaitTimeoutCleanupRef,
    ) -> CondvarWait<'a, T> {
        self.wait_timeout_with_cleanup(guard, timeout_ticks, Some(timeout_observer))
    }

    fn wait_timeout_with_cleanup<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout_ticks: u64,
        timeout_observer: Option<WaitTimeoutCleanupRef>,
    ) -> CondvarWait<'a, T> {
        let thread = Scheduler::global().and_then(|scheduler| scheduler.current_thread());

        let deadline = match plan_timed_wait(timeout_ticks) {
            TimedWaitPlan::ZeroTimeout => {
                // Zero timeout is a non-blocking check with explicit timed-out outcome.
                if let Some(thread) = &thread {
                    thread.set_wait_outcome(ThreadWaitOutcome::TimedOut);
                }

                return CondvarWait {
                    state: CondvarWaitState::Held(guard),
                    thread,
                    blocked: false,
                };
            }
            TimedWaitPlan::Unavailable => {
                // Without a scheduler we cannot block, so return with guard still held.
                return CondvarWait {
                    state: CondvarWaitState::Held(guard),
                    thread,
                    blocked: false,
                };
            }
            TimedWaitPlan::Deadline(deadline) => deadline,
        };

        let (mutex, interrupts_were_enabled) = guard.unlock_without_restore();
        // Timed wait uses scheduler tick deadlines managed by wait-queue timeouts.
        let blocked = self.wait_queue.block_current_until_if_with_timeout_cleanup(
            deadline,
            timeout_observer,
            |_, waiters, current| {
                waiters.push_back(current.clone());
                true
            },
        );

        CondvarWait {
            state: if blocked {
                CondvarWaitState::Unlocked {
                    mutex,
                    interrupts_were_enabled,
                }
            } else {
                let mut guard = mutex.lock();
                guard.set_interrupt_restore_state(interrupts_were_enabled);
                CondvarWaitState::Held(guard)
            },
            thread,
            blocked,
        }
    }
}

impl<'a, T> CondvarWait<'a, T> {
    pub fn blocked(&self) -> bool {
        self.blocked
    }

    pub fn timed_out(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| thread.wait_outcome() == ThreadWaitOutcome::TimedOut)
    }

    pub fn relock(self) -> MutexGuard<'a, T> {
        match self.state {
            CondvarWaitState::Held(guard) => guard,
            CondvarWaitState::Unlocked {
                mutex,
                interrupts_were_enabled,
            } => {
                if let Some(thread) = &self.thread {
                    // Guard can only be relocked after this same thread has resumed.
                    let current_tid =
                        Scheduler::global().and_then(|scheduler| scheduler.current_thread_id());
                    assert_eq!(
                        current_tid,
                        Some(thread.tid()),
                        "relock called before waiting thread resumed"
                    );
                }

                let mut guard = mutex.lock();
                guard.set_interrupt_restore_state(interrupts_were_enabled);
                guard
            }
        }
    }
}
