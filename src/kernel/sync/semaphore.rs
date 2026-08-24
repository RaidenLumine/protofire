//! src/kernel/sync/semaphore.rs
//!
//! Counting semaphore with permit accounting, blocking acquire, and timed waits.

use crate::kernel::process::ThreadWaitOutcome;

use super::{
    wait::{plan_timed_wait, TimedWaitPlan},
    WaitQueue,
};

pub struct Semaphore {
    wait_queue: WaitQueue<usize>,
}

impl Semaphore {
    pub fn new(permits: usize) -> Self {
        Self {
            wait_queue: WaitQueue::with_state(permits),
        }
    }

    pub fn permits(&self) -> usize {
        self.wait_queue.with_lock(|permits, _| *permits)
    }

    pub fn try_acquire(&self) -> bool {
        let acquired = self.wait_queue.with_lock(|permits, _| {
            if *permits == 0 {
                return false;
            }

            // Consume one permit immediately without queueing.
            *permits -= 1;
            true
        });

        if acquired {
            self.wait_queue
                .set_current_wait_outcome(ThreadWaitOutcome::Completed);
        }

        acquired
    }

    pub fn acquire(&self) -> bool {
        self.wait_queue
            .block_current_if(|permits, waiters, thread| {
                if *permits > 0 {
                    *permits -= 1;
                    thread.set_wait_outcome(ThreadWaitOutcome::Completed);
                    return false;
                }

                waiters.push_back(thread.clone());
                true
            })
    }

    pub fn acquire_timeout(&self, timeout_ticks: u64) -> bool {
        match plan_timed_wait(timeout_ticks) {
            TimedWaitPlan::Unavailable => false,
            TimedWaitPlan::ZeroTimeout => {
                if !self.try_acquire() {
                    self.wait_queue
                        .set_current_wait_outcome(ThreadWaitOutcome::TimedOut);
                }
                false
            }
            TimedWaitPlan::Deadline(deadline) => {
                self.wait_queue
                    .block_current_until_if(deadline, |permits, waiters, thread| {
                        if *permits > 0 {
                            *permits -= 1;
                            thread.set_wait_outcome(ThreadWaitOutcome::Completed);
                            return false;
                        }

                        waiters.push_back(thread.clone());
                        true
                    })
            }
        }
    }

    pub fn release(&self, permits: usize) -> usize {
        self.wait_queue.wake_with(|available, waiters, waking| {
            for _ in 0..permits {
                // Prefer handing permits directly to waiters before increasing available count.
                if let Some(thread) = WaitQueue::<usize>::take_next_waiter(waiters) {
                    waking.push(thread);
                } else {
                    *available = available.saturating_add(1);
                }
            }
        })
    }
}
