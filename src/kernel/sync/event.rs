//! src/kernel/sync/event.rs
//! Manual/auto-reset event primitive for signal-and-wake synchronization.

use crate::kernel::process::{Scheduler, ThreadWaitOutcome};

use super::{
    wait::{plan_timed_wait, TimedWaitPlan},
    WaitQueue,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventMode {
    ManualReset,
    AutoReset,
}

#[derive(Clone, Copy)]
struct EventState {
    mode: EventMode,
    signaled: bool,
}

pub struct Event {
    wait_queue: WaitQueue<EventState>,
}

impl Event {
    pub fn new(mode: EventMode, initially_signaled: bool) -> Self {
        Self {
            wait_queue: WaitQueue::with_state(EventState {
                mode,
                signaled: initially_signaled,
            }),
        }
    }

    pub fn manual_reset(initially_signaled: bool) -> Self {
        Self::new(EventMode::ManualReset, initially_signaled)
    }

    pub fn auto_reset(initially_signaled: bool) -> Self {
        Self::new(EventMode::AutoReset, initially_signaled)
    }

    pub fn mode(&self) -> EventMode {
        self.wait_queue.with_lock(|state, _| state.mode)
    }

    pub fn is_signaled(&self) -> bool {
        self.wait_queue.with_lock(|state, _| state.signaled)
    }

    pub fn waiter_count(&self) -> usize {
        self.wait_queue.waiter_count()
    }

    pub fn reset(&self) {
        self.wait_queue.with_lock(|state, _| {
            state.signaled = false;
        });
    }

    pub fn signal(&self) -> usize {
        self.wait_queue
            .wake_with(|state, waiters, waking| match state.mode {
                EventMode::ManualReset => {
                    // Manual-reset stays signaled and wakes every current waiter.
                    state.signaled = true;
                    waking.extend(waiters.drain(..));
                }
                EventMode::AutoReset => {
                    // Auto-reset releases at most one waiter, otherwise records a sticky signal.
                    if let Some(thread) = WaitQueue::<EventState>::take_next_waiter(waiters) {
                        state.signaled = false;
                        waking.push(thread);
                    } else {
                        state.signaled = true;
                    }
                }
            })
    }

    pub fn wait(&self) -> bool {
        self.wait_queue
            .block_current_if(|state, waiters, thread| match state.mode {
                EventMode::ManualReset if state.signaled => {
                    thread.set_wait_outcome(ThreadWaitOutcome::Completed);
                    false
                }
                EventMode::AutoReset if state.signaled => {
                    state.signaled = false;
                    thread.set_wait_outcome(ThreadWaitOutcome::Completed);
                    false
                }
                _ => {
                    waiters.push_back(thread.clone());
                    true
                }
            })
    }

    pub fn wait_timeout(&self, timeout_ticks: u64) -> bool {
        match plan_timed_wait(timeout_ticks) {
            TimedWaitPlan::Unavailable => false,
            TimedWaitPlan::ZeroTimeout => {
                // Zero-timeout behaves like a non-blocking probe against the current state.
                let Some(thread) =
                    Scheduler::global().and_then(|scheduler| scheduler.current_thread())
                else {
                    return false;
                };

                self.wait_queue.with_lock(|state, _| match state.mode {
                    EventMode::ManualReset if state.signaled => {
                        thread.set_wait_outcome(ThreadWaitOutcome::Completed);
                    }
                    EventMode::AutoReset if state.signaled => {
                        state.signaled = false;
                        thread.set_wait_outcome(ThreadWaitOutcome::Completed);
                    }
                    _ => {
                        thread.set_wait_outcome(ThreadWaitOutcome::TimedOut);
                    }
                });
                false
            }
            TimedWaitPlan::Deadline(deadline) => {
                self.wait_queue
                    .block_current_until_if(deadline, |state, waiters, thread| match state.mode {
                        EventMode::ManualReset if state.signaled => {
                            thread.set_wait_outcome(ThreadWaitOutcome::Completed);
                            false
                        }
                        EventMode::AutoReset if state.signaled => {
                            state.signaled = false;
                            thread.set_wait_outcome(ThreadWaitOutcome::Completed);
                            false
                        }
                        _ => {
                            waiters.push_back(thread.clone());
                            true
                        }
                    })
            }
        }
    }
}
