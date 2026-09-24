//! src/kernel/process/scheduler/terminate.rs
//!
//! Thread termination.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch;
use crate::kernel::sync::wait::WaiterIdentity;

use super::super::Process;
use super::super::TerminationReason;
use super::super::Thread;
use super::super::ThreadId;

use super::Scheduler;

/// What the placement watchdog saw when it named a process.
///
/// The two ways a process can be unplaced look the same in the report
/// otherwise, and they are different findings: a process with no threads left
/// is bookkeeping that did not finish, and one whose thread is in no queue is
/// a thread the scheduler has to account for.  Saying which one it was costs
/// nothing here and saves a round of guessing.
#[derive(Debug, Clone, Copy)]
pub(crate) enum UnplacedDetail {
    /// The process has no threads at all.
    NoThreads,
    /// The process has this many threads, and none of them was in a queue.
    NoPlacedThread {
        threads: usize,
        holding_suspended: bool,
    },
}

impl core::fmt::Display for UnplacedDetail {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoThreads => write!(formatter, "(no threads at all)"),
            Self::NoPlacedThread {
                threads,
                holding_suspended,
            } => write!(
                formatter,
                "({threads} thread(s), none placed, suspended-slot {})",
                if *holding_suspended { "full" } else { "empty" }
            ),
        }
    }
}

impl Scheduler {
    pub(crate) fn terminate_sibling_threads(&self, process: &Process, current_tid: ThreadId) {
        let pid = process.pid();

        // Remove sibling threads from all ready queues, collecting them so
        // they can be terminated *outside* the ready_queues lock.
        //
        // `Thread::terminate()` signals the thread's termination event,
        // which wakes join() waiters via `WaitQueue::wake_with` →
        // `Scheduler::wake_thread` → `enqueue_ready_thread`.  That path
        // re-locks ready_queues, so calling terminate() while still holding
        // the guard would self-deadlock a spinlock mutex whenever a dying
        // sibling has a live join() waiter.
        let mut to_terminate: Vec<Arc<Thread>> = Vec::new();
        {
            let mut ready_queues = self.ready_queues.lock();
            for deque in ready_queues.iter_mut() {
                deque.retain(|t| {
                    if t.pid() == pid && t.tid() != current_tid {
                        to_terminate.push(t.clone());
                        false
                    } else {
                        true
                    }
                });
            }
        }

        // Same for the waiting queue: remove the sibling waiters, terminate
        // them only after both queue locks are released.
        {
            let mut waiting_queue = self.waiting_queue.lock();
            waiting_queue.retain(|w| {
                if w.thread.pid() == pid && w.thread.tid() != current_tid {
                    to_terminate.push(w.thread.clone());
                    false
                } else {
                    true
                }
            });
        }

        for thread in to_terminate {
            thread.terminate();
        }
    }

    pub(crate) fn finish_current_thread(
        &self,
        reason: Option<TerminationReason>,
    ) -> Option<Arc<Thread>> {
        let current_thread = self.current.lock().take()?;
        let process = current_thread.process();

        // Kill every scheduler-visible sibling thread so the process reaches
        // the terminated state as soon as the current thread finishes.
        self.terminate_sibling_threads(process.as_ref(), current_thread.tid());

        // Terminate before leaving the thread current slot so waiters/process
        // state observe a fully recorded reason once scheduling continues.
        if let Some(reason) = reason {
            current_thread.terminate_with_reason(reason);
        } else {
            current_thread.terminate();
        }
        // Note: termination_event.signal() (called inside terminate()) already
        // wakes all join() waiters immediately and enqueues them to ready_queues.
        // Remove this thread's own timed-waiter entries from the waiting queue
        // right away so they don't linger as stale entries until the next tick.
        self.remove_timed_waiter(WaiterIdentity::from_thread(&current_thread));
        current_thread.save_context();

        // If the process has just transitioned to Terminated, notify the
        // parent process via SIGCHLD.
        #[cfg(target_os = "none")]
        if process.is_terminated() {
            let child_pid = process.pid();
            if let Some(parent_pid) = process.parent_pid() {
                let _ = self.send_signal(
                    child_pid,
                    parent_pid,
                    crate::abi::process::SIGCHLD,
                    child_pid as usize,
                );
            }
        }

        Some(current_thread)
    }

    pub(crate) fn terminate_current_thread(&self) -> ! {
        self.terminate_current_thread_with_reason(None)
    }

    pub(crate) fn record_dispatch(&self) {
        self.hotspot_stats.lock().observe_dispatch();
        if let Some(ref current) = *self.current.lock() {
            current.inc_schedule_count();
        }
    }

    pub(crate) fn record_block(&self) {
        self.hotspot_stats.lock().observe_block();
    }

    pub(crate) fn record_timed_wait_registration(&self) {
        self.hotspot_stats.lock().observe_timed_wait_registration();
    }

    pub(crate) fn record_signal_wake(&self, thread: &Thread) {
        self.hotspot_stats.lock().observe_signal_wake();
        let now = self.current_tick();
        let wait_start = thread
            .last_wait_start
            .swap(0, core::sync::atomic::Ordering::Relaxed);
        if wait_start != 0 {
            let waited = now.saturating_sub(wait_start);
            thread.add_wait_ticks(waited);
        }
    }

    pub(crate) fn record_timeout_wake(&self, woke: usize) {
        self.hotspot_stats.lock().observe_timeout_wake(woke);
    }

    pub(crate) fn record_preempt(&self, thread: &Thread) {
        self.hotspot_stats.lock().observe_preempt();
        thread.inc_preempt_count();
    }

    /// Count a wake that found nothing to wake.
    pub(crate) fn record_wake_refused(&self) {
        self.hotspot_stats.lock().observe_wake_refused();
    }

    /// Count an enqueue refused because the thread was not runnable.
    ///
    /// This is the one that matters: the caller has already made the thread
    /// `Ready`, so a thread that is not enqueued here is in no queue at all.
    ///
    /// Said once as well as counted, because it is the *cause* the placement
    /// watchdog cannot name: by the time the watchdog looks, all it can see is
    /// a thread in no queue, and this is the line that says whether the enqueue
    /// that should have placed it was refused.  Same reasoning as the other
    /// tripwires: a number nobody reads is not an explanation.
    pub(crate) fn record_enqueue_refused(&self) {
        let mut stats = self.hotspot_stats.lock();
        stats.observe_enqueue_refused();
        let first = stats.enqueue_refused_count == 1;
        drop(stats);
        if first {
            crate::println!(
                "[sched ] a runnable thread was refused by the ready queue: \
                 it is in no queue at all"
            );
        }
    }

    /// Count a thread that left the CPU and went nowhere.
    ///
    /// The scheduler took it out of the current slot expecting to requeue it,
    /// and it was not runnable — so it is in no queue now, and the resume path
    /// only walks queues.  Said once, for the same reason the others are: it is
    /// the one exit from the scheduler's view that leaves no other trace.
    pub(crate) fn record_dropped_current(&self) {
        let mut stats = self.hotspot_stats.lock();
        stats.observe_dropped_current();
        let first = stats.dropped_current_count == 1;
        drop(stats);
        if first {
            crate::println!(
                "[sched ] a thread left the CPU without being requeued: \
                 it is in no queue at all"
            );
        }
    }

    /// Count a timed waiter removed while it was still waiting for it.
    pub(crate) fn record_waiter_lost(&self) {
        let mut stats = self.hotspot_stats.lock();
        stats.observe_waiter_lost();
        // A tripwire, and a cold one: this should never happen, so it is worth
        // a line the first time it does.
        if stats.waiter_lost_count == 1 {
            crate::println!(
                "[sched ] a timed waiter was dropped while it was still waiting; \
                 the thread will never be woken"
            );
        }
    }

    /// Count a live process whose threads the scheduler cannot find.
    ///
    /// Prints once, because the second and later processes have the same
    /// cause and the first line already stopped the machine from looking
    /// healthy.
    pub(crate) fn record_unplaced_process(
        &self,
        pid: crate::kernel::process::ProcessId,
        name: &str,
        state: crate::kernel::process::ProcessState,
        detail: &UnplacedDetail,
    ) {
        let mut stats = self.hotspot_stats.lock();
        stats.observe_unplaced_process();
        let first = stats.unplaced_process_count == 1;
        drop(stats);
        if first {
            crate::println!(
                "[sched ] process pid={} name={} state={:?} {} has no thread in any queue: \
                 nothing will run it again",
                pid,
                name,
                state,
                detail,
            );
        }
    }

    pub(crate) fn terminate_current_thread_with_reason(
        &self,
        reason: Option<TerminationReason>,
    ) -> ! {
        let _interrupts_were_enabled = arch::interrupts::save_and_disable();

        if let Some(TerminationReason::Exit { status }) = reason {
            if status != 0 {
                if let Some(thread) = self.current.lock().as_ref().cloned() {
                    if let Some(launch) = thread.process().launch_context() {
                        crate::println!(
                            "[user  ] exit pid={} tid={} id={} status={}",
                            thread.pid(),
                            thread.tid(),
                            launch.catalog_id,
                            status
                        );
                    } else {
                        crate::println!(
                            "[sched ] exit pid={} tid={} status={}",
                            thread.pid(),
                            thread.tid(),
                            status
                        );
                    }
                }
            }
        }

        let Some(current_thread) = self.finish_current_thread(reason) else {
            self.restore_kernel_address_space();
            loop {
                arch::instructions::hlt();
            }
        };

        if !arch::supports_context_switch() {
            let _ = self.dispatch_next_simulated();
        }

        // Always restore the kernel address space before abandoning the dying
        // thread's context so the scheduler continues from a known-good view.
        self.restore_kernel_address_space();
        if arch::supports_context_switch() {
            // Save the context pointer before relinquishing the Arc.  The
            // Arc must live until switch_context writes the final CPU state
            // into the thread's context area, but the RSP switch inside
            // switch_context abandons this stack frame.  Move the Arc into
            // the scheduler so schedule_bare_metal can drop it once we are
            // safely back on the scheduler's own stack.
            let context_ptr = current_thread.context_ptr();
            *self.dying_thread.lock() = Some(current_thread);
            unsafe {
                arch::switch_context(context_ptr, self.dispatch_context.as_ptr());
            }
        }

        loop {
            arch::instructions::hlt();
        }
    }
}
