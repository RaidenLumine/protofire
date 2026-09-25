//! src/kernel/process/scheduler/waker.rs
//!
//! Block/wake/timed-waiter infrastructure.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::arch;
use crate::kernel::sync::wait::WaiterIdentity;
use crate::kernel::sync::WaitTimeoutCleanupRef;

use super::super::Thread;

use super::queue::*;
use super::types::TimedWaiter;
use super::Scheduler;

impl Scheduler {
    pub(crate) fn block_current_thread_if<F>(&self, prepare: F) -> bool
    where
        F: FnOnce(&Arc<Thread>) -> bool,
    {
        let interrupts_were_enabled = arch::interrupts::save_and_disable();
        let current_thread = match self.current.lock().take() {
            Some(thread) => thread,
            None => {
                arch::interrupts::restore(interrupts_were_enabled);
                return false;
            }
        };

        // Let the caller atomically change thread state and waiter metadata
        // while the thread is no longer current and interrupts are disabled.
        if !prepare(&current_thread) {
            *self.current.lock() = Some(current_thread);
            arch::interrupts::restore(interrupts_were_enabled);
            return false;
        }

        // Record wait-start tick for per-thread profiling.
        current_thread
            .last_wait_start
            .store(self.current_tick(), core::sync::atomic::Ordering::Relaxed);
        self.record_block();

        if arch::supports_context_switch() {
            self.restore_kernel_address_space();
            unsafe {
                arch::switch_context(current_thread.context_ptr(), self.dispatch_context.as_ptr());
            }
        } else {
            self.dispatch_next_simulated();
        }

        arch::interrupts::disable();
        arch::interrupts::restore(interrupts_were_enabled);
        true
    }

    pub(crate) fn wake_thread(&self, thread: Arc<Thread>) -> bool {
        let thread_cpu = thread.cpu_affinity();

        // Wake it before taking its timeout registration away.  The other
        // order leaves a thread that is still waiting with no way to be woken
        // by its deadline: the registration is gone, and a refusal here
        // (the thread was not actually waiting) returns before anything puts
        // it back.  A registration left on a thread that is not waiting is
        // harmless — the tick's stale pass drops it, which is what that pass
        // exists for.
        if !thread.wake_by_signal() {
            self.record_wake_refused();
            return false;
        }

        // The thread is ready now, so it no longer needs a deadline on this
        // CPU (or on its affinity CPU, where it was blocked).
        if let Some(target_sched) = super::registry::for_cpu(thread_cpu) {
            target_sched.remove_timed_waiter_for(WaiterIdentity::from_thread(&thread));
        } else {
            self.remove_timed_waiter(WaiterIdentity::from_thread(&thread));
        }

        // Enqueue into the thread's affinity CPU's ready queues.
        let enqueued = if let Some(target_sched) = super::registry::for_cpu(thread_cpu) {
            target_sched.enqueue_ready_thread_local(thread.clone())
        } else {
            self.enqueue_ready_thread_local(thread.clone())
        }
        .enqueued();
        if enqueued {
            self.record_signal_wake(&thread);
            // Set need_resched on the target CPU if the woken thread has
            // higher priority than what that CPU is currently running.
            if let Some(target_sched) = super::registry::for_cpu(thread_cpu) {
                target_sched.maybe_set_need_resched_for(&thread);
            } else {
                self.maybe_set_need_resched(&thread);
            }
            let current_cpu = crate::kernel::percpu::get().cpu_id;
            if thread_cpu != current_cpu {
                crate::kernel::smp::send_reschedule_ipi(thread_cpu);
            }
            true
        } else {
            false
        }
    }

    /// Wake every sleeper whose deadline has passed, on every CPU.
    ///
    /// A sleeping thread waits in the queue of the CPU it sleeps on, and a
    /// timer tick is the only thing that wakes it.  That makes "which CPUs
    /// take a timer interrupt" a liveness question rather than a hardware
    /// detail: an x86_64 AP never takes one — the PIT is wired to the boot
    /// CPU — so a worker that sleeps while running on an AP would stay asleep
    /// for the life of the machine.  So the sweep covers every CPU, and the
    /// take is exclusive: whichever CPU looks first removes the waiter, and
    /// the second finds nothing to do.
    pub(crate) fn wake_expired_sleepers(&self, ticks: u64) -> usize {
        let mut woke = self.wake_ready_threads(ticks);
        let local_cpu = crate::kernel::percpu::get().cpu_id;
        super::registry::for_each(|cpu_id, sched| {
            if cpu_id != local_cpu {
                woke += sched.wake_ready_threads(ticks);
            }
        });
        woke
    }

    /// Wake the sleepers whose deadline has passed from this scheduler's queue.
    pub(crate) fn wake_ready_threads(&self, ticks: u64) -> usize {
        let (stale, woke) = {
            let mut waiting_queue = self.waiting_queue.lock();
            (
                take_stale_timed_waiters(&mut waiting_queue),
                take_elapsed_timed_waiters(&mut waiting_queue, ticks),
            )
        };
        remove_timed_waiters_from_wait_queues(stale);

        if woke.is_empty() {
            return 0;
        }

        let mut woke_count = 0;
        for timed_waiter in woke {
            let thread = timed_waiter.thread;
            let cleanup = timed_waiter.cleanup;
            let priority = thread.priority();
            let thread_cpu = thread.cpu_affinity();
            let current_cpu = crate::kernel::percpu::get().cpu_id;

            // If the thread belongs to a different CPU, enqueue it there.
            let enqueued = if thread_cpu != current_cpu {
                if let Some(remote_sched) = super::registry::for_cpu(thread_cpu) {
                    let identity = WaiterIdentity::from_thread(&thread);
                    if let Some(ref cleanup) = cleanup {
                        cleanup.remove_waiter(identity);
                    }
                    if thread.wake_by_timeout() {
                        if let Some(ref cleanup) = cleanup {
                            cleanup.on_timeout(identity);
                        }
                        remote_sched.enqueue_ready_thread_local(thread)
                    } else {
                        EnqueueOutcome::NotReady
                    }
                } else {
                    // Fallback: enqueue locally.
                    process_elapsed_timed_waiter(
                        TimedWaiter { thread, cleanup },
                        &mut self.ready_queues.lock(),
                    )
                }
            } else {
                process_elapsed_timed_waiter(
                    TimedWaiter { thread, cleanup },
                    &mut self.ready_queues.lock(),
                )
            };

            if enqueued == EnqueueOutcome::NotReady {
                // The thread was already woken by something else, or it is
                // stopped: either way it is not ours to place.  Counted
                // because a *runnable* thread refused here would be one in no
                // queue at all.
                self.record_enqueue_refused();
            }

            if enqueued.enqueued() {
                woke_count += 1;
                // Set need_resched on the target CPU (if remote) or locally.
                if thread_cpu != current_cpu {
                    // Thread was enqueued on a remote CPU — wake it up.
                    if let Some(target_sched) = super::registry::for_cpu(thread_cpu) {
                        target_sched.set_need_resched();
                    }
                    crate::kernel::smp::send_reschedule_ipi(thread_cpu);
                } else if let Some(current) = self.current.lock().as_ref() {
                    if priority > current.priority() {
                        self.need_resched.store(true, Ordering::Relaxed);
                    }
                }
            }
        }

        if woke_count != 0 {
            self.record_timeout_wake(woke_count);
        }

        woke_count
    }

    pub(crate) fn current_tick(&self) -> u64 {
        if arch::supports_context_switch() {
            arch::timer::ticks()
        } else {
            *self.simulated_ticks.lock()
        }
    }

    /// Park a thread on this scheduler's waiting queue.
    ///
    /// The queue holds every thread the scheduler has taken out of the running
    /// set: one waiting for a deadline, and one blocked on a wait queue that
    /// will be woken by whoever signals it.  Holding all of them is what lets
    /// the scheduler tell "parked" from "lost" at all — a thread it cannot
    /// find in any queue is one it has no way to run again.
    pub(crate) fn park_thread(&self, thread: Arc<Thread>, cleanup: Option<WaitTimeoutCleanupRef>) {
        thread
            .last_wait_start
            .store(self.current_tick(), core::sync::atomic::Ordering::Relaxed);
        let mut waiting_queue = self.waiting_queue.lock();
        // Replace any stale waiter for the same thread so timeout wakeups keep
        // a single source of truth for deadline and cleanup ownership.
        let _ = remove_timed_waiters_by_identity(
            &mut waiting_queue,
            WaiterIdentity::from_thread(&thread),
        );
        waiting_queue.push(TimedWaiter { thread, cleanup });
    }

    /// Park a thread that has a deadline, and count its registration.
    ///
    /// The count is about deadlines rather than about parking — it is the
    /// number the machine's timeouts rest on, and the one a sleeper that never
    /// woke would have shown up in.
    pub(crate) fn register_timed_waiter(
        &self,
        thread: Arc<Thread>,
        cleanup: Option<WaitTimeoutCleanupRef>,
    ) {
        self.park_thread(thread, cleanup);
        self.record_timed_wait_registration();
    }

    pub(crate) fn remove_timed_waiter(&self, identity: WaiterIdentity) {
        let removed = {
            let mut waiting_queue = self.waiting_queue.lock();
            take_timed_waiters_by_identity(&mut waiting_queue, identity)
        };
        // The registration is gone, so a thread that is still waiting for a
        // deadline now has nothing that will wake it.  This is the invariant
        // whose violation was a machine that stopped with a sleeper in it, and
        // it is counted where it can actually be seen — the removal — rather
        // than looked for afterwards, when the thread is already unreachable.
        for waiter in removed {
            if waiter.thread.state() == super::super::ThreadState::Waiting
                && waiter.thread.wake_deadline().is_some()
                && waiter.thread.process().state() != super::super::ProcessState::Terminated
            {
                self.record_waiter_lost();
            }
        }
    }
}
