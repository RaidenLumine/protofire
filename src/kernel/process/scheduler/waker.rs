//! src/kernel/process/scheduler/waker.rs
//!
//! Block/wake/timed-waiter infrastructure.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::arch;
use crate::kernel::sync::{wait::WaiterIdentity, WaitTimeoutCleanupRef};

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
        // Remove timed waiter from the thread's affinity CPU (where it
        // was blocked).  On single-CPU or early boot, fall back to the
        // local scheduler.
        if let Some(target_sched) = crate::kernel::smp::get_percpu_scheduler(thread_cpu) {
            target_sched.remove_timed_waiter_for(WaiterIdentity::from_thread(&thread));
        } else {
            self.remove_timed_waiter(WaiterIdentity::from_thread(&thread));
        }
        if !thread.wake_by_signal() {
            return false;
        }
        // Enqueue into the thread's affinity CPU's ready queues.
        let enqueued =
            if let Some(target_sched) = crate::kernel::smp::get_percpu_scheduler(thread_cpu) {
                target_sched.enqueue_ready_thread_local(thread.clone())
            } else {
                enqueue_ready_thread(&mut self.ready_queues.lock(), thread.clone())
            };
        if enqueued {
            self.record_signal_wake(&thread);
            // Set need_resched on the target CPU if the woken thread has
            // higher priority than what that CPU is currently running.
            if let Some(target_sched) = crate::kernel::smp::get_percpu_scheduler(thread_cpu) {
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
                if let Some(remote_sched) = crate::kernel::smp::get_percpu_scheduler(thread_cpu) {
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
                        false
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

            if enqueued {
                woke_count += 1;
                // Set need_resched on the target CPU (if remote) or locally.
                if thread_cpu != current_cpu {
                    // Thread was enqueued on a remote CPU — wake it up.
                    if let Some(target_sched) = crate::kernel::smp::get_percpu_scheduler(thread_cpu)
                    {
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

    pub(crate) fn register_timed_waiter(
        &self,
        thread: Arc<Thread>,
        cleanup: Option<WaitTimeoutCleanupRef>,
    ) {
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
        self.record_timed_wait_registration();
    }

    pub(crate) fn remove_timed_waiter(&self, identity: WaiterIdentity) {
        let mut waiting_queue = self.waiting_queue.lock();
        let _ = remove_timed_waiters_by_identity(&mut waiting_queue, identity);
    }
}
