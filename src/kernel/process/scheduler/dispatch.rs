//! src/kernel/process/scheduler/dispatch.rs
//! Core scheduling loop, yield, sleep, and preemption.
use core::sync::atomic::Ordering;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch;

use super::super::Thread;
use super::queue::*;
use super::Scheduler;

impl Scheduler {
    /// Drop the deferred-dying thread reference so its kernel stack
    /// and other resources are freed.
    ///
    /// Must be called with interrupts enabled because the drop
    /// may acquire heap or MMU locks that would deadlock with a
    /// cross-CPU TLB shootdown IPI.
    pub fn process_deferred_dying(&self) {
        *self.deferred_dying.lock() = None;
    }

    /// Enter the main scheduling loop.
    ///
    /// On bare-metal targets this performs a hardware context switch
    /// to the next dispatchable thread.  On host-side builds it
    /// simulates the switch by manipulating thread ownership.
    ///
    /// This function registers a global scheduler pointer for the
    /// duration of the scheduling pass so that interrupt handlers
    /// and other contexts can find the scheduler via [`Self::global()`].
    pub fn schedule(&self) {
        // SAFETY: the scheduler remains live for the duration of this
        // scheduling pass, and `Drop` clears the global slot before teardown.
        unsafe {
            self.install_global_unchecked();
        }

        // Keep one scheduling policy/queue model, but swap the execution
        // mechanism depending on whether the current target can context-switch.
        if arch::supports_context_switch() {
            self.schedule_bare_metal();
        } else {
            self.schedule_simulated();
        }
    }

    pub(crate) fn schedule_simulated(&self) {
        // Host-side simulation still rotates through the same ready/current
        // states as bare metal; it just updates ownership instead of swapping
        // CPU register frames.
        // Preempt the current thread (move it back to ready queue)
        self.preempt_current_thread_simulated();
        // Dispatch the next ready thread
        self.dispatch_next_simulated();
    }

    pub(crate) fn schedule_bare_metal(&self) {
        loop {
            // Process any pending softirqs before selecting the next thread.
            crate::kernel::softirq::process_softirqs();
            // Move the dying thread from the previous scheduling epoch to the
            // deferred-drop slot.  The actual drop happens in
            // `process_deferred_dying()`, which is called with interrupts
            // enabled so that any lock contention inside `KernelStack::drop`
            // (e.g. the memory-manager spinlock) does not deadlock with a
            // cross-CPU TLB shootdown that requires our IPI acknowledgment.
            if let Some(dying) = self.dying_thread.lock().take() {
                *self.deferred_dying.lock() = Some(dying);
            }

            // Return to caller when a thread is already active and no urgent
            // reschedule (e.g. a higher-priority thread waking up) is pending.
            if self.current.lock().is_some() && !self.need_resched.load(Ordering::Relaxed) {
                return;
            }

            let next_thread = {
                let mut ready_queues = self.ready_queues.lock();
                take_next_dispatchable_thread(&mut ready_queues)
            };

            let Some(next_thread) = next_thread else {
                // No runnable local thread — try to steal work from another
                // CPU before falling back to the idle state.
                if self.try_steal_work() {
                    continue;
                }
                // Nothing to steal either: stay in kernel address space.
                let cpu_id = crate::kernel::percpu::get().cpu_id;
                self.stats.lock().record_idle_tick(cpu_id);
                self.restore_kernel_address_space();
                return;
            };

            if !self.prepare_thread_address_space_for_dispatch(&next_thread) {
                next_thread.terminate();
                self.restore_kernel_address_space();
                continue;
            }
            next_thread.restore_context();
            // Save the raw context pointer before moving the Arc into the
            // current slot, avoiding an unnecessary atomic refcount bump.
            let ctx_ptr = next_thread.context_ptr();
            *self.current.lock() = Some(next_thread); // move, not clone
            self.record_dispatch();
            // Clear the reschedule flag now that we've dispatched a thread.
            self.need_resched.store(false, Ordering::Relaxed);

            unsafe {
                arch::switch_context(self.dispatch_context.as_mut_ptr(), ctx_ptr);
            }

            // Increment per-CPU and global context switch counters.
            let percpu = crate::kernel::percpu::get_mut();
            percpu.context_switches = percpu.context_switches.saturating_add(1);
            self.stats.lock().record_context_switch();

            // Returning here means the running thread trapped, yielded, or was
            // preempted back into the scheduler context. Re-enter queue/state
            // bookkeeping with local interrupts masked again.
            arch::interrupts::disable();
        }
    }

    // ── SMP work stealing ─────────────────────────────────────────────────
    //
    // When a CPU's ready queues are empty, it steals threads from the
    // busiest online CPU to balance load across cores.

    /// Return the total number of ready threads on this CPU.
    fn local_ready_count(&self) -> usize {
        ready_queue_len(&self.ready_queues.lock())
    }

    /// Steal up to `count` threads from this CPU's ready queues.
    /// Threads are taken from the front of each priority level (highest
    /// first) so the victim's scheduling order is disturbed as little as
    /// possible.  Threads with a CPU affinity that excludes the local CPU
    /// are left in place.
    fn drain_local_ready_threads(&self, count: usize) -> Vec<Arc<Thread>> {
        let this_cpu = crate::kernel::percpu::get().cpu_id;
        steal_ready_threads(&mut self.ready_queues.lock(), count, Some(this_cpu))
    }

    /// Push a batch of threads into the local ready queues.
    fn add_ready_threads(&self, threads: Vec<Arc<Thread>>) {
        let mut ready_queues = self.ready_queues.lock();
        for thread in threads {
            enqueue_ready_thread(&mut ready_queues, thread);
        }
    }

    /// Scan online CPUs for the one with the most ready threads, then steal
    /// half of them to this CPU's ready queues.
    ///
    /// Returns `true` if at least one thread was stolen.
    fn try_steal_work(&self) -> bool {
        let online = crate::kernel::smp::online_cpu_count();
        if online < 2 {
            return false; // Nothing to steal from on a uniprocessor.
        }

        // Find the busiest remote CPU.
        let best = {
            let mut best: Option<(u32, usize)> = None;
            crate::kernel::smp::for_each_percpu_scheduler(|cpu_id, sched| {
                // Skip our own CPU.
                if cpu_id == crate::kernel::percpu::get().cpu_id {
                    return;
                }
                let count = sched.local_ready_count();
                match best {
                    Some((_, best_count)) if count > best_count => {
                        best = Some((cpu_id, count));
                    }
                    None => best = Some((cpu_id, count)),
                    _ => {}
                }
            });
            best
        };

        let Some((victim_id, victim_count)) = best else {
            return false;
        };

        let Some(victim_sched) = crate::kernel::smp::get_percpu_scheduler(victim_id) else {
            return false;
        };

        // Steal half of the victim's ready threads.
        let steal_count = (victim_count / 2).max(1);
        let stolen = victim_sched.drain_local_ready_threads(steal_count);

        if stolen.is_empty() {
            return false;
        }

        // Add stolen threads to our own ready queues.
        self.add_ready_threads(stolen);

        // Send a reschedule IPI to the victim so it re-evaluates its
        // queues (it may have been idle and now has fewer threads).
        crate::kernel::smp::send_reschedule_ipi(victim_id);

        true
    }

    /// Voluntarily yield the remainder of the current thread's time
    /// slice.
    ///
    /// The current thread is moved to the back of its priority queue
    /// and the next dispatchable thread (if any) is scheduled.
    /// If no other thread is runnable this is a no-op.
    pub(crate) fn yield_current_thread(&self) {
        let interrupts_were_enabled = arch::interrupts::save_and_disable();
        let ctx_ptr = {
            let thread = match self.current.lock().take() {
                Some(thread) => thread,
                None => {
                    arch::interrupts::restore(interrupts_were_enabled);
                    return;
                }
            };
            let mut ready_queues = self.ready_queues.lock();

            if !has_dispatchable_ready_thread(&mut ready_queues) {
                // If nothing else is runnable, keep running current thread.
                *self.current.lock() = Some(thread);
                arch::interrupts::restore(interrupts_were_enabled);
                return;
            }

            thread.yield_back_to_ready();
            thread.save_context();
            // Save the raw context pointer before moving the Arc into the
            // ready queue, avoiding an unnecessary atomic refcount bump.
            let ctx = thread.context_ptr();
            requeue_preempted_thread(&mut ready_queues, thread); // move, not clone
            ctx
        };

        self.restore_kernel_address_space();
        unsafe {
            arch::switch_context(ctx_ptr, self.dispatch_context.as_ptr());
        }

        arch::interrupts::disable();
        arch::interrupts::restore(interrupts_were_enabled);
    }

    /// Block the current thread for at least `ticks` timer ticks.
    ///
    /// The thread is placed in the waiting queue with a wake-up deadline
    /// calculated from the current tick counter.
    pub(crate) fn sleep_current_thread(&self, ticks: u64) {
        let duration = ticks.max(1);
        let deadline = self.current_tick().saturating_add(duration);

        let _ = self.block_current_thread_if(|current_thread| {
            current_thread.block_until(deadline);
            self.register_timed_waiter(current_thread.clone(), None);
            true
        });
    }

    /// Preempt the currently running thread from an interrupt context.
    ///
    /// Called from the timer tick handler when the current thread's time
    /// slice has expired.  The preempted thread is moved back to its
    /// priority queue and the scheduler dispatches the next ready thread.
    ///
    /// Returns `true` if a preemption actually occurred, `false` if there
    /// was no current thread or no other thread was ready.
    pub(crate) fn preempt_current_thread_from_interrupt(&self) -> bool {
        let ctx_ptr = {
            let thread = match self.current.lock().take() {
                Some(thread) => thread,
                None => return false,
            };
            let mut ready_queues = self.ready_queues.lock();

            if !has_dispatchable_ready_thread(&mut ready_queues) {
                *self.current.lock() = Some(thread);
                return false;
            }

            thread.yield_back_to_ready();
            thread.save_context();
            // Save the raw context pointer before moving the Arc into the
            // ready queue, avoiding an unnecessary atomic refcount bump.
            let ctx = thread.context_ptr();
            self.record_preempt(&thread);
            requeue_preempted_thread(&mut ready_queues, thread); // move, not clone
            ctx
        };

        // Timer preemption runs on an interrupt frame. Keep interrupts masked
        // across the address-space restore and context switch so a nested IRQ
        // cannot observe the old thread after it has been queued as ready.
        arch::interrupts::disable();
        self.restore_kernel_address_space();
        unsafe {
            arch::switch_context(ctx_ptr, self.dispatch_context.as_ptr());
        }

        arch::interrupts::disable();
        true
    }

    pub(crate) fn preempt_current_thread_simulated(&self) -> bool {
        let (thread, preempt_ok) = {
            let mut current = self.current.lock();
            let mut ready_queues = self.ready_queues.lock();

            let Some(thread) = current.take() else {
                return false;
            };

            if !should_requeue_simulated_preempted_thread(thread.state()) {
                return false;
            }

            if !has_dispatchable_ready_thread(&mut ready_queues) {
                *current = Some(thread);
                return false;
            }

            thread.yield_back_to_ready();
            thread.save_context();
            requeue_preempted_thread(&mut ready_queues, thread.clone());
            (thread, true)
        };
        self.record_preempt(&thread);
        preempt_ok
    }

    pub(crate) fn dispatch_next_simulated(&self) -> bool {
        let next_thread = {
            let mut ready_queues = self.ready_queues.lock();
            take_next_dispatchable_thread(&mut ready_queues)
        };

        let Some(next_thread) = next_thread else {
            return false;
        };

        next_thread.restore_context();
        *self.current.lock() = Some(next_thread);
        self.record_dispatch();
        true
    }
}
