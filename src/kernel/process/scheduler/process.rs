//! src/kernel/process/scheduler/process.rs
//!
//! Process lifecycle and query operations.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::super::{
    Process, ProcessId, ProcessSummary, TerminationReason, Thread, ThreadId, ThreadPriority,
    ThreadSummary,
};

use super::api::idle_entry;
use super::queue::*;
use super::types::{SchedulerHotspotStats, SchedulerStats};
use super::Scheduler;

impl Scheduler {
    /// Ensure an idle thread exists when no other thread is runnable.
    ///
    /// Spawns a kernel thread named `"idle"` that runs [`idle_entry`]
    /// if and only if the scheduler has no current thread and no ready
    /// threads are waiting.
    pub fn start_idle_process(&self) {
        if self.current.lock().is_some() {
            return;
        }

        let has_ready_thread = {
            let mut ready_queues = self.ready_queues.lock();
            has_dispatchable_ready_thread(&mut ready_queues)
        };
        if !has_ready_thread {
            self.spawn_kernel_named("idle", idle_entry);
        }
    }

    /// Return the TID of the currently running thread, or `None` if
    /// no thread is scheduled.
    pub fn current_thread_id(&self) -> Option<ThreadId> {
        self.current.lock().as_ref().map(|thread| thread.tid())
    }

    /// Return the number of dispatchable threads in the ready queues.
    ///
    /// Stale (non-dispatchable) entries are pruned before counting.
    pub fn ready_count(&self) -> usize {
        let mut ready_queues = self.ready_queues.lock();
        let _ = prune_nondispatchable_ready_threads(&mut ready_queues);
        ready_queues.iter().map(|q| q.len()).sum::<usize>()
    }

    /// Return the number of registered processes.
    ///
    /// Processes are registered only in the primary (CPU 0) scheduler.
    pub fn process_count(&self) -> usize {
        self.processes.lock().len()
    }

    /// Select the process with the highest OOM badness score.
    ///
    /// The caller provides a scoring function that takes a `&Process` and
    /// returns a `u64` score (higher = better candidate for termination).
    /// Returns `(pid, score)` for the worst-scoring process, or `None` if
    /// every process scored 0.
    pub fn select_oom_victim_by<F>(&self, score_fn: F) -> Option<(u32, u64)>
    where
        F: Fn(&Process) -> u64,
    {
        let processes = self.processes.lock();
        let mut best: Option<(u32, u64)> = None;

        for proc in processes.iter() {
            let score = score_fn(proc);
            if score == 0 {
                continue;
            }
            match best {
                Some((_, best_score)) if score <= best_score => {}
                _ => best = Some((proc.pid(), score)),
            }
        }

        best
    }

    /// Return a summary of every registered process and its aggregate
    /// CPU usage.
    ///
    /// Thread statistics are gathered from all per-CPU schedulers.
    pub fn list_process_summaries(&self) -> Vec<ProcessSummary> {
        // Build a pid → (max_priority, total_cpu_ticks) map from all live
        // threads across all per-CPU schedulers.
        let mut thread_stats: BTreeMap<ProcessId, (ThreadPriority, u64)> = BTreeMap::new();
        crate::kernel::smp::for_each_percpu_scheduler(|_cpu_id, sched| {
            sched.collect_thread_stats(&mut thread_stats);
        });
        // Also collect from local scheduler (handles single-CPU fallback).
        self.collect_thread_stats(&mut thread_stats);

        self.processes
            .lock()
            .iter()
            .map(|process| {
                let pid = process.pid();
                let stats = thread_stats.get(&pid);
                ProcessSummary {
                    pid,
                    ppid: process.parent_pid(),
                    name: process.name(),
                    state: process.state(),
                    thread_count: process.thread_ids().len(),
                    priority: stats.map(|(pri, _)| *pri).unwrap_or_default(),
                    cpu_ticks: stats.map(|(_, ticks)| *ticks).unwrap_or(0),
                    is_kernel: process.security_token().is_system(),
                }
            })
            .collect()
    }

    /// Return summaries of all threads belonging to the given process.
    ///
    /// Threads are collected from ready queues, waiting queues, and the
    /// currently-running slot across all per-CPU schedulers.
    pub fn list_thread_summaries(&self, pid: ProcessId) -> Vec<ThreadSummary> {
        let mut threads: Vec<Arc<Thread>> = Vec::new();
        crate::kernel::smp::for_each_percpu_scheduler(|_cpu_id, sched| {
            sched.collect_thread_summaries_for_pid(pid, &mut threads);
        });
        // Also collect from local scheduler (handles single-CPU fallback).
        self.collect_thread_summaries_for_pid(pid, &mut threads);
        threads.iter().map(|t| t.summary()).collect()
    }

    /// Return the number of threads currently in the timed-waiting queue.
    ///
    /// Stale waiters (threads no longer in [`ThreadState::Waiting`]) are
    /// pruned before counting.
    pub fn waiting_count(&self) -> usize {
        let stale = {
            let mut waiting_queue = self.waiting_queue.lock();
            take_stale_timed_waiters(&mut waiting_queue)
        };
        remove_timed_waiters_from_wait_queues(stale);
        self.waiting_queue.lock().len()
    }

    /// Return a snapshot of the scheduler hotspot statistics
    /// (dispatch count, block count, preempt count, etc.).
    pub fn hotspot_stats(&self) -> SchedulerHotspotStats {
        *self.hotspot_stats.lock()
    }

    /// Reset all hotspot statistics counters to zero.
    pub fn reset_hotspot_stats(&self) {
        *self.hotspot_stats.lock() = SchedulerHotspotStats::default();
    }

    /// Return a clone of the aggregate scheduler statistics
    /// (total ticks, context switches, load history).
    pub fn stats(&self) -> SchedulerStats {
        self.stats.lock().clone()
    }

    /// Reset all aggregate scheduler statistics to their initial values.
    pub fn reset_stats(&self) {
        *self.stats.lock() = SchedulerStats::new();
    }

    /// Look up a registered process by its PID.
    ///
    /// Returns `None` if no process with the given PID is found.
    pub fn process_by_pid(&self, pid: u32) -> Option<Arc<Process>> {
        self.processes
            .lock()
            .iter()
            .find(|process| process.pid() == pid)
            .cloned()
    }

    /// Find a thread by its TID, scanning the ready queues, waiting queue,
    /// and current thread slot.
    pub fn find_thread_by_tid(&self, tid: ThreadId) -> Option<Arc<Thread>> {
        // Check ready queues.
        {
            let ready = self.ready_queues.lock();
            for queue in ready.iter() {
                for t in queue.iter() {
                    if t.tid() == tid {
                        return Some(t.clone());
                    }
                }
            }
        }
        // Check waiting queue.
        {
            let waiting = self.waiting_queue.lock();
            for w in waiting.iter() {
                if w.thread.tid() == tid {
                    return Some(w.thread.clone());
                }
            }
        }
        // Check current thread.
        if let Some(current) = self.current_thread() {
            if current.tid() == tid {
                return Some(current);
            }
        }
        None
    }

    /// Reap a terminated process, returning its exit status.
    ///
    /// Removes the process from the parent's children list and from the
    /// scheduler's process registry.  The process's PID becomes available
    /// for reuse (PID 1 is reserved).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not registered.
    /// Returns an error from [`Process::reap_termination_reason`] if the
    /// process has not yet terminated.
    pub fn reap_process(&self, pid: u32) -> crate::Result<Option<TerminationReason>> {
        // Processes are registered only in the primary (BSP) scheduler.
        let primary = self.primary_scheduler();
        let process = primary.process_by_pid(pid).ok_or(crate::Error::NotFound)?;

        let reason = process.reap_termination_reason()?;

        // Remove this process from its parent's children list.
        if let Some(parent_pid) = process.parent_pid() {
            if let Some(parent) = primary.process_by_pid(parent_pid) {
                parent.remove_child(pid);
            }
        }

        primary
            .processes
            .lock()
            .retain(|process| process.pid() != pid);
        // Drop the deferred user address space (page tables, ASID) now that
        // interrupts are enabled and the heap allocator can safely free them.
        process.clear_deferred_user_address_space();
        // Recycle the PID for future allocation, but keep PID 1 reserved
        // (typically belonging to init/idle).
        if pid != 1 {
            primary.freed_pids.lock().push(pid);
        }
        Ok(reason)
    }

    pub(crate) fn primary_scheduler(&self) -> &Self {
        crate::kernel::smp::get_percpu_scheduler(0).unwrap_or(self)
    }

    /// Deliver a signal to a process.
    ///
    /// The signal is enqueued on the target process' pending-signal queue.
    /// Delivery is asynchronous — the target thread picks up the signal
    /// at the next interrupt or syscall return.
    ///
    /// # Parameters
    ///
    /// * `sender_pid` — PID of the sending process (can be 0 for kernel).
    /// * `pid` — target process PID.
    /// * `signal` — signal number (e.g. [`SIGCHLD`]).
    /// * `payload` — optional payload (interpretation is signal-specific).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the target PID is not registered.
    pub fn send_signal(
        &self,
        sender_pid: u32,
        pid: u32,
        signal: usize,
        payload: usize,
    ) -> crate::Result<()> {
        // Processes are registered only in the primary (BSP) scheduler.
        let primary = self.primary_scheduler();
        let process = primary.process_by_pid(pid).ok_or(crate::Error::NotFound)?;
        process.enqueue_signal(sender_pid, signal, payload)
    }

    /// Stop (suspend) all threads belonging to the given process.
    ///
    /// Scans ready queues, waiting queues, and the current-thread slot
    /// across all per-CPU schedulers.  Returns the number of threads
    /// that were stopped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not registered.
    pub fn stop_process(&self, pid: u32) -> crate::Result<u32> {
        // Processes are registered only in the primary (BSP) scheduler.
        let primary = self.primary_scheduler();
        let process = primary.process_by_pid(pid).ok_or(crate::Error::NotFound)?;
        let mut stopped: u32 = 0;
        // Scan all online CPUs' schedulers.
        crate::kernel::smp::for_each_percpu_scheduler(|_cpu_id, sched| {
            stopped += sched.stop_threads_of_process(&process);
        });
        // If no per-CPU schedulers are registered (single-CPU), scan local.
        if crate::kernel::smp::online_cpu_count() <= 1 {
            stopped += self.stop_threads_of_process(&process);
        }
        Ok(stopped)
    }

    /// Resume (continue) all stopped threads belonging to the given process.
    ///
    /// Scans ready queues, waiting queues, and the current-thread slot
    /// across all per-CPU schedulers.  Returns the number of threads
    /// that were resumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not registered.
    pub fn continue_process(&self, pid: u32) -> crate::Result<u32> {
        // Processes are registered only in the primary (BSP) scheduler.
        let primary = self.primary_scheduler();
        let process = primary.process_by_pid(pid).ok_or(crate::Error::NotFound)?;
        let mut resumed: u32 = 0;
        // Scan all online CPUs' schedulers.
        crate::kernel::smp::for_each_percpu_scheduler(|_cpu_id, sched| {
            resumed += sched.continue_threads_of_process(&process);
        });
        // If no per-CPU schedulers are registered (single-CPU), scan local.
        if crate::kernel::smp::online_cpu_count() <= 1 {
            resumed += self.continue_threads_of_process(&process);
        }
        Ok(resumed)
    }
}
