//! src/kernel/process/scheduler/spawn.rs
//!
//! Thread spawning, registration, and public spawn API.
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::kernel::sync::wait::WaiterIdentity;

use super::super::{Process, ProcessState, SecurityToken, Thread, UserThreadStart};

use super::queue::*;
use super::Scheduler;

impl Scheduler {
    pub(crate) fn register_spawned_thread(
        &self,
        process: Arc<Process>,
        thread: Arc<Thread>,
        start_suspended: bool,
    ) -> Arc<Thread> {
        // Assign CPU affinity round-robin across all online CPUs.
        let cpu_count = crate::kernel::smp::online_cpu_count();
        let target_cpu = if cpu_count > 1 {
            let cpu = self.next_cpu.fetch_add(1, Ordering::Relaxed) % cpu_count;
            thread.set_cpu_affinity(cpu);
            cpu
        } else {
            0
        };
        // Register the process in the primary (BSP, CPU 0) scheduler's
        // process list.  Per-CPU schedulers do not maintain their own process
        // registries: process enumeration (`process_count`,
        // `list_process_summaries`, `select_oom_victim_by`, `reap_process`)
        // reads only the primary's list.  `Scheduler::global()` returns the
        // *local* per-CPU scheduler on bare metal, so pushing to `self` would
        // make a process spawned from a non-CPU0 syscall context invisible to
        // every process scan and leak it at teardown.
        self.primary_scheduler()
            .processes
            .lock()
            .push(process.clone());
        if start_suspended {
            // Keep the process in New state — it will be transitioned to
            // Ready and enqueued when the parent calls wait_process.
            process.store_suspended_thread(thread.clone());
            return thread;
        }
        // Enqueue the thread into its assigned CPU's ready queues.
        let enqueued =
            if let Some(target_sched) = crate::kernel::smp::get_percpu_scheduler(target_cpu) {
                target_sched.enqueue_ready_thread_local(thread.clone())
            } else {
                enqueue_ready_thread(&mut self.ready_queues.lock(), thread.clone())
            };
        if enqueued {
            // If a high-priority thread was just spawned, request reschedule
            // on the target CPU so it can preempt at the next safe point.
            if let Some(target_sched) = crate::kernel::smp::get_percpu_scheduler(target_cpu) {
                target_sched.maybe_set_need_resched_for(&thread);
            } else {
                self.maybe_set_need_resched(&thread);
            }
            // Send a reschedule IPI if the target CPU is not the current one.
            if target_cpu != crate::kernel::percpu::get().cpu_id {
                crate::kernel::smp::send_reschedule_ipi(target_cpu);
            }
        }
        thread
    }

    pub(crate) fn resume_suspended_process(&self, process: &Arc<Process>) {
        if process.state() != ProcessState::New {
            return;
        }
        process.set_state(ProcessState::Ready);
        // Retrieve the thread stored during the suspended spawn.
        if let Some(thread) = process.take_suspended_thread() {
            let target_cpu = thread.cpu_affinity();
            let enqueued =
                if let Some(target_sched) = crate::kernel::smp::get_percpu_scheduler(target_cpu) {
                    target_sched.enqueue_ready_thread_local(thread.clone())
                } else {
                    enqueue_ready_thread(&mut self.ready_queues.lock(), thread.clone())
                };
            if enqueued {
                if let Some(target_sched) = crate::kernel::smp::get_percpu_scheduler(target_cpu) {
                    target_sched.maybe_set_need_resched_for(&thread);
                } else {
                    self.maybe_set_need_resched(&thread);
                }
            }
        }
    }

    pub(crate) fn maybe_set_need_resched(&self, thread: &Thread) {
        if let Some(current) = self.current.lock().as_ref() {
            if thread.priority() > current.priority() {
                self.need_resched.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Request a reschedule on the current CPU at the next safe preemption
    /// point.
    ///
    /// Safe to call from any context (interrupt, syscall, or idle).  The
    /// scheduler will check the flag at the next tick boundary or kernel-exit
    /// and yield the CPU to the highest-priority ready thread.
    pub fn set_need_resched(&self) {
        self.need_resched.store(true, Ordering::Relaxed);
    }

    pub(crate) fn enqueue_ready_thread_local(&self, thread: Arc<Thread>) -> bool {
        enqueue_ready_thread(&mut self.ready_queues.lock(), thread)
    }

    pub(crate) fn remove_timed_waiter_for(&self, identity: WaiterIdentity) {
        self.remove_timed_waiter(identity);
    }

    pub(crate) fn maybe_set_need_resched_for(&self, thread: &Thread) {
        self.maybe_set_need_resched(thread);
    }

    pub(crate) fn stop_threads_of_process(&self, process: &super::Process) -> u32 {
        let process_ptr = process as *const super::Process;
        let mut stopped: u32 = 0;
        // Ready queues.
        {
            let mut ready = self.ready_queues.lock();
            for queue in ready.iter_mut() {
                queue.retain(|t| {
                    if core::ptr::eq(Arc::as_ptr(t.process()), process_ptr) {
                        t.suspend();
                        stopped += 1;
                        false
                    } else {
                        true
                    }
                });
            }
        }
        // Waiting queue.
        //
        // Collect the timed waiters to stop under the waiting_queue lock, but
        // defer the WaitQueue cleanup and wake until after the lock is
        // released: the timed-blocking path
        // (`block_current_until_if_with_timeout_cleanup`) holds the underlying
        // WaitQueue inner lock while registering the timed waiter on this same
        // scheduler waiting_queue, so calling `cleanup.remove_waiter` (which
        // re-acquires that WaitQueue inner lock) while still holding the
        // waiting_queue lock would be an AB-BA inversion that can deadlock on
        // SMP (wake_ready_threads likewise drops the waiting_queue lock before
        // any remove_waiter call for the same reason).
        let mut stopped_waiters: Vec<super::types::TimedWaiter> = Vec::new();
        {
            let mut waiting = self.waiting_queue.lock();
            let mut i = 0;
            while i < waiting.len() {
                if core::ptr::eq(Arc::as_ptr(waiting[i].thread.process()), process_ptr) {
                    waiting[i].thread.suspend();
                    stopped += 1;
                    stopped_waiters.push(waiting.remove(i));
                } else {
                    i += 1;
                }
            }
        }
        for waiter in stopped_waiters {
            // The timed waiter is no longer in the scheduler's waiting queue,
            // so wake_ready_threads will never process it again.  Mirror the
            // normal timeout-wake path: deregister it from the underlying wait
            // queue and force the stop-pending wake so the thread is not
            // orphaned in the Waiting state (leaking its kernel stack and
            // blocking the scheduler's view).
            if let Some(cleanup) = &waiter.cleanup {
                cleanup.remove_waiter(WaiterIdentity::from_thread(&waiter.thread));
            }
            let _ = waiter.thread.wake_by_timeout();
        }
        // Current thread.
        if let Some(current) = self.current_thread() {
            if core::ptr::eq(Arc::as_ptr(current.process()), process_ptr) {
                current.suspend();
                stopped += 1;
                // Do not clear the current slot here: on bare metal the thread
                // is still executing on this CPU's stack, so emptying the slot
                // would let the scheduler double-dispatch or lose track of it.
                // Leave the slot intact; the normal context-switch-out paths
                // (preempt / yield / block) vacate it once the thread leaves
                // the CPU.
            }
        }
        stopped
    }

    /// Terminate every scheduler-visible thread of `process` that is not
    /// currently executing.
    ///
    /// Ready and waiting threads are terminated immediately — they are not
    /// running, so releasing their process resources from this context is
    /// safe.  A thread currently running on this CPU is only flagged to
    /// self-terminate at its next scheduler boundary, because terminating
    /// it here would tear down the process's resources while the thread is
    /// still executing on this CPU's stack.  This is the remote half of a
    /// SIGKILL default action.
    pub(crate) fn terminate_threads_of_process(
        &self,
        process: &Process,
    ) -> super::types::ProcessTerminateScan {
        let process_ptr = process as *const Process;
        let mut running_present = false;

        // Ready and waiting threads are collected under their queue locks and
        // terminated only after both locks are released.  `Thread::terminate`
        // signals the thread's termination event, which wakes join() waiters
        // via `wake_thread` → `enqueue_ready_thread` — a re-entrant lock on
        // ready_queues that would self-deadlock if called while the guard is
        // held (same reasoning as `terminate_sibling_threads`).
        let mut to_terminate: Vec<Arc<Thread>> = Vec::new();

        // Ready queues.
        {
            let mut ready = self.ready_queues.lock();
            for queue in ready.iter_mut() {
                queue.retain(|t| {
                    if core::ptr::eq(Arc::as_ptr(t.process()), process_ptr) {
                        to_terminate.push(t.clone());
                        false
                    } else {
                        true
                    }
                });
            }
        }

        // Waiting queue.  Collect the timed waiters under the waiting_queue
        // lock, then deregister + terminate after it is released so the
        // WaitQueue cleanup (which re-acquires queue inner locks) cannot AB-BA
        // invert with the waiting_queue lock (same reason
        // `stop_threads_of_process` defers its wake).
        let mut terminated_waiters: Vec<super::types::TimedWaiter> = Vec::new();
        {
            let mut waiting = self.waiting_queue.lock();
            let mut i = 0;
            while i < waiting.len() {
                if core::ptr::eq(Arc::as_ptr(waiting[i].thread.process()), process_ptr) {
                    terminated_waiters.push(waiting.remove(i));
                } else {
                    i += 1;
                }
            }
        }
        for waiter in terminated_waiters {
            // Deregister the timed waiter so the scheduler does not keep
            // tracking an orphaned entry, then terminate it.  `wake_by_timeout`
            // is a harmless no-op on a terminated thread.
            if let Some(cleanup) = &waiter.cleanup {
                cleanup.remove_waiter(WaiterIdentity::from_thread(&waiter.thread));
            }
            to_terminate.push(waiter.thread);
        }
        for thread in to_terminate {
            thread.terminate();
        }

        // Current (running) thread: flag it; it self-terminates when it next
        // leaves the CPU or is rescheduled.
        if let Some(current) = self.current_thread() {
            if core::ptr::eq(Arc::as_ptr(current.process()), process_ptr) {
                current.request_termination();
                running_present = true;
            }
        }

        super::types::ProcessTerminateScan { running_present }
    }

    pub(crate) fn continue_threads_of_process(&self, process: &super::Process) -> u32 {
        let process_ptr = process as *const super::Process;
        let mut resumed: u32 = 0;
        // Ready queues.
        {
            let ready = self.ready_queues.lock();
            for queue in ready.iter() {
                for t in queue.iter() {
                    if core::ptr::eq(Arc::as_ptr(t.process()), process_ptr) && t.is_stopped() {
                        t.resume();
                        resumed += 1;
                    }
                }
            }
        }
        // Waiting queue.
        {
            let waiting = self.waiting_queue.lock();
            for w in waiting.iter() {
                if core::ptr::eq(Arc::as_ptr(w.thread.process()), process_ptr)
                    && w.thread.is_stopped()
                {
                    w.thread.resume();
                    resumed += 1;
                }
            }
        }
        // Current thread.
        if let Some(current) = self.current_thread() {
            if core::ptr::eq(Arc::as_ptr(current.process()), process_ptr) && current.is_stopped() {
                current.resume();
                resumed += 1;
            }
        }
        resumed
    }

    pub(crate) fn collect_thread_stats(
        &self,
        stats: &mut alloc::collections::BTreeMap<super::ProcessId, (super::ThreadPriority, u64)>,
    ) {
        let ready = self.ready_queues.lock();
        for queue in ready.iter() {
            for t in queue.iter() {
                let pid = t.pid();
                let pri = t.priority();
                let ticks = t.cpu_ticks();
                stats
                    .entry(pid)
                    .and_modify(|(max_pri, total)| {
                        if pri > *max_pri {
                            *max_pri = pri;
                        }
                        *total += ticks;
                    })
                    .or_insert((pri, ticks));
            }
        }
        drop(ready);

        let waiting = self.waiting_queue.lock();
        for tw in waiting.iter() {
            let t = &tw.thread;
            let pid = t.pid();
            let pri = t.priority();
            let ticks = t.cpu_ticks();
            stats
                .entry(pid)
                .and_modify(|(max_pri, total)| {
                    if pri > *max_pri {
                        *max_pri = pri;
                    }
                    *total += ticks;
                })
                .or_insert((pri, ticks));
        }
        drop(waiting);

        if let Some(current) = self.current.lock().as_ref() {
            let pid = current.pid();
            let pri = current.priority();
            let ticks = current.cpu_ticks();
            stats
                .entry(pid)
                .and_modify(|(max_pri, total)| {
                    if pri > *max_pri {
                        *max_pri = pri;
                    }
                    *total += ticks;
                })
                .or_insert((pri, ticks));
        }
    }

    pub(crate) fn collect_thread_summaries_for_pid(
        &self,
        pid: super::ProcessId,
        threads: &mut Vec<Arc<Thread>>,
    ) {
        let ready = self.ready_queues.lock();
        for queue in ready.iter() {
            for t in queue.iter() {
                if t.pid() == pid {
                    threads.push(t.clone());
                }
            }
        }
        drop(ready);

        let waiting = self.waiting_queue.lock();
        for tw in waiting.iter() {
            if tw.thread.pid() == pid {
                threads.push(tw.thread.clone());
            }
        }
        drop(waiting);

        if let Some(current) = self.current.lock().as_ref() {
            if current.pid() == pid {
                threads.push(current.clone());
            }
        }
    }

    /// Create a new process in the Ready state (registered when its first
    /// thread is spawned via [`register_spawned_thread`]).
    pub(crate) fn create_ready_process(&self, name: &str) -> Arc<Process> {
        let process =
            Process::new_with_security_token(self.allocate_pid(), name, SecurityToken::system());
        process.set_state(ProcessState::Ready);
        process
    }

    /// Create a new process in the Ready state with the given security token.
    pub(crate) fn create_ready_process_with_security_token(
        &self,
        name: &str,
        security_token: SecurityToken,
    ) -> Arc<Process> {
        let process = Process::new_with_security_token(self.allocate_pid(), name, security_token);
        process.set_state(ProcessState::Ready);
        process
    }

    pub(crate) fn spawn_ready_thread<F>(&self, name: &str, build: F) -> Arc<Thread>
    where
        F: FnOnce(&Arc<Process>) -> Arc<Thread>,
    {
        let process = self.create_ready_process(name);
        let thread = build(&process);
        self.register_spawned_thread(process, thread, false)
    }

    pub(crate) fn spawn_ready_thread_with_security_token<F>(
        &self,
        name: &str,
        security_token: SecurityToken,
        build: F,
    ) -> Arc<Thread>
    where
        F: FnOnce(&Arc<Process>) -> Arc<Thread>,
    {
        let process = self.create_ready_process_with_security_token(name, security_token);
        let thread = build(&process);
        self.register_spawned_thread(process, thread, false)
    }

    pub(crate) fn spawn_ready_thread_with_security_token_and_setup<F, G>(
        &self,
        name: &str,
        security_token: SecurityToken,
        build: F,
        setup: G,
        start_suspended: bool,
    ) -> Arc<Thread>
    where
        F: FnOnce(&Arc<Process>) -> Arc<Thread>,
        G: FnOnce(&Arc<Process>),
    {
        let process = if start_suspended {
            // Create the process in New state (not Ready) so it won't be
            // dispatched until explicitly resumed.
            Process::new_with_security_token(self.allocate_pid(), name, security_token)
        } else {
            self.create_ready_process_with_security_token(name, security_token)
        };
        let thread = build(&process);
        setup(&process);
        self.register_spawned_thread(process, thread, start_suspended)
    }

    /// Spawn a named kernel thread with the given entry point.
    ///
    /// Host-side only; on bare-metal use [`spawn_kernel_named`].
    #[cfg(not(target_os = "none"))]
    pub fn spawn_named(&self, name: &str, entry_point: usize) -> Arc<Thread> {
        self.spawn_ready_thread(name, |process| Thread::new(process.clone(), entry_point))
    }

    /// Spawn a named kernel thread with a security token.
    ///
    /// Host-side only; on bare-metal use
    /// [`spawn_kernel_named_with_security_token`].
    #[cfg(not(target_os = "none"))]
    pub fn spawn_named_with_security_token(
        &self,
        name: &str,
        security_token: SecurityToken,
        entry_point: usize,
    ) -> Arc<Thread> {
        self.spawn_ready_thread_with_security_token(name, security_token, |process| {
            Thread::new(process.clone(), entry_point)
        })
    }

    /// Spawn a named kernel-mode thread with the given entry function.
    ///
    /// The thread runs in ring 0 (supervisor mode) and shares the kernel
    /// address space.
    pub fn spawn_kernel_named(&self, name: &str, entry: fn()) -> Arc<Thread> {
        self.spawn_ready_thread(name, |process| Thread::new_kernel(process.clone(), entry))
    }

    /// Spawn a named kernel-mode thread with an explicit [`SecurityToken`].
    ///
    /// The thread runs in ring 0 and shares the kernel address space.
    pub fn spawn_kernel_named_with_security_token(
        &self,
        name: &str,
        security_token: SecurityToken,
        entry: fn(),
    ) -> Arc<Thread> {
        self.spawn_ready_thread_with_security_token(name, security_token, |process| {
            Thread::new_kernel(process.clone(), entry)
        })
    }

    /// Only used by the host / demo-disk program-spawn paths; unused on plain
    /// bare-metal builds (kept as a public kernel spawn primitive).
    #[allow(dead_code)]
    pub(crate) fn spawn_kernel_named_with_security_token_and_setup<F>(
        &self,
        name: &str,
        security_token: SecurityToken,
        entry: fn(),
        setup: F,
    ) -> Arc<Thread>
    where
        F: FnOnce(&Arc<Process>),
    {
        self.spawn_ready_thread_with_security_token_and_setup(
            name,
            security_token,
            |process| Thread::new_kernel(process.clone(), entry),
            setup,
            false,
        )
    }

    /// Spawn a named user-mode thread with the given [`UserThreadStart`]
    /// descriptor.  Panics if the start descriptor is invalid.
    ///
    /// The thread runs in ring 3 with its own user address space.
    pub fn spawn_user_named(&self, name: &str, start: UserThreadStart) -> Arc<Thread> {
        self.try_spawn_user_named(name, start)
            .expect("invalid user thread start")
    }

    /// Spawn a named user-mode thread with a security token and
    /// [`UserThreadStart`] descriptor.  Panics if the start descriptor is
    /// invalid.
    pub fn spawn_user_named_with_security_token(
        &self,
        name: &str,
        security_token: SecurityToken,
        start: UserThreadStart,
    ) -> Arc<Thread> {
        self.try_spawn_user_named_with_security_token(name, security_token, start)
            .expect("invalid user thread start")
    }

    /// Try to spawn a named user-mode thread, returning an error if the
    /// [`UserThreadStart`] descriptor fails validation.
    pub fn try_spawn_user_named(
        &self,
        name: &str,
        start: UserThreadStart,
    ) -> crate::Result<Arc<Thread>> {
        self.try_spawn_user_named_with_security_token(name, SecurityToken::system(), start)
    }

    /// Try to spawn a named user-mode thread with a security token, returning
    /// an error if the [`UserThreadStart`] descriptor fails validation.
    pub fn try_spawn_user_named_with_security_token(
        &self,
        name: &str,
        security_token: SecurityToken,
        start: UserThreadStart,
    ) -> crate::Result<Arc<Thread>> {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
        let start = start.validate()?;

        Ok(
            self.spawn_ready_thread_with_security_token(name, security_token, |process| {
                Thread::try_new_user(process.clone(), start)
                    .expect("validated user thread start should construct")
            }),
        )
    }

    #[cfg(target_os = "none")]
    pub(crate) fn try_spawn_user_named_with_security_token_and_setup<F>(
        &self,
        name: &str,
        security_token: SecurityToken,
        start: UserThreadStart,
        setup: F,
        start_suspended: bool,
    ) -> crate::Result<Arc<Thread>>
    where
        F: FnOnce(&Arc<Process>),
    {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
        let start = start.validate()?;

        Ok(self.spawn_ready_thread_with_security_token_and_setup(
            name,
            security_token,
            |process| {
                Thread::try_new_user(process.clone(), start)
                    .expect("validated user thread start should construct")
            },
            setup,
            start_suspended,
        ))
    }

    /// Convenience spawn for host-side testing: creates a kernel thread named
    /// `"init"` with the given entry point.
    #[cfg(not(target_os = "none"))]
    pub fn spawn(&self, entry_point: usize) -> Arc<Thread> {
        self.spawn_named("init", entry_point)
    }
}
