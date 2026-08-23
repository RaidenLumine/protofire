//! src/kernel/process/thread/lifecycle.rs
//! Thread lifecycle: constructors, accessors, scheduling, termination,
//! suspend/resume, context save/restore, and arch-specific run_entry +
//! exception delivery.

use ::core::sync::atomic::AtomicBool;
use ::core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use alloc::sync::Arc;

use crate::kernel::process::scheduler::TIME_SLICE_TICKS;
use crate::kernel::sync::{Event, Mutex};
#[cfg(any(target_arch = "riscv64", test))]
use crate::Error;
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    test
))]
use crate::Result;

#[cfg(any(target_arch = "aarch64", test))]
use super::arch_aarch64::{
    AArch64PendingExceptionFrameStack, AArch64UserThreadContext, AARCH64_EXCEPTION_VECTOR_COUNT,
};

#[cfg(target_arch = "x86_64")]
use super::arch_x86_64::{
    X86_64PendingExceptionFrameStack, X86_64UserThreadContext, X86_64_EXCEPTION_VECTOR_COUNT,
};

use super::super::{Context, ContextCell, Process, ProcessId, ProcessState, TerminationReason};

#[cfg(any(target_arch = "riscv64", test))]
use super::arch_riscv64::RiscV64UserThreadContext;
use super::constants::*;
use super::kernel_stack::KernelStack;
use super::types::{
    ThreadExecutionState, ThreadPriority, ThreadSchedPolicy, ThreadSchedStats, ThreadState,
    ThreadSummary, ThreadWaitOutcome, UserThreadStart,
};
use super::Thread;

#[cfg(target_os = "none")]
pub(crate) fn should_enter_user_mode(user_start_present: bool, user_context_present: bool) -> bool {
    user_start_present && user_context_present
}

impl Thread {
    // Host-side scheduler tests model threads with placeholder instruction
    // pointers that are never executed through the bare-metal trampoline.
    #[cfg(not(target_os = "none"))]
    /// Create a new host-side test thread with the given entry point.
    /// Only available in non-bare-metal builds.
    pub fn new(process: Arc<Process>, entry_point: usize) -> Arc<Self> {
        Self::new_inner(process, entry_point, None, None)
    }

    /// Create a new kernel thread that executes `entry`.
    ///
    /// Kernel threads share the kernel address space and never enter user mode.
    pub fn new_kernel(process: Arc<Process>, entry: fn()) -> Arc<Self> {
        Self::new_inner(process, entry as *const () as usize, Some(entry), None)
    }

    /// Convenience wrapper around [`try_new_user`](Self::try_new_user) for test
    /// code.  Panics on invalid start addresses; production callers must use
    /// [`try_new_user`](Self::try_new_user) and handle the error.
    pub fn new_user(process: Arc<Process>, start: UserThreadStart) -> Arc<Self> {
        Self::try_new_user(process, start).expect("invalid user thread start")
    }

    /// Try to create a user thread.  Validates the start address; returns
    /// an error if the instruction pointer is outside userspace.
    pub(crate) fn try_new_user(process: Arc<Process>, start: UserThreadStart) -> Result<Arc<Self>> {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
        let start = start.validate()?;
        Ok(Self::new_inner(
            process,
            start.instruction_pointer,
            None,
            Some(start),
        ))
    }

    /// Create a user thread for a fork child, seeding the full
    /// [`X86_64UserThreadContext`] so the child resumes with the same
    /// register state as the parent (except RAX, which callers set to 0).
    #[cfg(target_arch = "x86_64")]
    pub fn new_user_fork(
        process: Arc<Process>,
        context: X86_64UserThreadContext,
    ) -> Result<Arc<Self>> {
        let start = UserThreadStart::new(
            context.instruction_pointer as usize,
            context.stack_pointer as usize,
            None::<usize>,
        );
        let start = start.validate()?;
        let thread = Self::new_inner(process, start.instruction_pointer, None, Some(start));
        // Overwrite the user context with the full fork context (which
        // includes preserved register values like RBX, RCX, etc.).
        *thread.x86_64_user_context.lock() = Some(context);
        Ok(thread)
    }

    /// Create a user thread for a fork child, seeding the full
    /// [`AArch64UserThreadContext`] so the child resumes with the same
    /// register state as the parent (except x0, which callers set to 0).
    ///
    /// Only compiled on bare-metal AArch64 — tested via the fork syscall
    /// integration path.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub fn new_user_fork(
        process: Arc<Process>,
        context: AArch64UserThreadContext,
    ) -> Result<Arc<Self>> {
        let start = UserThreadStart::new(
            context.instruction_pointer as usize,
            context.stack_pointer as usize,
            None::<usize>,
        );
        let start = start.validate()?;
        let thread = Self::new_inner(process, start.instruction_pointer, None, Some(start));
        // Overwrite the user context with the full fork context.
        #[cfg(any(target_arch = "aarch64", test))]
        thread.set_aarch64_user_context(context);
        Ok(thread)
    }

    /// Create a user thread for a fork child, seeding the full
    /// [`RiscV64UserThreadContext`] so the child resumes with the same
    /// register state as the parent (except a0, which callers set to 0).
    ///
    /// Only compiled on bare-metal RISC-V — tested via the fork syscall
    /// integration path.
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    pub fn new_user_fork(
        process: Arc<Process>,
        context: RiscV64UserThreadContext,
    ) -> Result<Arc<Self>> {
        let start = UserThreadStart::new(
            context.instruction_pointer as usize,
            context.x2 as usize,
            None::<usize>,
        );
        let start = start.validate()?;
        let thread = Self::new_inner(process, start.instruction_pointer, None, Some(start));
        // Overwrite the user context with the full fork context.
        #[cfg(any(target_arch = "riscv64", test))]
        thread.set_riscv64_user_context(context);
        Ok(thread)
    }

    fn new_inner(
        process: Arc<Process>,
        entry_point: usize,
        kernel_entry: Option<fn()>,
        user_start: Option<UserThreadStart>,
    ) -> Arc<Self> {
        let tid = process.allocate_tid();
        // Build an isolated kernel stack and seed context to the thread trampoline entry.
        let kernel_stack = KernelStack::new(KERNEL_STACK_GUARD_SIZE, DEFAULT_KERNEL_STACK_SIZE);
        let stack_top = kernel_stack.stack_top();
        let initial_stack_pointer = initialize_frame_kernel_stack(
            kernel_stack.stack_ptr(),
            kernel_stack.stack_len(),
            stack_top,
        );

        let mut context = Context::new(initial_instruction_pointer(entry_point, user_start));
        context.set_stack_pointer(initial_stack_pointer);
        #[cfg(any(target_arch = "aarch64", test))]
        let aarch64_user_context = user_start.map(AArch64UserThreadContext::from_start);
        #[cfg(target_arch = "x86_64")]
        let x86_64_user_context = user_start.map(X86_64UserThreadContext::from_start);
        #[cfg(any(target_arch = "riscv64", test))]
        let riscv64_user_context = user_start.map(RiscV64UserThreadContext::from_start);
        let execution_state = ThreadExecutionState {
            entry_point,
            kernel_entry,
            user_start,
            #[cfg(target_arch = "x86_64")]
            x86_64_exception_stack_pointer: user_start
                .and_then(|start| start.exception_stack_pointer),
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            _arch_exception_stack_pointer: user_start
                .and_then(|start| start.exception_stack_pointer),
        };

        let thread = Arc::new(Self {
            tid,
            process: process.clone(),
            execution_state: Mutex::new(execution_state),
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64_user_context: Mutex::new(aarch64_user_context),
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64_exception_handlers: Mutex::new([None; AARCH64_EXCEPTION_VECTOR_COUNT]),
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64_pending_exception_frames: Mutex::new(AArch64PendingExceptionFrameStack::new()),
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64_exception_preempt_resume_logged: AtomicBool::new(false),
            #[cfg(target_arch = "x86_64")]
            x86_64_user_context: Mutex::new(x86_64_user_context),
            #[cfg(target_arch = "x86_64")]
            x86_64_exception_handlers: Mutex::new([None; X86_64_EXCEPTION_VECTOR_COUNT]),
            #[cfg(target_arch = "x86_64")]
            x86_64_pending_exception_frames: Mutex::new(X86_64PendingExceptionFrameStack::new()),
            #[cfg(any(target_arch = "riscv64", test))]
            riscv64_user_context: Mutex::new(riscv64_user_context),
            priority: Mutex::new(ThreadPriority::default()),
            context: ContextCell::new(context),
            state: Mutex::new(ThreadState::Ready),
            termination_reason: Mutex::new(None),
            termination_event: Event::manual_reset(false),
            kernel_stack,
            switch_count: AtomicU64::new(0),
            cpu_ticks: AtomicU64::new(0),
            time_slice_remaining: AtomicU64::new(0),
            time_slice_ticks: AtomicU64::new(TIME_SLICE_TICKS),
            sched_policy: Mutex::new(ThreadSchedPolicy::default()),
            sched_stats: Mutex::new(ThreadSchedStats::default()),
            waiting_ticks: AtomicU64::new(0),
            last_wait_start: AtomicU64::new(0),
            wake_deadline: AtomicU64::new(0),
            wait_outcome: AtomicU8::new(ThreadWaitOutcome::Completed as u8),
            stop_pending: AtomicBool::new(false),
            cpu_affinity: AtomicU32::new(0),
            boosted: AtomicBool::new(false),
            active_address_space_generation: AtomicU64::new(0),
            canary: AtomicU64::new(0),
        });

        // If process registration fails (for example process already terminated),
        // terminate this freshly created thread instead of panicking.
        process
            .add_thread(tid)
            .unwrap_or_else(|_| thread.terminate());
        thread
    }

    /// Return the thread ID.
    pub fn tid(&self) -> ThreadId {
        self.tid
    }

    /// Return the process ID this thread belongs to.
    pub fn pid(&self) -> ProcessId {
        self.process.pid()
    }

    /// Return a reference to the [`Process`] this thread belongs to.
    pub fn process(&self) -> &Arc<Process> {
        &self.process
    }

    /// Return the address-space generation that was active when this thread
    /// last loaded the page-table root (CR3 / TTBR0_EL1), or 0 if the thread
    /// Record that this thread has activated the given address-space generation.
    #[cfg_attr(
        not(all(
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_os = "none"
        )),
        allow(dead_code)
    )]
    /// Record that this thread has activated the given address-space generation.
    ///
    /// Used by the page-fault handler to detect stale TLB entries.
    pub(crate) fn set_active_address_space_generation(&self, generation: u64) {
        self.active_address_space_generation
            .store(generation, Ordering::Release);
    }

    /// Push a fault record into the owning process's per-process fault ring
    /// buffer for post-mortem crash diagnosis.
    pub fn push_fault_record(
        &self,
        vector: u8,
        error_code: u64,
        fault_address: Option<usize>,
        instruction_pointer: u64,
        from_user_mode: bool,
    ) {
        self.process.push_fault_record(
            vector,
            error_code,
            fault_address,
            instruction_pointer,
            from_user_mode,
        );
    }

    /// Return the raw entry-point address (instruction pointer).
    pub fn entry_point(&self) -> usize {
        self.execution_state.lock().entry_point
    }

    #[cfg(target_os = "none")]
    /// Return the kernel entry function, if this is a kernel thread.
    pub(crate) fn kernel_entry(&self) -> Option<fn()> {
        self.execution_state.lock().kernel_entry
    }

    /// Return the user-space start parameters, if this is a user thread.
    pub fn user_start(&self) -> Option<UserThreadStart> {
        self.execution_state.lock().user_start
    }

    /// Return the current thread state (e.g. [`ThreadState::Ready`]).
    pub fn state(&self) -> ThreadState {
        *self.state.lock()
    }

    /// Return the thread's scheduling priority.
    pub fn priority(&self) -> ThreadPriority {
        *self.priority.lock()
    }

    /// Set the thread's scheduling priority.
    pub fn set_priority(&self, priority: ThreadPriority) {
        *self.priority.lock() = priority;
    }

    /// Return the thread's scheduling policy.
    pub fn sched_policy(&self) -> ThreadSchedPolicy {
        *self.sched_policy.lock()
    }

    /// Set the thread's scheduling policy.
    pub fn set_sched_policy(&self, policy: ThreadSchedPolicy) {
        *self.sched_policy.lock() = policy;
    }

    /// Preferred CPU for this thread (0 = any CPU, 1..N = specific CPU).
    /// The SMP scheduler uses this as a hint when choosing a run queue.
    pub fn cpu_affinity(&self) -> u32 {
        self.cpu_affinity.load(Ordering::Relaxed)
    }

    /// Pin this thread to a specific CPU.
    ///
    /// A value of `u32::MAX` removes the affinity pin.
    pub fn set_cpu_affinity(&self, cpu_id: u32) {
        self.cpu_affinity.store(cpu_id, Ordering::Relaxed);
    }

    /// Returns `true` when this thread was promoted to High priority by the
    /// scheduler's starvation-boost mechanism, rather than being a native
    /// High-priority thread.
    pub(crate) fn is_boosted(&self) -> bool {
        self.boosted.load(Ordering::Relaxed)
    }

    /// Mark this thread as boosted (set by the scheduler on promotion) or
    /// unboosted (on demotion back to Normal priority).
    pub(crate) fn set_boosted(&self, boosted: bool) {
        self.boosted.store(boosted, Ordering::Relaxed);
    }

    /// Per-thread time-slice quantum in ticks.  Defaults to the global
    /// [`TIME_SLICE_TICKS`] constant.  Minimum value is 1 tick.
    pub fn time_slice_ticks(&self) -> u64 {
        self.time_slice_ticks.load(Ordering::Relaxed)
    }

    /// Set a per-thread time-slice quantum in ticks.
    ///
    /// When the thread exhausts its slice it is preempted.
    pub fn set_time_slice_ticks(&self, ticks: u64) {
        let clamped = ticks.clamp(1, 20);
        self.time_slice_ticks.store(clamped, Ordering::Relaxed);
    }

    /// Snapshot of per-thread scheduling statistics.
    pub fn sched_stats(&self) -> ThreadSchedStats {
        *self.sched_stats.lock()
    }

    /// Increment the per-thread schedule dispatch counter.
    pub(crate) fn inc_schedule_count(&self) {
        let mut stats = self.sched_stats.lock();
        stats.schedule_count = stats.schedule_count.saturating_add(1);
    }

    /// Increment the per-thread preemption counter.
    pub(crate) fn inc_preempt_count(&self) {
        let mut stats = self.sched_stats.lock();
        stats.preempt_count = stats.preempt_count.saturating_add(1);
    }

    /// Add ticks to the per-thread total wait time.
    pub(crate) fn add_wait_ticks(&self, ticks: u64) {
        let mut stats = self.sched_stats.lock();
        stats.total_wait_ticks = stats.total_wait_ticks.saturating_add(ticks);
    }

    /// Return total CPU ticks consumed by this thread.
    pub fn cpu_ticks(&self) -> u64 {
        self.cpu_ticks.load(Ordering::Relaxed)
    }

    /// Return a diagnostic snapshot of this thread's key metrics.
    pub fn summary(&self) -> ThreadSummary {
        let sched_stats = self.sched_stats();
        ThreadSummary {
            tid: self.tid,
            priority: self.priority(),
            cpu_ticks: self.cpu_ticks(),
            state: self.state(),
            cpu_affinity: self.cpu_affinity(),
            schedule_count: sched_stats.schedule_count,
            preempt_count: sched_stats.preempt_count,
            total_wait_ticks: sched_stats.total_wait_ticks,
            time_slice_remaining: self.time_slice_remaining(),
            sched_policy: self.sched_policy(),
        }
    }

    /// Increment the CPU tick counter and return the new value.
    pub(crate) fn increment_cpu_ticks(&self) -> u64 {
        self.cpu_ticks.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Return the remaining ticks in the current time slice.
    pub(crate) fn time_slice_remaining(&self) -> u64 {
        self.time_slice_remaining.load(Ordering::Relaxed)
    }

    /// Set the remaining time-slice ticks.
    pub(crate) fn set_time_slice_remaining(&self, ticks: u64) {
        self.time_slice_remaining.store(ticks, Ordering::Relaxed);
    }

    /// Increment the waiting-ticks counter for hotspot profiling.
    pub(crate) fn inc_waiting_ticks(&self) -> u64 {
        self.waiting_ticks.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Reset the waiting-ticks counter to zero.
    pub(crate) fn reset_waiting_ticks(&self) {
        self.waiting_ticks.store(0, Ordering::Relaxed);
    }

    /// Return the termination reason if the thread has terminated.
    pub fn termination_reason(&self) -> Option<TerminationReason> {
        *self.termination_reason.lock()
    }

    /// Block the calling thread until this thread terminates.
    ///
    /// Returns `true` if the thread terminated, `false` if it was
    /// already in a terminal state.
    pub fn join(&self) -> bool {
        self.termination_event.wait()
    }

    /// Block the calling thread until this thread terminates or
    /// `timeout_ticks` elapses.
    pub fn join_timeout(&self, timeout_ticks: u64) -> bool {
        self.termination_event.wait_timeout(timeout_ticks)
    }

    /// Return the number of threads currently waiting for this thread
    /// to terminate.
    pub fn termination_waiter_count(&self) -> usize {
        self.termination_event.waiter_count()
    }

    /// Atomically set the thread state.
    ///
    /// Wakes waiters if the new state is a terminal state.
    pub fn set_state(&self, state: ThreadState) {
        *self.state.lock() = state;
    }

    fn set_process_and_thread_state(
        &self,
        process_state: ProcessState,
        thread_state: ThreadState,
    ) -> bool {
        // Stale ready/current entries must not revive an already terminated
        // thread or process when scheduler bookkeeping reaches them later.
        if self.state() == ThreadState::Terminated
            || self.process.state() == ProcessState::Terminated
        {
            return false;
        }

        self.process.set_state(process_state);
        self.set_state(thread_state);
        true
    }

    /// Save the current CPU context into the thread's context cell.
    pub fn save_context(&self) {
        self.switch_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Restore the thread's saved context into the CPU registers and
    /// resume execution.
    pub fn restore_context(&self) {
        let _ = self.set_process_and_thread_state(ProcessState::Running, ThreadState::Running);
    }

    /// Move the thread from [`ThreadState::Running`] back to
    /// [`ThreadState::Ready`], yielding the CPU.
    pub fn yield_back_to_ready(&self) {
        let _ = self.set_process_and_thread_state(ProcessState::Ready, ThreadState::Ready);
    }

    /// Terminate the thread with [`TerminationReason::Exited`].
    pub fn terminate(&self) {
        self.finish_termination(None);
    }

    /// Terminate the thread with the given reason.
    pub fn terminate_with_reason(&self, reason: TerminationReason) {
        self.finish_termination(Some(reason));
    }

    fn finish_termination(&self, reason: Option<TerminationReason>) {
        let mut state = self.state.lock();
        // Idempotent: repeated terminate calls should be a no-op.
        if *state == ThreadState::Terminated {
            return;
        }
        *state = ThreadState::Terminated;
        drop(state);
        // Clear user runtime state before notifying waiters/reaper.
        self.clear_user_runtime_state();
        *self.termination_reason.lock() = reason;
        let _ = self.process.finish_thread_termination(self.tid, reason);
        let _ = self.termination_event.signal();
        self.wake_deadline.store(0, Ordering::SeqCst);
        self.set_wait_outcome(ThreadWaitOutcome::Completed);
    }

    /// Block the calling thread until explicitly woken.
    ///
    /// The thread state transitions to [`ThreadState::Blocked`].
    pub fn block(&self) {
        self.enter_waiting_state(None);
    }

    /// Block the calling thread until explicitly woken or `wake_tick`
    /// elapses.
    pub fn block_until(&self, wake_tick: u64) {
        self.enter_waiting_state(Some(wake_tick));
    }

    fn enter_waiting_state(&self, wake_tick: Option<u64>) {
        if !self.set_process_and_thread_state(ProcessState::Waiting, ThreadState::Waiting) {
            return;
        }

        // Store deadline as +1 so zero can remain the "no deadline" sentinel.
        let encoded_deadline = wake_tick.map_or(0, |tick| tick.saturating_add(1));
        self.wake_deadline.store(encoded_deadline, Ordering::SeqCst);
        self.set_wait_outcome(ThreadWaitOutcome::Pending);
    }

    /// Wake the thread from a signal-induced wait.
    ///
    /// Returns `true` if the thread was actually waiting on a signal.
    pub fn wake_by_signal(&self) -> bool {
        self.wake_waiter(ThreadWaitOutcome::Completed)
    }

    /// Wake the thread from a timeout-induced wait.
    ///
    /// Returns `true` if the thread was actually waiting on a timeout.
    pub fn wake_by_timeout(&self) -> bool {
        self.wake_waiter(ThreadWaitOutcome::TimedOut)
    }

    /// Suspend the thread — transition to `Stopped`.
    ///
    /// If the thread is `Ready` or `Running`, it is suspended immediately.
    /// If the thread is `Waiting`, the `stop_pending` flag is set so that
    /// when it wakes it transitions to `Stopped` instead of `Ready`.
    ///
    /// Returns `true` if the suspend was accepted, `false` if the thread
    /// is already `Stopped` or `Terminated`.
    pub fn suspend(&self) -> bool {
        let mut state = self.state.lock();
        match *state {
            ThreadState::Ready | ThreadState::Running => {
                *state = ThreadState::Stopped;
                true
            }
            ThreadState::Waiting => {
                self.stop_pending.store(true, Ordering::Release);
                true
            }
            ThreadState::Stopped | ThreadState::Terminated => false,
        }
    }

    /// Resume a suspended thread — transition `Stopped` → `Ready`.
    ///
    /// Returns `true` on success, `false` if the thread is not `Stopped`.
    pub fn resume(&self) -> bool {
        self.set_process_and_thread_state(ProcessState::Ready, ThreadState::Ready)
    }

    /// Returns `true` if this thread is currently `Stopped`.
    pub fn is_stopped(&self) -> bool {
        matches!(*self.state.lock(), ThreadState::Stopped)
    }

    /// Return the absolute tick deadline when this blocked thread will
    /// automatically wake, or `None` if no timeout was set.
    ///
    /// The returned value reverses the +1 sentinel encoding used in
    /// [`block_until`](Self::block_until).
    pub fn wake_deadline(&self) -> Option<u64> {
        // Reverse the +1 sentinel encoding used in block_until.
        self.wake_deadline.load(Ordering::SeqCst).checked_sub(1)
    }

    /// Return a copy of the thread's saved CPU context (registers + stack
    /// pointer).
    pub fn context(&self) -> Context {
        self.context.get()
    }

    /// Return a raw mutable pointer to the thread's [`Context`] cell.
    ///
    /// Used by the scheduler to write the CPU state during a context switch.
    pub fn context_ptr(&self) -> *mut Context {
        self.context.as_mut_ptr()
    }

    /// When the saved stack pointer is within this many bytes of the stack
    /// bottom, the scheduler logs a warning.  This is a best-effort overflow
    /// detector — it does not *prevent* overflow like a real guard page.
    const KERNEL_STACK_LOW_WATERMARK: usize = 4096;

    /// Return `(bottom, top)` bounds of the kernel stack allocation.
    ///
    /// The stack grows downward from `top` toward `bottom`.  The range
    /// includes the unmapped guard page at the bottom.
    pub fn stack_bounds(&self) -> (usize, usize) {
        let bottom = self.kernel_stack.stack_ptr() as usize;
        (bottom, bottom + self.kernel_stack.stack_len())
    }

    /// Return the highest usable address on the kernel stack (the initial
    /// stack pointer value).
    pub fn kernel_stack_top(&self) -> usize {
        self.kernel_stack.stack_top()
    }

    /// Check whether the saved stack pointer has overflowed into the
    /// low-watermark region at the bottom of the kernel stack.
    ///
    /// Returns `true` when the stack is still safe (SP is above the
    /// watermark), `false` when the stack is dangerously deep.
    pub fn kernel_stack_usage_ok(&self) -> bool {
        let (bottom, top) = self.stack_bounds();
        let sp = self.context().stack_pointer;
        // The stack grows downward from `top` toward `bottom`.  If the
        // saved SP is not within the stack allocation at all we treat
        // it as suspicious and log, but we still return true to avoid
        // a false-positive panic.
        if sp < bottom || sp > top {
            return true;
        }

        sp.saturating_sub(bottom) >= Self::KERNEL_STACK_LOW_WATERMARK
    }

    /// Return the number of times this thread has been context-switched
    /// (saved + restored combined).
    pub fn switch_count(&self) -> u64 {
        self.switch_count.load(Ordering::Relaxed)
    }

    /// Return the outcome of the last wait operation.
    ///
    /// [`ThreadWaitOutcome::Pending`] while waiting, [`Completed`] after
    /// normal wake, [`TimedOut`] when the deadline expired.
    ///
    /// [`Completed`]: ThreadWaitOutcome::Completed
    /// [`TimedOut`]: ThreadWaitOutcome::TimedOut
    pub fn wait_outcome(&self) -> ThreadWaitOutcome {
        match self.wait_outcome.load(Ordering::SeqCst) {
            0 => ThreadWaitOutcome::Pending,
            2 => ThreadWaitOutcome::TimedOut,
            _ => ThreadWaitOutcome::Completed,
        }
    }

    pub(crate) fn set_wait_outcome(&self, outcome: ThreadWaitOutcome) {
        self.wait_outcome.store(outcome as u8, Ordering::SeqCst);
    }

    fn wake_waiter(&self, outcome: ThreadWaitOutcome) -> bool {
        if self.state() != ThreadState::Waiting {
            return false;
        }

        // If a stop was requested while waiting, transition to Stopped
        // instead of Ready.
        if self.stop_pending.swap(false, Ordering::AcqRel) {
            self.process.set_state(ProcessState::Ready);
            *self.state.lock() = ThreadState::Stopped;
            self.wake_deadline.store(0, Ordering::SeqCst);
            self.set_wait_outcome(outcome);
            return true;
        }

        if !self.set_process_and_thread_state(ProcessState::Ready, ThreadState::Ready) {
            return false;
        }

        self.wake_deadline.store(0, Ordering::SeqCst);
        self.set_wait_outcome(outcome);
        true
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    /// Entry trampoline for RISC-V user threads.  Validates the user context,
    /// switches to U-mode if the thread has a valid `UserThreadStart`, or
    /// calls the kernel entry function for pure kernel threads.
    ///
    /// Called by the scheduler when this thread is dispatched.
    pub fn run_entry(&self) {
        let user_start_present = self.user_start().is_some();
        let user_context = match self.validated_riscv64_user_context() {
            Ok(user_context) => user_context,
            Err(_) => {
                crate::println!(
                    "[user  ] invalid riscv64 user context before U-mode entry pid={} tid={}",
                    self.pid(),
                    self.tid()
                );
                return;
            }
        };

        if user_start_present && user_context.is_none() {
            crate::println!(
                "[user  ] missing riscv64 user context before first U-mode entry pid={} tid={}",
                self.pid(),
                self.tid()
            );
            return;
        }

        if should_enter_user_mode(user_start_present, user_context.is_some()) {
            let Some(context) = user_context else {
                return;
            };
            unsafe {
                crate::arch::riscv64::context::enter_user_mode_with_context(&context);
            }
        }

        let Some(entry) = self.kernel_entry() else {
            crate::println!(
                "[sched ] refusing to run thread with untyped kernel entry pid={} tid={} entry=0x{:x}",
                self.pid(),
                self.tid(),
                self.entry_point()
            );
            return;
        };
        crate::arch::interrupts::enable();
        entry();
    }

    #[cfg_attr(
        not(any(target_arch = "x86_64", target_arch = "aarch64")),
        allow(unused_variables)
    )]
    pub(crate) fn install_user_exception_handler(
        &self,
        vector: u8,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        let result =
            self.install_x86_64_exception_handler_with(vector, handler, stack_pointer, flags);

        #[cfg(target_arch = "aarch64")]
        let result =
            self.install_aarch64_exception_handler_with(vector, handler, stack_pointer, flags);

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let result = Err(Error::Unsupported);

        result
    }

    #[cfg(any(target_arch = "riscv64", test))]
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    /// Return the saved RISC-V user thread context (PC + GPRs), or `None` if
    /// this thread has never entered user mode.
    pub fn riscv64_user_context(&self) -> Option<RiscV64UserThreadContext> {
        *self.riscv64_user_context.lock()
    }

    #[cfg(any(target_arch = "riscv64", test))]
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub(crate) fn validated_riscv64_user_context(
        &self,
    ) -> Result<Option<RiscV64UserThreadContext>> {
        self.riscv64_user_context()
            .map(|context| {
                context
                    .validate_runtime_state()
                    .map_err(|_| Error::InternalError)
            })
            .transpose()
    }

    #[cfg(any(target_arch = "riscv64", test))]
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    pub(crate) fn set_riscv64_user_context(&self, context: RiscV64UserThreadContext) {
        *self.riscv64_user_context.lock() = Some(context);
    }

    #[cfg(any(target_arch = "riscv64", test))]
    #[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
    fn update_riscv64_user_context_if_valid(&self, context: RiscV64UserThreadContext) -> bool {
        let Ok(context) = context.validate_runtime_state() else {
            return false;
        };
        self.set_riscv64_user_context(context);
        true
    }

    #[cfg(target_arch = "riscv64")]
    pub(crate) fn capture_riscv64_user_context_from_trap(
        &self,
        frame: &crate::arch::riscv64::trap::TrapFrame,
    ) {
        let _ =
            self.update_riscv64_user_context_if_valid(RiscV64UserThreadContext::from_trap(frame));
    }

    #[cfg(target_arch = "riscv64")]
    pub(crate) fn write_riscv64_user_context_to_trap(
        &self,
        frame: &mut crate::arch::riscv64::trap::TrapFrame,
    ) {
        let user_context = self.riscv64_user_context();
        if let Some(context) = user_context {
            context.write_to_trap(frame);
        }
    }

    #[cfg(target_arch = "riscv64")]
    #[allow(dead_code)]
    fn clear_riscv64_user_runtime_state(&self) {
        *self.riscv64_user_context.lock() = None;
    }
}

use super::entry::{initial_instruction_pointer, initialize_frame_kernel_stack};
