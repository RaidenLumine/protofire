//! src/kernel/process/process/lifecycle.rs
//!
//! Process constructors, field accessors, thread management, signals, and
//! termination.

use ::core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::sync::{Event, Mutex, WaitQueue};
use crate::kernel::user::resolve_home_dir;
#[allow(unused_imports)]
use crate::println;
use crate::{Error, Result};

use super::super::thread::{Thread, ThreadId, ThreadWaitOutcome};
use super::constants::*;
use super::types::ProcessShmAttachment;
use super::types::*;
use super::Process;

impl Process {
    fn prepare_signal_wait(
        state: &mut PendingProcessSignalState,
        waiters: &mut VecDeque<Arc<Thread>>,
        thread: &Arc<Thread>,
    ) -> bool {
        if !state.pending.is_empty() {
            thread.set_wait_outcome(ThreadWaitOutcome::Completed);
            return false;
        }

        waiters.push_back(thread.clone());
        true
    }

    fn probe_signal_wait_ready(&self) -> bool {
        let has_pending = self
            .signal_queue
            .with_lock(|state, _| !state.pending.is_empty());
        self.signal_queue.set_current_wait_outcome(if has_pending {
            ThreadWaitOutcome::Completed
        } else {
            ThreadWaitOutcome::TimedOut
        });
        has_pending
    }

    /// Create a new process with the given PID and name.
    pub fn new(pid: ProcessId, name: &str) -> Arc<Self> {
        Self::new_with_security_token(pid, name, SecurityToken::system())
    }

    /// Create a new process with the given PID, name, and security token.
    pub fn new_with_security_token(
        pid: ProcessId,
        name: &str,
        security_token: SecurityToken,
    ) -> Arc<Self> {
        let process = Arc::new(Self {
            pid,
            parent_pid: Mutex::new(None),
            name: Mutex::new(name.to_string()),
            dumpable: AtomicU8::new(1),
            keepcaps: AtomicBool::new(false),
            tracer_pid: Mutex::new(None),
            ptrace_options: Mutex::new(0),
            ptrace_event_queue: Mutex::new(VecDeque::new()),
            seccomp_filter: Mutex::new(crate::kernel::process::seccomp::SeccompFilterState::new()),
            no_new_privs: AtomicBool::new(false),
            user_signal_handlers: Mutex::new([None; 32]),
            signal_sa_flags_storage: Mutex::new([0; 32]),
            signal_trampoline_addr: Mutex::new(0),
            threads: Mutex::new(Vec::new()),
            handle_table: Mutex::new(BTreeMap::new()),
            fd_table: Mutex::new(BTreeMap::new()),
            fd_flags: Mutex::new(BTreeMap::new()),
            children: Mutex::new(Vec::new()),
            signal_handlers: Mutex::new([None; 32]),
            signal_mask: Mutex::new(0),
            signal_queue: WaitQueue::with_state(PendingProcessSignalState::new()),
            security_token: Mutex::new(security_token),
            current_working_dir: Mutex::new(resolve_home_dir(security_token.user_id)),
            home_dir: Mutex::new(resolve_home_dir(security_token.user_id)),
            launch_context: Mutex::new(None),
            user_address_space: Mutex::new(None),
            termination_event: Event::manual_reset(false),
            standard_handles: Mutex::new([None; STANDARD_FD_COUNT]),
            state: Mutex::new(ProcessState::New),
            termination_reason: Mutex::new(None),
            fault_records: Mutex::new(FaultRecordRing::new()),
            suspended_thread: Mutex::new(None),
            deferred_user_address_space_drop: Mutex::new(None),
            termination_reaped: AtomicBool::new(false),
            address_space_generation: AtomicU64::new(0),
            program_break: AtomicU64::new(0),
            shm_va_hint: AtomicU64::new(0),
            shm_attachments: Mutex::new(Vec::new()),
            audit_enable_mask: AtomicU64::new(0),
            next_handle: AtomicU64::new(4),
            next_fd: AtomicU64::new(FIRST_EXPLICIT_FD as u64),
            next_tid: AtomicU32::new(1),
        });

        process.install_default_standard_handles();
        process
    }

    /// Return the process ID.
    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    /// Return the parent process ID, if known.
    pub fn parent_pid(&self) -> Option<ProcessId> {
        *self.parent_pid.lock()
    }

    /// Set the parent process ID.
    ///
    /// Used when reparenting orphaned processes after a parent terminates.
    pub(crate) fn set_parent_pid(&self, parent_pid: ProcessId) {
        *self.parent_pid.lock() = Some(parent_pid);
    }

    /// Register a child process. Called by the scheduler when spawning a new
    /// process with a known parent.
    pub(crate) fn add_child(&self, child_pid: ProcessId) {
        self.children.lock().push(child_pid);
    }

    /// Remove a child process from the tracking list (e.g. after the child
    /// terminates and is reaped).
    pub(crate) fn remove_child(&self, child_pid: ProcessId) {
        self.children.lock().retain(|&pid| pid != child_pid);
    }

    /// Return a snapshot of tracked child PIDs.
    pub fn children(&self) -> Vec<ProcessId> {
        self.children.lock().clone()
    }

    /// Return a snapshot of the process name.
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }

    /// Rename the process (used by PR_SET_NAME).
    pub fn set_name(&self, name: &str) {
        *self.name.lock() = alloc::string::String::from(name);
    }

    /// Return the dumpable flag (0 = not dumpable, 1 = dumpable).
    pub fn dumpable(&self) -> u8 {
        self.dumpable.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Set the dumpable flag (PR_SET_DUMPABLE).
    pub fn set_dumpable(&self, val: u8) {
        self.dumpable
            .store(val, core::sync::atomic::Ordering::Relaxed);
    }

    /// Return whether the process retains capabilities across exec.
    pub fn keepcaps(&self) -> bool {
        self.keepcaps.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Set the keep-caps flag (PR_SET_KEEPCAPS).
    pub fn set_keepcaps(&self, val: bool) {
        self.keepcaps
            .store(val, core::sync::atomic::Ordering::Relaxed);
    }

    /// Return the no_new_privs flag (PR_GET_NO_NEW_PRIVS).
    pub fn no_new_privs(&self) -> bool {
        self.no_new_privs
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Set the no_new_privs flag (PR_SET_NO_NEW_PRIVS).
    pub fn set_no_new_privs(&self, val: bool) {
        self.no_new_privs
            .store(val, core::sync::atomic::Ordering::Relaxed);
    }

    /// Return the current process state.
    pub fn state(&self) -> ProcessState {
        *self.state.lock()
    }

    /// Atomically set the process state.
    pub fn set_state(&self, state: ProcessState) {
        *self.state.lock() = state;
    }

    /// Return the termination reason if the process has terminated.
    pub fn termination_reason(&self) -> Option<TerminationReason> {
        *self.termination_reason.lock()
    }

    /// Record a termination reason for the process.
    ///
    /// Called during shutdown to provide a human-readable exit code or signal
    /// description for the reaper.
    pub(crate) fn record_termination_reason(&self, reason: Option<TerminationReason>) {
        *self.termination_reason.lock() = reason;
    }

    /// Push a fault record into the per-process ring buffer for post-mortem
    /// crash diagnosis. The ring buffer silently overwrites the oldest entry
    /// once capacity (4) is reached.
    pub(crate) fn push_fault_record(
        &self,
        vector: u8,
        error_code: u64,
        fault_address: Option<usize>,
        instruction_pointer: u64,
        from_user_mode: bool,
    ) {
        self.fault_records.lock().push(FaultRecord {
            vector,
            error_code,
            fault_address,
            instruction_pointer,
            from_user_mode,
        });
    }

    /// Return a snapshot of the recent fault records, oldest first.
    pub fn fault_records(&self) -> Vec<FaultRecord> {
        self.fault_records.lock().records().copied().collect()
    }

    /// Allocate and return the next thread ID for this process.
    pub fn allocate_tid(&self) -> ThreadId {
        self.next_tid.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a new thread ID with this process.
    pub fn add_thread(&self, tid: ThreadId) -> Result<()> {
        self.ensure_mutable()?;
        let mut threads = self.threads.lock();
        if threads.contains(&tid) {
            return Err(Error::Busy);
        }
        threads.push(tid);
        Ok(())
    }

    /// Return a snapshot of all thread IDs belonging to this process.
    pub fn thread_ids(&self) -> Vec<ThreadId> {
        self.threads.lock().clone()
    }

    /// Store the thread for a suspended (START_SUSPENDED) spawn.  The scheduler
    /// will retrieve and enqueue it when the parent calls `wait_process`.
    pub(crate) fn store_suspended_thread(&self, thread: alloc::sync::Arc<super::super::Thread>) {
        *self.suspended_thread.lock() = Some(thread);
    }

    /// Take the suspended thread, if any, so the scheduler can enqueue it.
    ///
    /// Returns `None` if no thread was stored or if the thread has already
    /// been taken.
    pub(crate) fn take_suspended_thread(&self) -> Option<alloc::sync::Arc<super::super::Thread>> {
        self.suspended_thread.lock().take()
    }

    /// Drop the deferred user address space.  Called during reap when
    /// interrupts are enabled so the heap allocator can safely free the
    /// page-table allocations.
    pub(crate) fn clear_deferred_user_address_space(&self) {
        *self.deferred_user_address_space_drop.lock() = None;
    }

    /// Complete termination of a thread, updating the process termination
    /// bookkeeping.  If this is the last thread, marks the process as
    /// terminated.
    pub(crate) fn finish_thread_termination(
        &self,
        tid: ThreadId,
        reason: Option<TerminationReason>,
    ) -> bool {
        let last_thread = {
            let mut threads = self.threads.lock();
            let Some(index) = threads.iter().position(|thread_id| *thread_id == tid) else {
                return false;
            };
            threads.swap_remove(index);
            threads.is_empty()
        };

        // Only the final live thread transitions the whole process into a
        // terminated/reapable state.
        if !last_thread || self.is_terminated() {
            return false;
        }

        self.complete_termination(reason);
        true
    }

    /// Return the security token associated with this process.
    pub fn security_token(&self) -> SecurityToken {
        *self.security_token.lock()
    }

    /// Whether this process has an installed user address space (as opposed to
    /// a pure kernel thread, which never gets one).
    pub fn has_user_address_space(&self) -> bool {
        self.user_address_space.lock().is_some()
    }

    /// Return a snapshot of the installed user address space, if any.
    pub fn user_address_space_summary(&self) -> Option<ProcessAddressSpaceSummary> {
        let space = self.user_address_space.lock();
        space.as_ref().map(|s| match s.process_summary() {
            Some(combined) => combined,
            None => ProcessAddressSpaceSummary {
                root_table_address: s.summary().root_table_address,
                mapped_page_count: s.summary().mapped_page_count,
                kernel_page_count: 0,
                user_page_count: s.summary().mapped_page_count,
                table_page_count: s.summary().table_page_count,
                pml4_entry_count: s.summary().pml4_entry_count,
                pdpt_count: s.summary().pdpt_count,
                page_directory_count: s.summary().page_directory_count,
                page_table_count: s.summary().page_table_count,
            },
        })
    }

    /// Return the current audit enable mask.
    pub fn audit_enable_mask(&self) -> u64 {
        self.audit_enable_mask.load(Ordering::Relaxed)
    }

    /// Set the audit enable mask.
    pub fn set_audit_enable_mask(&self, mask: u64) {
        self.audit_enable_mask.store(mask, Ordering::Relaxed);
    }

    /// Return a copy of the current working directory path.
    pub fn current_working_dir(&self) -> String {
        self.current_working_dir.lock().clone()
    }

    /// Set the current working directory path.
    pub fn set_current_working_dir(&self, path: &str) {
        if self.is_terminated() {
            return;
        }

        let current = self.current_working_dir.lock().clone();
        let Ok(normalized) = crate::kernel::fs::path::normalize_path(path, &current) else {
            return;
        };

        *self.current_working_dir.lock() = normalized;
    }

    /// Return the current program break (brk) value, in bytes.
    pub fn program_break(&self) -> usize {
        self.program_break.load(Ordering::Relaxed) as usize
    }

    /// Set the program break (brk) value, in bytes.
    pub fn set_program_break(&self, addr: usize) {
        self.program_break.store(addr as u64, Ordering::Relaxed);
    }

    // ── Shared memory attachment tracking ──────────────────────────────

    /// Return the next hint address for shm mappings.
    pub fn shm_va_hint(&self) -> usize {
        self.shm_va_hint.load(Ordering::Relaxed) as usize
    }

    /// Set the hint address for shm mappings.
    pub fn set_shm_va_hint(&self, addr: usize) {
        self.shm_va_hint.store(addr as u64, Ordering::Relaxed);
    }

    /// Record a shared-memory segment attachment.
    pub(crate) fn record_shm_attachment(&self, shmid: usize, va: usize, size: usize) {
        self.shm_attachments.lock().push(ProcessShmAttachment {
            shmid,
            virtual_address: va,
            size,
        });
    }

    /// Find an attachment by shmid.
    pub(crate) fn find_shm_attachment(&self, shmid: usize) -> Option<ProcessShmAttachment> {
        self.shm_attachments
            .lock()
            .iter()
            .find(|a| a.shmid == shmid)
            .cloned()
    }

    /// Remove an attachment by shmid.
    pub(crate) fn remove_shm_attachment(&self, shmid: usize) {
        self.shm_attachments.lock().retain(|a| a.shmid != shmid);
    }

    /// Collect all attachments (for cleanup at exit).
    pub(crate) fn collect_shm_attachments(&self) -> Vec<ProcessShmAttachment> {
        self.shm_attachments.lock().clone()
    }

    /// Clear all attachments (after cleaning up).
    pub(crate) fn clear_shm_attachments(&self) {
        self.shm_attachments.lock().clear();
    }

    /// Return the process's home directory.
    ///
    /// The home directory is derived from the process's [`SecurityToken`] uid
    /// at creation time (see [`home_dir_for_uid`]).  It is inherited across
    /// fork and preserved across exec.
    pub fn home_dir(&self) -> String {
        self.home_dir.lock().clone()
    }

    /// Configure the launch context used when the process starts
    /// a new program image.
    pub fn configure_launch(&self, launch: LaunchContext) {
        if self.is_terminated() {
            return;
        }

        self.set_current_working_dir(&launch.working_dir);
        *self.launch_context.lock() = Some(launch);
    }

    /// Return a copy of the launch context, if configured.
    pub fn launch_context(&self) -> Option<LaunchContext> {
        self.launch_context.lock().clone()
    }

    /// Call `f` with the launch context if one is configured.
    pub fn with_launch_context<T>(&self, f: impl FnOnce(&LaunchContext) -> T) -> Option<T> {
        self.launch_context.lock().as_ref().map(f)
    }

    /// Replace the current exec state with a new one, swapping the
    /// address space, working directory, home directory, and launch
    /// metadata atomically.
    ///
    /// Returns the previous [`ProcessExecState`] so callers can roll back
    /// on failure.
    pub(crate) fn replace_exec_state(
        &self,
        launch: LaunchContext,
        user_address_space: Option<ProcessUserAddressSpace>,
    ) -> Result<ProcessExecState> {
        self.ensure_mutable()?;

        // Unregister the old user pages from the software page table before
        // swapping to the new address space.
        if let Some(old_space) = self.user_address_space.lock().as_ref() {
            if let Some((start, end)) = old_space.user_page_va_range() {
                let len = end.saturating_sub(start);
                if let Some(mut memory) = crate::kernel::memory::global_mut() {
                    memory.unregister_user_page_range(start, len);
                }
            }
        }

        // Swap cwd, home_dir, launch metadata, and prepared address-space
        // as one logical exec-state transaction so callers can roll back on
        // later failure.
        let previous = ProcessExecState {
            current_working_dir: self.current_working_dir.lock().clone(),
            home_dir: self.home_dir.lock().clone(),
            launch_context: self.launch_context.lock().clone(),
            user_address_space: self.user_address_space.lock().take(),
        };

        *self.current_working_dir.lock() = launch.working_dir.clone();
        *self.home_dir.lock() = resolve_home_dir(self.security_token.lock().user_id);
        *self.launch_context.lock() = Some(launch);
        *self.user_address_space.lock() = user_address_space;

        Ok(previous)
    }

    /// Restore a previously-saved exec state.
    ///
    /// Used to roll back a failed in-place image swap so that cwd, home_dir,
    /// launch metadata, and address-space mappings are consistent again.
    pub(crate) fn restore_exec_state(&self, state: ProcessExecState) -> Result<()> {
        self.ensure_mutable()?;

        let ProcessExecState {
            current_working_dir,
            home_dir,
            launch_context,
            user_address_space,
        } = state;

        // Restore the exact pre-exec snapshot so a failed in-place image swap
        // leaves launch metadata, cwd, home_dir, and mappings consistent again.
        *self.current_working_dir.lock() = current_working_dir;
        *self.home_dir.lock() = home_dir;
        *self.launch_context.lock() = launch_context;
        *self.user_address_space.lock() = user_address_space;

        Ok(())
    }

    /// Return `true` when a custom handler is installed for `signal`.
    pub fn signal_has_handler(&self, signal: usize) -> bool {
        self.signal_handlers
            .lock()
            .get(signal)
            .and_then(|s| *s)
            .is_some()
    }

    /// Return `true` when `signal` is a well-known POSIX signal that has a
    /// default action (terminate, stop, continue, or ignore).
    fn is_posix_signal(signal: usize) -> bool {
        use crate::abi::process;
        matches!(
            signal,
            process::SIGHUP
                | process::SIGINT
                | process::SIGQUIT
                | process::SIGKILL
                | process::SIGTERM
                | process::SIGCHLD
                | process::SIGCONT
                | process::SIGSTOP
                | process::SIGTSTP
        )
    }

    /// Apply the POSIX default action for a signal synchronously.
    ///
    /// Called from [`enqueue_signal`] when no custom handler is installed
    /// for a well-known POSIX signal.  SIGKILL and SIGSTOP always execute
    /// the default regardless of handlers.
    fn apply_default_signal_action(&self, signal: usize) {
        use crate::abi::process;

        match signal {
            process::SIGHUP
            | process::SIGINT
            | process::SIGQUIT
            | process::SIGTERM
            | process::SIGKILL => {
                // Request termination rather than completing it inline: this
                // handler may run on a different CPU than the target's own
                // threads, and releasing the process's resources from here
                // would race with a thread still executing there.  The running
                // thread self-terminates at its next scheduler boundary.
                let reason = TerminationReason::Exit {
                    status: 128 + signal,
                };
                self.request_termination(Some(reason));
            }
            process::SIGSTOP | process::SIGTSTP => {
                // Stop is handled by the scheduler-level stop_process in the
                // syscall handler (SendSignal).  No additional work needed
                // here.
            }
            process::SIGCONT => {
                // Continue is handled by the scheduler-level continue_process
                // in the syscall handler (SendSignal).
            }
            _ => {
                // SIGCHLD and all other unhandled signals: ignore by default.
            }
        }
    }

    /// Enqueue a signal for delivery to this process.
    ///
    /// For well-known POSIX signals: when no custom handler is installed
    /// (or when the signal is SIGKILL / SIGSTOP), the POSIX default action
    /// is applied synchronously and the signal is *not* placed on the
    /// pending queue.
    ///
    /// For other (cooperative) signal numbers: the signal is always
    /// enqueued regardless of handler status, preserving the original
    /// cooperative signalling model.
    ///
    /// When the signal is blocked (via [`set_signal_mask`]), the default
    /// action is deferred — the signal is enqueued so the process can
    /// consume it after unblocking.
    pub fn enqueue_signal(
        &self,
        sender_pid: ProcessId,
        signal: usize,
        payload: usize,
    ) -> Result<()> {
        self.ensure_mutable()?;
        if !crate::abi::process::is_valid_process_signal(signal) {
            return Err(Error::InvalidArgument);
        }

        // POSIX signals get default-action treatment; cooperative signals
        // (4-8,10-14,16,21-31) are always enqueued.
        if Self::is_posix_signal(signal) {
            // SIGKILL and SIGSTOP always trigger the default action regardless
            // of any installed handler or signal mask.
            let always_default =
                signal == crate::abi::process::SIGKILL || signal == crate::abi::process::SIGSTOP;
            let has_handler = self.signal_has_handler(signal);
            let is_blocked = !always_default && self.is_signal_blocked(signal);

            if always_default || (!has_handler && !is_blocked) {
                self.apply_default_signal_action(signal);
                return Ok(());
            }
            // Signal has a handler or is blocked — fall through to enqueue.
        }

        let pending = PendingProcessSignal {
            sender_pid,
            signal,
            payload,
            si_code: 0,
            si_uid: self.security_token.lock().user_id as usize,
        };
        let mut enqueue_result = Ok(());
        let _ = self.signal_queue.wake_with(|state, waiters, waking| {
            if state.pending.len() == PENDING_PROCESS_SIGNAL_CAPACITY {
                enqueue_result = Err(Error::Busy);
                return;
            }
            if state.pending.try_reserve(1).is_err() {
                enqueue_result = Err(Error::OutOfMemory);
                return;
            }

            state.pending.push_back(pending);
            if let Some(thread) = WaitQueue::<PendingProcessSignalState>::take_next_waiter(waiters)
            {
                waking.push(thread);
            }
        });
        enqueue_result
    }

    /// Dequeue the next pending signal, if any.
    pub fn take_pending_signal(&self) -> Option<crate::abi::process::ProcessSignalRecord> {
        self.signal_queue
            .with_lock(|state, _| state.pending.pop_front().map(PendingProcessSignal::record))
    }

    /// Return the number of pending signals.
    pub fn pending_signal_count(&self) -> usize {
        self.signal_queue.with_lock(|state, _| state.pending.len())
    }

    /// Peek at the next pending signal without consuming it.
    ///
    /// Used by the async-delivery path to decide whether a signal can be
    /// delivered out-of-band; the signal is only dequeued by
    /// [`take_pending_signal`] once delivery is committed.
    pub fn peek_pending_signal(&self) -> Option<crate::abi::process::ProcessSignalRecord> {
        self.signal_queue.with_lock(|state, _| {
            state
                .pending
                .front()
                .copied()
                .map(PendingProcessSignal::record)
        })
    }

    /// Return the user-space async handler address for `signal`, if any.
    ///
    /// `Some(addr)` when an async handler is registered (via
    /// `SetSignalHandler` with a non-zero handler address); `None` for
    /// cooperative-only signals.
    ///
    /// Consumed only by the bare-metal async signal-delivery path in the
    /// per-arch trap dispatch (`target_os = "none"`).
    #[cfg(target_os = "none")]
    pub(crate) fn user_signal_handler(&self, signal: usize) -> Option<u64> {
        self.user_signal_handlers
            .lock()
            .get(signal)
            .copied()
            .flatten()
    }

    /// Register (or replace) the user-space async handler address for
    /// `signal`.
    pub(crate) fn install_user_signal_handler(&self, signal: usize, handler: u64) -> Result<()> {
        self.ensure_mutable()?;
        let mut handlers = self.user_signal_handlers.lock();
        let slot = handlers.get_mut(signal).ok_or(Error::InvalidArgument)?;
        *slot = Some(handler);
        Ok(())
    }

    /// Clear the user-space async handler address for `signal`.
    pub(crate) fn remove_user_signal_handler(&self, signal: usize) -> Result<()> {
        let mut handlers = self.user_signal_handlers.lock();
        if let Some(slot) = handlers.get_mut(signal) {
            *slot = None;
        }
        Ok(())
    }

    /// Return the ring-3 signal trampoline address (0 = not installed).
    ///
    /// Consumed only by the bare-metal async signal-delivery path in the
    /// per-arch trap dispatch (`target_os = "none"`).
    #[cfg(target_os = "none")]
    pub(crate) fn signal_trampoline_addr(&self) -> u64 {
        *self.signal_trampoline_addr.lock()
    }

    /// Record the ring-3 signal trampoline address.
    pub(crate) fn set_signal_trampoline_addr(&self, addr: u64) {
        *self.signal_trampoline_addr.lock() = addr;
    }

    /// Return the `SA_*` flags the signal handler for `signal` was installed
    /// with.
    ///
    /// Only `SA_RESTART` is currently defined by the kernel ABI; unknown bits
    /// are masked out at install time.  The async-delivery path consults this
    /// to decide whether an interrupted syscall should be re-issued.
    ///
    /// Consumed by the bare-metal async signal-delivery path (`target_os =
    /// "none"`) and by the SA-flags unit tests below.
    #[cfg(any(test, target_os = "none"))]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn signal_sa_flags(&self, signal: usize) -> u64 {
        self.signal_sa_flags_storage
            .lock()
            .get(signal)
            .copied()
            .unwrap_or(0)
    }

    /// Record the `SA_*` flags for `signal` (masked to the known set).
    pub(crate) fn install_signal_sa_flags(&self, signal: usize, flags: u64) -> Result<()> {
        self.ensure_mutable()?;
        let known = crate::abi::process::SIGNAL_SA_FLAGS_KNOWN;
        if flags & !known != 0 {
            // Unknown flags are rejected rather than silently dropped so a
            // caller relying on an unsupported `SA_` bit fails loudly.
            return Err(Error::InvalidArgument);
        }
        let mut storage = self.signal_sa_flags_storage.lock();
        let slot = storage.get_mut(signal).ok_or(Error::InvalidArgument)?;
        *slot = flags & known;
        Ok(())
    }

    /// Clear the `SA_*` flags for `signal` (used when restoring the default
    /// action).
    pub(crate) fn remove_signal_sa_flags(&self, signal: usize) -> Result<()> {
        let mut storage = self.signal_sa_flags_storage.lock();
        if let Some(slot) = storage.get_mut(signal) {
            *slot = 0;
        }
        Ok(())
    }

    /// Restore the POSIX default action for `signal` (remove any installed
    /// kernel proxy handler).
    pub(crate) fn remove_signal_handler(&self, signal: usize) -> Result<()> {
        self.ensure_mutable()?;
        let mut handlers = self.signal_handlers.lock();
        if let Some(slot) = handlers.get_mut(signal) {
            *slot = None;
        }
        Ok(())
    }

    /// Return the number of threads waiting for a signal.
    pub fn signal_waiter_count(&self) -> usize {
        self.signal_queue.waiter_count()
    }

    /// Block delivery of `signal` by setting its bit in the signal mask.
    ///
    /// While a signal is blocked, [`enqueue_signal`] will enqueue it but
    /// the default action is *not* applied synchronously.
    pub fn block_signal(&self, signal: usize) {
        if signal < 32 {
            let mut mask = self.signal_mask.lock();
            *mask |= 1 << signal;
        }
    }

    /// Unblock `signal` by clearing its bit in the signal mask.
    pub fn unblock_signal(&self, signal: usize) {
        if signal < 32 {
            let mut mask = self.signal_mask.lock();
            *mask &= !(1 << signal);
        }
    }

    /// Return `true` when `signal` is currently masked (blocked).
    pub fn is_signal_blocked(&self, signal: usize) -> bool {
        if signal < 32 {
            let mask = self.signal_mask.lock();
            *mask & (1 << signal) != 0
        } else {
            false
        }
    }

    /// Atomically set the signal mask and return the previous mask value.
    pub fn set_signal_mask(&self, mask: u32) -> u32 {
        let mut current = self.signal_mask.lock();
        let old = *current;
        *current = mask;
        old
    }

    /// Block the calling thread until a signal is delivered to this
    /// process.  Returns `true` if a signal was received.
    pub fn wait_for_signal(&self) -> bool {
        self.signal_queue
            .block_current_if(Self::prepare_signal_wait)
    }

    /// Block the calling thread until a signal is delivered or
    /// `timeout_ticks` elapses.
    pub fn wait_for_signal_timeout(&self, timeout_ticks: u64) -> bool {
        if timeout_ticks == 0 {
            let _ = self.probe_signal_wait_ready();
            return false;
        }

        let Some(scheduler) = super::super::Scheduler::global() else {
            return false;
        };

        let deadline = scheduler.current_tick().saturating_add(timeout_ticks);
        self.signal_queue
            .block_current_until_if(deadline, Self::prepare_signal_wait)
    }

    /// Block the calling thread until the process terminates.
    pub fn wait_for_termination(&self) -> bool {
        self.termination_event.wait()
    }

    /// Block the calling thread until the process terminates or
    /// `timeout_ticks` elapses.
    pub fn wait_for_termination_timeout(&self, timeout_ticks: u64) -> bool {
        self.termination_event.wait_timeout(timeout_ticks)
    }

    /// Return the number of threads waiting for process termination.
    pub fn termination_waiter_count(&self) -> usize {
        self.termination_event.waiter_count()
    }

    /// Reap the termination reason, consuming it.  Returns an error if
    /// called more than once.
    pub fn reap_termination_reason(&self) -> Result<Option<TerminationReason>> {
        if self.state() != ProcessState::Terminated {
            return Err(Error::Busy);
        }

        // Reaping is intentionally one-shot: once a waiter claims the reason,
        // later callers observe the process as already collected.
        if self
            .termination_reaped
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::NotFound);
        }

        Ok(self.termination_reason.lock().take())
    }

    /// Return `true` if the termination reason has already been reaped.
    pub fn termination_reaped(&self) -> bool {
        self.termination_reaped.load(Ordering::Acquire)
    }

    /// Return `true` if the process is in a terminal state.
    pub(crate) fn is_terminated(&self) -> bool {
        self.state() == ProcessState::Terminated
    }

    /// Ensure the process is in a mutable state, returning an error if
    /// it has already terminated.
    pub(crate) fn ensure_mutable(&self) -> Result<()> {
        if self.is_terminated() {
            return Err(Error::Busy);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::abi::process::{SA_RESTART, SIGNAL_SA_FLAGS_KNOWN};
    use crate::kernel::memory::MemoryManager;
    use crate::kernel::process::scheduler::api::idle_entry;
    use crate::kernel::process::{
        ProcessState, Scheduler, TerminationReason, Thread, UserThreadStart,
    };
    use crate::Error;

    use super::Process;

    /// Create a scheduler with a single runnable kernel thread installed as
    /// the current thread, plus that thread's process.  Mirrors
    /// `syscall::test_support::scheduled_current_process`.
    fn scheduled_current_process(name: &str) -> (Box<Scheduler>, Arc<Process>) {
        let scheduler = Box::new(Scheduler::new());
        let thread = scheduler.spawn_named(name, 0x1000);
        scheduler.schedule();
        assert_eq!(scheduler.current_thread_id(), Some(thread.tid()));
        (scheduler, thread.process().clone())
    }

    #[test]
    fn install_signal_sa_flags_roundtrips() {
        let process = Process::new(1001, "sa-flags-roundtrip");
        assert_eq!(process.signal_sa_flags(7), 0);

        process.install_signal_sa_flags(7, SA_RESTART).unwrap();
        assert_eq!(process.signal_sa_flags(7), SA_RESTART);

        // A different signal is unaffected (per-signal storage).
        assert_eq!(process.signal_sa_flags(8), 0);

        process.remove_signal_sa_flags(7).unwrap();
        assert_eq!(process.signal_sa_flags(7), 0);
    }

    #[test]
    fn install_signal_sa_flags_rejects_unknown_bits() {
        let process = Process::new(1002, "sa-flags-unknown");
        let unknown = SA_RESTART | 0x8000_0000;
        assert_eq!(
            process.install_signal_sa_flags(7, unknown),
            Err(Error::InvalidArgument)
        );
        // Nothing was stored.
        assert_eq!(process.signal_sa_flags(7), 0);
    }

    #[test]
    fn install_signal_sa_flags_rejects_out_of_range_signal() {
        let process = Process::new(1003, "sa-flags-range");
        // Index 0 is storable as plain array storage; the *syscall* entry
        // point (`set_handler`) validates signal 1..=31 via
        // `is_valid_process_signal` before ever reaching this method.
        process.install_signal_sa_flags(0, SA_RESTART).unwrap();
        assert_eq!(process.signal_sa_flags(0), SA_RESTART);
        // Out of array bounds -> InvalidArgument.
        assert_eq!(
            process.install_signal_sa_flags(32, SA_RESTART),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn known_flags_mask_only_contains_supported_sa_bits() {
        // Everything the kernel claims to know must actually be handled.
        // Currently that is exactly SA_RESTART.
        assert_eq!(SIGNAL_SA_FLAGS_KNOWN, SA_RESTART);
    }

    // ── Signal queue (FIFO ordering, peek, capacity) ────────────────────

    #[test]
    fn enqueue_signal_preserves_fifo_order() {
        let process = Process::new(1010, "signal-fifo");
        // Cooperative signal numbers are always enqueued regardless of handler.
        process.enqueue_signal(7, 10, 0xaaa).unwrap();
        process.enqueue_signal(8, 11, 0xbbb).unwrap();
        process.enqueue_signal(9, 12, 0xccc).unwrap();

        assert_eq!(process.pending_signal_count(), 3);

        let first = process.take_pending_signal().expect("first signal");
        assert_eq!(
            (first.signal, first.sender_pid, first.payload),
            (10, 7, 0xaaa)
        );
        let second = process.take_pending_signal().expect("second signal");
        assert_eq!(
            (second.signal, second.sender_pid, second.payload),
            (11, 8, 0xbbb)
        );
        let third = process.take_pending_signal().expect("third signal");
        assert_eq!(
            (third.signal, third.sender_pid, third.payload),
            (12, 9, 0xccc)
        );
        assert_eq!(process.take_pending_signal(), None);
    }

    #[test]
    fn empty_signal_queue_returns_none() {
        let process = Process::new(1011, "signal-empty");
        assert_eq!(process.pending_signal_count(), 0);
        assert_eq!(process.take_pending_signal(), None);
        assert_eq!(process.peek_pending_signal(), None);
    }

    #[test]
    fn peek_pending_signal_does_not_consume() {
        let process = Process::new(1012, "signal-peek");
        process.enqueue_signal(1, 10, 42).unwrap();
        assert_eq!(process.pending_signal_count(), 1);

        let peeked = process.peek_pending_signal().expect("peek");
        assert_eq!((peeked.signal, peeked.payload), (10, 42));
        assert_eq!(process.pending_signal_count(), 1, "peek must not consume");

        let taken = process.take_pending_signal().expect("take");
        assert_eq!((taken.signal, taken.payload), (10, 42));
        assert_eq!(process.pending_signal_count(), 0);
    }

    #[test]
    fn enqueue_signal_rejects_out_of_range_signal() {
        let process = Process::new(1013, "signal-range");
        assert_eq!(process.enqueue_signal(1, 0, 0), Err(Error::InvalidArgument));
        assert_eq!(
            process.enqueue_signal(1, 32, 0),
            Err(Error::InvalidArgument)
        );
        assert_eq!(process.pending_signal_count(), 0);
    }

    #[test]
    fn enqueue_signal_on_terminated_process_is_busy() {
        let process = Process::new(1014, "signal-terminated");
        process.complete_termination(Some(TerminationReason::Exit { status: 0 }));
        assert_eq!(process.state(), ProcessState::Terminated);
        assert_eq!(process.enqueue_signal(1, 10, 0), Err(Error::Busy));
    }

    #[test]
    fn enqueue_signal_capacity_is_bounded() {
        let process = Process::new(1015, "signal-capacity");
        let capacity = crate::kernel::process::process::constants::PENDING_PROCESS_SIGNAL_CAPACITY;
        for _ in 0..capacity {
            assert!(process.enqueue_signal(1, 10, 0).is_ok());
        }
        assert_eq!(process.pending_signal_count(), capacity);
        // The bounded queue rejects the next enqueue rather than growing.
        assert_eq!(process.enqueue_signal(1, 10, 0), Err(Error::Busy));
        assert_eq!(process.pending_signal_count(), capacity);
    }

    // ── Signal mask (block / unblock / atomic swap) ─────────────────────

    #[test]
    fn signal_mask_block_unblock_roundtrip() {
        let process = Process::new(1016, "signal-mask");
        assert!(!process.is_signal_blocked(10));
        process.block_signal(10);
        assert!(process.is_signal_blocked(10));
        process.unblock_signal(10);
        assert!(!process.is_signal_blocked(10));
        // Out-of-range signals are silently ignored by the mask helpers.
        process.block_signal(32);
        assert!(!process.is_signal_blocked(32));
    }

    #[test]
    fn set_signal_mask_returns_previous_mask() {
        let process = Process::new(1017, "signal-mask-swap");
        assert_eq!(process.set_signal_mask(1 << 10), 0);
        assert!(process.is_signal_blocked(10));
        assert_eq!(process.set_signal_mask(0), 1 << 10);
        assert!(!process.is_signal_blocked(10));
    }

    #[test]
    fn blocked_signal_is_enqueued_instead_of_default_action() {
        let process = Process::new(1018, "signal-blocked");
        process.block_signal(crate::abi::process::SIGTERM);
        process
            .enqueue_signal(1, crate::abi::process::SIGTERM, 0)
            .unwrap();
        // The terminating default action is deferred while the signal is blocked.
        assert_eq!(process.state(), ProcessState::New);
        assert_eq!(process.pending_signal_count(), 1);
        // Unblocking leaves the signal pending for the process to consume.
        process.unblock_signal(crate::abi::process::SIGTERM);
        assert_eq!(process.pending_signal_count(), 1);
    }

    // ── POSIX default actions ───────────────────────────────────────────

    #[test]
    fn sigterm_without_handler_terminates_process() {
        let process = Process::new(1019, "sigterm-default");
        process
            .enqueue_signal(1, crate::abi::process::SIGTERM, 0)
            .unwrap();
        assert_eq!(process.state(), ProcessState::Terminated);
        assert_eq!(
            process.termination_reason(),
            Some(TerminationReason::Exit {
                status: 128 + crate::abi::process::SIGTERM
            })
        );
    }

    #[test]
    fn sigkill_always_terminates_even_with_handler() {
        let process = Process::new(1020, "sigkill-default");
        process.install_signal_handler(9, |_| {}).unwrap();
        process
            .enqueue_signal(1, crate::abi::process::SIGKILL, 0)
            .unwrap();
        assert_eq!(process.state(), ProcessState::Terminated);
    }

    #[test]
    fn posix_signal_with_handler_is_enqueued_not_applied() {
        let process = Process::new(1021, "posix-handler");
        process
            .install_signal_handler(crate::abi::process::SIGTERM, |_| {})
            .unwrap();
        process
            .enqueue_signal(1, crate::abi::process::SIGTERM, 7)
            .unwrap();
        // A handler prevents the default action; the signal is queued instead.
        assert_eq!(process.state(), ProcessState::New);
        assert_eq!(process.pending_signal_count(), 1);
        let sig = process.take_pending_signal().unwrap();
        assert_eq!((sig.signal, sig.payload), (crate::abi::process::SIGTERM, 7));
    }

    // ── Signal handler registry ─────────────────────────────────────────

    #[test]
    fn signal_handler_install_remove_roundtrip() {
        let process = Process::new(1022, "handler-roundtrip");
        assert!(!process.signal_has_handler(10));
        assert_eq!(process.install_signal_handler(10, |_| {}), Ok(None));
        assert!(process.signal_has_handler(10));
        process.remove_signal_handler(10).unwrap();
        assert!(!process.signal_has_handler(10));
    }

    #[test]
    fn install_signal_handler_rejects_out_of_range() {
        let process = Process::new(1023, "handler-range");
        assert_eq!(
            process.install_signal_handler(32, |_| {}),
            Err(Error::InvalidArgument)
        );
    }

    // ── Thread bookkeeping ──────────────────────────────────────────────

    #[test]
    fn allocate_tid_is_monotonic() {
        let process = Process::new(1024, "tid-monotonic");
        let a = process.allocate_tid();
        let b = process.allocate_tid();
        let c = process.allocate_tid();
        assert!(a < b && b < c);
    }

    #[test]
    fn add_thread_duplicate_returns_busy() {
        let process = Process::new(1025, "tid-duplicate");
        let tid = process.allocate_tid();
        assert!(process.add_thread(tid).is_ok());
        assert_eq!(process.add_thread(tid), Err(Error::Busy));
        assert_eq!(process.thread_ids(), vec![tid]);
    }

    #[test]
    fn add_thread_on_terminated_process_is_busy() {
        let process = Process::new(1026, "tid-terminated");
        process.complete_termination(Some(TerminationReason::Exit { status: 0 }));
        assert_eq!(process.add_thread(process.allocate_tid()), Err(Error::Busy));
    }

    #[test]
    fn finish_thread_termination_removes_thread_and_terminates_when_last() {
        let process = Process::new(1027, "finish-thread");
        let t1 = process.allocate_tid();
        let t2 = process.allocate_tid();
        process.add_thread(t1).unwrap();
        process.add_thread(t2).unwrap();

        // Removing a non-final thread does not terminate the process.
        assert!(!process.finish_thread_termination(t1, None));
        assert_eq!(process.state(), ProcessState::New);
        assert_eq!(process.thread_ids(), vec![t2]);

        // Removing the final thread terminates the process with the reason.
        assert!(process.finish_thread_termination(t2, Some(TerminationReason::Exit { status: 5 })));
        assert_eq!(process.state(), ProcessState::Terminated);
        assert_eq!(
            process.termination_reason(),
            Some(TerminationReason::Exit { status: 5 })
        );
    }

    #[test]
    fn finish_thread_termination_unknown_tid_is_noop() {
        let process = Process::new(1028, "finish-unknown");
        let tid = process.allocate_tid();
        process.add_thread(tid).unwrap();
        assert!(!process.finish_thread_termination(999, None));
        assert_eq!(process.thread_ids(), vec![tid]);
        assert_eq!(process.state(), ProcessState::New);
    }

    // ── Termination / reap ──────────────────────────────────────────────

    #[test]
    fn reap_termination_reason_rejects_non_terminated() {
        let process = Process::new(1029, "reap-live");
        assert_eq!(process.reap_termination_reason(), Err(Error::Busy));
    }

    #[test]
    fn reap_termination_reason_is_one_shot() {
        let process = Process::new(1030, "reap-once");
        process.complete_termination(Some(TerminationReason::Exit { status: 7 }));
        assert_eq!(
            process.reap_termination_reason(),
            Ok(Some(TerminationReason::Exit { status: 7 }))
        );
        assert!(process.termination_reaped());
        // The reason is consumed; a second reap is rejected.
        assert_eq!(process.reap_termination_reason(), Err(Error::NotFound));
    }

    #[test]
    fn termination_clears_signal_state() {
        let process = Process::new(1031, "term-clear");
        process.install_signal_handler(10, |_| {}).unwrap();
        process.enqueue_signal(1, 10, 0).unwrap();
        assert_eq!(process.pending_signal_count(), 1);

        process.complete_termination(Some(TerminationReason::Exit { status: 0 }));

        assert!(!process.signal_has_handler(10));
        assert_eq!(process.pending_signal_count(), 0);
    }

    // ── Wait-for-signal (requires a scheduler) ──────────────────────────

    #[test]
    fn wait_for_signal_with_pending_does_not_block() {
        let (_scheduler, process) = scheduled_current_process("wait-signal-pending");
        process.enqueue_signal(1, 10, 0).unwrap();
        // prepare_signal_wait sees a non-empty queue and returns without blocking.
        assert!(!process.wait_for_signal());
        assert_eq!(process.signal_waiter_count(), 0);
    }

    #[test]
    fn wait_for_signal_blocks_then_wakes_on_enqueue() {
        let (_scheduler, process) = scheduled_current_process("wait-signal-block");
        assert!(process.wait_for_signal(), "blocks while the queue is empty");
        assert_eq!(process.signal_waiter_count(), 1);

        process.enqueue_signal(1, 10, 0).unwrap();
        assert_eq!(
            process.signal_waiter_count(),
            0,
            "waiter is woken by the signal"
        );
    }

    #[test]
    fn wait_for_signal_timeout_zero_probes_without_blocking() {
        let (_scheduler, process) = scheduled_current_process("wait-signal-timeout");
        assert!(!process.wait_for_signal_timeout(0));
        assert_eq!(process.signal_waiter_count(), 0);
    }

    #[test]
    fn wait_for_signal_timeout_with_deadline_blocks() {
        let (_scheduler, process) = scheduled_current_process("wait-signal-deadline");
        assert!(process.wait_for_signal_timeout(100));
        assert_eq!(process.signal_waiter_count(), 1);
    }

    // ── Wait-for-termination ────────────────────────────────────────────

    #[test]
    fn wait_for_termination_blocks_then_wakes_on_last_thread_exit() {
        let (_scheduler, process) = scheduled_current_process("wait-term-block");
        let tids = process.thread_ids();
        assert_eq!(tids.len(), 1);
        let tid = tids[0];

        assert!(
            process.wait_for_termination(),
            "blocks while the process is live"
        );
        assert_eq!(process.termination_waiter_count(), 1);

        assert!(process.finish_thread_termination(tid, Some(TerminationReason::Exit { status: 3 })));
        assert_eq!(process.state(), ProcessState::Terminated);
        assert_eq!(
            process.termination_waiter_count(),
            0,
            "waiter woken by termination"
        );
    }

    #[test]
    fn wait_for_termination_returns_false_when_already_terminated() {
        let (_scheduler, process) = scheduled_current_process("wait-term-done");
        process.complete_termination(Some(TerminationReason::Exit { status: 0 }));
        assert!(!process.wait_for_termination());
        assert_eq!(process.termination_waiter_count(), 0);
    }

    // ── Fork ────────────────────────────────────────────────────────────

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    mod fork_tests {
        use super::*;

        fn fork_ready_memory() -> MemoryManager {
            let mut memory = MemoryManager::new();
            memory.page_table.init();
            memory
        }

        #[test]
        fn fork_rejects_zero_threads() {
            let process = Process::new(1040, "fork-zero-threads");
            let mut memory = fork_ready_memory();
            assert!(matches!(process.fork(&mut memory, 9001), Err(Error::Busy)));
        }

        #[test]
        fn fork_rejects_more_than_one_thread() {
            let process = Process::new(1041, "fork-multi-thread");
            let _t1 = Thread::new_kernel(process.clone(), idle_entry);
            let _t2 = Thread::new_kernel(process.clone(), idle_entry);
            let mut memory = fork_ready_memory();
            assert!(matches!(process.fork(&mut memory, 9001), Err(Error::Busy)));
        }

        #[test]
        fn fork_rejects_missing_user_address_space() {
            let process = Process::new(1042, "fork-no-space");
            let _t = Thread::new_kernel(process.clone(), idle_entry);
            let mut memory = fork_ready_memory();
            assert!(matches!(
                process.fork(&mut memory, 9001),
                Err(Error::InvalidArgument)
            ));
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn fork_creates_independent_address_space_with_cow() {
            use crate::arch::x86_64::paging::{
                prepare_process_address_space, KernelPagePlan, KernelPageTableSpec,
            };
            use crate::kernel::memory::paging::{MappingKind, PagePermissions};
            use crate::kernel::process::ProcessUserAddressSpace;
            use crate::user::program::{
                UserImageLoadPlan, UserImageSegmentPlan, USER_EXCEPTION_STACK_GUARD_SIZE,
                USER_EXCEPTION_STACK_SIZE, USER_STACK_GUARD_SIZE, USER_STACK_SIZE,
                X86_64_USER_STACK_TOP,
            };

            let kernel_plan = KernelPagePlan::from_ranges(
                (0x200_000, 0x201_000),
                (0x210_000, 0x211_000),
                (0x220_000, 0x221_000),
                (0x230_000, 0x231_000),
                (0x240_000, 0x242_000),
            )
            .expect("kernel page plan");
            let kernel_spec = KernelPageTableSpec::from_plan(&kernel_plan).expect("kernel spec");

            let stack_top = X86_64_USER_STACK_TOP;
            let stack_bottom = stack_top - USER_STACK_SIZE;
            let stack_guard_start = stack_bottom - USER_STACK_GUARD_SIZE;
            let stack_guard_end = stack_bottom;
            let exception_stack_top = stack_guard_start;
            let exception_stack_bottom = exception_stack_top - USER_EXCEPTION_STACK_SIZE;
            let exception_stack_guard_start =
                exception_stack_bottom - USER_EXCEPTION_STACK_GUARD_SIZE;
            let exception_stack_guard_end = exception_stack_bottom;

            let plan = UserImageLoadPlan {
                entry_point: 0x401_000,
                image_start: 0x401_000,
                image_end: 0x405_000,
                stack_guard_start,
                stack_guard_end,
                stack_bottom,
                stack_top,
                exception_stack_guard_start,
                exception_stack_guard_end,
                exception_stack_bottom,
                exception_stack_top,
                segments: vec![
                    UserImageSegmentPlan {
                        virtual_start: 0x401_000,
                        virtual_end: 0x403_000,
                        page_start: 0x401_000,
                        page_end: 0x403_000,
                        file_offset: 0x1000,
                        file_size: 0x1800,
                        zero_start: 0x402_800,
                        zero_end: 0x403_000,
                        permissions: PagePermissions::READ_EXECUTE,
                    },
                    UserImageSegmentPlan {
                        virtual_start: 0x404_000,
                        virtual_end: 0x405_000,
                        page_start: 0x404_000,
                        page_end: 0x405_000,
                        file_offset: 0x3000,
                        file_size: 0x800,
                        zero_start: 0x404_800,
                        zero_end: 0x405_000,
                        permissions: PagePermissions::READ_WRITE,
                    },
                ],
            };
            let mut image = vec![0_u8; 0x4000];
            image[0x1000..0x2800].fill(0xAB);
            image[0x3000..0x3800].fill(0xCD);

            let prepared = prepare_process_address_space(&kernel_spec, &plan, &image)
                .expect("prepared process address space");
            let parent_entries = prepared.user_page_entries();
            assert!(!parent_entries.is_empty());

            let process = Process::new(1043, "fork-parent");
            process.install_user_address_space(ProcessUserAddressSpace::from_prepared_process(
                prepared,
            ));
            let _thread = Thread::new_user(
                process.clone(),
                UserThreadStart::new(plan.entry_point, stack_top, None),
            );

            let mut memory = fork_ready_memory();
            let mut writable = Vec::new();
            for &(va, pa, perms) in &parent_entries {
                memory.register_user_pages(&[(va, pa, perms, MappingKind::Anonymous)]);
                if perms.contains(PagePermissions::WRITE) {
                    writable.push(va);
                }
            }
            assert!(
                !writable.is_empty(),
                "load plan must include a writable page"
            );

            let child = process.fork(&mut memory, 9001).expect("fork succeeds");

            // Fresh child identity: the caller-provided PID is adopted, and
            // the child copies the parent's image with its own address space.
            assert_eq!(child.pid(), 9001);
            assert_eq!(child.name(), "fork-parent-fork");
            assert!(child.has_user_address_space());

            let parent_root = process
                .user_address_space_summary()
                .expect("parent address space")
                .root_table_address;
            let child_root = child
                .user_address_space_summary()
                .expect("child address space")
                .root_table_address;
            assert_ne!(
                parent_root, child_root,
                "address spaces must be independent"
            );

            // The parent's previously-writable pages are demoted to CoW read-only.
            for va in &writable {
                let (_, perms, kind) = memory
                    .page_table
                    .lookup_mapping(*va)
                    .unwrap_or_else(|| panic!("va {va:#x} must remain mapped"));
                assert_eq!(kind, MappingKind::Cow, "va {va:#x} should be CoW");
                assert!(
                    !perms.contains(PagePermissions::WRITE),
                    "va {va:#x} should be read-only after fork"
                );
            }
        }
    }
}
