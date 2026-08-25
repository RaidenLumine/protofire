//! src/kernel/process/process/fork.rs
//!
//! Process fork, termination cleanup, signal handler installation.

use ::core::sync::atomic::Ordering;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::device;
use crate::kernel::user::resolve_home_dir;
#[allow(unused_imports)]
use crate::println;
use crate::Error;
use crate::Result;

use super::constants::*;
use super::types::*;
use super::Process;

impl Process {
    pub fn install_signal_handler(
        &self,
        signal: usize,
        handler: SignalHandler,
    ) -> Result<Option<SignalHandler>> {
        self.ensure_mutable()?;
        let mut handlers = self.signal_handlers.lock();
        let slot = handlers.get_mut(signal).ok_or(Error::InvalidArgument)?;
        let old = slot.replace(handler);
        Ok(old)
    }

    pub(crate) fn install_default_standard_handles(&self) {
        if let Err(error) = self.try_install_default_standard_handles() {
            #[cfg(target_os = "none")]
            println!(
                "[proc  ] failed to install default std handles pid={} error={}",
                self.pid(),
                error.as_str()
            );
            #[cfg(not(target_os = "none"))]
            let _ = error;
        }
    }

    fn try_install_default_standard_handles(&self) -> Result<()> {
        let open_default_device = |name: &str, rights: u32, cleanup: &[Handle]| -> Result<Handle> {
            self.cleanup_on_error(cleanup, self.open_device_handle(name, rights))
        };
        let bind_default_handle = |fd: FileDescriptor, handle: Handle, cleanup: &[Handle]| {
            self.cleanup_on_error(cleanup, self.bind_standard_handle(fd, handle))
        };

        let stdin = open_default_device(device::CONSOLE_DEVICE_NAME, HANDLE_RIGHT_READ, &[])?;
        let stdout = open_default_device(device::DEBUG_DEVICE_NAME, HANDLE_RIGHT_WRITE, &[stdin])?;
        let stderr = open_default_device(
            device::DEBUG_DEVICE_NAME,
            HANDLE_RIGHT_WRITE,
            &[stdin, stdout],
        )?;

        bind_default_handle(STDIN_FD, stdin, &[stdin, stdout, stderr])?;
        bind_default_handle(STDOUT_FD, stdout, &[stdout, stderr])?;
        bind_default_handle(STDERR_FD, stderr, &[stderr])?;

        Ok(())
    }

    fn release_termination_resources(&self) {
        // Detach any attached shared-memory segments from the global registry
        // and the hardware/software page tables before tearing down the address
        // space (no-op when the process never attached any segment).  This is
        // the caller documented by `kernel::shm::detach_all_for_process`.
        crate::kernel::shm::detach_all_for_process(self);
        self.clear_exec_runtime_state();
        self.clear_signal_runtime_state();
        *self.standard_handles.lock() = [None; STANDARD_FD_COUNT];
        self.fd_flags.lock().clear();
        self.fd_table.lock().clear();
        self.handle_table.lock().clear();
        self.children.lock().clear();
    }

    pub(crate) fn complete_termination(&self, reason: Option<TerminationReason>) {
        self.set_state(ProcessState::Terminated);
        // A reason recorded up front by `request_termination` (a remote
        // SIGKILL) must survive if the terminating thread has none of its
        // own to report.
        match reason {
            Some(reason) => self.record_termination_reason(Some(reason)),
            None if self.termination_reason.lock().is_none() => {
                self.record_termination_reason(None)
            }
            None => {}
        }
        self.termination_reaped.store(false, Ordering::Release);
        self.release_termination_resources();
        let _ = self.termination_event.signal();
    }

    /// Request termination of this process from a context that may be running
    /// on a different CPU than the process's own threads.
    ///
    /// Unlike [`complete_termination`](Self::complete_termination), this does
    /// **not** release the process's resources (fd table, address space,
    /// shared-memory segments) from the caller's context — doing so would
    /// race with a thread still executing on another CPU.  Threads that are
    /// not currently running are terminated immediately; a running thread is
    /// flagged to self-terminate at its next scheduler boundary, where the
    /// resource teardown runs in its own context.
    pub(crate) fn request_termination(&self, reason: Option<TerminationReason>) {
        if self.is_terminated() {
            return;
        }
        if let Some(reason) = reason {
            self.record_termination_reason(Some(reason));
        }
        self.set_state(ProcessState::Terminated);
        self.termination_reaped.store(false, Ordering::Release);

        let mut running_present = false;
        let mut scanned = false;
        if let Some(scheduler) = crate::kernel::process::Scheduler::global() {
            let mut running = false;
            crate::kernel::smp::for_each_percpu_scheduler(|_cpu_id, sched| {
                running |= sched.terminate_threads_of_process(self).running_present;
            });
            // Single-CPU (or before per-CPU schedulers are registered): the
            // primary scheduler holds the process's threads.
            if crate::kernel::smp::online_cpu_count() <= 1 {
                running |= scheduler.terminate_threads_of_process(self).running_present;
            }
            running_present = running;
            scanned = true;
        }

        if !scanned || !running_present {
            // No global scheduler (host unit tests) or no thread is currently
            // executing: nothing can be racing with us, so finishing the
            // termination here is safe.
            self.complete_termination(reason);
        }
    }

    fn clear_signal_runtime_state(&self) {
        *self.signal_handlers.lock() = [None; 32];
        self.signal_queue.with_lock(|state, waiters| {
            state.pending.clear();
            waiters.clear();
        });
    }

    fn clear_exec_runtime_state(&self) {
        *self.current_working_dir.lock() = resolve_home_dir(self.security_token.lock().user_id);
        *self.home_dir.lock() = resolve_home_dir(self.security_token.lock().user_id);
        *self.launch_context.lock() = None;
        // Unregister user pages from the software page table before dropping
        // the address space, so stale entries don't persist.
        // Take the lock once and hold it for both read and clear.
        {
            let mut guard = self.user_address_space.lock();
            if let Some(addr_space) = guard.as_ref() {
                if let Some((start, end)) = addr_space.user_page_va_range() {
                    let len = end.saturating_sub(start);
                    if let Some(mut memory) = crate::kernel::memory::global_mut() {
                        memory.unregister_user_page_range(start, len);
                    }
                }
            }
            // Transfer the address space into the process's deferred-drop slot
            // so it can be freed later when interrupts are enabled (e.g. during
            // reap by the parent), rather than inside the trap handler where
            // the heap allocator may deadlock with interrupts disabled.
            *self.deferred_user_address_space_drop.lock() = guard.take();
        }
    }

    // ── Fork ────────────────────────────────────────────────────────────

    /// Fork this process: create a child with a cloned address space where
    /// writable pages become Copy-on-Write (shared read-only).
    ///
    /// Returns the child process whose address space is already installed.
    /// The caller must pass a freshly allocated `child_pid` (PID 0 is not a
    /// valid process identity and would corrupt the parent's child table and
    /// the fork return value), then create a child user thread and register
    /// the child process with the scheduler.
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    pub fn fork(
        self: &Arc<Process>,
        memory: &mut crate::kernel::memory::MemoryManager,
        child_pid: u32,
    ) -> Result<Arc<Process>> {
        use crate::kernel::memory::paging::MappingKind;
        use crate::kernel::memory::paging::PagePermissions;

        self.ensure_mutable()?;

        // Fork only supports single-threaded processes in this prototype.
        if self.threads.lock().len() != 1 {
            return Err(Error::Busy);
        }

        // ── 1. Create child process ──────────────────────────────────
        let child_name = {
            let mut name = self.name.lock().clone();
            name.push_str("-fork");
            name
        };
        let child =
            Process::new_with_security_token(child_pid, &child_name, *self.security_token.lock());

        // ── 2. Clone FDs ─────────────────────────────────────────────
        {
            let parent_fd_table = self.fd_table.lock();
            let parent_fd_flags = self.fd_flags.lock();
            let fds: Vec<(FileDescriptor, Handle, FdFlags)> = parent_fd_table
                .iter()
                .map(|(&fd, &handle)| {
                    let flags = parent_fd_flags.get(&fd).copied().unwrap_or(FdFlags::NONE);
                    (fd, handle, flags)
                })
                .collect();
            drop(parent_fd_flags);
            drop(parent_fd_table);

            for (_fd, parent_handle, flags) in &fds {
                let entry = self.handle_entry(*parent_handle)?;
                let child_handle = entry.reopen_handle_in(&child)?;
                let child_fd = child.install_fd_handle(child_handle)?;
                if *flags != FdFlags::NONE {
                    child.fd_flags.lock().insert(child_fd, *flags);
                }
            }
        }

        // Clone launch context, cwd, and home_dir.
        if let Some(launch) = self.launch_context.lock().as_ref() {
            child.configure_launch(launch.clone());
        }
        child.set_current_working_dir(&self.current_working_dir());
        *child.home_dir.lock() = self.home_dir.lock().clone();

        // ── 3. Fork address space ────────────────────────────────────
        let (child_addr_space, shared_pages, all_child_pages) = {
            let mut parent_addr_space = self.user_address_space.lock();
            let parent_space = parent_addr_space.as_mut().ok_or(Error::InvalidArgument)?;
            let prepared = parent_space
                .prepared_process_address_space_mut()
                .ok_or(Error::InvalidArgument)?;
            prepared.fork_clone().ok_or(Error::InvalidArgument)?
        };

        // ── 4. Register in software page table ───────────────────────
        // CoW-shared pages.
        let mut child_cow_entries: Vec<(usize, usize, PagePermissions, MappingKind)> =
            Vec::with_capacity(shared_pages.len());
        for &(va, pa, _perms) in &shared_pages {
            child_cow_entries.push((va, pa, PagePermissions::READ, MappingKind::Cow));
            // Update parent software mapping: Anonymous → Cow, RW → R.
            memory
                .page_table_mut()
                .replace_mapping_kind(va, MappingKind::Cow)
                .ok();
            memory
                .page_table_mut()
                .replace_mapping_permissions(va, PagePermissions::READ)
                .ok();
            // Refcounting: the shared frame is now tracked by both
            // parent and child.  Each gets a reference so the count
            // starts at 2; when both have CoW-faulted (or exited)
            // the count reaches 0 and the frame is freed.
            memory.inc_frame_refcount(pa); // parent's reference
            memory.inc_frame_refcount(pa); // child's reference
                                           // Remove frame from parent's PreparedUserPage list (transfer
                                           // ownership to the refcount table).
            {
                let mut parent_addr_space = self.user_address_space.lock();
                if let Some(parent_space) = parent_addr_space.as_mut() {
                    if let Some(prepared) = parent_space.prepared_process_address_space_mut() {
                        prepared.remove_user_page_frame(va);
                    }
                }
            }
        }

        // Non-CoW pages (DemandPaged code pages, read-only data).  Pages the
        // parent already shares CoW with one of its own ancestors (inherited
        // from a prior fork) must stay CoW in the grandchild and gain one more
        // reference to the shared frame; re-registering them as
        // Anonymous/DemandPaged would undercount the holders and let a later
        // teardown skip the CoW refcount release.
        for &(va, pa, perms) in &all_child_pages {
            if shared_pages.iter().any(|(v, _, _)| *v == va) {
                continue;
            }
            if let Some((_, _, MappingKind::Cow)) = memory.page_table().lookup_mapping(va) {
                memory.inc_frame_refcount(pa); // grandchild's reference
                child_cow_entries.push((va, pa, PagePermissions::READ, MappingKind::Cow));
                continue;
            }
            let kind = if perms.contains(PagePermissions::EXECUTE) {
                MappingKind::DemandPaged
            } else {
                MappingKind::Anonymous
            };
            memory.register_user_pages(&[(va, pa, perms, kind)]);
        }

        // Register CoW entries.
        memory.register_user_pages(&child_cow_entries);

        // ── 5. Install child address space ───────────────────────────
        let child_user_addr_space =
            ProcessUserAddressSpace::from_prepared_process(child_addr_space);
        child.install_user_address_space(child_user_addr_space);

        Ok(child)
    }
}
