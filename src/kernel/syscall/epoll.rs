//! src/kernel/syscall/epoll.rs
//!
//! epoll syscall handlers (#118–#120).
//!
//! Provides event-driven I/O notification: epoll_create, epoll_ctl, epoll_wait.
//!
//! # Syscall overview
//!
//! | #    | Name          | Description                                |
//! |------|---------------|--------------------------------------------|
//! | 118  | `EpollCreate` | Create an epoll instance (returns fd)      |
//! | 119  | `EpollCtl`    | Control interest list (add/mod/del)        |
//! | 120  | `EpollWait`   | Wait for events on monitored fds           |

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;

use crate::kernel::process::process::types::EpollEvent;
use crate::kernel::process::process::types::EpollState;
use crate::kernel::process::process::types::KernelObject;
use crate::kernel::process::Process;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::kernel::sync::wait::plan_timed_wait;
use crate::kernel::sync::wait::TimedWaitPlan;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

use super::runtime;
use super::user_memory;

// ── Constants ──────────────────────────────────────────────────────────────

/// epoll_ctl operations.
pub(crate) const EPOLL_CTL_ADD: u32 = 1;
pub(crate) const EPOLL_CTL_DEL: u32 = 2;
pub(crate) const EPOLL_CTL_MOD: u32 = 3;

/// epoll event flags (bitmask compatible with epoll_event.events).
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
// const EPOLLERR: u32 = 0x008;
// const EPOLLHUP: u32 = 0x010;

// ── Epoll state ───────────────────────────────────────────────────────────

/// Size of the epoll event record returned to userspace.
const EPOLL_EVENT_SIZE: usize = 12; // u32 events + u64 data

impl EpollState {
    fn add_fd(&mut self, fd: usize, event: EpollEvent) -> Result<()> {
        if self.monitored.contains_key(&fd) {
            return Err(Error::AlreadyExists);
        }
        self.monitored.insert(fd, event);
        Ok(())
    }

    fn del_fd(&mut self, fd: usize) -> Result<()> {
        if self.monitored.remove(&fd).is_none() {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    fn mod_fd(&mut self, fd: usize, event: EpollEvent) -> Result<()> {
        if !self.monitored.contains_key(&fd) {
            return Err(Error::NotFound);
        }
        self.monitored.insert(fd, event);
        Ok(())
    }

    /// Probe all monitored fds for readiness, collecting ready events into
    /// the given buffer.  Returns the number of events collected.
    fn collect_ready(&self, process: &Process, events: &mut [u8]) -> usize {
        let mut count = 0;
        let mut offset = 0;
        for (fd, ep_event) in &self.monitored {
            if offset + EPOLL_EVENT_SIZE > events.len() {
                break;
            }
            let mut revents: u32 = 0;
            if ep_event.events & EPOLLIN != 0 {
                // Check readability via the handle entry.
                if let Ok(entry) = process.handle_entry(*fd as u64) {
                    if entry.is_readable().unwrap_or(false) {
                        revents |= EPOLLIN;
                    }
                }
            }
            if ep_event.events & EPOLLOUT != 0 {
                if let Ok(entry) = process.handle_entry(*fd as u64) {
                    if entry.is_writable().unwrap_or(false) {
                        revents |= EPOLLOUT;
                    }
                }
            }
            if revents != 0 {
                // Write epoll_event: u32 events + u64 data.
                let event_bytes = revents.to_ne_bytes();
                let data_bytes = ep_event.data.to_ne_bytes();
                events[offset..offset + 4].copy_from_slice(&event_bytes);
                events[offset + 4..offset + 12].copy_from_slice(&data_bytes);
                offset += EPOLL_EVENT_SIZE;
                count += 1;
            }
        }
        count
    }
}

// ── Syscall handlers ───────────────────────────────────────────────────────

/// EpollCreate (#118): Create an epoll instance.
///
/// Args: 0=flags(u32)
pub(super) fn epoll_create(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let _flags = context.arg(0) as u32;
    super::validate_zeroed_args(context, 1)?;

    let state = Arc::new(Mutex::new(EpollState {
        monitored: BTreeMap::new(),
    }));

    let fd = runtime::with_current_process(|process| {
        let handle = process.open_handle(KernelObject::Epoll(state.clone()), HANDLE_RIGHT_READ)?;
        process.install_fd_handle(handle)
    })?;

    Ok(super::SyscallDispatch::complete(fd))
}

/// EpollCtl (#119): Control an epoll instance's interest list.
///
/// Args: 0=epfd, 1=op(u32), 2=fd(usize), 3=event_ptr, 4=event_len
pub(super) fn epoll_ctl(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let epfd = context.arg(0);
    let op = context.arg(1) as u32;
    let fd = context.arg(2);
    let event_ptr = context.arg(3) as *const u8;
    let event_len = context.arg(4);

    super::validate_zeroed_args(context, 5)?;

    // Parse the epoll_event from userspace if provided.
    let event = if event_len >= EPOLL_EVENT_SIZE && !event_ptr.is_null() {
        let buf = user_memory::with_optional_input_slice(event_ptr, EPOLL_EVENT_SIZE, |buf| {
            let events =
                u32::from_ne_bytes(buf[..4].try_into().map_err(|_| Error::InvalidArgument)?);
            let data =
                u64::from_ne_bytes(buf[4..12].try_into().map_err(|_| Error::InvalidArgument)?);
            Ok(EpollEvent { events, data })
        })?;
        Some(buf)
    } else {
        None
    };

    let ep_state = {
        runtime::with_current_process(|process| {
            let (_handle, entry) = process.resolve_fd(epfd)?;
            match &entry.object {
                KernelObject::Epoll(s) => Ok(s.clone()),
                _ => Err(Error::InvalidArgument),
            }
        })
    }?;

    let mut state = ep_state.lock();
    match op {
        EPOLL_CTL_ADD => {
            let event = event.ok_or(Error::InvalidArgument)?;
            state.add_fd(fd, event)?;
        }
        EPOLL_CTL_DEL => {
            state.del_fd(fd)?;
        }
        EPOLL_CTL_MOD => {
            let event = event.ok_or(Error::InvalidArgument)?;
            state.mod_fd(fd, event)?;
        }
        _ => return Err(Error::Unsupported),
    }
    Ok(super::SyscallDispatch::complete(0))
}

/// EpollWait (#120): Wait for events on monitored fds.
///
/// Args: 0=epfd, 1=events_ptr(out), 2=events_len, 3=timeout_ticks(u64)
pub(super) fn epoll_wait(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let epfd = context.arg(0);
    let events_ptr = context.arg(1) as *mut u8;
    let events_len = context.arg(2);
    let timeout_ticks = context.arg(3) as u64;

    super::validate_zeroed_args(context, 4)?;

    if events_len < EPOLL_EVENT_SIZE {
        return Err(Error::InvalidArgument);
    }

    // Resolve the epoll instance.
    let ep_state = {
        runtime::with_current_process(|process| {
            let (_handle, entry) = process.resolve_fd(epfd)?;
            match &entry.object {
                KernelObject::Epoll(s) => Ok(s.clone()),
                _ => Err(Error::InvalidArgument),
            }
        })
    }?;

    let max_events = events_len / EPOLL_EVENT_SIZE;
    let mut buf = vec![0u8; max_events * EPOLL_EVENT_SIZE];

    // Phase 1: non-blocking probe.
    let mut ready = {
        runtime::with_current_process(|process| {
            let state = ep_state.lock();
            Ok(state.collect_ready(process, &mut buf))
        })
    }?;

    if ready > 0 || timeout_ticks == 0 {
        // Copy collected events to userspace.
        let copy_len = ready * EPOLL_EVENT_SIZE;
        user_memory::with_optional_output_slice(events_ptr, copy_len, |dst| {
            dst.copy_from_slice(&buf[..copy_len]);
            Ok(())
        })?;
        return Ok(super::SyscallDispatch::complete(ready));
    }

    // Phase 2: blocking wait.
    // For simplicity, use timer-based polling similar to poll().
    match plan_timed_wait(timeout_ticks) {
        TimedWaitPlan::Unavailable | TimedWaitPlan::ZeroTimeout => Err(Error::TimedOut),
        TimedWaitPlan::Deadline(_deadline) => {
            // Use a simple sleep loop to re-probe until timeout.
            let scheduler = runtime::global_scheduler()?;
            let deadline_tick = scheduler.current_tick().saturating_add(timeout_ticks);
            loop {
                let now = scheduler.current_tick();
                if now >= deadline_tick {
                    break;
                }
                // Sleep for a short interval then re-probe.
                let remaining = deadline_tick - now;
                let sleep_ticks = remaining.min(5); // max 5 ticks between probes
                crate::kernel::process::scheduler::api::sleep_current(sleep_ticks);
                // Re-probe.
                ready = {
                    runtime::with_current_process(|process| {
                        let state = ep_state.lock();
                        Ok(state.collect_ready(process, &mut buf))
                    })
                }?;
                if ready > 0 {
                    break;
                }
            }
            let copy_len = ready * EPOLL_EVENT_SIZE;
            user_memory::with_optional_output_slice(events_ptr, copy_len, |dst| {
                dst.copy_from_slice(&buf[..copy_len]);
                Ok(())
            })?;
            Ok(super::SyscallDispatch::complete(ready))
        }
    }
}
