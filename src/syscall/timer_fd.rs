//! src/syscall/timer_fd.rs
//!
//! timerfd — timer expiration notification file descriptor.
//!
//! Provides a file descriptor that becomes readable when a kernel timer
//! expires.  Supports both one-shot and periodic timers.
//!
//! # Syscall
//!
//! `TimerFd = 109`
//! - `arg(0)` = `expiry_delta: u64` — number of ticks from now to first expiry
//! - `arg(1)` = `interval_ticks: u64` — periodic interval (0 = one-shot)
//! - `arg(2)` = `flags: u32` — reserved (pass 0)

use alloc::sync::Arc;
use core::sync::atomic::AtomicU64;

use super::runtime;
use crate::kernel::process::process::types::TimerFdState;
use crate::kernel::process::wait::WaitQueue;
use crate::kernel::process::KernelObject;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::syscall::SyscallContext;
use crate::Result;

/// Handler for `TimerFd` syscall (#109).
///
/// Creates a timerfd, arms it with the given expiry and interval, and
/// returns a file descriptor.
pub fn timerfd(ctx: &mut SyscallContext) -> Result<crate::syscall::SyscallDispatch> {
    let expiry_delta = ctx.arg(0) as u64;
    let interval_ticks = ctx.arg(1) as u64;
    let _flags = ctx.arg(2) as u32;

    let current_tick = if let Some(sched) = crate::kernel::process::Scheduler::global() {
        sched.current_tick()
    } else {
        0
    };
    let expiry = if expiry_delta == 0 {
        0 // disarmed
    } else {
        current_tick.saturating_add(expiry_delta)
    };

    let state = Arc::new(TimerFdState {
        expiry: AtomicU64::new(expiry),
        interval: AtomicU64::new(interval_ticks),
        expirations: AtomicU64::new(0),
        wait_queue: WaitQueue::new(),
    });

    // Hand it to the tick that expires it.  The expiry check is process
    // state, so it lives in `kernel::process::timer_fd`; this side only makes
    // the timer and attaches it to a descriptor.
    if expiry > 0 {
        crate::kernel::process::timer_fd::register(&state);
    }

    let process = runtime::current_process()?;
    let fd = process.open_descriptor(KernelObject::TimerFd(state), HANDLE_RIGHT_READ)?;

    Ok(crate::syscall::SyscallDispatch::complete(fd))
}
