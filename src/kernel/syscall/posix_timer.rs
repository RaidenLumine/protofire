//! src/kernel/syscall/posix_timer.rs
//!
//! Syscall handlers for POSIX per-process timers (#137–140).

use crate::kernel::process::posix_timer;
use crate::kernel::syscall::table::{SyscallContext, SyscallDispatch};
use crate::Result;

/// timer_create(clock_id, sevp) → timer_id
pub fn timer_create(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    let clock_id = ctx.arg(0) as u32;
    let _sevp = ctx.arg(1); // sigevent pointer (not yet used for full struct)

    // Get current PID via the scheduler.
    let pid = super::runtime::current_process_pid().unwrap_or(0);

    let timer_id = posix_timer::timer_create(pid, clock_id)?;
    Ok(SyscallDispatch::complete(timer_id as usize))
}

/// timer_settime(timer_id, flags, new_value, old_value) → 0 or error
pub fn timer_settime(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    let timer_id = ctx.arg(0) as posix_timer::TimerId;
    let flags = ctx.arg(1) as u32;
    let new_value_ptr = ctx.arg(2) as *const u8;

    // Parse itimerspec from user memory (3 u64s: value_sec, value_nsec, interval_sec, interval_nsec).
    // Layout: it_interval.tv_sec, it_interval.tv_nsec, it_value.tv_sec, it_value.tv_nsec
    if new_value_ptr.is_null() {
        return Err(crate::Error::InvalidArgument);
    }

    let interval_sec;
    let interval_nsec;
    let value_sec;
    let value_nsec;
    unsafe {
        let p = new_value_ptr;
        interval_sec = *(p as *const i64);
        interval_nsec = *(p.add(8) as *const i64);
        value_sec = *(p.add(16) as *const i64);
        value_nsec = *(p.add(24) as *const i64);
    }

    posix_timer::timer_settime(
        timer_id,
        flags,
        value_sec,
        value_nsec,
        interval_sec,
        interval_nsec,
    )?;

    // TODO: if old_value is non-null, write the previous timer state.
    Ok(SyscallDispatch::complete(0))
}

/// timer_gettime(timer_id, value) → 0 or error
pub fn timer_gettime(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    let timer_id = ctx.arg(0) as posix_timer::TimerId;
    let value_ptr = ctx.arg(1) as *mut u8;

    if value_ptr.is_null() {
        return Err(crate::Error::InvalidArgument);
    }

    let (val_sec, val_nsec, int_sec, int_nsec) = posix_timer::timer_gettime(timer_id)?;

    unsafe {
        let p = value_ptr;
        *(p as *mut i64) = int_sec;
        *(p.add(8) as *mut i64) = int_nsec;
        *(p.add(16) as *mut i64) = val_sec;
        *(p.add(24) as *mut i64) = val_nsec;
    }

    Ok(SyscallDispatch::complete(0))
}

/// timer_delete(timer_id) → 0 or error
pub fn timer_delete(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    let timer_id = ctx.arg(0) as posix_timer::TimerId;
    posix_timer::timer_delete(timer_id)?;
    Ok(SyscallDispatch::complete(0))
}
