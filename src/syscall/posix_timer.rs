//! src/syscall/posix_timer.rs
//!
//! Syscall handlers for POSIX per-process timers (#137–140).

use crate::kernel::process::posix_timer;
use crate::syscall::table::SyscallContext;
use crate::syscall::table::SyscallDispatch;
use crate::Result;

/// Bytes of the `itimerspec` the timer syscalls exchange: two `timespec`s of
/// two `i64`s each.
const ITIMERSPEC_SIZE: usize = 32;

/// Read the `i64` at `offset` of an `itimerspec` image the kernel copied out of
/// user memory.
fn spec_value(spec: &[u8], offset: usize) -> i64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&spec[offset..offset + 8]);
    i64::from_ne_bytes(bytes)
}

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

    // Parse itimerspec from user memory (3 u64s: value_sec, value_nsec,
    // interval_sec, interval_nsec). Layout: it_interval.tv_sec,
    // it_interval.tv_nsec, it_value.tv_sec, it_value.tv_nsec
    if new_value_ptr.is_null() {
        return Err(crate::Error::InvalidArgument);
    }

    // The image is validated against the process's own mappings and copied out
    // before it is decoded, so a pointer that names kernel memory is an error
    // rather than a read, and the decode never touches a user address itself.
    let spec: [u8; ITIMERSPEC_SIZE] =
        super::user_memory::read_user_value(new_value_ptr, ITIMERSPEC_SIZE, ITIMERSPEC_SIZE)?;

    let interval_sec = spec_value(&spec, 0);
    let interval_nsec = spec_value(&spec, 8);
    let value_sec = spec_value(&spec, 16);
    let value_nsec = spec_value(&spec, 24);

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

    // As `timer_settime`, in the other direction: the write goes through the
    // validated user-output path, so where it lands is checked before it
    // happens.
    let mut spec = [0u8; ITIMERSPEC_SIZE];
    spec[0..8].copy_from_slice(&int_sec.to_ne_bytes());
    spec[8..16].copy_from_slice(&int_nsec.to_ne_bytes());
    spec[16..24].copy_from_slice(&val_sec.to_ne_bytes());
    spec[24..32].copy_from_slice(&val_nsec.to_ne_bytes());
    super::user_memory::copy_user_bytes(&spec, value_ptr, ITIMERSPEC_SIZE)?;

    Ok(SyscallDispatch::complete(0))
}

/// timer_delete(timer_id) → 0 or error
pub fn timer_delete(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    let timer_id = ctx.arg(0) as posix_timer::TimerId;
    posix_timer::timer_delete(timer_id)?;
    Ok(SyscallDispatch::complete(0))
}
