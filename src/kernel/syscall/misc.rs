//! src/kernel/syscall/misc.rs
//! Misc syscall handlers such as yield, debug write, exit, and console read.

use crate::kernel::console;
use crate::util::debug;
use crate::{Error, Result};

pub(super) fn yield_now(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 0)?;
    // Yield is represented as a dispatch action so the trap path can reschedule.
    Ok(super::SyscallDispatch::yield_now())
}

pub(super) fn write_debug(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let buffer_ptr = context.arg(0) as *const u8;
    let length = context.arg(1);

    super::validate_zeroed_args(context, 2)?;
    super::user_memory::with_optional_input_slice(buffer_ptr, length, |buffer| {
        debug::write_bytes(buffer);
        Ok(())
    })?;
    Ok(super::SyscallDispatch::complete(length))
}

pub(super) fn exit(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 1)?;
    Ok(super::SyscallDispatch::exit(context.arg(0)))
}

/// Syscall 4: read_console(buffer, length) — read up to `length` bytes of
/// console input.  Blocks until at least one byte is available (no timeout
/// argument on this legacy syscall; the line-oriented ReadConsoleLine syscall
/// is preferred by the shell).
pub(super) fn read_console(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let buffer_ptr = context.arg(0) as *mut u8;
    let length = context.arg(1);

    super::validate_zeroed_args(context, 2)?;
    if length == 0 {
        return Ok(super::SyscallDispatch::complete(0));
    }

    let read = super::user_memory::with_optional_output_slice(buffer_ptr, length, |buffer| {
        Ok(console::init_global()
            .read_bytes_timeout(buffer, u64::MAX)
            .unwrap_or(0))
    })?;
    Ok(super::SyscallDispatch::complete(read))
}

/// Syscall 70: gettimeofday(out_ptr, len) — write a 16-byte `{tv_sec, tv_usec}`
/// pair (both u64) into the caller's buffer.
pub(super) fn gettimeofday(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *mut u8;
    let len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;
    if len < 16 {
        return Err(Error::InvalidArgument);
    }

    let secs = crate::arch::timer::rtc_now_unix().unwrap_or(0);
    // Approximate microseconds from the tick counter (100 Hz → 10 ms/tick).
    let usecs = crate::arch::timer::ticks() % 100 * 10_000;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&secs.to_ne_bytes());
    buf[8..16].copy_from_slice(&usecs.to_ne_bytes());

    super::user_memory::copy_user_bytes(&buf, ptr, 16)?;
    Ok(super::SyscallDispatch::complete(16))
}

/// Syscall 71: gethostname(out_ptr, len) — copy the kernel hostname.
pub(super) fn gethostname(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *mut u8;
    let len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;
    if len == 0 {
        return Ok(super::SyscallDispatch::complete(0));
    }

    let written = super::user_memory::with_optional_output_slice(ptr, len, |buffer| {
        Ok(crate::kernel::network::gethostname(buffer))
    })?;
    Ok(super::SyscallDispatch::complete(written))
}

/// Syscall 72: sethostname(name_ptr, name_len).
pub(super) fn sethostname(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *const u8;
    let len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;
    super::user_memory::with_optional_input_slice(ptr, len, |name| {
        crate::kernel::network::sethostname(name);
        Ok(())
    })?;
    Ok(super::SyscallDispatch::complete(len))
}

/// Syscall 75: getrandom(out_ptr, len) — fill the buffer with CSPRNG bytes.
pub(super) fn getrandom(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *mut u8;
    let len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;
    if len == 0 {
        return Ok(super::SyscallDispatch::complete(0));
    }

    super::user_memory::with_optional_output_slice(ptr, len, |buffer| {
        crate::kernel::random::fill_random(buffer);
        Ok(())
    })?;
    Ok(super::SyscallDispatch::complete(len))
}
