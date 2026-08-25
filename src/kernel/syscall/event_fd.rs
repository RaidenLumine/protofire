//! src/kernel/syscall/event_fd.rs
//!
//! eventfd — lightweight event notification file descriptor.
//!
//! Mirrors Linux `eventfd2()` semantics:
//! - `read()`  returns a u64 counter value and resets it (or decrements in
//!   semaphore mode).
//! - `write()` adds an 8-byte u64 value to the counter and wakes waiters.
//! - poll `POLLIN` is asserted when the counter is non-zero.
//! - poll `POLLOUT` is always asserted (counter cannot saturate in practice).
//!
//! # Syscall
//!
//! `EventFd = 107`
//! - `arg(0)` = `initval: u32` — initial counter value
//! - `arg(1)` = `flags: u32`   — `EFD_SEMAPHORE` (1), `EFD_NONBLOCK` (2),
//!   `EFD_CLOEXEC` (4)

use alloc::sync::Arc;
use core::sync::atomic::AtomicU64;

use super::runtime;
use crate::kernel::process::process::types::EventFdState;
use crate::kernel::process::{FdFlags, KernelObject, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE};
use crate::kernel::sync::wait::WaitQueue;
use crate::kernel::syscall::SyscallContext;
use crate::{Error, Result};

// ABI flag bits.  EFD_SEMAPHORE/EFD_NONBLOCK are only referenced by the unit
// tests below — the eventfd read path interprets the raw flags through the
// types module's own constants — so they are gated to test builds.
#[cfg(test)]
pub const EFD_SEMAPHORE: u32 = crate::kernel::process::process::types::EFD_SEMAPHORE;
#[cfg(test)]
pub const EFD_NONBLOCK: u32 = crate::kernel::process::process::types::EFD_NONBLOCK;
pub const EFD_CLOEXEC: u32 = crate::kernel::process::process::types::EFD_CLOEXEC;
const EFD_KNOWN_FLAGS: u32 = crate::kernel::process::process::types::EFD_KNOWN_FLAGS;

/// Reject unknown flag bits (Linux `eventfd2` returns `EINVAL` for these).
fn validate_flags(flags: u32) -> Result<()> {
    if flags & !EFD_KNOWN_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handler for `EventFd` syscall (#107).
///
/// Creates an eventfd object and returns a file descriptor.
///
/// - `EFD_SEMAPHORE` — reads return 1 and decrement the counter by one.
/// - `EFD_NONBLOCK` — reads of a zero counter report `Busy` (EAGAIN) instead of
///   blocking.
/// - `EFD_CLOEXEC` — the descriptor is marked close-on-exec.
pub fn eventfd(ctx: &mut SyscallContext) -> Result<crate::kernel::syscall::SyscallDispatch> {
    let initval = ctx.arg(0) as u32;
    let flags = ctx.arg(1) as u32;
    validate_flags(flags)?;

    let state = Arc::new(EventFdState {
        counter: AtomicU64::new(initval as u64),
        wait_queue: WaitQueue::new(),
        flags,
    });

    runtime::with_current_process(|process| {
        let fd = process.open_descriptor(
            KernelObject::EventFd(state.clone()),
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )?;
        if flags & EFD_CLOEXEC != 0 {
            process.set_fd_flags(fd, FdFlags::CLOEXEC, FdFlags::NONE)?;
        }
        Ok(crate::kernel::syscall::SyscallDispatch::complete(fd))
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::*;
    use crate::kernel::syscall::table::SyscallNumber;

    #[test]
    fn known_flag_bits_are_accepted() {
        assert!(validate_flags(0).is_ok());
        assert!(validate_flags(EFD_SEMAPHORE).is_ok());
        assert!(validate_flags(EFD_NONBLOCK).is_ok());
        assert!(validate_flags(EFD_CLOEXEC).is_ok());
        assert!(validate_flags(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC).is_ok());
    }

    #[test]
    fn unknown_flag_bits_are_rejected() {
        assert_eq!(validate_flags(8), Err(Error::InvalidArgument));
        assert_eq!(validate_flags(1 << 31), Err(Error::InvalidArgument));
    }

    #[test]
    fn eventfd_syscall_creates_fd_and_applies_cloexec() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("eventfd-create");
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::EventFd as usize,
            [5, EFD_CLOEXEC as usize, 0, 0, 0, 0],
        );
        let result = eventfd(&mut context).expect("eventfd create should succeed");
        let fd = result.value as crate::kernel::process::FileDescriptor;

        // The descriptor is bound and carries the close-on-exec flag.
        let flags = process
            .get_fd_flags(fd)
            .expect("created fd should have flags");
        assert!(flags.contains(FdFlags::CLOEXEC), "EFD_CLOEXEC must apply");
    }

    #[test]
    fn eventfd_syscall_without_cloexec_leaves_fd_inheritable() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("eventfd-inherit");
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::EventFd as usize,
            [0, 0, 0, 0, 0, 0],
        );
        let result = eventfd(&mut context).expect("eventfd create should succeed");
        let fd = result.value as crate::kernel::process::FileDescriptor;
        let flags = process
            .get_fd_flags(fd)
            .expect("created fd should have flags");
        assert!(!flags.contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn eventfd_syscall_rejects_unknown_flags() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("eventfd-badflags");
        let mut context = crate::kernel::syscall::SyscallContext::new(
            SyscallNumber::EventFd as usize,
            [0, 16, 0, 0, 0, 0],
        );
        assert_eq!(eventfd(&mut context), Err(Error::InvalidArgument));
    }
}
