//! src/kernel/syscall/signal_fd.rs
//!
//! signalfd — signal notification file descriptor.
//!
//! Mirrors Linux `signalfd()` semantics in the kernel's cooperative signal
//! model: a signalfd dequeues pending POSIX / cooperative signals that match
//! a user-specified mask, making them accessible via `read()` instead of
//! `wait_signal()`.
//!
//! # Syscall
//!
//! `SignalFd = 108`
//! - `arg(0)` = `sigset: u32` — bitmask of signals to catch (bit N = signal N)
//! - `arg(1)` = `flags: u32`  — reserved (pass 0)

use alloc::sync::Arc;

use super::runtime;
use crate::kernel::process::process::types::SignalFdState;
use crate::kernel::process::KernelObject;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::kernel::syscall::SyscallContext;
use crate::Result;

/// Handler for `SignalFd` syscall (#108).
///
/// Creates a signalfd object and returns a file descriptor.
pub fn signalfd(ctx: &mut SyscallContext) -> Result<crate::kernel::syscall::SyscallDispatch> {
    let sigset = ctx.arg(0) as u64;
    let _flags = ctx.arg(1) as u32;

    let process = runtime::current_process()?;

    let state = Arc::new(SignalFdState {
        sigset,
        process: Arc::downgrade(&process),
    });

    let fd = process.open_descriptor(KernelObject::SignalFd(state), HANDLE_RIGHT_READ)?;

    Ok(crate::kernel::syscall::SyscallDispatch::complete(fd))
}
