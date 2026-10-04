//! src/arch/aarch64/signal.rs
//!
//! Restoring the user context a signal frame recorded.
//!
//! AArch64 delivers an async signal by writing an
//! [`crate::abi::process::AArch64SignalFrame`] on the user stack and letting
//! the handler's trampoline call `SYS_SIGRETURN` with a pointer to it (see
//! `try_async_signal_delivery_aarch64`), which is the same shape x86_64 uses.
//! The restore itself is not written yet: this answers `NotImplemented`, which
//! is the honest report of where the machine's half of `sigreturn` stands
//! rather than a rule the syscall layer should carry.

use crate::Result;

/// Restore this thread's saved user context from the signal frame at
/// `frame_ptr`.
pub fn restore_signal_frame(_frame_ptr: usize) -> Result<()> {
    Err(crate::Error::NotImplemented)
}
