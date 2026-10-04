//! src/arch/riscv64/signal.rs
//!
//! Restoring the user context a signal frame recorded.
//!
//! This machine has no user-mode exception delivery yet, so it has no frame to
//! restore from and no trampoline that would call `SYS_SIGRETURN`.  The answer
//! is the machine's, which is why it is here rather than in the syscall layer:
//! when RISC-V grows the delivery path, this is the file that grows with it.

use crate::Result;

/// Restore this thread's saved user context from the signal frame at
/// `frame_ptr`.
pub fn restore_signal_frame(_frame_ptr: usize) -> Result<()> {
    Err(crate::Error::NotImplemented)
}
