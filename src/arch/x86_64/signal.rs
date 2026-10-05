//! src/arch/x86_64/signal.rs
//!
//! Restoring the user context a signal frame recorded.
//!
//! The frame is the ABI record `SYS_SIGRETURN` is handed a pointer to
//! ([`crate::abi::process::SignalFrame`]); what the machine does with it is
//! its own, and this is where x86_64 does it: the saved instruction pointer,
//! stack pointer and flags become the thread's user context, which the trap
//! path applies on the way out.

use crate::abi::process::SignalFrame;
use crate::syscall::table::runtime::with_current_thread;
use crate::syscall::table::user_memory::read_user_value;
use crate::Result;

/// Restore this thread's saved user context from the signal frame at
/// `frame_ptr`.
pub fn restore_signal_frame(frame_ptr: usize) -> Result<()> {
    let size = core::mem::size_of::<SignalFrame>();
    let frame: SignalFrame = read_user_value(frame_ptr as *const u8, size, size)?;

    with_current_thread(|thread| {
        let mut user_ctx = thread
            .x86_64_user_context()
            .ok_or(crate::Error::InternalError)?;
        // Every register the handler was free to clobber, then the three words
        // that say where the interrupted code was.
        user_ctx.set_regs(frame.regs);
        user_ctx.instruction_pointer = frame.orig_rip;
        user_ctx.rflags = frame.orig_rflags;
        user_ctx.stack_pointer = frame.orig_rsp;
        thread.set_x86_64_user_context(user_ctx);
        Ok(())
    })
}
