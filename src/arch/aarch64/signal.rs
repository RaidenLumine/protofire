//! src/arch/aarch64/signal.rs
//!
//! Restoring the user context a signal frame recorded.
//!
//! AArch64 delivers an async signal by writing an
//! [`crate::abi::process::AArch64SignalFrame`] on the user stack and letting
//! the handler's trampoline call `SYS_SIGRETURN` with a pointer to it (see
//! `try_async_signal_delivery_aarch64`), which is the same shape x86_64 uses.
//! This is where the frame's three words of exception-return state become the
//! thread's user context again; the trap path applies them on the way out.
//!
//! The state that must *not* be captured back is the syscall trap itself: the
//! `svc` that reaches here was executed by the trampoline, so the live frame
//! describes the trampoline and not the code the signal interrupted.
//! Capturing it would overwrite the restore that was just asked for, which is
//! why the syscall layer reports `SigReturn` as a capture point to skip.

use crate::abi::process::AArch64SignalFrame;
use crate::syscall::table::runtime::with_current_thread;
use crate::syscall::table::user_memory::read_user_value;
use crate::Result;

/// Restore this thread's saved user context from the signal frame at
/// `frame_ptr`.
pub fn restore_signal_frame(frame_ptr: usize) -> Result<()> {
    let size = core::mem::size_of::<AArch64SignalFrame>();
    let frame: AArch64SignalFrame = read_user_value(frame_ptr as *const u8, size, size)?;

    with_current_thread(|thread| {
        let mut user_ctx = thread
            .aarch64_user_context()
            .ok_or(crate::Error::InternalError)?;
        // Every register the handler was free to clobber, then the three words
        // that say where the interrupted code was.
        user_ctx.set_regs(frame.regs);
        user_ctx.instruction_pointer = frame.orig_elr;
        user_ctx.stack_pointer = frame.orig_sp;
        user_ctx.saved_program_status = frame.orig_spsr;
        thread.set_aarch64_user_context(user_ctx);
        Ok(())
    })
}
