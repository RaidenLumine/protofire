//! src/arch/riscv64/signal.rs
//!
//! Restoring the user context a signal frame recorded.
//!
//! An async signal is delivered by writing a
//! [`crate::abi::process::RiscV64SignalFrame`] on the user stack and letting
//! the handler's trampoline call `SYS_SIGRETURN` with a pointer to it (see
//! `try_async_signal_delivery_riscv64`) — the same shape the other two
//! architectures use.  This is where the frame's SEPC, user stack pointer and
//! SSTATUS become the thread's user context again; the trap path applies them
//! on the way out, and it is also where they are validated, so a frame that
//! was tampered with cannot put the core back into supervisor mode.
//!
//! The live trap frame is deliberately not captured on this path: the `ecall`
//! that reaches here belongs to the trampoline, so its SEPC is inside the
//! trampoline rather than at the interrupted instruction.  See
//! `SyscallAction::SigReturn` in the capture-point policy.

use crate::abi::process::RiscV64SignalFrame;
use crate::syscall::table::runtime::with_current_thread;
use crate::syscall::table::user_memory::read_user_value;
use crate::Result;

/// Restore this thread's saved user context from the signal frame at
/// `frame_ptr`.
pub fn restore_signal_frame(frame_ptr: usize) -> Result<()> {
    let size = core::mem::size_of::<RiscV64SignalFrame>();
    let frame: RiscV64SignalFrame = read_user_value(frame_ptr as *const u8, size, size)?;

    with_current_thread(|thread| {
        let mut user_ctx = thread
            .riscv64_user_context()
            .ok_or(crate::Error::InternalError)?;
        // Every register the handler was free to clobber — including `x2`,
        // which is this machine's stack pointer — then where the interrupted
        // code was.
        user_ctx.set_regs(frame.regs);
        user_ctx.instruction_pointer = frame.orig_sepc;
        user_ctx.saved_program_status = frame.orig_sstatus;
        thread.set_riscv64_user_context(user_ctx);
        Ok(())
    })
}
