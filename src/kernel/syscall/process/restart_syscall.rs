//! src/kernel/syscall/process/restart_syscall.rs
//!
//! RestartSyscall syscall — re-issue an interrupted blocking syscall.
//!
//! Registered for ABI completeness (syscall 136).  This kernel performs
//! automatic restart at the syscall-dispatch layer and does not maintain a
//! per-thread restart block, so the handler is a no-op that reports success.
//!
//! ## Why no restart block is needed
//!
//! On x86_64 the syscall ABI passes arguments in registers that live in the
//! trap frame, and those registers are preserved across the signal frame the
//! async-delivery path injects.  When a handler is installed with
//! `SA_RESTART`, [`try_async_signal_delivery`] rewinds the saved RIP by the
//! 2-byte length of `int 0x80`, so returning from the handler transparently
//! re-issues the syscall with its original registers.  Linux's
//! `restart_syscall` exists for the rarer case where a syscall *consumed* its
//! register arguments before blocking; this kernel has no such path, hence no
//! restart block.  (AArch64/RISC-V async delivery happens only on user-mode
//! IRQ frames — see the SA_RESTART notes in `src/arch/*/trap.rs` — so a real
//! restart block would only be needed when interruptible-syscall machinery is
//! added there.)

use crate::Result;

pub(super) fn restart_syscall(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    // No arguments — the restart block is purely kernel-internal and this
    // kernel has none, so the syscall simply reports success.
    let _ = context;
    Ok(super::SyscallDispatch::complete(0))
}

#[cfg(test)]
mod tests {
    use super::restart_syscall;
    use crate::kernel::syscall::{SyscallContext, SyscallDispatch, SyscallNumber};

    #[test]
    fn restart_syscall_is_a_successful_no_op() {
        let mut context =
            SyscallContext::new(SyscallNumber::RestartSyscall as usize, [0, 0, 0, 0, 0, 0]);
        assert_eq!(
            restart_syscall(&mut context),
            Ok(SyscallDispatch::complete(0))
        );
    }
}
