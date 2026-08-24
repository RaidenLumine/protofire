//! src/kernel/syscall/process/sigsuspend.rs
//!
//! SigSuspend syscall — atomically replace the signal mask and suspend the
//! calling thread until a signal is delivered, then restore the old mask.

use crate::abi::process as process_abi;
use crate::Result;

pub(super) fn sigsuspend(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let mask = context.arg(0) as u32;
    let flags = context.arg(1);

    super::validate_known_flags(flags, process_abi::PROCESS_SIGNAL_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 2)?;

    super::runtime::with_current_process(|process| {
        // Atomically install the caller's mask for the duration of the wait,
        // then restore the previous mask once a signal has been delivered.
        let old_mask = process.set_signal_mask(mask);
        let delivered = super::process_signal::wait_for_process_signal(
            process,
            process_abi::WAIT_SIGNAL_BLOCK_INDEFINITELY_TICKS as u64,
        );
        process.set_signal_mask(old_mask);

        delivered.map(|_| super::SyscallDispatch::complete(0))
    })
}

#[cfg(test)]
mod tests {
    use super::sigsuspend;
    use crate::abi::process::PROCESS_SIGNAL_KNOWN_FLAGS;
    use crate::kernel::syscall::{SyscallContext, SyscallNumber};
    use crate::Error;

    #[test]
    fn sigsuspend_rejects_unknown_flags() {
        let mut context =
            SyscallContext::new(SyscallNumber::SigSuspend as usize, [0, 1, 0, 0, 0, 0]);

        assert_eq!(sigsuspend(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn sigsuspend_rejects_non_zero_reserved_args() {
        let mut context = SyscallContext::new(
            SyscallNumber::SigSuspend as usize,
            [0, PROCESS_SIGNAL_KNOWN_FLAGS, 1, 0, 0, 0],
        );

        assert_eq!(sigsuspend(&mut context), Err(Error::InvalidArgument));
    }
}
