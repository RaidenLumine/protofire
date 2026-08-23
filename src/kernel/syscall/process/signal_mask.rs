//! src/kernel/syscall/process/signal_mask.rs
//! SetSignalMask syscall — get/set the per-process POSIX signal mask.

use crate::abi::process as process_abi;
use crate::Result;

pub(super) fn set_signal_mask(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let mask = context.arg(0) as u32;
    let flags = context.arg(1);

    super::validate_known_flags(flags, process_abi::PROCESS_SIGNAL_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 2)?;

    let old_mask =
        super::runtime::with_current_process(|process| Ok(process.set_signal_mask(mask)))?;
    Ok(super::SyscallDispatch::complete(old_mask as usize))
}

#[cfg(test)]
mod tests {
    use super::set_signal_mask;
    use crate::abi::process::PROCESS_SIGNAL_KNOWN_FLAGS;
    use crate::kernel::syscall::{SyscallContext, SyscallNumber};

    #[test]
    fn set_signal_mask_rejects_unknown_flags() {
        let mut context =
            SyscallContext::new(SyscallNumber::SetSignalMask as usize, [0, 1, 0, 0, 0, 0]);

        assert_eq!(
            set_signal_mask(&mut context),
            Err(crate::Error::InvalidArgument)
        );
    }

    #[test]
    fn set_signal_mask_rejects_non_zero_reserved_args() {
        let mut context = SyscallContext::new(
            SyscallNumber::SetSignalMask as usize,
            [0, PROCESS_SIGNAL_KNOWN_FLAGS, 1, 0, 0, 0],
        );

        assert_eq!(
            set_signal_mask(&mut context),
            Err(crate::Error::InvalidArgument)
        );
    }
}
