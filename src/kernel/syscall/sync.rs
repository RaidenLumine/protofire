//! src/kernel/syscall/sync.rs
//! Global filesystem synchronization syscall handler (#180).
//!
//! `sync()` flushes every mounted filesystem's dirty block-cache data to the
//! underlying persistent storage — the explicit half of the "persistent
//! cache" durability story (the automatic half is the scheduler-driven aged
//! write-back).  Returns 0 on success.

use crate::Result;

use super::{SyscallContext, SyscallDispatch};

pub(super) fn sync(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    super::validate_zeroed_args(context, 1)?;
    crate::kernel::fs::sync_global_all().map(|()| SyscallDispatch::complete(0))
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "none"))]
    use super::super::test_support;
    use super::super::{SyscallContext, SyscallDispatch, SyscallNumber};
    use super::sync as sync_syscall;
    use crate::Error;

    #[test]
    fn sync_rejects_non_zero_reserved_args() {
        // arg0 = 0, but reserved arg1 is non-zero.
        let mut context = SyscallContext::new(SyscallNumber::Sync as usize, [0, 1, 0, 0, 0, 0]);
        assert_eq!(sync_syscall(&mut context), Err(Error::InvalidArgument));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn sync_flushes_global_filesystem_without_installed_fs() {
        // With no global filesystem installed, sync is a success no-op.
        let _guard = test_support::test_lock();
        {
            let (_scheduler, _process) = test_support::scheduled_current_process("sync-no-fs");
        }
        let mut context = SyscallContext::new(SyscallNumber::Sync as usize, [0, 0, 0, 0, 0, 0]);
        assert_eq!(sync_syscall(&mut context), Ok(SyscallDispatch::complete(0)));
    }
}
