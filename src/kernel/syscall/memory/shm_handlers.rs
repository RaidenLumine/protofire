//! src/kernel/syscall/memory/shm_handlers.rs
//!
//! Syscall handlers for System V shared memory operations (#100-103).
//!
//! The segment engine lives in `crate::kernel::shm`; these handlers marshal
//! syscall arguments and user pointers and forward to it.

use crate::abi::shm as abi;
use crate::kernel::process::Process;
use crate::kernel::shm;
use crate::Error;
use crate::Result;

use super::runtime;
use super::user_memory;
use super::SyscallContext;
use super::SyscallDispatch;

/// shmget(key, size, flags) → shmid
pub(super) fn shmget(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let key = context.arg(0);
    let size = context.arg(1);
    let flags = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    runtime::with_current_process(|process: &Process| {
        let token = process.security_token();
        let shmid = shm::shmget(
            key,
            size,
            flags,
            process.pid(),
            token.user_id,
            token.primary_group_id,
        )?;
        Ok(SyscallDispatch::complete(shmid))
    })
}

/// shmat(shmid, addr_hint, flags) → virtual_address
pub(super) fn shmat(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let shmid = context.arg(0);
    let addr_hint = context.arg(1);
    let flags = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    runtime::with_current_process(|process: &Process| {
        let virtual_address = shm::shmat(shmid, addr_hint, flags, process)?;
        Ok(SyscallDispatch::complete(virtual_address))
    })
}

/// shmdt(shmid) → 0 on success
pub(super) fn shmdt(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let shmid = context.arg(0);
    super::validate_zeroed_args(context, 1)?;

    runtime::with_current_process(|process: &Process| {
        shm::shmdt(shmid, process)?;
        Ok(SyscallDispatch::complete(0))
    })
}

/// shmctl(shmid, cmd, buf) → 0 on success
///
/// `buf` points to a `ShmidDs` for `IPC_STAT` (kernel writes) and `IPC_SET`
/// (kernel reads); it is ignored for `IPC_RMID`.
pub(super) fn shmctl(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let shmid = context.arg(0);
    let cmd = context.arg(1);
    let buf_ptr = context.arg(2) as *mut u8;
    super::validate_zeroed_args(context, 3)?;

    let ds_size = core::mem::size_of::<abi::ShmidDs>();

    match cmd {
        abi::IPC_RMID => {
            shm::shmctl(shmid, cmd, None)?;
            Ok(SyscallDispatch::complete(0))
        }
        abi::IPC_STAT => {
            user_memory::validate_current_process_user_output_buffer(buf_ptr, ds_size, ds_size)?;
            let mut ds: abi::ShmidDs = unsafe { core::mem::zeroed() };
            shm::shmctl(shmid, cmd, Some(&mut ds))?;
            // `ds` was zeroed first, so every byte including padding is
            // initialised; safe to copy out as raw bytes.
            user_memory::with_optional_output_slice(buf_ptr, ds_size, |out| {
                // SAFETY: `out` is `ds_size` writable bytes and `ds` is fully
                // initialised with `#[repr(C)]` layout matching the ABI.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (&ds as *const abi::ShmidDs).cast::<u8>(),
                        out.as_mut_ptr(),
                        ds_size,
                    );
                }
                Ok(())
            })?;
            Ok(SyscallDispatch::complete(0))
        }
        abi::IPC_SET => {
            let mut ds: abi::ShmidDs = user_memory::read_user_value(buf_ptr, ds_size, ds_size)?;
            shm::shmctl(shmid, cmd, Some(&mut ds))?;
            Ok(SyscallDispatch::complete(0))
        }
        _ => Err(Error::InvalidArgument),
    }
}

#[cfg(test)]
mod tests {
    use super::shmat;
    use super::shmctl;
    use super::shmdt;
    use super::shmget;
    use crate::abi::shm::IPC_RMID;
    use crate::abi::shm::IPC_STAT;
    use crate::kernel::syscall::SyscallContext;
    use crate::kernel::syscall::SyscallNumber;
    use crate::Error;

    #[test]
    fn shmctl_rejects_unknown_command() {
        let mut context = SyscallContext::new(SyscallNumber::ShmCtl as usize, [0, 99, 0, 0, 0, 0]);

        assert_eq!(shmctl(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn shmctl_stat_requires_a_buffer() {
        let mut context =
            SyscallContext::new(SyscallNumber::ShmCtl as usize, [0, IPC_STAT, 0, 0, 0, 0]);

        assert_eq!(shmctl(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn shmctl_rmid_missing_segment_returns_not_found() {
        let mut context = SyscallContext::new(
            SyscallNumber::ShmCtl as usize,
            [0x1234, IPC_RMID, 0, 0, 0, 0],
        );

        assert_eq!(shmctl(&mut context), Err(Error::NotFound));
    }

    #[test]
    fn shmget_rejects_nonzero_trailing_args() {
        let mut context = SyscallContext::new(SyscallNumber::ShmGet as usize, [0, 0, 0, 1, 0, 0]);

        assert_eq!(shmget(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn shmat_rejects_nonzero_trailing_args() {
        let mut context = SyscallContext::new(SyscallNumber::ShmAt as usize, [0, 0, 0, 1, 0, 0]);

        assert_eq!(shmat(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn shmdt_rejects_nonzero_trailing_args() {
        let mut context = SyscallContext::new(SyscallNumber::ShmDt as usize, [0, 1, 0, 0, 0, 0]);

        assert_eq!(shmdt(&mut context), Err(Error::InvalidArgument));
    }
}
