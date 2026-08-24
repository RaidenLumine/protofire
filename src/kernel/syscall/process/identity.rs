//! src/kernel/syscall/process/identity.rs
//!
//! Identity syscall handlers: getpid, getppid, getuid, getgid.

use crate::kernel::process::Process;
use crate::Result;

pub(super) fn getpid(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    super::super::validate_zeroed_args(context, 0)?;
    super::super::runtime::with_current_process(|process: &Process| {
        Ok(super::super::SyscallDispatch::complete(
            process.pid() as usize
        ))
    })
}

pub(super) fn getppid(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    super::super::validate_zeroed_args(context, 0)?;
    super::super::runtime::with_current_process(|process: &Process| {
        let ppid = process.parent_pid().unwrap_or(0);
        Ok(super::super::SyscallDispatch::complete(ppid as usize))
    })
}

pub(super) fn getuid(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    super::super::validate_zeroed_args(context, 0)?;
    super::super::runtime::with_current_process(|process: &Process| {
        let token = process.security_token();
        Ok(super::super::SyscallDispatch::complete(
            token.user_id as usize,
        ))
    })
}

pub(super) fn getgid(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    super::super::validate_zeroed_args(context, 0)?;
    super::super::runtime::with_current_process(|process: &Process| {
        let token = process.security_token();
        Ok(super::super::SyscallDispatch::complete(
            token.primary_group_id as usize,
        ))
    })
}
