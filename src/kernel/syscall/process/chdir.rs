//! src/kernel/syscall/process/chdir.rs
//! SetCurrentDir syscall handler.

use crate::kernel::process::Process;
use crate::Result;

pub(super) fn set_current_dir(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let path_ptr = context.arg(0) as *const u8;
    let path_len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;
    let path = super::user_memory::user_string(path_ptr, path_len)?;
    super::runtime::with_current_process(|process: &Process| {
        process.set_current_working_dir(&path);
        Ok(super::SyscallDispatch::complete(0))
    })
}
