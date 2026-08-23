//! src/kernel/syscall/launch_metadata.rs
//! Launch metadata syscalls exposing argv/env/cwd/app-id/path information.

use alloc::string::String;

use crate::kernel::process::LaunchContext;
use crate::{Error, Result};

pub(super) fn arg_count(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    launch_context_list_len_syscall(context, |launch| &launch.arguments)
}

pub(super) fn arg_value(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    launch_context_list_value_syscall(context, |launch| &launch.arguments)
}

pub(super) fn env_count(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    launch_context_list_len_syscall(context, |launch| &launch.environment)
}

pub(super) fn env_value(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    launch_context_list_value_syscall(context, |launch| &launch.environment)
}

pub(super) fn current_dir(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 2)?;
    let buffer_ptr = context.arg(0) as *mut u8;
    let buffer_len = context.arg(1);
    super::runtime::with_current_process(|process| {
        let value = process.current_working_dir();
        copy_user_string_value(&value, buffer_ptr, buffer_len)
    })
}

pub(super) fn app_id(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    launch_context_string_syscall(context, |launch| &launch.catalog_id)
}

pub(super) fn app_version(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    launch_context_string_syscall(context, |launch| &launch.version)
}

pub(super) fn image_path(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    launch_context_string_syscall(context, |launch| &launch.image_path)
}

pub(super) fn manifest_path(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    launch_context_string_syscall(context, |launch| &launch.manifest_path)
}

fn current_launch_context_list_len_or_zero<F>(select: F) -> Result<usize>
where
    F: FnOnce(&LaunchContext) -> &[String],
{
    // Count syscalls are tolerant: return 0 when launch metadata is absent.
    Ok(
        super::runtime::with_current_launch_context(|launch| Ok(select(launch).len()))?
            .unwrap_or(0),
    )
}

fn launch_context_list_len_syscall<F>(
    context: &super::SyscallContext,
    select: F,
) -> Result<super::SyscallDispatch>
where
    F: FnOnce(&LaunchContext) -> &[String],
{
    super::validate_zeroed_args(context, 0)?;
    Ok(super::SyscallDispatch::complete(
        current_launch_context_list_len_or_zero(select)?,
    ))
}

fn launch_context_list_value_syscall<F>(
    context: &super::SyscallContext,
    select: F,
) -> Result<super::SyscallDispatch>
where
    F: FnOnce(&LaunchContext) -> &[String],
{
    super::validate_zeroed_args(context, 3)?;
    let index = context.arg(0);
    let buffer_ptr = context.arg(1) as *mut u8;
    let buffer_len = context.arg(2);
    // Value syscalls are strict: missing launch context or OOB index is an error.
    super::runtime::require_current_launch_context(|launch| {
        let value = select(launch).get(index).ok_or(Error::NotFound)?;
        copy_user_string_value(value, buffer_ptr, buffer_len)
    })
}

fn launch_context_string_syscall<F>(
    context: &super::SyscallContext,
    select: F,
) -> Result<super::SyscallDispatch>
where
    F: FnOnce(&LaunchContext) -> &str,
{
    super::validate_zeroed_args(context, 2)?;
    let buffer_ptr = context.arg(0) as *mut u8;
    let buffer_len = context.arg(1);
    super::runtime::require_current_launch_context(|launch| {
        copy_user_string_value(select(launch), buffer_ptr, buffer_len)
    })
}

fn copy_user_string_value(
    value: &str,
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<super::SyscallDispatch> {
    // Shared helper preserves probe/copy behavior for all string-returning syscalls.
    super::user_memory::copy_user_bytes(value.as_bytes(), buffer_ptr, buffer_len)
        .map(super::SyscallDispatch::complete)
}

#[cfg(test)]
mod tests {
    use super::super::{test_support, SyscallContext, SyscallDispatch, SyscallNumber};
    use super::{app_id, arg_count, arg_value, current_dir, env_count};
    use crate::Error;

    #[test]
    fn launch_metadata_count_syscalls_return_zero_when_launch_context_is_absent() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("launch-metadata-count-absent");

        let mut arg_count_ctx =
            SyscallContext::new(SyscallNumber::ArgCount as usize, [0, 0, 0, 0, 0, 0]);
        assert_eq!(
            arg_count(&mut arg_count_ctx),
            Ok(SyscallDispatch::complete(0))
        );

        let mut env_count_ctx =
            SyscallContext::new(SyscallNumber::EnvCount as usize, [0, 0, 0, 0, 0, 0]);
        assert_eq!(
            env_count(&mut env_count_ctx),
            Ok(SyscallDispatch::complete(0))
        );
    }

    #[test]
    fn launch_metadata_value_syscalls_reject_absent_launch_context() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("launch-metadata-value-absent");

        let mut arg_value_ctx =
            SyscallContext::new(SyscallNumber::ArgValue as usize, [0, 0, 0, 0, 0, 0]);
        assert_eq!(arg_value(&mut arg_value_ctx), Err(Error::NotFound));

        let mut app_id_ctx = SyscallContext::new(SyscallNumber::AppId as usize, [0, 0, 0, 0, 0, 0]);
        assert_eq!(app_id(&mut app_id_ctx), Err(Error::NotFound));

        let mut cwd_ctx =
            SyscallContext::new(SyscallNumber::CurrentDir as usize, [0, 0, 0, 0, 0, 0]);
        // current_dir resolves from the process cwd (always present), so a
        // zero-length buffer is answered as a size probe — never NotFound.
        assert!(current_dir(&mut cwd_ctx).is_ok());
    }
}
