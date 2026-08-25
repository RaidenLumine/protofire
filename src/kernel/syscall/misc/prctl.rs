//! src/kernel/syscall/misc/prctl.rs
//!
//! prctl — process control operations (syscall #130).
//!
//! Provides a minimal subset of Linux-style prctl operations:
//! name, dumpable, keepcaps, no_new_privs.

use crate::Error;
use crate::Result;

// ── prctl operation codes ──────────────────────────────────────────────

/// Get the current process's dumpable flag.
const PR_GET_DUMPABLE: i32 = 3;
/// Set the current process's dumpable flag.
const PR_SET_DUMPABLE: i32 = 4;
/// Get the current process's keepcaps flag.
const PR_GET_KEEPCAPS: i32 = 7;
/// Set the current process's keepcaps flag.
const PR_SET_KEEPCAPS: i32 = 8;
/// Get the current process's no_new_privs flag.
const PR_GET_NO_NEW_PRIVS: i32 = 38;
/// Set the current process's no_new_privs flag.
const PR_SET_NO_NEW_PRIVS: i32 = 39;
/// Get the current process name.
const PR_GET_NAME: i32 = 15;
/// Set the current process name (max 16 bytes).
const PR_SET_NAME: i32 = 16;

/// Maximum process name length (matching Linux TASK_COMM_LEN).
const PR_MAX_NAME_LEN: usize = 16;

pub(super) fn prctl(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let option = context.arg(0) as i32;
    let arg2 = context.arg(1);
    let arg3 = context.arg(2);

    match option {
        PR_GET_DUMPABLE => {
            super::validate_zeroed_args(context, 1)?;
            let dumpable = super::runtime::current_process()
                .map(|p| p.dumpable())
                .unwrap_or(1);
            Ok(super::SyscallDispatch::complete(dumpable as usize))
        }
        PR_SET_DUMPABLE => {
            super::validate_zeroed_args(context, 2)?;
            let val = arg2 as u8;
            if val > 1 {
                return Err(Error::InvalidArgument);
            }
            if let Ok(process) = super::runtime::current_process() {
                process.set_dumpable(val);
            }
            Ok(super::SyscallDispatch::complete(0))
        }
        PR_GET_KEEPCAPS => {
            super::validate_zeroed_args(context, 1)?;
            let keepcaps = super::runtime::current_process()
                .map(|p| p.keepcaps())
                .unwrap_or(false);
            Ok(super::SyscallDispatch::complete(keepcaps as usize))
        }
        PR_SET_KEEPCAPS => {
            super::validate_zeroed_args(context, 2)?;
            let val = arg2 != 0;
            if let Ok(process) = super::runtime::current_process() {
                process.set_keepcaps(val);
            }
            Ok(super::SyscallDispatch::complete(0))
        }
        PR_GET_NO_NEW_PRIVS => {
            super::validate_zeroed_args(context, 1)?;
            let no_new_privs = super::runtime::current_process()
                .map(|p| p.no_new_privs())
                .unwrap_or(false);
            Ok(super::SyscallDispatch::complete(no_new_privs as usize))
        }
        PR_SET_NO_NEW_PRIVS => {
            super::validate_zeroed_args(context, 2)?;
            let val = arg2 != 0;
            if let Ok(process) = super::runtime::current_process() {
                process.set_no_new_privs(val);
            }
            Ok(super::SyscallDispatch::complete(0))
        }
        PR_GET_NAME => {
            let buf_ptr = arg2 as *mut u8;
            let buf_len = arg3;
            if buf_len == 0 {
                return Err(Error::InvalidArgument);
            }
            let name = super::runtime::current_process()
                .map(|p| p.name())
                .unwrap_or_default();
            let copy_len = name.len().min(buf_len - 1);

            // Validate output buffer.
            super::user_memory::validate_current_process_user_output_buffer(
                buf_ptr, buf_len, buf_len,
            )?;

            // Write name (without trailing null).
            if copy_len > 0 {
                super::user_memory::copy_user_bytes(name.as_bytes(), buf_ptr, copy_len)?;
            }
            // Write null terminator.
            super::user_memory::with_user_access_guard(|| unsafe {
                buf_ptr.add(copy_len).write(0u8);
            });
            Ok(super::SyscallDispatch::complete(copy_len))
        }
        PR_SET_NAME => {
            let buf_ptr = arg2 as *const u8;
            let buf_len = arg3;
            if buf_len == 0 || buf_len > PR_MAX_NAME_LEN {
                return Err(Error::InvalidArgument);
            }
            // Read the user string.
            super::user_memory::validate_current_process_user_input_buffer(
                buf_ptr, buf_len, buf_len,
            )?;
            let name_bytes = super::user_memory::with_user_access_guard(|| {
                let mut buf = [0u8; PR_MAX_NAME_LEN];
                #[allow(clippy::needless_range_loop)]
                for i in 0..buf_len {
                    buf[i] = unsafe { buf_ptr.add(i).read() };
                }
                buf
            });
            // Truncate at first null byte.
            let null_pos = name_bytes[..buf_len]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(buf_len);
            if null_pos == 0 {
                return Err(Error::InvalidArgument);
            }
            let truncated = core::str::from_utf8(&name_bytes[..null_pos])
                .map_err(|_| Error::InvalidArgument)?;

            if let Ok(process) = super::runtime::current_process() {
                process.set_name(truncated);
            }
            Ok(super::SyscallDispatch::complete(0))
        }
        _ => Err(Error::NotImplemented),
    }
}
