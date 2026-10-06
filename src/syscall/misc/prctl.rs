//! src/syscall/misc/prctl.rs
//!
//! prctl — process control operations (syscall #130).
//!
//! Provides a minimal subset of Linux-style prctl operations:
//! name, dumpable, keepcaps, no_new_privs.

use crate::Error;
use crate::Result;

// The operation codes are the ABI's, not this file's: user space has to pass
// the same numbers, and the mirror in `src/user/shared/abi/prctl.rs` is what
// lets it name them instead of spelling them.
use crate::abi::prctl::PR_GET_DUMPABLE;
use crate::abi::prctl::PR_GET_KEEPCAPS;
use crate::abi::prctl::PR_GET_NAME;
use crate::abi::prctl::PR_GET_NO_NEW_PRIVS;
use crate::abi::prctl::PR_MAX_NAME_LEN;
use crate::abi::prctl::PR_SET_DUMPABLE;
use crate::abi::prctl::PR_SET_KEEPCAPS;
use crate::abi::prctl::PR_SET_NAME;
use crate::abi::prctl::PR_SET_NO_NEW_PRIVS;

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
            // `copy_user_bytes` opens the access window for its own copy, so
            // this byte does not need a window of its own — the output buffer
            // was validated for `buf_len` bytes above and `copy_len` is at most
            // `buf_len - 1`, so the byte is inside the validated range.
            // SAFETY: the output buffer was validated for `buf_len` bytes above
            // and `copy_len` is at most `buf_len - 1`, so the byte this points
            // at is inside the validated range.
            let terminator = unsafe { buf_ptr.add(copy_len) };
            super::user_memory::copy_user_bytes(&[0u8], terminator, 1)?;
            Ok(super::SyscallDispatch::complete(copy_len))
        }
        PR_SET_NAME => {
            let buf_ptr = arg2 as *const u8;
            let buf_len = arg3;
            if buf_len == 0 || buf_len > PR_MAX_NAME_LEN {
                return Err(Error::InvalidArgument);
            }
            // Read the user string into kernel memory.  The window belongs to
            // that copy, and `buf_len` is bounded by `PR_MAX_NAME_LEN`, which
            // is far inside the staged buffer.
            let name_bytes = super::user_memory::with_staged_input(buf_ptr, buf_len, |staged| {
                let mut buf = [0u8; PR_MAX_NAME_LEN];
                buf[..buf_len].copy_from_slice(staged);
                Ok(buf)
            })?;
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
