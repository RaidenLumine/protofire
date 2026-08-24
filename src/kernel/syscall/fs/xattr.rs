//! src/kernel/syscall/fs/xattr.rs
//!
//! Extended-attribute (xattr) and per-file data-reduction flag syscalls.
//!
//! # Syscalls
//!
//! - `SetXattr = 151`   — set an extended attribute (path, name, value).
//! - `GetXattr = 152`   — read an extended attribute value (path, name, out).
//! - `ListXattr = 153`  — list extended attribute names (path, out).
//! - `RemoveXattr = 154`— remove an extended attribute (path, name).
//! - `SetFileFlags = 155` — toggle per-file data-reduction flags (path, set, clear).
//! - `GetFileFlags = 156` — read per-file data-reduction flags (path).

use alloc::vec::Vec;

use crate::abi::fs as fs_abi;
use crate::{Error, Result};

use super::runtime::with_current_process_security_token_fs;
use super::user_memory::{copy_user_bytes, user_path_arg, with_optional_input_slice};
use super::{validate_known_flags, SyscallContext, SyscallDispatch};

/// Validate an xattr name: non-empty and within the ABI limit.
fn validate_xattr_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() > fs_abi::XATTR_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate an xattr value: within the ABI limit.
fn validate_xattr_value(value: &[u8]) -> Result<()> {
    if value.len() > fs_abi::XATTR_VALUE_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Set an extended attribute (#151).
///
/// `arg(0..1)` = path ptr/len; `arg(2..3)` = name ptr/len;
/// `arg(4..5)` = value ptr/len.  Returns 0 on success.
pub(super) fn set_xattr(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let path = user_path_arg(context, 0, 1)?;
    let name = with_optional_input_slice(context.arg(2) as *const u8, context.arg(3), |b| {
        Ok(b.to_vec())
    })?;
    let value = with_optional_input_slice(context.arg(4) as *const u8, context.arg(5), |b| {
        Ok(b.to_vec())
    })?;
    validate_xattr_name(&name)?;
    validate_xattr_value(&value)?;

    with_current_process_security_token_fs(|token, fs| {
        let normalized = fs.normalize_path(path)?;
        fs.set_xattr_for_normalized_path(&normalized, &name, &value, token)?;
        Ok(SyscallDispatch::complete(0))
    })
}

/// Read an extended attribute value (#152).
///
/// `arg(0..1)` = path; `arg(2..3)` = name; `arg(4..5)` = value out buffer.
/// Returns the value length; a zero-length out buffer probes the size.
pub(super) fn get_xattr(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let path = user_path_arg(context, 0, 1)?;
    let name = with_optional_input_slice(context.arg(2) as *const u8, context.arg(3), |b| {
        Ok(b.to_vec())
    })?;
    validate_xattr_name(&name)?;
    let value_out_ptr = context.arg(4) as *mut u8;
    let value_out_len = context.arg(5);

    let value = with_current_process_security_token_fs(|token, fs| {
        let normalized = fs.normalize_path(path)?;
        fs.get_xattr_for_normalized_path(&normalized, &name, token)
    })?;
    let value = value.ok_or(Error::NotFound)?;
    let written = copy_user_bytes(&value, value_out_ptr, value_out_len)?;
    Ok(SyscallDispatch::complete(written))
}

/// List extended attribute names (#153).
///
/// `arg(0..1)` = path; `arg(2..3)` = output buffer.  Names are written as a
/// concatenation of NUL-terminated byte strings (Linux `listxattr` format).
/// Returns the total byte length; a zero-length buffer probes the size.
pub(super) fn list_xattr(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let path = user_path_arg(context, 0, 1)?;
    let buffer_ptr = context.arg(2) as *mut u8;
    let buffer_len = context.arg(3);

    let entries = with_current_process_security_token_fs(|token, fs| {
        let normalized = fs.normalize_path(path)?;
        fs.list_xattrs_for_normalized_path(&normalized, token)
    })?;

    let mut names: Vec<u8> = Vec::new();
    for entry in &entries {
        names.extend_from_slice(&entry.name);
        names.push(0);
    }
    let written = copy_user_bytes(&names, buffer_ptr, buffer_len)?;
    Ok(SyscallDispatch::complete(written))
}

/// Remove an extended attribute (#154).
///
/// `arg(0..1)` = path; `arg(2..3)` = name.  Returns 0 on success.
pub(super) fn remove_xattr(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let path = user_path_arg(context, 0, 1)?;
    let name = with_optional_input_slice(context.arg(2) as *const u8, context.arg(3), |b| {
        Ok(b.to_vec())
    })?;
    validate_xattr_name(&name)?;

    with_current_process_security_token_fs(|token, fs| {
        let normalized = fs.normalize_path(path)?;
        fs.remove_xattr_for_normalized_path(&normalized, &name, token)?;
        Ok(SyscallDispatch::complete(0))
    })
}

/// Toggle per-file data-reduction flags (#155).
///
/// `arg(0..1)` = path; `arg(2)` = flags to set; `arg(3)` = flags to clear.
/// Only the compression flag is settable/clearable; the dedup flag is
/// maintained by the filesystem.  Returns 0 on success.
pub(super) fn set_file_flags(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let path = user_path_arg(context, 0, 1)?;
    let set = context.arg(2) as u32;
    let clear = context.arg(3) as u32;

    // Only the compression flag is user-settable.
    let mutable = fs_abi::FILE_FLAG_COMPRESSED;
    validate_known_flags(set as usize, mutable as usize)?;
    validate_known_flags(clear as usize, mutable as usize)?;
    if set & clear != 0 {
        return Err(Error::InvalidArgument);
    }

    with_current_process_security_token_fs(|token, fs| {
        let normalized = fs.normalize_path(path)?;
        fs.set_file_flags_for_normalized_path(&normalized, set, clear, token)?;
        Ok(SyscallDispatch::complete(0))
    })
}

/// Read per-file data-reduction flags (#156).
///
/// `arg(0..1)` = path.  Returns the `FILE_FLAG_*` bitmask.
pub(super) fn get_file_flags(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let path = user_path_arg(context, 0, 1)?;

    let flags = with_current_process_security_token_fs(|token, fs| {
        let normalized = fs.normalize_path(path)?;
        fs.get_file_flags_for_normalized_path(&normalized, token)
    })?;
    Ok(SyscallDispatch::complete(flags as usize))
}
