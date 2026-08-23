//! src/kernel/fs/filesystem/access_helpers.rs
//! Access-check helpers (free functions).
//! These determine required access bits and mount write-visibility rules.

use crate::kernel::process::{SecurityToken, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE};

use super::super::layout;
use super::super::vfs::NodeKind;
use super::super::FileSystem;
use super::super::{ACCESS_EXECUTE_BIT, ACCESS_READ_BIT, ACCESS_WRITE_BIT};

pub(crate) fn required_open_access(kind: NodeKind, desired_access: u32) -> u16 {
    let mut required = 0;
    if desired_access & HANDLE_RIGHT_READ != 0 {
        required |= ACCESS_READ_BIT;
    }
    if desired_access & HANDLE_RIGHT_WRITE != 0 {
        required |= ACCESS_WRITE_BIT;
    }
    if kind == NodeKind::Directory && required != 0 {
        required |= ACCESS_EXECUTE_BIT;
    }
    required
}

pub(crate) fn open_requires_mount_write_access(kind: NodeKind, required_access: u16) -> bool {
    required_access & ACCESS_WRITE_BIT != 0 && kind != NodeKind::Device
}

pub(crate) const fn mount_is_ordinary_writable(flags: u32) -> bool {
    flags & layout::MOUNT_READ_ONLY == 0
}

pub(crate) fn mount_allows_write_for_security_token(
    flags: u32,
    security_token: SecurityToken,
) -> bool {
    mount_is_ordinary_writable(flags) || security_token.may_bypass_read_only_mounts()
}

pub(crate) fn path_write_access_visible_to_security_token(
    normalized: &str,
    security_token: SecurityToken,
    fs: &FileSystem,
) -> bool {
    match fs.resolve_mount_entry(normalized) {
        Some((mount, _relative_path)) => {
            mount_allows_write_for_security_token(mount.flags, security_token)
        }
        None => true,
    }
}
