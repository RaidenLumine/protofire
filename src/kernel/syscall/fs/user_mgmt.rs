//! src/kernel/syscall/fs/user_mgmt.rs
//!
//! User management syscall handlers: add/remove user records and set passwords.
//! These wrap the in-memory user database with filesystem persistence.

use crate::kernel::user::{self, UserRecord};
use crate::{Error, Result};

use super::user_memory::user_string;
use super::SyscallContext;

/// Require a privileged (root/system) caller for account-management syscalls.
fn require_privileged_caller() -> Result<()> {
    super::runtime::with_current_process(|process| {
        if !process.security_token().is_admin_mode() {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    })
}

// ── AddUser (slot 89) ─────────────────────────────────────────────────────

pub(super) fn add_user(context: &mut SyscallContext) -> Result<super::SyscallDispatch> {
    require_privileged_caller()?;

    let username_ptr = context.arg(0) as *const u8;
    let username_len = context.arg(1);
    let uid = context.arg(2) as u32;
    let gid = context.arg(3) as u32;
    let home_ptr = context.arg(4) as *const u8;
    let home_len = context.arg(5);

    // Validate uid/gid are non-zero.
    if uid == 0 || gid == 0 {
        return Err(Error::InvalidArgument);
    }

    // Read username from user memory.
    let username = user_string(username_ptr, username_len)?;

    // Read home path from user memory.
    let home = user_string(home_ptr, home_len)?;

    // Acquire the user database.
    let db_mutex = user::global_user_database().ok_or(Error::InternalError)?;
    let Some(fs_guard) = crate::kernel::fs::global() else {
        return Err(Error::InternalError);
    };
    let fs = fs_guard.lock();

    let mut slot = db_mutex.lock();
    let db = slot.as_mut().ok_or(Error::InternalError)?;

    let record = UserRecord {
        username: username.clone(),
        uid,
        gid,
        home: home.clone(),
    };

    db.add_user(record, &fs)?;

    // Create the home directory skeleton; roll back the DB entry on failure.
    if let Err(e) = user::create_home_skeleton(&fs, &home) {
        let _ = db.remove_user(uid, &fs);
        return Err(e);
    }

    Ok(super::SyscallDispatch::complete(0))
}

// ── RemoveUser (slot 90) ──────────────────────────────────────────────────

pub(super) fn remove_user(context: &mut SyscallContext) -> Result<super::SyscallDispatch> {
    require_privileged_caller()?;

    let uid = context.arg(0) as u32;

    // Refuse to delete root.
    if uid == 0 {
        return Err(Error::InvalidArgument);
    }

    let Some(fs_guard) = crate::kernel::fs::global() else {
        return Err(Error::InternalError);
    };
    let fs = fs_guard.lock();

    // Removes from passwd (persisted) and also cleans up the shadow entry.
    user::remove_user(uid, &fs)?;

    Ok(super::SyscallDispatch::complete(0))
}

// ── SetUserPassword (slot 91) ─────────────────────────────────────────────

pub(super) fn set_user_password(context: &mut SyscallContext) -> Result<super::SyscallDispatch> {
    require_privileged_caller()?;

    let username_ptr = context.arg(0) as *const u8;
    let username_len = context.arg(1);
    let password_ptr = context.arg(2) as *const u8;
    let password_len = context.arg(3);

    // Validate non-empty username and password.
    if username_len == 0 || password_len == 0 {
        return Err(Error::InvalidArgument);
    }

    // Read username from user memory.
    let username = user_string(username_ptr, username_len)?;

    // Read password from user memory.
    let password = user_string(password_ptr, password_len)?;

    let Some(fs_guard) = crate::kernel::fs::global() else {
        return Err(Error::InternalError);
    };
    let fs = fs_guard.lock();

    user::set_user_password(&username, &password, &fs)?;

    Ok(super::SyscallDispatch::complete(0))
}
