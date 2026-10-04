//! src/syscall/install.rs
//!
//! The install syscall: handing the kernel a package to install.
//!
//! The work is `user::program::install::package::install_staged_package`; what
//! this adds is the way a ring-3 program reaches it.  There is deliberately no
//! policy here beyond resolving the path: the install reads the package and
//! writes `/apps` through the *filesystem*, under the caller's security token
//! (`current_execution_security_token`, which every one of those calls uses),
//! so a program can install exactly what it can read and exactly where it can
//! write.  A caller that cannot read its own package gets the filesystem's
//! refusal, and one that cannot write the app zone gets the same — from the
//! zone's own rules rather than from a second check here that could disagree
//! with them.
//!
//! The path is resolved against the caller's working directory, because that is
//! what a program means by a relative path; the install itself is anchored at
//! the root from there.
//!
//! Nothing is returned beyond success: what was installed is a fact of the
//! filesystem (`/apps/current/<app_id>.toml`, the versioned catalog record and
//! the payload), and the caller reads it the way everything else does — by
//! reading files.

/// Install the staged package at the path the caller names.
#[cfg(any(feature = "demo-disk", test))]
pub(super) fn install(
    context: &mut super::SyscallContext,
) -> super::Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 2)?;

    let raw = super::user_memory::user_path_arg(context, 0, 1)?;
    let cwd = super::runtime::current_process()?.current_working_dir();
    let path = crate::fs::path::normalize_path(&raw, &cwd)?;

    let fs = super::runtime::global_fs()?;
    let fs = fs.lock();
    crate::user::program::install_staged_package(&fs, &path)?;

    Ok(super::SyscallDispatch::complete(0))
}

// A build with no demo disk has no install path compiled in: the number stays
// reserved, and the call answers that this is not the machine for it.
#[cfg(not(any(feature = "demo-disk", test)))]
pub(super) fn install(
    _context: &mut super::SyscallContext,
) -> super::Result<super::SyscallDispatch> {
    Err(crate::Error::Unsupported)
}
