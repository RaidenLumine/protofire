//! src/kernel/syscall/fs/path.rs
//! Path-source decoding and dirfd-based path resolution helpers for fs syscalls.

use alloc::string::{String, ToString};

use crate::abi::fs as fs_abi;
use crate::kernel::fs;
use crate::kernel::process::Process;
use crate::Result;

#[derive(Clone, Copy)]
pub(super) enum PathSource<'a> {
    Current(&'a str),
    DirFd { dirfd: usize, path: &'a str },
}

pub(super) fn context_path_source<'a>(
    context: &'a super::SyscallContext,
    path_arg: usize,
    len_arg: usize,
) -> Result<PathSource<'a>> {
    Ok(PathSource::Current(super::user_memory::user_path_arg(
        context, path_arg, len_arg,
    )?))
}

pub(super) fn context_path_source_at<'a>(
    context: &'a super::SyscallContext,
    dirfd_arg: usize,
    path_arg: usize,
    len_arg: usize,
) -> Result<PathSource<'a>> {
    Ok(PathSource::DirFd {
        dirfd: context.arg(dirfd_arg),
        path: super::user_memory::user_path_arg(context, path_arg, len_arg)?,
    })
}

pub(super) fn context_path_source_after_reserved<'a>(
    context: &'a super::SyscallContext,
    path_arg: usize,
    len_arg: usize,
    reserved_arg: usize,
) -> Result<PathSource<'a>> {
    super::validate_zeroed_args(context, reserved_arg)?;
    context_path_source(context, path_arg, len_arg)
}

pub(super) fn context_path_source_at_after_reserved<'a>(
    context: &'a super::SyscallContext,
    dirfd_arg: usize,
    path_arg: usize,
    len_arg: usize,
    reserved_arg: usize,
) -> Result<PathSource<'a>> {
    super::validate_zeroed_args(context, reserved_arg)?;
    context_path_source_at(context, dirfd_arg, path_arg, len_arg)
}

pub(super) fn normalize_process_path_source(
    process: &Process,
    source: PathSource<'_>,
) -> Result<String> {
    match source {
        PathSource::Current(path) => {
            let cwd = process.current_working_dir();
            fs::path::normalize_path(path, &cwd)
        }
        PathSource::DirFd { dirfd, path } => normalize_path_from_dirfd(process, dirfd, path),
    }
}

pub(super) fn with_current_process_path_source<T>(
    source: PathSource<'_>,
    f: impl FnOnce(&Process, String) -> Result<T>,
) -> Result<T> {
    super::runtime::with_current_process(|process| {
        let normalized = normalize_process_path_source(process, source)?;
        f(process, normalized)
    })
}

pub(super) fn with_current_process_path_pair_sources<T>(
    first: PathSource<'_>,
    second: PathSource<'_>,
    f: impl FnOnce(&Process, String, String) -> Result<T>,
) -> Result<T> {
    super::runtime::with_current_process(|process| {
        let first = normalize_process_path_source(process, first)?;
        let second = normalize_process_path_source(process, second)?;
        f(process, first, second)
    })
}

pub(super) fn dispatch_path_source<F>(
    source: PathSource<'_>,
    f: F,
) -> Result<super::SyscallDispatch>
where
    F: FnOnce(String) -> Result<super::SyscallDispatch>,
{
    with_current_process_path_source(source, |_process, normalized| f(normalized))
}

pub(super) fn dispatch_path_pair_sources<F>(
    first: PathSource<'_>,
    second: PathSource<'_>,
    f: F,
) -> Result<super::SyscallDispatch>
where
    F: FnOnce(String, String) -> Result<super::SyscallDispatch>,
{
    // Normalize both sides first so rename-style handlers only deal with
    // canonical paths after dirfd and CWD resolution.
    with_current_process_path_pair_sources(first, second, |_process, first, second| {
        f(first, second)
    })
}

fn normalize_path_from_dirfd(process: &Process, dirfd: usize, path: &str) -> Result<String> {
    if path.trim().starts_with('/') {
        // Absolute inputs are anchored from root and intentionally bypass dirfd.
        return fs::path::normalize_path(path, "/");
    }

    let base = directory_path_for_fd(process, dirfd)?;
    fs::path::normalize_path(path, &base)
}

fn directory_path_for_fd(process: &Process, dirfd: usize) -> Result<String> {
    if dirfd == fs_abi::AT_FDCWD {
        // `AT_FDCWD` sentinel: resolve relative paths from the caller CWD.
        return Ok(process.current_working_dir());
    }

    let entry = process.fd_entry(dirfd)?;
    entry.directory_backing_path().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::{normalize_process_path_source, PathSource};
    use crate::abi::fs::AT_FDCWD;
    use crate::kernel::process::{Process, STDOUT_FD};
    use crate::{Error, Result};

    #[test]
    fn at_fdcwd_path_source_resolves_relative_path_from_process_cwd() {
        let process = Process::new(1, "path-current");
        process.set_current_working_dir("/data/users/guest/downloads");

        assert_normalized(
            process.as_ref(),
            PathSource::DirFd {
                dirfd: AT_FDCWD,
                path: "../notes/todo.txt",
            },
            Ok("/data/users/guest/notes/todo.txt".into()),
        );
    }

    #[test]
    fn directory_fd_path_source_resolves_relative_path_from_directory_backing_path() {
        let process = Process::new(2, "path-dirfd");
        let dirfd = process
            .open_directory_descriptor("/apps/current/demo", 0)
            .expect("open directory descriptor");

        assert_normalized(
            process.as_ref(),
            PathSource::DirFd {
                dirfd,
                path: "../catalog/demo.toml",
            },
            Ok("/apps/current/catalog/demo.toml".into()),
        );
    }

    #[test]
    fn absolute_path_source_bypasses_dirfd_anchor() {
        let process = Process::new(3, "path-absolute");
        let dirfd = process
            .open_directory_descriptor("/data/users/guest/downloads", 0)
            .expect("open directory descriptor");

        assert_normalized(
            process.as_ref(),
            PathSource::DirFd {
                dirfd,
                path: "/system/config/kernel.toml",
            },
            Ok("/system/config/kernel.toml".into()),
        );
    }

    #[test]
    fn absolute_path_source_bypasses_invalid_dirfd_anchor() {
        let process = Process::new(3, "path-absolute-invalid-dirfd");

        assert_normalized(
            process.as_ref(),
            PathSource::DirFd {
                dirfd: STDOUT_FD,
                path: "/system/config/kernel.toml",
            },
            Ok("/system/config/kernel.toml".into()),
        );
    }

    #[test]
    fn absolute_path_source_with_whitespace_bypasses_invalid_dirfd_anchor() {
        let process = Process::new(5, "path-absolute-whitespace-invalid-dirfd");

        assert_normalized(
            process.as_ref(),
            PathSource::DirFd {
                dirfd: STDOUT_FD,
                path: "   /system/config/kernel.toml   ",
            },
            Ok("/system/config/kernel.toml".into()),
        );
    }

    #[test]
    fn pair_path_sources_allow_absolute_dirfd_inputs_to_bypass_invalid_dirfd_anchor() {
        let (_guard, _scheduler, process) =
            super::super::test_support::locked_scheduled_current_process(
                "path-pair-absolute-invalid-dirfd",
            );
        process.set_current_working_dir("/data/users/guest/downloads");

        assert_eq!(
            super::with_current_process_path_pair_sources(
                PathSource::DirFd {
                    dirfd: STDOUT_FD,
                    path: "/system/config/kernel.toml",
                },
                PathSource::DirFd {
                    dirfd: AT_FDCWD,
                    path: "../notes/todo.txt",
                },
                |_process, first, second| Ok((first, second)),
            ),
            Ok((
                "/system/config/kernel.toml".into(),
                "/data/users/guest/notes/todo.txt".into(),
            )),
        );
    }

    #[test]
    fn pair_path_sources_allow_whitespace_absolute_dirfd_inputs_to_bypass_invalid_dirfd_anchor() {
        let (_guard, _scheduler, process) =
            super::super::test_support::locked_scheduled_current_process(
                "path-pair-whitespace-absolute-invalid-dirfd",
            );
        process.set_current_working_dir("/data/users/guest/downloads");

        assert_eq!(
            super::with_current_process_path_pair_sources(
                PathSource::DirFd {
                    dirfd: STDOUT_FD,
                    path: "   /system/config/kernel.toml   ",
                },
                PathSource::DirFd {
                    dirfd: AT_FDCWD,
                    path: "../notes/todo.txt",
                },
                |_process, first, second| Ok((first, second)),
            ),
            Ok((
                "/system/config/kernel.toml".into(),
                "/data/users/guest/notes/todo.txt".into(),
            )),
        );
    }

    #[test]
    fn non_directory_fd_is_rejected_as_path_anchor() {
        let process = Process::new(4, "path-device-fd");

        assert_normalized(
            process.as_ref(),
            PathSource::DirFd {
                dirfd: STDOUT_FD,
                path: "notes/todo.txt",
            },
            Err(Error::InvalidArgument),
        );
    }

    fn assert_normalized(process: &Process, source: PathSource<'_>, expected: Result<String>) {
        assert_eq!(normalize_process_path_source(process, source), expected);
    }
}
