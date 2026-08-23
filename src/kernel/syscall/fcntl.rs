//! src/kernel/syscall/fcntl.rs
//! fcntl syscall handler (#179).
//!
//! Supports the POSIX descriptor-control commands that map onto existing
//! per-process infrastructure, plus the pipe-buffer commands that close the
//! "no fcntl(F_SETPIPE_SZ)" gap:
//!
//! - `F_DUPFD`     — duplicate `fd` onto the lowest free descriptor `>= arg`.
//! - `F_GETFD`     — return the per-fd flags (`FD_CLOEXEC`).
//! - `F_SETFD`     — set the per-fd flags.
//! - `F_GETFL`     — return the access mode | `O_NONBLOCK`.
//! - `F_SETFL`     — set `O_NONBLOCK` (only settable bit).
//! - `F_GETPIPE_SZ`— return the pipe buffer capacity.
//! - `F_SETPIPE_SZ`— resize the pipe buffer (rounded/clamped, data preserved).

use crate::abi::fs as fs_abi;
use crate::kernel::process::{FdFlags, KernelObject, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE};
use crate::{Error, Result};

use super::{runtime, SyscallContext, SyscallDispatch};

/// Read-only access mode returned by `F_GETFL` (Linux `O_RDONLY`).
const O_RDONLY: usize = 0;
/// Write-only access mode returned by `F_GETFL` (Linux `O_WRONLY`).
const O_WRONLY: usize = 1;
/// Read-write access mode returned by `F_GETFL` (Linux `O_RDWR`).
const O_RDWR: usize = 2;

pub(super) fn fcntl(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let fd = context.arg(0);
    let cmd = context.arg(1);
    let arg = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    runtime::with_current_process(|process| match cmd {
        fs_abi::F_DUPFD => {
            let newfd = process.duplicate_fd_from(fd, arg)?;
            Ok(SyscallDispatch::complete(newfd))
        }
        fs_abi::F_GETFD => {
            let flags = process.get_fd_flags(fd)?;
            Ok(SyscallDispatch::complete(flags.0 as usize))
        }
        fs_abi::F_SETFD => {
            let set = FdFlags(arg as u8);
            process.set_fd_flags(fd, set, FdFlags::NONE)?;
            Ok(SyscallDispatch::complete(0))
        }
        fs_abi::F_GETFL => get_fl(process, fd),
        fs_abi::F_SETFL => set_fl(process, fd, arg),
        fs_abi::F_GETPIPE_SZ => get_pipe_sz(process, fd),
        fs_abi::F_SETPIPE_SZ => set_pipe_sz(process, fd, arg),
        _ => Err(Error::Unsupported),
    })
}

/// `F_GETFL`: report the access mode plus `O_NONBLOCK` for file-backed fds.
/// Non-file descriptors report the access mode only.
fn get_fl(process: &crate::kernel::process::Process, fd: usize) -> Result<SyscallDispatch> {
    let entry = process.fd_entry(fd)?;
    // `|` in match patterns is alternation, not bitwise-or, so the read-write
    // case must be tested explicitly with `==`.
    let rights = entry.rights & (HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE);
    let access_mode = if rights == HANDLE_RIGHT_READ {
        O_RDONLY
    } else if rights == HANDLE_RIGHT_WRITE {
        O_WRONLY
    } else if rights == (HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE) {
        O_RDWR
    } else {
        O_RDONLY
    };
    let nonblock = match &entry.object {
        KernelObject::File(file) => file.with_file_handle(|handle| Ok(handle.is_nonblocking()))?,
        _ => false,
    };
    let flags = access_mode | if nonblock { fs_abi::O_NONBLOCK } else { 0 };
    Ok(SyscallDispatch::complete(flags))
}

/// `F_SETFL`: accept `O_NONBLOCK` (the only settable status bit) and apply it
/// to the underlying node.  Non-file descriptors are rejected.
fn set_fl(
    process: &crate::kernel::process::Process,
    fd: usize,
    arg: usize,
) -> Result<SyscallDispatch> {
    if arg & !fs_abi::O_NONBLOCK != 0 {
        return Err(Error::InvalidArgument);
    }
    let entry = process.fd_entry(fd)?;
    match &entry.object {
        KernelObject::File(file) => {
            file.with_file_handle(|handle| handle.set_nonblocking(arg & fs_abi::O_NONBLOCK != 0))?;
            Ok(SyscallDispatch::complete(0))
        }
        _ => Err(Error::Unsupported),
    }
}

/// `F_GETPIPE_SZ`: return the pipe capacity, or fail for non-pipe fds.
fn get_pipe_sz(process: &crate::kernel::process::Process, fd: usize) -> Result<SyscallDispatch> {
    let entry = process.fd_entry(fd)?;
    let capacity = match &entry.object {
        KernelObject::File(file) => {
            file.with_file_handle(|handle| handle.pipe_capacity().ok_or(Error::Unsupported))?
        }
        _ => return Err(Error::Unsupported),
    };
    Ok(SyscallDispatch::complete(capacity))
}

/// `F_SETPIPE_SZ`: resize the pipe buffer to `arg` bytes (rounded and clamped
/// like Linux), preserving buffered data.
fn set_pipe_sz(
    process: &crate::kernel::process::Process,
    fd: usize,
    arg: usize,
) -> Result<SyscallDispatch> {
    let size = crate::kernel::fs::pipe::round_pipe_size(arg);
    let entry = process.fd_entry(fd)?;
    match &entry.object {
        KernelObject::File(file) => {
            file.with_file_handle(|handle| handle.set_pipe_capacity(size))?;
            Ok(SyscallDispatch::complete(size))
        }
        _ => Err(Error::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "none"))]
    use super::super::test_support;
    use super::super::{SyscallContext, SyscallDispatch, SyscallNumber};
    use super::fcntl as fcntl_syscall;
    use crate::abi::fs as fs_abi;
    use crate::kernel::fs::pipe::{round_pipe_size, DEFAULT_PIPE_CAPACITY};
    use crate::kernel::process::{HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE};
    use crate::Error;

    /// Create a `pipe` context and run the handler, returning the two fds.
    ///
    /// The handle numbers are informational (the process's handle table
    /// assigns its own keys via `open_descriptor`), so fixed values suffice —
    /// no global filesystem is needed in these tests.
    #[cfg(not(target_os = "none"))]
    fn open_test_pipe(process: &crate::kernel::process::Process) -> (usize, usize) {
        let (read_vnode, write_vnode) = crate::kernel::fs::pipe::pipe_channel();
        let security = crate::kernel::fs::vfs::SecurityDescriptor::root_for_kind(
            crate::kernel::fs::NodeKind::File,
        );
        let security_source =
            crate::kernel::fs::vfs::SecurityDescriptorMutationSupport::LayoutDerivedOnly;
        let read_fd = process
            .open_file_descriptor(
                "pipe:read",
                crate::kernel::fs::FileHandle::new(
                    0x5000,
                    read_vnode,
                    security,
                    security_source,
                    0,
                ),
                HANDLE_RIGHT_READ,
            )
            .expect("open read end");
        let write_fd = process
            .open_file_descriptor(
                "pipe:write",
                crate::kernel::fs::FileHandle::new(
                    0x5001,
                    write_vnode,
                    security,
                    security_source,
                    0,
                ),
                HANDLE_RIGHT_WRITE,
            )
            .expect("open write end");
        (read_fd, write_fd)
    }

    #[test]
    fn fcntl_round_pipe_size_matches_helper() {
        assert_eq!(round_pipe_size(1), 4096);
        assert_eq!(round_pipe_size(DEFAULT_PIPE_CAPACITY), 16384);
        assert_eq!(round_pipe_size(1024 * 1024 + 1), 1024 * 1024);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fcntl_rejects_non_zero_reserved_args() {
        let mut context =
            SyscallContext::new(SyscallNumber::Fcntl as usize, [usize::MAX, 0, 0, 1, 0, 0]);
        assert_eq!(fcntl_syscall(&mut context), Err(Error::InvalidArgument));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fcntl_get_pipe_sz_and_set_pipe_sz_round_trip() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("fcntl-pipe-sz");
        let (read_fd, write_fd) = open_test_pipe(process.as_ref());

        // Default capacity is reported by both ends.
        let mut get = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_GETPIPE_SZ, 0, 0, 0, 0],
        );
        assert_eq!(
            fcntl_syscall(&mut get),
            Ok(SyscallDispatch::complete(DEFAULT_PIPE_CAPACITY))
        );

        // Grow to 64 KiB.
        let mut set = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [write_fd, fs_abi::F_SETPIPE_SZ, 64 * 1024, 0, 0, 0],
        );
        assert_eq!(
            fcntl_syscall(&mut set),
            Ok(SyscallDispatch::complete(64 * 1024))
        );

        // Both ends observe the new capacity.
        let mut get2 = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_GETPIPE_SZ, 0, 0, 0, 0],
        );
        assert_eq!(
            fcntl_syscall(&mut get2),
            Ok(SyscallDispatch::complete(64 * 1024))
        );
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fcntl_set_pipe_sz_rounds_and_clamps() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("fcntl-pipe-clamp");
        let (read_fd, _write_fd) = open_test_pipe(process.as_ref());

        // Requesting 1 byte clamps up to one page.
        let mut set = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_SETPIPE_SZ, 1, 0, 0, 0],
        );
        assert_eq!(
            fcntl_syscall(&mut set),
            Ok(SyscallDispatch::complete(round_pipe_size(1)))
        );
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fcntl_pipe_sz_on_non_pipe_fd_is_unsupported() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("fcntl-pipe-notpipe");
        // Stdout (fd 1) is a device, not a pipe.
        let mut get = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [1, fs_abi::F_GETPIPE_SZ, 0, 0, 0, 0],
        );
        assert_eq!(fcntl_syscall(&mut get), Err(Error::Unsupported));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fcntl_getfd_setfd_round_trip() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("fcntl-fd-flags");
        let (read_fd, _write_fd) = open_test_pipe(process.as_ref());

        // Initial F_GETFD is 0.
        let mut get = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_GETFD, 0, 0, 0, 0],
        );
        assert_eq!(fcntl_syscall(&mut get), Ok(SyscallDispatch::complete(0)));

        // F_SETFD with FD_CLOEXEC.
        let mut set = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_SETFD, fs_abi::FD_CLOEXEC, 0, 0, 0],
        );
        assert_eq!(fcntl_syscall(&mut set), Ok(SyscallDispatch::complete(0)));

        // F_GETFD now reports CLOEXEC.
        let mut get2 = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_GETFD, 0, 0, 0, 0],
        );
        assert_eq!(
            fcntl_syscall(&mut get2),
            Ok(SyscallDispatch::complete(fs_abi::FD_CLOEXEC))
        );
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fcntl_setfl_nonblock_then_getfl_reflects_flag() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("fcntl-setfl");
        let (read_fd, write_fd) = open_test_pipe(process.as_ref());

        // Read end: O_RDONLY (0), no nonblock.
        let mut get = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_GETFL, 0, 0, 0, 0],
        );
        assert_eq!(fcntl_syscall(&mut get), Ok(SyscallDispatch::complete(0)));

        // Set O_NONBLOCK on the read end.
        let mut set = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_SETFL, fs_abi::O_NONBLOCK, 0, 0, 0],
        );
        assert_eq!(fcntl_syscall(&mut set), Ok(SyscallDispatch::complete(0)));

        // F_GETFL now reports O_NONBLOCK.
        let mut get2 = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_GETFL, 0, 0, 0, 0],
        );
        assert_eq!(
            fcntl_syscall(&mut get2),
            Ok(SyscallDispatch::complete(fs_abi::O_NONBLOCK))
        );

        // Write end: O_WRONLY (1), still no nonblock.
        let mut get3 = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [write_fd, fs_abi::F_GETFL, 0, 0, 0, 0],
        );
        assert_eq!(fcntl_syscall(&mut get3), Ok(SyscallDispatch::complete(1)));

        // Unknown status bits are rejected.
        let mut bad = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_SETFL, 0x40_0000, 0, 0, 0],
        );
        assert_eq!(fcntl_syscall(&mut bad), Err(Error::InvalidArgument));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fcntl_f_dupfd_allocates_lowest_free_at_or_above_arg() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("fcntl-dupfd");
        let (read_fd, write_fd) = open_test_pipe(process.as_ref());

        // Duplicate onto the lowest free fd >= read_fd (which is write_fd + 1).
        let mut dup = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [read_fd, fs_abi::F_DUPFD, read_fd, 0, 0, 0],
        );
        let newfd = fcntl_syscall(&mut dup)
            .expect("F_DUPFD should succeed")
            .value;
        assert!(newfd > write_fd);
        // The duplicated fd refers to the same pipe read end.
        assert!(matches!(
            process
                .fd_entry(newfd)
                .expect("duplicated fd resolves")
                .object,
            crate::kernel::process::KernelObject::File(_)
        ));
        assert!(matches!(
            process
                .fd_entry(read_fd)
                .expect("source fd resolves")
                .object,
            crate::kernel::process::KernelObject::File(_)
        ));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fcntl_on_invalid_fd_returns_not_found() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("fcntl-invalid-fd");
        let mut get = SyscallContext::new(
            SyscallNumber::Fcntl as usize,
            [usize::MAX, fs_abi::F_GETFD, 0, 0, 0, 0],
        );
        assert_eq!(fcntl_syscall(&mut get), Err(Error::NotFound));
    }
}
