//! src/user/syscall/fs.rs
//!
//! User-side filesystem syscall helpers built on top of `UserSyscall`.

use crate::kernel::syscall::{SyscallContext, SyscallNumber};

impl super::UserSyscall {
    // ── Filesystem syscalls ─────────────────────────────────────────

    /// Open `path` (pointer + length) with `flags`, returning a file
    /// descriptor.
    pub const fn open(path: usize, length: usize, flags: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::Open as usize, [path, length, flags, 0, 0, 0])
    }

    /// Read up to `length` bytes from `fd` into `buffer`, waiting at most
    /// `timeout_ticks` for a device-style descriptor.
    pub const fn read(
        fd: usize,
        buffer: usize,
        length: usize,
        timeout_ticks: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::Read as usize,
            [fd, buffer, length, timeout_ticks, 0, 0],
        )
    }

    /// Write `length` bytes from `buffer` to `fd`.
    pub const fn write(fd: usize, buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::Write as usize, [fd, buffer, length, 0, 0, 0])
    }

    /// Close `fd`, releasing any kernel resources associated with it.
    pub const fn close(fd: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0])
    }

    /// Move the file position of `fd` to `offset` relative to `whence`
    /// (one of `SEEK_SET` / `SEEK_CUR` / `SEEK_END`).
    pub const fn seek(fd: usize, offset: usize, whence: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::Seek as usize, [fd, offset, whence, 0, 0, 0])
    }

    /// Truncate or extend `fd` so its size becomes `length`.
    pub const fn set_len(fd: usize, length: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::SetLength as usize, [fd, length, 0, 0, 0, 0])
    }

    /// Create the directory at `path`.
    pub const fn make_dir(path: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::CreateDir as usize,
            [path, length, 0, 0, 0, 0],
        )
    }

    /// Remove the file at `path`.
    pub const fn remove_path(path: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::RemovePath as usize,
            [path, length, 0, 0, 0, 0],
        )
    }
}
