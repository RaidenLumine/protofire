//! src/kernel/io.rs
//!
//! Unified process I/O adapter over files, directories, and device-backed descriptors.

pub use crate::kernel::device::{
    CONSOLE_DEVICE_PATH, DEBUG_DEVICE_PATH, KEYBOARD_DEVICE_PATH, KEYBOARD_RAW_DEVICE_PATH,
    NULL_DEVICE_PATH, SERIAL0_DEVICE_PATH, STDERR_DEVICE_PATH, STDIN_DEVICE_PATH,
    STDOUT_DEVICE_PATH, ZERO_DEVICE_PATH,
};
use crate::kernel::process::{
    process::OpenFile, FileDescriptor, HandleEntry, Process, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE,
};
use crate::{Error, Result};

fn resolve_io_entry(
    process: &Process,
    fd: FileDescriptor,
    required_rights: u32,
) -> Result<HandleEntry> {
    let entry = process.fd_entry(fd)?;
    // Directory handles are metadata channels; they are never byte-stream I/O targets.
    if entry.is_directory_like() {
        return Err(Error::InvalidArgument);
    }
    if required_rights != 0 && entry.rights & required_rights != required_rights {
        return Err(Error::PermissionDenied);
    }

    Ok(entry)
}

fn with_file_io_entry<T>(
    process: &Process,
    fd: FileDescriptor,
    required_rights: u32,
    f: impl FnOnce(OpenFile) -> Result<T>,
) -> Result<T> {
    f(resolve_io_entry(process, fd, required_rights)?.into_file()?)
}

fn dispatch_stream_io(
    process: &Process,
    fd: FileDescriptor,
    required_rights: u32,
    payload_is_empty: bool,
    f: impl FnOnce(HandleEntry) -> Result<usize>,
) -> Result<usize> {
    let entry = resolve_io_entry(process, fd, required_rights)?;
    if payload_is_empty {
        // Preserve fd/type/rights validation above but allow empty I/O payloads.
        Ok(0)
    } else {
        f(entry)
    }
}

pub fn read(
    process: &Process,
    fd: FileDescriptor,
    buffer: &mut [u8],
    timeout_ticks: u64,
) -> Result<usize> {
    dispatch_stream_io(process, fd, HANDLE_RIGHT_READ, buffer.is_empty(), |entry| {
        entry.read_stream(buffer, timeout_ticks)
    })
}

pub fn seek(process: &Process, fd: FileDescriptor, offset: i64, whence: usize) -> Result<u64> {
    with_file_io_entry(process, fd, 0, |file| file.seek(offset, whence))
}

pub fn set_len(process: &Process, fd: FileDescriptor, length: u64) -> Result<u64> {
    with_file_io_entry(process, fd, HANDLE_RIGHT_WRITE, |file| file.set_len(length))
}

pub fn duplicate(process: &Process, fd: FileDescriptor) -> Result<usize> {
    process.duplicate_fd(fd)
}

/// Duplicate `fd` onto `newfd` (POSIX dup2 semantics).
/// Closes `newfd` first if it was already open.
pub fn duplicate2(process: &Process, fd: FileDescriptor, newfd: FileDescriptor) -> Result<usize> {
    process.duplicate_fd_to(fd, newfd)
}

pub fn close(process: &Process, fd: FileDescriptor) -> Result<()> {
    // If the descriptor is a TcpListener, unbind the port before removing
    // the fd so the port becomes available for reuse.
    if let Ok(listener) = process.get_listener(fd) {
        listener.close()?;
    }
    // If the descriptor is a UdpSocket, unbind the port before removing
    // the fd so the port becomes available for reuse.
    if let Ok(socket) = process.get_udp_socket(fd) {
        socket.close()?;
    }
    process.close_fd(fd)
}

/// Set or clear per-file-descriptor flags (e.g. `FdFlags::CLOEXEC`).
///
/// Bits set in `set_flags` are enabled; bits set in `clear_flags` are disabled.
/// Returns the previous flags.
pub fn fsync(process: &Process, fd: FileDescriptor) -> Result<()> {
    with_file_io_entry(process, fd, 0, |file| file.sync())
}

pub fn fdatasync(process: &Process, fd: FileDescriptor) -> Result<()> {
    with_file_io_entry(process, fd, 0, |file| file.sync_data())
}

pub fn set_fd_flags(process: &Process, fd: FileDescriptor, set: u8, clear: u8) -> Result<usize> {
    use crate::kernel::process::FdFlags;

    let previous = process.get_fd_flags(fd)?;
    process.set_fd_flags(fd, FdFlags(set), FdFlags(clear))?;
    Ok(previous.0 as usize)
}

pub fn write(process: &Process, fd: FileDescriptor, buffer: &[u8]) -> Result<usize> {
    dispatch_stream_io(
        process,
        fd,
        HANDLE_RIGHT_WRITE,
        buffer.is_empty(),
        |entry| entry.write_stream(buffer),
    )
}

/// Check whether a file descriptor is ready for reading without blocking.
///
/// Returns `Ok(true)` if the fd exists, has read rights, and has data
/// available (or is a type that is always readable, like a regular file).
/// Returns `Ok(false)` if no data is immediately available.
/// Returns `Err(_)` if the fd does not exist.
pub fn fd_readable(process: &Process, fd: FileDescriptor) -> Result<bool> {
    let entry = process.fd_entry(fd)?;
    if entry.rights & HANDLE_RIGHT_READ == 0 {
        return Ok(false);
    }
    // Conservative default: any fd with read rights is considered readable.
    // Socket/pipe-specific buffer checks can be added later.
    Ok(true)
}

/// Check whether a file descriptor is ready for writing without blocking.
///
/// Returns `Ok(true)` if the fd exists, has write rights, and can accept
/// data without blocking.  Returns `Err(_)` if the fd does not exist.
pub fn fd_writable(process: &Process, fd: FileDescriptor) -> Result<bool> {
    let entry = process.fd_entry(fd)?;
    if entry.rights & HANDLE_RIGHT_WRITE == 0 {
        return Ok(false);
    }
    // Conservative default: any fd with write rights is considered writable.
    // Socket/pipe-specific buffer checks can be added later.
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{read, seek, set_len, write};
    use crate::kernel::process::{
        Process, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE, STDIN_FD, STDOUT_FD,
    };
    use crate::Error;

    #[test]
    fn directory_descriptors_are_invalid_for_stream_and_position_operations() {
        let process = Process::new(21, "io-directory-fd");
        let fd = process
            .open_directory_descriptor("/tmp", HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)
            .expect("open directory descriptor");
        let mut empty = [];

        assert_eq!(
            read(process.as_ref(), fd, &mut empty, 0),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            write(process.as_ref(), fd, &[]),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            seek(process.as_ref(), fd, 0, 0),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            set_len(process.as_ref(), fd, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn zero_length_operations_still_enforce_descriptor_rights() {
        let process = Process::new(22, "io-rights-check");
        let mut empty = [];

        assert_eq!(
            read(process.as_ref(), STDOUT_FD, &mut empty, 0),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            write(process.as_ref(), STDIN_FD, &[]),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            set_len(process.as_ref(), STDIN_FD, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn non_file_descriptors_reject_seek_and_set_len() {
        let process = Process::new(23, "io-non-file-ops");

        assert_eq!(
            seek(process.as_ref(), STDIN_FD, 0, 0),
            Err(Error::Unsupported)
        );
        assert_eq!(
            set_len(process.as_ref(), STDOUT_FD, 0),
            Err(Error::Unsupported)
        );
    }
}
