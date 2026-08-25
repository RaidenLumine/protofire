//! src/kernel/syscall/io_fd.rs
//!
//! File-descriptor syscall handlers for read/write/seek/close/dup/set-length
//! operations.

use crate::kernel::fs::pipe;
use crate::kernel::io;
use crate::kernel::process::{Process, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE};
use crate::Result;

trait DispatchValue {
    fn into_dispatch(self) -> super::SyscallDispatch;
}

impl DispatchValue for usize {
    fn into_dispatch(self) -> super::SyscallDispatch {
        super::SyscallDispatch::complete(self)
    }
}

impl DispatchValue for u64 {
    fn into_dispatch(self) -> super::SyscallDispatch {
        super::SyscallDispatch::complete(self as usize)
    }
}

impl DispatchValue for () {
    fn into_dispatch(self) -> super::SyscallDispatch {
        super::SyscallDispatch::complete(0)
    }
}

pub(super) fn set_length(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 2)?;
    let fd = context.arg(0);
    let length = context.arg(1) as u64;
    complete_current_process_fd(fd, |process, fd| io::set_len(process, fd, length))
}

pub(super) fn read(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let buffer_ptr = context.arg(1) as *mut u8;
    let length = context.arg(2);
    let timeout_ticks = context.arg(3) as u64;

    super::validate_zeroed_args(context, 4)?;
    super::user_memory::with_optional_output_slice(buffer_ptr, length, |buffer| {
        complete_current_process_fd(fd, |process, fd| {
            io::read(process, fd, buffer, timeout_ticks)
        })
    })
}

pub(super) fn write(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let buffer_ptr = context.arg(1) as *const u8;
    let length = context.arg(2);

    super::validate_zeroed_args(context, 3)?;
    super::user_memory::with_optional_input_slice(buffer_ptr, length, |buffer| {
        complete_current_process_fd(fd, |process, fd| io::write(process, fd, buffer))
    })
}

pub(super) fn close(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 1)?;
    let fd = context.arg(0);
    complete_current_process_fd(fd, io::close)
}

pub(super) fn duplicate(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 1)?;
    let fd = context.arg(0);
    complete_current_process_fd(fd, io::duplicate)
}

pub(super) fn duplicate2(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let newfd = context.arg(1);
    super::validate_zeroed_args(context, 2)?;
    complete_current_process_fd(fd, |process, fd| io::duplicate2(process, fd, newfd))
}

pub(super) fn set_fd_flags(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 3)?;
    let fd = context.arg(0);
    let set = context.arg(1) as u8;
    let clear = context.arg(2) as u8;
    complete_current_process_fd(fd, |process, fd| io::set_fd_flags(process, fd, set, clear))
}

pub(super) fn seek(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 3)?;
    let fd = context.arg(0);
    let offset = context.arg(1) as isize as i64;
    let whence = context.arg(2);
    complete_current_process_fd(fd, |process, fd| io::seek(process, fd, offset, whence))
}

pub(super) fn fsync(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 1)?;
    let fd = context.arg(0);
    complete_current_process_fd(fd, io::fsync)
}

pub(super) fn fdatasync(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 1)?;
    let fd = context.arg(0);
    complete_current_process_fd(fd, io::fdatasync)
}

pub(super) fn pipe(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    // pipe(fds: *mut [usize; 2]) -> 0 on success
    // arg(0): pointer to output buffer (user memory)
    // arg(1): length of output buffer (must equal 2 * size_of::<usize>())
    let buffer_ptr = context.arg(0) as *mut u8;
    let buffer_len = context.arg(1);

    super::validate_zeroed_args(context, 2)?;

    let output = super::user_memory::FixedOutputBuffer::<[usize; 2]>::new(buffer_ptr, buffer_len)?;

    super::runtime::with_current_process(|process| {
        // Create the two VNode ends.
        let (read_vnode, write_vnode) = pipe::pipe_channel();

        // Allocate two consecutive handle numbers from the global filesystem.
        let read_handle = crate::kernel::fs::global()
            .ok_or(crate::Error::InternalError)?
            .lock()
            .alloc_handles(2);
        let write_handle = read_handle + 1;

        let security = crate::kernel::fs::vfs::SecurityDescriptor::root_for_kind(
            crate::kernel::fs::NodeKind::File,
        );
        let security_source =
            crate::kernel::fs::vfs::SecurityDescriptorMutationSupport::LayoutDerivedOnly;

        let read_file_handle = crate::kernel::fs::FileHandle::new(
            read_handle,
            read_vnode,
            security,
            security_source,
            0, // mount_flags
        );

        let write_file_handle = crate::kernel::fs::FileHandle::new(
            write_handle,
            write_vnode,
            security,
            security_source,
            0, // mount_flags
        );

        let read_fd =
            process.open_file_descriptor("pipe:read", read_file_handle, HANDLE_RIGHT_READ)?;
        let write_fd =
            process.open_file_descriptor("pipe:write", write_file_handle, HANDLE_RIGHT_WRITE)?;

        // POSIX pipefd[0] = read, pipefd[1] = write.
        output.copy_value(&[read_fd, write_fd])
    })
}

fn complete_current_process_fd<F, T>(fd: usize, f: F) -> Result<super::SyscallDispatch>
where
    F: FnOnce(&Process, usize) -> Result<T>,
    T: DispatchValue,
{
    super::runtime::with_current_process(|process| f(process, fd))
        .map(|value| value.into_dispatch())
}

// ── Poll: multi-fd readiness ────────────────────────────────────────────────

/// Poll flags (matching typical POSIX poll.h values).
const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
/// Set in `revents` when an error occurred on the fd.
const POLLERR: u16 = 0x008;
/// Set in `revents` when the fd is not open / invalid.
#[allow(dead_code)]
const POLLNVAL: u16 = 0x020;

/// User-facing pollfd struct (must match ring3 layout).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PollFd {
    fd: i32,
    events: u16,
    revents: u16,
}

/// Probe all PollFd entries and set their `revents` fields.
/// Returns the number of fds with non-zero revents.
fn probe_all(process: &crate::kernel::process::Process, fds: &mut [PollFd]) -> usize {
    let mut ready_count: usize = 0;

    for entry in fds.iter_mut() {
        entry.revents = 0;

        // Negative fd → invalid.
        if entry.fd < 0 {
            entry.revents |= POLLNVAL;
            ready_count += 1;
            continue;
        }

        let fd = entry.fd as crate::kernel::process::FileDescriptor;

        // Check readability.
        if entry.events & POLLIN != 0 {
            match io::fd_readable(process, fd) {
                Ok(true) => entry.revents |= POLLIN,
                Ok(false) => {} // Not ready.
                Err(_) => entry.revents |= POLLERR,
            }
        }

        // Check writability.
        if entry.events & POLLOUT != 0 {
            match io::fd_writable(process, fd) {
                Ok(true) => entry.revents |= POLLOUT,
                Ok(false) => {} // Not ready.
                Err(_) => entry.revents |= POLLERR,
            }
        }

        if entry.revents != 0 {
            ready_count += 1;
        }
    }

    ready_count
}

pub(super) fn poll(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fds_ptr = context.arg(0) as *mut PollFd;
    let nfds = context.arg(1);
    let timeout_ticks = context.arg(2) as u64;

    super::validate_zeroed_args(context, 3)?;

    if nfds == 0 {
        return Ok(super::SyscallDispatch::complete(0));
    }

    // Cap the number of fds to a reasonable limit.
    let nfds = nfds.min(256);
    let byte_len = nfds
        .checked_mul(core::mem::size_of::<PollFd>())
        .ok_or(crate::Error::InvalidArgument)?;

    super::user_memory::with_optional_output_slice(fds_ptr as *mut u8, byte_len, |buffer| {
        // SAFETY: buffer is validated user memory, PollFd is repr(C) and Copy.
        let fds =
            unsafe { core::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<PollFd>(), nfds) };

        super::runtime::with_current_process(|process| {
            // Phase 1: non-blocking probe.
            let ready_count = probe_all(process, fds);
            if ready_count > 0 || timeout_ticks == 0 {
                return Ok(super::SyscallDispatch::complete(ready_count));
            }

            // Phase 2: blocking wait with timeout.
            // Re-probe after sleeping; the scheduler's timer tick handler wakes
            // the thread when the deadline expires.  This is a timer-based poll
            // (not event-driven) — correct but adds wake-up latency.
            let ready_count = super::wait_common::wait_until_ready(
                timeout_ticks,
                u64::MAX,
                || {
                    let n = probe_all(process, fds);
                    (n > 0).then_some(n)
                },
                || {
                    // Short sleep between probes (used only for the
                    // block-indefinitely path, which poll never enters since we
                    // always pass an explicit timeout_ticks > 0 here).
                    crate::kernel::process::scheduler::api::sleep_current(1);
                    true
                },
                |remaining| {
                    crate::kernel::process::scheduler::api::sleep_current(remaining);
                    true
                },
                super::wait_common::current_wait_timed_out,
            )
            .unwrap_or(0);
            Ok(super::SyscallDispatch::complete(ready_count))
        })
    })
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "none"))]
    use super::super::test_support;
    use super::{
        close as close_fd, duplicate as duplicate_fd, fdatasync as fdatasync_fd, fsync as fsync_fd,
        read as read_fd, seek as seek_fd, set_length as set_length_fd, write as write_fd,
    };
    use crate::kernel::{
        network,
        process::{HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE},
        syscall::{SyscallContext, SyscallDispatch, SyscallNumber},
    };
    use crate::Error;
    #[cfg(not(target_os = "none"))]
    use alloc::{format, sync::Arc};
    #[cfg(not(target_os = "none"))]
    use std::io::{Read as _, Write as _};

    #[cfg(not(target_os = "none"))]
    fn open_network_fd(
        process: &crate::kernel::process::Process,
        port: u16,
    ) -> crate::Result<usize> {
        let connection = network::connect_tcp("127.0.0.1", port)?;
        process.open_network_descriptor(
            &format!("127.0.0.1:{port}"),
            connection,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
    }

    #[cfg(not(target_os = "none"))]
    fn scheduled_network_fd(
        test_name: &str,
        server: impl FnOnce(std::net::TcpStream) + Send + 'static,
    ) -> (
        test_support::TestLockGuard,
        alloc::boxed::Box<crate::kernel::process::Scheduler>,
        Arc<crate::kernel::process::Process>,
        usize,
        std::thread::JoinHandle<()>,
    ) {
        let (_guard, scheduler, process) =
            test_support::locked_scheduled_current_process(test_name);
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept loopback connection");
            server(socket);
        });
        let fd = open_network_fd(process.as_ref(), port).expect("open network fd");

        (_guard, scheduler, process, fd, server)
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fd_io_syscalls_reject_non_zero_reserved_args_before_runtime_lookup() {
        let mut read_context =
            SyscallContext::new(SyscallNumber::Read as usize, [usize::MAX, 0, 0, 0, 1, 0]);
        assert_eq!(read_fd(&mut read_context), Err(Error::InvalidArgument));

        let mut write_context =
            SyscallContext::new(SyscallNumber::Write as usize, [usize::MAX, 0, 0, 1, 0, 0]);
        assert_eq!(write_fd(&mut write_context), Err(Error::InvalidArgument));

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [usize::MAX, 1, 0, 0, 0, 0]);
        assert_eq!(close_fd(&mut close_context), Err(Error::InvalidArgument));

        let mut duplicate_context =
            SyscallContext::new(SyscallNumber::Dup as usize, [usize::MAX, 1, 0, 0, 0, 0]);
        assert_eq!(
            duplicate_fd(&mut duplicate_context),
            Err(Error::InvalidArgument)
        );

        let mut seek_context =
            SyscallContext::new(SyscallNumber::Seek as usize, [usize::MAX, 0, 0, 1, 0, 0]);
        assert_eq!(seek_fd(&mut seek_context), Err(Error::InvalidArgument));

        let mut set_length_context = SyscallContext::new(
            SyscallNumber::SetLength as usize,
            [usize::MAX, 0, 1, 0, 0, 0],
        );
        assert_eq!(
            set_length_fd(&mut set_length_context),
            Err(Error::InvalidArgument)
        );

        let mut fsync_context =
            SyscallContext::new(SyscallNumber::Fsync as usize, [usize::MAX, 1, 0, 0, 0, 0]);
        assert_eq!(fsync_fd(&mut fsync_context), Err(Error::InvalidArgument));

        let mut fdatasync_context = SyscallContext::new(
            SyscallNumber::Fdatasync as usize,
            [usize::MAX, 0, 1, 0, 0, 0],
        );
        assert_eq!(
            fdatasync_fd(&mut fdatasync_context),
            Err(Error::InvalidArgument)
        );
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn invalid_fd_syscalls_return_not_found_without_touching_buffers() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("io-fd-invalid");
        let invalid_fd = usize::MAX;

        let mut read_context =
            SyscallContext::new(SyscallNumber::Read as usize, [invalid_fd, 0, 0, 0, 0, 0]);
        assert_eq!(read_fd(&mut read_context), Err(Error::NotFound));

        let mut write_context =
            SyscallContext::new(SyscallNumber::Write as usize, [invalid_fd, 0, 0, 0, 0, 0]);
        assert_eq!(write_fd(&mut write_context), Err(Error::NotFound));

        let mut duplicate_context =
            SyscallContext::new(SyscallNumber::Dup as usize, [invalid_fd, 0, 0, 0, 0, 0]);
        assert_eq!(duplicate_fd(&mut duplicate_context), Err(Error::NotFound));

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [invalid_fd, 0, 0, 0, 0, 0]);
        assert_eq!(close_fd(&mut close_context), Err(Error::NotFound));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn network_fd_syscalls_duplicate_close_read_and_write_over_shared_connection() {
        let (_guard, _scheduler, _process, fd, server) =
            scheduled_network_fd("io-fd-network", |mut socket| {
                socket.write_all(b"ping").expect("write server payload");
                let mut reply = [0_u8; 4];
                socket.read_exact(&mut reply).expect("read client reply");
                assert_eq!(&reply, b"pong");
            });

        let mut duplicate_context =
            SyscallContext::new(SyscallNumber::Dup as usize, [fd, 0, 0, 0, 0, 0]);
        let duplicated_fd = duplicate_fd(&mut duplicate_context)
            .expect("duplicate network fd")
            .value;
        assert_ne!(duplicated_fd, fd);

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(
            close_fd(&mut close_context),
            Ok(SyscallDispatch::complete(0))
        );

        let mut buffer = [0_u8; 4];
        let mut read_context = SyscallContext::new(
            SyscallNumber::Read as usize,
            [
                duplicated_fd,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                100,
                0,
                0,
            ],
        );
        assert_eq!(read_fd(&mut read_context), Ok(SyscallDispatch::complete(4)));
        assert_eq!(&buffer, b"ping");

        let payload = *b"pong";
        let mut write_context = SyscallContext::new(
            SyscallNumber::Write as usize,
            [
                duplicated_fd,
                payload.as_ptr() as usize,
                payload.len(),
                0,
                0,
                0,
            ],
        );
        assert_eq!(
            write_fd(&mut write_context),
            Ok(SyscallDispatch::complete(4))
        );

        let mut close_duplicate_context = SyscallContext::new(
            SyscallNumber::Close as usize,
            [duplicated_fd, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            close_fd(&mut close_duplicate_context),
            Ok(SyscallDispatch::complete(0))
        );

        let mut closed_read_context = SyscallContext::new(
            SyscallNumber::Read as usize,
            [
                duplicated_fd,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                0,
                0,
                0,
            ],
        );
        assert_eq!(read_fd(&mut closed_read_context), Err(Error::NotFound));

        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn close_syscall_returns_not_found_after_fd_is_already_closed() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("io-fd-double-close");
        let fd = 1;

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(
            close_fd(&mut close_context),
            Ok(SyscallDispatch::complete(0))
        );

        let mut second_close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(close_fd(&mut second_close_context), Err(Error::NotFound));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn zero_length_network_fd_syscalls_preserve_fd_validation_without_touching_buffers() {
        let (_guard, _scheduler, _process, fd, server) =
            scheduled_network_fd("io-fd-zero", |mut socket| {
                let mut buffer = [0_u8; 1];
                assert_eq!(socket.read(&mut buffer).expect("wait for client close"), 0);
            });

        let mut read_context =
            SyscallContext::new(SyscallNumber::Read as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(read_fd(&mut read_context), Ok(SyscallDispatch::complete(0)));

        let mut write_context =
            SyscallContext::new(SyscallNumber::Write as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(
            write_fd(&mut write_context),
            Ok(SyscallDispatch::complete(0))
        );

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(
            close_fd(&mut close_context),
            Ok(SyscallDispatch::complete(0))
        );

        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn network_fd_syscalls_reject_seek_and_set_length() {
        let (_guard, _scheduler, _process, fd, server) =
            scheduled_network_fd("io-fd-unsupported", |_socket| {});

        let mut seek_context =
            SyscallContext::new(SyscallNumber::Seek as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(seek_fd(&mut seek_context), Err(Error::Unsupported));

        let mut set_length_context =
            SyscallContext::new(SyscallNumber::SetLength as usize, [fd, 1, 0, 0, 0, 0]);
        assert_eq!(
            set_length_fd(&mut set_length_context),
            Err(Error::Unsupported)
        );

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(
            close_fd(&mut close_context),
            Ok(SyscallDispatch::complete(0))
        );

        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn network_fd_syscalls_reject_non_zero_length_null_buffers() {
        let (_guard, _scheduler, _process, fd, server) =
            scheduled_network_fd("io-fd-null-buffer", |_socket| {});

        let mut read_context =
            SyscallContext::new(SyscallNumber::Read as usize, [fd, 0, 1, 0, 0, 0]);
        assert_eq!(read_fd(&mut read_context), Err(Error::InvalidArgument));

        let mut write_context =
            SyscallContext::new(SyscallNumber::Write as usize, [fd, 0, 1, 0, 0, 0]);
        assert_eq!(write_fd(&mut write_context), Err(Error::InvalidArgument));

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(
            close_fd(&mut close_context),
            Ok(SyscallDispatch::complete(0))
        );

        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fsync_on_network_fd_returns_unsupported() {
        let (_guard, _scheduler, _process, fd, server) =
            scheduled_network_fd("io-fd-fsync-net", |_socket| {});

        let mut context = SyscallContext::new(SyscallNumber::Fsync as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(fsync_fd(&mut context), Err(Error::Unsupported));

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0]);
        close_fd(&mut close_context).expect("close");
        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fdatasync_on_network_fd_returns_unsupported() {
        let (_guard, _scheduler, _process, fd, server) =
            scheduled_network_fd("io-fd-fdatasync-net", |_socket| {});

        let mut context =
            SyscallContext::new(SyscallNumber::Fdatasync as usize, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(fdatasync_fd(&mut context), Err(Error::Unsupported));

        let mut close_context =
            SyscallContext::new(SyscallNumber::Close as usize, [fd, 0, 0, 0, 0, 0]);
        close_fd(&mut close_context).expect("close");
        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fsync_rejects_non_zero_reserved_args() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("io-fd-fsync-reserved");

        let mut context = SyscallContext::new(SyscallNumber::Fsync as usize, [0, 1, 0, 0, 0, 0]);
        assert_eq!(fsync_fd(&mut context), Err(Error::InvalidArgument));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fdatasync_rejects_non_zero_reserved_args() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("io-fd-fdatasync-reserved");

        let mut context =
            SyscallContext::new(SyscallNumber::Fdatasync as usize, [0, 0, 1, 0, 0, 0]);
        assert_eq!(fdatasync_fd(&mut context), Err(Error::InvalidArgument));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn fsync_on_invalid_fd_returns_not_found() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("io-fd-fsync-invalid");

        let mut context =
            SyscallContext::new(SyscallNumber::Fsync as usize, [usize::MAX, 0, 0, 0, 0, 0]);
        assert_eq!(fsync_fd(&mut context), Err(Error::NotFound));
    }
}
