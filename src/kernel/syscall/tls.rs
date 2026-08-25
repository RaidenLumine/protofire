//! src/kernel/syscall/tls.rs
//!
//! TLS 1.3 connect system call handler.
//!
//! Provides syscall #121 (TlsConnect) which establishes a TCP connection
//! to a remote host, performs a full TLS 1.3 handshake, and returns a file
//! descriptor that transparently encrypts outgoing data and decrypts
//! incoming data.

use alloc::string::ToString;
use alloc::sync::Arc;

use crate::kernel::network::tls;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::kernel::process::HANDLE_RIGHT_WRITE;
use crate::Error;
use crate::Result;

/// Maximum hostname length accepted by the TLS connect syscall.
const MAX_TLS_HOST_BYTES: usize = 4096;

/// Syscall #121: TlsConnect — connect to a remote TLS 1.3 server.
///
/// Arguments:
///   arg0 = hostname pointer (user-space string)
///   arg1 = hostname length
///   arg2 = port (u16)
///   arg3 = flags (must be 0)
///
/// Returns a file descriptor that supports read/write/close/poll.
pub(super) fn tls_connect(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let (host, port) = tls_connect_request(context)?;
    let connection = Arc::new(tls::tls_connect(host, port)?);
    let endpoint = connection.endpoint().to_string();
    super::runtime::with_current_process(|process| {
        let fd = process.open_tls_descriptor(
            &endpoint,
            connection,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

/// Parse and validate TlsConnect arguments from the syscall context.
///
/// Mirrors `network::connect_tcp_request` — same argument layout:
///   arg0 = host pointer, arg1 = host length, arg2 = port, arg3 = flags
fn tls_connect_request<'a>(context: &super::SyscallContext) -> Result<(&'a str, u16)> {
    let host_ptr = context.arg(0) as *const u8;
    let host_len = context.arg(1);
    let port = context.arg(2);
    let flags = context.arg(3);

    validate_tls_connect_args(host_len, port, flags)?;
    super::validate_zeroed_args(context, 4)?;
    let host = super::user_memory::user_bounded_str(host_ptr, host_len, MAX_TLS_HOST_BYTES)?;
    Ok((host, port as u16))
}

/// Validate TlsConnect argument constraints.
fn validate_tls_connect_args(host_len: usize, port: usize, flags: usize) -> Result<()> {
    if host_len == 0 || port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }

    super::validate_known_flags(flags, 0)?;
    Ok(())
}
