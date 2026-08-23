//! src/kernel/syscall/network.rs
//! Minimal network syscalls for capability discovery and TCP connection creation.

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::abi::net as net_abi;
use crate::kernel::network;
use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::process::{HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE};
use crate::{Error, Result};

const MAX_CONNECT_HOST_BYTES: usize = 4096;

pub(super) fn status(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 0)?;
    Ok(super::SyscallDispatch::complete(network::status_flags()))
}

pub(super) fn connect_tcp(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let (host, port) = connect_tcp_request(context)?;
    let connection = network::connect_tcp(host, port)?;
    let endpoint = connection.endpoint().to_string();
    super::runtime::with_current_process(|process| {
        let fd = process.open_network_descriptor(
            &endpoint,
            connection,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

pub(super) fn listen_tcp(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let (port, backlog) = listen_tcp_request(context)?;
    let listener = network::listen_tcp(port, backlog)?;
    super::runtime::with_current_process(|process| {
        let fd = process.open_listener_descriptor(port, listener, HANDLE_RIGHT_READ)?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

pub(super) fn accept_tcp(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let listener_fd = accept_tcp_request(context)?;
    super::runtime::with_current_process(|process| {
        let listener = process.get_listener(listener_fd)?;
        let connection = network::accept_tcp(&listener)?;
        let endpoint = connection.endpoint().to_string();
        let fd = process.open_network_descriptor(
            &endpoint,
            connection,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

fn connect_tcp_request<'a>(context: &super::SyscallContext) -> Result<(&'a str, u16)> {
    let host_ptr = context.arg(0) as *const u8;
    let host_len = context.arg(1);
    let port = context.arg(2);
    let flags = context.arg(3);

    validate_connect_tcp_args(host_len, port, flags)?;
    super::validate_zeroed_args(context, 4)?;
    let host = super::user_memory::user_bounded_str(host_ptr, host_len, MAX_CONNECT_HOST_BYTES)?;
    Ok((host, port as u16))
}

fn validate_connect_tcp_args(host_len: usize, port: usize, flags: usize) -> Result<()> {
    if host_len == 0 || port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }

    super::validate_known_flags(flags, net_abi::NETWORK_CONNECT_KNOWN_FLAGS)?;
    Ok(())
}

fn listen_tcp_request(context: &super::SyscallContext) -> Result<(u16, u16)> {
    let port = context.arg(0);
    let backlog = context.arg(1);
    let flags = context.arg(2);

    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    if backlog > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }

    super::validate_known_flags(flags, net_abi::NETWORK_LISTEN_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 3)?;
    Ok((port as u16, backlog as u16))
}

fn accept_tcp_request(context: &super::SyscallContext) -> Result<usize> {
    let listener_fd = context.arg(0);
    let flags = context.arg(1);

    super::validate_known_flags(flags, net_abi::NETWORK_ACCEPT_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 2)?;
    Ok(listener_fd)
}

// ─── UDP syscall handlers ───────────────────────────────────────────────

pub(super) fn bind_udp(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let (port,) = bind_udp_request(context)?;
    let socket = network::bind_udp(port)?;
    super::runtime::with_current_process(|process| {
        let fd =
            process.open_udp_descriptor(port, socket, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

pub(super) fn send_to_udp(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let (fd, dest_ip, dest_port, payload, is_v6) = send_to_udp_request(context)?;
    super::runtime::with_current_process(|process| {
        let socket = process.get_udp_socket(fd)?;
        match dest_ip {
            IpAddress::V4(v4) => {
                if is_v6 {
                    return Err(Error::InvalidArgument);
                }
                network::send_to_udp(&socket, v4, dest_port, payload)?;
            }
            IpAddress::V6(v6) => {
                if !is_v6 {
                    return Err(Error::InvalidArgument);
                }
                network::send_to_udp_v6(&socket, v6, dest_port, payload)?;
            }
        }
        Ok(super::SyscallDispatch::complete(payload.len()))
    })
}

pub(super) fn recv_from_udp(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let (fd, buffer, src_addr_out_ptr, is_v6) = recv_from_udp_request(context)?;
    super::runtime::with_current_process(|process| {
        let socket = process.get_udp_socket(fd)?;
        if is_v6 {
            let (n, src_ip, src_port) = network::recv_from_udp_v6(&socket, buffer)?;
            // Write 20-byte source address (16 IP + 2 port + 2 pad).
            if src_addr_out_ptr != 0 {
                let mut addr_bytes = [0u8; 20];
                addr_bytes[0..16].copy_from_slice(&src_ip);
                addr_bytes[16..18].copy_from_slice(&src_port.to_le_bytes());
                // Bytes 18-19 remain zero (padding).
                super::user_memory::copy_user_bytes(&addr_bytes, src_addr_out_ptr as *mut u8, 20)?;
            }
            Ok(super::SyscallDispatch::complete(n))
        } else {
            let (n, src_ip, src_port) = network::recv_from_udp(&socket, buffer)?;
            // Write 8-byte source address (4 IP + 2 port + 2 pad).
            if src_addr_out_ptr != 0 {
                let mut addr_bytes = [0u8; 8];
                addr_bytes[0..4].copy_from_slice(&src_ip);
                addr_bytes[4..6].copy_from_slice(&src_port.to_le_bytes());
                // Bytes 6-7 remain zero (padding).
                super::user_memory::copy_user_bytes(&addr_bytes, src_addr_out_ptr as *mut u8, 8)?;
            }
            Ok(super::SyscallDispatch::complete(n))
        }
    })
}

// ─── request validation ─────────────────────────────────────────────────

fn bind_udp_request(context: &super::SyscallContext) -> Result<(u16,)> {
    let port = context.arg(0);
    let flags = context.arg(1);

    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }

    super::validate_known_flags(flags, net_abi::NETWORK_BIND_UDP_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 2)?;
    Ok((port as u16,))
}

fn send_to_udp_request(
    context: &super::SyscallContext,
) -> Result<(usize, IpAddress, u16, &[u8], bool)> {
    let fd = context.arg(0);
    let arg1 = context.arg(1);
    let dest_port = context.arg(2);
    let data_ptr = context.arg(3);
    let data_len = context.arg(4);
    let flags = context.arg(5);

    if dest_port == 0 || dest_port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    if data_len == 0 {
        return Err(Error::InvalidArgument);
    }

    super::validate_known_flags(flags, net_abi::NETWORK_SENDTO_UDP_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 6)?;

    let is_v6 = flags & net_abi::NETWORK_SENDTO_UDP_FLAG_IPV6 != 0;
    let dest_ip = if is_v6 {
        // arg1 is a pointer to a 16-byte IPv6 address in user memory.
        let addr_slice = super::user_memory::optional_user_input_slice(arg1 as *const u8, 16)?
            .ok_or(Error::InvalidArgument)?;
        if addr_slice.len() != 16 {
            return Err(Error::InvalidArgument);
        }
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(addr_slice);
        IpAddress::V6(v6)
    } else {
        // arg1 is a packed 32-bit IPv4 address.
        let v4 = [
            (arg1 >> 24) as u8,
            (arg1 >> 16) as u8,
            (arg1 >> 8) as u8,
            arg1 as u8,
        ];
        IpAddress::V4(v4)
    };

    let payload = super::user_memory::optional_user_input_slice(data_ptr as *const u8, data_len)?
        .ok_or(Error::InvalidArgument)?;
    Ok((fd, dest_ip, dest_port as u16, payload, is_v6))
}

fn recv_from_udp_request(
    context: &super::SyscallContext,
) -> Result<(usize, &mut [u8], usize, bool)> {
    let fd = context.arg(0);
    let buffer_ptr = context.arg(1);
    let buffer_len = context.arg(2);
    let src_addr_out_ptr = context.arg(3);
    let flags = context.arg(4);

    if buffer_len == 0 {
        return Err(Error::InvalidArgument);
    }

    super::validate_known_flags(flags, net_abi::NETWORK_RECVFROM_UDP_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 5)?;

    let buffer = super::user_memory::optional_user_output_slice(buffer_ptr as *mut u8, buffer_len)?
        .ok_or(Error::InvalidArgument)?;
    let is_v6 = flags & net_abi::NETWORK_RECVFROM_UDP_FLAG_IPV6 != 0;
    Ok((fd, buffer, src_addr_out_ptr, is_v6))
}

#[cfg(test)]
fn validate_connect_tcp_shape(host_len: usize, port: usize, flags: usize) -> Result<()> {
    validate_connect_tcp_args(host_len, port, flags)
}

// ─── Socket address syscall handlers ────────────────────────────────────

const SOCKADDR_IN_SIZE: usize = 16; // struct sockaddr_in

/// Return the local address bound to socket `fd`.
///
/// Writes a 16-byte `sockaddr_in` struct (family + port + IPv4 + padding)
/// to the user-provided buffer.  Supports TCP connections and UDP sockets.
pub(super) fn getsockname(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let buffer_ptr = context.arg(1) as *mut u8;
    let buffer_len = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    super::user_memory::validate_current_process_user_output_buffer(
        buffer_ptr,
        buffer_len,
        SOCKADDR_IN_SIZE,
    )?;

    let addr = super::runtime::with_current_process(|process| {
        let entry = process.fd_entry(fd)?;
        match &entry.object {
            crate::kernel::process::process::KernelObject::Network(conn) => {
                conn.local_addr().ok_or(crate::Error::Unsupported)
            }
            crate::kernel::process::process::KernelObject::UdpSocket(sock) => {
                sock.local_addr().ok_or(crate::Error::Unsupported)
            }
            _ => Err(crate::Error::InvalidArgument),
        }
    })?;

    let sockaddr = network::SockAddrIn {
        sin_family: 2u16, // AF_INET
        sin_port: addr.1.to_be(),
        sin_addr: addr.0,
        sin_zero: [0u8; 8],
    };

    super::user_memory::copy_user_bytes(&sockaddr.to_bytes(), buffer_ptr, buffer_len)?;
    Ok(super::SyscallDispatch::complete(SOCKADDR_IN_SIZE))
}

/// Return the remote (peer) address connected to socket `fd`.
///
/// Writes a 16-byte `sockaddr_in` struct (family + port + IPv4 + padding)
/// to the user-provided buffer.  Only TCP connections have a peer address;
/// UDP sockets return [`Error::InvalidArgument`].
pub(super) fn getpeername(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let buffer_ptr = context.arg(1) as *mut u8;
    let buffer_len = context.arg(2);
    super::validate_zeroed_args(context, 3)?;

    super::user_memory::validate_current_process_user_output_buffer(
        buffer_ptr,
        buffer_len,
        SOCKADDR_IN_SIZE,
    )?;

    let addr = super::runtime::with_current_process(|process| {
        let entry = process.fd_entry(fd)?;
        match &entry.object {
            crate::kernel::process::process::KernelObject::Network(conn) => {
                conn.remote_addr().ok_or(crate::Error::Unsupported)
            }
            _ => Err(crate::Error::InvalidArgument),
        }
    })?;

    let sockaddr = network::SockAddrIn {
        sin_family: 2u16, // AF_INET
        sin_port: addr.1.to_be(),
        sin_addr: addr.0,
        sin_zero: [0u8; 8],
    };

    super::user_memory::copy_user_bytes(&sockaddr.to_bytes(), buffer_ptr, buffer_len)?;
    Ok(super::SyscallDispatch::complete(SOCKADDR_IN_SIZE))
}

// ─── Raw socket syscall handlers ───────────────────────────────────────

/// Create a raw socket bound to the given IP protocol number.
///
/// args[0] = protocol (u8, e.g. 1=ICMP, 6=TCP, 17=UDP)
/// args[1] = flags (reserved, must be 0)
pub(super) fn create_raw_socket(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let protocol = context.arg(0) as u8;
    let flags = context.arg(1);

    if protocol == 0 {
        return Err(Error::InvalidArgument);
    }
    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 2)?;

    let handle = network::create_raw_socket(protocol)?;
    super::runtime::with_current_process(|process| {
        let fd =
            process.open_raw_socket_descriptor(handle, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

/// Send a raw IP packet.
///
/// args[0] = fd (raw socket descriptor)
/// args[1] = dest_ip_ptr (pointer to 4-byte IPv4 or 16-byte IPv6 address)
/// args[2] = dest_ip_len (4 or 16)
/// args[3] = data_ptr
/// args[4] = data_len
/// args[5] = flags (reserved, must be 0)
pub(super) fn send_raw_packet(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let dest_ip_ptr = context.arg(1) as *const u8;
    let dest_ip_len = context.arg(2);
    let data_ptr = context.arg(3) as *const u8;
    let data_len = context.arg(4);
    let flags = context.arg(5);

    if dest_ip_len != 4 && dest_ip_len != 16 {
        return Err(Error::InvalidArgument);
    }
    if data_len == 0 {
        return Err(Error::InvalidArgument);
    }
    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 6)?;

    let dest_slice = super::user_memory::optional_user_input_slice(dest_ip_ptr, dest_ip_len)?
        .ok_or(Error::InvalidArgument)?;
    let data = super::user_memory::optional_user_input_slice(data_ptr, data_len)?
        .ok_or(Error::InvalidArgument)?;

    let dest_ip = if dest_ip_len == 4 {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(dest_slice);
        IpAddress::V4(v4)
    } else {
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(dest_slice);
        IpAddress::V6(v6)
    };

    super::runtime::with_current_process(|process| {
        let handle = process.get_raw_socket(fd)?;
        network::send_raw_packet(handle, dest_ip, data)?;
        Ok(super::SyscallDispatch::complete(data_len))
    })
}

/// Receive a raw packet from a raw socket (non-blocking).
///
/// args[0] = fd
/// args[1] = buffer_ptr
/// args[2] = buffer_len
/// args[3] = src_addr_out_ptr (output: 4-byte IPv4 or 16-byte IPv6)
/// args[4] = flags (reserved, must be 0)
pub(super) fn recv_raw_packet(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let buffer_ptr = context.arg(1) as *mut u8;
    let buffer_len = context.arg(2);
    let src_addr_out_ptr = context.arg(3);
    let flags = context.arg(4);

    if buffer_len == 0 {
        return Err(Error::InvalidArgument);
    }
    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 5)?;

    let buffer = super::user_memory::optional_user_output_slice(buffer_ptr, buffer_len)?
        .ok_or(Error::InvalidArgument)?;

    super::runtime::with_current_process(|process| {
        let handle = process.get_raw_socket(fd)?;
        let (n, src_ip) = network::recv_raw_packet(handle, buffer)?;

        // Write source address back to user-space if requested.
        if src_addr_out_ptr != 0 {
            match src_ip {
                IpAddress::V4(v4) => {
                    super::user_memory::copy_user_bytes(&v4, src_addr_out_ptr as *mut u8, 4)?;
                }
                IpAddress::V6(v6) => {
                    super::user_memory::copy_user_bytes(&v6, src_addr_out_ptr as *mut u8, 16)?;
                }
            }
        }

        Ok(super::SyscallDispatch::complete(n))
    })
}

// ─── resolve_hostname ─────────────────────────────────────────────────────

const MAX_RESOLVE_HOST_BYTES: usize = 256;

/// Syscall 93: Resolve a hostname to an IPv4 address.
///
/// Arguments:
///   host_ptr — pointer to hostname string
///   host_len — length of hostname string (max 256 bytes)
///
/// Returns the 4-byte IPv4 address packed into a u32 (network byte order).
pub(super) fn resolve_hostname(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let host_ptr = context.arg(0) as *const u8;
    let host_len = context.arg(1);

    if host_len == 0 || host_len > MAX_RESOLVE_HOST_BYTES {
        return Err(Error::InvalidArgument);
    }
    super::validate_zeroed_args(context, 2)?;

    let hostname =
        super::user_memory::user_bounded_str(host_ptr, host_len, MAX_RESOLVE_HOST_BYTES)?;

    let ip = crate::kernel::network::dns::resolve_hostname(hostname)?;

    // Pack the 4-byte IPv4 address into a u32 (network byte order).
    let addr_u32 = u32::from_be_bytes(ip);
    Ok(super::SyscallDispatch::complete(addr_u32 as usize))
}

// ─── setsockopt / getsockopt ──────────────────────────────────────────────

/// Syscall 79: Set socket option.
///
/// Arguments:
///   fd       — socket fd
///   level    — `SOL_SOCKET` or `IPPROTO_TCP`
///   name     — option name (e.g. `SO_KEEPALIVE`, `TCP_NODELAY`)
///   val_ptr  — pointer to option value buffer
///   val_len  — length of option value
///   reserved — must be zero
pub(super) fn setsockopt(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let level = context.arg(1) as u32;
    let name = context.arg(2) as u32;
    let val_ptr = context.arg(3) as *const u8;
    let val_len = context.arg(4);
    super::validate_zeroed_args(context, 5)?;

    if val_len == 0 || val_len > 64 {
        return Err(Error::InvalidArgument);
    }

    let val = super::user_memory::optional_user_input_slice(val_ptr, val_len)?
        .ok_or(Error::InvalidArgument)?;

    super::runtime::with_current_process(|process| {
        let entry = process.fd_entry(fd)?;
        match &entry.object {
            crate::kernel::process::process::KernelObject::Network(conn) => {
                set_tcp_option(conn, level, name, val)
            }
            _ => Err(Error::InvalidArgument),
        }
    })?;

    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall 80: Get socket option.
///
/// Arguments:
///   fd       — socket fd
///   level    — `SOL_SOCKET` or `IPPROTO_TCP`
///   name     — option name (e.g. `SO_KEEPALIVE`, `TCP_NODELAY`)
///   val_ptr  — output buffer pointer
///   val_len  — output buffer capacity
///   reserved — must be zero
///
/// Returns the number of bytes written to the output buffer.
pub(super) fn getsockopt(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let level = context.arg(1) as u32;
    let name = context.arg(2) as u32;
    let val_ptr = context.arg(3) as *mut u8;
    let val_len = context.arg(4);
    super::validate_zeroed_args(context, 5)?;

    if val_len == 0 || val_len > 64 {
        return Err(Error::InvalidArgument);
    }

    super::user_memory::validate_current_process_user_output_buffer(val_ptr, val_len, 1)?;

    let out = super::runtime::with_current_process(|process| {
        let entry = process.fd_entry(fd)?;
        match &entry.object {
            crate::kernel::process::process::KernelObject::Network(conn) => {
                get_tcp_option(conn, level, name)
            }
            _ => Err(Error::InvalidArgument),
        }
    })?;

    let write_len = out.len().min(val_len);
    super::user_memory::copy_user_bytes(&out[..write_len], val_ptr, val_len)?;
    Ok(super::SyscallDispatch::complete(write_len))
}

/// Apply a socket option to a TCP connection.
fn set_tcp_option(
    conn: &crate::kernel::network::TcpConnection,
    level: u32,
    name: u32,
    val: &[u8],
) -> Result<()> {
    #[cfg(target_os = "none")]
    {
        conn.set_option(level, name, val)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (conn, level, name, val);
        Ok(())
    }
}

/// Read a socket option from a TCP connection.
fn get_tcp_option(
    conn: &crate::kernel::network::TcpConnection,
    level: u32,
    name: u32,
) -> Result<Vec<u8>> {
    #[cfg(target_os = "none")]
    {
        conn.get_option(level, name)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (conn, level, name);
        Ok(alloc::vec![0u8])
    }
}

// ─── DCCP syscall handlers (#157-163) ───────────────────────────────────

/// Syscall 157: dccp_bind(port, service_code, flags) → fd.
pub(super) fn dccp_bind(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let port = context.arg(0);
    let service_code = context.arg(1) as u32;
    let flags = context.arg(2);

    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    super::validate_known_flags(flags, net_abi::NETWORK_DCCP_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 3)?;

    let socket = network::bind_dccp(port as u16, service_code)?;
    super::runtime::with_current_process(|process| {
        let fd = process.open_dccp_descriptor(
            socket.local_port,
            socket,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

/// Syscall 158: dccp_listen(port, backlog, service_code, flags) → fd.
pub(super) fn dccp_listen(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let port = context.arg(0);
    let backlog = context.arg(1);
    let service_code = context.arg(2) as u32;
    let flags = context.arg(3);

    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    if backlog > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    super::validate_known_flags(flags, net_abi::NETWORK_DCCP_LISTEN_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 4)?;

    let socket = network::listen_dccp(port as u16, backlog as u16, service_code)?;
    super::runtime::with_current_process(|process| {
        let fd = process.open_dccp_descriptor(socket.local_port, socket, HANDLE_RIGHT_READ)?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

/// Syscall 159: dccp_connect(dest_ip, dest_port, service_code, flags) → fd.
///
/// `arg0` is a packed IPv4 address (big-endian u32) unless
/// [`net_abi::NETWORK_DCCP_FLAG_IPV6`] is set, in which case it points to a
/// 16-byte IPv6 address.
pub(super) fn dccp_connect(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ip_arg = context.arg(0);
    let dest_port = context.arg(1);
    let service_code = context.arg(2) as u32;
    let flags = context.arg(3);

    if dest_port == 0 || dest_port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    super::validate_known_flags(flags, net_abi::NETWORK_DCCP_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 4)?;

    let dst = if flags & net_abi::NETWORK_DCCP_FLAG_IPV6 != 0 {
        let addr_bytes = super::user_memory::optional_user_input_slice(ip_arg as *const u8, 16)?
            .ok_or(Error::InvalidArgument)?;
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(addr_bytes);
        IpAddress::V6(bytes)
    } else {
        let ip = ip_arg as u32;
        IpAddress::V4(ip.to_be_bytes())
    };

    let socket = network::connect_dccp(dst, dest_port as u16, service_code)?;
    super::runtime::with_current_process(|process| {
        let fd = process.open_dccp_descriptor(
            socket.local_port,
            socket,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

/// Syscall 160: dccp_accept(fd, flags) → new fd.
pub(super) fn dccp_accept(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let flags = context.arg(1);

    super::validate_known_flags(flags, net_abi::NETWORK_DCCP_ACCEPT_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 2)?;

    super::runtime::with_current_process(|process| {
        let entry = process.fd_entry(fd)?;
        let crate::kernel::process::KernelObject::DccpSocket(listener) = &entry.object else {
            return Err(Error::InvalidArgument);
        };
        let socket = network::accept_dccp(listener)?;
        let fd = process.open_dccp_descriptor(
            socket.local_port,
            socket,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )?;
        Ok(super::SyscallDispatch::complete(fd))
    })
}

/// Syscall 161: dccp_send(fd, data_ptr, data_len, flags) → bytes sent.
pub(super) fn dccp_send(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let data_ptr = context.arg(1) as *const u8;
    let data_len = context.arg(2);
    let flags = context.arg(3);

    super::validate_known_flags(flags, net_abi::NETWORK_DCCP_SEND_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 4)?;

    super::runtime::with_current_process(|process| {
        let entry = process.fd_entry(fd)?;
        let crate::kernel::process::KernelObject::DccpSocket(socket) = &entry.object else {
            return Err(Error::InvalidArgument);
        };
        super::user_memory::with_optional_input_slice(data_ptr, data_len, |payload| {
            network::send_dccp(socket, payload)
        })
    })
    .map(super::SyscallDispatch::complete)
}

/// Syscall 162: dccp_recv(fd, buf, buf_len, src_addr_out, flags) → bytes read.
pub(super) fn dccp_recv(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let buf_ptr = context.arg(1) as *mut u8;
    let buf_len = context.arg(2);
    let src_addr_out_ptr = context.arg(3) as *mut u8;
    let flags = context.arg(4);

    super::validate_known_flags(flags, net_abi::NETWORK_DCCP_RECV_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 5)?;

    super::runtime::with_current_process(|process| {
        let entry = process.fd_entry(fd)?;
        let crate::kernel::process::KernelObject::DccpSocket(socket) = &entry.object else {
            return Err(Error::InvalidArgument);
        };
        super::user_memory::with_optional_output_slice(buf_ptr, buf_len, |buffer| {
            let (read, peer_ip, peer_port) = network::recv_dccp(socket, buffer)?;
            // If the caller supplied a non-empty `src_addr_out` (8 bytes for
            // IPv4, 20 for IPv6), write the peer address + port there.
            if !src_addr_out_ptr.is_null() {
                let mut addr_bytes = [0u8; 20];
                let addr_len = match peer_ip {
                    IpAddress::V4(bytes) => {
                        addr_bytes[..4].copy_from_slice(&bytes);
                        8
                    }
                    IpAddress::V6(bytes) => {
                        addr_bytes[..16].copy_from_slice(&bytes);
                        20
                    }
                };
                // Layout is IP bytes followed by the 2-byte port at the tail of
                // the output (bytes 6..8 for IPv4, 18..20 for IPv6); the bytes
                // between IP and port remain zero.
                addr_bytes[addr_len - 2..addr_len].copy_from_slice(&peer_port.to_be_bytes());
                super::user_memory::copy_user_bytes(
                    &addr_bytes[..addr_len],
                    src_addr_out_ptr,
                    addr_len,
                )?;
            }
            Ok(read)
        })
    })
    .map(super::SyscallDispatch::complete)
}

/// Syscall 163: dccp_close(fd, flags).
pub(super) fn dccp_close(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let flags = context.arg(1);

    super::validate_known_flags(flags, net_abi::NETWORK_DCCP_ACCEPT_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 2)?;

    super::runtime::with_current_process(|process| {
        process.close_fd(fd)?;
        Ok(())
    })?;
    Ok(super::SyscallDispatch::complete(0))
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "none"))]
    use super::super::test_support;
    use super::{connect_tcp, connect_tcp_request, status, validate_connect_tcp_shape};
    use crate::abi::net as net_abi;
    use crate::kernel::{
        network,
        process::{KernelObject, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE},
        syscall::{SyscallContext, SyscallDispatch, SyscallNumber},
    };
    use crate::Error;
    #[cfg(not(target_os = "none"))]
    use alloc::format;

    #[test]
    fn network_status_reports_runtime_capability_flags() {
        let mut context = SyscallContext::new(SyscallNumber::NetworkStatus as usize, [0; 6]);

        assert_eq!(
            status(&mut context),
            Ok(SyscallDispatch::complete(network::status_flags()))
        );
    }

    #[test]
    fn network_status_rejects_non_zero_reserved_args() {
        let mut context =
            SyscallContext::new(SyscallNumber::NetworkStatus as usize, [1, 0, 0, 0, 0, 0]);

        assert_eq!(status(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_connect_tcp_shape_accepts_valid_connect_arguments() {
        assert_eq!(
            validate_connect_tcp_shape(1, 443, net_abi::NETWORK_CONNECT_FLAG_NONE),
            Ok(())
        );
    }

    #[test]
    fn validate_connect_tcp_shape_rejects_invalid_argument_shapes() {
        assert_eq!(
            validate_connect_tcp_shape(0, 443, net_abi::NETWORK_CONNECT_FLAG_NONE),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            validate_connect_tcp_shape(1, 0, net_abi::NETWORK_CONNECT_FLAG_NONE),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            validate_connect_tcp_shape(
                1,
                u16::MAX as usize + 1,
                net_abi::NETWORK_CONNECT_FLAG_NONE,
            ),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            validate_connect_tcp_shape(1, 443, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn connect_tcp_request_rejects_non_utf8_host_bytes() {
        let host = [0xff_u8, 0xfe];
        let context = SyscallContext::new(
            SyscallNumber::ConnectTcp as usize,
            [
                host.as_ptr() as usize,
                host.len(),
                443,
                net_abi::NETWORK_CONNECT_FLAG_NONE,
                0,
                0,
            ],
        );

        assert!(matches!(
            connect_tcp_request(&context),
            Err(Error::InvalidArgument)
        ));
    }

    #[test]
    fn connect_tcp_request_rejects_non_zero_reserved_args() {
        let host = b"example";
        let context = SyscallContext::new(
            SyscallNumber::ConnectTcp as usize,
            [
                host.as_ptr() as usize,
                host.len(),
                443,
                net_abi::NETWORK_CONNECT_FLAG_NONE,
                1,
                0,
            ],
        );

        assert!(matches!(
            connect_tcp_request(&context),
            Err(Error::InvalidArgument)
        ));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn connect_tcp_installs_network_descriptor_for_current_process() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("network-syscall");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let server = std::thread::spawn(move || {
            let (_socket, _) = listener.accept().expect("accept loopback connection");
        });
        let host = b"127.0.0.1";
        let mut context = SyscallContext::new(
            SyscallNumber::ConnectTcp as usize,
            [
                host.as_ptr() as usize,
                host.len(),
                port as usize,
                net_abi::NETWORK_CONNECT_FLAG_NONE,
                0,
                0,
            ],
        );

        let dispatch = connect_tcp(&mut context).expect("connect tcp syscall");
        let fd = dispatch.value;
        assert_eq!(dispatch, SyscallDispatch::complete(fd));

        let entry = process.fd_entry(fd).expect("resolve network fd");
        assert_eq!(entry.rights, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE);
        match entry.object {
            KernelObject::Network(connection) => {
                assert_eq!(connection.endpoint(), &format!("127.0.0.1:{port}"));
            }
            other => panic!("expected network descriptor, found {other:?}"),
        }

        process.close_fd(fd).expect("close network fd");
        server.join().expect("join loopback server");
    }
}
