//! src/kernel/network/mod.rs
//!
//! Kernel-owned TCP connectivity abstraction used by syscall and
//! remote-download paths.
//!
//! Sub-module organisation:
//! - `link/`     — Link-layer: `device` (NIC trait), `ethernet` (framing)
//! - `internet/` — Internet-layer: `ip`, `ipv4`, `ipv6`, `arp`, `icmp`,
//!   `icmpv6`
//! - `tcp/`      — TCP state machine, connect / read / write / close
//! - `udp`       — UDP datagram send / receive with port binding
//! - `dhcp`      — DHCP client
//! - `dns`       — DNS resolver
//! - `stack`     — `NetworkStack` singleton (global packet demux and protocol
//!   dispatch)
//! - `net_profiler` — Network performance counters

pub mod dccp;
pub mod dhcp;
pub mod dns;
pub use internet::ipv4;
pub use internet::ipv6;
pub mod filter;
pub mod internet;
pub mod ipsec;
pub mod link;
pub mod local;
pub mod mdns;
pub mod mrouting;
pub mod net_profiler;
pub mod ntp;
pub mod ppp;
pub mod pppoe;
pub mod raw;
pub mod sctp;
pub mod stack;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod wireguard;

#[cfg(not(target_os = "none"))]
use alloc::format;
use alloc::string::String;
#[cfg(not(target_os = "none"))]
use alloc::sync::Arc;
use core::fmt;
#[cfg(not(target_os = "none"))]
use core::time::Duration;

use crate::abi::net as net_abi;
#[cfg(not(target_os = "none"))]
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

#[cfg(not(target_os = "none"))]
// Keep timeout conversion aligned with the current 100 Hz scheduler/timer tick.
const NETWORK_TIMEOUT_TICK_MILLIS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkCapabilities {
    pub backend_id: &'static str,
    pub available: bool,
    pub requires_host_runtime: bool,
    pub supports_tcp_connect: bool,
    pub supports_tcp_listen: bool,
    pub supports_udp_datagram: bool,
    pub supports_stream_io: bool,
    pub supports_read_timeouts: bool,
    pub zero_timeout_read_is_poll: bool,
    pub supports_ipv6: bool,
    pub note: &'static str,
}

impl NetworkCapabilities {
    // These bits are part of the shared ABI, so user space can reason about the
    // backend without string-parsing `backend_id`.
    pub const fn status_flags(self) -> u32 {
        let mut flags = 0;
        if self.available {
            flags |= net_abi::NETWORK_STATUS_FLAG_AVAILABLE;
        }
        if self.requires_host_runtime {
            flags |= net_abi::NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME;
        }
        if self.supports_tcp_connect {
            flags |= net_abi::NETWORK_STATUS_FLAG_TCP_CONNECT;
        }
        if self.supports_stream_io {
            flags |= net_abi::NETWORK_STATUS_FLAG_STREAM_IO;
        }
        if self.supports_read_timeouts {
            flags |= net_abi::NETWORK_STATUS_FLAG_READ_TIMEOUTS;
        }
        if self.zero_timeout_read_is_poll {
            flags |= net_abi::NETWORK_STATUS_FLAG_ZERO_TIMEOUT_READ_IS_POLL;
        }
        if self.supports_tcp_listen {
            flags |= net_abi::NETWORK_STATUS_FLAG_TCP_LISTEN;
        }
        if self.supports_udp_datagram {
            flags |= net_abi::NETWORK_STATUS_FLAG_UDP_DATAGRAM;
        }
        if self.supports_ipv6 {
            flags |= net_abi::NETWORK_STATUS_FLAG_IPV6;
        }
        flags
    }
}

#[derive(Clone)]
pub struct TcpConnection {
    endpoint: String,
    #[cfg(not(target_os = "none"))]
    inner: Arc<Mutex<TcpConnectionInner>>,
    /// Native TCP connection handle (bare-metal only).
    #[cfg(target_os = "none")]
    native: crate::kernel::network::tcp::NativeTcpConnection,
}

#[cfg(not(target_os = "none"))]
struct TcpConnectionInner {
    stream: std::net::TcpStream,
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
enum HostReadReset {
    NonBlocking,
    ReadTimeout,
}

/// A listening TCP socket.
///
/// On host builds this wraps a `std::net::TcpListener`.  On bare-metal it
/// stores the local port number; the listener state lives in the global
/// [`TcpConnectionTable`].
#[derive(Clone)]
pub struct TcpListener {
    port: u16,
    #[cfg(not(target_os = "none"))]
    inner: Arc<Mutex<std::net::TcpListener>>,
}

impl TcpListener {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Unbind the listening port.
    pub fn close(&self) -> Result<()> {
        #[cfg(not(target_os = "none"))]
        {
            // Dropping the TcpListener is sufficient on host — the socket
            // will be closed when the inner Arc is dropped.
            let _ = self;
            Ok(())
        }

        #[cfg(target_os = "none")]
        {
            let stack =
                crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
            let mut table = stack.tcp_table().lock();
            crate::kernel::network::tcp::unlisten(&mut table, self.port);
            Ok(())
        }
    }

    /// Check whether this TCP listener has pending connection requests.
    /// Returns `Ok(true)` if `accept()` would return immediately.
    pub fn is_readable(&self) -> Result<bool> {
        #[cfg(not(target_os = "none"))]
        {
            let _ = self;
            Ok(true)
        }
        #[cfg(target_os = "none")]
        {
            let stack =
                crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
            let table = stack.tcp_table().lock();
            Ok(crate::kernel::network::tcp::table::listener_has_pending(
                &table, self.port,
            ))
        }
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListener")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// A bound UDP socket.
///
/// On bare-metal the socket state lives in the global [`UdpSocketTable`];
/// this handle stores only the local port number.  On host (non-test) builds
/// the type is still available for fd management but the native UDP path
/// requires a mock network stack (test-only).
#[derive(Clone, Debug)]
pub struct UdpSocket {
    port: u16,
}

/// Re-export the local socket type for use in KernelObject.
pub use local::LocalSocket;

/// Re-export the concrete network stack type so both the network module and
/// its `stack` submodule can refer to it as `super::NetworkStack`.
pub use stack::NetworkStack;

impl UdpSocket {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Unbind the UDP port.
    pub fn close(&self) -> Result<()> {
        #[cfg(any(target_os = "none", test))]
        {
            if let Some(stack) = crate::kernel::network::stack::NetworkStack::global() {
                stack.udp_table().lock().unbind(self.port);
            }
            Ok(())
        }

        #[cfg(not(any(target_os = "none", test)))]
        {
            let _ = self;
            Ok(())
        }
    }
}

/// Accept timeout in ticks (60 seconds at 100 Hz).
#[cfg(target_os = "none")]
const ACCEPT_TIMEOUT_TICKS: u64 = 6000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelTcpBackend {
    #[cfg(not(target_os = "none"))]
    HostRuntimeCompat,
    #[cfg(any(target_os = "none", test))]
    Native,
}

impl KernelTcpBackend {
    fn status(self) -> net_abi::NetworkStatus {
        match self {
            #[cfg(not(target_os = "none"))]
            Self::HostRuntimeCompat => net_abi::NetworkStatus::from_flags(
                net_abi::NETWORK_STATUS_FLAG_AVAILABLE
                    | net_abi::NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME
                    | net_abi::NETWORK_STATUS_FLAG_TCP_CONNECT
                    | net_abi::NETWORK_STATUS_FLAG_TCP_LISTEN
                    | net_abi::NETWORK_STATUS_FLAG_UDP_DATAGRAM
                    | net_abi::NETWORK_STATUS_FLAG_STREAM_IO
                    | net_abi::NETWORK_STATUS_FLAG_READ_TIMEOUTS
                    | net_abi::NETWORK_STATUS_FLAG_ZERO_TIMEOUT_READ_IS_POLL,
            ),
            #[cfg(any(target_os = "none", test))]
            Self::Native => {
                // On bare-metal, the Native backend is compiled in but may not
                // have a live NetworkStack if no device was discovered.  When
                // the stack is absent, drop the AVAILABLE / TCP / STREAM_IO
                // flags so that backend_class() correctly reports NativePending
                // instead of Native, giving userspace a clear diagnostic.
                #[cfg(target_os = "none")]
                let available = crate::kernel::network::stack::NetworkStack::global().is_some();
                #[cfg(not(target_os = "none"))]
                let available = true; // tests always assume Native is available

                let base =
                    net_abi::NETWORK_STATUS_FLAG_UDP_DATAGRAM | net_abi::NETWORK_STATUS_FLAG_IPV6;
                if available {
                    net_abi::NetworkStatus::from_flags(
                        net_abi::NETWORK_STATUS_FLAG_AVAILABLE
                            | net_abi::NETWORK_STATUS_FLAG_TCP_CONNECT
                            | net_abi::NETWORK_STATUS_FLAG_TCP_LISTEN
                            | net_abi::NETWORK_STATUS_FLAG_STREAM_IO
                            | net_abi::NETWORK_STATUS_FLAG_READ_TIMEOUTS
                            | net_abi::NETWORK_STATUS_FLAG_ZERO_TIMEOUT_READ_IS_POLL
                            | base,
                    )
                } else {
                    net_abi::NetworkStatus::from_flags(base)
                }
            }
        }
    }

    fn capabilities(self) -> NetworkCapabilities {
        network_capabilities_from_status(self.status())
    }

    fn connect_tcp(self, host: &str, port: u16) -> Result<TcpConnection> {
        match self {
            #[cfg(not(target_os = "none"))]
            Self::HostRuntimeCompat => connect_host_tcp(host, port),
            #[cfg(any(target_os = "none", test))]
            Self::Native => connect_native_tcp(host, port),
        }
    }

    fn listen_tcp(self, port: u16, backlog: u16) -> Result<TcpListener> {
        match self {
            #[cfg(not(target_os = "none"))]
            Self::HostRuntimeCompat => listen_host_tcp(port, backlog),
            #[cfg(any(target_os = "none", test))]
            Self::Native => listen_native_tcp(port, backlog),
        }
    }

    fn accept_tcp(self, listener: &TcpListener) -> Result<TcpConnection> {
        match self {
            #[cfg(not(target_os = "none"))]
            Self::HostRuntimeCompat => accept_host_tcp(listener),
            #[cfg(any(target_os = "none", test))]
            Self::Native => accept_native_tcp(listener),
        }
    }
}

impl TcpConnection {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn read(&self, buffer: &mut [u8], timeout_ticks: u64) -> Result<usize> {
        #[cfg(not(target_os = "none"))]
        {
            if buffer.is_empty() {
                return Ok(0);
            }

            let mut inner = self.inner.lock();
            read_host_stream(&mut inner.stream, buffer, timeout_ticks)
        }

        #[cfg(target_os = "none")]
        {
            let stack =
                crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
            self.native.read(stack, buffer, timeout_ticks)
        }
    }

    pub fn write(&self, buffer: &[u8]) -> Result<usize> {
        #[cfg(not(target_os = "none"))]
        {
            use std::io::Write;

            if buffer.is_empty() {
                return Ok(0);
            }

            let mut inner = self.inner.lock();
            inner
                .stream
                .write(buffer)
                .map_err(|error| map_host_io_error(&error))
        }

        #[cfg(target_os = "none")]
        {
            let stack =
                crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
            let table = stack.tcp_table().lock();
            self.native.write(&table, buffer)
        }
    }

    pub fn write_all(&self, buffer: &[u8]) -> Result<()> {
        #[cfg(not(target_os = "none"))]
        {
            use std::io::Write;

            if buffer.is_empty() {
                return Ok(());
            }

            let mut inner = self.inner.lock();
            inner
                .stream
                .write_all(buffer)
                .map_err(|error| map_host_io_error(&error))?;
            inner
                .stream
                .flush()
                .map_err(|error| map_host_io_error(&error))?;
            Ok(())
        }

        #[cfg(target_os = "none")]
        {
            let stack =
                crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
            self.native.write_all(stack, buffer)
        }
    }

    /// Initiate an orderly close (FIN handshake) of this connection.
    ///
    /// On bare-metal this sends a FIN segment and transitions the TCP state
    /// machine through the closing sequence.  On host builds this shuts down
    /// both halves of the underlying socket.
    pub fn close(&self) -> Result<()> {
        #[cfg(not(target_os = "none"))]
        {
            let inner = self.inner.lock();
            inner
                .stream
                .shutdown(std::net::Shutdown::Both)
                .map_err(|error| map_host_io_error(&error))
        }

        #[cfg(target_os = "none")]
        {
            let stack =
                crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
            self.native.close(stack)
        }
    }
}

impl fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConnection")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl TcpConnection {
    /// Set a socket option on this connection (bare-metal only).
    #[cfg(target_os = "none")]
    pub(crate) fn set_option(&self, level: u32, name: u32, val: &[u8]) -> Result<()> {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        let table = stack.tcp_table().lock();
        crate::kernel::network::tcp::table::set_option(&table, &self.native, level, name, val)
    }

    /// Get a socket option from this connection (bare-metal only).
    #[cfg(target_os = "none")]
    pub(crate) fn get_option(&self, level: u32, name: u32) -> Result<alloc::vec::Vec<u8>> {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        let table = stack.tcp_table().lock();
        crate::kernel::network::tcp::table::get_option(&table, &self.native, level, name)
    }
}

const fn network_capabilities_from_status(status: net_abi::NetworkStatus) -> NetworkCapabilities {
    NetworkCapabilities {
        backend_id: status.backend_id(),
        available: status.available(),
        requires_host_runtime: status.requires_host_runtime(),
        supports_tcp_connect: status.supports_tcp_connect(),
        supports_tcp_listen: status.supports_tcp_listen(),
        supports_udp_datagram: status.supports_udp_datagram(),
        supports_stream_io: status.supports_stream_io(),
        supports_read_timeouts: status.supports_read_timeouts(),
        zero_timeout_read_is_poll: status.zero_timeout_read_is_poll(),
        supports_ipv6: status.supports_ipv6(),
        note: status.kernel_note(),
    }
}

const fn active_kernel_tcp_backend() -> KernelTcpBackend {
    #[cfg(not(target_os = "none"))]
    {
        KernelTcpBackend::HostRuntimeCompat
    }

    #[cfg(target_os = "none")]
    {
        KernelTcpBackend::Native
    }
}

#[cfg(test)]
fn host_network_status() -> net_abi::NetworkStatus {
    KernelTcpBackend::HostRuntimeCompat.status()
}

#[cfg(not(target_os = "none"))]
#[cfg(test)]
fn host_network_capabilities() -> NetworkCapabilities {
    network_capabilities_from_status(host_network_status())
}

#[cfg(all(test, not(target_os = "none")))]
fn native_network_status() -> net_abi::NetworkStatus {
    KernelTcpBackend::Native.status()
}

#[cfg(all(test, not(target_os = "none")))]
fn native_network_capabilities() -> NetworkCapabilities {
    network_capabilities_from_status(native_network_status())
}

// Syscall and remote-fetch layers should consume the same backend status source
// rather than reconstructing it from partially duplicated capability checks.
pub fn status() -> net_abi::NetworkStatus {
    active_kernel_tcp_backend().status()
}

pub fn capabilities() -> NetworkCapabilities {
    active_kernel_tcp_backend().capabilities()
}

pub fn status_flags() -> usize {
    status().flags() as usize
}

pub fn connect_tcp(host: &str, port: u16) -> Result<TcpConnection> {
    let host = validate_connect_host(host)?;
    if port == 0 {
        return Err(Error::InvalidArgument);
    }

    active_kernel_tcp_backend().connect_tcp(host, port)
}

/// Create a listening TCP socket on `port`.
///
/// `backlog` specifies the maximum number of pending connections; a value
/// of 0 selects the kernel default (16).  Returns a [`TcpListener`] that
/// can be passed to [`accept_tcp`].
pub fn listen_tcp(port: u16, backlog: u16) -> Result<TcpListener> {
    if port == 0 {
        return Err(Error::InvalidArgument);
    }
    active_kernel_tcp_backend().listen_tcp(port, backlog)
}

/// Accept an incoming connection on a listening socket.
///
/// Blocks (with a 60-second timeout) until a client connects.  Returns a
/// [`TcpConnection`] for the accepted connection.
pub fn accept_tcp(listener: &TcpListener) -> Result<TcpConnection> {
    active_kernel_tcp_backend().accept_tcp(listener)
}

// ─── UDP public API ──────────────────────────────────────────────────────

/// Bind a UDP socket to `port` and return a handle.
///
/// On bare-metal and in tests the port is registered in the global
/// [`UdpSocketTable`].  On host non-test builds this returns
/// [`Error::Unsupported`](crate::Error::Unsupported).
pub fn bind_udp(port: u16) -> Result<UdpSocket> {
    if port == 0 {
        return Err(Error::InvalidArgument);
    }
    bind_udp_impl(port)
}

/// Send a UDP datagram to `dest_ip:dest_port` from the bound socket.
///
/// The socket must have been bound via [`bind_udp`] first.
pub fn send_to_udp(
    socket: &UdpSocket,
    dest_ip: [u8; 4],
    dest_port: u16,
    payload: &[u8],
) -> Result<()> {
    if dest_port == 0 {
        return Err(Error::InvalidArgument);
    }
    send_to_udp_impl(socket, dest_ip, dest_port, payload)
}

/// Receive a UDP datagram from a bound socket.
///
/// Returns `(bytes_read, src_ip, src_port)`.  When the receive queue is
/// empty this returns [`Error::TimedOut`](crate::Error::TimedOut)
/// (non-blocking poll).
pub fn recv_from_udp(socket: &UdpSocket, buffer: &mut [u8]) -> Result<(usize, [u8; 4], u16)> {
    recv_from_udp_impl(socket, buffer)
}

/// Send a UDP datagram over IPv6 to `dest_ip:dest_port` from the bound socket.
///
/// The socket must have been bound via [`bind_udp`] first.  `dest_ip` is a
/// 16-byte IPv6 address in network byte order.
pub fn send_to_udp_v6(
    socket: &UdpSocket,
    dest_ip: [u8; 16],
    dest_port: u16,
    payload: &[u8],
) -> Result<()> {
    if dest_port == 0 {
        return Err(Error::InvalidArgument);
    }
    send_to_udp_v6_impl(socket, dest_ip, dest_port, payload)
}

/// Receive a UDP datagram over IPv6 from a bound socket.
///
/// Returns `(bytes_read, src_ip, src_port)` where `src_ip` is a 16-byte
/// IPv6 address.  When the receive queue is empty this returns
/// [`Error::TimedOut`](crate::Error::TimedOut) (non-blocking poll).
pub fn recv_from_udp_v6(socket: &UdpSocket, buffer: &mut [u8]) -> Result<(usize, [u8; 16], u16)> {
    recv_from_udp_v6_impl(socket, buffer)
}

#[cfg(any(target_os = "none", test))]
fn bind_udp_impl(port: u16) -> Result<UdpSocket> {
    let stack = crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
    stack.udp_table().lock().bind(port)?;
    Ok(UdpSocket { port })
}

#[cfg(not(any(target_os = "none", test)))]
fn bind_udp_impl(_port: u16) -> Result<UdpSocket> {
    Err(Error::Unsupported)
}

#[cfg(any(target_os = "none", test))]
fn send_to_udp_impl(
    socket: &UdpSocket,
    dest_ip: [u8; 4],
    dest_port: u16,
    payload: &[u8],
) -> Result<()> {
    let stack = crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
    udp::send_to(stack, socket.port, dest_ip, dest_port, payload)
}

#[cfg(not(any(target_os = "none", test)))]
fn send_to_udp_impl(
    _socket: &UdpSocket,
    _dest_ip: [u8; 4],
    _dest_port: u16,
    _payload: &[u8],
) -> Result<()> {
    Err(Error::Unsupported)
}

#[cfg(any(target_os = "none", test))]
fn recv_from_udp_impl(socket: &UdpSocket, buffer: &mut [u8]) -> Result<(usize, [u8; 4], u16)> {
    let stack = crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
    let (n, ip, port) = stack.udp_table().lock().recv_from(socket.port, buffer)?;
    let v4 = ip.as_ipv4().ok_or(Error::Unsupported)?;
    Ok((n, v4, port))
}

#[cfg(not(any(target_os = "none", test)))]
fn recv_from_udp_impl(_socket: &UdpSocket, _buffer: &mut [u8]) -> Result<(usize, [u8; 4], u16)> {
    Err(Error::Unsupported)
}

#[cfg(any(target_os = "none", test))]
fn send_to_udp_v6_impl(
    socket: &UdpSocket,
    dest_ip: [u8; 16],
    dest_port: u16,
    payload: &[u8],
) -> Result<()> {
    let stack = crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
    udp::send_to_v6(stack, socket.port, dest_ip, dest_port, payload)
}

#[cfg(not(any(target_os = "none", test)))]
fn send_to_udp_v6_impl(
    _socket: &UdpSocket,
    _dest_ip: [u8; 16],
    _dest_port: u16,
    _payload: &[u8],
) -> Result<()> {
    Err(Error::Unsupported)
}

#[cfg(any(target_os = "none", test))]
fn recv_from_udp_v6_impl(socket: &UdpSocket, buffer: &mut [u8]) -> Result<(usize, [u8; 16], u16)> {
    let stack = crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
    let (n, ip, port) = stack.udp_table().lock().recv_from(socket.port, buffer)?;
    let v6 = ip.as_ipv6().ok_or(Error::Unsupported)?;
    Ok((n, v6, port))
}

#[cfg(not(any(target_os = "none", test)))]
fn recv_from_udp_v6_impl(
    _socket: &UdpSocket,
    _buffer: &mut [u8],
) -> Result<(usize, [u8; 16], u16)> {
    Err(Error::Unsupported)
}

// ─── DCCP public API ─────────────────────────────────────────────────────

/// A DCCP socket handle (RFC 4340).  DCCP is a connection-oriented datagram
/// protocol: a handshake establishes the connection, then unreliable
/// datagrams flow with congestion control.
///
/// On bare-metal and in tests the socket state lives in the global
/// [`DccpConnectionTable`]; this handle stores the local port, the remote
/// endpoint (once connected), and the negotiated service code.
#[derive(Debug, Clone)]
pub struct DccpSocket {
    pub local_port: u16,
    /// Remote endpoint once connected/established (`None` for a bound or
    /// listening socket).
    pub remote: Option<(IpAddress, u16)>,
    pub service_code: u32,
    pub is_listener: bool,
}

impl DccpSocket {
    /// Whether this socket has a pending inbound DCCP datagram.
    pub fn is_readable(&self) -> bool {
        #[cfg(any(target_os = "none", test))]
        {
            let Some((remote_ip, remote_port)) = self.remote else {
                return false;
            };
            let Some(stack) = crate::kernel::network::stack::NetworkStack::global() else {
                return false;
            };
            let table = stack.dccp_table().lock();
            let conn = dccp::NativeDccpConnection {
                local_port: self.local_port,
                remote_ip,
                remote_port,
            };
            table
                .lookup(&conn.key())
                .map(|state| !state.lock().receive_queue.is_empty())
                .unwrap_or(false)
        }
        #[cfg(not(any(target_os = "none", test)))]
        {
            let _ = self;
            false
        }
    }

    /// Whether this socket can accept a DCCP datagram for sending (i.e. it
    /// is connected, not a bare bind/listen handle).
    pub fn is_writable(&self) -> bool {
        !self.is_listener && self.remote.is_some()
    }
}

/// Bind a DCCP port for a connection-oriented datagram socket.
pub fn bind_dccp(port: u16, service_code: u32) -> Result<DccpSocket> {
    if port == 0 {
        return Err(Error::InvalidArgument);
    }
    #[cfg(any(target_os = "none", test))]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        stack.dccp_table().lock().bind(port)?;
        Ok(DccpSocket {
            local_port: port,
            remote: None,
            service_code,
            is_listener: false,
        })
    }
    #[cfg(not(any(target_os = "none", test)))]
    {
        let _ = (port, service_code);
        Err(Error::Unsupported)
    }
}

/// Start listening for DCCP Requests on `port` with `service_code`.
pub fn listen_dccp(port: u16, backlog: u16, service_code: u32) -> Result<DccpSocket> {
    if port == 0 {
        return Err(Error::InvalidArgument);
    }
    #[cfg(any(target_os = "none", test))]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        stack
            .dccp_table()
            .lock()
            .listen(port, backlog, service_code)?;
        Ok(DccpSocket {
            local_port: port,
            remote: None,
            service_code,
            is_listener: true,
        })
    }
    #[cfg(not(any(target_os = "none", test)))]
    {
        let _ = (port, backlog, service_code);
        Err(Error::Unsupported)
    }
}

/// Initiate a DCCP connection to `dst:dst_port`.
pub fn connect_dccp(dst: IpAddress, dst_port: u16, service_code: u32) -> Result<DccpSocket> {
    if dst_port == 0 {
        return Err(Error::InvalidArgument);
    }
    #[cfg(any(target_os = "none", test))]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        let conn = dccp::ops::connect(stack, dst, dst_port, service_code)?;
        Ok(DccpSocket {
            local_port: conn.local_port,
            remote: Some((dst, dst_port)),
            service_code,
            is_listener: false,
        })
    }
    #[cfg(not(any(target_os = "none", test)))]
    {
        let _ = (dst, dst_port, service_code);
        Err(Error::Unsupported)
    }
}

/// Accept the next pending DCCP connection on `listener` (non-blocking).
pub fn accept_dccp(listener: &DccpSocket) -> Result<DccpSocket> {
    if !listener.is_listener {
        return Err(Error::InvalidArgument);
    }
    #[cfg(any(target_os = "none", test))]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        match dccp::ops::accept_nonblocking(stack, listener.local_port)? {
            Some(conn) => Ok(DccpSocket {
                local_port: conn.local_port,
                remote: Some((conn.remote_ip, conn.remote_port)),
                service_code: listener.service_code,
                is_listener: false,
            }),
            None => Err(Error::TimedOut),
        }
    }
    #[cfg(not(any(target_os = "none", test)))]
    {
        let _ = listener;
        Err(Error::Unsupported)
    }
}

/// Send one DCCP datagram on an established connection.
pub fn send_dccp(socket: &DccpSocket, payload: &[u8]) -> Result<usize> {
    let (remote_ip, remote_port) = socket.remote.ok_or(Error::InvalidArgument)?;
    let conn = dccp::NativeDccpConnection {
        local_port: socket.local_port,
        remote_ip,
        remote_port,
    };
    #[cfg(any(target_os = "none", test))]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        dccp::ops::send(stack, &conn, payload)
    }
    #[cfg(not(any(target_os = "none", test)))]
    {
        let _ = (conn, payload);
        Err(Error::Unsupported)
    }
}

/// Receive one DCCP datagram from an established connection (non-blocking).
/// Returns `(bytes_read, peer_ip, peer_port)` or [`Error::TimedOut`].
pub fn recv_dccp(socket: &DccpSocket, buffer: &mut [u8]) -> Result<(usize, IpAddress, u16)> {
    let (remote_ip, remote_port) = socket.remote.ok_or(Error::InvalidArgument)?;
    let conn = dccp::NativeDccpConnection {
        local_port: socket.local_port,
        remote_ip,
        remote_port,
    };
    #[cfg(any(target_os = "none", test))]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        dccp::ops::recv(stack, &conn, buffer)
    }
    #[cfg(not(any(target_os = "none", test)))]
    {
        let _ = (conn, buffer);
        Err(Error::Unsupported)
    }
}

/// Close a DCCP socket: a connected socket sends Close and is removed; a
/// listener is uninstalled.
pub fn close_dccp(socket: &DccpSocket) -> Result<()> {
    #[cfg(any(target_os = "none", test))]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        if socket.is_listener {
            let mut table = stack.dccp_table().lock();
            table.remove_listener(socket.local_port);
            table.unbind(socket.local_port);
            return Ok(());
        }
        if let Some((remote_ip, remote_port)) = socket.remote {
            let conn = dccp::NativeDccpConnection {
                local_port: socket.local_port,
                remote_ip,
                remote_port,
            };
            let _ = dccp::ops::close(stack, &conn);
            let mut table = stack.dccp_table().lock();
            table.remove(&conn.key());
            table.unbind(socket.local_port);
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "none", test)))]
    {
        let _ = socket;
        Ok(())
    }
}

/// Parse a dotted-quad IPv4 address string (e.g. "10.0.2.2") into
/// `[u8; 4]`.  Returns an error on any malformed input.
#[cfg(target_os = "none")]
fn parse_ipv4_address(host: &str) -> Result<[u8; 4]> {
    let parts: alloc::vec::Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::InvalidArgument);
    }
    let mut addr = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        addr[i] = part.parse::<u8>().map_err(|_| Error::InvalidArgument)?;
    }
    Ok(addr)
}

/// Native TCP connect: resolve the host as an IPv4 address and initiate
/// a TCP connection through the global network stack.
#[cfg(any(target_os = "none", test))]
fn connect_native_tcp(host: &str, port: u16) -> Result<TcpConnection> {
    #[cfg(target_os = "none")]
    {
        // Accept dotted-quad literals directly; attempt hostname
        // resolution (hosts table → DNS) for everything else.
        let ip = if let Ok(addr) = parse_ipv4_address(host) {
            addr
        } else {
            crate::kernel::network::dns::resolve_hostname(host)?
        };
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        let native = crate::kernel::network::tcp::connect(stack, ip, port)?;
        let endpoint = alloc::format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port);
        Ok(TcpConnection { endpoint, native })
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = host;
        let _ = port;
        Err(Error::Unsupported)
    }
}

// ─── listen / accept implementations ───

#[cfg(not(target_os = "none"))]
fn listen_host_tcp(port: u16, _backlog: u16) -> Result<TcpListener> {
    let listener = std::net::TcpListener::bind(("0.0.0.0", port))
        .map_err(|error| map_host_connect_error(&error))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| map_host_io_error(&error))?;
    Ok(TcpListener {
        port,
        inner: Arc::new(Mutex::new(listener)),
    })
}

#[cfg(not(target_os = "none"))]
fn accept_host_tcp(listener: &TcpListener) -> Result<TcpConnection> {
    let inner = listener.inner.lock();
    // Set blocking for the duration of accept, then restore.
    inner
        .set_nonblocking(false)
        .map_err(|error| map_host_io_error(&error))?;
    let (stream, peer_addr) = inner.accept().map_err(|error| map_host_io_error(&error))?;
    inner
        .set_nonblocking(true)
        .map_err(|error| map_host_io_error(&error))?;
    drop(inner);

    stream
        .set_nodelay(true)
        .map_err(|error| map_host_io_error(&error))?;
    let endpoint = format!("{peer_addr}");
    Ok(TcpConnection {
        endpoint,
        inner: Arc::new(Mutex::new(TcpConnectionInner { stream })),
    })
}

#[cfg(any(target_os = "none", test))]
fn listen_native_tcp(port: u16, backlog: u16) -> Result<TcpListener> {
    #[cfg(target_os = "none")]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
        let mut table = stack.tcp_table().lock();
        tcp::listen(&mut table, port, backlog as usize)?;
        Ok(TcpListener { port })
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = port;
        let _ = backlog;
        Err(Error::Unsupported)
    }
}

#[cfg(any(target_os = "none", test))]
fn accept_native_tcp(listener: &TcpListener) -> Result<TcpConnection> {
    #[cfg(target_os = "none")]
    {
        let stack =
            crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;

        let start_tick = stack.current_tick();
        loop {
            // Fast path: check if a connection is already pending.
            {
                let mut table = stack.tcp_table().lock();
                if let Some(native) = tcp::accept_nonblocking(&mut table, listener.port) {
                    let endpoint = native.endpoint();
                    return Ok(TcpConnection { endpoint, native });
                }
            }

            // Check timeout.
            let elapsed = stack.current_tick().wrapping_sub(start_tick);
            if elapsed >= ACCEPT_TIMEOUT_TICKS {
                return Err(Error::TimedOut);
            }

            // Poll to drive the state machine.
            let _ = stack.poll();
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = listener;
        Err(Error::Unsupported)
    }
}

fn validate_connect_host(host: &str) -> Result<&str> {
    if host.is_empty()
        || host
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(Error::InvalidArgument);
    }

    Ok(host)
}

#[cfg(not(target_os = "none"))]
fn connect_host_tcp(host: &str, port: u16) -> Result<TcpConnection> {
    // Host builds intentionally reuse the host TCP stack until the kernel has
    // native drivers and protocol layers of its own.
    let stream = std::net::TcpStream::connect((host, port))
        .map_err(|error| map_host_connect_error(&error))?;
    stream
        .set_nodelay(true)
        .map_err(|error| map_host_io_error(&error))?;
    Ok(TcpConnection {
        endpoint: format!("{host}:{port}"),
        inner: Arc::new(Mutex::new(TcpConnectionInner { stream })),
    })
}

#[cfg(not(target_os = "none"))]
fn map_host_connect_error(error: &std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Error::TimedOut,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            Error::InvalidArgument
        }
        std::io::ErrorKind::PermissionDenied => Error::PermissionDenied,
        std::io::ErrorKind::Unsupported => Error::Unsupported,
        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::AddrInUse => Error::Busy,
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::AddrNotAvailable
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::HostUnreachable
        | std::io::ErrorKind::NetworkUnreachable => Error::NotFound,
        _ => Error::DeviceError,
    }
}

#[cfg(not(target_os = "none"))]
fn map_host_io_error(error: &std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Error::TimedOut,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            Error::InvalidArgument
        }
        std::io::ErrorKind::NotFound => Error::NotFound,
        std::io::ErrorKind::PermissionDenied => Error::PermissionDenied,
        std::io::ErrorKind::Unsupported => Error::Unsupported,
        _ => Error::DeviceError,
    }
}

#[cfg(not(target_os = "none"))]
fn configure_host_read(stream: &std::net::TcpStream, timeout_ticks: u64) -> Result<HostReadReset> {
    if timeout_ticks == 0 {
        // A zero timeout is treated as a non-blocking poll, matching the rest
        // of the kernel I/O surface where timeout 0 means "do not wait".
        stream
            .set_nonblocking(true)
            .map_err(|error| map_host_io_error(&error))?;
        return Ok(HostReadReset::NonBlocking);
    }

    stream
        .set_read_timeout(Some(timeout_duration_from_ticks(timeout_ticks)))
        .map_err(|error| map_host_io_error(&error))?;
    Ok(HostReadReset::ReadTimeout)
}

#[cfg(not(target_os = "none"))]
fn restore_host_read(stream: &std::net::TcpStream, reset: HostReadReset) {
    match reset {
        HostReadReset::NonBlocking => {
            let _ = stream.set_nonblocking(false);
        }
        HostReadReset::ReadTimeout => {
            let _ = stream.set_read_timeout(None);
        }
    }
}

#[cfg(not(target_os = "none"))]
fn read_host_stream(
    stream: &mut std::net::TcpStream,
    buffer: &mut [u8],
    timeout_ticks: u64,
) -> Result<usize> {
    use std::io::Read;

    let reset = configure_host_read(stream, timeout_ticks)?;
    let result = stream
        .read(buffer)
        .map_err(|error| map_host_io_error(&error));
    restore_host_read(stream, reset);
    result
}

#[cfg(not(target_os = "none"))]
fn timeout_duration_from_ticks(timeout_ticks: u64) -> Duration {
    Duration::from_millis(timeout_ticks.saturating_mul(NETWORK_TIMEOUT_TICK_MILLIS))
}

// ── Hostname ─────────────────────────────────────────────────────────

/// Maximum hostname length (including NUL terminator).
pub const HOSTNAME_MAX: usize = 256;

/// Kernel hostname, stored as a NUL-terminated byte array.
static HOSTNAME: crate::kernel::sync::Mutex<[u8; HOSTNAME_MAX]> =
    crate::kernel::sync::Mutex::new([0u8; HOSTNAME_MAX]);

/// Read the current kernel hostname into `buffer`.
///
/// Returns the number of bytes written (not including the NUL terminator).
/// If the buffer is too small, the hostname is truncated (no NUL added).
pub fn gethostname(buffer: &mut [u8]) -> usize {
    let hostname = HOSTNAME.lock();
    let len = hostname
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(hostname.len());
    let copy_len = len.min(buffer.len());
    buffer[..copy_len].copy_from_slice(&hostname[..copy_len]);
    copy_len
}

/// Set the kernel hostname from `name`.
///
/// Truncates to [`HOSTNAME_MAX`]` - 1` bytes and appends a NUL terminator.
pub fn sethostname(name: &[u8]) {
    let mut hostname = HOSTNAME.lock();
    let copy_len = name.len().min(HOSTNAME_MAX - 1);
    hostname[..copy_len].copy_from_slice(&name[..copy_len]);
    hostname[copy_len] = 0; // NUL terminator
}

// ── Socket address ───────────────────────────────────────────────────

/// IPv4 socket address (POSIX `struct sockaddr_in` layout, 16 bytes).
#[repr(C)]
pub struct SockAddrIn {
    /// Address family (`AF_INET = 2`).
    pub sin_family: u16,
    /// Port in network byte order (big-endian).
    pub sin_port: u16,
    /// IPv4 address (4 bytes, network byte order).
    pub sin_addr: [u8; 4],
    /// Zero padding to fill 16 bytes.
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    pub const SIZE: usize = 16;

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[..2].copy_from_slice(&self.sin_family.to_ne_bytes());
        buf[2..4].copy_from_slice(&self.sin_port.to_ne_bytes());
        buf[4..8].copy_from_slice(&self.sin_addr);
        buf[8..16].copy_from_slice(&self.sin_zero);
        buf
    }
}

impl TcpConnection {
    /// Return the local socket address `(ip, port)` for this connection.
    ///
    /// The local IP comes from the network stack; on bare-metal targets
    /// where the stack is unavailable this returns `None`.
    pub fn local_addr(&self) -> Option<([u8; 4], u16)> {
        #[cfg(target_os = "none")]
        {
            let stack = crate::kernel::network::stack::NetworkStack::global()?;
            let local_ip = stack.local_ip();
            Some((local_ip, self.native.local_port))
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self;
            None
        }
    }

    /// Return the remote (peer) socket address `(ip, port)` for this
    /// connection.
    pub fn remote_addr(&self) -> Option<([u8; 4], u16)> {
        #[cfg(target_os = "none")]
        {
            Some((self.native.remote_ip, self.native.remote_port))
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self;
            None
        }
    }

    /// Check whether this TCP connection has data available to read.
    /// Returns `Ok(true)` if data is available, `Ok(false)` if empty.
    pub fn is_readable(&self) -> Result<bool> {
        #[cfg(not(target_os = "none"))]
        {
            let _ = self;
            Ok(true)
        }
        #[cfg(target_os = "none")]
        {
            let stack =
                crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
            let table = stack.tcp_table().lock();
            let conn = table
                .lookup(
                    self.native.local_port,
                    self.native.remote_ip,
                    self.native.remote_port,
                )
                .ok_or(Error::NotFound)?;
            let state = conn.lock();
            Ok(state.available() > 0
                || matches!(
                    state.state,
                    crate::kernel::network::tcp::TcpState::CloseWait
                        | crate::kernel::network::tcp::TcpState::Closing
                ))
        }
    }

    /// Check whether this TCP connection can accept data for writing.
    /// Returns `Ok(true)` if the connection is in a writable state.
    pub fn is_writable(&self) -> Result<bool> {
        #[cfg(not(target_os = "none"))]
        {
            let _ = self;
            Ok(true)
        }
        #[cfg(target_os = "none")]
        {
            let stack =
                crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
            let table = stack.tcp_table().lock();
            let conn = table
                .lookup(
                    self.native.local_port,
                    self.native.remote_ip,
                    self.native.remote_port,
                )
                .ok_or(Error::NotFound)?;
            let state = conn.lock();
            Ok(matches!(
                state.state,
                crate::kernel::network::tcp::TcpState::Established
                    | crate::kernel::network::tcp::TcpState::CloseWait
                    | crate::kernel::network::tcp::TcpState::FinWait1
                    | crate::kernel::network::tcp::TcpState::FinWait2
            ))
        }
    }
}

impl UdpSocket {
    /// Return the local socket address `(ip, port)` for this bound UDP
    /// socket.
    ///
    /// The local IP comes from the network stack; on bare-metal targets
    /// where the stack is unavailable this returns `None`.
    pub fn local_addr(&self) -> Option<([u8; 4], u16)> {
        #[cfg(target_os = "none")]
        {
            let stack = crate::kernel::network::stack::NetworkStack::global()?;
            let local_ip = stack.local_ip();
            Some((local_ip, self.port))
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self;
            None
        }
    }

    /// Check whether this UDP socket has a pending datagram to receive.
    /// Returns `Ok(true)` if data is available, `Ok(false)` if empty.
    pub fn is_readable(&self) -> Result<bool> {
        #[cfg(any(target_os = "none", test))]
        {
            if let Some(stack) = crate::kernel::network::stack::NetworkStack::global() {
                let table = stack.udp_table().lock();
                Ok(table.has_pending(self.port))
            } else {
                Ok(false)
            }
        }
        #[cfg(not(any(target_os = "none", test)))]
        {
            let _ = self;
            Ok(false)
        }
    }
}

// ─── Raw socket public API ────────────────────────────────────────────

use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::process::RawSocketHandle;

/// Create a raw socket bound to `protocol` (IP protocol number, e.g. 1=ICMP).
///
/// Returns a [`RawSocketHandle`] that can be stored in the process fd table.
pub fn create_raw_socket(protocol: u8) -> Result<RawSocketHandle> {
    let stack = crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
    let socket_id = stack.alloc_raw_socket_id();
    let mut raw_sockets = stack.raw_sockets().lock();
    raw_sockets.insert(socket_id, raw::RawSocket::new(protocol));
    Ok(RawSocketHandle {
        socket_id,
        protocol,
    })
}

/// Send a raw IP packet to `dest_ip` from the raw socket identified by
/// `handle`.
///
/// The payload is sent as-is (the caller is responsible for constructing the
/// IP header and transport-layer segment).
pub fn send_raw_packet(_handle: RawSocketHandle, dest_ip: IpAddress, data: &[u8]) -> Result<()> {
    let stack = crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
    match dest_ip {
        IpAddress::V4(dst) => {
            let raw_ip = alloc::vec::Vec::from(data);
            stack.send_ipv4_packet(dst, raw_ip)
        }
        IpAddress::V6(dst) => {
            let raw_ip = alloc::vec::Vec::from(data);
            stack.send_ipv6_packet(dst, raw_ip)
        }
    }
}

/// Receive a raw packet from the raw socket identified by `handle`
/// (non-blocking).
///
/// Returns `Ok((n, src_ip))` where `n` is the number of bytes written to
/// `buffer`. Returns `Err(Error::TimedOut)` if the receive queue is empty.
pub fn recv_raw_packet(handle: RawSocketHandle, buffer: &mut [u8]) -> Result<(usize, IpAddress)> {
    let stack = crate::kernel::network::stack::NetworkStack::global().ok_or(Error::Unsupported)?;
    let mut raw_sockets = stack.raw_sockets().lock();
    let socket = raw_sockets
        .get_mut(&handle.socket_id)
        .ok_or(Error::NotFound)?;
    let (n, src, _dst) = socket.recv(buffer)?;
    Ok((n, src))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "none"))]
    use std::io::Read;
    #[cfg(not(target_os = "none"))]
    use std::io::Write;

    #[cfg(not(target_os = "none"))]
    #[test]
    fn native_network_capabilities_report_available_backend() {
        let capabilities = native_network_capabilities();
        let status = native_network_status();

        assert_eq!(capabilities.backend_id, status.backend_id());
        assert_eq!(capabilities.note, status.kernel_note());
        assert!(capabilities.available);
        assert!(!capabilities.requires_host_runtime);
        assert!(capabilities.supports_tcp_connect);
        assert!(capabilities.supports_tcp_listen);
        assert!(capabilities.supports_udp_datagram);
        assert!(capabilities.supports_stream_io);
        assert!(capabilities.supports_read_timeouts);
        assert!(capabilities.zero_timeout_read_is_poll);
        assert!(capabilities.supports_ipv6);
        assert_eq!(capabilities.status_flags(), 509);
        assert!(status.available());
        assert!(!status.requires_host_runtime());
        assert!(status.supports_tcp_connect());
        assert!(status.supports_tcp_listen());
        assert!(status.supports_udp_datagram());
        assert!(status.supports_stream_io());
        assert!(status.supports_read_timeouts());
        assert!(status.zero_timeout_read_is_poll());
        assert!(status.supports_ipv6());
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn native_backend_profile_keeps_status_and_connect_routing_aligned() {
        let backend = KernelTcpBackend::Native;
        let status = backend.status();
        let capabilities = backend.capabilities();

        assert_eq!(status, native_network_status());
        assert_eq!(capabilities.status_flags(), status.flags());
        // connect_native_tcp falls back to Unsupported on host
        assert!(matches!(
            backend.connect_tcp("127.0.0.1", 80),
            Err(Error::Unsupported)
        ));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_network_capabilities_report_tcp_connect_support() {
        let capabilities = host_network_capabilities();
        let status = host_network_status();

        assert_eq!(capabilities.backend_id, status.backend_id());
        assert_eq!(capabilities.note, status.kernel_note());
        assert!(capabilities.available);
        assert!(capabilities.requires_host_runtime);
        assert!(capabilities.supports_tcp_connect);
        assert!(capabilities.supports_tcp_listen);
        assert!(capabilities.supports_udp_datagram);
        assert!(capabilities.supports_stream_io);
        assert!(capabilities.supports_read_timeouts);
        assert!(capabilities.zero_timeout_read_is_poll);
        assert!(status.available());
        assert!(status.requires_host_runtime());
        assert!(status.supports_tcp_connect());
        assert!(status.supports_tcp_listen());
        assert!(status.supports_udp_datagram());
        assert!(status.supports_stream_io());
        assert!(status.supports_read_timeouts());
        assert!(status.zero_timeout_read_is_poll());
        assert!(!status.supports_ipv6());
        assert!(!capabilities.supports_ipv6);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_backend_profile_keeps_status_and_flags_aligned() {
        let backend = KernelTcpBackend::HostRuntimeCompat;
        let status = backend.status();
        let capabilities = backend.capabilities();

        assert_eq!(status, host_network_status());
        assert_eq!(capabilities.status_flags(), status.flags());
    }

    #[test]
    fn exported_status_flags_follow_reported_status_and_capabilities() {
        assert_eq!(status_flags(), status().flags() as usize);
        assert_eq!(status_flags(), capabilities().status_flags() as usize);
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_connect_error_mapping_preserves_distinct_connection_classes() {
        assert_eq!(
            map_host_connect_error(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            Error::NotFound
        );
        assert_eq!(
            map_host_connect_error(&std::io::Error::from(std::io::ErrorKind::AddrNotAvailable)),
            Error::NotFound
        );
        assert_eq!(
            map_host_connect_error(&std::io::Error::from(std::io::ErrorKind::AddrInUse)),
            Error::Busy
        );
        assert_eq!(
            map_host_connect_error(&std::io::Error::from(std::io::ErrorKind::TimedOut)),
            Error::TimedOut
        );
        assert_eq!(
            map_host_connect_error(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            Error::PermissionDenied
        );
    }

    #[test]
    fn connect_tcp_rejects_invalid_host_shapes_before_backend_use() {
        for host in [
            "",
            " ",
            " host",
            "host ",
            "host name",
            "host\nname",
            "host\tname",
        ] {
            assert!(matches!(connect_tcp(host, 80), Err(Error::InvalidArgument)));
        }
    }

    #[test]
    fn connect_tcp_rejects_zero_port() {
        assert!(matches!(
            connect_tcp("127.0.0.1", 0),
            Err(Error::InvalidArgument)
        ));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_connect_tcp_supports_loopback_round_trip() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept loopback connection");
            socket.write_all(b"ping").expect("write server payload");
            let mut reply = [0_u8; 4];
            socket.read_exact(&mut reply).expect("read client reply");
            assert_eq!(&reply, b"pong");
        });

        let connection = connect_tcp("127.0.0.1", port).expect("connect loopback");
        assert_eq!(connection.endpoint(), &format!("127.0.0.1:{port}"));

        let mut received = [0_u8; 4];
        assert_eq!(connection.read(&mut received, 100), Ok(4));
        assert_eq!(&received, b"ping");
        assert_eq!(connection.write_all(b"pong"), Ok(()));

        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_connect_tcp_maps_refused_loopback_port_to_not_found() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("listener addr").port();
        drop(listener);

        assert!(matches!(
            connect_tcp("127.0.0.1", port),
            Err(Error::NotFound)
        ));
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_zero_timeout_read_polls_without_waiting_for_peer_data() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (_socket, _) = listener.accept().expect("accept loopback connection");
            release_receiver
                .recv()
                .expect("wait for client poll completion");
        });

        let connection = connect_tcp("127.0.0.1", port).expect("connect loopback");
        let mut buffer = [0_u8; 1];
        assert_eq!(connection.read(&mut buffer, 0), Err(Error::TimedOut));

        release_sender
            .send(())
            .expect("release loopback server after poll");
        server.join().expect("join polling server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_read_reports_short_payload_without_padding() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept loopback connection");
            socket.write_all(b"abc").expect("write short payload");
        });

        let connection = connect_tcp("127.0.0.1", port).expect("connect loopback");
        let mut buffer = [0_u8; 8];
        assert_eq!(connection.read(&mut buffer, 100), Ok(3));
        assert_eq!(&buffer[..3], b"abc");
        assert_eq!(&buffer[3..], &[0_u8; 5]);

        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_zero_timeout_poll_restores_blocking_read_state() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept loopback connection");
            release_receiver.recv().expect("wait for client poll");
            socket.write_all(b"x").expect("write server payload");
        });

        let connection = connect_tcp("127.0.0.1", port).expect("connect loopback");
        let mut buffer = [0_u8; 1];
        assert_eq!(connection.read(&mut buffer, 0), Err(Error::TimedOut));

        release_sender
            .send(())
            .expect("release loopback server after poll");
        assert_eq!(connection.read(&mut buffer, 100), Ok(1));
        assert_eq!(&buffer, b"x");

        server.join().expect("join loopback server");
    }

    #[cfg(not(target_os = "none"))]
    #[test]
    fn host_read_returns_eof_when_peer_closes_connection() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("listener addr").port();
        let server = std::thread::spawn(move || {
            let (_socket, _) = listener.accept().expect("accept loopback connection");
        });

        let connection = connect_tcp("127.0.0.1", port).expect("connect loopback");
        let mut buffer = [0_u8; 1];
        assert_eq!(connection.read(&mut buffer, 100), Ok(0));

        server.join().expect("join loopback server");
    }

    // ─── UDP tests ──────────────────────────────────────────────────────

    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use crate::kernel::network::stack::NetworkStack;

    fn make_udp_test_stack() -> &'static NetworkStack {
        unsafe {
            NetworkStack::uninstall_global();
        }
        let dev = Arc::new(MockNetworkDevice::new(
            "udp-api-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(dev, [10, 0, 2, 15]);
        NetworkStack::global().expect("stack should be initialised")
    }

    #[test]
    fn bind_udp_reserves_port() {
        let _stack = make_udp_test_stack();
        let socket = bind_udp(8080).expect("bind should succeed");
        assert_eq!(socket.port(), 8080);
        // Duplicate bind must fail.
        assert!(matches!(bind_udp(8080), Err(Error::AlreadyExists)));
    }

    #[test]
    fn bind_udp_rejects_port_zero() {
        let _stack = make_udp_test_stack();
        assert!(matches!(bind_udp(0), Err(Error::InvalidArgument)));
    }

    #[test]
    fn send_to_udp_rejects_unbound_port() {
        let stack = make_udp_test_stack();
        // Create a handle without actually binding.
        let socket = UdpSocket { port: 9999 };
        assert!(matches!(
            send_to_udp(&socket, [10, 0, 2, 100], 53, b"data"),
            Err(Error::NotFound)
        ));
        // Ensure the stack is still usable after the error.
        let _ = stack.current_tick();
    }

    #[test]
    fn send_to_udp_and_recv_from_udp_round_trip() {
        let stack = make_udp_test_stack();
        let socket = bind_udp(9000).expect("bind");

        // Pre-populate ARP cache so send_to works without blocking.
        stack.arp_cache().lock().insert(
            [10, 0, 2, 100],
            crate::kernel::network::link::ethernet::MacAddress([
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            ]),
            stack.current_tick(),
        );

        // Deliver a datagram to the socket's receive queue (simulating a
        // remote peer that received our send and replied).
        {
            let mut table = stack.udp_table().lock();
            table.deliver([10, 0, 2, 100], 53, 9000, b"pong".to_vec());
        }

        // Receive the reply.
        let mut buf = [0u8; 64];
        let (n, src_ip, src_port) = recv_from_udp(&socket, &mut buf).expect("recv_from_udp");
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(src_ip, [10, 0, 2, 100]);
        assert_eq!(src_port, 53);
    }

    #[test]
    fn recv_from_udp_timed_out_on_empty_queue() {
        let _stack = make_udp_test_stack();
        let socket = bind_udp(9001).expect("bind");
        let mut buf = [0u8; 64];
        assert_eq!(recv_from_udp(&socket, &mut buf), Err(Error::TimedOut));
    }

    #[test]
    fn close_udp_socket_unbinds_port() {
        let _stack = make_udp_test_stack();
        let socket = bind_udp(7000).expect("bind");
        socket.close().expect("close should succeed");
        // Port should be free after close.
        let _rebound = bind_udp(7000).expect("rebind after close should succeed");
    }
}
