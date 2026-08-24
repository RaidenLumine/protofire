//! src/abi/net.rs
//!
//! Network ABI status records and flag constants shared with user space.

// ── Backend class ──

/// Classifies the network backend reported through the status ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NetworkBackendClass {
    /// No usable backend.
    Unknown = 0,
    /// Host-runtime compatibility shim (non-bare-metal test builds).
    HostRuntimeCompat = 1,
    /// Native kernel TCP/IP stack is active.
    Native = 2,
    /// Native stack compiled in but not yet available (no device found).
    NativePending = 3,
}

// ── Status flags ──

pub const NETWORK_STATUS_FLAG_AVAILABLE: u32 = 1 << 0;
pub const NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME: u32 = 1 << 1;
pub const NETWORK_STATUS_FLAG_TCP_CONNECT: u32 = 1 << 2;
pub const NETWORK_STATUS_FLAG_STREAM_IO: u32 = 1 << 3;
pub const NETWORK_STATUS_FLAG_READ_TIMEOUTS: u32 = 1 << 4;
pub const NETWORK_STATUS_FLAG_ZERO_TIMEOUT_READ_IS_POLL: u32 = 1 << 5;
pub const NETWORK_STATUS_FLAG_TCP_LISTEN: u32 = 1 << 6;
pub const NETWORK_STATUS_FLAG_UDP_DATAGRAM: u32 = 1 << 7;
pub const NETWORK_STATUS_FLAG_IPV6: u32 = 1 << 8;

// ── NetworkStatus ──

/// Capability bitmask returned by the `network_status` ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStatus {
    flags: u32,
}

impl NetworkStatus {
    pub const fn from_flags(flags: u32) -> Self {
        Self { flags }
    }

    pub const fn flags(self) -> u32 {
        self.flags
    }

    pub const fn backend_class(self) -> NetworkBackendClass {
        if self.flags & NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME != 0 {
            NetworkBackendClass::HostRuntimeCompat
        } else if self.flags & NETWORK_STATUS_FLAG_AVAILABLE == 0 {
            NetworkBackendClass::Unknown
        } else if self.has(NETWORK_STATUS_FLAG_TCP_CONNECT)
            && self.has(NETWORK_STATUS_FLAG_STREAM_IO)
        {
            NetworkBackendClass::Native
        } else {
            NetworkBackendClass::NativePending
        }
    }

    const fn has(self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    // ─── Capability accessors (const, usable in const fns) ──────────

    /// Short identifier for the active backend.
    pub const fn backend_id(self) -> &'static str {
        if self.requires_host_runtime() {
            "host-runtime"
        } else if self.supports_tcp_connect() && self.supports_stream_io() {
            "native"
        } else if self.available() {
            "native-pending"
        } else {
            "unknown"
        }
    }

    /// Whether any usable backend is currently available.
    pub const fn available(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_AVAILABLE)
    }

    /// Whether the backend requires the host runtime shim (test builds).
    pub const fn requires_host_runtime(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME)
    }

    /// Whether outbound TCP connect() is supported.
    pub const fn supports_tcp_connect(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_TCP_CONNECT)
    }

    /// Whether passive TCP listen() is supported.
    pub const fn supports_tcp_listen(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_TCP_LISTEN)
    }

    /// Whether UDP datagram sockets are supported.
    pub const fn supports_udp_datagram(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_UDP_DATAGRAM)
    }

    /// Whether streaming (byte-stream) I/O is supported.
    pub const fn supports_stream_io(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_STREAM_IO)
    }

    /// Whether receive timeouts are supported.
    pub const fn supports_read_timeouts(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_READ_TIMEOUTS)
    }

    /// Whether a zero timeout is treated as a poll (non-blocking read).
    pub const fn zero_timeout_read_is_poll(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_ZERO_TIMEOUT_READ_IS_POLL)
    }

    /// Whether IPv6 is supported.
    pub const fn supports_ipv6(self) -> bool {
        self.has(NETWORK_STATUS_FLAG_IPV6)
    }

    /// Human-readable note about the backend state.
    pub const fn kernel_note(self) -> &'static str {
        if self.requires_host_runtime() {
            "host-runtime compatibility shim"
        } else if !self.available() {
            "native stack compiled in, no device available"
        } else if self.supports_tcp_connect() && self.supports_stream_io() {
            "native kernel TCP/IP stack active"
        } else {
            "native stack pending"
        }
    }
}

pub const NETWORK_CONNECT_FLAG_NONE: usize = 0;
// Keep the known-flag mask explicit so future extensions can widen it without
// changing validation call sites.
pub const NETWORK_CONNECT_KNOWN_FLAGS: usize = NETWORK_CONNECT_FLAG_NONE;

pub const NETWORK_LISTEN_FLAG_NONE: usize = 0;
pub const NETWORK_LISTEN_KNOWN_FLAGS: usize = NETWORK_LISTEN_FLAG_NONE;

pub const NETWORK_ACCEPT_FLAG_NONE: usize = 0;
pub const NETWORK_ACCEPT_KNOWN_FLAGS: usize = NETWORK_ACCEPT_FLAG_NONE;

pub const NETWORK_BIND_UDP_FLAG_NONE: usize = 0;
pub const NETWORK_BIND_UDP_KNOWN_FLAGS: usize = NETWORK_BIND_UDP_FLAG_NONE;

pub const NETWORK_SENDTO_UDP_FLAG_NONE: usize = 0;
/// When set, `arg1` is a pointer to a 16-byte IPv6 destination address
/// instead of a packed IPv4 address.
pub const NETWORK_SENDTO_UDP_FLAG_IPV6: usize = 1 << 0;
pub const NETWORK_SENDTO_UDP_KNOWN_FLAGS: usize = NETWORK_SENDTO_UDP_FLAG_IPV6;

pub const NETWORK_RECVFROM_UDP_FLAG_NONE: usize = 0;
/// When set, the source address output is 20 bytes (16-byte IPv6 + 2-byte
/// port + 2-byte padding) instead of 8 bytes (4-byte IPv4 + 2-byte port +
/// 2-byte padding).
pub const NETWORK_RECVFROM_UDP_FLAG_IPV6: usize = 1 << 0;
pub const NETWORK_RECVFROM_UDP_KNOWN_FLAGS: usize = NETWORK_RECVFROM_UDP_FLAG_IPV6;

// ─── DCCP (RFC 4340) flags ────────────────────────────────────────────

pub const NETWORK_DCCP_FLAG_NONE: usize = 0;
/// When set in `dccp_connect`, `arg0` is a pointer to a 16-byte IPv6
/// destination address instead of a packed IPv4 address.
pub const NETWORK_DCCP_FLAG_IPV6: usize = 1 << 0;
pub const NETWORK_DCCP_KNOWN_FLAGS: usize = NETWORK_DCCP_FLAG_IPV6;

pub const NETWORK_DCCP_LISTEN_FLAG_NONE: usize = 0;
pub const NETWORK_DCCP_LISTEN_KNOWN_FLAGS: usize = NETWORK_DCCP_LISTEN_FLAG_NONE;

pub const NETWORK_DCCP_ACCEPT_FLAG_NONE: usize = 0;
pub const NETWORK_DCCP_ACCEPT_KNOWN_FLAGS: usize = NETWORK_DCCP_ACCEPT_FLAG_NONE;

pub const NETWORK_DCCP_SEND_FLAG_NONE: usize = 0;
pub const NETWORK_DCCP_SEND_KNOWN_FLAGS: usize = NETWORK_DCCP_SEND_FLAG_NONE;

pub const NETWORK_DCCP_RECV_FLAG_NONE: usize = 0;
pub const NETWORK_DCCP_RECV_KNOWN_FLAGS: usize = NETWORK_DCCP_RECV_FLAG_NONE;

#[cfg(test)]
mod tests {
    use super::{
        NetworkBackendClass, NetworkStatus, NETWORK_CONNECT_FLAG_NONE, NETWORK_CONNECT_KNOWN_FLAGS,
        NETWORK_STATUS_FLAG_AVAILABLE, NETWORK_STATUS_FLAG_IPV6, NETWORK_STATUS_FLAG_READ_TIMEOUTS,
        NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME, NETWORK_STATUS_FLAG_STREAM_IO,
        NETWORK_STATUS_FLAG_TCP_CONNECT, NETWORK_STATUS_FLAG_TCP_LISTEN,
        NETWORK_STATUS_FLAG_UDP_DATAGRAM, NETWORK_STATUS_FLAG_ZERO_TIMEOUT_READ_IS_POLL,
    };

    #[test]
    fn network_status_flag_masks_are_stable() {
        assert_eq!(NETWORK_STATUS_FLAG_AVAILABLE, 1);
        assert_eq!(NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME, 2);
        assert_eq!(NETWORK_STATUS_FLAG_TCP_CONNECT, 4);
        assert_eq!(NETWORK_STATUS_FLAG_STREAM_IO, 8);
        assert_eq!(NETWORK_STATUS_FLAG_READ_TIMEOUTS, 16);
        assert_eq!(NETWORK_STATUS_FLAG_ZERO_TIMEOUT_READ_IS_POLL, 32);
        assert_eq!(NETWORK_STATUS_FLAG_TCP_LISTEN, 64);
        assert_eq!(NETWORK_STATUS_FLAG_UDP_DATAGRAM, 128);
        assert_eq!(NETWORK_STATUS_FLAG_IPV6, 256);

        assert_eq!(NETWORK_CONNECT_FLAG_NONE, 0);
        assert_eq!(NETWORK_CONNECT_KNOWN_FLAGS, 0);
    }

    #[test]
    fn status_from_flags_round_trips() {
        let status = NetworkStatus::from_flags(
            NETWORK_STATUS_FLAG_AVAILABLE | NETWORK_STATUS_FLAG_TCP_CONNECT,
        );
        assert_eq!(
            status.flags(),
            NETWORK_STATUS_FLAG_AVAILABLE | NETWORK_STATUS_FLAG_TCP_CONNECT
        );
        assert!(status.has(NETWORK_STATUS_FLAG_AVAILABLE));
        assert!(!status.has(NETWORK_STATUS_FLAG_READ_TIMEOUTS));
    }

    #[test]
    fn backend_class_classification() {
        assert_eq!(
            NetworkStatus::from_flags(NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME).backend_class(),
            NetworkBackendClass::HostRuntimeCompat
        );
        assert_eq!(
            NetworkStatus::from_flags(0).backend_class(),
            NetworkBackendClass::Unknown
        );
        assert_eq!(
            NetworkStatus::from_flags(
                NETWORK_STATUS_FLAG_AVAILABLE
                    | NETWORK_STATUS_FLAG_TCP_CONNECT
                    | NETWORK_STATUS_FLAG_STREAM_IO
            )
            .backend_class(),
            NetworkBackendClass::Native
        );
        assert_eq!(
            NetworkStatus::from_flags(NETWORK_STATUS_FLAG_AVAILABLE).backend_class(),
            NetworkBackendClass::NativePending
        );
    }
}
