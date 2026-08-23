//! src/kernel/network/udp.rs
//! UDP protocol (RFC 768): datagram send / receive with port-based
//! demultiplexing and optional checksum.

use alloc::collections::btree_map::BTreeMap;
use alloc::collections::vec_deque::VecDeque;
use alloc::vec::Vec;

use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::internet::ipv4::{self, IpProtocol, Ipv4Addr, Ipv4Header};
use crate::kernel::network::internet::ipv6::{self, Ipv6Addr, Ipv6Header, Ipv6NextHeader};
use crate::{Error, Result};

// ─── UDP constants ───

/// UDP header size in bytes.
pub const UDP_HEADER_SIZE: usize = 8;

// ─── UDP header ───

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub header: UdpHeader,
    pub payload: Vec<u8>,
}

// ─── Parse / build ───

/// Parse a UDP datagram from a byte slice.
pub fn parse_datagram(data: &[u8]) -> Result<UdpDatagram> {
    if data.len() < UDP_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    let source_port = u16::from_be_bytes([data[0], data[1]]);
    let destination_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    let payload_len = (length as usize).saturating_sub(UDP_HEADER_SIZE);
    let payload = if payload_len > 0 && UDP_HEADER_SIZE + payload_len <= data.len() {
        Vec::from(&data[UDP_HEADER_SIZE..UDP_HEADER_SIZE + payload_len])
    } else if data.len() > UDP_HEADER_SIZE {
        Vec::from(&data[UDP_HEADER_SIZE..])
    } else {
        Vec::new()
    };

    Ok(UdpDatagram {
        header: UdpHeader {
            source_port,
            destination_port,
            length,
            checksum,
        },
        payload,
    })
}

/// Build a UDP datagram from header and payload.
pub fn build_datagram(header: &UdpHeader, payload: &[u8]) -> Vec<u8> {
    let total_len = (UDP_HEADER_SIZE + payload.len()) as u16;
    let mut buf = Vec::with_capacity(total_len as usize);
    buf.extend_from_slice(&header.source_port.to_be_bytes());
    buf.extend_from_slice(&header.destination_port.to_be_bytes());
    buf.extend_from_slice(&total_len.to_be_bytes());
    // Checksum placeholder (0 = no checksum for now)
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(payload);
    buf
}

/// Build a UDP datagram with a real checksum computed over the IPv4/IPv6
/// pseudo-header + UDP header + payload.
///
/// Per RFC 768 (IPv4) a zero checksum is legal, but RFC 8200 §8.1 makes a
/// zero UDP checksum *illegal* for IPv6 — receivers MUST discard such
/// datagrams — so outbound IPv6 UDP must always carry a real checksum.
/// A computed checksum of 0 is transmitted as 0xFFFF (the RFC 768
/// exception), which also guarantees the IPv6 field is never 0.
///
/// `src_ip` and `dst_ip` must be the same address family ([`IpAddress::V4`]
/// or [`IpAddress::V6`]); mismatched families produce a zero checksum as a
/// safe fallback.
pub fn build_datagram_with_checksum(
    header: &UdpHeader,
    payload: &[u8],
    src_ip: IpAddress,
    dst_ip: IpAddress,
) -> Vec<u8> {
    debug_assert!(
        UDP_HEADER_SIZE + payload.len() <= u16::MAX as usize,
        "UDP datagram exceeds maximum length"
    );
    let total_len = (UDP_HEADER_SIZE + payload.len()) as u16;
    let mut buf = Vec::with_capacity(total_len as usize);
    buf.extend_from_slice(&header.source_port.to_be_bytes());
    buf.extend_from_slice(&header.destination_port.to_be_bytes());
    buf.extend_from_slice(&total_len.to_be_bytes());
    // Checksum placeholder — zeroed during computation
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(payload);

    // Compute checksum over pseudo-header + UDP header + payload.
    let mut sum: u32 = 0;
    match (&src_ip, &dst_ip) {
        (IpAddress::V4(src), IpAddress::V4(dst)) => {
            ipv4::pseudo_header_checksum_add(
                &mut sum,
                *src,
                *dst,
                IpProtocol::Udp.to_u8(),
                total_len,
            );
        }
        (IpAddress::V6(src), IpAddress::V6(dst)) => {
            ipv6::pseudo_header_checksum_add(
                &mut sum,
                *src,
                *dst,
                Ipv6NextHeader::Udp.to_u8(),
                total_len as u32,
            );
        }
        _ => {
            // Mismatched address families — leave checksum as 0.
        }
    }
    ipv4::checksum_add(&mut sum, &buf);
    let checksum = ipv4::checksum_finalize(sum);
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };

    buf[6] = (checksum >> 8) as u8;
    buf[7] = checksum as u8;
    buf
}

// ─── UDP socket table ───

/// A bound UDP socket with a receive queue.
pub struct UdpSocket {
    pub local_port: u16,
    /// Queue of (source_ip, source_port, data) tuples.
    /// The source IP is an [`IpAddress`] to support both IPv4 and IPv6 peers.
    receive_queue: VecDeque<(IpAddress, u16, Vec<u8>)>,
}

impl UdpSocket {
    pub fn new(local_port: u16) -> Self {
        Self {
            local_port,
            receive_queue: VecDeque::new(),
        }
    }
}

/// Table of bound UDP sockets, keyed by local port.
pub struct UdpSocketTable {
    sockets: BTreeMap<u16, UdpSocket>,
}

impl Default for UdpSocketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpSocketTable {
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
        }
    }

    /// Bind a UDP socket to `port`.
    pub fn bind(&mut self, port: u16) -> Result<()> {
        if self.sockets.contains_key(&port) {
            return Err(Error::AlreadyExists);
        }
        self.sockets.insert(port, UdpSocket::new(port));
        Ok(())
    }

    /// Unbind the socket at `port`.
    pub fn unbind(&mut self, port: u16) {
        self.sockets.remove(&port);
    }

    /// Deliver a datagram to the bound socket at `dst_port`.
    /// Returns `true` if delivered, `false` if no socket is bound to the port.
    /// `src_ip` is an [`IpAddress`] to support both IPv4 and IPv6.
    pub fn deliver(
        &mut self,
        src_ip: impl Into<IpAddress>,
        src_port: u16,
        dst_port: u16,
        data: Vec<u8>,
    ) -> bool {
        if let Some(socket) = self.sockets.get_mut(&dst_port) {
            socket
                .receive_queue
                .push_back((src_ip.into(), src_port, data));
            true
        } else {
            false
        }
    }

    /// Receive a datagram from `port`'s queue.
    /// Returns `(bytes_read, src_ip, src_port)` on success.
    /// Returns `Err(TimedOut)` when the queue is empty (non-blocking).
    pub fn recv_from(&mut self, port: u16, buffer: &mut [u8]) -> Result<(usize, IpAddress, u16)> {
        let socket = self.sockets.get_mut(&port).ok_or(Error::NotFound)?;
        match socket.receive_queue.pop_front() {
            Some((src_ip, src_port, data)) => {
                let len = data.len().min(buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                Ok((len, src_ip, src_port))
            }
            None => Err(Error::TimedOut),
        }
    }

    /// Check whether the socket at `port` has a datagram queued for receive.
    pub fn has_pending(&self, port: u16) -> bool {
        self.sockets
            .get(&port)
            .is_some_and(|socket| !socket.receive_queue.is_empty())
    }

    /// Check if a port is bound.
    pub fn is_bound(&self, port: u16) -> bool {
        self.sockets.contains_key(&port)
    }

    /// Number of bound sockets.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Returns true when no sockets are bound.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
}

// ─── Integration helpers ───

/// Build an IPv4 packet containing a UDP datagram.
pub fn build_udp_ipv4_packet(
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let header = UdpHeader {
        source_port,
        destination_port: dest_port,
        length: 0, // computed by build_datagram_with_checksum
        checksum: 0,
    };
    let udp_bytes = build_datagram_with_checksum(
        &header,
        payload,
        IpAddress::V4(source_ip),
        IpAddress::V4(dest_ip),
    );

    let ip_header = Ipv4Header {
        total_length: 0,
        identification: 0,
        flags_fragment_offset: 0,
        ttl: ipv4::IPV4_DEFAULT_TTL,
        protocol: IpProtocol::Udp,
        header_checksum: 0,
        source: source_ip,
        destination: dest_ip,
    };

    ipv4::build_packet(&ip_header, &udp_bytes)
}

/// Build an IPv6 packet containing a UDP datagram.
pub fn build_udp_ipv6_packet(
    source_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
    source_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let header = UdpHeader {
        source_port,
        destination_port: dest_port,
        length: 0,
        checksum: 0,
    };
    let udp_bytes = build_datagram_with_checksum(
        &header,
        payload,
        IpAddress::V6(source_ip),
        IpAddress::V6(dest_ip),
    );

    let ip_header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: Ipv6NextHeader::Udp,
        hop_limit: ipv6::IPV6_DEFAULT_HOP_LIMIT,
        source: source_ip,
        destination: dest_ip,
    };

    ipv6::build_packet(&ip_header, &udp_bytes)
}

/// Send a UDP datagram through the network stack (IPv4).
///
/// The source port must have been previously bound via
/// [`UdpSocketTable::bind`].  This function verifies the binding under
/// a short-lived lock, then releases it before calling into the network
/// stack send path — avoiding the deadlock that would arise from
/// holding the UDP table lock across `send_ipv4_packet` → ARP resolution
/// → `poll()`.
///
/// Returns [`Error::NotFound`](crate::Error::NotFound) if `src_port`
/// is not bound.
pub fn send_to(
    stack: &crate::kernel::network::stack::NetworkStack,
    src_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    payload: &[u8],
) -> Result<()> {
    // Verify the port is bound (short-lived lock — released before
    // we call into the send path so poll() can safely acquire the
    // UDP table lock for incoming datagram delivery).
    {
        let table = stack.udp_table().lock();
        if !table.is_bound(src_port) {
            return Err(Error::NotFound);
        }
    }

    let raw = build_udp_ipv4_packet(stack.local_ip(), dest_ip, src_port, dest_port, payload);
    stack.profiler.inc_udp_datagrams_tx();
    stack.send_ipv4_packet(dest_ip, raw)
}

/// Send a UDP datagram through the network stack (IPv6).
///
/// Same contract as [`send_to`] but uses IPv6 addressing and NDP for
/// MAC resolution.
pub fn send_to_v6(
    stack: &crate::kernel::network::stack::NetworkStack,
    src_port: u16,
    dest_ip: Ipv6Addr,
    dest_port: u16,
    payload: &[u8],
) -> Result<()> {
    {
        let table = stack.udp_table().lock();
        if !table.is_bound(src_port) {
            return Err(Error::NotFound);
        }
    }

    let src = stack.local_ip_v6();
    let raw = build_udp_ipv6_packet(src, dest_ip, src_port, dest_port, payload);
    stack.profiler.inc_udp_datagrams_tx();
    stack.send_ipv6_packet(dest_ip, raw)
}

// ─── tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_build_round_trip() {
        let header = UdpHeader {
            source_port: 12345,
            destination_port: 53,
            length: 0,
            checksum: 0,
        };
        let raw = build_datagram(&header, b"dns query");
        let parsed = parse_datagram(&raw).expect("should parse");

        assert_eq!(parsed.header.source_port, 12345);
        assert_eq!(parsed.header.destination_port, 53);
        assert_eq!(parsed.header.length, 8 + 9); // header + payload
        assert_eq!(&parsed.payload, b"dns query");
    }

    #[test]
    fn parse_rejects_short_data() {
        assert_eq!(parse_datagram(&[0u8; 4]), Err(Error::InvalidArgument));
    }

    #[test]
    fn bind_and_unbind() {
        let mut table = UdpSocketTable::new();
        assert!(table.is_empty());

        table.bind(8080).expect("bind should succeed");
        assert!(table.is_bound(8080));
        assert_eq!(table.len(), 1);

        // Duplicate bind should fail
        assert_eq!(table.bind(8080), Err(Error::AlreadyExists));

        table.unbind(8080);
        assert!(!table.is_bound(8080));
        assert!(table.is_empty());
    }

    #[test]
    fn send_and_receive() {
        let mut table = UdpSocketTable::new();
        table.bind(9000).expect("bind");

        // Deliver a datagram
        assert!(table.deliver([10, 0, 2, 100], 12345, 9000, b"hello udp".to_vec()));

        // Receive it
        let mut buf = [0u8; 64];
        let (n, src_ip, src_port) = table.recv_from(9000, &mut buf).expect("should recv");
        assert_eq!(n, 9);
        assert_eq!(&buf[..n], b"hello udp");
        assert_eq!(
            src_ip,
            crate::kernel::network::internet::ip::IpAddress::V4([10, 0, 2, 100])
        );
        assert_eq!(src_port, 12345);

        // Queue should be empty now
        assert_eq!(table.recv_from(9000, &mut buf), Err(Error::TimedOut));
    }

    #[test]
    fn deliver_to_unbound_port_returns_false() {
        let mut table = UdpSocketTable::new();
        let delivered = table.deliver([10, 0, 2, 1], 53, 9999, b"drop me".to_vec());
        assert!(!delivered);
        assert!(table.is_empty());
    }

    #[test]
    fn recv_from_unbound_port_returns_not_found() {
        let mut table = UdpSocketTable::new();
        let mut buf = [0u8; 64];
        assert_eq!(table.recv_from(9999, &mut buf), Err(Error::NotFound));
    }

    #[test]
    fn recv_truncates_to_buffer() {
        let mut table = UdpSocketTable::new();
        table.bind(1).expect("bind");
        assert!(table.deliver([0; 4], 0, 1, b"long message".to_vec()));

        let mut buf = [0u8; 4];
        let (n, _, _) = table.recv_from(1, &mut buf).expect("should recv");
        assert_eq!(n, 4);
        assert_eq!(&buf, b"long");
    }

    #[test]
    fn build_udp_ipv4_is_valid_packet() {
        let raw = build_udp_ipv4_packet([10, 0, 2, 15], [10, 0, 2, 2], 12345, 53, b"test");

        // Should be parseable as IPv4
        let ip_packet = ipv4::parse_packet(&raw).expect("should parse IPv4");
        assert_eq!(ip_packet.header.protocol, IpProtocol::Udp);
        assert_eq!(ip_packet.header.source, [10, 0, 2, 15]);
        assert_eq!(ip_packet.header.destination, [10, 0, 2, 2]);

        // Should be parseable as UDP
        let udp = parse_datagram(&ip_packet.payload).expect("should parse UDP");
        assert_eq!(udp.header.source_port, 12345);
        assert_eq!(udp.header.destination_port, 53);
        assert_eq!(&udp.payload, b"test");
    }

    // ─── send_to tests (needs a NetworkStack with mock device) ───

    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use crate::kernel::network::link::ethernet::MacAddress;
    use crate::kernel::network::stack::NetworkStack;
    use alloc::sync::Arc;

    fn make_test_stack() -> &'static NetworkStack {
        unsafe {
            NetworkStack::uninstall_global();
        }
        let dev = Arc::new(MockNetworkDevice::new(
            "udp-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(dev, [10, 0, 2, 15]);
        NetworkStack::global().expect("stack should be initialised")
    }

    #[test]
    fn send_to_rejects_unbound_port() {
        let stack = make_test_stack();
        // No port bound, and send_to checks binding before touching
        // ARP — so this works even without a populated ARP cache.
        assert_eq!(
            send_to(stack, 9000, [10, 0, 2, 100], 53, b"data"),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn send_to_succeeds_for_bound_port() {
        let stack = make_test_stack();
        {
            stack.udp_table().lock().bind(9000).expect("bind");
        } // release lock before calling send_to
          // Pre-populate the ARP cache so resolve_mac doesn't spin-wait
          // (ticks never advance in test — no scheduler running).
        stack.arp_cache().lock().insert(
            [10, 0, 2, 100],
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );
        assert!(send_to(stack, 9000, [10, 0, 2, 100], 53, b"hello").is_ok());
    }

    #[test]
    fn udp_bind_send_recv_round_trip() {
        let stack = make_test_stack();
        {
            let mut table = stack.udp_table().lock();
            table.bind(9000).expect("bind");
        }

        // Pre-populate ARP cache so send_to's resolve_mac won't hang.
        stack.arp_cache().lock().insert(
            [10, 0, 2, 100],
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );

        // Send a datagram through the stack.
        send_to(stack, 9000, [10, 0, 2, 100], 53, b"ping").expect("send_to");

        // Simulate the peer replying by delivering a response directly
        // to the socket's receive queue.
        {
            let mut table = stack.udp_table().lock();
            assert!(table.deliver([10, 0, 2, 100], 53, 9000, b"pong".to_vec()));
        }

        // Receive the reply.
        let mut table = stack.udp_table().lock();
        let mut buf = [0u8; 64];
        let (n, src_ip, src_port) = table.recv_from(9000, &mut buf).expect("recv_from");
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(
            src_ip,
            crate::kernel::network::internet::ip::IpAddress::V4([10, 0, 2, 100])
        );
        assert_eq!(src_port, 53);
    }
}
