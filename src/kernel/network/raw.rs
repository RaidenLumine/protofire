//! src/kernel/network/raw.rs
//! Raw IP socket support.
//!
//! Raw sockets allow user-space programs to send and receive IP packets
//! directly, bypassing the transport-layer protocol stack.  Each raw socket
//! is bound to a specific IP protocol number; incoming packets matching
//! that protocol are duplicated to the socket's receive queue.

use alloc::collections::vec_deque::VecDeque;
use alloc::vec::Vec;

use crate::kernel::network::internet::ip::IpAddress;
use crate::{Error, Result};

// ─── Raw socket ─────────────────────────────────────────────────────────

/// Maximum number of queued packets per raw socket (bound to minimise
/// memory usage; raw sockets are a privileged operation).
const RAW_SOCKET_QUEUE_SIZE: usize = 64;

/// A received raw IP packet.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Source address (IPv4 or IPv6).
    pub source: IpAddress,
    /// Destination address (IPv4 or IPv6).
    pub destination: IpAddress,
    /// The raw IP payload (everything after the IP header, i.e. the
    /// transport-layer segment).
    pub payload: Vec<u8>,
}

/// A raw IP socket bound to a specific protocol number.
pub struct RawSocket {
    /// Protocol number this socket receives (e.g. 1 = ICMP, 6 = TCP).
    pub protocol: u8,
    /// Receive queue.
    queue: VecDeque<RawPacket>,
}

impl RawSocket {
    /// Create a new raw socket bound to `protocol`.
    pub fn new(protocol: u8) -> Self {
        Self {
            protocol,
            queue: VecDeque::new(),
        }
    }

    /// Deliver a received packet to this socket's receive queue.
    ///
    /// Returns `true` if the packet was accepted, `false` if the queue is
    /// full (packet dropped).
    pub fn deliver(&mut self, source: IpAddress, destination: IpAddress, payload: &[u8]) -> bool {
        if self.queue.len() >= RAW_SOCKET_QUEUE_SIZE {
            return false;
        }
        self.queue.push_back(RawPacket {
            source,
            destination,
            payload: Vec::from(payload),
        });
        true
    }

    /// Receive a queued raw packet (non-blocking).
    ///
    /// Returns `Ok((n, source, destination, payload))` where `n` is the
    /// payload length written to the buffer.
    /// Returns `Err(Error::TimedOut)` if the queue is empty.
    pub fn recv(&mut self, buffer: &mut [u8]) -> Result<(usize, IpAddress, IpAddress)> {
        let packet = self.queue.pop_front().ok_or(Error::TimedOut)?;
        let copy_len = packet.payload.len().min(buffer.len());
        buffer[..copy_len].copy_from_slice(&packet.payload[..copy_len]);
        Ok((copy_len, packet.source, packet.destination))
    }

    /// Return the number of queued packets.
    #[cfg(test)]
    pub fn queued(&self) -> usize {
        self.queue.len()
    }
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliver_and_recv_round_trip() {
        let mut sock = RawSocket::new(1); // ICMP
        let src = IpAddress::V4([10, 0, 2, 1]);
        let dst = IpAddress::V4([10, 0, 2, 15]);
        assert!(sock.deliver(src, dst, b"icmp_payload"));

        let mut buf = [0u8; 64];
        let (n, r_src, r_dst) = sock.recv(&mut buf).expect("should recv");
        assert_eq!(&buf[..n], b"icmp_payload");
        assert_eq!(r_src, src);
        assert_eq!(r_dst, dst);
    }

    #[test]
    fn recv_empty_returns_timed_out() {
        let mut sock = RawSocket::new(6); // TCP
        let mut buf = [0u8; 64];
        assert_eq!(sock.recv(&mut buf), Err(Error::TimedOut));
    }

    #[test]
    fn queue_overrun_drops_packets() {
        let mut sock = RawSocket::new(17); // UDP
        let src = IpAddress::V4([10, 0, 2, 1]);
        let dst = IpAddress::V4([10, 0, 2, 15]);

        // Fill the queue past the limit.
        for i in 0..70 {
            sock.deliver(src, dst, &[i as u8]);
        }
        // Only 64 should be queued.
        assert_eq!(sock.queued(), 64);
    }

    #[test]
    fn ipv6_deliver_and_recv() {
        let mut sock = RawSocket::new(58); // ICMPv6
        let src = IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert!(sock.deliver(src, dst, b"icmpv6_data"));

        let mut buf = [0u8; 64];
        let (n, r_src, _r_dst) = sock.recv(&mut buf).expect("should recv");
        assert_eq!(&buf[..n], b"icmpv6_data");
        assert_eq!(r_src, src);
    }
}
