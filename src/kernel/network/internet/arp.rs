//! src/kernel/network/internet/arp.rs
//! ARP protocol (RFC 826): IPv4-to-MAC address resolution with an in-memory
//! tick-based cache.

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

use super::ipv4::Ipv4Addr;
use crate::kernel::network::link::ethernet::{self, EtherType, EthernetFrame, MacAddress};
use crate::kernel::network::stack::NetworkStack;
use crate::{Error, Result};

// ─── ARP constants ───

/// Hardware type: Ethernet.
pub const ARP_HTYPE_ETHERNET: u16 = 1;
/// Protocol type: IPv4.
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
/// Hardware address length for Ethernet.
pub const ARP_HLEN_ETHERNET: u8 = 6;
/// Protocol address length for IPv4.
pub const ARP_PLEN_IPV4: u8 = 4;

/// ARP operation codes.
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

/// Total ARP packet size (fixed for Ethernet/IPv4): 2+2+1+1+2+6+4+6+4 = 28.
pub const ARP_PACKET_SIZE: usize = 28;

/// Cache entry lifetime in ticks (600 ticks = 6 s at 100 Hz).
pub const ARP_CACHE_TTL_TICKS: u64 = 600;

/// ARP resolution timeout in ticks (50 ticks = 500 ms at 100 Hz).
pub const ARP_RESOLVE_TIMEOUT_TICKS: u64 = 50;

/// Maximum number of ARP Request retransmissions before giving up.
const ARP_MAX_RETRIES: u32 = 3;

/// Interval between ARP Request retransmissions (33 ticks ≈ 330 ms at 100 Hz).
const ARP_RETRANSMIT_TICKS: u64 = 33;

/// Hard upper bound on spin-loop iterations to prevent an infinite hang when
/// ticks never advance (e.g. in tests with no timer interrupt).  At ~1 μs per
/// iteration this gives at most ~1 s of busy-wait, after which we fall through
/// to the tick-based timeout path (which returns `TimedOut` regardless).
const ARP_MAX_SPIN_ITERATIONS: u64 = 1_000_000;

// ─── ARP operation enum ───

/// ARP operation codes (RFC 826 §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    /// ARP Request — "who has this IP?".
    Request,
    /// ARP Reply — "I have this IP".
    Reply,
    /// Any other operation code.
    Other(u16),
}

impl ArpOperation {
    /// Map a raw 16-bit operation code to an [`ArpOperation`].
    pub fn from_u16(value: u16) -> Self {
        match value {
            ARP_OP_REQUEST => Self::Request,
            ARP_OP_REPLY => Self::Reply,
            other => Self::Other(other),
        }
    }

    /// The 16-bit operation code as it appears on the wire.
    pub fn value(self) -> u16 {
        match self {
            Self::Request => ARP_OP_REQUEST,
            Self::Reply => ARP_OP_REPLY,
            Self::Other(other) => other,
        }
    }
}

/// A decoded ARP packet (fixed Ethernet/IPv4 layout, 28 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_size: u8,
    pub protocol_size: u8,
    pub operation: ArpOperation,
    pub sender_mac: MacAddress,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddress,
    pub target_ip: Ipv4Addr,
}

/// Parse a raw ARP packet payload (the bytes following the Ethernet header).
pub fn parse_arp_packet(data: &[u8]) -> Result<ArpPacket> {
    if data.len() < ARP_PACKET_SIZE {
        return Err(Error::InvalidArgument);
    }
    Ok(ArpPacket {
        hardware_type: u16::from_be_bytes([data[0], data[1]]),
        protocol_type: u16::from_be_bytes([data[2], data[3]]),
        hardware_size: data[4],
        protocol_size: data[5],
        operation: ArpOperation::from_u16(u16::from_be_bytes([data[6], data[7]])),
        sender_mac: MacAddress([data[8], data[9], data[10], data[11], data[12], data[13]]),
        sender_ip: [data[14], data[15], data[16], data[17]],
        target_mac: MacAddress([data[18], data[19], data[20], data[21], data[22], data[23]]),
        target_ip: [data[24], data[25], data[26], data[27]],
    })
}

/// Serialize an [`ArpPacket`] into its 28-byte wire format.
fn build_arp_packet(packet: &ArpPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ARP_PACKET_SIZE);
    buf.extend_from_slice(&packet.hardware_type.to_be_bytes());
    buf.extend_from_slice(&packet.protocol_type.to_be_bytes());
    buf.push(packet.hardware_size);
    buf.push(packet.protocol_size);
    buf.extend_from_slice(&packet.operation.value().to_be_bytes());
    buf.extend_from_slice(&packet.sender_mac.0);
    buf.extend_from_slice(&packet.sender_ip);
    buf.extend_from_slice(&packet.target_mac.0);
    buf.extend_from_slice(&packet.target_ip);
    buf
}

// ─── ARP cache ───

struct ArpCacheEntry {
    mac: MacAddress,
    expires_at: u64,
}

/// In-memory IPv4→MAC cache with tick-based expiry.
#[derive(Default)]
pub struct ArpCache {
    entries: BTreeMap<Ipv4Addr, ArpCacheEntry>,
}

impl ArpCache {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up the MAC for `ip`, returning `None` if not cached or expired.
    pub fn lookup(&mut self, ip: Ipv4Addr, current_tick: u64) -> Option<MacAddress> {
        let entry = self.entries.get(&ip)?;
        if current_tick >= entry.expires_at {
            self.entries.remove(&ip);
            return None;
        }
        Some(entry.mac)
    }

    /// Insert or refresh a cache entry.
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddress, current_tick: u64) {
        self.entries.insert(
            ip,
            ArpCacheEntry {
                mac,
                expires_at: current_tick + ARP_CACHE_TTL_TICKS,
            },
        );
    }

    /// Evict all entries that have expired at or before `current_tick`.
    ///
    /// Called every tick by [`NetworkStack::advance_tick`].  Uses the same
    /// expiry rule as [`lookup`](Self::lookup) (`current_tick >= expires_at`)
    /// so a lookup immediately after eviction never resurrects a stale entry.
    pub fn evict_expired(&mut self, current_tick: u64) {
        self.entries
            .retain(|_, entry| entry.expires_at > current_tick);
    }
}

// ─── Resolution ───

/// Resolve `target_ip` to a MAC address, sending an ARP Request and
/// busy-waiting for the Reply if it isn't cached.
///
/// Returns [`Error::TimedOut`] if no Reply arrives within
/// [`ARP_RESOLVE_TIMEOUT_TICKS`].
///
/// Uses a tick-based timeout (50 ticks = 500 ms at 100 Hz) rather than
/// a fixed iteration count so the behaviour is independent of poll
/// latency.
pub fn resolve_mac(stack: &NetworkStack, target_ip: Ipv4Addr) -> Result<MacAddress> {
    let start_tick = stack.current_tick();

    // Check cache first.
    {
        let mut cache = stack.arp_cache().lock();
        if let Some(mac) = cache.lookup(target_ip, start_tick) {
            stack.profiler.inc_arp_lookups();
            return Ok(mac);
        }
    }
    stack.profiler.inc_arp_misses();

    // Spin-wait for the reply with tick-based timeout and retransmission.
    // Retransmit the ARP Request up to ARP_MAX_RETRIES times at
    // ARP_RETRANSMIT_TICKS intervals to handle packet loss.
    let mut retries = 0u32;
    let mut last_request_tick = start_tick;
    let mut iterations: u64 = 0;

    // Send the initial ARP Request.
    send_arp_request(stack, target_ip)?;

    loop {
        let _ = stack.poll();
        // Yield the CPU on host/test builds so this busy-wait doesn't
        // consume 100% of a core while waiting for the ARP reply.
        core::hint::spin_loop();

        let tick = stack.current_tick();

        // Retransmit the ARP Request if the interval has elapsed.
        if tick.wrapping_sub(last_request_tick) >= ARP_RETRANSMIT_TICKS && retries < ARP_MAX_RETRIES
        {
            send_arp_request(stack, target_ip)?;
            last_request_tick = tick;
            retries += 1;
        }

        // Overall timeout — give up after ARP_RESOLVE_TIMEOUT_TICKS.
        if tick.wrapping_sub(start_tick) >= ARP_RESOLVE_TIMEOUT_TICKS {
            stack.profiler.inc_arp_resolves_timeout();
            return Err(Error::TimedOut);
        }

        let mut cache = stack.arp_cache().lock();
        if let Some(mac) = cache.lookup(target_ip, tick) {
            return Ok(mac);
        }

        // Hard iteration cap — prevents an infinite hang when ticks never
        // advance (e.g. in tests with no timer interrupt).
        iterations += 1;
        if iterations >= ARP_MAX_SPIN_ITERATIONS {
            stack.profiler.inc_arp_resolves_timeout();
            return Err(Error::TimedOut);
        }
    }
}

/// Send a broadcast ARP Request for `target_ip`.
fn send_arp_request(stack: &NetworkStack, target_ip: Ipv4Addr) -> Result<()> {
    stack.profiler.inc_arp_resolves_sent();
    let request = ArpPacket {
        hardware_type: ARP_HTYPE_ETHERNET,
        protocol_type: ARP_PTYPE_IPV4,
        hardware_size: ARP_HLEN_ETHERNET,
        protocol_size: ARP_PLEN_IPV4,
        operation: ArpOperation::Request,
        sender_mac: MacAddress(stack.local_mac),
        sender_ip: stack.local_ip(),
        target_mac: MacAddress([0, 0, 0, 0, 0, 0]),
        target_ip,
    };
    let payload = build_arp_packet(&request);
    let frame = EthernetFrame::new(
        MacAddress([0xFF; 6]),
        MacAddress(stack.local_mac),
        EtherType::Arp,
        payload,
    );
    let raw = ethernet::build_frame(&frame)?;
    stack.device().send(&raw)
}

// ─── Inbound handling ───

/// Process a received ARP packet.
///
/// - Requests targeting our IP produce a unicast Reply.
/// - Replies refresh the sender's entry in the ARP cache.
pub fn process_arp_packet(stack: &NetworkStack, packet: &ArpPacket) -> Result<()> {
    stack.profiler.inc_arp_packets_rx();
    match packet.operation {
        ArpOperation::Request => {
            // Only reply if the request targets our IP.
            if packet.target_ip != stack.local_ip() {
                return Ok(());
            }
            send_arp_reply(stack, packet)?;
        }
        ArpOperation::Reply => {
            // Update the cache with the sender's mapping.
            let mut cache = stack.arp_cache().lock();
            cache.insert(packet.sender_ip, packet.sender_mac, stack.current_tick());
            // Count as a lookup hit: a received ARP Reply fills the cache
            // and effectively resolves the sender's address.
            drop(cache);
            stack.profiler.inc_arp_lookups();
        }
        _ => {}
    }
    Ok(())
}

/// Send an ARP Reply in response to `request`.
fn send_arp_reply(stack: &NetworkStack, request: &ArpPacket) -> Result<()> {
    let reply = ArpPacket {
        hardware_type: request.hardware_type,
        protocol_type: request.protocol_type,
        hardware_size: request.hardware_size,
        protocol_size: request.protocol_size,
        operation: ArpOperation::Reply,
        sender_mac: MacAddress(stack.local_mac),
        sender_ip: stack.local_ip(),
        target_mac: request.sender_mac,
        target_ip: request.sender_ip,
    };
    let payload = build_arp_packet(&reply);
    // Unicast the Reply back to the requester (it advertised its MAC in the
    // Request's sender field).
    let frame = EthernetFrame::new(
        request.sender_mac,
        MacAddress(stack.local_mac),
        EtherType::Arp,
        payload,
    );
    let raw = ethernet::build_frame(&frame)?;
    stack.device().send(&raw)
}

/// Announce our current IP→MAC mapping to the local segment (gratuitous ARP).
///
/// Broadcasts an ARP Request that targets our own IP, letting peers refresh
/// their caches after an address change (e.g. DHCP).
pub fn send_gratuitous_arp(stack: &NetworkStack) -> Result<()> {
    let own_ip = stack.local_ip();
    let request = ArpPacket {
        hardware_type: ARP_HTYPE_ETHERNET,
        protocol_type: ARP_PTYPE_IPV4,
        hardware_size: ARP_HLEN_ETHERNET,
        protocol_size: ARP_PLEN_IPV4,
        operation: ArpOperation::Request,
        sender_mac: MacAddress(stack.local_mac),
        sender_ip: own_ip,
        target_mac: MacAddress([0, 0, 0, 0, 0, 0]),
        target_ip: own_ip,
    };
    let payload = build_arp_packet(&request);
    let frame = EthernetFrame::new(
        MacAddress([0xFF; 6]),
        MacAddress(stack.local_mac),
        EtherType::Arp,
        payload,
    );
    let raw = ethernet::build_frame(&frame)?;
    stack.device().send(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_build_round_trips() {
        let packet = ArpPacket {
            hardware_type: ARP_HTYPE_ETHERNET,
            protocol_type: ARP_PTYPE_IPV4,
            hardware_size: ARP_HLEN_ETHERNET,
            protocol_size: ARP_PLEN_IPV4,
            operation: ArpOperation::Request,
            sender_mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
            sender_ip: [10, 0, 2, 1],
            target_mac: MacAddress([0; 6]),
            target_ip: [10, 0, 2, 100],
        };
        let raw = build_arp_packet(&packet);
        assert_eq!(raw.len(), ARP_PACKET_SIZE);
        let parsed = parse_arp_packet(&raw).expect("parse");
        assert_eq!(parsed, packet);
    }

    #[test]
    fn parse_rejects_short_packet() {
        assert_eq!(parse_arp_packet(&[0; 20]), Err(Error::InvalidArgument));
    }

    #[test]
    fn operation_round_trips() {
        assert_eq!(ArpOperation::from_u16(1), ArpOperation::Request);
        assert_eq!(ArpOperation::from_u16(2), ArpOperation::Reply);
        assert_eq!(ArpOperation::Request.value(), 1);
        assert_eq!(ArpOperation::Reply.value(), 2);
    }

    #[test]
    fn cache_expires_entries() {
        let mut cache = ArpCache::new();
        cache.insert([10, 0, 2, 1], MacAddress([0x11, 0, 0, 0, 0, 1]), 0);
        assert_eq!(
            cache.lookup([10, 0, 2, 1], 100),
            Some(MacAddress([0x11, 0, 0, 0, 0, 1]))
        );
        // Expired after ARP_CACHE_TTL_TICKS ticks.
        assert_eq!(cache.lookup([10, 0, 2, 1], ARP_CACHE_TTL_TICKS), None);
    }
}
