//! src/kernel/network/internet/nat.rs
//!
//! Network Address Translation / Port Address Translation (NAPT).
//!
//! Implements IPv4 source-NAT masquerading (RFC 2663 / RFC 3022):
//! - Outbound SNAT: replaces internal src_ip:src_port with external IP and an
//!   allocated ephemeral port.
//! - Inbound reverse DNAT: matches the translated port against the
//!   connection-tracking table and restores the original dst_ip:dst_port.
//! - Connection tracking with per-protocol timeout eviction.
//!
//! This is a "cone NAT" (full-cone for UDP, address-restricted for TCP):
//! once a mapping is created, any external host can send to the translated
//! port and reach the internal host.

use alloc::collections::btree_map::{BTreeMap, Entry};
use alloc::vec::Vec;
use core::fmt;

use crate::kernel::network::internet::ipv4;

// ── Constants ───────────────────────────────────────────────────────────────

/// First ephemeral port used for NAT translations.
const NAT_PORT_START: u16 = 32768;
/// Last ephemeral port used for NAT translations.
const NAT_PORT_END: u16 = 60999;

/// TCP established timeout: 24 hours in ticks (at 100 Hz = 8,640,000 ticks).
const TCP_ESTABLISHED_TIMEOUT: u64 = 8_640_000;
/// TCP TIME_WAIT timeout: 120 seconds in ticks.
const TCP_TIME_WAIT_TIMEOUT: u64 = 12_000;
/// TCP NEW (SYN_SENT) timeout: 60 seconds in ticks.
const TCP_NEW_TIMEOUT: u64 = 6_000;
/// UDP flow timeout: 300 seconds in ticks.
const UDP_TIMEOUT: u64 = 30_000;
/// ICMP echo timeout: 30 seconds in ticks.
const ICMP_TIMEOUT: u64 = 3_000;
/// Other protocols: 60 seconds in ticks.
const OTHER_TIMEOUT: u64 = 6_000;

/// Interval between expired-entry sweeps (30 seconds in ticks).
const SWEEP_INTERVAL: u64 = 3_000;

/// Maximum entries in the NAT table before rejecting new translations.
const MAX_NAT_ENTRIES: usize = 1024;

// ── Types ───────────────────────────────────────────────────────────────────

/// Per-protocol connection state for timeout selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatConnState {
    /// TCP: SYN sent, waiting for SYN-ACK.
    TcpNew,
    /// TCP: handshake complete, data flowing.
    TcpEstablished,
    /// TCP: FIN exchange in progress or TIME_WAIT.
    TcpClosing,
    /// UDP: bidirectional flow active.
    UdpActive,
    /// ICMP echo (or other ICMP query).
    IcmpActive,
    /// Other (generic) protocol.
    Other,
}

/// Key that uniquely identifies a NAT session.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NatKey {
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    protocol: u8,
}

/// A single connection-tracking / NAT translation entry.
///
/// The 4-tuple identity (`src_ip:src_port → dst_ip:dst_port:protocol`) lives
/// in the owning `NatKey`; the entry stores the fields the translation paths
/// actually consume.
#[derive(Debug, Clone)]
struct NatEntry {
    /// Original source IP (internal host).
    src_ip: [u8; 4],
    /// Original source port (internal host).
    src_port: u16,
    /// Translated source port (the external-facing port).
    xlate_port: u16,
    /// Connection state (drives timeout selection).
    state: NatConnState,
    /// Tick when this entry was last used (matched in either direction).
    last_seen: u64,
}

impl NatEntry {
    fn timeout_ticks(&self) -> u64 {
        match self.state {
            NatConnState::TcpNew => TCP_NEW_TIMEOUT,
            NatConnState::TcpEstablished => TCP_ESTABLISHED_TIMEOUT,
            NatConnState::TcpClosing => TCP_TIME_WAIT_TIMEOUT,
            NatConnState::UdpActive => UDP_TIMEOUT,
            NatConnState::IcmpActive => ICMP_TIMEOUT,
            NatConnState::Other => OTHER_TIMEOUT,
        }
    }

    fn is_expired(&self, current_tick: u64) -> bool {
        current_tick.wrapping_sub(self.last_seen) >= self.timeout_ticks()
    }
}

// ── NAT table ──────────────────────────────────────────────────────────────

/// Network Address Translation (NAPT) table with connection tracking.
pub struct NatTable {
    /// Connection tracking: maps (src, sport, dst, dport, proto) → entry.
    entries: BTreeMap<NatKey, NatEntry>,
    /// Reverse lookup: translated_port → key (for inbound DNAT).
    xlate_to_key: BTreeMap<u16, NatKey>,
    /// Currently allocated translated ports.
    allocated_ports: BTreeMap<u16, ()>,
    /// External (public-facing) IP address.
    external_ip: [u8; 4],
    /// Tick of the last sweep.
    last_sweep: u64,
    /// Whether NAT is enabled.
    enabled: bool,
}

impl fmt::Debug for NatTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatTable")
            .field("entries", &self.entries.len())
            .field("external_ip", &self.external_ip)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl NatTable {
    /// Create a new empty NAT table.
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            xlate_to_key: BTreeMap::new(),
            allocated_ports: BTreeMap::new(),
            external_ip: [0, 0, 0, 0],
            last_sweep: 0,
            enabled: false,
        }
    }

    /// Enable NAT with the given external (public) IP address.
    pub fn enable(&mut self, external_ip: [u8; 4]) {
        self.external_ip = external_ip;
        self.enabled = true;
    }

    /// Disable NAT.
    pub fn disable(&mut self) {
        self.enabled = false;
        self.entries.clear();
        self.xlate_to_key.clear();
        self.allocated_ports.clear();
    }

    /// Whether NAT is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the external IP address (the NAT's public address).
    pub fn external_ip(&self) -> [u8; 4] {
        self.external_ip
    }

    /// Number of active translation entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    // ── Port allocation ──────────────────────────────────────────────────

    /// Allocate a translated (external) port for the given protocol.
    /// Returns `None` if port exhaustion or table full.
    fn alloc_xlate_port(&mut self) -> Option<u16> {
        if self.entries.len() >= MAX_NAT_ENTRIES {
            return None;
        }
        for port in NAT_PORT_START..=NAT_PORT_END {
            if let Entry::Vacant(e) = self.allocated_ports.entry(port) {
                e.insert(());
                return Some(port);
            }
        }
        None
    }

    /// Release a translated port back to the pool.
    fn free_xlate_port(&mut self, port: u16) {
        self.allocated_ports.remove(&port);
    }

    // ── SNAT: Outbound translation ───────────────────────────────────────

    /// Apply source NAT to an outbound IPv4 packet.
    ///
    /// Replaces `src_ip` with the external IP and `src_port` with an
    /// allocated translated port.  Creates or updates a connection-tracking
    /// entry.  Returns the modified packet bytes on success.
    pub fn snat_ipv4(&mut self, packet: &[u8], current_tick: u64) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }

        let (header, header_len) = ipv4::parse_ipv4_header(packet)?;
        let src_ip = header.source;
        let dst_ip = header.destination;
        // `header.protocol` is the typed IpProtocol enum; NAT keys and the
        // protocol matching below work on the raw IANA protocol number.
        let protocol = header.protocol.to_u8();
        let total_len = header.total_length as usize;

        if total_len != packet.len() {
            return None;
        }

        // Only NAT TCP, UDP, and ICMP for now.
        let (src_port, dst_port) = match protocol {
            6 | 17 => extract_tcp_udp_ports(packet, header_len)?,
            1 => (0, 0),      // ICMP — use query ID on ICMP echo (handled separately)
            _ => return None, // unsupported protocol, pass through
        };

        let key = NatKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        };

        // Look up or create a NAT entry.
        let xlate_port = if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_seen = current_tick;
            entry.xlate_port
        } else {
            let xlate_port = self.alloc_xlate_port()?;
            let entry = NatEntry {
                src_ip,
                src_port,
                xlate_port,
                state: if protocol == 6 {
                    NatConnState::TcpNew
                } else if protocol == 17 {
                    NatConnState::UdpActive
                } else {
                    NatConnState::IcmpActive
                },
                last_seen: current_tick,
            };
            self.entries.insert(key.clone(), entry);
            self.xlate_to_key.insert(xlate_port, key);
            xlate_port
        };

        // Rewrite the packet.
        let mut new_packet = packet.to_vec();

        // Replace source IP in IP header.
        new_packet[12..16].copy_from_slice(&self.external_ip);

        // Fix IP header checksum.
        let old_ip_csum = u16::from_be_bytes([new_packet[10], new_packet[11]]);
        let new_ip_csum =
            update_ip_checksum_after_src_change(old_ip_csum, src_ip, self.external_ip);
        new_packet[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());

        // Replace source port in TCP/UDP header.
        if protocol == 6 || protocol == 17 {
            // TCP carries its checksum at offset 16; UDP at offset 6.  The
            // checksum field must lie within the segment before it is
            // rewritten — a truncated transport header is dropped.
            let csum_offset = if protocol == 6 { 16 } else { 6 };
            if packet.len() < header_len + csum_offset + 2 {
                return None;
            }
            new_packet[header_len..header_len + 2].copy_from_slice(&xlate_port.to_be_bytes());

            // Fix TCP/UDP checksum (pseudo-header change).
            let old_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
            let old_csum = u16::from_be_bytes([
                new_packet[header_len + csum_offset],
                new_packet[header_len + csum_offset + 1],
            ]);
            let new_csum = update_transport_checksum_after_nat(
                old_csum,
                old_port,
                xlate_port,
                src_ip,
                self.external_ip,
            );
            new_packet[header_len + csum_offset..header_len + csum_offset + 2]
                .copy_from_slice(&new_csum.to_be_bytes());
        }

        Some(new_packet)
    }

    // ── DNAT: Inbound reverse translation ────────────────────────────────

    /// Apply destination NAT to an inbound IPv4 packet (reverse translation).
    ///
    /// Looks up the translated destination port in the connection-tracking
    /// table and restores the original `dst_ip:dst_port`.  Returns `None` if
    /// there is no matching translation entry (packet is dropped).
    pub fn dnat_ipv4(&mut self, packet: &[u8], current_tick: u64) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }

        let (header, header_len) = ipv4::parse_ipv4_header(packet)?;
        let dst_ip = header.destination;
        // `header.protocol` is the typed IpProtocol enum; NAT keys and the
        // protocol matching below work on the raw IANA protocol number.
        let protocol = header.protocol.to_u8();

        // Only process reverse NAT if the packet is addressed to our
        // external IP.
        if dst_ip != self.external_ip {
            return None;
        }

        let (dst_port, _src_port) = match protocol {
            6 | 17 => {
                let (sport, dport) = extract_tcp_udp_ports(packet, header_len)?;
                (dport, sport)
            }
            1 => (0, 0),
            _ => return None,
        };

        // Look up by translated port.
        let key = self.xlate_to_key.get(&dst_port)?;
        let entry = self.entries.get_mut(key)?;

        // Update last-seen and potentially promote TCP state.
        entry.last_seen = current_tick;
        if entry.state == NatConnState::TcpNew {
            entry.state = NatConnState::TcpEstablished;
        }

        let original_dst_ip = entry.src_ip;
        let original_dst_port = entry.src_port;

        // Rewrite the packet.
        let mut new_packet = packet.to_vec();

        // Restore destination IP.
        new_packet[16..20].copy_from_slice(&original_dst_ip);

        // Fix IP header checksum.
        let old_ip_csum = u16::from_be_bytes([new_packet[10], new_packet[11]]);
        let new_ip_csum = update_ip_checksum_after_src_change(old_ip_csum, dst_ip, original_dst_ip);
        new_packet[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());

        // Restore destination port in TCP/UDP header.
        if protocol == 6 || protocol == 17 {
            // TCP checksum at offset 16, UDP at offset 6.  The checksum
            // field must lie within the segment before it is rewritten — a
            // truncated transport header is dropped.
            let csum_offset = if protocol == 6 { 16 } else { 6 };
            if packet.len() < header_len + csum_offset + 2 {
                return None;
            }
            let old_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
            new_packet[header_len + 2..header_len + 4]
                .copy_from_slice(&original_dst_port.to_be_bytes());

            let old_csum_bytes = [
                new_packet[header_len + csum_offset],
                new_packet[header_len + csum_offset + 1],
            ];
            let old_csum = u16::from_be_bytes(old_csum_bytes);
            if old_csum == 0 {
                // Checksum is zero — no fixup needed (uncommon for UDP,
                // but allowed for UDP/IPv4).
            } else {
                let new_csum = update_transport_checksum_after_nat(
                    old_csum,
                    old_port,
                    original_dst_port,
                    dst_ip,
                    original_dst_ip,
                );
                new_packet[header_len + csum_offset..header_len + csum_offset + 2]
                    .copy_from_slice(&new_csum.to_be_bytes());
            }
        }

        Some(new_packet)
    }

    // ── Housekeeping ────────────────────────────────────────────────────

    /// Sweep expired entries.  Call periodically from the tick handler.
    pub fn sweep_expired(&mut self, current_tick: u64) {
        if current_tick.wrapping_sub(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = current_tick;

        let expired: Vec<NatKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired(current_tick))
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            if let Some(entry) = self.entries.remove(&key) {
                self.xlate_to_key.remove(&entry.xlate_port);
                self.free_xlate_port(entry.xlate_port);
            }
        }
    }

    /// Mark a TCP flow as established (called when SYN-ACK is seen).
    pub fn promote_tcp_to_established(
        &mut self,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
    ) {
        let key = NatKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: 6,
        };
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.state == NatConnState::TcpNew {
                entry.state = NatConnState::TcpEstablished;
            }
        }
    }

    /// Mark a TCP flow as closed (FIN exchange seen).
    pub fn mark_tcp_closing(
        &mut self,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
    ) {
        let key = NatKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: 6,
        };
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.state = NatConnState::TcpClosing;
        }
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Extract source and destination ports from TCP/UDP header.
fn extract_tcp_udp_ports(packet: &[u8], header_len: usize) -> Option<(u16, u16)> {
    if packet.len() < header_len + 4 {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
    let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
    Some((src_port, dst_port))
}

/// Incremental IP header checksum update after changing source IP.
///
/// Standard incremental checksum update: `new_csum = ~(~old_csum + ~old_val +
/// new_val)` where the ones-complement is folded with carry.
fn update_ip_checksum_after_src_change(old_csum: u16, old_src: [u8; 4], new_src: [u8; 4]) -> u16 {
    let old_high = u16::from_be_bytes([old_src[0], old_src[1]]);
    let old_low = u16::from_be_bytes([old_src[2], old_src[3]]);
    let new_high = u16::from_be_bytes([new_src[0], new_src[1]]);
    let new_low = u16::from_be_bytes([new_src[2], new_src[3]]);

    incremental_checksum_update(old_csum, old_high, new_high);
    let csum = incremental_checksum_update(old_csum, old_high, new_high);
    incremental_checksum_update(csum, old_low, new_low)
}

/// Update a transport-layer (TCP/UDP) checksum after NAT rewrites.
///
/// The pseudo-header changes because src_ip and/or src_port changed.
/// We directly update the old checksum by undoing the old value and
/// applying the new one.
fn update_transport_checksum_after_nat(
    old_csum: u16,
    old_port: u16,
    new_port: u16,
    old_ip: [u8; 4],
    new_ip: [u8; 4],
) -> u16 {
    // Update pseudo-header: IP parts.
    let mut csum = old_csum;

    // Undo old IP, apply new IP (2 x 16-bit words).
    let old_ip_hi = u16::from_be_bytes([old_ip[0], old_ip[1]]);
    let old_ip_lo = u16::from_be_bytes([old_ip[2], old_ip[3]]);
    let new_ip_hi = u16::from_be_bytes([new_ip[0], new_ip[1]]);
    let new_ip_lo = u16::from_be_bytes([new_ip[2], new_ip[3]]);

    csum = incremental_checksum_update(csum, old_ip_hi, new_ip_hi);
    csum = incremental_checksum_update(csum, old_ip_lo, new_ip_lo);

    // Update port.
    csum = incremental_checksum_update(csum, old_port, new_port);

    csum
}

/// Incremental ones-complement checksum update.
///
/// `new_csum = ~(~old_csum + ~old_val + new_val)` folded with carry.
fn incremental_checksum_update(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut csum = !old_csum as u32;
    csum = csum.wrapping_add(!old_val as u32);
    csum = csum.wrapping_add(new_val as u32);
    // Fold carry.
    while csum > 0xFFFF {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    !(csum as u16)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::network::internet::ipv4;
    use alloc::vec;

    /// Build a minimal IPv4 TCP packet.
    fn build_ipv4_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_header_len = 20;
        let total_len = 20 + tcp_header_len + payload.len();
        let mut packet = vec![0u8; total_len];

        // IP header.
        let ver_ihl: u8 = 0x45;
        packet[0] = ver_ihl;
        packet[1] = 0; // DSCP/ECN
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x0000u16.to_be_bytes()); // ID
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags+Offset
        packet[8] = 64; // TTL
        packet[9] = 6; // Protocol = TCP
                       // Checksum at 10-11, initially 0.
        packet[12..16].copy_from_slice(&src_ip);
        packet[16..20].copy_from_slice(&dst_ip);

        // TCP header.
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[24..28].copy_from_slice(&0u32.to_be_bytes()); // seq
        packet[28..32].copy_from_slice(&0u32.to_be_bytes()); // ack
        let data_offset: u8 = 5 << 4;
        packet[32] = data_offset;
        packet[33] = 0x10; // ACK flag
        packet[34..36].copy_from_slice(&0xFFFFu16.to_be_bytes()); // window
                                                                  // Checksum at 36-37, initially 0.
        packet[38..40].copy_from_slice(&0u16.to_be_bytes()); // urgent ptr

        // Payload.
        packet[40..].copy_from_slice(payload);

        // Compute IP checksum.
        let ip_csum = ipv4::compute_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // Compute TCP checksum.
        let pseudo = ipv4::pseudo_header_checksum_input(src_ip, dst_ip, 6, &packet[20..]);
        let tcp_csum = ipv4::compute_checksum(&pseudo);
        packet[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

        packet
    }

    /// Build a minimal IPv4 UDP packet.
    fn build_ipv4_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_header_len = 8;
        let total_len = 20 + udp_header_len + payload.len();
        let mut packet = vec![0u8; total_len];

        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&src_ip);
        packet[16..20].copy_from_slice(&dst_ip);

        // UDP header.
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len = (udp_header_len + payload.len()) as u16;
        packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
        // Checksum at 26-27, initially 0.
        packet[28..].copy_from_slice(payload);

        // IP checksum.
        let ip_csum = ipv4::compute_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // UDP checksum.
        let pseudo = ipv4::pseudo_header_checksum_input(src_ip, dst_ip, 17, &packet[20..]);
        let udp_csum = ipv4::compute_checksum(&pseudo);
        packet[26..28].copy_from_slice(&udp_csum.to_be_bytes());

        packet
    }

    #[test]
    fn nat_snat_rewrites_source() {
        let mut table = NatTable::new();
        table.enable([10, 0, 0, 1]); // external IP

        let internal = [192, 168, 1, 100];
        let external = [93, 184, 216, 34];
        let packet = build_ipv4_tcp_packet(internal, external, 45678, 80, b"GET /");

        let result = table.snat_ipv4(&packet, 0).expect("snat should succeed");
        assert!(result.len() == packet.len());

        // Source IP should be rewritten.
        let (header, _) = ipv4::parse_ipv4_header(&result).expect("parse header");
        assert_eq!(header.source, [10, 0, 0, 1]);
        assert_eq!(header.destination, external);

        // Source port should be in the NAT range.
        let sport = u16::from_be_bytes([result[20], result[21]]);
        assert!((NAT_PORT_START..=NAT_PORT_END).contains(&sport));

        // IP checksum should still be valid.
        let ip_csum = ipv4::compute_checksum(&result[..20]);
        assert_eq!(ip_csum, 0);

        assert_eq!(table.entry_count(), 1);
    }

    #[test]
    fn nat_dnat_restores_original() {
        let mut table = NatTable::new();
        table.enable([10, 0, 0, 1]);

        let internal = [192, 168, 1, 100];
        let external = [93, 184, 216, 34];

        // Outbound: create NAT entry.
        let out = build_ipv4_tcp_packet(internal, external, 45678, 80, b"GET /");
        let snat_packet = table.snat_ipv4(&out, 0).expect("snat");
        let sport = u16::from_be_bytes([snat_packet[20], snat_packet[21]]);

        // Inbound: reply from external server.
        let reply = build_ipv4_tcp_packet(external, [10, 0, 0, 1], 80, sport, b"HTTP/1.1 200");
        let dnat_packet = table.dnat_ipv4(&reply, 100).expect("dnat");

        // Destination IP should be restored.
        let (header, _) = ipv4::parse_ipv4_header(&dnat_packet).expect("parse");
        assert_eq!(header.destination, internal);
    }

    #[test]
    fn nat_dnat_drops_unknown_translation() {
        let mut table = NatTable::new();
        table.enable([10, 0, 0, 1]);

        // Inbound packet to a port with no translation.
        let reply = build_ipv4_tcp_packet([93, 184, 216, 34], [10, 0, 0, 1], 80, 50000, b"data");
        assert!(table.dnat_ipv4(&reply, 0).is_none());
    }

    #[test]
    fn nat_sweep_expires_old_entries() {
        let mut table = NatTable::new();
        table.enable([10, 0, 0, 1]);

        let packet = build_ipv4_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 45678, 53, b"query");
        let _ = table.snat_ipv4(&packet, 0).expect("snat");
        assert_eq!(table.entry_count(), 1);

        // Advance time past UDP timeout + sweep interval.
        table.sweep_expired(UDP_TIMEOUT + SWEEP_INTERVAL + 1);
        assert_eq!(table.entry_count(), 0);
    }

    #[test]
    fn nat_snat_reuses_existing_entry() {
        let mut table = NatTable::new();
        table.enable([10, 0, 0, 1]);

        let internal = [192, 168, 1, 100];
        let external = [93, 184, 216, 34];

        let pkt1 = build_ipv4_tcp_packet(internal, external, 45678, 80, b"req1");
        let result1 = table.snat_ipv4(&pkt1, 0).expect("snat1");
        let port1 = u16::from_be_bytes([result1[20], result1[21]]);

        let pkt2 = build_ipv4_tcp_packet(internal, external, 45678, 80, b"req2");
        let result2 = table.snat_ipv4(&pkt2, 100).expect("snat2");
        let port2 = u16::from_be_bytes([result2[20], result2[21]]);

        // Same internal (src_ip, src_port, dst_ip, dst_port, proto) → same
        // translated port.
        assert_eq!(port1, port2);
        assert_eq!(table.entry_count(), 1);
    }

    #[test]
    fn nat_disabled_passes_through() {
        let mut table = NatTable::new();
        // Not enabled.

        let packet =
            build_ipv4_tcp_packet([192, 168, 1, 100], [93, 184, 216, 34], 45678, 80, b"GET /");
        assert!(table.snat_ipv4(&packet, 0).is_none());
        assert!(table.dnat_ipv4(&packet, 0).is_none());
    }

    #[test]
    fn incremental_checksum_update_preserves_validity() {
        // A simple test: start with a valid zero checksum, change port,
        // verify the result is still valid.
        let old_port: u16 = 80;
        let new_port: u16 = 8080;
        // Simulate a checksum that was computed over a pseudo-header
        // that included old_port.
        let old_csum = ipv4::compute_checksum(&[
            0x00, 0x00, 0x00, 0x50, // old port = 80 (0x0050)
            0x00, 0x00,
        ]);
        let new_csum = incremental_checksum_update(old_csum, old_port, new_port);
        // Verify: new checksum should be valid for the new data.
        let verify = ipv4::compute_checksum(&[
            0x00, 0x00, 0x1F, 0x90, // new port = 8080 (0x1F90)
            0x00, 0x00,
        ]);
        assert_eq!(new_csum, verify);
    }

    #[test]
    fn nat_port_exhaustion_rejects_new_flows() {
        let mut table = NatTable::new();
        table.enable([10, 0, 0, 1]);

        // Exhaust all ports.
        for port in NAT_PORT_START..=NAT_PORT_END {
            table.allocated_ports.insert(port, ());
        }

        let packet =
            build_ipv4_tcp_packet([192, 168, 1, 100], [93, 184, 216, 34], 45678, 80, b"GET /");
        assert!(
            table.snat_ipv4(&packet, 0).is_none(),
            "should fail on port exhaustion"
        );
    }
}
