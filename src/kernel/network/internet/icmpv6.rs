//! src/kernel/network/internet/icmpv6.rs
//!
//! ICMPv6 (RFC 4443) and Neighbor Discovery Protocol (RFC 4861) for IPv6.
//!
//! Implements:
//! - ICMPv6 Echo Request / Reply (ping6)
//! - NDP Neighbor Solicitation / Advertisement (MAC resolution)
//! - NDP Router Solicitation / Advertisement (SLAAC)
//! - Neighbor cache (IPv6 → MAC, with reachability states)
//! - Duplicate Address Detection (DAD)

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

use super::ipv4;
use super::ipv6::{self, Ipv6Addr, Ipv6Header, Ipv6NextHeader, IPV6_HEADER_SIZE};
use super::mld;
use crate::kernel::network::link::ethernet::{self, EtherType, MacAddress};
use crate::kernel::network::stack::NetworkStack;
use crate::{Error, Result};

// ─── ICMPv6 type constants ──────────────────────────────────────────────

pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;

// NDP message types (RFC 4861)
pub const NDP_ROUTER_SOLICITATION: u8 = 133;
pub const NDP_ROUTER_ADVERTISEMENT: u8 = 134;
pub const NDP_NEIGHBOR_SOLICITATION: u8 = 135;
pub const NDP_NEIGHBOR_ADVERTISEMENT: u8 = 136;

// ─── NDP option types ───────────────────────────────────────────────────

const NDP_OPT_SOURCE_LL_ADDR: u8 = 1;
const NDP_OPT_TARGET_LL_ADDR: u8 = 2;
const NDP_OPT_PREFIX_INFO: u8 = 3;
/// NDP MTU option type (RFC 4861 §4.6.4): advertises the link MTU, which
/// hosts MUST honor when it is >= IPV6_MIN_MTU (1280).
const NDP_OPT_MTU: u8 = 5;

// ─── ICMPv6 header size ─────────────────────────────────────────────────

/// ICMPv6 header: type(1) + code(1) + checksum(2) = 4 bytes.
pub const ICMPV6_HEADER_SIZE: usize = 4;

// ─── ICMPv6 message ─────────────────────────────────────────────────────

/// Parsed ICMPv6 header (first 4 bytes; NDP messages have additional fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
}

/// Parse an ICMPv6 header from a byte slice.
pub fn parse_icmpv6_header(data: &[u8]) -> Result<Icmpv6Header> {
    if data.len() < ICMPV6_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    Ok(Icmpv6Header {
        icmp_type: data[0],
        code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
    })
}

/// Build an ICMPv6 message with checksum computed over the IPv6 pseudo-header
/// and message body.
///
/// The ICMPv6 checksum covers the pseudo-header + ICMPv6 message (RFC 4443
/// §2.3).
pub fn build_icmpv6_message(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    icmp_type: u8,
    code: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ICMPV6_HEADER_SIZE + body.len());
    buf.push(icmp_type);
    buf.push(code);
    // Checksum placeholder
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(body);

    // Compute checksum over pseudo-header + message
    let mut sum: u32 = 0;
    ipv6::pseudo_header_checksum_add(
        &mut sum,
        src,
        dst,
        Ipv6NextHeader::Icmpv6.to_u8(),
        buf.len() as u32,
    );
    ipv4::checksum_add(&mut sum, &buf);
    let checksum = ipv4::checksum_finalize(sum);

    buf[2] = (checksum >> 8) as u8;
    buf[3] = checksum as u8;
    buf
}

/// Maximum number of bytes of the invoking packet that fit after the ICMPv6
/// header, the reserved field, and the IPv6 header within the minimum IPv6
/// MTU (1280 bytes).
fn dest_unreachable_embed_len(original_payload: &[u8]) -> usize {
    let max_embed = 1280usize
        .saturating_sub(IPV6_HEADER_SIZE)
        .saturating_sub(ICMPV6_HEADER_SIZE)
        .saturating_sub(4);
    original_payload.len().min(max_embed)
}

/// Build an ICMPv6 Destination Unreachable message (type 1, code 4 = port
/// unreachable).  Embeds as much of the invoking packet as fits without
/// exceeding the minimum IPv6 MTU (1280 bytes).
///
/// Returns a complete ICMPv6 message (header + reserved + embedded data).
/// This single-argument form has no access to the reply's source and
/// destination addresses, so its checksum is computed over the ICMPv6
/// message alone; callers that know the reply addresses should use
/// [`build_icmpv6_dest_unreachable_for`] so the checksum covers the IPv6
/// pseudo-header (RFC 4443 §2.3).
pub fn build_icmpv6_dest_unreachable(original_payload: &[u8]) -> Vec<u8> {
    let embed_len = dest_unreachable_embed_len(original_payload);

    let mut msg = Vec::with_capacity(ICMPV6_HEADER_SIZE + 4 + embed_len);
    msg.push(ICMPV6_DEST_UNREACHABLE);
    msg.push(4);
    msg.extend_from_slice(&[0u8; 2]); // checksum placeholder
    msg.extend_from_slice(&[0u8; 4]); // reserved
    msg.extend_from_slice(&original_payload[..embed_len]);

    let checksum = ipv4::compute_checksum(&msg);
    msg[2] = (checksum >> 8) as u8;
    msg[3] = checksum as u8;
    msg
}

/// Build a complete ICMPv6 Destination Unreachable message (type 1, code 4)
/// with the checksum computed over the IPv6 pseudo-header of the reply sent
/// from `src` to `dst`.
pub fn build_icmpv6_dest_unreachable_for(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    original_payload: &[u8],
) -> Vec<u8> {
    let embed_len = dest_unreachable_embed_len(original_payload);
    let mut body = Vec::with_capacity(4 + embed_len);
    body.extend_from_slice(&[0u8; 4]); // reserved
    body.extend_from_slice(&original_payload[..embed_len]);
    build_icmpv6_message(src, dst, ICMPV6_DEST_UNREACHABLE, 4, &body)
}

// ─── ICMPv6 error-message inspection ─────────────────────────────────────

/// Information about the original packet embedded in an ICMPv6 error message.
///
/// Populated by [`parse_icmpv6_error_info`] from a Destination Unreachable
/// message, which carries the offending IPv6 header (plus the first bytes of
/// its transport header for TCP/UDP) per RFC 4443 §2.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6ErrorInfo {
    pub original_src: Ipv6Addr,
    pub original_dst: Ipv6Addr,
    pub next_header: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Parse the embedded original-packet information from an ICMPv6 Destination
/// Unreachable message (type 1).
///
/// Returns `Some` when the message is a Destination Unreachable (used by the
/// stack to detect an unreachable destination and to notify the affected
/// TCP/UDP connection), or `None` for any other ICMPv6 type or a malformed
/// packet.  The parse is deliberately lenient — ports are only extracted when
/// the embedded transport header is present.
pub fn parse_icmpv6_error_info(data: &[u8]) -> Option<Icmpv6ErrorInfo> {
    // ICMPv6 header (4) + reserved (4) + embedded IPv6 header (40).
    let embedded = ICMPV6_HEADER_SIZE + 4;
    if data.len() < embedded + IPV6_HEADER_SIZE {
        return None;
    }
    if data[0] != ICMPV6_DEST_UNREACHABLE {
        return None;
    }

    // The embedded IPv6 base header starts after the ICMPv6 header + reserved.
    let ip = &data[embedded..];
    let mut original_src = [0u8; 16];
    original_src.copy_from_slice(&ip[8..24]);
    let mut original_dst = [0u8; 16];
    original_dst.copy_from_slice(&ip[24..40]);
    let next_header = ip[6];

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    // TCP (6) and UDP (17) embed 8 bytes of the transport header; the source
    // and destination ports are its first four bytes.
    if (next_header == 6 || next_header == 17) && data.len() >= embedded + IPV6_HEADER_SIZE + 4 {
        let transport = &data[embedded + IPV6_HEADER_SIZE..];
        src_port = u16::from_be_bytes([transport[0], transport[1]]);
        dst_port = u16::from_be_bytes([transport[2], transport[3]]);
    }

    Some(Icmpv6ErrorInfo {
        original_src,
        original_dst,
        next_header,
        src_port,
        dst_port,
    })
}

// ─── ICMPv6 processing ─────────────────────────────────────────────────

/// Process an incoming ICMPv6 packet embedded in an IPv6 datagram.
///
/// Returns `Ok(Some((reply_header, reply_data)))` if a reply should be
/// sent, or `Ok(None)` if the packet was silently consumed.
pub fn process_icmpv6_packet(
    stack: &NetworkStack,
    ip_src: Ipv6Addr,
    ip_dst: Ipv6Addr,
    icmp_data: &[u8],
) -> Result<Option<(Ipv6Header, Vec<u8>)>> {
    if icmp_data.len() < ICMPV6_HEADER_SIZE {
        return Ok(None);
    }

    let header = parse_icmpv6_header(icmp_data)?;

    match header.icmp_type {
        ICMPV6_ECHO_REQUEST => {
            // Build Echo Reply
            let reply_body = &icmp_data[ICMPV6_HEADER_SIZE..];
            let reply_msg = build_icmpv6_message(ip_dst, ip_src, ICMPV6_ECHO_REPLY, 0, reply_body);

            let ip_header = Ipv6Header {
                traffic_class: 0,
                flow_label: 0,
                payload_length: 0,
                next_header: Ipv6NextHeader::Icmpv6,
                hop_limit: ipv6::IPV6_DEFAULT_HOP_LIMIT,
                source: ip_dst,
                destination: ip_src,
            };

            Ok(Some((ip_header, reply_msg)))
        }
        NDP_NEIGHBOR_SOLICITATION => process_neighbor_solicitation(stack, ip_src, icmp_data),
        NDP_NEIGHBOR_ADVERTISEMENT => process_neighbor_advertisement(stack, ip_src, icmp_data),
        NDP_ROUTER_SOLICITATION => {
            // Only routers respond to RS; hosts silently ignore.
            Ok(None)
        }
        NDP_ROUTER_ADVERTISEMENT => {
            process_router_advertisement(stack, icmp_data);
            Ok(None)
        }
        // MLDv1 types (RFC 2710)
        mld::MLD_TYPE_QUERY | mld::MLD_TYPE_REPORT | mld::MLD_TYPE_DONE => {
            let mut mld_state = stack.mld_state().lock();
            let replies =
                mld::process_mld_message(stack, ip_src, ip_dst, icmp_data, &mut mld_state);
            // Send any pending MLD replies.
            for (ip_header, reply_payload) in replies {
                let _ = send_ipv6_frame(stack, &ip_header, &reply_payload);
            }
            Ok(None)
        }
        _ => {
            // Silently ignore other ICMPv6 types.
            Ok(None)
        }
    }
}

// ─── NDP: Neighbor Solicitation (RFC 4861 §4.3) ─────────────────────────

/// Size of an NDP Neighbor Solicitation message:
/// 4 (ICMPv6 header) + 4 (reserved) + 16 (target address) = 24.
const NDP_NS_BASE_SIZE: usize = 24;

fn process_neighbor_solicitation(
    stack: &NetworkStack,
    ip_src: Ipv6Addr,
    data: &[u8],
) -> Result<Option<(Ipv6Header, Vec<u8>)>> {
    if data.len() < NDP_NS_BASE_SIZE {
        return Ok(None);
    }

    // Target address is at offset 8 (after ICMPv6 header + 4 reserved bytes).
    let mut target = [0u8; 16];
    target.copy_from_slice(&data[8..24]);

    // Check if the target matches one of our addresses.
    let our_link_local = stack.local_ip_v6();
    let our_global = stack.global_ip_v6();
    let is_for_us = target == our_link_local || our_global.is_some_and(|global| target == global);

    if !is_for_us {
        return Ok(None);
    }

    // Extract source link-layer address option if present.
    let src_mac = extract_ll_addr_option(data, NDP_NS_BASE_SIZE, NDP_OPT_SOURCE_LL_ADDR);

    // If a source MAC is provided, cache it (optimistic cache update per
    // RFC 4861 §7.2.5).
    if let Some(mac) = src_mac {
        let mut cache = stack.neighbor_cache_v6().lock();
        cache.insert(ip_src, mac, stack.current_tick());
        cache.set_reachable(ip_src);
    }

    // Build NA: set Solicited flag (S=1), target=our address, target LL addr
    // option.  The reply is sent from `target` to the soliciting host.
    let our_mac = MacAddress(stack.local_mac);
    let na = build_neighbor_advertisement(
        target, // reply source
        ip_src, // reply destination
        target, // target address
        true,   // solicited
        false,  // not a router
        &our_mac,
    );

    let ip_header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: Ipv6NextHeader::Icmpv6,
        hop_limit: 255, // NDP requires hop limit 255
        source: target, // use the target address as source
        destination: ip_src,
    };

    Ok(Some((ip_header, na)))
}

// ─── NDP: Neighbor Advertisement (RFC 4861 §4.4) ────────────────────────

/// Size of an NDP Neighbor Advertisement message:
/// 4 (ICMPv6 header) + 4 (flags+reserved) + 16 (target address) = 24.
const NDP_NA_BASE_SIZE: usize = 24;

fn process_neighbor_advertisement(
    stack: &NetworkStack,
    ip_src: Ipv6Addr,
    data: &[u8],
) -> Result<Option<(Ipv6Header, Vec<u8>)>> {
    if data.len() < NDP_NA_BASE_SIZE {
        return Ok(None);
    }

    // Target address is at offset 8.
    let mut target = [0u8; 16];
    target.copy_from_slice(&data[8..24]);

    // Extract target link-layer address option.
    let target_mac = extract_ll_addr_option(data, NDP_NA_BASE_SIZE, NDP_OPT_TARGET_LL_ADDR);

    if let Some(mac) = target_mac {
        // Cache the target's MAC (used for both solicited and unsolicited NAs).
        let mut cache = stack.neighbor_cache_v6().lock();
        cache.insert(target, mac, stack.current_tick());
        cache.set_reachable(target);
    }

    // Also cache the sender's mapping (in case of unsolicited NA from source ≠
    // target).
    let src_mac = extract_ll_addr_option(data, NDP_NA_BASE_SIZE, NDP_OPT_TARGET_LL_ADDR);
    if let Some(mac) = src_mac {
        let mut cache = stack.neighbor_cache_v6().lock();
        cache.insert(ip_src, mac, stack.current_tick());
    }

    // NA doesn't generate a reply.
    Ok(None)
}

/// Build a Neighbor Advertisement message as a complete ICMPv6 message
/// (type 136, code 0).  `src` and `dst` are the source and destination of
/// the NA reply and are used for the checksum's IPv6 pseudo-header.
fn build_neighbor_advertisement(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    target: Ipv6Addr,
    solicited: bool,
    router: bool,
    target_ll_addr: &MacAddress,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(28);
    // Flags: R (bit 7), S (bit 6), O (bit 5)
    let mut flags: u8 = 0;
    if router {
        flags |= 0x80;
    }
    if solicited {
        flags |= 0x40;
    }
    // Override flag (O) = 0 (we're not overriding an existing entry).

    body.push(flags);
    body.push(0); // reserved
    body.push(0); // reserved
    body.push(0); // reserved
                  // Target address
    body.extend_from_slice(&target);
    // Target link-layer address option
    push_ll_addr_option(&mut body, NDP_OPT_TARGET_LL_ADDR, target_ll_addr);

    build_icmpv6_message(src, dst, NDP_NEIGHBOR_ADVERTISEMENT, 0, &body)
}

// ─── NDP: Router Solicitation (RFC 4861 §4.1) ──────────────────────────

/// Size of an NDP Router Solicitation message (ICMPv6 header + 4 reserved).
const NDP_RS_BASE_SIZE: usize = ICMPV6_HEADER_SIZE + 4;

/// Build a Router Solicitation message to solicit Router Advertisements.
pub fn build_router_solicitation(src_ll_addr: &MacAddress) -> Vec<u8> {
    let mut body = Vec::with_capacity(NDP_RS_BASE_SIZE + 8);
    // Reserved (4 bytes)
    body.extend_from_slice(&[0u8; 4]);
    // Source link-layer address option
    push_ll_addr_option(&mut body, NDP_OPT_SOURCE_LL_ADDR, src_ll_addr);
    body
}

// ─── NDP: Router Advertisement processing (SLAAC) ──────────────────────

/// Minimum size of an RA: 4 (ICMPv6) + 12 (RA fields) = 16 bytes.
const NDP_RA_BASE_SIZE: usize = 16;

/// Process a Router Advertisement and update the neighbor cache / SLAAC state.
///
/// Extracts the router's MAC (from the source link-layer address option),
/// Prefix Information options, and MTU.  If a valid global prefix is found
/// and SLAAC is enabled, a global IPv6 address is formed and configured.
fn process_router_advertisement(stack: &NetworkStack, data: &[u8]) {
    if data.len() < NDP_RA_BASE_SIZE {
        return;
    }

    let _hop_limit = data[4];
    let flags = data[5];
    let router_lifetime = u16::from_be_bytes([data[6], data[7]]);
    let reachable_time = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let retrans_timer = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    // managed (M) flag: bit 7 of flags byte
    let _managed = flags & 0x80 != 0;
    // other (O) flag: bit 6 of flags byte
    let _other_config = flags & 0x40 != 0;

    // Update stack's RA parameters (used by SLAAC logic).
    if router_lifetime > 0 {
        stack.set_router_lifetime_v6(router_lifetime);
    }
    if reachable_time > 0 {
        stack.set_reachable_time_v6(reachable_time as u64);
    }
    if retrans_timer > 0 {
        stack.set_retrans_timer_v6(retrans_timer as u64);
    }

    // Parse options.
    let mut pos = NDP_RA_BASE_SIZE;
    while pos + 1 < data.len() {
        let opt_type = data[pos];
        let opt_len = data[pos + 1] as usize;
        if opt_len == 0 {
            break;
        }
        let opt_bytes = opt_len * 8; // NDP option lengths are in units of 8 bytes.
        if pos + opt_bytes > data.len() {
            break;
        }

        match opt_type {
            NDP_OPT_SOURCE_LL_ADDR if opt_bytes >= 8 => {
                if opt_bytes >= 8 {
                    let mac = MacAddress([
                        data[pos + 2],
                        data[pos + 3],
                        data[pos + 4],
                        data[pos + 5],
                        data[pos + 6],
                        data[pos + 7],
                    ]);
                    // We don't know the router's IP here directly, but
                    // the sender's IPv6 source was the router.  The caller
                    // should cache this.  We store the router MAC for later
                    // use by SLAAC.
                    stack.set_router_mac_v6(mac);
                }
            }
            NDP_OPT_PREFIX_INFO if opt_bytes >= 32 => {
                // Prefix Information option (RFC 4861 §4.6.2)
                let prefix_len = data[pos + 2];
                let prefix_flags = data[pos + 3];
                let valid_lifetime = u32::from_be_bytes([
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]);
                let preferred_lifetime = u32::from_be_bytes([
                    data[pos + 8],
                    data[pos + 9],
                    data[pos + 10],
                    data[pos + 11],
                ]);
                let mut prefix = [0u8; 16];
                prefix.copy_from_slice(&data[pos + 16..pos + 32]);

                // Mask to prefix_len bits.
                let prefix_bytes = (prefix_len / 8) as usize;
                let prefix_bits = prefix_len % 8;
                if prefix_bits > 0 && prefix_bytes < 16 {
                    prefix[prefix_bytes] &= !((1u8 << (8 - prefix_bits)) - 1);
                }
                for item in prefix
                    .iter_mut()
                    .skip(prefix_bytes.saturating_add(if prefix_bits > 0 { 1 } else { 0 }))
                {
                    *item = 0;
                }

                // L flag: on-link
                let _on_link = prefix_flags & 0x80 != 0;
                // A flag: autonomous address configuration (SLAAC)
                let autonomous = prefix_flags & 0x40 != 0;

                if autonomous && valid_lifetime > 0 && prefix_len == 64 {
                    // Form a global address: prefix + IID (interface identifier).
                    // IID is the lower 64 bits of our link-local address
                    // (which is EUI-64 derived from MAC).
                    let ll = stack.local_ip_v6();
                    let mut global_addr = [0u8; 16];
                    global_addr[..8].copy_from_slice(&prefix[..8]);
                    global_addr[8..].copy_from_slice(&ll[8..]);

                    // Store the global address configuration.
                    stack.set_global_ip_v6(global_addr, valid_lifetime, preferred_lifetime);
                }
            }
            NDP_OPT_MTU if opt_bytes >= 8 => {
                // MTU option (RFC 4861 §4.6.4): 32-bit MTU at bytes 4..8.
                // Hosts MUST ignore values below IPV6_MIN_MTU to avoid
                // pathological self-fragmentation (RFC 4861 §6.3.4).
                let mtu = u32::from_be_bytes([
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]);
                if mtu >= ipv6::IPV6_MIN_MTU as u32 {
                    stack.set_link_mtu_v6(mtu.min(u16::MAX as u32) as u16);
                }
            }
            _ => {
                // Unknown option — skip.
            }
        }
        pos += opt_bytes;
    }
}

// ─── Duplicate Address Detection (DAD) ──────────────────────────────────

/// Perform Duplicate Address Detection for `addr` by sending a Neighbor
/// Solicitation with the unspecified source address.
///
/// Returns `true` if the address is unique (no response within the DAD
/// timeout), `false` if a duplicate was detected.
///
/// This should be called after configuring a new IPv6 address (link-local
/// or global).
pub fn perform_dad(stack: &NetworkStack, addr: Ipv6Addr) -> bool {
    // Build DAD NS: target = addr, source = ::, no source LL addr option.
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&[0u8; 4]); // reserved
    body.extend_from_slice(&addr); // target

    let msg = build_icmpv6_message(
        [0u8; 16], // source = ::
        ipv6::solicited_node_multicast(addr),
        NDP_NEIGHBOR_SOLICITATION,
        0,
        &body,
    );

    let ip_header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: Ipv6NextHeader::Icmpv6,
        hop_limit: 255,
        source: [0u8; 16],
        destination: ipv6::solicited_node_multicast(addr),
    };

    let _ = send_ipv6_frame(stack, &ip_header, &msg);

    // Wait for a response — if any NA comes back for this address, it's a
    // duplicate.  We poll for a short period (DAD_TIMEOUT_TICKS).
    let start = stack.current_tick();
    const DAD_TIMEOUT_TICKS: u64 = 100; // 1 second

    loop {
        let _ = stack.poll();
        // Yield the CPU on host/test builds while waiting for DAD to complete.
        core::hint::spin_loop();
        if stack.current_tick().wrapping_sub(start) >= DAD_TIMEOUT_TICKS {
            return true; // no conflict detected
        }
        // Check the DAD conflict flag on the stack.
        if stack.dad_conflict_detected() {
            stack.clear_dad_conflict();
            return false;
        }
    }
}

// ─── Neighbor Cache ─────────────────────────────────────────────────────

/// States for a neighbor cache entry (RFC 4861 §7.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    /// Address resolution in progress.
    Incomplete,
    /// Resolution completed, confirmed reachable.
    Reachable,
    /// Reachable time expired, not yet confirmed stale.
    Stale,
    /// Actively probing (NS sent, waiting for NA).
    Probe,
}

struct NeighborEntry {
    mac: MacAddress,
    state: NeighborState,
    expires_at: u64,
}

pub struct NeighborCache {
    entries: BTreeMap<Ipv6Addr, NeighborEntry>,
}

impl Default for NeighborCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighborCache {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up the MAC for `ip`, returning `None` if not cached or expired.
    pub fn lookup(&mut self, ip: Ipv6Addr, current_tick: u64) -> Option<MacAddress> {
        let entry = self.entries.get(&ip)?;
        if entry.state == NeighborState::Incomplete {
            return None;
        }
        if current_tick >= entry.expires_at && entry.state != NeighborState::Probe {
            // Transition to Stale on expiry — copy the MAC first.
            let mac = entry.mac;
            if let Some(e) = self.entries.get_mut(&ip) {
                e.state = NeighborState::Stale;
            }
            return Some(mac);
        }
        Some(entry.mac)
    }

    /// Insert or update a cache entry.
    pub fn insert(&mut self, ip: Ipv6Addr, mac: MacAddress, current_tick: u64) {
        self.entries.insert(
            ip,
            NeighborEntry {
                mac,
                state: NeighborState::Stale,
                expires_at: current_tick + REACHABLE_TIME_TICKS,
            },
        );
    }

    /// Set an entry's state to Reachable.
    pub fn set_reachable(&mut self, ip: Ipv6Addr) {
        if let Some(entry) = self.entries.get_mut(&ip) {
            entry.state = NeighborState::Reachable;
        }
    }

    /// Set an entry as Incomplete (resolution in progress).
    pub fn set_incomplete(&mut self, ip: Ipv6Addr, current_tick: u64) {
        self.entries.insert(
            ip,
            NeighborEntry {
                mac: MacAddress([0; 6]),
                state: NeighborState::Incomplete,
                expires_at: current_tick + RETRANSMIT_TIMER_TICKS,
            },
        );
    }

    /// Returns `true` if the entry is in Incomplete state.
    pub fn is_incomplete(&self, ip: Ipv6Addr) -> bool {
        self.entries
            .get(&ip)
            .is_some_and(|e| e.state == NeighborState::Incomplete)
    }

    /// Evict stale entries past their lifetime.
    pub fn evict_expired(&mut self, current_tick: u64) {
        self.entries.retain(|_, entry| {
            entry.state != NeighborState::Stale || current_tick < entry.expires_at
        });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn state(&self, ip: Ipv6Addr) -> Option<NeighborState> {
        self.entries.get(&ip).map(|e| e.state)
    }
}

// ─── Neighbor Cache Timing ──────────────────────────────────────────────

/// Reachable time in ticks (30 seconds at 100 Hz).
const REACHABLE_TIME_TICKS: u64 = 3000;

/// Retransmit timer in ticks (1 second at 100 Hz).
pub const RETRANSMIT_TIMER_TICKS: u64 = 100;

/// Maximum Neighbor Solicitation retries.
const MAX_MULTICAST_SOLICIT: u32 = 3;

/// Neighbor Solicitation retransmit interval in ticks (1 second).
const RETRANS_TIMER_TICKS: u64 = 100;

// ─── NDP: MAC resolution (Neighbor Solicitation) ────────────────────────

/// Resolve an IPv6 address to a MAC address via NDP Neighbor Solicitation.
///
/// Analogous to `arp::resolve_mac` for IPv4.  Sends an NS to the
/// solicited-node multicast address and waits for an NA.
pub fn resolve_mac_v6(stack: &NetworkStack, target_ip: Ipv6Addr) -> Result<MacAddress> {
    let start_tick = stack.current_tick();

    // Check cache first.
    {
        let mut cache = stack.neighbor_cache_v6().lock();
        if let Some(mac) = cache.lookup(target_ip, start_tick) {
            return Ok(mac);
        }
        // Mark as Incomplete to avoid duplicate NS.
        if !cache.is_incomplete(target_ip) {
            cache.set_incomplete(target_ip, start_tick);
        }
    }

    // Send Neighbor Solicitation.
    send_neighbor_solicitation(stack, target_ip)?;

    // Wait for NA with tick-based timeout and retries.
    let mut retries = 0u32;
    let mut last_ns_tick = start_tick;

    loop {
        let _ = stack.poll();

        let tick = stack.current_tick();

        // Retransmit NS every RETRANS_TIMER_TICKS.
        if tick.wrapping_sub(last_ns_tick) >= RETRANS_TIMER_TICKS && retries < MAX_MULTICAST_SOLICIT
        {
            send_neighbor_solicitation(stack, target_ip)?;
            last_ns_tick = tick;
            retries += 1;
        }

        // Yield the CPU while waiting for the NA reply.
        core::hint::spin_loop();

        // Check cache for a completed entry.
        let mut cache = stack.neighbor_cache_v6().lock();
        if let Some(mac) = cache.lookup(target_ip, tick) {
            return Ok(mac);
        }
        drop(cache);

        if retries >= MAX_MULTICAST_SOLICIT
            && tick.wrapping_sub(last_ns_tick) >= RETRANS_TIMER_TICKS
        {
            return Err(Error::TimedOut);
        }
    }
}

/// Send a Neighbor Solicitation for `target` to its solicited-node multicast
/// address.
fn send_neighbor_solicitation(stack: &NetworkStack, target: Ipv6Addr) -> Result<()> {
    let sn_mcast = ipv6::solicited_node_multicast(target);
    let src = stack.local_ip_v6();

    let mut body = Vec::with_capacity(24 + 8);
    body.extend_from_slice(&[0u8; 4]); // reserved
    body.extend_from_slice(&target); // target address
    push_ll_addr_option(
        &mut body,
        NDP_OPT_SOURCE_LL_ADDR,
        &MacAddress(stack.local_mac),
    );

    let msg = build_icmpv6_message(src, sn_mcast, NDP_NEIGHBOR_SOLICITATION, 0, &body);

    let ip_header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: Ipv6NextHeader::Icmpv6,
        hop_limit: 255,
        source: src,
        destination: sn_mcast,
    };

    send_ipv6_frame(stack, &ip_header, &msg)
}

// ─── SLAAC: Address Configuration ──────────────────────────────────────

/// Send a Router Solicitation to the all-routers multicast address.
/// This triggers Router Advertisements for SLAAC.
pub fn send_router_solicitation(stack: &NetworkStack) -> Result<()> {
    let src = stack.local_ip_v6();
    let dst = ipv6::IPV6_ALL_ROUTERS_MULTICAST;

    let body = build_router_solicitation(&MacAddress(stack.local_mac));
    let msg = build_icmpv6_message(src, dst, NDP_ROUTER_SOLICITATION, 0, &body);

    let ip_header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: Ipv6NextHeader::Icmpv6,
        hop_limit: 255,
        source: src,
        destination: dst,
    };

    send_ipv6_frame(stack, &ip_header, &msg)
}

/// Run SLAAC: send Router Solicitations and wait for a Router Advertisement
/// that provides a global prefix.  After receiving an RA, perform DAD on
/// the newly formed global address.
///
/// Returns the global address on success, or `Err(Error::TimedOut)` if no
/// RA is received within the timeout.
#[cfg(target_os = "none")]
pub fn run_slaac(stack: &NetworkStack) -> Result<Ipv6Addr> {
    const SLAAC_TIMEOUT_TICKS: u64 = 300; // 3 seconds
    const SLAAC_MAX_RS: u32 = 3;

    let start = stack.current_tick();
    let mut rs_count = 0u32;
    let mut last_rs_tick = start.wrapping_sub(RETRANS_TIMER_TICKS);

    loop {
        let tick = stack.current_tick();

        if tick.wrapping_sub(start) >= SLAAC_TIMEOUT_TICKS {
            return Err(Error::TimedOut);
        }

        // Send RS periodically.
        if tick.wrapping_sub(last_rs_tick) >= RETRANS_TIMER_TICKS && rs_count < SLAAC_MAX_RS {
            let _ = send_router_solicitation(stack);
            last_rs_tick = tick;
            rs_count += 1;
        }

        // Poll to receive RA.
        let _ = stack.poll();
        // Yield the CPU on host/test builds while waiting for the RA.
        core::hint::spin_loop();

        // Check if a global address was configured.
        if let Some(global) = stack.global_ip_v6() {
            // Perform DAD on the new global address.
            if perform_dad(stack, global) {
                return Ok(global);
            }
            // DAD failed — clear the address and try again with a new RS.
            stack.clear_global_ip_v6();
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────

/// Extract a link-layer address option from an NDP message.
fn extract_ll_addr_option(data: &[u8], offset: usize, opt_type: u8) -> Option<MacAddress> {
    let mut pos = offset;
    while pos + 1 < data.len() {
        let otype = data[pos];
        let olen = data[pos + 1] as usize;
        if olen == 0 {
            break;
        }
        let opt_bytes = olen * 8;
        if pos + opt_bytes > data.len() {
            break;
        }
        if otype == opt_type && opt_bytes >= 8 {
            return Some(MacAddress([
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]));
        }
        pos += opt_bytes;
    }
    None
}

/// Append a link-layer address option to an NDP message.
fn push_ll_addr_option(buf: &mut Vec<u8>, opt_type: u8, mac: &MacAddress) {
    buf.push(opt_type);
    buf.push(1); // length = 1 unit of 8 bytes
    buf.extend_from_slice(&mac.0);
    buf.push(0); // padding to 8 bytes
    buf.push(0);
}

/// Send an IPv6 packet wrapped in an Ethernet frame.
/// Uses either unicast or multicast MAC depending on the destination.
pub fn send_ipv6_frame(
    stack: &NetworkStack,
    ip_header: &Ipv6Header,
    ip_payload: &[u8],
) -> Result<()> {
    let raw_ip = ipv6::build_packet(ip_header, ip_payload);

    // Determine Ethernet destination MAC.
    let dst_ip = ip_header.destination;
    let dst_mac = if dst_ip[0] == 0xff {
        // Multicast: use 33:33:xx:xx:xx:xx mapping.
        MacAddress(ipv6::multicast_mac_from_ipv6(dst_ip))
    } else if dst_ip == ipv6::IPV6_ALL_ROUTERS_MULTICAST || dst_ip == ipv6::IPV6_ALL_NODES_MULTICAST
    {
        MacAddress(ipv6::multicast_mac_from_ipv6(dst_ip))
    } else {
        // Unicast: resolve via neighbor cache (or NS/NA).
        // For unicast destinations, the caller should have resolved the MAC
        // via resolve_mac_v6() already.  If not, we attempt resolution here.
        match resolve_mac_v6(stack, dst_ip) {
            Ok(mac) => mac,
            Err(_) => {
                // Resolution failed — can't send.
                return Err(Error::NotFound);
            }
        }
    };

    let frame = ethernet::EthernetFrame::new(
        dst_mac,
        MacAddress(stack.local_mac),
        EtherType::Ipv6,
        raw_ip,
    );
    let raw_frame = ethernet::build_frame(&frame)?;
    stack.device().send(&raw_frame)
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use alloc::sync::Arc;

    #[allow(dead_code)]
    fn make_test_stack() -> &'static NetworkStack {
        unsafe {
            NetworkStack::uninstall_global();
        }
        let dev = Arc::new(MockNetworkDevice::new(
            "icmpv6-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(dev, [10, 0, 2, 15]);
        NetworkStack::global().expect("stack should be initialised")
    }

    // ── ICMPv6 header tests ──────────────────────────────────────────

    #[test]
    fn icmpv6_header_parse_round_trip() {
        let src: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let body = b"echo_payload";

        let msg = build_icmpv6_message(src, dst, ICMPV6_ECHO_REQUEST, 0, body);
        let header = parse_icmpv6_header(&msg).expect("should parse");
        assert_eq!(header.icmp_type, ICMPV6_ECHO_REQUEST);
        assert_eq!(header.code, 0);

        // Checksum should be valid (pseudo-header + message checksum = 0)
        let mut sum: u32 = 0;
        ipv6::pseudo_header_checksum_add(
            &mut sum,
            src,
            dst,
            Ipv6NextHeader::Icmpv6.to_u8(),
            msg.len() as u32,
        );
        ipv4::checksum_add(&mut sum, &msg);
        assert_eq!(ipv4::checksum_finalize(sum), 0);
    }

    #[test]
    fn icmpv6_echo_reply_is_correct_type() {
        let src: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let body = b"ping6_data";
        let echo_req = build_icmpv6_message(src, dst, ICMPV6_ECHO_REQUEST, 0, body);
        let request_header = parse_icmpv6_header(&echo_req).expect("parse");
        assert_eq!(request_header.icmp_type, ICMPV6_ECHO_REQUEST);

        // Build reply
        let reply = build_icmpv6_message(dst, src, ICMPV6_ECHO_REPLY, 0, body);
        let reply_header = parse_icmpv6_header(&reply).expect("parse");
        assert_eq!(reply_header.icmp_type, ICMPV6_ECHO_REPLY);
    }

    // ── Neighbor cache tests ──────────────────────────────────────────

    #[test]
    fn neighbor_cache_insert_and_lookup() {
        let mut cache = NeighborCache::new();
        let ip: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        cache.insert(ip, mac, 100);
        assert_eq!(cache.lookup(ip, 100), Some(mac));
    }

    #[test]
    fn neighbor_cache_expires() {
        let mut cache = NeighborCache::new();
        let ip: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mac = MacAddress([0xAA; 6]);

        cache.insert(ip, mac, 0);
        // At tick 0 it's in Stale state.
        let state = cache.state(ip);
        assert_eq!(state, Some(NeighborState::Stale));

        // After REACHABLE_TIME_TICKS it should still return the MAC but be Stale.
        let ttl = REACHABLE_TIME_TICKS + 1;
        assert_eq!(cache.lookup(ip, ttl), Some(mac));
        assert_eq!(cache.state(ip), Some(NeighborState::Stale));
    }

    #[test]
    fn neighbor_cache_incomplete_returns_none() {
        let mut cache = NeighborCache::new();
        let ip: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        cache.set_incomplete(ip, 0);
        assert_eq!(cache.lookup(ip, 0), None);
        assert!(cache.is_incomplete(ip));
    }

    #[test]
    fn neighbor_cache_evict_expired_stale_entries() {
        let mut cache = NeighborCache::new();
        let ip1: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ip2: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        cache.insert(ip1, MacAddress([0x11; 6]), 100); // expires at 100+3000 = 3100
        cache.insert(ip2, MacAddress([0x22; 6]), 100);
        assert_eq!(cache.len(), 2);

        // Evict at tick 2000 — both entries expired (2000 >= 3100? no, 2000 < 3100).
        // Wait, the insert adds 3000 to get expires_at, so they expire at 3100.
        // At tick 2000, neither is expired — both still in cache.
        cache.evict_expired(2000);
        assert_eq!(cache.len(), 2);

        // Evict at tick 5000 — both should be gone now (Stale past expiry).
        cache.evict_expired(5000);
        assert!(cache.is_empty());
    }

    // ── NDP message tests ─────────────────────────────────────────────

    #[test]
    fn build_neighbor_advertisement_sets_solicited_flag() {
        let src: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let target: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mac = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

        let na = build_neighbor_advertisement(src, target, target, true, false, &mac);
        // Complete ICMPv6 NA: header(4) + flags(1) + reserved(3) + target(16)
        // + option(8) = 32 bytes.
        assert!(na.len() >= 28);
        // ICMPv6 type 136 = Neighbor Advertisement.
        assert_eq!(na[0], NDP_NEIGHBOR_ADVERTISEMENT);
        // Flags byte is at offset 4 (after the 4-byte ICMPv6 header).
        // Solicited flag (bit 6) should be set.
        assert_eq!(na[4] & 0x40, 0x40);
        // Router flag (bit 7) should be clear.
        assert_eq!(na[4] & 0x80, 0x00);
    }

    #[test]
    fn neighbor_solicitation_includes_target_address() {
        let target: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let src: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let sn_mcast = ipv6::solicited_node_multicast(target);

        let mut body = Vec::new();
        body.extend_from_slice(&[0u8; 4]); // reserved
        body.extend_from_slice(&target);
        push_ll_addr_option(&mut body, NDP_OPT_SOURCE_LL_ADDR, &MacAddress([0x52; 6]));

        let msg = build_icmpv6_message(src, sn_mcast, NDP_NEIGHBOR_SOLICITATION, 0, &body);
        let hdr = parse_icmpv6_header(&msg).expect("parse");
        assert_eq!(hdr.icmp_type, NDP_NEIGHBOR_SOLICITATION);

        // Target should be at offset 8 (4 ICMPv6 + 4 reserved).
        let parsed_target: Ipv6Addr = msg[8..24].try_into().unwrap();
        assert_eq!(parsed_target, target);
    }

    // ── Link-local address generation test ────────────────────────────

    #[test]
    fn link_local_address_from_mac_is_fe80_prefix() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let ll = ipv6::link_local_from_mac(mac);
        assert_eq!(ll[0], 0xfe);
        assert_eq!(ll[1], 0x80);
    }
}
