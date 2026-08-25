//! src/kernel/network/filter/mod.rs
//!
//! Lightweight stateful packet filter / firewall for the native network stack.
//!
//! Provides rule-based filtering of IPv4 packets at the IP layer, with optional
//! connection tracking so that established flows are automatically allowed.
//!
//! ## Architecture
//!
//! A [`PacketFilter`] holds an ordered list of [`FilterRule`]s and a
//! connection-tracking flow table.  Two entry points are called from the
//! network stack:
//!
//! - `check_inbound(header, payload, local_ip, tick)` — called in `dispatch.rs`
//!   after fragment reassembly + NAT DNAT, before protocol demux.
//! - `check_outbound(header, payload, local_ip, tick)` — called in `send.rs`
//!   before NAT SNAT.
//!
//! Each method walks the rule list in order.  The first matching rule's action
//! is taken.  If no rule matches, the default action applies.  For stateful
//! rules, the flow is tracked so that return traffic auto-matches.
//!
//! The design follows the same patterns as the NAT module (`internet/nat.rs`).

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::filter::{
    FilterRuleDef, FILTER_ACTION_ALLOW, FILTER_ACTION_DENY, FILTER_PROTOCOL_ANY,
    FILTER_PROTOCOL_ICMP, FILTER_PROTOCOL_TCP, FILTER_PROTOCOL_UDP,
};
use crate::kernel::network::internet::ipv4::{IpProtocol, Ipv4Addr, Ipv4Header};

// ─── Constants ───────────────────────────────────────────────────────────

/// Maximum number of rules in the filter.
const MAX_FILTER_RULES: usize = 256;

/// Maximum number of connection-tracked flows.
const MAX_FILTER_FLOWS: usize = 4096;

/// Flow timeout for established TCP connections (24 hours in ticks =
/// 8,640,000).
const TCP_FLOW_TIMEOUT: u64 = 8_640_000;

/// Flow timeout for UDP flows (300 seconds in ticks = 30,000).
const UDP_FLOW_TIMEOUT: u64 = 30_000;

/// Flow timeout for generic flows (60 seconds in ticks = 6,000).
const DEFAULT_FLOW_TIMEOUT: u64 = 6_000;

/// Interval between expired-flow sweep checks (30 seconds in ticks).
const SWEEP_INTERVAL: u64 = 3_000;

// ─── Direction ───────────────────────────────────────────────────────────

/// Packet direction relative to this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDirection {
    /// Match both inbound and outbound.
    Both,
    /// Inbound: arriving from the network to this host.
    Inbound,
    /// Outbound: leaving this host to the network.
    Outbound,
}

impl FilterDirection {
    fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Inbound,
            2 => Self::Outbound,
            _ => Self::Both,
        }
    }
}

// ─── Action ──────────────────────────────────────────────────────────────

/// What to do when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    /// Allow the packet through.
    Allow,
    /// Drop the packet silently.
    Deny,
}

impl FilterAction {
    fn from_u32(v: u32) -> Self {
        match v {
            FILTER_ACTION_DENY => Self::Deny,
            _ => Self::Allow,
        }
    }
}

// ─── IP address / CIDR helpers ──────────────────────────────────────────

/// Check whether `addr` matches a CIDR prefix `(prefix_addr, prefix_len)`.
/// A prefix_len of 0 matches any address.
fn cidr_match(addr: [u8; 4], prefix_addr: [u8; 4], prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let shift = 32u8.saturating_sub(prefix_len);
    let addr_u32 = u32::from_be_bytes(addr);
    let prefix_u32 = u32::from_be_bytes(prefix_addr);
    (addr_u32 >> shift) == (prefix_u32 >> shift)
}

/// Check whether `port` falls within `[start, end]`.
/// If start == 0, it matches any port.
/// If end == 0, it matches only start (single port).
fn port_match(port: u16, start: u32, end: u32) -> bool {
    if start == 0 {
        return true;
    }
    let port_u32 = port as u32;
    let end_actual = if end == 0 { start } else { end };
    port_u32 >= start && port_u32 <= end_actual
}

// ─── Flow key for connection tracking ────────────────────────────────────

/// Key that identifies a bidirectional flow.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    /// Source IP (in the original direction).
    src_ip: [u8; 4],
    /// Destination IP (in the original direction).
    dst_ip: [u8; 4],
    /// Source port (0 for non-TCP/UDP protocols).
    src_port: u16,
    /// Destination port (0 for non-TCP/UDP protocols).
    dst_port: u16,
    /// IP protocol number.
    protocol: u8,
}

/// A tracked flow entry.
#[derive(Debug, Clone)]
struct FlowEntry {
    /// When this flow was last seen (tick).
    last_seen: u64,
    /// IP protocol number (6=TCP, 17=UDP, 0/other = generic).
    protocol: u8,
}

impl FlowEntry {
    /// Inactivity timeout, selected by protocol.  The filter doesn't inspect
    /// TCP connection state, so the timeout is the "last seen" bound after
    /// which the flow is considered dead.
    fn timeout_ticks(&self) -> u64 {
        match self.protocol {
            6 => TCP_FLOW_TIMEOUT,
            17 => UDP_FLOW_TIMEOUT,
            _ => DEFAULT_FLOW_TIMEOUT,
        }
    }

    fn is_expired(&self, current_tick: u64) -> bool {
        current_tick.wrapping_sub(self.last_seen) >= self.timeout_ticks()
    }
}

/// Build a canonical FlowKey from original-direction 5-tuple.
/// The key is ordered so that (src, dst) is always (lower, higher) for
/// the IP pair — this lets return traffic look up the same entry.
fn make_flow_key(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> FlowKey {
    // Normalise so that the flow is direction-agnostic.
    // Compare IP as u32, then port.
    let src_u32 = u32::from_be_bytes(src_ip);
    let dst_u32 = u32::from_be_bytes(dst_ip);
    if src_u32 < dst_u32 || (src_u32 == dst_u32 && src_port < dst_port) {
        FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    } else {
        FlowKey {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
            protocol,
        }
    }
}

// ─── FilterRule ──────────────────────────────────────────────────────────

/// A single packet filter rule.
#[derive(Debug)]
pub struct FilterRule {
    /// Unique rule identifier.
    pub id: u64,
    /// Action when matched.
    pub action: FilterAction,
    /// IP protocol to match (0 = any).
    pub protocol: u32,
    /// Source address prefix.
    pub src_addr: [u8; 4],
    /// Source CIDR prefix length.
    pub src_prefix: u8,
    /// Destination address prefix.
    pub dst_addr: [u8; 4],
    /// Destination CIDR prefix length.
    pub dst_prefix: u8,
    /// Source port range start.
    pub src_port_start: u32,
    /// Source port range end.
    pub src_port_end: u32,
    /// Destination port range start.
    pub dst_port_start: u32,
    /// Destination port range end.
    pub dst_port_end: u32,
    /// Direction to match.
    pub direction: FilterDirection,
    /// Whether to track this flow for stateful filtering.
    pub stateful: bool,
    /// Packets matched by this rule.
    pub packets_matched: AtomicU64,
    /// Bytes matched by this rule.
    pub bytes_matched: AtomicU64,
}

impl FilterRule {
    /// Check whether this rule matches the given packet and direction.
    fn rule_matches(
        &self,
        direction: FilterDirection,
        header: &Ipv4Header,
        payload: &[u8],
    ) -> bool {
        // Direction check.
        if self.direction != FilterDirection::Both && self.direction != direction {
            return false;
        }

        // Protocol check.
        if self.protocol != FILTER_PROTOCOL_ANY {
            let proto = header.protocol.to_u8() as u32;
            if proto != self.protocol {
                return false;
            }
        }

        // Source address check.
        if !cidr_match(header.source, self.src_addr, self.src_prefix) {
            return false;
        }

        // Destination address check.
        if !cidr_match(header.destination, self.dst_addr, self.dst_prefix) {
            return false;
        }

        // Port checks (only for TCP/UDP).
        if (self.protocol == FILTER_PROTOCOL_ANY
            || self.protocol == FILTER_PROTOCOL_TCP
            || self.protocol == FILTER_PROTOCOL_UDP)
            && (header.protocol == IpProtocol::Tcp || header.protocol == IpProtocol::Udp)
        {
            if let Some((src_port, dst_port)) = extract_ports(payload) {
                if !port_match(src_port, self.src_port_start, self.src_port_end) {
                    return false;
                }
                if !port_match(dst_port, self.dst_port_start, self.dst_port_end) {
                    return false;
                }
            }
        }

        true
    }

    /// Record a match, updating statistics.
    fn record_match(&self, byte_count: usize) {
        self.packets_matched.fetch_add(1, Ordering::Relaxed);
        self.bytes_matched
            .fetch_add(byte_count as u64, Ordering::Relaxed);
    }
}

// ─── PacketFilter ────────────────────────────────────────────────────────

/// The central packet filter holding rules, connection tracking, and
/// default policy.
pub struct PacketFilter {
    /// Ordered list of filter rules.
    rules: Vec<FilterRule>,
    /// Next rule ID to assign.
    next_rule_id: u64,
    /// Connection tracking flow table.
    flows: BTreeMap<FlowKey, FlowEntry>,
    /// Default action when no rule matches.
    default_action: FilterAction,
    /// Whether the filter is enabled.
    enabled: bool,
    /// Tick of the last flow sweep.
    last_sweep: u64,
    /// Total packets dropped since enable/creation.
    packets_dropped: AtomicU64,
    /// Total packets allowed since enable/creation.
    packets_allowed: AtomicU64,
}

impl Default for PacketFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketFilter {
    /// Create a new packet filter with default-allow policy and disabled state.
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            next_rule_id: 1,
            flows: BTreeMap::new(),
            default_action: FilterAction::Allow,
            enabled: false,
            last_sweep: 0,
            packets_dropped: AtomicU64::new(0),
            packets_allowed: AtomicU64::new(0),
        }
    }

    // ── Public API ────────────────────────────────────────────────────

    /// Enable the packet filter.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the packet filter (pass all traffic).
    pub fn disable(&mut self) {
        self.enabled = false;
        self.flows.clear();
    }

    /// Whether the filter is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Add a rule from an ABI `FilterRuleDef`, returning the assigned rule id.
    pub fn add_rule(&mut self, def: &FilterRuleDef) -> Result<u64, crate::Error> {
        if self.rules.len() >= MAX_FILTER_RULES {
            return Err(crate::Error::Busy);
        }
        if def.action != FILTER_ACTION_ALLOW && def.action != FILTER_ACTION_DENY {
            return Err(crate::Error::InvalidArgument);
        }
        if def.protocol != FILTER_PROTOCOL_ANY
            && def.protocol != FILTER_PROTOCOL_TCP
            && def.protocol != FILTER_PROTOCOL_UDP
            && def.protocol != FILTER_PROTOCOL_ICMP
        {
            // Unknown protocol is fine — just match by number.
        }
        if def.src_prefix > 32 || def.dst_prefix > 32 {
            return Err(crate::Error::InvalidArgument);
        }

        let id = self.next_rule_id;
        self.next_rule_id += 1;

        self.rules.push(FilterRule {
            id,
            action: FilterAction::from_u32(def.action),
            protocol: def.protocol,
            src_addr: def.src_addr,
            src_prefix: def.src_prefix as u8,
            dst_addr: def.dst_addr,
            dst_prefix: def.dst_prefix as u8,
            src_port_start: def.src_port_start,
            src_port_end: def.src_port_end,
            dst_port_start: def.dst_port_start,
            dst_port_end: def.dst_port_end,
            direction: FilterDirection::from_u32(def.flags & 0x03),
            stateful: def.stateful != 0,
            packets_matched: AtomicU64::new(0),
            bytes_matched: AtomicU64::new(0),
        });

        Ok(id)
    }

    /// Remove a rule by id.  Returns `true` if found and removed.
    pub fn remove_rule(&mut self, id: u64) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < len_before
    }

    /// Set the default action (Allow or Deny).
    pub fn set_default_action(&mut self, action: FilterAction) {
        self.default_action = action;
    }

    /// Get the default action.
    pub fn default_action(&self) -> FilterAction {
        self.default_action
    }

    /// Number of rules.
    pub fn num_rules(&self) -> u32 {
        self.rules.len() as u32
    }

    /// Number of active flows.
    pub fn num_flows(&self) -> u32 {
        self.flows.len() as u32
    }

    /// Total dropped packets.
    pub fn packets_dropped(&self) -> u64 {
        self.packets_dropped.load(Ordering::Relaxed)
    }

    /// Total allowed packets.
    pub fn packets_allowed(&self) -> u64 {
        self.packets_allowed.load(Ordering::Relaxed)
    }

    // ── Filter check (inbound) ────────────────────────────────────────

    /// Check an inbound packet (arriving from the network).
    ///
    /// Returns `true` if the packet should be allowed, `false` if dropped.
    /// Updates counters and connection tracking as appropriate.
    pub fn check_inbound(
        &mut self,
        header: &Ipv4Header,
        payload: &[u8],
        _local_ip: Ipv4Addr,
        tick: u64,
    ) -> bool {
        if !self.enabled {
            self.packets_allowed.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        self.check_packet(FilterDirection::Inbound, header, payload, tick)
    }

    /// Check an outbound packet (leaving this host).
    ///
    /// Returns `true` if the packet should be allowed, `false` if dropped.
    pub fn check_outbound(
        &mut self,
        header: &Ipv4Header,
        payload: &[u8],
        _local_ip: Ipv4Addr,
        tick: u64,
    ) -> bool {
        if !self.enabled {
            self.packets_allowed.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        self.check_packet(FilterDirection::Outbound, header, payload, tick)
    }

    // ── Core check logic ──────────────────────────────────────────────

    fn check_packet(
        &mut self,
        direction: FilterDirection,
        header: &Ipv4Header,
        payload: &[u8],
        tick: u64,
    ) -> bool {
        let byte_count = header.total_length as usize;

        // ── Connection tracking: allow established flows ──────────
        // For TCP/UDP, check if this packet belongs to a tracked flow.
        let protocol = header.protocol;
        if protocol == IpProtocol::Tcp || protocol == IpProtocol::Udp {
            let (src_port, dst_port) = match extract_ports(payload) {
                Some(ports) => ports,
                None => return self.apply_default_action(byte_count),
            };
            let key = make_flow_key(
                header.source,
                header.destination,
                src_port,
                dst_port,
                protocol.to_u8(),
            );
            if let Some(entry) = self.flows.get_mut(&key) {
                entry.last_seen = tick;
                self.packets_allowed.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        // ── Walk rules in order ───────────────────────────────────
        for rule in self.rules.iter() {
            if rule.rule_matches(direction, header, payload) {
                rule.record_match(byte_count);
                match rule.action {
                    FilterAction::Allow => {
                        // Track the flow for stateful rules.
                        if rule.stateful
                            && (protocol == IpProtocol::Tcp || protocol == IpProtocol::Udp)
                        {
                            let (src_port, dst_port) = match extract_ports(payload) {
                                Some(p) => p,
                                None => {
                                    self.packets_allowed.fetch_add(1, Ordering::Relaxed);
                                    return true;
                                }
                            };
                            let key = make_flow_key(
                                header.source,
                                header.destination,
                                src_port,
                                dst_port,
                                protocol.to_u8(),
                            );
                            if self.flows.len() < MAX_FILTER_FLOWS {
                                self.flows.entry(key).or_insert(FlowEntry {
                                    last_seen: tick,
                                    protocol: protocol.to_u8(),
                                });
                            }
                        }
                        self.packets_allowed.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                    FilterAction::Deny => {
                        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                }
            }
        }

        // ── No rule matched → apply default action ────────────────
        self.apply_default_action(byte_count)
    }

    /// Apply the default action.
    fn apply_default_action(&self, _byte_count: usize) -> bool {
        match self.default_action {
            FilterAction::Allow => {
                self.packets_allowed.fetch_add(1, Ordering::Relaxed);
                true
            }
            FilterAction::Deny => {
                self.packets_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    // ── Flow table maintenance ──────────────────────────────────────

    /// Sweep expired flow entries.  Should be called periodically from
    /// `advance_tick()`.
    pub fn sweep_expired(&mut self, current_tick: u64) {
        if !self.enabled {
            return;
        }
        // Only sweep every SWEEP_INTERVAL ticks.
        if current_tick.wrapping_sub(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = current_tick;

        self.flows
            .retain(|_, entry| !entry.is_expired(current_tick));
    }

    /// Clear all rules and flows.
    pub fn clear(&mut self) {
        self.rules.clear();
        self.flows.clear();
        self.packets_dropped.store(0, Ordering::Relaxed);
        self.packets_allowed.store(0, Ordering::Relaxed);
    }

    /// Iterate over rules (for testing / syscall inspection).
    pub fn rules(&self) -> &[FilterRule] {
        &self.rules
    }
}

// ─── Port extraction helper ──────────────────────────────────────────────

/// Extract TCP or UDP source and destination ports from a transport-layer
/// segment.  Returns `None` if the payload is too short.
fn extract_ports(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < 4 {
        return None;
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    Some((src_port, dst_port))
}

// Provide a zeroed FilterRuleDef for tests.
#[cfg(test)]
impl FilterRuleDef {
    fn zeroed() -> Self {
        Self {
            flags: 0,
            action: 0,
            protocol: 0,
            src_addr: [0; 4],
            src_prefix: 0,
            dst_addr: [0; 4],
            dst_prefix: 0,
            src_port_start: 0,
            src_port_end: 0,
            dst_port_start: 0,
            dst_port_end: 0,
            stateful: 0,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::filter::FILTER_ACTION_ALLOW;

    fn make_test_header(source: [u8; 4], dest: [u8; 4], protocol: IpProtocol) -> Ipv4Header {
        Ipv4Header {
            total_length: 40,
            identification: 0,
            flags_fragment_offset: 0,
            ttl: 64,
            protocol,
            header_checksum: 0,
            source,
            destination: dest,
        }
    }

    #[test]
    fn filter_disabled_allows_all() {
        let mut pf = PacketFilter::new();
        assert!(!pf.is_enabled());
        let hdr = make_test_header([10, 0, 2, 1], [10, 0, 2, 2], IpProtocol::Tcp);
        assert!(pf.check_inbound(&hdr, &[0u8; 4], [10, 0, 2, 15], 100));
    }

    #[test]
    fn filter_enabled_deny_all_default() {
        let mut pf = PacketFilter::new();
        pf.enable();
        pf.set_default_action(FilterAction::Deny);
        let hdr = make_test_header([10, 0, 2, 1], [10, 0, 2, 2], IpProtocol::Tcp);
        assert!(!pf.check_inbound(&hdr, &[0u8; 4], [10, 0, 2, 15], 100));
    }

    #[test]
    fn filter_allow_specific_src_ip() {
        let mut pf = PacketFilter::new();
        pf.enable();
        pf.set_default_action(FilterAction::Deny);

        let mut def = FilterRuleDef::zeroed();
        def.action = FILTER_ACTION_ALLOW;
        def.src_addr = [10, 0, 2, 50];
        def.src_prefix = 32;
        def.protocol = FILTER_PROTOCOL_ANY;
        pf.add_rule(&def).expect("add rule");

        // Matching source should be allowed.
        let hdr = make_test_header([10, 0, 2, 50], [10, 0, 2, 1], IpProtocol::Tcp);
        assert!(pf.check_inbound(&hdr, &[0u8; 4], [10, 0, 2, 15], 100));

        // Non-matching source should be denied.
        let hdr2 = make_test_header([10, 0, 2, 99], [10, 0, 2, 1], IpProtocol::Tcp);
        assert!(!pf.check_inbound(&hdr2, &[0u8; 4], [10, 0, 2, 15], 100));
    }

    #[test]
    fn filter_allow_specific_dst_port_tcp() {
        let mut pf = PacketFilter::new();
        pf.enable();
        pf.set_default_action(FilterAction::Deny);

        let mut def = FilterRuleDef::zeroed();
        def.action = FILTER_ACTION_ALLOW;
        def.protocol = FILTER_PROTOCOL_TCP;
        def.dst_port_start = 80;
        pf.add_rule(&def).expect("add rule");

        let hdr = make_test_header([10, 0, 2, 1], [10, 0, 2, 2], IpProtocol::Tcp);
        // Port 80 → allowed.
        let payload = [0x00, 0x35, 0x00, 0x50]; // src=53, dst=80
        assert!(pf.check_inbound(&hdr, &payload, [10, 0, 2, 15], 100));

        // Port 90 → denied.
        let payload2 = [0x00, 0x35, 0x00, 0x5a]; // src=53, dst=90
        assert!(!pf.check_inbound(&hdr, &payload2, [10, 0, 2, 15], 100));
    }

    #[test]
    fn filter_cidr_match_subnet() {
        let mut pf = PacketFilter::new();
        pf.enable();
        pf.set_default_action(FilterAction::Deny);

        let mut def = FilterRuleDef::zeroed();
        def.action = FILTER_ACTION_ALLOW;
        def.src_addr = [10, 0, 2, 0];
        def.src_prefix = 24; // 10.0.2.0/24
        pf.add_rule(&def).expect("add rule");

        let hdr = make_test_header([10, 0, 2, 100], [192, 168, 1, 1], IpProtocol::Tcp);
        assert!(pf.check_inbound(&hdr, &[0u8; 4], [10, 0, 2, 15], 100));

        let hdr2 = make_test_header([10, 0, 3, 100], [192, 168, 1, 1], IpProtocol::Tcp);
        assert!(!pf.check_inbound(&hdr2, &[0u8; 4], [10, 0, 2, 15], 100));
    }

    #[test]
    fn filter_stateful_tracks_flow() {
        let mut pf = PacketFilter::new();
        pf.enable();
        pf.set_default_action(FilterAction::Deny);

        // Allow outbound TCP to port 80, stateful.
        let mut def = FilterRuleDef::zeroed();
        def.action = FILTER_ACTION_ALLOW;
        def.protocol = FILTER_PROTOCOL_TCP;
        def.dst_port_start = 80;
        def.stateful = 1;
        def.flags = 2; // Outbound
        pf.add_rule(&def).expect("add rule");

        let payload = [0x04, 0x00, 0x00, 0x50]; // src=1024, dst=80

        // Outbound SYN → should match rule and create flow.
        let hdr_out = make_test_header([10, 0, 2, 15], [93, 184, 216, 34], IpProtocol::Tcp);
        assert!(pf.check_outbound(&hdr_out, &payload, [10, 0, 2, 15], 100));

        // Return traffic (inbound) → should be allowed by flow table.
        let hdr_in = make_test_header([93, 184, 216, 34], [10, 0, 2, 15], IpProtocol::Tcp);
        let reply_payload = [0x00, 0x50, 0x04, 0x00]; // src=80, dst=1024
        assert!(
            pf.check_inbound(&hdr_in, &reply_payload, [10, 0, 2, 15], 101),
            "stateful: return traffic should be allowed"
        );

        // Different flow → should be denied.
        let hdr_in2 = make_test_header([93, 184, 216, 35], [10, 0, 2, 15], IpProtocol::Tcp);
        let reply_payload2 = [0x00, 0x50, 0x04, 0x01]; // src=80, dst=1025
        assert!(
            !pf.check_inbound(&hdr_in2, &reply_payload2, [10, 0, 2, 15], 102),
            "different flow should be denied"
        );
    }

    #[test]
    fn filter_remove_rule() {
        let mut pf = PacketFilter::new();
        let def = FilterRuleDef::zeroed();
        let id = pf.add_rule(&def).expect("add rule");
        assert_eq!(pf.num_rules(), 1);
        assert!(pf.remove_rule(id));
        assert_eq!(pf.num_rules(), 0);
    }

    #[test]
    fn filter_add_rule_rejects_invalid_prefix() {
        let mut pf = PacketFilter::new();
        let mut def = FilterRuleDef::zeroed();
        def.src_prefix = 33;
        assert!(pf.add_rule(&def).is_err());
    }

    #[test]
    fn filter_sweep_expires_flows_by_protocol_timeout() {
        let mut pf = PacketFilter::new();
        pf.enable();
        let mut def = FilterRuleDef::zeroed();
        def.action = FILTER_ACTION_ALLOW;
        def.protocol = FILTER_PROTOCOL_ANY;
        def.stateful = 1;
        pf.add_rule(&def).expect("add rule");

        // TCP flow: timeout is TCP_FLOW_TIMEOUT (24 h).
        let tcp_payload = [0x04, 0x00, 0x00, 0x50];
        let tcp_hdr = make_test_header([10, 0, 2, 15], [10, 0, 2, 1], IpProtocol::Tcp);
        assert!(pf.check_outbound(&tcp_hdr, &tcp_payload, [10, 0, 2, 15], 100));

        // UDP flow: timeout is UDP_FLOW_TIMEOUT (300 s).
        let udp_payload = [0x04, 0x00, 0x00, 0x35];
        let udp_hdr = make_test_header([10, 0, 2, 15], [10, 0, 2, 1], IpProtocol::Udp);
        assert!(pf.check_outbound(&udp_hdr, &udp_payload, [10, 0, 2, 15], 100));
        assert_eq!(pf.num_flows(), 2);

        // Both flows survive past the generic (60 s) timeout.
        pf.sweep_expired(100 + DEFAULT_FLOW_TIMEOUT + 1);
        assert_eq!(pf.num_flows(), 2);

        // The UDP flow expires once its 300 s timeout elapses (the sweep
        // above set `last_sweep`, so allow the SWEEP_INTERVAL window).
        pf.sweep_expired(100 + UDP_FLOW_TIMEOUT + SWEEP_INTERVAL);
        assert_eq!(pf.num_flows(), 1);

        // The TCP flow survives far past the UDP timeout and only expires
        // once its 24 h timeout elapses.
        pf.sweep_expired(100 + TCP_FLOW_TIMEOUT + 1);
        assert_eq!(pf.num_flows(), 0);
    }

    #[test]
    fn cidr_match_helpers() {
        assert!(cidr_match([10, 0, 2, 50], [10, 0, 2, 0], 24));
        assert!(!cidr_match([10, 0, 3, 50], [10, 0, 2, 0], 24));
        assert!(cidr_match([192, 168, 1, 1], [192, 168, 0, 0], 16));
        assert!(cidr_match([10, 0, 0, 1], [0, 0, 0, 0], 0)); // prefix_len=0 →
                                                             // matches anything
    }

    #[test]
    fn cidr_match_zero_prefix() {
        assert!(cidr_match([10, 0, 0, 1], [0, 0, 0, 0], 0));
        assert!(cidr_match([255, 255, 255, 255], [0, 0, 0, 0], 0));
    }

    #[test]
    fn port_match_helpers() {
        assert!(port_match(80, 80, 0));
        assert!(port_match(80, 80, 80));
        assert!(port_match(85, 80, 90));
        assert!(!port_match(79, 80, 90));
        assert!(!port_match(91, 80, 90));
        assert!(port_match(53, 0, 0)); // start=0 → any
    }

    #[test]
    fn extract_ports_valid() {
        let payload = [0x04, 0x00, 0x00, 0x50]; // src=1024, dst=80
        assert_eq!(extract_ports(&payload), Some((1024, 80)));
    }

    #[test]
    fn extract_ports_short() {
        assert_eq!(extract_ports(&[0x00]), None);
        assert_eq!(extract_ports(&[]), None);
    }

    #[test]
    fn make_flow_key_is_symmetric() {
        let a = make_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 100, 200, 6);
        let b = make_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 200, 100, 6);
        assert_eq!(a, b, "flow keys should be direction-agnostic");
    }
}
