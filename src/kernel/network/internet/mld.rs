//! src/kernel/network/internet/mld.rs
//!
//! MLDv1 (RFC 2710) — IPv6 multicast group management.
//!
//! MLDv1 uses ICMPv6 message types 130 (Query), 131 (Report), 132 (Done).
//! These messages are carried inside ICMPv6 with hop-limit 1 and link-local
//! source addresses.  MLD is the IPv6 equivalent of IGMPv2.

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

use super::icmpv6::build_icmpv6_message;
use super::icmpv6::parse_icmpv6_header;
use super::icmpv6::ICMPV6_HEADER_SIZE;
use super::ipv6::Ipv6Addr;
use super::ipv6::Ipv6Header;
use super::ipv6::Ipv6NextHeader;
use crate::kernel::network::stack::NetworkStack;
use crate::Result;

// ─── MLDv1 ICMPv6 type constants ────────────────────────────────────────

/// MLDv1 Multicast Listener Query (type 130).
pub const MLD_TYPE_QUERY: u8 = 130;
/// MLDv1 Multicast Listener Report (type 131).
pub const MLD_TYPE_REPORT: u8 = 131;
/// MLDv1 Multicast Listener Done (type 132).
pub const MLD_TYPE_DONE: u8 = 132;

// ─── MLDv1 message structure ────────────────────────────────────────────

/// MLDv1 message (beyond the 4-byte ICMPv6 header).
///
/// Wire format after ICMPv6 header:
///   max_resp_delay (2), reserved (2), multicast_address (16) = 20 bytes.
pub const MLD_MIN_BODY_SIZE: usize = 20;
pub const MLD_MIN_SIZE: usize = ICMPV6_HEADER_SIZE + MLD_MIN_BODY_SIZE;

/// All-routers multicast address (ff02::2) — used for Done messages.
const MLD_ALL_ROUTERS: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MldMessage {
    pub icmp_type: u8,
    pub code: u8,
    pub max_resp_delay: u16,
    pub multicast_address: Ipv6Addr,
}

/// Parse an MLD message from an ICMPv6 payload.
pub fn parse_mld_message(data: &[u8]) -> Result<MldMessage> {
    if data.len() < MLD_MIN_SIZE {
        return Err(crate::Error::InvalidArgument);
    }
    let hdr = parse_icmpv6_header(data)?;
    let max_resp_delay = u16::from_be_bytes([data[4], data[5]]);
    let mut multicast_address = [0u8; 16];
    multicast_address.copy_from_slice(&data[8..24]);
    Ok(MldMessage {
        icmp_type: hdr.icmp_type,
        code: hdr.code,
        max_resp_delay,
        multicast_address,
    })
}

/// Build an MLD message (ICMPv6 header + MLD body).
pub fn build_mld_message(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    icmp_type: u8,
    max_resp_delay: u16,
    multicast_address: Ipv6Addr,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(MLD_MIN_BODY_SIZE);
    body.extend_from_slice(&max_resp_delay.to_be_bytes());
    body.extend_from_slice(&[0u8; 2]); // reserved
    body.extend_from_slice(&multicast_address);
    build_icmpv6_message(src, dst, icmp_type, 0, &body)
}

// ─── Multicast group state ──────────────────────────────────────────────

#[derive(Debug, Clone)]
struct MldGroupState {
    joined: bool,
    report_timer_deadline: u64,
}

/// Host-side MLDv1 state for multicast group memberships.
pub struct MldState {
    groups: BTreeMap<Ipv6Addr, MldGroupState>,
}

impl Default for MldState {
    fn default() -> Self {
        Self::new()
    }
}

impl MldState {
    pub fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
        }
    }

    /// Join a multicast group — send an unsolicited Report.  Returns the
    /// (report_type, group) or `None` if already joined.
    pub fn join(&mut self, group: Ipv6Addr, _current_tick: u64) -> Option<(u8, Ipv6Addr)> {
        if self.groups.contains_key(&group) {
            return None;
        }
        self.groups.insert(
            group,
            MldGroupState {
                joined: true,
                report_timer_deadline: 0,
            },
        );
        Some((MLD_TYPE_REPORT, group))
    }

    /// Leave a multicast group — send a Done message.  Returns the group
    /// or `None`.
    pub fn leave(&mut self, group: Ipv6Addr) -> Option<Ipv6Addr> {
        if self.groups.remove(&group).is_some() {
            Some(group)
        } else {
            None
        }
    }

    /// Returns `true` if we are joined to `group`.
    #[allow(dead_code)]
    pub fn is_joined(&self, group: Ipv6Addr) -> bool {
        self.groups.get(&group).is_some_and(|s| s.joined)
    }
}

// ─── MLD processing ─────────────────────────────────────────────────────

/// Process an incoming MLD message (ICMPv6 types 130–132).
///
/// Returns a list of `(Ipv6Header, Vec<u8>)` replies to send.
pub fn process_mld_message(
    stack: &NetworkStack,
    src_ip: Ipv6Addr,
    _dst_ip: Ipv6Addr,
    icmp_data: &[u8],
    mld_state: &mut MldState,
) -> Vec<(Ipv6Header, Vec<u8>)> {
    let mut replies = Vec::new();

    let msg = match parse_mld_message(icmp_data) {
        Ok(m) => m,
        Err(_) => return replies,
    };

    let tick = stack.current_tick();

    match msg.icmp_type {
        MLD_TYPE_QUERY => {
            let is_general = msg.multicast_address == [0u8; 16];
            if is_general {
                let max_delay_ticks = ((msg.max_resp_delay as u64).max(1) * 10) / 1000;
                for state in mld_state.groups.values_mut() {
                    if state.joined && state.report_timer_deadline == 0 {
                        let spread = (state as *const _ as u64) % max_delay_ticks.max(1);
                        state.report_timer_deadline = tick.wrapping_add(spread);
                    }
                }
            } else if let Some(state) = mld_state.groups.get_mut(&msg.multicast_address) {
                if state.joined && state.report_timer_deadline == 0 {
                    let max_delay_ticks = ((msg.max_resp_delay as u64).max(1) * 10) / 1000;
                    let spread = (state as *const _ as u64) % max_delay_ticks.max(1);
                    state.report_timer_deadline = tick.wrapping_add(spread);
                }
            }
        }

        MLD_TYPE_REPORT => {
            // Report suppression: if another host has reported for a group
            // we're about to report for, cancel our pending report.
            if msg.multicast_address != [0u8; 16] {
                if let Some(state) = mld_state.groups.get_mut(&msg.multicast_address) {
                    state.report_timer_deadline = 0;
                }
            }
        }

        MLD_TYPE_DONE => {
            // Another host is leaving — a router would send a group-specific
            // query.  As a host, we don't need to act.
        }

        _ => {}
    }

    // Deliver expired report timers.
    for (group, state) in mld_state.groups.iter_mut() {
        if state.joined && state.report_timer_deadline != 0 {
            let elapsed = tick.wrapping_sub(state.report_timer_deadline);
            if elapsed <= (u64::MAX / 2) {
                state.report_timer_deadline = 0;
                let raw =
                    build_mld_message(stack.local_ip_v6(), *group, MLD_TYPE_REPORT, 0, *group);
                let ip_header = Ipv6Header {
                    traffic_class: 0,
                    flow_label: 0,
                    payload_length: 0,
                    next_header: Ipv6NextHeader::Icmpv6,
                    hop_limit: 1,
                    source: stack.local_ip_v6(),
                    destination: *group,
                };
                replies.push((ip_header, raw));
            }
        }
    }

    let _ = src_ip;
    replies
}

/// Called periodically from `advance_tick()` to send pending MLD reports.
pub fn mld_tick_maintenance(
    stack: &NetworkStack,
    mld_state: &mut MldState,
) -> Vec<(Ipv6Header, Vec<u8>)> {
    let mut replies = Vec::new();
    let tick = stack.current_tick();

    for (group, state) in mld_state.groups.iter_mut() {
        if state.joined && state.report_timer_deadline != 0 {
            let elapsed = tick.wrapping_sub(state.report_timer_deadline);
            if elapsed <= (u64::MAX / 2) {
                state.report_timer_deadline = 0;
                let raw =
                    build_mld_message(stack.local_ip_v6(), *group, MLD_TYPE_REPORT, 0, *group);
                let ip_header = Ipv6Header {
                    traffic_class: 0,
                    flow_label: 0,
                    payload_length: 0,
                    next_header: Ipv6NextHeader::Icmpv6,
                    hop_limit: 1,
                    source: stack.local_ip_v6(),
                    destination: *group,
                };
                replies.push((ip_header, raw));
            }
        }
    }

    replies
}

/// Build a Done message to leave a multicast group.
pub fn build_done_message(src: Ipv6Addr, group: Ipv6Addr) -> (Ipv6Header, Vec<u8>) {
    let raw = build_mld_message(src, MLD_ALL_ROUTERS, MLD_TYPE_DONE, 0, group);
    let ip_header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: Ipv6NextHeader::Icmpv6,
        hop_limit: 1,
        source: src,
        destination: MLD_ALL_ROUTERS,
    };
    (ip_header, raw)
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_build_round_trip() {
        let src: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let group: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42];
        let raw = build_mld_message(src, group, MLD_TYPE_REPORT, 0, group);
        let parsed = parse_mld_message(&raw).expect("should parse");
        assert_eq!(parsed.icmp_type, MLD_TYPE_REPORT);
        assert_eq!(parsed.multicast_address, group);
        assert_eq!(parsed.max_resp_delay, 0);
    }

    #[test]
    fn join_sends_report() {
        let group: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42];
        let mut state = MldState::new();
        let result = state.join(group, 0);
        assert!(result.is_some());
        let (ty, grp) = result.unwrap();
        assert_eq!(ty, MLD_TYPE_REPORT);
        assert_eq!(grp, group);
    }

    #[test]
    fn double_join_is_idempotent() {
        let group: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42];
        let mut state = MldState::new();
        assert!(state.join(group, 0).is_some());
        assert!(state.join(group, 0).is_none());
    }

    #[test]
    fn leave_after_join() {
        let group: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42];
        let mut state = MldState::new();
        state.join(group, 0);
        assert!(state.leave(group).is_some());
        assert!(!state.is_joined(group));
    }

    #[test]
    fn leave_without_join_returns_none() {
        let mut state = MldState::new();
        assert!(state
            .leave([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99])
            .is_none());
    }

    #[test]
    fn done_message_has_correct_destination() {
        let src: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let group: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42];
        let (header, _raw) = build_done_message(src, group);
        assert_eq!(header.destination, MLD_ALL_ROUTERS);
        assert_eq!(header.hop_limit, 1);
    }
}
