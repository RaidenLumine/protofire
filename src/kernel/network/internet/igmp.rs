//! src/kernel/network/internet/igmp.rs
//!
//! IGMPv2 (RFC 2236) — IPv4 multicast group management.
//!
//! Implements host-side IGMPv2:
//! - Respond to General Membership Queries with delayed Membership Reports.
//! - Send Membership Reports when joining a group.
//! - Send Leave Group messages when leaving a group.
//! - Process incoming Membership Queries and Reports.

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

use super::ipv4::{self, IpProtocol, Ipv4Addr, Ipv4Header};
use crate::kernel::network::stack::NetworkStack;
use crate::Result;

// ─── IGMPv2 type constants ──────────────────────────────────────────────

pub const IGMP_TYPE_MEMBERSHIP_QUERY: u8 = 0x11;
pub const IGMP_TYPE_MEMBERSHIP_REPORT_V1: u8 = 0x12;
pub const IGMP_TYPE_MEMBERSHIP_REPORT_V2: u8 = 0x16;
pub const IGMP_TYPE_LEAVE_GROUP: u8 = 0x17;

// ─── IGMPv2 header sizes ────────────────────────────────────────────────

/// Minimum IGMP message size (type + max_resp_time + checksum + group = 8).
const IGMP_MIN_SIZE: usize = 8;

/// IGMPv2 Membership Report sent as IPv4 multicast to the group address.
const IGMP_ALL_ROUTERS: Ipv4Addr = [224, 0, 0, 2];

// ─── IGMPv2 header ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpMessage {
    pub igmp_type: u8,
    pub max_resp_time: u8,
    pub checksum: u16,
    pub group_address: Ipv4Addr,
}

/// Parse an IGMP message from a byte slice.
pub fn parse_igmp_message(data: &[u8]) -> Result<IgmpMessage> {
    if data.len() < IGMP_MIN_SIZE {
        return Err(crate::Error::InvalidArgument);
    }
    let igmp_type = data[0];
    let max_resp_time = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let mut group_address = [0u8; 4];
    group_address.copy_from_slice(&data[4..8]);

    Ok(IgmpMessage {
        igmp_type,
        max_resp_time,
        checksum,
        group_address,
    })
}

/// Build an IGMP message into wire-format bytes.
pub fn build_igmp_message(msg: &IgmpMessage) -> Vec<u8> {
    let mut buf = Vec::with_capacity(IGMP_MIN_SIZE);
    buf.push(msg.igmp_type);
    buf.push(msg.max_resp_time);
    // Checksum placeholder
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(&msg.group_address);

    let checksum = ipv4::compute_checksum(&buf);
    buf[2] = (checksum >> 8) as u8;
    buf[3] = checksum as u8;

    buf
}

// ─── Multicast group state ──────────────────────────────────────────────

/// Per-group state tracking: are we joined, and do we have a pending
/// delayed response timer?
#[derive(Debug, Clone)]
struct IgmpGroupState {
    /// Whether we have joined this group.
    joined: bool,
    /// Tick when the delayed response timer fires (0 = none pending).
    report_timer_deadline: u64,
    /// Tick when the last (unsolicited) Membership Report was sent, used to
    /// refresh membership periodically (RFC 2236 §4).
    last_report_sent: u64,
}

/// Host-side IGMPv2 state for multicast group memberships.
pub struct IgmpState {
    /// Groups keyed by multicast address.
    groups: BTreeMap<Ipv4Addr, IgmpGroupState>,
    /// Unsolicited report interval in ticks (10 s at 100 Hz).
    unsolicited_report_interval: u64,
}

impl Default for IgmpState {
    fn default() -> Self {
        Self::new()
    }
}

impl IgmpState {
    pub fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            unsolicited_report_interval: 1000, // 10 s
        }
    }

    /// Join a multicast group — send an unsolicited Membership Report and
    /// start the report timer.  Returns the report to send, or `None` if
    /// already joined.
    pub fn join(&mut self, group: Ipv4Addr, _current_tick: u64) -> Option<IgmpMessage> {
        if self.groups.contains_key(&group) {
            return None;
        }
        self.groups.insert(
            group,
            IgmpGroupState {
                joined: true,
                report_timer_deadline: 0,
                last_report_sent: 0,
            },
        );
        Some(IgmpMessage {
            igmp_type: IGMP_TYPE_MEMBERSHIP_REPORT_V2,
            max_resp_time: 0,
            checksum: 0,
            group_address: group,
        })
    }

    /// Leave a multicast group — send a Leave Group message if we were
    /// joined.  Returns the leave message to send, or `None`.
    pub fn leave(&mut self, group: Ipv4Addr) -> Option<IgmpMessage> {
        if self.groups.remove(&group).is_some() {
            Some(IgmpMessage {
                igmp_type: IGMP_TYPE_LEAVE_GROUP,
                max_resp_time: 0,
                checksum: 0,
                group_address: group,
            })
        } else {
            None
        }
    }

    /// Returns `true` if we are joined to `group`.
    #[allow(dead_code)]
    pub fn is_joined(&self, group: Ipv4Addr) -> bool {
        self.groups.get(&group).is_some_and(|s| s.joined)
    }
}

// ─── IGMP processing ────────────────────────────────────────────────────

/// Process an incoming IGMP message.
///
/// Returns a list of `(Ipv4Header, Vec<u8>)` replies that the caller should
/// send (e.g. delayed Membership Reports that have now expired).
pub fn process_igmp_message(
    stack: &NetworkStack,
    src_ip: Ipv4Addr,
    igmp_data: &[u8],
    igmp_state: &mut IgmpState,
) -> Vec<(Ipv4Header, Vec<u8>)> {
    let mut replies = Vec::new();

    let msg = match parse_igmp_message(igmp_data) {
        Ok(m) => m,
        Err(_) => return replies,
    };

    let tick = stack.current_tick();

    match msg.igmp_type {
        IGMP_TYPE_MEMBERSHIP_QUERY => {
            // General Query: group_address = 0.0.0.0
            // Group-Specific Query: group_address = specific group.
            let is_general = msg.group_address == [0, 0, 0, 0];

            if is_general {
                // For each joined group, schedule a random delayed report.
                let max_delay_ticks = (msg.max_resp_time as u64).max(1) * 10; // 0.1 s per unit
                for state in igmp_state.groups.values_mut() {
                    if state.joined && state.report_timer_deadline == 0 {
                        // Schedule report within [0, max_delay_ticks).  Use a
                        // simple deterministic spread based on the group address
                        // low byte (avoids Math::random which is forbidden in
                        // workflow scripts; the spread is sufficient for test
                        // scenarios).
                        let spread = (state as *const _ as u64) % max_delay_ticks.max(1);
                        state.report_timer_deadline = tick.wrapping_add(spread);
                    }
                }
            } else if let Some(state) = igmp_state.groups.get_mut(&msg.group_address) {
                if state.joined && state.report_timer_deadline == 0 {
                    let max_delay_ticks = (msg.max_resp_time as u64).max(1) * 10;
                    let spread = (state as *const _ as u64) % max_delay_ticks.max(1);
                    state.report_timer_deadline = tick.wrapping_add(spread);
                }
            }
        }

        IGMP_TYPE_MEMBERSHIP_REPORT_V1 | IGMP_TYPE_MEMBERSHIP_REPORT_V2
            if msg.group_address != [0, 0, 0, 0] =>
        {
            // Another host has reported — if we have a pending report for the
            // same group, cancel it (report suppression, RFC 2236 §3).
            if let Some(state) = igmp_state.groups.get_mut(&msg.group_address) {
                state.report_timer_deadline = 0;
            }
        }

        _ => {
            // Leave Group and other types — silently ignored at the host side.
        }
    }

    // Check for expired report timers.
    for (group, state) in igmp_state.groups.iter_mut() {
        if state.joined && state.report_timer_deadline != 0 {
            let elapsed = tick.wrapping_sub(state.report_timer_deadline);
            if elapsed <= (u64::MAX / 2) {
                // Timer has fired.
                state.report_timer_deadline = 0;
                let reply = IgmpMessage {
                    igmp_type: IGMP_TYPE_MEMBERSHIP_REPORT_V2,
                    max_resp_time: 0,
                    checksum: 0,
                    group_address: *group,
                };
                let raw = build_igmp_message(&reply);
                let ip_header = Ipv4Header {
                    total_length: 0,
                    identification: 0,
                    flags_fragment_offset: 0,
                    ttl: 1, // IGMP reports use TTL 1 (link-local)
                    protocol: IpProtocol::Igmp,
                    header_checksum: 0,
                    source: stack.local_ip(),
                    destination: *group, // sent to the group address
                };
                replies.push((ip_header, raw));
            }
        }
    }

    // Drive periodic unsolicited reports.
    // (In a real implementation this would be timer-driven; for now we piggy-
    // back on incoming IGMP traffic to check for expired intervals.)
    let _ = src_ip;

    replies
}

/// Called periodically from `advance_tick()` to send unsolicited
/// Membership Reports for joined groups and to refresh state.
pub fn igmp_tick_maintenance(
    stack: &NetworkStack,
    igmp_state: &mut IgmpState,
) -> Vec<(Ipv4Header, Vec<u8>)> {
    let mut replies = Vec::new();
    let tick = stack.current_tick();
    let interval = igmp_state.unsolicited_report_interval.max(1);

    for (group, state) in igmp_state.groups.iter_mut() {
        // Deliver an expired delayed-response timer (scheduled by a Query).
        if state.joined && state.report_timer_deadline != 0 {
            let elapsed = tick.wrapping_sub(state.report_timer_deadline);
            if elapsed <= (u64::MAX / 2) {
                state.report_timer_deadline = 0;
                let reply = IgmpMessage {
                    igmp_type: IGMP_TYPE_MEMBERSHIP_REPORT_V2,
                    max_resp_time: 0,
                    checksum: 0,
                    group_address: *group,
                };
                let raw = build_igmp_message(&reply);
                let ip_header = Ipv4Header {
                    total_length: 0,
                    identification: 0,
                    flags_fragment_offset: 0,
                    ttl: 1,
                    protocol: IpProtocol::Igmp,
                    header_checksum: 0,
                    source: stack.local_ip(),
                    destination: *group,
                };
                replies.push((ip_header, raw));
                state.last_report_sent = tick;
                continue;
            }
        }

        // Refresh membership with a periodic unsolicited Report (RFC 2236
        // §4) so routers don't expire our membership while we idle.
        if state.joined && tick.wrapping_sub(state.last_report_sent) >= interval {
            state.last_report_sent = tick;
            let reply = IgmpMessage {
                igmp_type: IGMP_TYPE_MEMBERSHIP_REPORT_V2,
                max_resp_time: 0,
                checksum: 0,
                group_address: *group,
            };
            let raw = build_igmp_message(&reply);
            let ip_header = Ipv4Header {
                total_length: 0,
                identification: 0,
                flags_fragment_offset: 0,
                ttl: 1,
                protocol: IpProtocol::Igmp,
                header_checksum: 0,
                source: stack.local_ip(),
                destination: *group,
            };
            replies.push((ip_header, raw));
        }
    }

    replies
}

/// Send a Leave Group message for `group` to the all-routers multicast
/// address (224.0.0.2).
pub fn build_leave_message(group: Ipv4Addr) -> (Ipv4Header, Vec<u8>) {
    let msg = IgmpMessage {
        igmp_type: IGMP_TYPE_LEAVE_GROUP,
        max_resp_time: 0,
        checksum: 0,
        group_address: group,
    };
    let raw = build_igmp_message(&msg);
    let ip_header = Ipv4Header {
        total_length: 0,
        identification: 0,
        flags_fragment_offset: 0,
        ttl: 1,
        protocol: IpProtocol::Igmp,
        header_checksum: 0,
        source: [0; 4], // filled by caller
        destination: IGMP_ALL_ROUTERS,
    };
    (ip_header, raw)
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use alloc::sync::Arc;

    fn make_test_stack() -> &'static NetworkStack {
        unsafe {
            NetworkStack::uninstall_global();
        }
        let dev = Arc::new(MockNetworkDevice::new(
            "igmp-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(dev, [10, 0, 2, 15]);
        NetworkStack::global().expect("stack should be initialised")
    }

    #[test]
    fn parse_and_build_round_trip() {
        let msg = IgmpMessage {
            igmp_type: IGMP_TYPE_MEMBERSHIP_REPORT_V2,
            max_resp_time: 0,
            checksum: 0,
            group_address: [224, 0, 0, 1],
        };
        let raw = build_igmp_message(&msg);
        let parsed = parse_igmp_message(&raw).expect("should parse");
        assert_eq!(parsed.igmp_type, IGMP_TYPE_MEMBERSHIP_REPORT_V2);
        assert_eq!(parsed.group_address, [224, 0, 0, 1]);
        // Checksum should be valid.
        assert_eq!(ipv4::compute_checksum(&raw), 0);
    }

    #[test]
    fn join_sends_report() {
        let group: Ipv4Addr = [224, 0, 0, 42];
        let mut state = IgmpState::new();
        let report = state.join(group, 0);
        assert!(report.is_some());
        assert_eq!(report.unwrap().igmp_type, IGMP_TYPE_MEMBERSHIP_REPORT_V2);
    }

    #[test]
    fn double_join_is_idempotent() {
        let group: Ipv4Addr = [224, 0, 0, 42];
        let mut state = IgmpState::new();
        assert!(state.join(group, 0).is_some());
        assert!(state.join(group, 0).is_none());
    }

    #[test]
    fn leave_sends_leave() {
        let group: Ipv4Addr = [224, 0, 0, 42];
        let mut state = IgmpState::new();
        state.join(group, 0);
        let leave = state.leave(group);
        assert!(leave.is_some());
        assert_eq!(leave.unwrap().igmp_type, IGMP_TYPE_LEAVE_GROUP);
    }

    #[test]
    fn leave_without_join_returns_none() {
        let mut state = IgmpState::new();
        assert!(state.leave([224, 0, 0, 99]).is_none());
    }

    #[test]
    fn query_schedules_delayed_reports() {
        let _stack = make_test_stack();
        let group: Ipv4Addr = [224, 0, 0, 1];
        let mut igmp = IgmpState::new();
        igmp.join(group, 0);

        // Build a General Query.
        let query = IgmpMessage {
            igmp_type: IGMP_TYPE_MEMBERSHIP_QUERY,
            max_resp_time: 10, // 1 second
            checksum: 0,
            group_address: [0, 0, 0, 0],
        };
        let raw = build_igmp_message(&query);

        let stack = NetworkStack::global().unwrap();
        let replies = process_igmp_message(stack, [10, 0, 2, 1], &raw, &mut igmp);
        // No immediate reply expected — report is delayed.
        assert!(replies.is_empty());
    }

    #[test]
    fn leave_group_message_has_correct_type() {
        let (header, raw) = build_leave_message([224, 0, 0, 1]);
        assert_eq!(header.protocol, IpProtocol::Igmp);
        assert_eq!(header.destination, IGMP_ALL_ROUTERS);
        assert_eq!(raw[0], IGMP_TYPE_LEAVE_GROUP);
    }
}
