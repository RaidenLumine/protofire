//! src/abi/filter.rs
//!
//! Shared ABI types for the packet filter / firewall.
//!
//! These types are `#[repr(C)]` and must remain binary-stable across kernel
//! revisions.  Both the kernel and ring3 user-space programs use these
//! definitions to interpret syscall arguments for the filter subsystem.

/// Size of a serialised `FilterRuleDef` struct in bytes (12 × u32).
pub const FILTER_RULE_DEF_SIZE: usize = 48;

/// Size of a serialised `FilterStats` struct in bytes (4 × u32 + 2 × u64).
pub const FILTER_STATS_SIZE: usize = 32;

/// Action: allow the packet through.
pub const FILTER_ACTION_ALLOW: u32 = 0;
/// Action: drop the packet.
pub const FILTER_ACTION_DENY: u32 = 1;

/// Direction: match both inbound and outbound.
pub const FILTER_DIRECTION_BOTH: u32 = 0;
/// Direction: match inbound packets only.
pub const FILTER_DIRECTION_INBOUND: u32 = 1;
/// Direction: match outbound packets only.
pub const FILTER_DIRECTION_OUTBOUND: u32 = 2;

/// Protocol wildcard (match any IP protocol).
pub const FILTER_PROTOCOL_ANY: u32 = 0;
/// IP protocol number for TCP.
pub const FILTER_PROTOCOL_TCP: u32 = 6;
/// IP protocol number for UDP.
pub const FILTER_PROTOCOL_UDP: u32 = 17;
/// IP protocol number for ICMP.
pub const FILTER_PROTOCOL_ICMP: u32 = 1;

/// Default action flag: allow.
pub const FILTER_DEFAULT_ALLOW: u32 = 0;
/// Default action flag: deny.
pub const FILTER_DEFAULT_DENY: u32 = 1;

/// A single firewall rule definition (packed, fixed-size).
///
/// All fields are u32-aligned so the struct has no padding on any common
/// architecture.  Passed by pointer as the argument to the FilterAddRule
/// syscall (#122).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterRuleDef {
    /// Reserved flags (must be 0).
    pub flags: u32,
    /// Action when matched: FILTER_ACTION_ALLOW (0) or FILTER_ACTION_DENY (1).
    pub action: u32,
    /// IP protocol: FILTER_PROTOCOL_ANY (0), TCP (6), UDP (17), ICMP (1).
    pub protocol: u32,
    /// Source IPv4 address in network byte order.
    /// Use 0.0.0.0 ([0u8; 4]) to match any source.
    pub src_addr: [u8; 4],
    /// Source CIDR prefix length (0–32). 0 matches any source.
    pub src_prefix: u32,
    /// Destination IPv4 address in network byte order.
    /// Use 0.0.0.0 to match any destination.
    pub dst_addr: [u8; 4],
    /// Destination CIDR prefix length (0–32). 0 matches any destination.
    pub dst_prefix: u32,
    /// Source port range start (0 = any / match any).  Only meaningful for
    /// TCP and UDP rules.
    pub src_port_start: u32,
    /// Source port range end (0 = use src_port_start as a single-port match).
    pub src_port_end: u32,
    /// Destination port range start (0 = any).
    pub dst_port_start: u32,
    /// Destination port range end (0 = use dst_port_start as a single-port match).
    pub dst_port_end: u32,
    /// Enable stateful connection tracking for this rule (0 = stateless,
    /// 1 = track flow and auto-allow return traffic).
    pub stateful: u32,
}

/// Filter statistics returned by the FilterGetStats syscall (#125).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterStats {
    /// Whether the filter is enabled (1) or disabled (0).
    pub enabled: u32,
    /// Default action: FILTER_DEFAULT_ALLOW (0) or FILTER_DEFAULT_DENY (1).
    pub default_action: u32,
    /// Number of rules currently installed.
    pub num_rules: u32,
    /// Number of active connection-tracked flows.
    pub active_flows: u32,
    /// Total packets dropped since filter start.
    pub packets_dropped: u64,
    /// Total packets allowed since filter start.
    pub packets_allowed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_rule_def_size_is_stable() {
        assert_eq!(
            core::mem::size_of::<FilterRuleDef>(),
            FILTER_RULE_DEF_SIZE,
            "FilterRuleDef size changed — update FILTER_RULE_DEF_SIZE"
        );
    }

    #[test]
    fn filter_stats_size_is_stable() {
        assert_eq!(
            core::mem::size_of::<FilterStats>(),
            FILTER_STATS_SIZE,
            "FilterStats size changed — update FILTER_STATS_SIZE"
        );
    }

    #[test]
    fn filter_flag_constants_are_stable() {
        assert_eq!(FILTER_ACTION_ALLOW, 0);
        assert_eq!(FILTER_ACTION_DENY, 1);
        assert_eq!(FILTER_DIRECTION_BOTH, 0);
        assert_eq!(FILTER_DIRECTION_INBOUND, 1);
        assert_eq!(FILTER_DIRECTION_OUTBOUND, 2);
        assert_eq!(FILTER_PROTOCOL_ANY, 0);
        assert_eq!(FILTER_PROTOCOL_TCP, 6);
        assert_eq!(FILTER_PROTOCOL_UDP, 17);
        assert_eq!(FILTER_PROTOCOL_ICMP, 1);
        assert_eq!(FILTER_DEFAULT_ALLOW, 0);
        assert_eq!(FILTER_DEFAULT_DENY, 1);
    }
}
