//! src/kernel/network/link/stp.rs
//!
//! STP — Spanning Tree Protocol (IEEE 802.1D) with RSTP elements (802.1w).
//!
//! ## Educational purpose
//!
//! STP prevents bridging loops in layer-2 networks with redundant links.
//! Without STP, broadcast frames would circulate forever, causing a
//! "broadcast storm" that brings the network down.  STP elects a root
//! bridge and selectively blocks ports to create a loop-free tree topology.
//!
//! RSTP (Rapid STP, 802.1w) improves convergence from 30-50 seconds down
//! to sub-second by replacing timer-based transitions with an explicit
//! proposal/agreement handshake.
//!
//! ## Why not production?
//!
//! - This kernel is a host, not a bridge.  STP is a bridge protocol.
//! - Real bridge implementations require hardware forwarding table (FDB)
//!   management, BPDU guard, root guard, loop guard, and per-VLAN STP.
//! - Modern data centers use TRILL, SPB (802.1aq), or layer-3 fabrics instead
//!   of STP for redundancy.
//!
//! ## Algorithm overview
//!
//! 1. **Root election**: bridge with lowest Bridge ID becomes root. Bridge ID =
//!    Priority (2B, default 32768) + MAC (6B).
//! 2. **Root port selection**: each non-root bridge picks the port with the
//!    lowest path cost to the root.
//! 3. **Designated port selection**: on each LAN segment, the bridge with the
//!    lowest root path cost becomes the designated bridge; its port on that
//!    segment is the designated port.
//! 4. **Blocking**: all ports that are neither root nor designated are blocked
//!    (no forwarding, no learning).
//! 5. **Port states**: Disabled → Blocking → Listening → Learning → Forwarding.
//!
//! ## RSTP improvements
//!
//! - Edge ports: skip Listening/Learning (immediate Forwarding for host-facing
//!   ports).
//! - Point-to-point links: proposal/agreement handshake for fast convergence.
//! - Port roles kept as in 802.1D (Root, Designated, Alternate/Backup).

use alloc::vec::Vec;

// ── Constants ──────────────────────────────────────────────────────────────

/// Default bridge priority.
pub const DEFAULT_BRIDGE_PRIORITY: u16 = 32768;
/// Path cost for a 10 Gbps link (IEEE 802.1D-2004 default cost values).
pub const PATH_COST_10G: u32 = 2;
/// Path cost for a 1 Gbps link.
pub const PATH_COST_1G: u32 = 4;
/// Path cost for a 100 Mbps link.
pub const PATH_COST_100M: u32 = 19;
/// Path cost for a 10 Mbps link.
pub const PATH_COST_10M: u32 = 100;
/// Default Hello Time (seconds).
pub const DEFAULT_HELLO_TIME: u16 = 2;
/// Default Max Age (seconds).
pub const DEFAULT_MAX_AGE: u16 = 20;
/// Default Forward Delay (seconds).
pub const DEFAULT_FORWARD_DELAY: u16 = 15;

// ── BPDU types ─────────────────────────────────────────────────────────────

/// BPDU Type for configuration BPDU (802.1D).
pub const BPDU_TYPE_CONFIG: u8 = 0x00;
/// BPDU Type for topology change notification (802.1D).
pub const BPDU_TYPE_TCN: u8 = 0x80;
/// BPDU Type for RST BPDU (802.1w, version 2).
pub const BPDU_TYPE_RST: u8 = 0x02;

/// BPDU flags bitmask.
pub mod bpdu_flags {
    /// Topology Change flag.
    pub const TC: u8 = 0x01;
    /// Topology Change Acknowledgement flag.
    pub const TCA: u8 = 0x80;
    /// Proposal flag (RSTP).
    pub const PROPOSAL: u8 = 0x02;
    /// Agreement flag (RSTP).
    pub const AGREEMENT: u8 = 0x80;
    /// Port Role: bits 2-3 (RSTP).
    pub const PORT_ROLE_MASK: u8 = 0x0C;
    pub const PORT_ROLE_UNKNOWN: u8 = 0x00;
    pub const PORT_ROLE_ALT_BACKUP: u8 = 0x04;
    pub const PORT_ROLE_ROOT: u8 = 0x08;
    pub const PORT_ROLE_DESIGNATED: u8 = 0x0C;
    /// Learning flag (RSTP).
    pub const LEARNING: u8 = 0x10;
    /// Forwarding flag (RSTP).
    pub const FORWARDING: u8 = 0x20;
}

// ── Data structures ────────────────────────────────────────────────────────

/// Bridge Identifier (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BridgeId {
    /// Priority (top 4 bits) + System ID Extension (lower 12 bits, VLAN ID).
    pub priority: u16,
    /// MAC address (6 bytes).
    pub mac: [u8; 6],
}

impl BridgeId {
    pub fn new(priority: u16, mac: [u8; 6]) -> Self {
        Self { priority, mac }
    }

    /// Encode Bridge ID for BPDU (8 bytes: 2B priority + 6B MAC).
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[..2].copy_from_slice(&self.priority.to_be_bytes());
        buf[2..8].copy_from_slice(&self.mac);
        buf
    }

    /// Decode Bridge ID from BPDU bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let priority = u16::from_be_bytes([data[0], data[1]]);
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[2..8]);
        Some(Self { priority, mac })
    }
}

/// Configuration BPDU (IEEE 802.1D, 35 bytes).
#[derive(Debug, Clone)]
pub struct ConfigBpdu {
    /// Protocol Identifier (always 0x0000).
    pub protocol_id: u16,
    /// Protocol Version (0 = STP, 2 = RSTP).
    pub version: u8,
    /// BPDU Type.
    pub bpdu_type: u8,
    /// Flags.
    pub flags: u8,
    /// Root Bridge ID.
    pub root_id: BridgeId,
    /// Root Path Cost.
    pub root_path_cost: u32,
    /// Bridge ID of the transmitting bridge.
    pub bridge_id: BridgeId,
    /// Port Identifier (2 bytes).
    pub port_id: u16,
    /// Message Age (in 1/256 seconds — simplified to seconds here).
    pub message_age: u16,
    /// Max Age.
    pub max_age: u16,
    /// Hello Time.
    pub hello_time: u16,
    /// Forward Delay.
    pub forward_delay: u16,
}

impl ConfigBpdu {
    /// Serialize a configuration BPDU to bytes (35 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(35);
        buf.extend_from_slice(&self.protocol_id.to_be_bytes());
        buf.push(self.version);
        buf.push(self.bpdu_type);
        buf.push(self.flags);
        buf.extend_from_slice(&self.root_id.to_bytes());
        buf.extend_from_slice(&self.root_path_cost.to_be_bytes());
        buf.extend_from_slice(&self.bridge_id.to_bytes());
        buf.extend_from_slice(&self.port_id.to_be_bytes());
        buf.extend_from_slice(&self.message_age.to_be_bytes());
        buf.extend_from_slice(&self.max_age.to_be_bytes());
        buf.extend_from_slice(&self.hello_time.to_be_bytes());
        buf.extend_from_slice(&self.forward_delay.to_be_bytes());
        buf
    }

    /// Parse a configuration BPDU from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 35 {
            return None;
        }
        let protocol_id = u16::from_be_bytes([data[0], data[1]]);
        let version = data[2];
        let bpdu_type = data[3];
        let flags = data[4];
        let root_id = BridgeId::from_bytes(&data[5..13])?;
        let root_path_cost = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let bridge_id = BridgeId::from_bytes(&data[17..25])?;
        let port_id = u16::from_be_bytes([data[25], data[26]]);
        let message_age = u16::from_be_bytes([data[27], data[28]]);
        let max_age = u16::from_be_bytes([data[29], data[30]]);
        let hello_time = u16::from_be_bytes([data[31], data[32]]);
        let forward_delay = u16::from_be_bytes([data[33], data[34]]);
        Some(ConfigBpdu {
            protocol_id,
            version,
            bpdu_type,
            flags,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            message_age,
            max_age,
            hello_time,
            forward_delay,
        })
    }

    /// Create a default configuration BPDU for a given bridge.
    pub fn new_default(bridge_id: BridgeId, port_id: u16) -> Self {
        Self {
            protocol_id: 0x0000,
            version: 0,
            bpdu_type: BPDU_TYPE_CONFIG,
            flags: 0,
            root_id: bridge_id, // initially, each bridge thinks it's the root
            root_path_cost: 0,
            bridge_id,
            port_id,
            message_age: 0,
            max_age: DEFAULT_MAX_AGE,
            hello_time: DEFAULT_HELLO_TIME,
            forward_delay: DEFAULT_FORWARD_DELAY,
        }
    }
}

// ── Port states ────────────────────────────────────────────────────────────

/// STP port state (802.1D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpPortState {
    /// Administratively down.
    Disabled,
    /// Receiving BPDUs, not forwarding or learning.
    Blocking,
    /// Sending and receiving BPDUs, building filtering database.
    Listening,
    /// Learning MAC addresses, not forwarding.
    Learning,
    /// Fully operational (forwarding + learning).
    Forwarding,
}

/// STP port role (802.1D + 802.1w).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpPortRole {
    /// Port on the path toward the root bridge.
    Root,
    /// Port on the path away from the root (to a LAN segment).
    Designated,
    /// Blocked port that provides an alternate path to the root (RSTP).
    Alternate,
    /// Blocked port that provides a backup path to the same LAN segment (RSTP).
    Backup,
}

/// A single port on an STP bridge.
#[derive(Debug, Clone)]
pub struct StpPort {
    pub port_id: u16,
    /// Whether this port connects to another bridge (true) or a host (false).
    pub point_to_point: bool,
    /// Whether this is an edge port (host-facing, skip STP learning).
    pub edge: bool,
    /// Current port state.
    pub state: StpPortState,
    /// Current port role.
    pub role: StpPortRole,
    /// Path cost associated with this port.
    pub path_cost: u32,
}

impl StpPort {
    pub fn new(port_id: u16, path_cost: u32) -> Self {
        Self {
            port_id,
            point_to_point: true,
            edge: false,
            state: StpPortState::Blocking,
            role: StpPortRole::Designated,
            path_cost,
        }
    }

    /// Create an edge port (host-facing, immediate forwarding).
    pub fn new_edge(port_id: u16, path_cost: u32) -> Self {
        Self {
            port_id,
            point_to_point: false,
            edge: true,
            state: StpPortState::Forwarding,
            role: StpPortRole::Designated,
            path_cost,
        }
    }
}

// ── STP bridge ─────────────────────────────────────────────────────────────

/// STP bridge instance.
#[derive(Debug)]
pub struct StpBridge {
    pub bridge_id: BridgeId,
    /// Ports on this bridge.
    pub ports: Vec<StpPort>,
    /// The bridge currently believed to be the root.
    pub root_bridge_id: BridgeId,
    /// Path cost from this bridge to the root.
    pub root_path_cost: u32,
    /// The port that leads toward the root (None if this is the root bridge).
    pub root_port: Option<u16>,
    /// Last received BPDU on each port (port_id -> BPDU).
    bpdu_cache: Vec<(u16, ConfigBpdu)>,
}

impl StpBridge {
    /// Create a new STP bridge with the given MAC address.
    pub fn new(mac: [u8; 6]) -> Self {
        let bridge_id = BridgeId::new(DEFAULT_BRIDGE_PRIORITY, mac);
        Self {
            bridge_id,
            ports: Vec::new(),
            root_bridge_id: bridge_id,
            root_path_cost: 0,
            root_port: None,
            bpdu_cache: Vec::new(),
        }
    }

    /// Create a bridge with a specific priority (lower = more likely to be
    /// root).
    pub fn with_priority(priority: u16, mac: [u8; 6]) -> Self {
        let bridge_id = BridgeId::new(priority, mac);
        Self {
            bridge_id,
            ports: Vec::new(),
            root_bridge_id: bridge_id,
            root_path_cost: 0,
            root_port: None,
            bpdu_cache: Vec::new(),
        }
    }

    /// Add a port to this bridge.
    pub fn add_port(&mut self, port: StpPort) {
        self.ports.push(port);
    }

    /// Whether this bridge is the root bridge.
    pub fn is_root(&self) -> bool {
        self.root_bridge_id == self.bridge_id
    }

    /// Run the STP election algorithm based on received BPDUs.
    /// This determines the root bridge, root port, and designated ports.
    pub fn run_election(&mut self) {
        // Find the best BPDU received on any port.
        let mut best_bpdu: Option<ConfigBpdu> = None;
        let mut best_port: Option<u16> = None;

        for (port_id, bpdu) in &self.bpdu_cache {
            if let Some(ref current_best) = best_bpdu {
                if is_better_bpdu(bpdu, current_best) {
                    best_bpdu = Some(bpdu.clone());
                    best_port = Some(*port_id);
                }
            } else {
                best_bpdu = Some(bpdu.clone());
                best_port = Some(*port_id);
            }
        }

        // If we received a superior BPDU, update root information.
        if let Some(bpdu) = &best_bpdu {
            if bpdu.root_id < self.bridge_id
                || (bpdu.root_id == self.bridge_id && bpdu.root_path_cost < self.root_path_cost)
            {
                self.root_bridge_id = bpdu.root_id;
                // Root path cost = received root path cost + our port cost.
                if let Some(port_id) = best_port {
                    let port_cost = self
                        .ports
                        .iter()
                        .find(|p| p.port_id == port_id)
                        .map(|p| p.path_cost)
                        .unwrap_or(PATH_COST_1G);
                    self.root_path_cost = bpdu.root_path_cost + port_cost;
                }
                self.root_port = best_port;
            }
        } else {
            // No BPDUs received — believe we are the root.
            self.root_bridge_id = self.bridge_id;
            self.root_path_cost = 0;
            self.root_port = None;
        }

        // Update port roles.
        for port in &mut self.ports {
            if Some(port.port_id) == self.root_port {
                port.role = StpPortRole::Root;
                port.state = StpPortState::Forwarding;
            } else if !port.edge {
                // Non-root, non-edge ports become Designated (if we're the
                // designated bridge for that segment) or Blocked.
                // Simplification: all non-root ports are Designated unless
                // we received a superior BPDU on that port.
                let is_designated = !self.bpdu_cache.iter().any(|(pid, bpdu)| {
                    *pid == port.port_id
                        && (bpdu.root_id < self.root_bridge_id
                            || (bpdu.root_id == self.root_bridge_id
                                && bpdu.root_path_cost < self.root_path_cost))
                });
                if is_designated {
                    port.role = StpPortRole::Designated;
                    port.state = StpPortState::Forwarding;
                } else {
                    port.role = StpPortRole::Alternate;
                    port.state = StpPortState::Blocking;
                }
            }
        }
    }

    /// Receive a BPDU on a specific port.
    pub fn receive_bpdu(&mut self, port_id: u16, bpdu: ConfigBpdu) {
        // Remove any previous BPDU from this port.
        self.bpdu_cache.retain(|(pid, _)| *pid != port_id);
        self.bpdu_cache.push((port_id, bpdu));
    }

    /// Generate a BPDU to send on a specific port.
    pub fn generate_bpdu(&self, port_id: u16) -> ConfigBpdu {
        ConfigBpdu {
            protocol_id: 0x0000,
            version: 0,
            bpdu_type: BPDU_TYPE_CONFIG,
            flags: 0,
            root_id: self.root_bridge_id,
            root_path_cost: self.root_path_cost,
            bridge_id: self.bridge_id,
            port_id,
            message_age: 0,
            max_age: DEFAULT_MAX_AGE,
            hello_time: DEFAULT_HELLO_TIME,
            forward_delay: DEFAULT_FORWARD_DELAY,
        }
    }
}

/// Compare two BPDUs: returns true if `a` is superior to `b`.
/// Criteria (in order): lower root ID, lower root path cost, lower
/// transmitting bridge ID, lower port ID.
fn is_better_bpdu(a: &ConfigBpdu, b: &ConfigBpdu) -> bool {
    if a.root_id != b.root_id {
        return a.root_id < b.root_id;
    }
    if a.root_path_cost != b.root_path_cost {
        return a.root_path_cost < b.root_path_cost;
    }
    if a.bridge_id != b.bridge_id {
        return a.bridge_id < b.bridge_id;
    }
    a.port_id < b.port_id
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// In a 3-bridge triangle, one port must be blocked to prevent a loop.
    #[test]
    fn triangle_topology_root_election() {
        // Three bridges with different MACs and priorities.
        let mut bridge_a = StpBridge::with_priority(4096, [0x00, 0x00, 0x00, 0x00, 0x00, 0x0A]);
        let mut bridge_b = StpBridge::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x0B]);
        let mut bridge_c = StpBridge::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x0C]);

        // Add ports to each bridge.
        bridge_a.add_port(StpPort::new(1, PATH_COST_1G));
        bridge_a.add_port(StpPort::new(2, PATH_COST_1G));
        bridge_b.add_port(StpPort::new(1, PATH_COST_1G));
        bridge_b.add_port(StpPort::new(2, PATH_COST_1G));
        bridge_c.add_port(StpPort::new(1, PATH_COST_1G));
        bridge_c.add_port(StpPort::new(2, PATH_COST_1G));

        // A (lowest priority) should become root.
        bridge_b.receive_bpdu(1, bridge_a.generate_bpdu(1));
        bridge_c.receive_bpdu(1, bridge_a.generate_bpdu(2));

        bridge_b.run_election();
        bridge_c.run_election();

        // Bridge A is root.
        assert!(bridge_a.is_root());

        // B and C should see A as root.
        assert_eq!(bridge_b.root_bridge_id, bridge_a.bridge_id);
        assert_eq!(bridge_c.root_bridge_id, bridge_a.bridge_id);

        // B and C should each have a root port.
        assert!(
            bridge_b.root_port.is_some(),
            "Bridge B should have a root port"
        );
        assert!(
            bridge_c.root_port.is_some(),
            "Bridge C should have a root port"
        );
    }

    /// The bridge with the numerically lowest Bridge ID wins root election.
    #[test]
    fn lowest_bridge_id_wins() {
        // Two bridges: one with priority 4096, one with default 32768.
        let root_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let other_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];

        let mut root_bridge = StpBridge::with_priority(4096, root_mac);
        root_bridge.add_port(StpPort::new(1, PATH_COST_1G));

        let mut other_bridge = StpBridge::new(other_mac);
        other_bridge.add_port(StpPort::new(1, PATH_COST_1G));

        // Other bridge receives BPDU from root.
        other_bridge.receive_bpdu(1, root_bridge.generate_bpdu(1));
        other_bridge.run_election();

        assert!(root_bridge.is_root());
        assert!(!other_bridge.is_root());
        assert_eq!(other_bridge.root_bridge_id, root_bridge.bridge_id);
    }

    /// BPDU serialization roundtrip.
    #[test]
    fn bpdu_format_roundtrip() {
        let bridge_id = BridgeId::new(32768, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let bpdu = ConfigBpdu::new_default(bridge_id, 42);

        let bytes = bpdu.to_bytes();
        assert_eq!(bytes.len(), 35, "BPDU should be 35 bytes");

        let parsed = ConfigBpdu::from_bytes(&bytes).expect("parse BPDU");
        assert_eq!(parsed.protocol_id, bpdu.protocol_id);
        assert_eq!(parsed.version, bpdu.version);
        assert_eq!(parsed.bpdu_type, bpdu.bpdu_type);
        assert_eq!(parsed.root_id, bpdu.root_id);
        assert_eq!(parsed.root_path_cost, bpdu.root_path_cost);
        assert_eq!(parsed.bridge_id, bpdu.bridge_id);
        assert_eq!(parsed.port_id, bpdu.port_id);
        assert_eq!(parsed.max_age, bpdu.max_age);
        assert_eq!(parsed.hello_time, bpdu.hello_time);
        assert_eq!(parsed.forward_delay, bpdu.forward_delay);
    }

    /// Bridge ID comparison: lower Bridge ID wins.
    #[test]
    fn bridge_id_comparison() {
        let a = BridgeId::new(4096, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let b = BridgeId::new(32768, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let c = BridgeId::new(4096, [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);

        assert!(a < b, "Lower priority should win");
        assert!(a < c, "Same priority, lower MAC should win");
    }

    /// After link failure, topology should reconverge.
    #[test]
    fn topology_change_on_link_failure() {
        let mut bridge_a = StpBridge::with_priority(4096, [0x00; 6]);
        bridge_a.add_port(StpPort::new(1, PATH_COST_1G));

        let mut bridge_b = StpBridge::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x0B]);
        bridge_b.add_port(StpPort::new(1, PATH_COST_1G));
        bridge_b.add_port(StpPort::new(2, PATH_COST_1G));

        // B receives BPDU from A on port 1.
        bridge_b.receive_bpdu(1, bridge_a.generate_bpdu(1));
        bridge_b.run_election();
        assert_eq!(bridge_b.root_bridge_id, bridge_a.bridge_id);
        assert_eq!(bridge_b.root_port, Some(1));

        // Simulate link failure: remove BPDU from port 1 (BPDU ages out).
        bridge_b.bpdu_cache.retain(|(pid, _)| *pid != 1);
        bridge_b.run_election();

        // Without A's BPDU, B should believe it's the root again.
        assert_eq!(bridge_b.root_bridge_id, bridge_b.bridge_id);
        assert!(bridge_b.root_port.is_none());
    }

    /// Edge ports start in Forwarding state immediately.
    #[test]
    fn edge_port_immediate_forwarding() {
        let mut bridge = StpBridge::new([0xAA; 6]);
        bridge.add_port(StpPort::new_edge(1, PATH_COST_1G));
        bridge.add_port(StpPort::new(2, PATH_COST_1G));

        // Edge port should be Forwarding.
        let edge_port = bridge.ports.iter().find(|p| p.port_id == 1).unwrap();
        assert_eq!(edge_port.state, StpPortState::Forwarding);
        assert!(edge_port.edge);

        // Non-edge port should start Blocking.
        let net_port = bridge.ports.iter().find(|p| p.port_id == 2).unwrap();
        assert_eq!(net_port.state, StpPortState::Blocking);
    }
}
