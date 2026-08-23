//! src/kernel/network/internet/mobile_ip.rs
//! Mobile IPv4 agent advertisement (RFC 3344).
//!
//! ## Educational purpose
//!
//! A mobile node moving between networks must learn which agent can serve
//! it.  Mobility agents (home agent and foreign agent) announce themselves
//! with an ICMP Router Advertisement (type 9) carrying mobility-agent
//! extensions.  The advertisement tells the mobile node its registration
//! lifetime, the care-of address(es) to use, and which agent capabilities
//! (home / foreign) are available on the visited link.
//!
//! ## Why not production?
//!
//! - Mobility support has largely moved to protocol-independent solutions
//!   (MIPv6, Proxy MIP, and L3 fabric mobility in data centres).
//! - Registration security (RFC 3344 §5) depends on a shared secret that a
//!   kernel-only model cannot supply; production agents authenticate every
//!   registration with a 128-bit authenticator extension.
//! - The byte layout here is the *advertisement* only — the registration
//!   request/reply machinery is left to a higher layer.

use alloc::vec::Vec;

// ─── Wire-format constants (RFC 3344) ──────────────────────────────────────

/// ICMP type carried by every agent advertisement (Router Advertisement).
pub const ICMP_TYPE_ROUTER_ADVERTISEMENT: u8 = 9;
/// ICMP code for a mobility-agent advertisement.
pub const ICMP_CODE_MOBILITY_AGENT: u8 = 16;
/// Mobility-agent advertisement extension type (§3.2.2.1).
pub const EXT_TYPE_MOBILITY_AGENT: u8 = 16;
/// Care-of address extension type (§3.2.2.2).
pub const EXT_TYPE_CARE_OF: u8 = 5;
/// Length of the mobility-agent extension body: seq(2) + lifetime(2) +
/// flags(1) + reserved(1).
pub const MOBILITY_AGENT_EXT_LENGTH: u8 = 6;
/// Size of a care-of extension header (type + length).
pub const CARE_OF_EXT_HEADER_LEN: usize = 2;
/// Size of a single care-of address in bytes.
pub const ADDRESS_SIZE: usize = 4;

// ─── Capability flags (mobility-agent extension) ───────────────────────────

/// R — registration required.  The mobile node must register before using
/// the care-of address.
pub const FLAG_REGISTRATION_REQUIRED: u8 = 0x80;
/// H — this agent is a home agent.
pub const FLAG_HOME_AGENT: u8 = 0x40;
/// F — this agent is a foreign agent.
pub const FLAG_FOREIGN_AGENT: u8 = 0x20;
/// M — minimal encapsulation is supported.
pub const FLAG_MINIMAL_ENCAPSULATION: u8 = 0x10;
/// G — GRE encapsulation is supported.
pub const FLAG_GRE: u8 = 0x08;
/// V — Van Jacobson header compression is supported.
pub const FLAG_VAN_JACOBSON: u8 = 0x04;
/// T — tunnel reverse-encapsulation is supported.
pub const FLAG_TUNNEL_REVERSE: u8 = 0x02;

// ─── Agent advertisement ───────────────────────────────────────────────────

/// A decoded Mobile IPv4 agent advertisement.
///
/// The wire format is an ICMP Router Advertisement (type 9, code 16) with a
/// mobility-agent extension and zero or more care-of addresses:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type=9    |    Code=16    |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   num_addrs   |   entry_size  |        lifetime               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type=16    |   Length=6    |          Sequence             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Reg life    |   Flags |Rsvd |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type=5     | Length=4*N    |   Care-of address 1          ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAdvertisement {
    /// Registration sequence number echoed back by the mobile node.
    pub sequence: u16,
    /// Registration lifetime offered by the agent, in seconds.
    pub reg_lifetime: u16,
    /// Care-of addresses the mobile node may register with.
    pub care_of_addresses: Vec<[u8; 4]>,
    /// Capability flags (see the `FLAG_*` constants).
    pub flags: u8,
}

impl AgentAdvertisement {
    /// Create an advertisement with no capability flags set.
    pub fn new(sequence: u16, reg_lifetime: u16, care_of_addresses: Vec<[u8; 4]>) -> Self {
        Self {
            sequence,
            reg_lifetime,
            care_of_addresses,
            flags: 0,
        }
    }

    /// Whether this agent offers home-agent service (H bit).
    pub fn is_home_agent(&self) -> bool {
        self.flags & FLAG_HOME_AGENT != 0
    }

    /// Whether this agent offers foreign-agent service (F bit).
    pub fn is_foreign_agent(&self) -> bool {
        self.flags & FLAG_FOREIGN_AGENT != 0
    }

    /// Whether registration is mandatory before the mobile node may use the
    /// care-of address (R bit).
    pub fn registration_required(&self) -> bool {
        self.flags & FLAG_REGISTRATION_REQUIRED != 0
    }

    /// Serialize the advertisement to its wire representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let coa_bytes = self.care_of_addresses.len() * ADDRESS_SIZE;
        let mut buf = Vec::with_capacity(18 + coa_bytes);

        // ICMP Router Advertisement base (8 bytes).
        buf.push(ICMP_TYPE_ROUTER_ADVERTISEMENT);
        buf.push(ICMP_CODE_MOBILITY_AGENT);
        buf.extend_from_slice(&[0, 0]); // checksum (omitted in this model)
        buf.push(0); // num_addrs — no router address list carried
        buf.push(0); // entry_size
        buf.extend_from_slice(&self.reg_lifetime.to_be_bytes());

        // Mobility-agent advertisement extension (8 bytes).
        buf.push(EXT_TYPE_MOBILITY_AGENT);
        buf.push(MOBILITY_AGENT_EXT_LENGTH);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.reg_lifetime.to_be_bytes());
        buf.push(self.flags);
        buf.push(0); // reserved

        // Care-of address extension.
        buf.push(EXT_TYPE_CARE_OF);
        buf.push((self.care_of_addresses.len() * ADDRESS_SIZE) as u8);
        for coa in &self.care_of_addresses {
            buf.extend_from_slice(coa);
        }
        buf
    }

    /// Parse an advertisement from its wire representation.
    ///
    /// Returns `None` if the buffer is too short, is not a mobility-agent
    /// advertisement, or carries a truncated care-of extension.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        // Base (8) + mobility-agent ext (8) + care-of ext header (2).
        if data.len() < 18 {
            return None;
        }
        if data[0] != ICMP_TYPE_ROUTER_ADVERTISEMENT || data[1] != ICMP_CODE_MOBILITY_AGENT {
            return None;
        }
        if data[8] != EXT_TYPE_MOBILITY_AGENT || data[9] != MOBILITY_AGENT_EXT_LENGTH {
            return None;
        }

        let sequence = u16::from_be_bytes([data[10], data[11]]);
        let reg_lifetime = u16::from_be_bytes([data[12], data[13]]);
        let flags = data[14];

        if data[16] != EXT_TYPE_CARE_OF {
            return None;
        }
        let coa_count = data[17] as usize / ADDRESS_SIZE;
        let need = 18 + coa_count * ADDRESS_SIZE;
        if data.len() < need {
            return None;
        }

        let mut care_of_addresses = Vec::with_capacity(coa_count);
        for i in 0..coa_count {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&data[18 + i * ADDRESS_SIZE..18 + (i + 1) * ADDRESS_SIZE]);
            care_of_addresses.push(addr);
        }

        Some(Self {
            sequence,
            reg_lifetime,
            care_of_addresses,
            flags,
        })
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn agent_advertisement_round_trip() {
        let mut adv = AgentAdvertisement::new(42, 3600, vec![[10, 0, 0, 1]]);
        adv.flags = FLAG_HOME_AGENT | FLAG_FOREIGN_AGENT;

        let bytes = adv.to_bytes();
        let parsed = AgentAdvertisement::from_bytes(&bytes).expect("parse");
        assert!(parsed.is_home_agent());
        assert!(parsed.is_foreign_agent());
        assert!(!parsed.registration_required(), "R bit not set");
        assert_eq!(parsed.sequence, 42);
        assert_eq!(parsed.reg_lifetime, 3600);
        assert_eq!(parsed.care_of_addresses.len(), 1);
        assert_eq!(parsed.care_of_addresses[0], [10, 0, 0, 1]);
    }

    #[test]
    fn registration_required_flag_round_trips() {
        let mut adv = AgentAdvertisement::new(1, 120, vec![[192, 0, 2, 10]]);
        adv.flags = FLAG_REGISTRATION_REQUIRED;

        let bytes = adv.to_bytes();
        let parsed = AgentAdvertisement::from_bytes(&bytes).expect("parse");
        assert!(parsed.registration_required());
        assert!(!parsed.is_home_agent());
        assert!(!parsed.is_foreign_agent());
    }

    #[test]
    fn multiple_care_of_addresses() {
        let coas = vec![[10, 0, 0, 1], [10, 0, 0, 2], [10, 0, 0, 3]];
        let adv = AgentAdvertisement::new(7, 600, coas.clone());
        let parsed = AgentAdvertisement::from_bytes(&adv.to_bytes()).expect("parse");
        assert_eq!(parsed.care_of_addresses, coas);
    }

    #[test]
    fn rejects_non_agent_advertisement() {
        // Not a router advertisement at all.
        assert!(AgentAdvertisement::from_bytes(&[8, 0, 0, 0, 0, 0, 0, 0]).is_none());
        // Router advertisement, but the wrong code.
        let wrong_code = [9, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, 0, 0, 0, 0, 5, 4];
        assert!(AgentAdvertisement::from_bytes(&wrong_code).is_none());
    }

    #[test]
    fn rejects_truncated_advertisement() {
        // Care-of extension claims 1 address but supplies no address bytes.
        let truncated = [9, 16, 0, 0, 0, 0, 0, 0, 16, 6, 0, 42, 14, 16, 96, 0, 5, 4];
        assert!(AgentAdvertisement::from_bytes(&truncated).is_none());
    }
}
