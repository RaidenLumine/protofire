//! src/kernel/network/ipsec/mod.rs
//! IPsec (RFC 4301): Security Policy Database (SPD), Security Association
//! Database (SAD), and ESP (RFC 4303) / AH (RFC 4302) transforms.
//!
//! SAs are configured manually (no IKE): a userspace component programs the
//! SPD/SAD through the `ipsec_add_sp`/`ipsec_add_sa` syscalls, providing the
//! SPI, keys, mode, and selectors.  The data plane consults the SPD on
//! outbound/inbound packets, applies the matching SA (ESP encryption or AH
//! authentication), and performs anti-replay checks on inbound SAs.

pub mod ah;
pub mod esp;
pub mod transform;

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

use crate::abi::ipsec as abi;
use crate::kernel::network::internet::ip::IpAddress;
use crate::{Error, Result};

/// IPsec transform mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecMode {
    Transport,
    Tunnel,
}

/// Which protocol protects the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecProto {
    Esp,
    Ah,
}

/// ESP AEAD algorithms (RFC 4106 / RFC 7634).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgo {
    Aes128Gcm,
    ChaCha20Poly1305,
}

/// AH authentication algorithms (RFC 4868).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAlgo {
    HmacSha256,
}

/// SPD actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpAction {
    Bypass,
    Discard,
    Protect,
}

impl Default for SpAction {
    /// The default SPD action is `Bypass` (allow all traffic) so that a
    /// freshly created policy database does not silently drop packets.
    fn default() -> Self {
        Self::Bypass
    }
}

/// SPD directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpDirection {
    Inbound,
    Outbound,
    Both,
}

/// Traffic selector: source/destination CIDR + protocol + ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpSelector {
    pub src: IpAddress,
    pub src_prefix: u8,
    pub dst: IpAddress,
    pub dst_prefix: u8,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl SpSelector {
    fn address_matches(candidate: &[u8], net: &[u8], prefix: u8) -> bool {
        let full_bytes = (prefix / 8) as usize;
        let remaining_bits = prefix % 8;
        if candidate.len() != net.len() || full_bytes > candidate.len() {
            return false;
        }
        if candidate[..full_bytes] != net[..full_bytes] {
            return false;
        }
        if remaining_bits > 0 {
            let mask = 0xFFu8 << (8 - remaining_bits);
            if candidate[full_bytes] & mask != net[full_bytes] & mask {
                return false;
            }
        }
        true
    }

    fn matches(
        &self,
        src: IpAddress,
        dst: IpAddress,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        // Candidate and selector must share an address family.
        match (src, self.src) {
            (IpAddress::V4(candidate), IpAddress::V4(net)) => {
                if !Self::address_matches(&candidate, &net, self.src_prefix) {
                    return false;
                }
            }
            (IpAddress::V6(candidate), IpAddress::V6(net)) => {
                if !Self::address_matches(&candidate, &net, self.src_prefix) {
                    return false;
                }
            }
            _ => return false,
        }
        match (dst, self.dst) {
            (IpAddress::V4(candidate), IpAddress::V4(net)) => {
                if !Self::address_matches(&candidate, &net, self.dst_prefix) {
                    return false;
                }
            }
            (IpAddress::V6(candidate), IpAddress::V6(net)) => {
                if !Self::address_matches(&candidate, &net, self.dst_prefix) {
                    return false;
                }
            }
            _ => return false,
        }
        (self.protocol == 0 || self.protocol == protocol)
            && (self.src_port == 0 || self.src_port == src_port)
            && (self.dst_port == 0 || self.dst_port == dst_port)
    }
}

/// One SPD entry (order matters — first match wins, like firewall rules).
#[derive(Debug, Clone)]
pub struct SpEntry {
    pub id: u64,
    pub direction: SpDirection,
    pub selector: SpSelector,
    pub action: SpAction,
    /// SAD id of the SA to apply for `Protect`.
    pub sa_id: Option<u32>,
}

/// A security association.
#[derive(Debug, Clone)]
pub struct IpsecSa {
    pub id: u32,
    pub spi: u32,
    pub mode: IpsecMode,
    pub proto: IpsecProto,
    pub aead: Option<AeadAlgo>,
    pub auth: Option<AuthAlgo>,
    pub enc_key: Vec<u8>,
    pub salt: Vec<u8>,
    pub auth_key: Vec<u8>,
    pub tunnel_src: Option<IpAddress>,
    pub tunnel_dst: Option<IpAddress>,
    /// Next outbound sequence number.
    pub seq_counter: u64,
    /// Anti-replay window: bitmap of the last 64 sequence numbers seen.
    pub replay_window: u64,
    /// Highest sequence number seen.
    pub replay_last: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub lifetime_bytes: u64,
    pub lifetime_ticks: u64,
}

impl IpsecSa {
    /// Allocate and return the next outbound sequence number.
    pub fn next_seq(&mut self) -> u64 {
        self.seq_counter = self.seq_counter.wrapping_add(1);
        self.seq_counter
    }

    /// Update the anti-replay window for an inbound `seq`.  Returns `false`
    /// when the packet is a duplicate or too far behind (RFC 4303 §3.4.3).
    pub fn check_replay(&mut self, seq: u64) -> bool {
        let seq = seq & 0xFFFF_FFFF;
        if seq == 0 {
            return false;
        }
        let window_size = 64u64;
        if seq > self.replay_last {
            // Advance the window.
            let diff = seq - self.replay_last;
            if diff >= window_size {
                self.replay_window = 0;
            } else {
                self.replay_window <<= diff;
            }
            self.replay_window |= 1;
            self.replay_last = seq;
            true
        } else {
            let diff = self.replay_last - seq;
            if diff >= window_size {
                return false; // too old
            }
            let bit = 1u64 << diff;
            if self.replay_window & bit != 0 {
                return false; // duplicate
            }
            self.replay_window |= bit;
            true
        }
    }
}

/// Security Policy Database (ordered list).
#[derive(Default)]
pub struct IpsecSpd {
    pub entries: Vec<SpEntry>,
    next_id: u64,
    pub default_action: SpAction,
}

impl IpsecSpd {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 1,
            default_action: SpAction::Bypass,
        }
    }

    /// Add an entry from an ABI definition.
    pub fn add(&mut self, def: &abi::IpsecSpDef) -> Result<u64> {
        let action = match def.action {
            abi::IPSEC_ACTION_BYPASS => SpAction::Bypass,
            abi::IPSEC_ACTION_DISCARD => SpAction::Discard,
            abi::IPSEC_ACTION_PROTECT => SpAction::Protect,
            _ => return Err(Error::InvalidArgument),
        };
        let direction = match def.direction {
            abi::IPSEC_DIR_INBOUND => SpDirection::Inbound,
            abi::IPSEC_DIR_OUTBOUND => SpDirection::Outbound,
            abi::IPSEC_DIR_BOTH => SpDirection::Both,
            _ => return Err(Error::InvalidArgument),
        };
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(SpEntry {
            id,
            direction,
            selector: SpSelector {
                src: IpAddress::V4(def.src_addr),
                src_prefix: def.src_prefix.min(32) as u8,
                dst: IpAddress::V4(def.dst_addr),
                dst_prefix: def.dst_prefix.min(32) as u8,
                protocol: def.protocol.min(255) as u8,
                src_port: def.src_port.min(u16::MAX as u32) as u16,
                dst_port: def.dst_port.min(u16::MAX as u32) as u16,
            },
            action,
            sa_id: (def.action == abi::IPSEC_ACTION_PROTECT).then_some(def.sa_id),
        });
        Ok(id)
    }

    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.id != id);
        self.entries.len() != before
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// First-match lookup for outbound traffic.
    pub fn lookup_outbound(
        &self,
        src: IpAddress,
        dst: IpAddress,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> SpAction {
        for entry in &self.entries {
            let matches_direction =
                matches!(entry.direction, SpDirection::Outbound | SpDirection::Both);
            if matches_direction
                && entry
                    .selector
                    .matches(src, dst, protocol, src_port, dst_port)
            {
                return entry.action;
            }
        }
        self.default_action
    }

    /// First-match lookup for inbound traffic.
    pub fn lookup_inbound(
        &self,
        src: IpAddress,
        dst: IpAddress,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> SpAction {
        for entry in &self.entries {
            let matches_direction =
                matches!(entry.direction, SpDirection::Inbound | SpDirection::Both);
            if matches_direction
                && entry
                    .selector
                    .matches(src, dst, protocol, src_port, dst_port)
            {
                return entry.action;
            }
        }
        self.default_action
    }
}

/// Security Association Database, indexed by SPI and by local id.
#[derive(Default)]
pub struct IpsecSad {
    pub by_spi: BTreeMap<u32, IpsecSa>,
    pub by_id: BTreeMap<u32, IpsecSa>,
    next_id: u32,
}

impl IpsecSad {
    pub fn new() -> Self {
        Self {
            by_spi: BTreeMap::new(),
            by_id: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Add an SA from an ABI definition.
    pub fn add(&mut self, def: &abi::IpsecSaDef) -> Result<u32> {
        if def.spi == 0 || def.spi == 0xFFFFFFFF {
            return Err(Error::InvalidArgument);
        }
        let mode = match def.mode {
            abi::IPSEC_MODE_TRANSPORT => IpsecMode::Transport,
            abi::IPSEC_MODE_TUNNEL => IpsecMode::Tunnel,
            _ => return Err(Error::InvalidArgument),
        };
        let proto = match def.proto {
            abi::IPSEC_PROTO_ESP => IpsecProto::Esp,
            abi::IPSEC_PROTO_AH => IpsecProto::Ah,
            _ => return Err(Error::InvalidArgument),
        };
        let aead = match (proto, def.aead_algo) {
            (IpsecProto::Esp, abi::IPSEC_AEAD_AES128_GCM) => Some(AeadAlgo::Aes128Gcm),
            (IpsecProto::Esp, abi::IPSEC_AEAD_CHACHA20_POLY1305) => {
                Some(AeadAlgo::ChaCha20Poly1305)
            }
            (IpsecProto::Esp, _) => return Err(Error::InvalidArgument),
            (IpsecProto::Ah, _) => None,
        };
        let auth = match (proto, def.auth_algo) {
            (IpsecProto::Ah, abi::IPSEC_AUTH_HMAC_SHA256) => Some(AuthAlgo::HmacSha256),
            (IpsecProto::Ah, _) => return Err(Error::InvalidArgument),
            (IpsecProto::Esp, _) => None,
        };
        if def.enc_key_len as usize > def.enc_key.len()
            || def.auth_key_len as usize > def.auth_key.len()
        {
            return Err(Error::InvalidArgument);
        }

        let id = self.next_id;
        self.next_id += 1;
        let sa = IpsecSa {
            id,
            spi: def.spi,
            mode,
            proto,
            aead,
            auth,
            enc_key: def.enc_key[..def.enc_key_len as usize].to_vec(),
            salt: def.salt.to_vec(),
            auth_key: def.auth_key[..def.auth_key_len as usize].to_vec(),
            tunnel_src: (def.tunnel_src != [0; 4]).then_some(IpAddress::V4(def.tunnel_src)),
            tunnel_dst: (def.tunnel_dst != [0; 4]).then_some(IpAddress::V4(def.tunnel_dst)),
            seq_counter: 0,
            replay_window: 0,
            replay_last: 0,
            packets_in: 0,
            packets_out: 0,
            bytes_in: 0,
            bytes_out: 0,
            lifetime_bytes: def.lifetime_bytes,
            lifetime_ticks: def.lifetime_ticks,
        };
        if self.by_spi.contains_key(&def.spi) {
            return Err(Error::AlreadyExists);
        }
        self.by_spi.insert(def.spi, sa.clone());
        self.by_id.insert(id, sa);
        Ok(id)
    }

    pub fn remove_spi(&mut self, spi: u32) -> bool {
        let removed = self.by_spi.remove(&spi);
        if let Some(sa) = removed {
            self.by_id.remove(&sa.id);
            true
        } else {
            false
        }
    }

    pub fn by_spi(&self, spi: u32) -> Option<&IpsecSa> {
        self.by_spi.get(&spi)
    }

    pub fn by_id(&self, id: u32) -> Option<&IpsecSa> {
        self.by_id.get(&id)
    }

    pub fn len(&self) -> usize {
        self.by_spi.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_spi.is_empty()
    }
}

/// Extract the TCP/UDP/DCCP source and destination ports from a transport
/// payload (first 4 bytes of the segment, big-endian).
pub(crate) fn transport_ports(payload: &[u8]) -> (u16, u16) {
    if payload.len() >= 4 {
        (
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[2], payload[3]]),
        )
    } else {
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(addr: [u8; 4]) -> IpAddress {
        IpAddress::V4(addr)
    }

    #[test]
    fn spd_first_match_wins_and_bypass_default() {
        let mut spd = IpsecSpd::new();
        let def = abi::IpsecSpDef {
            flags: 0,
            action: abi::IPSEC_ACTION_PROTECT,
            direction: abi::IPSEC_DIR_OUTBOUND,
            protocol: 17,
            src_addr: [10, 0, 2, 15],
            src_prefix: 32,
            dst_addr: [10, 0, 2, 100],
            dst_prefix: 32,
            src_port: 0,
            dst_port: 53,
            sa_id: 7,
            reserved: 0,
        };
        spd.add(&def).expect("add sp");
        // Matching traffic → Protect.
        assert_eq!(
            spd.lookup_outbound(v4([10, 0, 2, 15]), v4([10, 0, 2, 100]), 17, 12345, 53),
            SpAction::Protect
        );
        // Different dst → default Bypass.
        assert_eq!(
            spd.lookup_outbound(v4([10, 0, 2, 15]), v4([10, 0, 2, 200]), 17, 12345, 53),
            SpAction::Bypass
        );
    }

    #[test]
    fn sad_round_trip_by_spi_and_id() {
        let mut sad = IpsecSad::new();
        let mut def = abi::IpsecSaDef {
            flags: 0,
            spi: 0x01020304,
            mode: abi::IPSEC_MODE_TRANSPORT,
            proto: abi::IPSEC_PROTO_ESP,
            aead_algo: abi::IPSEC_AEAD_AES128_GCM,
            auth_algo: 0,
            enc_key_len: 16,
            auth_key_len: 0,
            enc_key: [0u8; 32],
            auth_key: [0u8; 32],
            salt: [0u8; 12],
            src_addr: [0; 4],
            dst_addr: [0; 4],
            tunnel_src: [0; 4],
            tunnel_dst: [0; 4],
            lifetime_bytes: 0,
            lifetime_ticks: 0,
        };
        for i in 0..16 {
            def.enc_key[i] = i as u8;
        }
        let id = sad.add(&def).expect("add sa");
        assert_eq!(sad.by_spi(0x01020304).expect("spi").id, id);
        assert_eq!(sad.by_id(id).expect("id").spi, 0x01020304);
        assert!(sad.remove_spi(0x01020304));
        assert!(sad.by_spi(0x01020304).is_none());
        assert!(sad.by_id(id).is_none());
    }

    #[test]
    fn anti_replay_window_accepts_new_and_rejects_duplicates() {
        let mut sad = IpsecSad::new();
        let def = abi::IpsecSaDef {
            flags: 0,
            spi: 9,
            mode: abi::IPSEC_MODE_TRANSPORT,
            proto: abi::IPSEC_PROTO_ESP,
            aead_algo: abi::IPSEC_AEAD_AES128_GCM,
            auth_algo: 0,
            enc_key_len: 16,
            auth_key_len: 0,
            enc_key: [0u8; 32],
            auth_key: [0u8; 32],
            salt: [0u8; 12],
            src_addr: [0; 4],
            dst_addr: [0; 4],
            tunnel_src: [0; 4],
            tunnel_dst: [0; 4],
            lifetime_bytes: 0,
            lifetime_ticks: 0,
        };
        let sa = sad.add(&def).expect("add");
        let sa = sad.by_id(sa).expect("sa");
        let mut sa = sa.clone();

        assert!(sa.check_replay(1));
        assert!(sa.check_replay(2));
        assert!(!sa.check_replay(1), "duplicate rejected");
        assert!(!sa.check_replay(2), "duplicate rejected");
        // A far-ahead sequence is new — the window advances by a full 64
        // and the packet is accepted (RFC 4303 §3.4.3).
        assert!(sa.check_replay(2 + 64));
        // Sequence 2 is now exactly one window behind the new high-water
        // mark, so it must be rejected as too old.
        assert!(!sa.check_replay(2), "far-behind sequence rejected");
        assert!(sa.check_replay(2 + 65), "fresh seq accepted");
    }
}
