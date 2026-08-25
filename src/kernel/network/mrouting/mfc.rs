//! src/kernel/network/mrouting/mfc.rs
//!
//! Multicast forwarding cache (MFC): `(source, group)` entries mapping an
//! incoming VIF to a list of outgoing VIFs, with per-VIF TTL thresholds and
//! packet/byte counters (the kernel data plane of multicast routing).

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

use crate::abi::mrt as mrt_abi;
use crate::kernel::network::internet::ip::IpAddress;
use crate::Error;
use crate::Result;

/// One outgoing-VIF of an MFC entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutVif {
    pub vif: u32,
    pub ttl: u8,
}

/// A multicast forwarding-cache entry.  `source`/`group` are either IPv4 or
/// IPv6 addresses, matching the address family of the forwarded traffic.
#[derive(Debug, Clone)]
pub struct MfcEntry {
    pub source: IpAddress,
    pub group: IpAddress,
    pub in_vif: u32,
    pub out_vifs: Vec<OutVif>,
    pub pkt_count: u64,
    pub byte_count: u64,
    pub last_used: u64,
}

/// The multicast forwarding cache, keyed by `(source, group)`.
#[derive(Default)]
pub struct MfcCache {
    pub entries: BTreeMap<(IpAddress, IpAddress), MfcEntry>,
}

impl MfcCache {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Add an MFC entry from an ABI definition (IPv4 source/group).
    pub fn add(&mut self, def: &mrt_abi::MrtMfcDef, tick: u64) -> Result<()> {
        if def.num_out_vifs as usize > def.out_vifs.len() {
            return Err(Error::InvalidArgument);
        }
        let source = IpAddress::V4(def.source);
        let group = IpAddress::V4(def.group);
        if self.entries.contains_key(&(source, group)) {
            return Err(Error::AlreadyExists);
        }
        let out_vifs = def.out_vifs[..def.num_out_vifs as usize]
            .iter()
            .map(|o| OutVif {
                vif: o.vif,
                ttl: o.ttl.min(255) as u8,
            })
            .collect();
        self.entries.insert(
            (source, group),
            MfcEntry {
                source,
                group,
                in_vif: def.in_vif,
                out_vifs,
                pkt_count: 0,
                byte_count: 0,
                last_used: tick,
            },
        );
        Ok(())
    }

    pub fn remove(&mut self, source: IpAddress, group: IpAddress) -> bool {
        self.entries.remove(&(source, group)).is_some()
    }

    pub fn lookup(&self, source: IpAddress, group: IpAddress) -> Option<&MfcEntry> {
        self.entries.get(&(source, group))
    }

    pub fn lookup_mut(&mut self, source: IpAddress, group: IpAddress) -> Option<&mut MfcEntry> {
        self.entries.get_mut(&(source, group))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mfc_def(source: [u8; 4], group: [u8; 4], in_vif: u32) -> mrt_abi::MrtMfcDef {
        mrt_abi::MrtMfcDef {
            source,
            group,
            in_vif,
            num_out_vifs: 1,
            out_vifs: [mrt_abi::MrtOutVif { vif: 1, ttl: 3 }; 4],
        }
    }

    #[test]
    fn add_lookup_remove_and_duplicate() {
        let mut cache = MfcCache::new();
        assert!(cache
            .add(&mfc_def([10, 0, 2, 1], [224, 1, 2, 3], 0), 0)
            .is_ok());
        assert!(
            cache
                .add(&mfc_def([10, 0, 2, 1], [224, 1, 2, 3], 0), 0)
                .is_err(),
            "duplicate (S,G)"
        );
        let entry = cache
            .lookup(IpAddress::V4([10, 0, 2, 1]), IpAddress::V4([224, 1, 2, 3]))
            .expect("entry");
        assert_eq!(entry.in_vif, 0);
        assert_eq!(entry.out_vifs[0].ttl, 3);
        assert!(cache.remove(IpAddress::V4([10, 0, 2, 1]), IpAddress::V4([224, 1, 2, 3])));
        assert!(cache.is_empty());
    }

    #[test]
    fn invalid_out_vif_count_rejected() {
        let mut def = mfc_def([1, 1, 1, 1], [224, 0, 0, 1], 0);
        def.num_out_vifs = 5; // exceeds the array capacity
        assert!(MfcCache::new().add(&def, 0).is_err());
    }
}
