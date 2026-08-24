//! src/kernel/network/mrouting/vif.rs
//!
//! Virtual interfaces (VIFs) for multicast routing.
//!
//! VIF 0 is always the local (host) interface — the single network device
//! plus local delivery.  Additional VIFs are logical interfaces used for
//! multicast forwarding decisions; with the single-device model they all
//! transmit out of the same physical NIC.

use alloc::collections::btree_map::BTreeMap;

use crate::abi::mrt as mrt_abi;
use crate::{Error, Result};

/// VIF 0 is always the local interface.
pub const VIF_LOCAL: u32 = 0;

/// A virtual interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VifEntry {
    pub index: u32,
    /// `MRT_VIF_FLAG_*` bitmask.
    pub flags: u32,
    /// Minimum TTL required to forward onto this VIF.
    pub threshold: u8,
    /// Rate limit (packets/second, 0 = unlimited).
    pub rate_limit: u32,
}

/// Table of virtual interfaces.
#[derive(Default)]
pub struct VifTable {
    vifs: BTreeMap<u32, VifEntry>,
    next_vif: u32,
}

impl VifTable {
    pub fn new() -> Self {
        Self {
            vifs: BTreeMap::new(),
            next_vif: 1,
        }
    }

    /// Install the local VIF 0.
    pub fn install_local(&mut self) {
        self.vifs.insert(
            VIF_LOCAL,
            VifEntry {
                index: VIF_LOCAL,
                flags: mrt_abi::MRT_VIF_FLAG_LOCAL,
                threshold: 0,
                rate_limit: 0,
            },
        );
    }

    /// Add a VIF from an ABI definition.  Returns the assigned index.
    pub fn add(&mut self, def: &mrt_abi::MrtVifDef) -> Result<u32> {
        let index = if def.vif_index != 0 {
            def.vif_index
        } else {
            self.next_vif
        };
        if self.vifs.contains_key(&index) {
            return Err(Error::AlreadyExists);
        }
        self.vifs.insert(
            index,
            VifEntry {
                index,
                flags: def.flags,
                threshold: def.threshold.min(255) as u8,
                rate_limit: def.rate_limit,
            },
        );
        if index >= self.next_vif {
            self.next_vif = index + 1;
        }
        Ok(index)
    }

    pub fn remove(&mut self, index: u32) -> bool {
        self.vifs.remove(&index).is_some()
    }

    pub fn get(&self, index: u32) -> Option<&VifEntry> {
        self.vifs.get(&index)
    }

    /// Iterate over all VIF entries.
    pub fn iter(&self) -> impl Iterator<Item = &VifEntry> {
        self.vifs.values()
    }

    pub fn len(&self) -> usize {
        self.vifs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vifs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vif_def(index: u32, flags: u32) -> mrt_abi::MrtVifDef {
        mrt_abi::MrtVifDef {
            flags,
            vif_index: index,
            threshold: 0,
            rate_limit: 0,
            reserved0: 0,
            reserved1: 0,
        }
    }

    #[test]
    fn add_remove_and_duplicate_rejected() {
        let mut table = VifTable::new();
        table.install_local();
        assert!(table.get(VIF_LOCAL).is_some());

        let idx = table
            .add(&vif_def(1, mrt_abi::MRT_VIF_FLAG_PIM))
            .expect("add");
        assert_eq!(idx, 1);
        assert!(table.add(&vif_def(1, 0)).is_err(), "duplicate VIF");
        assert!(table.remove(1));
        assert!(table.get(1).is_none());
    }

    #[test]
    fn auto_assign_increments() {
        let mut table = VifTable::new();
        let a = table.add(&vif_def(0, 0)).expect("auto a");
        let b = table.add(&vif_def(0, 0)).expect("auto b");
        assert_eq!(a, 1);
        assert_eq!(b, 2);
    }
}
