//! src/abi/mrt.rs
//! Shared ABI definitions for multicast routing (MRT) control — VIF and
//! multicast-forwarding-cache (MFC) management, mirroring the Linux
//! `MRT_*` multicast-routing ioctl surface.

/// Size of a serialised `MrtVifDef` (6 × u32).
pub const MRT_VIF_DEF_SIZE: usize = 24;
/// Size of a serialised `MrtMfcDef` (source+group + 3×u32 + 4×MrtOutVif).
pub const MRT_MFC_DEF_SIZE: usize = 48;

/// VIF flag: this VIF is the local (host) interface.
pub const MRT_VIF_FLAG_LOCAL: u32 = 1;
/// VIF flag: the interface runs PIM.
pub const MRT_VIF_FLAG_PIM: u32 = 2;

/// A virtual interface definition.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrtVifDef {
    /// `MRT_VIF_FLAG_*` bitmask.
    pub flags: u32,
    /// Requested VIF index (0 = local; or 0 to auto-assign).
    pub vif_index: u32,
    /// Minimum TTL required to forward onto this VIF.
    pub threshold: u32,
    /// Rate limit in packets/second (0 = unlimited).
    pub rate_limit: u32,
    pub reserved0: u32,
    pub reserved1: u32,
}

/// One outgoing-VIF entry of an MFC entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrtOutVif {
    pub vif: u32,
    /// Per-entry TTL threshold for this VIF.
    pub ttl: u32,
}

/// A multicast forwarding cache entry: `(source, group)` → in/out VIFs.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrtMfcDef {
    pub source: [u8; 4],
    pub group: [u8; 4],
    pub in_vif: u32,
    pub num_out_vifs: u32,
    pub out_vifs: [MrtOutVif; 4],
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn abi_struct_sizes_are_stable() {
        assert_eq!(size_of::<MrtVifDef>(), MRT_VIF_DEF_SIZE);
        assert_eq!(size_of::<MrtMfcDef>(), MRT_MFC_DEF_SIZE);
    }
}
