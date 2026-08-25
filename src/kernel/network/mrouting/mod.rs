//! src/kernel/network/mrouting/mod.rs
//!
//! Multicast routing (MRT) state.
//!
//! Sub-module organisation:
//! - `vif`          — Virtual interfaces (`VifTable` / `VifEntry`)
//! - `mfc`          — Multicast forwarding cache (`MfcCache` / `MfcEntry`)
//! - `igmp_router`  — IGMPv2 router membership tracking (IPv4)
//! - `mld_router`   — MLDv1 router membership tracking (IPv6)
//! - `pim`          — PIM-DM control plane (`PimState`)
//!
//! [`MrtState`] bundles all of the above into the per-stack multicast routing
//! state held by the
//! [`NetworkStack`](crate::kernel::network::stack::NetworkStack).

pub(crate) mod igmp_router;
pub(crate) mod mfc;
pub(crate) mod mld_router;
pub(crate) mod pim;
pub(crate) mod vif;

use crate::abi::mrt::MrtMfcDef;
use crate::abi::mrt::MrtVifDef;
use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::stack::NetworkStack;
use crate::Error;
use crate::Result;

use igmp_router::IgmpRouterState;
use mfc::MfcCache;
use mld_router::MldRouterState;
use pim::PimState;
use vif::VifTable;
use vif::VIF_LOCAL;

/// Per-stack multicast routing state.
pub struct MrtState {
    /// Virtual interface table (VIF 0 is the local host interface).
    pub vif_table: VifTable,
    /// Multicast forwarding cache: `(source, group)` → outgoing VIFs.
    pub mfc_cache: MfcCache,
    /// IGMPv2 router membership state (IPv4 groups per VIF).
    pub igmp_router: IgmpRouterState,
    /// MLDv1 router membership state (IPv6 groups per VIF).
    pub mld_router: MldRouterState,
    /// PIM-DM control-plane state (Hello / Join-Prune / prune table).
    pub pim: PimState,
}

impl Default for MrtState {
    fn default() -> Self {
        Self::new()
    }
}

impl MrtState {
    /// Create empty multicast routing state.
    pub fn new() -> Self {
        Self {
            vif_table: VifTable::new(),
            mfc_cache: MfcCache::new(),
            igmp_router: IgmpRouterState::new(),
            mld_router: MldRouterState::new(),
            pim: PimState::new(),
        }
    }

    /// Periodic multicast-routing maintenance (driven from the stack tick):
    /// age out stale PIM prune entries and PIM neighbor state, and emit a
    /// periodic PIM Hello while the control plane is enabled.
    ///
    /// `stack` is passed through so a Hello can be transmitted on the wire.
    pub fn tick(&mut self, tick: u64, stack: &NetworkStack) {
        pim::tick(self, tick, stack);
    }

    /// Enable multicast routing (mrt_init): install the local VIF and start
    /// the IGMP/MLD router membership trackers.
    pub fn init(&mut self) {
        self.vif_table.install_local();
        self.igmp_router.enable();
        self.mld_router.enable();
    }

    /// Disable multicast routing (mrt_done): stop the membership trackers.
    ///
    /// The VIF table and MFC cache are retained (Linux leaves the tables in
    /// place across `mrt_done`); a later `mrt_init` re-enables forwarding.
    pub fn done(&mut self) {
        self.igmp_router.disable();
        self.mld_router.disable();
    }

    /// Add a virtual interface from an ABI definition.  Returns the assigned
    /// VIF index.
    pub fn add_vif(&mut self, def: &MrtVifDef) -> Result<u32> {
        self.vif_table.add(def)
    }

    /// Remove the virtual interface at `index`.  The local VIF 0 cannot be
    /// removed.
    pub fn del_vif(&mut self, index: u32) -> Result<()> {
        if index == VIF_LOCAL {
            return Err(Error::InvalidArgument);
        }
        if !self.vif_table.remove(index) {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Add a multicast forwarding-cache entry from an ABI definition.
    pub fn add_mfc(&mut self, def: &MrtMfcDef) -> Result<()> {
        self.mfc_cache.add(def, 0)
    }

    /// Remove the multicast forwarding-cache entry for `(source, group)`.
    pub fn del_mfc(&mut self, source: IpAddress, group: IpAddress) -> Result<()> {
        if !self.mfc_cache.remove(source, group) {
            return Err(Error::NotFound);
        }
        Ok(())
    }
}
