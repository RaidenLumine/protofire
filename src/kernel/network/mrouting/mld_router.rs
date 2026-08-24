//! src/kernel/network/mrouting/mld_router.rs
//!
//! MLDv1 router mode (RFC 2710): track IPv6 multicast listener membership
//! per VIF from MLD Reports, remove on Done, and emit periodic General
//! Queries.  Mirrors [`super::igmp_router::IgmpRouterState`] for IPv6.

use alloc::collections::btree_map::BTreeMap;

use crate::kernel::network::internet::ipv6::Ipv6Addr;

/// Default General Query interval: 125 seconds at 100 Hz.
pub const DEFAULT_QUERY_INTERVAL_TICKS: u64 = 12_500;
/// Listener timeout: 2 × query interval.
pub const LISTENER_TIMEOUT_TICKS: u64 = 25_000;

/// MLDv1 router state.
#[derive(Default)]
pub struct MldRouterState {
    pub enabled: bool,
    /// VIF index → multicast group → last report tick.
    pub ifcs: BTreeMap<u32, BTreeMap<Ipv6Addr, u64>>,
    pub query_interval_ticks: u64,
    last_query_tick: u64,
}

impl MldRouterState {
    pub fn new() -> Self {
        Self {
            enabled: false,
            ifcs: BTreeMap::new(),
            query_interval_ticks: DEFAULT_QUERY_INTERVAL_TICKS,
            // Sentinel "never queried": a fresh router sends an immediate
            // General Query on startup (RFC 3810 §6).
            last_query_tick: u64::MAX,
        }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
        self.ifcs.clear();
    }

    pub fn on_report(&mut self, vif: u32, group: Ipv6Addr, tick: u64) {
        self.ifcs.entry(vif).or_default().insert(group, tick);
    }

    pub fn on_done(&mut self, vif: u32, group: Ipv6Addr) {
        if let Some(groups) = self.ifcs.get_mut(&vif) {
            groups.remove(&group);
        }
    }

    pub fn is_local_member(&self, group: Ipv6Addr) -> bool {
        self.ifcs.values().any(|groups| groups.contains_key(&group))
    }

    pub fn should_send_general_query(&mut self, tick: u64) -> bool {
        if !self.enabled {
            return false;
        }
        if self.last_query_tick == u64::MAX
            || tick.wrapping_sub(self.last_query_tick) >= self.query_interval_ticks
        {
            self.last_query_tick = tick;
            true
        } else {
            false
        }
    }

    pub fn expire(&mut self, tick: u64) {
        for groups in self.ifcs.values_mut() {
            groups.retain(|_, last| tick.wrapping_sub(*last) < LISTENER_TIMEOUT_TICKS);
        }
        self.ifcs.retain(|_, groups| !groups.is_empty());
    }

    pub fn group_count(&self) -> usize {
        self.ifcs.values().map(|g| g.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(byte: u8) -> Ipv6Addr {
        let mut g = [0u8; 16];
        g[0] = 0xff;
        g[1] = 0x02;
        g[15] = byte;
        g
    }

    #[test]
    fn report_done_and_membership() {
        let mut state = MldRouterState::new();
        state.enable();
        let g = group(9);
        assert!(!state.is_local_member(g));
        state.on_report(0, g, 50);
        assert!(state.is_local_member(g));
        state.on_done(0, g);
        assert!(!state.is_local_member(g));
    }

    #[test]
    fn general_query_interval() {
        let mut state = MldRouterState::new();
        state.enable();
        assert!(state.should_send_general_query(0));
        assert!(!state.should_send_general_query(state.query_interval_ticks - 1));
        assert!(state.should_send_general_query(state.query_interval_ticks));
    }

    #[test]
    fn listener_expires() {
        let mut state = MldRouterState::new();
        state.on_report(0, group(7), 100);
        state.expire(100 + LISTENER_TIMEOUT_TICKS + 1);
        assert_eq!(state.group_count(), 0);
    }
}
