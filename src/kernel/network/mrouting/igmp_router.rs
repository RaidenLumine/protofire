//! src/kernel/network/mrouting/igmp_router.rs
//!
//! IGMPv2 router mode (RFC 2236): track which multicast groups have local
//! members on each VIF (from Membership Reports), expire them on Leave, and
//! periodically emit General Queries to discover members.

use alloc::collections::btree_map::BTreeMap;

use crate::kernel::network::internet::ipv4::Ipv4Addr;

/// Default General Query interval: 125 seconds at 100 Hz.
pub const DEFAULT_QUERY_INTERVAL_TICKS: u64 = 12_500;
/// Membership timeout: 2 × query interval.
pub const MEMBERSHIP_TIMEOUT_TICKS: u64 = 25_000;

/// IGMPv2 router state.
#[derive(Default)]
pub struct IgmpRouterState {
    pub enabled: bool,
    /// VIF index → multicast group → last report tick.
    pub ifcs: BTreeMap<u32, BTreeMap<Ipv4Addr, u64>>,
    pub query_interval_ticks: u64,
    last_query_tick: u64,
}

impl IgmpRouterState {
    pub fn new() -> Self {
        Self {
            enabled: false,
            ifcs: BTreeMap::new(),
            query_interval_ticks: DEFAULT_QUERY_INTERVAL_TICKS,
            // Sentinel "never queried": a fresh router sends an immediate
            // General Query on startup (RFC 2236 §4).
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

    /// Record a Membership Report for `group` on `vif`.
    pub fn on_report(&mut self, vif: u32, group: Ipv4Addr, tick: u64) {
        self.ifcs.entry(vif).or_default().insert(group, tick);
    }

    /// Record a Leave Group for `group` on `vif`.
    pub fn on_leave(&mut self, vif: u32, group: Ipv4Addr) {
        if let Some(groups) = self.ifcs.get_mut(&vif) {
            groups.remove(&group);
        }
    }

    /// Whether any local VIF reports members for `group`.
    pub fn is_local_member(&self, group: Ipv4Addr) -> bool {
        self.ifcs.values().any(|groups| groups.contains_key(&group))
    }

    /// Whether a General Query should be sent now, and advance the timer.
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

    /// Expire group memberships that have not been refreshed within
    /// [`MEMBERSHIP_TIMEOUT_TICKS`].
    pub fn expire(&mut self, tick: u64) {
        for groups in self.ifcs.values_mut() {
            groups.retain(|_, last| tick.wrapping_sub(*last) < MEMBERSHIP_TIMEOUT_TICKS);
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

    #[test]
    fn report_leave_and_membership() {
        let mut state = IgmpRouterState::new();
        state.enable();
        let group = [224, 1, 2, 3];
        assert!(!state.is_local_member(group));
        state.on_report(0, group, 100);
        assert!(state.is_local_member(group));
        state.on_leave(0, group);
        assert!(!state.is_local_member(group));
    }

    #[test]
    fn general_query_interval() {
        let mut state = IgmpRouterState::new();
        state.enable();
        assert!(state.should_send_general_query(0));
        assert!(!state.should_send_general_query(100));
        assert!(!state.should_send_general_query(state.query_interval_ticks - 1));
        assert!(state.should_send_general_query(state.query_interval_ticks));
    }

    #[test]
    fn membership_expires() {
        let mut state = IgmpRouterState::new();
        state.on_report(0, [224, 0, 0, 1], 100);
        state.expire(100 + MEMBERSHIP_TIMEOUT_TICKS + 1);
        assert_eq!(state.group_count(), 0);
    }
}
