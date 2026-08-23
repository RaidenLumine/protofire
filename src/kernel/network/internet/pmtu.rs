//! src/kernel/network/internet/pmtu.rs
//! IPv6 per-destination Path MTU discovery cache (RFC 8201).
//!
//! When an ICMPv6 Packet Too Big (type 2) arrives, the advertised MTU is
//! recorded for the destination that was being sent to.  Outbound IPv6
//! packets are fragmented down to the cached MTU (never below
//! [`IPV6_MIN_MTU`]).  Entries expire after a fixed lifetime so the stack
//! can re-probe larger sizes, matching RFC 8201's periodic raise.

use alloc::collections::btree_map::BTreeMap;

use super::ipv6::{Ipv6Addr, IPV6_MIN_MTU};

/// One cached PMTU entry.
#[derive(Debug, Clone, Copy)]
pub struct PmtuEntry {
    /// Effective path MTU in bytes (never below `IPV6_MIN_MTU`).
    pub mtu: u32,
    /// Tick at which this entry was last updated.
    pub updated_at: u64,
}

/// Per-destination IPv6 path MTU cache.
pub struct PmtuCache {
    entries: BTreeMap<Ipv6Addr, PmtuEntry>,
}

impl Default for PmtuCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PmtuCache {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Return the cached PMTU for `dst`, if any.
    pub fn lookup(&self, dst: Ipv6Addr) -> Option<u32> {
        self.entries.get(&dst).map(|entry| entry.mtu)
    }

    /// Record the path MTU for `dst` from a Packet Too Big message.
    ///
    /// MTUs below [`IPV6_MIN_MTU`] are clamped up to the minimum (RFC 8200
    /// §5): a router must not advertise an unusable link, and treating a
    /// smaller value as the minimum keeps senders on the wire.
    pub fn update_from_ptb(&mut self, dst: Ipv6Addr, mtu: u32, tick: u64) {
        let mtu = mtu.max(IPV6_MIN_MTU as u32);
        self.entries.insert(
            dst,
            PmtuEntry {
                mtu,
                updated_at: tick,
            },
        );
    }

    /// Forget the cached PMTU for `dst` (e.g. when re-probing).
    pub fn remove(&mut self, dst: Ipv6Addr) {
        self.entries.remove(&dst);
    }

    /// Drop entries whose last update is older than `ttl_ticks`.
    pub fn evict_expired(&mut self, tick: u64, ttl_ticks: u64) {
        self.entries
            .retain(|_, entry| tick.wrapping_sub(entry.updated_at) < ttl_ticks);
    }

    /// Number of cached entries.
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

    const DST: Ipv6Addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    #[test]
    fn lookup_returns_none_for_unknown_destination() {
        let cache = PmtuCache::new();
        assert_eq!(cache.lookup(DST), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn update_from_ptb_records_mtu() {
        let mut cache = PmtuCache::new();
        cache.update_from_ptb(DST, 1400, 100);
        assert_eq!(cache.lookup(DST), Some(1400));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn update_clamps_below_minimum_mtu() {
        let mut cache = PmtuCache::new();
        // A router advertising below the IPv6 minimum is clamped up.
        cache.update_from_ptb(DST, 512, 100);
        assert_eq!(cache.lookup(DST), Some(IPV6_MIN_MTU as u32));
    }

    #[test]
    fn update_overwrites_prior_value() {
        let mut cache = PmtuCache::new();
        cache.update_from_ptb(DST, 1400, 100);
        cache.update_from_ptb(DST, 1280, 150);
        assert_eq!(cache.lookup(DST), Some(1280));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn remove_forgets_destination() {
        let mut cache = PmtuCache::new();
        cache.update_from_ptb(DST, 1400, 100);
        cache.remove(DST);
        assert_eq!(cache.lookup(DST), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn evict_expired_drops_old_entries() {
        let mut cache = PmtuCache::new();
        cache.update_from_ptb(DST, 1400, 100);
        assert_eq!(cache.len(), 1);
        cache.evict_expired(100 + 60_000 + 1, 60_000);
        assert!(cache.is_empty());
    }

    #[test]
    fn evict_preserves_fresh_entries() {
        let mut cache = PmtuCache::new();
        cache.update_from_ptb(DST, 1400, 100);
        cache.evict_expired(100 + 30_000, 60_000);
        assert_eq!(cache.len(), 1);
    }
}
