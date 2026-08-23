//! src/kernel/network/stack/routing.rs
//! IPv4 routing table with longest-prefix-match lookup.
//!
//! Stores a set of `(destination, netmask, gateway, metric)` entries and
//! resolves the best route for a given destination IP.  The gateway IP is
//! used for ARP resolution instead of directly resolving the destination.

use alloc::vec::Vec;

use crate::kernel::network::internet::ipv4::Ipv4Addr;

// ─── Route entry ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// Network or host destination.
    pub destination: Ipv4Addr,
    /// Subnet mask (255.255.255.255 for host routes).
    pub netmask: Ipv4Addr,
    /// Next-hop gateway (0.0.0.0 for directly-connected routes).
    pub gateway: Ipv4Addr,
    /// Route metric (lower = preferred).
    pub metric: u32,
}

impl RouteEntry {
    /// Create a new host route (netmask = 255.255.255.255).
    pub fn host(destination: Ipv4Addr, gateway: Ipv4Addr) -> Self {
        Self {
            destination,
            netmask: [255, 255, 255, 255],
            gateway,
            metric: 0,
        }
    }

    /// Create a new network route.
    pub fn network(destination: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> Self {
        Self {
            destination,
            netmask,
            gateway,
            metric: 0,
        }
    }

    /// Set route metric.  Builder pattern.
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = metric;
        self
    }

    /// Check whether `addr` matches this route.
    pub fn matches(&self, addr: Ipv4Addr) -> bool {
        let masked_dst = [
            self.destination[0] & self.netmask[0],
            self.destination[1] & self.netmask[1],
            self.destination[2] & self.netmask[2],
            self.destination[3] & self.netmask[3],
        ];
        let masked_addr = [
            addr[0] & self.netmask[0],
            addr[1] & self.netmask[1],
            addr[2] & self.netmask[2],
            addr[3] & self.netmask[3],
        ];
        masked_dst == masked_addr
    }

    /// Return the prefix length (number of leading 1 bits in netmask).
    pub fn prefix_len(&self) -> u32 {
        let mut bits: u32 = 0;
        for octet in self.netmask {
            bits += octet.count_ones();
        }
        bits
    }
}

// ─── Routing table ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RoutingTable {
    entries: Vec<RouteEntry>,
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a route entry.  If an entry with the same (destination, netmask)
    /// already exists it is replaced.
    pub fn add(&mut self, entry: RouteEntry) {
        self.entries
            .retain(|e| !(e.destination == entry.destination && e.netmask == entry.netmask));
        self.entries.push(entry);
    }

    /// Remove all routes matching `destination` and `netmask`.
    pub fn remove(&mut self, destination: Ipv4Addr, netmask: Ipv4Addr) {
        self.entries
            .retain(|e| !(e.destination == destination && e.netmask == netmask));
    }

    /// Look up the best route for `addr` using longest-prefix-match.
    ///
    /// Returns `Some((gateway, prefix_len))` where `gateway` is the
    /// next-hop IP to ARP-resolve, and `prefix_len` is the number of
    /// matching bits (for diagnostics).
    ///
    /// If `gateway` is 0.0.0.0 the destination is directly reachable and
    /// the caller should ARP-resolve `addr` directly.
    ///
    /// Returns `None` if no route matches.
    pub fn lookup(&self, addr: Ipv4Addr) -> Option<(Ipv4Addr, u32)> {
        let mut best: Option<&RouteEntry> = None;
        let mut best_prefix_len: u32 = 0;
        let mut best_metric: u32 = u32::MAX;

        for entry in &self.entries {
            if entry.matches(addr) {
                let prefix_len = entry.prefix_len();
                if prefix_len > best_prefix_len
                    || (prefix_len == best_prefix_len && entry.metric < best_metric)
                {
                    best = Some(entry);
                    best_prefix_len = prefix_len;
                    best_metric = entry.metric;
                }
            }
        }

        best.map(|e| (e.gateway, best_prefix_len))
    }

    /// Install the default route from the DHCP lease or static configuration.
    ///
    /// gateway = 0.0.0.0 means "no gateway configured" and installs a
    /// directly-connected route for our subnet instead.
    pub fn install_default(
        &mut self,
        local_ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        gateway: Ipv4Addr,
    ) {
        // Remove any previous default and subnet routes.
        let subnet = [
            local_ip[0] & subnet_mask[0],
            local_ip[1] & subnet_mask[1],
            local_ip[2] & subnet_mask[2],
            local_ip[3] & subnet_mask[3],
        ];
        self.entries.retain(|e| {
            !(e.destination == [0, 0, 0, 0] && e.netmask == [0, 0, 0, 0]
                || e.destination == subnet && e.netmask == subnet_mask)
        });

        if gateway != [0, 0, 0, 0] {
            // Default route via gateway.
            self.add(RouteEntry {
                destination: [0, 0, 0, 0],
                netmask: [0, 0, 0, 0],
                gateway,
                metric: 0,
            });
        }

        // Always install a directly-connected subnet route.
        let subnet = [
            local_ip[0] & subnet_mask[0],
            local_ip[1] & subnet_mask[1],
            local_ip[2] & subnet_mask[2],
            local_ip[3] & subnet_mask[3],
        ];
        self.add(RouteEntry {
            destination: subnet,
            netmask: subnet_mask,
            gateway: [0, 0, 0, 0],
            metric: 1, // slightly higher metric than default via gateway
        });
    }

    /// Return the number of entries in the table.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_match_prefers_specific_route() {
        let mut table = RoutingTable::new();
        table.add(RouteEntry::network(
            [10, 0, 0, 0],
            [255, 0, 0, 0],
            [10, 0, 0, 1],
        ));
        table.add(RouteEntry::network(
            [10, 0, 2, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
        ));

        let (gw, prefix) = table.lookup([10, 0, 2, 15]).expect("should match");
        assert_eq!(gw, [0, 0, 0, 0]);
        assert_eq!(prefix, 24);
    }

    #[test]
    fn default_route_matches_everything() {
        let mut table = RoutingTable::new();
        table.add(RouteEntry {
            destination: [0, 0, 0, 0],
            netmask: [0, 0, 0, 0],
            gateway: [192, 168, 1, 1],
            metric: 0,
        });

        let (gw, _) = table
            .lookup([8, 8, 8, 8])
            .expect("should match via default");
        assert_eq!(gw, [192, 168, 1, 1]);
    }

    #[test]
    fn no_match_returns_none() {
        let table = RoutingTable::new();
        assert!(table.lookup([10, 0, 0, 1]).is_none());
    }

    #[test]
    fn host_route_overrides_network_route() {
        let mut table = RoutingTable::new();
        table.add(RouteEntry::network(
            [10, 0, 0, 0],
            [255, 255, 255, 0],
            [10, 0, 0, 1],
        ));
        table.add(RouteEntry::host([10, 0, 0, 55], [10, 0, 0, 99]));

        let (gw, prefix) = table.lookup([10, 0, 0, 55]).expect("should match");
        assert_eq!(gw, [10, 0, 0, 99]);
        assert_eq!(prefix, 32); // /32 host route
    }

    #[test]
    fn install_default_sets_subnet_and_default_routes() {
        let mut table = RoutingTable::new();
        table.install_default([10, 0, 2, 15], [255, 255, 255, 0], [10, 0, 2, 2]);
        // Should have at least: default route and subnet route.
        assert!(table.len() >= 2);

        // Subnet-local access should be direct (gateway = 0.0.0.0).
        let (gw, _) = table.lookup([10, 0, 2, 99]).expect("subnet match");
        assert_eq!(gw, [0, 0, 0, 0]);

        // External access should go via gateway.
        let (gw2, _) = table.lookup([8, 8, 8, 8]).expect("default match");
        assert_eq!(gw2, [10, 0, 2, 2]);
    }

    #[test]
    fn install_default_without_gateway_only_installs_subnet_route() {
        let mut table = RoutingTable::new();
        table.install_default([10, 0, 2, 15], [255, 255, 255, 0], [0, 0, 0, 0]);
        // External access should fail.
        assert!(table.lookup([8, 8, 8, 8]).is_none());
        // Subnet access should be direct.
        assert_eq!(table.lookup([10, 0, 2, 99]), Some(([0, 0, 0, 0], 24)));
    }
}
