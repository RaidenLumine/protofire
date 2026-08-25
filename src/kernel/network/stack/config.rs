//! src/kernel/network/stack/config.rs
//!
//! Accessors for the network device, protocol tables, ticks, and
//! IPv4 / IPv6 addressing configuration.

use alloc::collections::btree_map::BTreeMap;

use crate::kernel::network::dccp::DccpConnectionTable;
use crate::kernel::network::filter::PacketFilter;
use crate::kernel::network::internet::icmpv6::NeighborCache;
use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::internet::ipv6::Ipv6Addr;
use crate::kernel::network::internet::mld::MldState;
use crate::kernel::network::internet::pmtu::PmtuCache;
use crate::kernel::network::ipsec::IpsecSad;
use crate::kernel::network::ipsec::IpsecSpd;
use crate::kernel::network::link::device::NetworkDevice;
use crate::kernel::network::link::ethernet;
use crate::kernel::network::mdns::MdnsResponder;
use crate::kernel::network::mrouting::MrtState;
use crate::kernel::network::ntp::NtpClient;
use crate::kernel::network::ppp::PppState;
use crate::kernel::network::raw::RawSocket;

use crate::kernel::network::internet::arp::ArpCache;
use crate::kernel::network::internet::fragments::FragmentCache;
use crate::kernel::network::internet::fragments::Ipv6FragmentCache;
use crate::kernel::network::internet::igmp::IgmpState;
use crate::kernel::network::internet::nat::NatTable;
use crate::kernel::network::stack::routing::RoutingTable;
use crate::kernel::network::tcp::TcpConnectionTable;
use crate::kernel::network::udp::UdpSocketTable;
use crate::kernel::sync::Mutex;
use core::sync::atomic::Ordering;

use super::NetworkStack;

impl NetworkStack {
    /// Return a reference to the underlying network device.
    pub fn device(&self) -> &dyn NetworkDevice {
        &*self.device
    }

    /// Return the device MTU for MSS calculation.
    pub(crate) fn mtu(&self) -> usize {
        self.device.mtu()
    }

    /// Return a reference to the ARP cache.
    pub fn arp_cache(&self) -> &Mutex<ArpCache> {
        &self.arp_cache
    }

    /// Return a reference to the TCP connection table.
    pub fn tcp_table(&self) -> &Mutex<TcpConnectionTable> {
        &self.tcp_table
    }

    /// Return a reference to the UDP socket table.
    pub fn udp_table(&self) -> &Mutex<UdpSocketTable> {
        &self.udp_table
    }

    /// Return the current tick count.
    pub fn current_tick(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    /// Update the stack's local IP address and announce the new binding
    /// via a gratuitous ARP request.
    ///
    /// # Safety
    ///
    /// This writes through a shared reference via `SyncUnsafeCell`.  The write
    /// is safe because DHCP runs during boot before any concurrent readers
    /// exist.
    pub fn set_ip(&self, new_ip: Ipv4Addr) {
        // SAFETY: `local_ip` is only mutated during boot-time DHCP, before
        // any concurrent readers exist.  After boot the field is read-only.
        unsafe {
            self.local_ip.write(new_ip);
        }
        // Announce the new IP→MAC mapping to the local network segment.
        // Failure is non-fatal: the stack works even without GARP.
        let _ = crate::kernel::network::internet::arp::send_gratuitous_arp(self);
    }

    /// Return our local IPv4 address.
    pub fn local_ip(&self) -> Ipv4Addr {
        // SAFETY: single-threaded kernel; no concurrent write can be in flight
        // when this read executes.
        unsafe { self.local_ip.read() }
    }

    /// Return the configured DNS server address.
    pub fn dns_server(&self) -> Ipv4Addr {
        // SAFETY: single-threaded kernel.
        unsafe { self.dns_server.read() }
    }

    /// Update the DNS server address (e.g. from DHCP lease).
    ///
    /// See [`set_ip`] for the interior-mutability rationale.
    pub fn set_dns_server(&self, addr: Ipv4Addr) {
        // SAFETY: only written during boot-time DHCP.
        unsafe {
            self.dns_server.write(addr);
        }
    }

    /// Return the configured subnet mask.
    pub fn subnet_mask(&self) -> Ipv4Addr {
        // SAFETY: single-threaded kernel.
        unsafe { self.subnet_mask.read() }
    }

    /// Update the subnet mask (e.g. from DHCP lease).
    pub fn set_subnet_mask(&self, mask: Ipv4Addr) {
        // SAFETY: only written during boot-time DHCP.
        unsafe {
            self.subnet_mask.write(mask);
        }
    }

    /// Return the configured default gateway.
    pub fn gateway(&self) -> Ipv4Addr {
        // SAFETY: single-threaded kernel.
        unsafe { self.gateway.read() }
    }

    /// Update the default gateway (e.g. from DHCP lease).
    pub fn set_gateway(&self, gw: Ipv4Addr) {
        // SAFETY: only written during boot-time DHCP.
        unsafe {
            self.gateway.write(gw);
        }
    }

    // ─── IPv6 address accessors ─────────────────────────────────────

    /// Return our IPv6 link-local address (derived from MAC at init).
    pub fn local_ip_v6(&self) -> Ipv6Addr {
        self.local_ip_v6
    }

    /// Return our IPv6 global unicast address, if configured by SLAAC.
    pub fn global_ip_v6(&self) -> Option<Ipv6Addr> {
        self.global_ip_v6.lock().map(|(addr, _, _)| addr)
    }

    /// Set the global IPv6 address with valid and preferred lifetimes
    /// (in seconds).  Called when a Router Advertisement with a valid
    /// Prefix Information option is received.
    pub fn set_global_ip_v6(&self, addr: Ipv6Addr, valid_lifetime: u32, preferred_lifetime: u32) {
        *self.global_ip_v6.lock() = Some((addr, valid_lifetime, preferred_lifetime));
    }

    /// Clear the global IPv6 address (on DAD failure or lease expiry).
    pub fn clear_global_ip_v6(&self) {
        *self.global_ip_v6.lock() = None;
    }

    /// Return a reference to the IPv6 neighbor cache.
    pub fn neighbor_cache_v6(&self) -> &Mutex<NeighborCache> {
        &self.neighbor_cache_v6
    }

    /// Return the router lifetime from the most recent RA (seconds).
    pub fn router_lifetime_v6(&self) -> u64 {
        self.router_lifetime_v6.load(Ordering::Relaxed)
    }

    /// Update the router lifetime (e.g. from an RA).
    pub fn set_router_lifetime_v6(&self, lifetime: u16) {
        self.router_lifetime_v6
            .store(lifetime as u64, Ordering::Relaxed);
    }

    /// Return the reachable time from the most recent RA (ms).
    pub fn reachable_time_v6(&self) -> u64 {
        self.reachable_time_v6.load(Ordering::Relaxed)
    }

    /// Update the reachable time (e.g. from an RA).
    pub fn set_reachable_time_v6(&self, time_ms: u64) {
        self.reachable_time_v6.store(time_ms, Ordering::Relaxed);
    }

    /// Return the retransmit timer from the most recent RA (ms).
    pub fn retrans_timer_v6(&self) -> u64 {
        self.retrans_timer_v6.load(Ordering::Relaxed)
    }

    /// Update the retransmit timer (e.g. from an RA).
    pub fn set_retrans_timer_v6(&self, time_ms: u64) {
        self.retrans_timer_v6.store(time_ms, Ordering::Relaxed);
    }

    /// Return the router MAC from the most recent RA, if any.
    pub fn router_mac_v6(&self) -> Option<[u8; 6]> {
        *self.router_mac_v6.lock()
    }

    /// Store the router MAC (from an RA source link-layer address option).
    pub fn set_router_mac_v6(&self, mac: ethernet::MacAddress) {
        *self.router_mac_v6.lock() = Some(mac.0);
    }

    /// Check and clear the DAD conflict flag.
    pub fn dad_conflict_detected(&self) -> bool {
        self.dad_conflict.swap(false, Ordering::Relaxed)
    }

    /// Clear the DAD conflict flag.
    pub fn clear_dad_conflict(&self) {
        self.dad_conflict.store(false, Ordering::Relaxed);
    }

    // ─── Protocol tables and Phase-4 state ─────────────────────────

    /// Return a reference to the DCCP connection table.
    pub fn dccp_table(&self) -> &Mutex<DccpConnectionTable> {
        &self.dccp_table
    }

    /// Return a reference to the IPsec security policy database.
    pub fn ipsec_spd(&self) -> &Mutex<IpsecSpd> {
        &self.ipsec_spd
    }

    /// Return a reference to the IPsec security association database.
    pub fn ipsec_sad(&self) -> &Mutex<IpsecSad> {
        &self.ipsec_sad
    }

    /// Return a reference to the multicast routing state.
    pub fn mrt(&self) -> &Mutex<MrtState> {
        &self.mrt
    }

    /// Return a reference to the IPv4 reassembly buffer cache.
    pub fn fragment_cache(&self) -> &Mutex<FragmentCache> {
        &self.fragment_cache
    }

    /// Return a reference to the IPv6 reassembly buffer cache.
    pub fn ipv6_fragment_cache(&self) -> &Mutex<Ipv6FragmentCache> {
        &self.ipv6_fragment_cache
    }

    /// Return a reference to the routing table.
    pub fn routing_table(&self) -> &Mutex<RoutingTable> {
        &self.routing_table
    }

    /// Return a reference to the IGMPv2 host membership state.
    pub fn igmp_state(&self) -> &Mutex<IgmpState> {
        &self.igmp_state
    }

    /// Return a reference to the MLDv1 host membership state.
    pub fn mld_state(&self) -> &Mutex<MldState> {
        &self.mld_state
    }

    /// Return a reference to the NAT table.
    pub fn nat_table(&self) -> &Mutex<NatTable> {
        &self.nat_table
    }

    /// Return a reference to the raw socket table.
    pub fn raw_sockets(&self) -> &Mutex<BTreeMap<u32, RawSocket>> {
        &self.raw_sockets
    }

    /// Allocate a fresh raw socket id.
    ///
    /// The id is a monotonically increasing `u32` (wrapping in the extremely
    /// unlikely event of a rollover) and 0 is never handed out.
    pub(crate) fn alloc_raw_socket_id(&self) -> u32 {
        self.next_raw_socket_id.fetch_add(1, Ordering::Relaxed) as u32
    }

    /// Return a reference to the NTP client.
    pub fn ntp_client(&self) -> &Mutex<NtpClient> {
        &self.ntp_client
    }

    /// Return a reference to the mDNS responder.
    pub fn mdns_responder(&self) -> &Mutex<MdnsResponder> {
        &self.mdns_responder
    }

    /// Return a reference to the PPP session state.
    pub fn ppp_state(&self) -> &Mutex<PppState> {
        &self.ppp_state
    }

    /// Return a reference to the packet filter table.
    pub fn filter_table(&self) -> &Mutex<PacketFilter> {
        &self.filter_table
    }

    /// Return the IPv6 link MTU learned from Router Advertisements.
    pub fn link_mtu_v6(&self) -> u64 {
        self.link_mtu_v6.load(Ordering::Relaxed)
    }

    /// Record the IPv6 link MTU advertised by a Router Advertisement
    /// (RFC 4861 §6.3.4).  Callers must reject values below `IPV6_MIN_MTU`.
    pub fn set_link_mtu_v6(&self, mtu: u16) {
        self.link_mtu_v6.store(mtu as u64, Ordering::Relaxed);
    }

    /// Return a reference to the IPv6 path MTU cache.
    pub fn pmtu_cache_v6(&self) -> &Mutex<PmtuCache> {
        &self.pmtu_cache_v6
    }
}
