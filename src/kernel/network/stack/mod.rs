//! src/kernel/network/stack/mod.rs
//!
//! `NetworkStack` — global singleton that owns the network device and
//! orchestrates protocol-layer dispatch (Ethernet → IPv4 / IPv6 → transport).
//!
//! Sub-module organisation:
//! - `global`    — Global singleton, initialisation, uninstall
//! - `config`    — Accessors: device, tables, ticks, IPv4/IPv6 addressing
//! - `dhcp`      — DHCP lease management (bare-metal only)
//! - `dispatch`  — Tick maintenance, polling, and protocol demux
//! - `send`      — Packet transmission (IPv4 unicast/broadcast, IPv6 unicast)

use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64};

use crate::kernel::network::dccp::DccpConnectionTable;
use crate::kernel::network::filter::PacketFilter;
use crate::kernel::network::internet::arp::ArpCache;
use crate::kernel::network::internet::fragments::{FragmentCache, Ipv6FragmentCache};
use crate::kernel::network::internet::icmpv6::NeighborCache;
use crate::kernel::network::internet::igmp::IgmpState;
use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::internet::ipv6::Ipv6Addr;
use crate::kernel::network::internet::mld::MldState;
use crate::kernel::network::internet::nat::NatTable;
use crate::kernel::network::internet::pmtu::PmtuCache;
use crate::kernel::network::ipsec::{IpsecSad, IpsecSpd};
use crate::kernel::network::link::device::NetworkDevice;
use crate::kernel::network::mdns::MdnsResponder;
use crate::kernel::network::mrouting::MrtState;
use crate::kernel::network::net_profiler::NetProfiler;
use crate::kernel::network::ntp::NtpClient;
use crate::kernel::network::ppp::PppState;
use crate::kernel::network::raw::RawSocket;
use crate::kernel::network::stack::routing::RoutingTable;
use crate::kernel::network::tcp::TcpConnectionTable;
use crate::kernel::network::udp::UdpSocketTable;
use crate::kernel::sync::Mutex;
use crate::util::sync_unsafe_cell::SyncUnsafeCell;

#[cfg(target_os = "none")]
use crate::kernel::network::dhcp::{DhcpLease, LeaseState};

pub(crate) mod config;
pub(crate) mod dhcp;
pub(crate) mod dispatch;
pub(crate) mod global;
pub(crate) mod routing;
pub(crate) mod send;
#[cfg(test)]
mod tests;

/// Central network stack holding the device handle, local addressing
/// information, per-protocol state, and a tick counter.
pub struct NetworkStack {
    device: Arc<dyn NetworkDevice>,
    /// Our IPv4 address.
    ///
    /// # Safety
    ///
    /// Wrapped in `SyncUnsafeCell` because DHCP writes this during boot while
    /// the field is also read by `poll()` (ICMP replies) and `send_to` (UDP
    /// source).  The kernel is single-threaded so concurrent reads/writes
    /// cannot happen in practice; the `SyncUnsafeCell` merely tells the
    /// compiler about the interior-mutability contract.
    pub local_ip: SyncUnsafeCell<Ipv4Addr>,
    /// Our MAC address (cached from the device at init time).
    pub local_mac: [u8; 6],
    /// DNS server address (configured by DHCP or defaulted to QEMU's
    /// gateway proxy at 10.0.2.3).
    /// Same interior-mutability contract as [`local_ip`](Self::local_ip).
    dns_server: SyncUnsafeCell<Ipv4Addr>,
    /// Subnet mask (configured by DHCP or defaulted to /24).
    /// Same interior-mutability contract as [`local_ip`](Self::local_ip).
    subnet_mask: SyncUnsafeCell<Ipv4Addr>,
    /// Default gateway (configured by DHCP or defaulted to 10.0.2.2).
    /// Same interior-mutability contract as [`local_ip`](Self::local_ip).
    gateway: SyncUnsafeCell<Ipv4Addr>,
    /// ARP cache (IPv4 → MAC) with tick-based TTL.
    arp_cache: Mutex<ArpCache>,
    /// TCP connection table (keyed by local port).
    tcp_table: Mutex<TcpConnectionTable>,
    /// UDP socket table (keyed by local port).
    udp_table: Mutex<UdpSocketTable>,
    /// Monotonically increasing tick counter (100 Hz).  Used by ARP cache
    /// expiry and TCP retransmission timers, and DHCP lease renewal.
    ticks: AtomicU64,
    /// DHCP lease obtained at boot (and renewed thereafter).  `None` until
    /// a lease is acquired or when operating with a static IP.
    #[cfg(target_os = "none")]
    dhcp_lease: Mutex<Option<DhcpLease>>,
    /// Ticks at which the current lease was acquired / last renewed.
    #[cfg(target_os = "none")]
    dhcp_lease_started_at: Mutex<u64>,
    /// Current renewal state (Bound / Renewing / Rebinding / Expired).
    #[cfg(target_os = "none")]
    dhcp_renew_state: Mutex<LeaseState>,
    /// Network stack operation profiler (zero-cost when `net_profiler`
    /// feature is disabled).
    pub profiler: NetProfiler,
    // ── IPv6 fields ──────────────────────────────────────────────────
    /// Our IPv6 link-local address (derived from MAC at init time).
    local_ip_v6: Ipv6Addr,
    /// Our IPv6 global unicast address (configured by SLAAC).  `None`
    /// until a Router Advertisement with a valid prefix is processed.
    global_ip_v6: Mutex<Option<(Ipv6Addr, u32, u32)>>,
    //                               addr    valid pref
    /// Neighbor cache (IPv6 → MAC) with reachability states.
    neighbor_cache_v6: Mutex<NeighborCache>,
    /// Router lifetime from the most recent RA (in seconds).  0 means
    /// no router is available.
    router_lifetime_v6: AtomicU64,
    /// Reachable time from the most recent RA (in ms).
    reachable_time_v6: AtomicU64,
    /// Retransmit timer from the most recent RA (in ms).
    retrans_timer_v6: AtomicU64,
    /// Router MAC address from the most recent RA.
    router_mac_v6: Mutex<Option<[u8; 6]>>,
    /// DAD conflict flag — set when a Neighbor Advertisement contests
    /// an address we're trying to configure.
    dad_conflict: AtomicBool,
    // ── Transport / security / multicast routing tables ─────────────
    /// DCCP connection table (keyed by local port).
    dccp_table: Mutex<DccpConnectionTable>,
    /// IPsec security policy database.
    ipsec_spd: Mutex<IpsecSpd>,
    /// IPsec security association database.
    ipsec_sad: Mutex<IpsecSad>,
    /// Multicast routing state (MRT vif/mfc tables + IGMP/MLD routers).
    mrt: Mutex<MrtState>,
    /// Path MTU cache for IPv6 (per-destination).
    pmtu_cache_v6: Mutex<PmtuCache>,
    /// Link MTU for IPv6 learned from Router Advertisements.
    link_mtu_v6: AtomicU64,
    // ── Phase 4 fields ───────────────────────────────────────────────
    /// IPv4 reassembly buffer cache (fragmented datagrams in flight).
    fragment_cache: Mutex<FragmentCache>,
    /// Policy routing table (prefix / gateway / interface).
    routing_table: Mutex<RoutingTable>,
    /// IGMPv2 host membership state (IPv4 multicast groups).
    igmp_state: Mutex<IgmpState>,
    /// MLDv1 host membership state (IPv6 multicast groups).
    mld_state: Mutex<MldState>,
    /// Raw IP sockets, keyed by a monotonically allocated socket id.
    raw_sockets: Mutex<BTreeMap<u32, RawSocket>>,
    /// Next raw socket id (starts at 1; 0 is never handed out).
    next_raw_socket_id: AtomicU64,
    /// NAT table: translation entries keyed by the packet 4-tuple.
    nat_table: Mutex<NatTable>,
    /// IPv6 reassembly buffer cache (fragmented datagrams in flight).
    ipv6_fragment_cache: Mutex<Ipv6FragmentCache>,
    /// NTP client (offset tracking against a configured server).
    ntp_client: Mutex<NtpClient>,
    /// Tick at which the NTP client last issued a poll.
    last_ntp_poll: AtomicU64,
    /// mDNS responder (`.local` probe / announce + query answering).
    mdns_responder: Mutex<MdnsResponder>,
    /// PPP session state (used by stack/ppp.rs).
    ppp_state: Mutex<PppState>,
    /// Packet filter table (firewall rules consulted on ingress).
    filter_table: Mutex<PacketFilter>,
}
