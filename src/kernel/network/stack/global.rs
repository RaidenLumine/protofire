//! src/kernel/network/stack/global.rs
//!
//! Global singleton, initialisation, and teardown for [`NetworkStack`].

use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;

#[cfg(not(test))]
use core::sync::atomic::AtomicPtr;
#[cfg(not(test))]
use core::sync::atomic::Ordering;

use crate::kernel::network::internet::fragments::FragmentCache;
use crate::kernel::network::internet::fragments::Ipv6FragmentCache;
use crate::kernel::network::internet::igmp::IgmpState;
use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::internet::ipv6;
use crate::kernel::network::internet::mld::MldState;
use crate::kernel::network::internet::nat::NatTable;
use crate::kernel::network::link::device::NetworkDevice;
use crate::kernel::network::mdns::MdnsResponder;
use crate::kernel::network::net_profiler::NetProfiler;
use crate::kernel::network::ntp::NtpClient;
use crate::kernel::network::ppp::PppState;

use super::routing::RoutingTable;
use super::NetworkStack;

/// The global network stack singleton.
///
/// On bare-metal this is initialised once during boot and never dropped.
/// On host (test) builds the caller is responsible for cleanup between
/// tests via [`uninstall_global`].
///
/// In test mode the slot is thread-local so parallel test threads get
/// independent stack instances.  Process-wide synchronisation is
/// unnecessary because the test runner isolates threads via `catch_unwind`.
#[cfg(not(test))]
static GLOBAL_STACK: AtomicPtr<NetworkStack> = AtomicPtr::new(core::ptr::null_mut());

#[cfg(test)]
std::thread_local! {
    static GLOBAL_STACK: core::cell::Cell<*mut NetworkStack> =
        const { core::cell::Cell::new(core::ptr::null_mut()) };
}

#[cfg(not(test))]
fn load_global_stack() -> *mut NetworkStack {
    GLOBAL_STACK.load(Ordering::Acquire)
}

#[cfg(test)]
fn load_global_stack() -> *mut NetworkStack {
    GLOBAL_STACK.with(|slot| slot.get())
}

#[cfg(not(test))]
fn swap_global_stack(new: *mut NetworkStack) -> *mut NetworkStack {
    GLOBAL_STACK.swap(new, Ordering::Release)
}

#[cfg(test)]
fn swap_global_stack(new: *mut NetworkStack) -> *mut NetworkStack {
    GLOBAL_STACK.with(|slot| {
        let old = slot.get();
        slot.set(new);
        old
    })
}

impl NetworkStack {
    /// Create and install the global network stack.
    ///
    /// # Panics
    /// Panics if a stack is already installed (double-init is a kernel bug).
    pub fn init_with_device(device: Arc<dyn NetworkDevice>, local_ip: Ipv4Addr) {
        let mac = device.mac_address();
        let device_mtu = device.mtu() as u64;
        let link_local_v6 = ipv6::link_local_from_mac(mac);
        let stack = Box::new(NetworkStack {
            device,
            local_ip: crate::util::sync_unsafe_cell::SyncUnsafeCell::new(local_ip),
            local_mac: mac,
            // Sensible defaults for QEMU user-mode networking; DHCP
            // will overwrite these when it negotiates a lease.
            dns_server: crate::util::sync_unsafe_cell::SyncUnsafeCell::new([10, 0, 2, 3]),
            subnet_mask: crate::util::sync_unsafe_cell::SyncUnsafeCell::new([255, 255, 255, 0]),
            gateway: crate::util::sync_unsafe_cell::SyncUnsafeCell::new([10, 0, 2, 2]),
            arp_cache: crate::kernel::sync::Mutex::new(
                crate::kernel::network::internet::arp::ArpCache::new(),
            ),
            tcp_table: crate::kernel::sync::Mutex::new(
                crate::kernel::network::tcp::TcpConnectionTable::new(),
            ),
            udp_table: crate::kernel::sync::Mutex::new(
                crate::kernel::network::udp::UdpSocketTable::new(),
            ),
            dccp_table: crate::kernel::sync::Mutex::new(
                crate::kernel::network::dccp::DccpConnectionTable::new(),
            ),
            ipsec_spd: crate::kernel::sync::Mutex::new(
                crate::kernel::network::ipsec::IpsecSpd::new(),
            ),
            ipsec_sad: crate::kernel::sync::Mutex::new(
                crate::kernel::network::ipsec::IpsecSad::new(),
            ),
            mrt: crate::kernel::sync::Mutex::new(crate::kernel::network::mrouting::MrtState::new()),
            ticks: core::sync::atomic::AtomicU64::new(0),
            #[cfg(target_os = "none")]
            dhcp_lease: crate::kernel::sync::Mutex::new(None),
            #[cfg(target_os = "none")]
            dhcp_lease_started_at: crate::kernel::sync::Mutex::new(0),
            #[cfg(target_os = "none")]
            dhcp_renew_state: crate::kernel::sync::Mutex::new(
                crate::kernel::network::dhcp::LeaseState::Bound,
            ),
            profiler: NetProfiler::default(),
            // IPv6 fields
            local_ip_v6: link_local_v6,
            global_ip_v6: crate::kernel::sync::Mutex::new(None),
            neighbor_cache_v6: crate::kernel::sync::Mutex::new(
                crate::kernel::network::internet::icmpv6::NeighborCache::new(),
            ),
            router_lifetime_v6: core::sync::atomic::AtomicU64::new(0),
            reachable_time_v6: core::sync::atomic::AtomicU64::new(0),
            retrans_timer_v6: core::sync::atomic::AtomicU64::new(0),
            router_mac_v6: crate::kernel::sync::Mutex::new(None),
            dad_conflict: core::sync::atomic::AtomicBool::new(false),
            pmtu_cache_v6: crate::kernel::sync::Mutex::new(
                crate::kernel::network::internet::pmtu::PmtuCache::new(),
            ),
            link_mtu_v6: core::sync::atomic::AtomicU64::new(device_mtu),
            // IPv6 fields
            // Phase 4 fields
            fragment_cache: crate::kernel::sync::Mutex::new(FragmentCache::new()),
            routing_table: crate::kernel::sync::Mutex::new(RoutingTable::new()),
            igmp_state: crate::kernel::sync::Mutex::new(IgmpState::new()),
            mld_state: crate::kernel::sync::Mutex::new(MldState::new()),
            raw_sockets: crate::kernel::sync::Mutex::new(BTreeMap::new()),
            next_raw_socket_id: core::sync::atomic::AtomicU64::new(1),
            nat_table: crate::kernel::sync::Mutex::new(NatTable::new()),
            ipv6_fragment_cache: crate::kernel::sync::Mutex::new(Ipv6FragmentCache::new()),
            ntp_client: crate::kernel::sync::Mutex::new(NtpClient::new(
                "pool.ntp.org",
                crate::kernel::network::dhcp::TICKS_PER_SECOND,
            )),
            last_ntp_poll: core::sync::atomic::AtomicU64::new(0),
            mdns_responder: crate::kernel::sync::Mutex::new(MdnsResponder::new("adastra")),
            ppp_state: crate::kernel::sync::Mutex::new(PppState::new()),
            filter_table: crate::kernel::sync::Mutex::new(
                crate::kernel::network::filter::PacketFilter::new(),
            ),
        });

        let ptr = Box::into_raw(stack);
        let prev = swap_global_stack(ptr);
        assert!(
            prev.is_null(),
            "NetworkStack double-init: a global stack is already installed"
        );

        // Announce our IP→MAC mapping to the local network segment.
        // Only in production — tests exercise send_gratuitous_arp directly.
        // Failure is non-fatal: the stack works even without GARP.
        #[cfg(not(test))]
        {
            let stack_ref = unsafe { ptr.as_ref().expect("just allocated") };
            let _ = crate::kernel::network::internet::arp::send_gratuitous_arp(stack_ref);
        }
    }

    /// Return a reference to the global network stack, or `None` if not yet
    /// initialised.
    pub fn global() -> Option<&'static NetworkStack> {
        // Safety: the pointer is either null or was initialised by
        // `init_with_device` and remains valid for the kernel lifetime.
        unsafe { load_global_stack().as_ref() }
    }

    /// Remove the global stack.  Only meaningful in test builds; on
    /// bare-metal the stack lives forever.
    ///
    /// # Safety
    /// Caller must ensure no concurrent access to the stack is in flight.
    #[cfg(test)]
    pub unsafe fn uninstall_global() {
        let ptr = swap_global_stack(core::ptr::null_mut());
        if !ptr.is_null() {
            // Re-box and drop so the raw pointer is properly freed.
            let _ = Box::from_raw(ptr);
        }
    }
}

// Safety: NetworkStack is only accessed through the global AtomicPtr on
// bare-metal (single-consumer poll path, mutex-guarded protocol tables).
// Host tests may use multiple threads but all mutable state is behind
// Mutex or Atomic.
unsafe impl Send for NetworkStack {}
unsafe impl Sync for NetworkStack {}
