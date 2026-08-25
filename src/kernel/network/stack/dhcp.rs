//! src/kernel/network/stack/dhcp.rs
//!
//! DHCP lease management for [`NetworkStack`] (bare-metal only).

#[cfg(target_os = "none")]
use crate::kernel::network::dhcp::DhcpLease;
#[cfg(target_os = "none")]
use crate::kernel::network::dhcp::LeaseState;

use super::NetworkStack;

impl NetworkStack {
    /// Store a DHCP lease and configure the stack's IP, DNS, gateway, and
    /// subnet mask from it.  Records the current tick as the lease start.
    #[cfg(target_os = "none")]
    pub fn set_dhcp_lease(&self, lease: DhcpLease) {
        self.set_ip(lease.yiaddr);
        if let Some(dns) = lease.dns_server {
            self.set_dns_server(dns);
        }
        if let Some(gw) = lease.router {
            self.set_gateway(gw);
        }
        if let Some(mask) = lease.subnet_mask {
            self.set_subnet_mask(mask);
        }
        *self.dhcp_lease_started_at.lock() = self.current_tick();
        *self.dhcp_lease.lock() = Some(lease);
        *self.dhcp_renew_state.lock() = LeaseState::Bound;
        // Install the default route via the DHCP-provided gateway.
        self.routing_table.lock().install_default(
            self.local_ip(),
            self.subnet_mask(),
            self.gateway(),
        );
    }

    /// Return a clone of the current DHCP lease, if one exists.
    #[cfg(target_os = "none")]
    pub fn dhcp_lease(&self) -> Option<DhcpLease> {
        self.dhcp_lease.lock().clone()
    }

    /// Host builds never obtain a lease, so there is none to report.
    #[cfg(not(target_os = "none"))]
    pub fn dhcp_lease(&self) -> Option<crate::kernel::network::dhcp::DhcpLease> {
        None
    }

    /// Clear the DHCP lease (on expiry or when switching to static IP).
    #[cfg(target_os = "none")]
    pub fn clear_dhcp_lease(&self) {
        *self.dhcp_lease.lock() = None;
        *self.dhcp_renew_state.lock() = LeaseState::Expired;
    }

    /// Return the current DHCP renewal state.
    #[cfg(target_os = "none")]
    pub fn dhcp_renew_state(&self) -> LeaseState {
        *self.dhcp_renew_state.lock()
    }
}
