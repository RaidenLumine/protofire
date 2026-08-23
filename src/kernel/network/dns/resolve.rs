//! src/kernel/network/dns/resolve.rs
//! Hostname resolution: static hosts table → DNS cache → DNS query.

#[cfg(target_os = "none")]
use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::internet::ipv4::Ipv4Addr;
#[cfg(target_os = "none")]
use crate::kernel::network::internet::ipv6::Ipv6Addr;
#[cfg(target_os = "none")]
use crate::kernel::network::stack::NetworkStack;
use crate::{Error, Result};

use super::cache::lookup_hosts;
#[cfg(target_os = "none")]
use super::cache::{cache_insert, cache_lookup};
#[cfg(target_os = "none")]
use super::parse::parse_a_record_with_ttl;
#[cfg(target_os = "none")]
use super::parse::parse_aaaa_record;
#[cfg(target_os = "none")]
use super::query::{build_query, build_query_aaaa};

// ── Operational constants (bare-metal only) ──

/// Well-known DNS port.
#[cfg(target_os = "none")]
const DNS_PORT: u16 = 53;

/// Ephemeral source port used for DNS queries.
#[cfg(target_os = "none")]
const DNS_EPHEMERAL_PORT: u16 = 53000;

/// Maximum ticks to wait for a DNS response (200 ticks = 2 s at 100 Hz).
#[cfg(target_os = "none")]
const DNS_QUERY_TIMEOUT_TICKS: u64 = 200;

/// Maximum number of retries when no response is received.
#[cfg(target_os = "none")]
const DNS_MAX_RETRIES: u32 = 2;

// ── Resolution ──

/// Resolve a hostname to an IPv4 address.
///
/// Checks the static hosts table first, then falls back to DNS on bare-metal
/// builds.  On host (test) builds, only the hosts table is consulted — DNS
/// resolution is handled by the OS network stack in those environments.
pub fn resolve_hostname(hostname: &str) -> Result<Ipv4Addr> {
    // 1. Static hosts table.
    if let Some(addr) = lookup_hosts(hostname) {
        return Ok(addr);
    }

    // 2. Fall back to DNS on bare-metal.
    #[cfg(target_os = "none")]
    {
        resolve(hostname)
    }

    // 3. On host builds without DNS, treat as not found.
    #[cfg(not(target_os = "none"))]
    {
        Err(Error::NotFound)
    }
}

/// Resolve a hostname to an IPv4 address via DNS.
///
/// Sends a standard A-record query to the configured DNS server and blocks
/// (via poll loop) until a response arrives or the timeout expires.
/// Successful results are cached with the TTL from the DNS response.
///
/// This function is only available on bare-metal; host-mode builds resolve
/// hostnames through the OS resolver in `std::net::TcpStream::connect`.
///
/// Prefer [`resolve_hostname`] for most callers — it checks the static hosts
/// table and the DNS cache before falling back to DNS.
#[cfg(target_os = "none")]
pub fn resolve(hostname: &str) -> Result<Ipv4Addr> {
    let stack = NetworkStack::global().ok_or(Error::Unsupported)?;
    let now = stack.current_tick();

    // 1. Check the DNS cache first (hosts table is checked by resolve_hostname).
    if let Some(addr) = cache_lookup(hostname, now) {
        return Ok(addr);
    }

    // Bind an ephemeral port for the DNS query exchange.
    {
        let mut udp_table = stack.udp_table().lock();
        if !udp_table.is_bound(DNS_EPHEMERAL_PORT) {
            udp_table.bind(DNS_EPHEMERAL_PORT)?;
        }
    }

    let query = build_query(hostname);

    for retry in 0..=DNS_MAX_RETRIES {
        // Send the query to the DNS server configured on the stack
        // (set by DHCP at boot, or defaulted to 10.0.2.3).
        let dns_server = stack.dns_server();
        crate::kernel::network::udp::send_to(
            stack,
            DNS_EPHEMERAL_PORT,
            dns_server,
            DNS_PORT,
            &query,
        )?;

        // Spin-poll for the response, draining the stack rx path each
        // iteration so UDP datagrams can be delivered to our bound port.
        for _tick in 0..DNS_QUERY_TIMEOUT_TICKS {
            // Drive the stack poll loop so incoming frames are demuxed
            // and delivered to the UDP socket table.
            let _ = stack.poll();

            // Check our bound port for a response.
            let mut buffer = [0u8; 512];
            match stack
                .udp_table()
                .lock()
                .recv_from(DNS_EPHEMERAL_PORT, &mut buffer)
            {
                Ok((len, _src_ip, _src_port)) => {
                    // Try to parse the response.  A well-behaved DNS
                    // server sends the answer from port 53; additional
                    // source verification could be added here.
                    if let Ok((addr, ttl_secs)) = parse_a_record_with_ttl(&buffer[..len]) {
                        // Cache the result with the TTL from the response.
                        let ttl_ticks = (ttl_secs as u64).saturating_mul(100);
                        cache_insert(hostname, addr, ttl_ticks, stack.current_tick());
                        return Ok(addr);
                    }
                    // Malformed response — keep waiting (the real
                    // answer may still arrive).
                }
                Err(Error::TimedOut) => {
                    // Queue empty — keep polling.
                }
                Err(_) => {
                    // Unexpected error — keep waiting.
                }
            }

            // Yield the CPU so other runnable threads can make progress
            // while we wait for the DNS response.  If no other thread is
            // ready the scheduler returns immediately.
            crate::kernel::process::scheduler::yield_current();
        }

        // Timeout — rebind if our port was somehow taken.
        if retry < DNS_MAX_RETRIES {
            let mut udp_table = stack.udp_table().lock();
            if !udp_table.is_bound(DNS_EPHEMERAL_PORT) {
                let _ = udp_table.bind(DNS_EPHEMERAL_PORT);
            }
        }
    }

    // Clean up the ephemeral binding on final failure.
    stack.udp_table().lock().unbind(DNS_EPHEMERAL_PORT);
    Err(Error::TimedOut)
}

/// Resolve a hostname to an IPv6 address via DNS (AAAA query).
///
/// Sends a standard AAAA-record query to the configured DNS server and blocks
/// (via poll loop) until a response arrives or the timeout expires.
///
/// This function is only available on bare-metal; host-mode builds resolve
/// hostnames through the OS resolver.
#[cfg(target_os = "none")]
pub fn resolve_v6(hostname: &str) -> Result<Ipv6Addr> {
    let stack = NetworkStack::global().ok_or(Error::Unsupported)?;

    // Bind an ephemeral port for the DNS query exchange.
    {
        let mut udp_table = stack.udp_table().lock();
        if !udp_table.is_bound(DNS_EPHEMERAL_PORT) {
            udp_table.bind(DNS_EPHEMERAL_PORT)?;
        }
    }

    let query = build_query_aaaa(hostname);

    for retry in 0..=DNS_MAX_RETRIES {
        // Send the query to the DNS server configured on the stack.
        let dns_server = stack.dns_server();
        crate::kernel::network::udp::send_to(
            stack,
            DNS_EPHEMERAL_PORT,
            dns_server,
            DNS_PORT,
            &query,
        )?;

        // Spin-poll for the response.
        for _tick in 0..DNS_QUERY_TIMEOUT_TICKS {
            let _ = stack.poll();

            let mut buffer = [0u8; 512];
            match stack
                .udp_table()
                .lock()
                .recv_from(DNS_EPHEMERAL_PORT, &mut buffer)
            {
                Ok((len, _src_ip, _src_port)) => {
                    if let Ok(addr) = parse_aaaa_record(&buffer[..len]) {
                        return Ok(addr);
                    }
                }
                Err(Error::TimedOut) => {
                    // Queue empty — keep polling.
                }
                Err(_) => {
                    // Unexpected error — keep waiting.
                }
            }

            crate::kernel::process::scheduler::yield_current();
        }

        // Timeout — rebind if our port was somehow taken.
        if retry < DNS_MAX_RETRIES {
            let mut udp_table = stack.udp_table().lock();
            if !udp_table.is_bound(DNS_EPHEMERAL_PORT) {
                let _ = udp_table.bind(DNS_EPHEMERAL_PORT);
            }
        }
    }

    // Clean up the ephemeral binding on final failure.
    stack.udp_table().lock().unbind(DNS_EPHEMERAL_PORT);
    Err(Error::TimedOut)
}

/// Resolve a hostname to an [`IpAddress`] by trying AAAA first (preferring
/// IPv6), then falling back to A (IPv4).
///
/// Only available on bare-metal.
#[cfg(target_os = "none")]
pub fn resolve_dual_stack(hostname: &str) -> Result<IpAddress> {
    // Try IPv6 first.
    if let Ok(v6) = resolve_v6(hostname) {
        return Ok(IpAddress::V6(v6));
    }
    // Fall back to IPv4.
    resolve(hostname).map(IpAddress::V4)
}
