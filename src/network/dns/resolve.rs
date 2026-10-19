//! src/network/dns/resolve.rs
//!
//! Hostname resolution: static hosts table → DNS cache → DNS query.

use crate::network::internet::ip::IpAddress;
use crate::network::internet::ipv4::Ipv4Addr;
#[cfg(target_os = "none")]
use crate::network::internet::ipv6::Ipv6Addr;
use crate::network::stack::NetworkStack;
use crate::Error;
use crate::Result;

use super::cache::cache_insert;
use super::cache::cache_lookup;
use super::cache::lookup_hosts;
use super::parse::parse_a_record_with_ttl;
#[cfg(target_os = "none")]
use super::parse::parse_aaaa_record;
use super::query::build_query;
#[cfg(target_os = "none")]
use super::query::build_query_aaaa;

// ── Operational constants ──

/// Well-known DNS port.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) const DNS_PORT: u16 = 53;

/// Ephemeral source port used for DNS queries.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const DNS_EPHEMERAL_PORT: u16 = 53000;

/// Maximum ticks to wait for a DNS response (200 ticks = 2 s at 100 Hz).
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) const DNS_QUERY_TIMEOUT_TICKS: u64 = 200;

/// Maximum number of retries when no response is received.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const DNS_MAX_RETRIES: u32 = 2;

/// How many times the resolver has parked waiting for an answer.
///
/// The spin this replaced ran its loop a fixed number of times whether or not
/// a datagram arrived.  This counter is what tells a boot that the loop is
/// gone and the wait is real: a resolver that quietly kept polling would
/// still return the right answer and would leave this at zero.
pub(crate) static DNS_PARK_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

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
/// Sends a standard A-record query to the configured DNS server and waits on
/// the socket's receive queue until a response arrives or the timeout expires.
/// Successful results are cached with the TTL from the DNS response.
///
/// The host build compiles this too, and [`resolve_hostname`] does not call
/// it there: a host resolves names through its own stack, and its fallback
/// stays [`Error::NotFound`].  Compiling it keeps the wait loop runnable
/// against a mock device, which is what `tests/net/dns_wait.rs` gates.
///
/// Prefer [`resolve_hostname`] for most callers — it checks the static hosts
/// table and the DNS cache before falling back to DNS.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
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
        crate::network::udp::send_to(stack, DNS_EPHEMERAL_PORT, dns_server, DNS_PORT, &query)?;

        // Park until the answer arrives or this attempt's budget is spent.
        // The receiver that drives the device is the deferred receive thread;
        // this caller no longer polls.
        let deadline = stack.current_tick().saturating_add(DNS_QUERY_TIMEOUT_TICKS);
        if let Ok(addr) = await_a_record(
            stack,
            DNS_EPHEMERAL_PORT,
            dns_server,
            &query[..2],
            hostname,
            deadline,
        ) {
            return Ok(addr);
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
/// Sends a standard AAAA-record query to the configured DNS server and waits
/// on the socket's receive queue until a response arrives or the timeout
/// expires.
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
        crate::network::udp::send_to(stack, DNS_EPHEMERAL_PORT, dns_server, DNS_PORT, &query)?;

        let deadline = stack.current_tick().saturating_add(DNS_QUERY_TIMEOUT_TICKS);
        if let Ok(addr) = await_aaaa_record(stack, DNS_EPHEMERAL_PORT, deadline) {
            return Ok(addr);
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

/// Wait for an A answer on `port`, filtering and caching it.
///
/// The query has already been sent.  Each iteration drains whatever the
/// socket holds and then parks on the socket's wait queue until the next
/// delivery or `deadline`.  A wake is not trusted as "the answer is here":
/// another waiter on the same port can take the datagram first, and the
/// deadline is delivered as a wake too, so the drain and the clock decide.
///
/// This is the whole of what the resolver does between sending and giving up,
/// in one function, so the gate that runs it and the syscall share it.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn await_a_record(
    stack: &NetworkStack,
    port: u16,
    dns_server: Ipv4Addr,
    transaction_id: &[u8],
    hostname: &str,
    deadline: u64,
) -> Result<Ipv4Addr> {
    loop {
        let wait = {
            let mut udp_table = stack.udp_table().lock();
            let Some(wait) = udp_table.readiness(port) else {
                // The binding is gone; this attempt cannot receive anything.
                return Err(Error::NotFound);
            };

            let mut buffer = [0u8; 512];
            match udp_table.recv_from(port, &mut buffer) {
                Ok((len, src_ip, src_port)) => {
                    // Only accept answers from the configured nameserver
                    // whose 16-bit transaction ID matches the query just
                    // sent; drop anything else.
                    let from_nameserver = len >= 2
                        && src_ip == IpAddress::V4(dns_server)
                        && src_port == DNS_PORT
                        && buffer[..2] == *transaction_id;
                    if from_nameserver {
                        if let Ok((addr, ttl_secs)) = parse_a_record_with_ttl(&buffer[..len]) {
                            let ttl_ticks = (ttl_secs as u64).saturating_mul(100);
                            cache_insert(hostname, addr, ttl_ticks, stack.current_tick());
                            return Ok(addr);
                        }
                        // Malformed response — keep waiting: the real answer
                        // may still arrive.
                    }
                }
                Err(Error::TimedOut) => {
                    // Queue empty — wait for the next delivery.
                }
                Err(_) => {
                    // Unexpected error — keep waiting.
                }
            }
            wait
        };

        if stack.current_tick() >= deadline {
            return Err(Error::TimedOut);
        }
        DNS_PARK_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        wait.wait(deadline);
    }
}

/// Wait for an AAAA answer on `port`.
///
/// The same loop as [`await_a_record`] without the nameserver and
/// transaction-id filter the AAAA path never had.
#[cfg(target_os = "none")]
fn await_aaaa_record(stack: &NetworkStack, port: u16, deadline: u64) -> Result<Ipv6Addr> {
    loop {
        let wait = {
            let mut udp_table = stack.udp_table().lock();
            let Some(wait) = udp_table.readiness(port) else {
                return Err(Error::NotFound);
            };

            let mut buffer = [0u8; 512];
            match udp_table.recv_from(port, &mut buffer) {
                Ok((len, _, _)) => {
                    if let Ok(addr) = parse_aaaa_record(&buffer[..len]) {
                        return Ok(addr);
                    }
                }
                Err(Error::TimedOut) => {
                    // Queue empty — wait for the next delivery.
                }
                Err(_) => {
                    // Unexpected error — keep waiting.
                }
            }
            wait
        };

        if stack.current_tick() >= deadline {
            return Err(Error::TimedOut);
        }
        wait.wait(deadline);
    }
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
