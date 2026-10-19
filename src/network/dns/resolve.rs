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
#[cfg(target_os = "none")]
use super::query::build_query_aaaa_with_id;
use super::query::build_query_with_id;

// ── Operational constants ──

/// Well-known DNS port.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) const DNS_PORT: u16 = 53;

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

/// The budget a caller that is not a foreground syscall gives one lookup.
///
/// Twenty ticks is 200 ms at 100 Hz: a tenth of the syscall's per-attempt
/// budget.  The maintenance thread is the caller this exists for — it resolves
/// the NTP server's name inside a pass whose other jobs are periodic, and a
/// pass that waited the syscall's full six seconds of retries would have
/// stopped doing everything else.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) const DNS_BACKGROUND_TIMEOUT_TICKS: u64 = 20;

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

/// A UDP port held for the length of one lookup.
///
/// The port is bound once, before the retry loop, and released when the guard
/// is dropped.  That is not convenience: `send_to` answers with `?` inside the
/// loop, so every early return between bind and the end is a path that must
/// not leak a port, and `Drop` is the only shape that cannot miss one.
///
/// The guard unbinds the port it was given, never "the" port, so it cannot
/// remove a socket somebody else is using.  It also holds the stack it bound
/// from rather than asking the global for one again on the way out: a lookup
/// that overlapped a stack being replaced would otherwise release its port on
/// whichever stack happened to be installed when it returned.
pub(crate) struct PortGuard<'a> {
    pub(crate) port: u16,
    stack: &'a NetworkStack,
}

impl<'a> PortGuard<'a> {
    /// Take the next free port in the dynamic range.
    pub(crate) fn bind(stack: &'a NetworkStack) -> Result<Self> {
        let port = stack.udp_table().lock().bind_ephemeral()?;
        Ok(Self { port, stack })
    }
}

impl Drop for PortGuard<'_> {
    fn drop(&mut self) {
        self.stack.udp_table().lock().unbind(self.port);
    }
}

/// Draw a transaction id for one lookup.
///
/// Sixteen bits from the CSPRNG, which the stack already uses for TCP's
/// initial sequence number.  The id is the only thing that separates this
/// lookup's answer from one meant for a previous lookup on the same port, so
/// a counter would hand an observer the next one.
pub(crate) fn draw_transaction_id() -> u16 {
    let mut bytes = [0u8; 2];
    crate::kernel::random::fill_random(&mut bytes);
    u16::from_be_bytes(bytes)
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
    resolve_within(hostname, DNS_QUERY_TIMEOUT_TICKS, DNS_MAX_RETRIES)
}

/// Resolve with an explicit per-attempt budget and retry count.
///
/// The budget is wall-clock waiting, not iterations, so it is the caller's to
/// choose: a syscall can afford seconds, and a background pass whose other
/// jobs are periodic cannot.  The maintenance thread resolves the NTP server's
/// name, and it is the one caller that matters here — a resolver parked there
/// holds up every other job in the same pass, so it asks for a short budget
/// and no retries rather than the syscall's full one.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn resolve_within(
    hostname: &str,
    timeout_ticks: u64,
    max_retries: u32,
) -> Result<Ipv4Addr> {
    let stack = NetworkStack::global().ok_or(Error::Unsupported)?;
    let now = stack.current_tick();

    // 1. Check the DNS cache first (hosts table is checked by resolve_hostname).
    if let Some(addr) = cache_lookup(hostname, now) {
        return Ok(addr);
    }

    // One port and one transaction id for the whole lookup, released by the
    // guard when this function returns however it returns.
    let port = PortGuard::bind(stack)?;
    let query = build_query_with_id(draw_transaction_id(), hostname);
    // The filter compares the first two bytes, so it reads the id back out of
    // the query rather than carrying a second copy that could disagree.
    let transaction_id = [query[0], query[1]];

    for _ in 0..=max_retries {
        // Send the query to the DNS server configured on the stack
        // (set by DHCP at boot, or defaulted to 10.0.2.3).
        let dns_server = stack.dns_server();
        crate::network::udp::send_to(stack, port.port, dns_server, DNS_PORT, &query)?;

        // Park until the answer arrives or this attempt's budget is spent.
        // The receiver that drives the device is the deferred receive thread;
        // this caller no longer polls.
        let deadline = stack.current_tick().saturating_add(timeout_ticks);
        if let Ok(addr) = await_a_record(
            stack,
            port.port,
            dns_server,
            &transaction_id,
            hostname,
            deadline,
        ) {
            return Ok(addr);
        }
    }

    // The guard releases the port on the way out.
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

    // As in `resolve`: one port for the whole lookup, released by the guard.
    let port = PortGuard::bind(stack)?;
    let query = build_query_aaaa_with_id(draw_transaction_id(), hostname);

    for _ in 0..=DNS_MAX_RETRIES {
        // Send the query to the DNS server configured on the stack.
        let dns_server = stack.dns_server();
        crate::network::udp::send_to(stack, port.port, dns_server, DNS_PORT, &query)?;

        let deadline = stack.current_tick().saturating_add(DNS_QUERY_TIMEOUT_TICKS);
        if let Ok(addr) = await_aaaa_record(stack, port.port, deadline) {
            return Ok(addr);
        }
    }

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
        // A wait that cannot park has nothing that could ever wake it, and the
        // deadline it is watching belongs to a clock that will not advance, so
        // looping would spin.  Give up instead; the caller's retry and rebind
        // path is the same one a timeout takes.
        if !wait.wait(deadline) {
            return Err(Error::TimedOut);
        }
        DNS_PARK_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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
        if !wait.wait(deadline) {
            return Err(Error::TimedOut);
        }
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
