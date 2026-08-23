//! src/kernel/network/dns/cache.rs
//! Static hosts table (analogous to `/etc/hosts`) and a TTL-aware DNS
//! response cache for A-record resolutions.

use crate::kernel::network::internet::ipv4::Ipv4Addr;
#[cfg(target_os = "none")]
use crate::kernel::sync::Mutex;
#[cfg(target_os = "none")]
use alloc::collections::BTreeMap;
#[cfg(target_os = "none")]
use alloc::string::String;

// ── TTL clamping constants (bare-metal scheduler ticks at 100 Hz) ──

/// Minimum TTL to honour from a DNS response (60 seconds).
#[cfg(target_os = "none")]
const DNS_CACHE_MIN_TTL_TICKS: u64 = 60 * 100; // 60 s at 100 Hz

/// Maximum TTL to honour from a DNS response (3600 seconds = 1 hour).
#[cfg(target_os = "none")]
const DNS_CACHE_MAX_TTL_TICKS: u64 = 3600 * 100; // 3600 s at 100 Hz

// ── Static hosts table ──

/// A static hostname-to-IPv4 mapping, analogous to `/etc/hosts`.
///
/// Checked by [`resolve_hostname`] before falling back to DNS.  Each entry
/// is a (hostname, IPv4 address) pair.  Hostnames are compared
/// case-insensitively.
const HOSTS_TABLE: &[(&str, Ipv4Addr)] = &[
    ("localhost", [127, 0, 0, 1]),
    ("localhost.localdomain", [127, 0, 0, 1]),
    ("gateway", [10, 0, 2, 2]),
    ("nameserver", [10, 0, 2, 3]),
];

/// Look up a hostname in the static hosts table.
///
/// Returns `Some(addr)` if an entry matches (case-insensitive comparison),
/// or `None` if the hostname is not in the table.
pub(crate) fn lookup_hosts(hostname: &str) -> Option<Ipv4Addr> {
    for &(name, addr) in HOSTS_TABLE {
        if name.eq_ignore_ascii_case(hostname) {
            return Some(addr);
        }
    }
    None
}

// ── DNS response cache ──

/// A cached DNS A-record result with an expiration tick.
#[cfg(target_os = "none")]
#[derive(Debug, Clone)]
struct CachedEntry {
    addr: Ipv4Addr,
    /// Absolute tick when this entry expires.
    expires_at: u64,
}

/// Global DNS response cache.
///
/// Caches successful A-record resolutions keyed by hostname (lowercased).
/// Entries expire after the TTL reported in the DNS response, clamped to
/// [`DNS_CACHE_MIN_TTL_TICKS`, `DNS_CACHE_MAX_TTL_TICKS`].
#[cfg(target_os = "none")]
static DNS_CACHE: Mutex<BTreeMap<String, CachedEntry>> = Mutex::new(BTreeMap::new());

/// Look up a hostname in the DNS cache.
///
/// Returns `Some(addr)` if a non-expired entry exists, or `None` on a
/// cache miss (including expired entries, which are evicted).
#[cfg(target_os = "none")]
pub(crate) fn cache_lookup(hostname: &str, now: u64) -> Option<Ipv4Addr> {
    let cache = DNS_CACHE.lock();
    let key = lowercase_hostname(hostname);
    match cache.get(&key) {
        Some(entry) if entry.expires_at > now => Some(entry.addr),
        _ => None,
    }
}

/// Insert a resolved address into the DNS cache.
///
/// `ttl_ticks` is the TTL in scheduler ticks, clamped to the configured
/// min/max bounds.  Expired entries for the same key are overwritten.
#[cfg(target_os = "none")]
pub(crate) fn cache_insert(hostname: &str, addr: Ipv4Addr, ttl_ticks: u64, now: u64) {
    let clamped_ttl = ttl_ticks.clamp(DNS_CACHE_MIN_TTL_TICKS, DNS_CACHE_MAX_TTL_TICKS);
    let mut cache = DNS_CACHE.lock();
    let key = lowercase_hostname(hostname);
    cache.insert(
        key,
        CachedEntry {
            addr,
            expires_at: now.saturating_add(clamped_ttl),
        },
    );
}

/// Evict all expired entries from the DNS cache.
///
/// Called periodically from [`NetworkStack::advance_tick`] so the cache
/// does not grow without bound.
#[cfg(target_os = "none")]
pub fn evict_expired(now: u64) {
    let mut cache = DNS_CACHE.lock();
    // BTreeMap::retain is unstable in kernel no_std; collect live keys
    // and rebuild.
    let live: BTreeMap<String, CachedEntry> = cache
        .iter()
        .filter(|(_, entry)| entry.expires_at > now)
        .map(|(k, v): (&String, &CachedEntry)| (k.clone(), v.clone()))
        .collect();
    *cache = live;
}

/// Return the lowercased hostname used as a cache key.
#[cfg(target_os = "none")]
fn lowercase_hostname(hostname: &str) -> String {
    let mut s = String::with_capacity(hostname.len());
    for ch in hostname.chars() {
        s.push(ch.to_ascii_lowercase());
    }
    s
}
