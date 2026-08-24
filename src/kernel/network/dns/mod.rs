//! src/kernel/network/dns/mod.rs
//!
//! Minimal DNS A-record resolver (RFC 1035) built on the kernel UDP stack.
//!
//! Sends a standard DNS query to a configurable nameserver and extracts
//! the first A (IPv4) record from the response.  Only used on bare-metal;
//! host-mode builds resolve hostnames through the OS resolver.
//!
//! ## DNS response cache
//!
//! Successful A-record resolutions are cached in a TTL-aware cache so
//! repeated lookups of the same hostname (common during a TCP connect /
//! TLS handshake sequence) avoid a full DNS round-trip.  Entries expire
//! after the TTL returned by the nameserver (clamped to [60 s, 3600 s]).
//!
//! Sub-module organisation:
//! - `query`   — DNS query builders (A, AAAA, EDNS0, PTR)
//! - `parse`   — DNS response parsers (A, AAAA, PTR) and name decoding
//! - `cache`   — Static hosts table and DNS response cache
//! - `resolve` — Hostname resolution with cache, hosts table, and DNS fallback

pub(crate) mod cache;
pub(crate) mod parse;
pub(crate) mod query;
pub(crate) mod resolve;
#[cfg(test)]
mod tests;

// Re-export public API so external consumers see the same paths.
// `evict_expired` is bare-metal only (called from NetworkStack).
#[cfg(target_os = "none")]
pub(crate) use cache::evict_expired;
pub use parse::{parse_a_record, parse_aaaa_record, parse_ptr_record};
pub use query::{
    build_query, build_query_a_edns0, build_query_aaaa, build_query_edns0, build_query_ptr_v4,
    build_query_ptr_v6,
};
// resolve_hostname is always available; the DNS resolvers are bare-metal only.
pub use resolve::resolve_hostname;
#[cfg(target_os = "none")]
pub use resolve::{resolve, resolve_dual_stack, resolve_v6};

// ── DNS message constants (shared across query, parse, and tests) ──

pub(crate) const DNS_HEADER_SIZE: usize = 12;
pub(crate) const DNS_FLAGS_QR_RESPONSE: u16 = 0x8000;
pub(crate) const DNS_FLAGS_OPCODE_QUERY: u16 = 0x0000;
pub(crate) const DNS_FLAGS_RD: u16 = 0x0100; // Recursion desired
pub(crate) const DNS_FLAGS_RCODE_MASK: u16 = 0x000F;
pub(crate) const DNS_RCODE_NXDOMAIN: u16 = 3;
pub(crate) const DNS_TYPE_A: u16 = 1; // Host address (A record)
pub(crate) const DNS_TYPE_AAAA: u16 = 28; // IPv6 host address (AAAA record)
pub(crate) const DNS_CLASS_IN: u16 = 1; // Internet
pub(crate) const DNS_TYPE_PTR: u16 = 12;
pub(crate) const DNS_TYPE_OPT: u16 = 41; // OPT pseudo-RR type
pub(crate) const DNS_EDNS0_UDP_PAYLOAD: u16 = 4096;

/// Ephemeral source port used for DNS queries in tests and on bare-metal.
#[cfg(any(target_os = "none", test))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const DNS_EPHEMERAL_PORT: u16 = 53000;
