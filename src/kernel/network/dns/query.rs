//! src/kernel/network/dns/query.rs
//!
//! DNS query builders: A, AAAA, EDNS0 (RFC 6891), and PTR reverse lookups.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::internet::ipv6::Ipv6Addr;

use super::{
    DNS_CLASS_IN, DNS_EDNS0_UDP_PAYLOAD, DNS_FLAGS_OPCODE_QUERY, DNS_FLAGS_RD, DNS_HEADER_SIZE,
    DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_OPT, DNS_TYPE_PTR,
};

/// Fixed query identifier (16 bits).  A single resolver reuses the same ID;
/// the UDP 4-tuple disambiguates concurrent in-flight queries.
const DNS_QUERY_ID: u16 = 0x0001;

/// Encode a hostname as a DNS wire name: a sequence of length-prefixed labels
/// terminated by a zero-length root label (RFC 1035 §3.1).
pub(crate) fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let len = label.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&label.as_bytes()[..len]);
    }
    out.push(0);
    out
}

/// Build a 12-byte DNS query header.
fn query_header(qdcount: u16, arcount: u16) -> [u8; DNS_HEADER_SIZE] {
    let mut header = [0u8; DNS_HEADER_SIZE];
    header[0] = (DNS_QUERY_ID >> 8) as u8;
    header[1] = DNS_QUERY_ID as u8;
    let flags = DNS_FLAGS_OPCODE_QUERY | DNS_FLAGS_RD;
    header[2] = (flags >> 8) as u8;
    header[3] = flags as u8;
    header[4] = (qdcount >> 8) as u8;
    header[5] = qdcount as u8;
    // ANCOUNT / NSCOUNT remain zero; only ARCOUNT is written.
    header[10] = (arcount >> 8) as u8;
    header[11] = arcount as u8;
    header
}

/// Build a DNS A-record query for `name` (RFC 1035).
///
/// Returns the full query message as bytes, ready to be sent to a nameserver
/// on UDP port 53.
pub fn build_query(name: &str) -> Vec<u8> {
    build_query_with_type(name, DNS_TYPE_A)
}

/// Build a DNS AAAA-record query for `name`.
pub fn build_query_aaaa(name: &str) -> Vec<u8> {
    build_query_with_type(name, DNS_TYPE_AAAA)
}

/// Build a DNS query for `name` with the given QTYPE and class IN.
fn build_query_with_type(name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DNS_HEADER_SIZE + name.len() + 2 + 4);
    buf.extend_from_slice(&query_header(1, 0));
    buf.extend_from_slice(&encode_dns_name(name));
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    buf
}

/// Build an A-record query with an EDNS0 OPT pseudo-RR advertising a 4096-byte
/// UDP payload (RFC 6891).  Alias of [`build_query_a_edns0`].
pub fn build_query_edns0(name: &str) -> Vec<u8> {
    build_query_a_edns0(name)
}

/// Build an A-record query with an EDNS0 OPT pseudo-RR.
///
/// The OPT record advertises the maximum UDP payload we can receive, which
/// allows authoritative servers to send larger (and, for DNSSEC, signed)
/// responses.  The additional section holds exactly one OPT RR.
pub fn build_query_a_edns0(name: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DNS_HEADER_SIZE + name.len() + 2 + 4 + 11);
    buf.extend_from_slice(&query_header(1, 1));
    buf.extend_from_slice(&encode_dns_name(name));
    buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    // OPT pseudo-RR (RFC 6891 §6.1.2): root name, TYPE OPT, CLASS = UDP
    // payload size, TTL 0, empty RDATA.
    buf.push(0); // root name
    buf.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
    buf.extend_from_slice(&DNS_EDNS0_UDP_PAYLOAD.to_be_bytes());
    buf.extend_from_slice(&[0u8; 6]); // TTL (4) + RDLENGTH (2)
    buf
}

/// Build a PTR reverse-lookup query for an IPv4 address.
///
/// Uses the `x.x.x.x.in-addr.arpa` domain (RFC 1035 §3.5), with the octets of
/// `addr` reversed.
pub fn build_query_ptr_v4(addr: Ipv4Addr) -> Vec<u8> {
    let name = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        addr[3], addr[2], addr[1], addr[0]
    );
    build_query_with_type(&name, DNS_TYPE_PTR)
}

/// Build a PTR reverse-lookup query for an IPv6 address.
///
/// Uses the nibble-reversed `ip6.arpa` domain (RFC 3596 §2.5): each nibble of
/// the address becomes a single-character label, in reverse byte order.
pub fn build_query_ptr_v6(addr: Ipv6Addr) -> Vec<u8> {
    let mut nibbles = String::with_capacity(32 * 4 + 9);
    for byte in addr.iter().rev() {
        nibbles.push_str(&format!("{:x}.{:x}.", byte >> 4, byte & 0x0F));
    }
    nibbles.push_str("ip6.arpa");
    build_query_with_type(&nibbles, DNS_TYPE_PTR)
}
