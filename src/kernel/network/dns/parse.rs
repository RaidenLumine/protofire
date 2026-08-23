//! src/kernel/network/dns/parse.rs
//! DNS response parsers for A, AAAA, and PTR records, plus DNS name
//! decoding with message-compression support.

use alloc::string::String;

use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::internet::ipv6::Ipv6Addr;
use crate::{Error, Result};

use super::{
    DNS_FLAGS_QR_RESPONSE, DNS_FLAGS_RCODE_MASK, DNS_HEADER_SIZE, DNS_RCODE_NXDOMAIN, DNS_TYPE_A,
    DNS_TYPE_AAAA, DNS_TYPE_PTR,
};

// ── A record parsing ──

/// Parse a DNS response and extract the first A record's IPv4 address.
///
/// Returns `Err(NotFound)` on NXDOMAIN, `Err(TimedOut)` if the response
/// contains no answer records, or `Err(DeviceError)` for malformed data.
pub fn parse_a_record(response: &[u8]) -> Result<Ipv4Addr> {
    parse_a_record_with_ttl(response).map(|(addr, _ttl)| addr)
}

/// Parse a DNS response and extract the first A record's IPv4 address
/// together with its TTL in seconds.
///
/// See [`parse_a_record`] for error semantics.
pub(crate) fn parse_a_record_with_ttl(response: &[u8]) -> Result<(Ipv4Addr, u32)> {
    if response.len() < DNS_HEADER_SIZE {
        return Err(Error::DeviceError);
    }

    // ── Header ──
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let rcode = flags & DNS_FLAGS_RCODE_MASK;
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    let ancount = u16::from_be_bytes([response[6], response[7]]);

    // Verify this is a response.
    if flags & DNS_FLAGS_QR_RESPONSE == 0 {
        return Err(Error::DeviceError);
    }

    if rcode == DNS_RCODE_NXDOMAIN {
        return Err(Error::NotFound);
    }
    if rcode != 0 {
        return Err(Error::DeviceError);
    }
    if ancount == 0 {
        return Err(Error::TimedOut);
    }

    // ── Skip the question section ──
    let mut pos = DNS_HEADER_SIZE;
    for _ in 0..qdcount {
        pos = skip_name(response, pos)?;
        pos = pos.checked_add(4).ok_or(Error::DeviceError)?; // QTYPE + QCLASS
        if pos > response.len() {
            return Err(Error::DeviceError);
        }
    }

    // ── Scan answer RRs for an A record ──
    for _ in 0..ancount {
        pos = skip_name(response, pos)?;

        // TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        if pos + 10 > response.len() {
            return Err(Error::DeviceError);
        }

        let rr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rr_ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10; // advance past the fixed RR header

        if pos + rdlength > response.len() {
            return Err(Error::DeviceError);
        }

        if rr_type == DNS_TYPE_A && rdlength == 4 {
            let addr: Ipv4Addr = [
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3],
            ];
            return Ok((addr, rr_ttl));
        }

        pos += rdlength;
    }

    // No A record found in the answer section.
    Err(Error::TimedOut)
}

// ── AAAA record parsing ──

/// Parse a DNS response and extract the first AAAA record's IPv6 address.
///
/// Returns `Err(NotFound)` on NXDOMAIN, `Err(TimedOut)` if the response
/// contains no answer records, or `Err(DeviceError)` for malformed data.
pub fn parse_aaaa_record(response: &[u8]) -> Result<Ipv6Addr> {
    if response.len() < DNS_HEADER_SIZE {
        return Err(Error::DeviceError);
    }

    // ── Header ──
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let rcode = flags & DNS_FLAGS_RCODE_MASK;
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    let ancount = u16::from_be_bytes([response[6], response[7]]);

    // Verify this is a response.
    if flags & DNS_FLAGS_QR_RESPONSE == 0 {
        return Err(Error::DeviceError);
    }

    if rcode == DNS_RCODE_NXDOMAIN {
        return Err(Error::NotFound);
    }
    if rcode != 0 {
        return Err(Error::DeviceError);
    }
    if ancount == 0 {
        return Err(Error::TimedOut);
    }

    // ── Skip the question section ──
    let mut pos = DNS_HEADER_SIZE;
    for _ in 0..qdcount {
        pos = skip_name(response, pos)?;
        pos = pos.checked_add(4).ok_or(Error::DeviceError)?; // QTYPE + QCLASS
        if pos > response.len() {
            return Err(Error::DeviceError);
        }
    }

    // ── Scan answer RRs for an AAAA record ──
    for _ in 0..ancount {
        pos = skip_name(response, pos)?;

        // TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        if pos + 10 > response.len() {
            return Err(Error::DeviceError);
        }

        let rr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10; // advance past the fixed RR header

        if pos + rdlength > response.len() {
            return Err(Error::DeviceError);
        }

        if rr_type == DNS_TYPE_AAAA && rdlength == 16 {
            let addr: Ipv6Addr = [
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3],
                response[pos + 4],
                response[pos + 5],
                response[pos + 6],
                response[pos + 7],
                response[pos + 8],
                response[pos + 9],
                response[pos + 10],
                response[pos + 11],
                response[pos + 12],
                response[pos + 13],
                response[pos + 14],
                response[pos + 15],
            ];
            return Ok(addr);
        }

        pos += rdlength;
    }

    // No AAAA record found in the answer section.
    Err(Error::TimedOut)
}

// ── PTR record parsing ──

/// Parse a PTR DNS response and extract the first target hostname.
///
/// Returns `Err(NotFound)` on NXDOMAIN, `Err(TimedOut)` if the response
/// contains no answer records, or `Err(DeviceError)` for malformed data.
pub fn parse_ptr_record(response: &[u8]) -> Result<String> {
    if response.len() < DNS_HEADER_SIZE {
        return Err(Error::DeviceError);
    }

    let flags = u16::from_be_bytes([response[2], response[3]]);
    let rcode = flags & DNS_FLAGS_RCODE_MASK;
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    let ancount = u16::from_be_bytes([response[6], response[7]]);

    if flags & DNS_FLAGS_QR_RESPONSE == 0 {
        return Err(Error::DeviceError);
    }
    if rcode == DNS_RCODE_NXDOMAIN {
        return Err(Error::NotFound);
    }
    if rcode != 0 {
        return Err(Error::DeviceError);
    }
    if ancount == 0 {
        return Err(Error::TimedOut);
    }

    // Skip the question section.
    let mut pos = DNS_HEADER_SIZE;
    for _ in 0..qdcount {
        pos = skip_name(response, pos)?;
        pos = pos.checked_add(4).ok_or(Error::DeviceError)?;
        if pos > response.len() {
            return Err(Error::DeviceError);
        }
    }

    // Scan answer RRs for a PTR record.
    for _ in 0..ancount {
        pos = skip_name(response, pos)?;

        if pos + 10 > response.len() {
            return Err(Error::DeviceError);
        }

        let rr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > response.len() {
            return Err(Error::DeviceError);
        }

        if rr_type == DNS_TYPE_PTR {
            let hostname = read_name(response, pos)?;
            return Ok(hostname);
        }

        pos += rdlength;
    }

    Err(Error::TimedOut)
}

// ── Name decoding ──

/// Read a DNS name (possibly compressed) into a String, starting at `pos`.
///
/// Returns the decoded hostname.  Handles message compression by following
/// pointers to a maximum depth to prevent infinite loops.
fn read_name(data: &[u8], start_pos: usize) -> Result<String> {
    let mut name = String::with_capacity(64);
    let mut pos = start_pos;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        if pos >= data.len() {
            return Err(Error::DeviceError);
        }
        let len = data[pos];
        if len == 0 {
            // Root label — end of name.
            if !jumped {
                // Advance past the root label only if we're not following a
                // pointer (the caller owns the outer advancement).
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 1 >= data.len() {
                return Err(Error::DeviceError);
            }
            let offset = ((len as usize & !0xC0) << 8) | data[pos + 1] as usize;
            pos = offset;
            if !jumped {
                jumped = true;
            }
            jumps += 1;
            if jumps > 10 {
                // Pointer loop detected — malformed packet.
                return Err(Error::DeviceError);
            }
            continue;
        }
        // Regular label.
        pos += 1;
        if pos + len as usize > data.len() {
            return Err(Error::DeviceError);
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &data[pos..pos + len as usize] {
            name.push(b as char);
        }
        pos += len as usize;
    }

    Ok(name)
}

/// Skip a DNS name (possibly compressed) starting at `pos`.
///
/// Returns the byte offset immediately after the name.  Handles message
/// compression pointers (top two bits set) by advancing past the pointer
/// (2 bytes) without following it.
fn skip_name(data: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= data.len() {
            return Err(Error::DeviceError);
        }
        let len = data[pos];
        if len == 0 {
            return Ok(pos + 1); // root label
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: 2 bytes total.
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
    }
}
