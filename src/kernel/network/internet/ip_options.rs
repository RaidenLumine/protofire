//! src/kernel/network/internet/ip_options.rs
//! IPv4 options (RFC 791): a minimal parser for the option area of an IPv4
//! header.
//!
//! ## Educational purpose
//!
//! IPv4 headers carry optional facilities (record route, source routing,
//! timestamps) in the variable-length area that follows the fixed 20-byte
//! header.  Every IPv4 device must be able to *skip* unknown or malformed
//! options, because the header length field is the only reliable guide to
//! where the payload begins.  This module implements that walker and a
//! hand-rolled decoder for the interesting options.
//!
//! ## Why not production?
//!
//! - Real kernels keep the option walker in lock-step with checksum and
//!   fragmentation handling, and must reject options that request unsafe
//!   behaviours (source routing is routinely disabled on the Internet).
//! - This parser is intentionally lenient: it stops at the first malformed
//!   option rather than producing detailed error codes.

use alloc::vec::Vec;

// ─── IPv4 option type constants (RFC 791) ──────────────────────────────────

/// End of Options List — terminates parsing.
pub const IPOPT_END: u8 = 0;
/// No Operation — a one-byte padding option.
pub const IPOPT_NOP: u8 = 1;
/// Record Route.
pub const IPOPT_RR: u8 = 7;
/// Loose Source Route.
pub const IPOPT_LSR: u8 = 131;
/// Strict Source Route.
pub const IPOPT_SSR: u8 = 137;
/// Timestamp.
pub const IPOPT_TS: u8 = 68;

// ─── Parsed options ────────────────────────────────────────────────────────

/// A decoded IPv4 option.
///
/// The walker only materialises the options it understands; everything else
/// is preserved verbatim as [`Ipv4Option::Unknown`] so that round-tripping
/// the header stays lossless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4Option {
    /// End of Options List (type 0) — no more options follow.
    EndOfList,
    /// No Operation (type 1) — a single-byte no-op.
    NoOperation,
    /// Record Route (type 7): each router along the path appends its address.
    RecordRoute {
        /// 1-based offset of the next free slot inside the option.
        pointer: u8,
        /// Addresses recorded so far (each 4 bytes).
        route: Vec<[u8; 4]>,
    },
    /// Loose Source Route (type 131): route through the listed routers,
    /// but intermediate hops are permitted between them.
    LooseSourceRoute {
        pointer: u8,
        addresses: Vec<[u8; 4]>,
    },
    /// Strict Source Route (type 137): visit the listed routers exactly.
    StrictSourceRoute {
        pointer: u8,
        addresses: Vec<[u8; 4]>,
    },
    /// Timestamp (type 68): each router may add a 4-byte timestamp.
    Timestamp {
        /// 1-based offset of the next free timestamp slot.
        pointer: u8,
        /// Number of timestamps that could not be recorded (overflow).
        overflow: u8,
        /// 0 = timestamps only, 1 = address + timestamp, 3 = pre-specified
        /// addresses.
        flags: u8,
        /// The 4-byte timestamp values recorded so far.
        entries: Vec<[u8; 4]>,
    },
    /// Any option this parser does not understand.
    Unknown { option_type: u8, data: Vec<u8> },
}

// ─── Parser ────────────────────────────────────────────────────────────────

/// Parse the option area of an IPv4 header into its decoded options.
///
/// The walker is defensive: at the first malformed option it stops and
/// returns whatever was parsed before the problem, mirroring how a real
/// kernel must keep the payload offset trustworthy.
pub fn parse_ipv4_options(data: &[u8]) -> Vec<Ipv4Option> {
    let mut options = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let opt_type = data[i];
        match opt_type {
            IPOPT_END => {
                // End of Options List: the remaining bytes are padding.
                options.push(Ipv4Option::EndOfList);
                break;
            }
            IPOPT_NOP => {
                // No Operation: always skipped, never a multi-byte option.
                options.push(Ipv4Option::NoOperation);
                i += 1;
            }
            t => {
                // All other options carry an explicit length byte.
                if i + 1 >= data.len() {
                    break; // truncated length byte
                }
                let len = data[i + 1] as usize;
                if len < 2 || i + len > data.len() {
                    break; // malformed length
                }
                let body = &data[i + 2..i + len];
                match t {
                    IPOPT_TS => options.push(parse_timestamp_option(body)),
                    IPOPT_RR | IPOPT_LSR | IPOPT_SSR => {
                        options.push(parse_route_option(t, body));
                    }
                    _ => options.push(Ipv4Option::Unknown {
                        option_type: t,
                        data: body.to_vec(),
                    }),
                }
                i += len;
            }
        }
    }

    options
}

/// Decode the body of a Timestamp option (everything after type + length).
fn parse_timestamp_option(body: &[u8]) -> Ipv4Option {
    if body.len() < 2 {
        return Ipv4Option::Unknown {
            option_type: IPOPT_TS,
            data: body.to_vec(),
        };
    }

    let pointer = body[0];
    let overflow_flags = body[1];
    let overflow = overflow_flags >> 4;
    let flags = overflow_flags & 0x0F;
    // Flags 1 and 3 prepend a 4-byte router address to each timestamp.
    let entry_size = if flags == 0 { 4 } else { 8 };

    let mut entries = Vec::new();
    let mut e = 2;
    while e + entry_size <= body.len() {
        // For address+timestamp entries we keep the timestamp half.
        let start = if flags == 0 { e } else { e + entry_size - 4 };
        let mut ts = [0u8; 4];
        ts.copy_from_slice(&body[start..start + 4]);
        entries.push(ts);
        e += entry_size;
    }

    Ipv4Option::Timestamp {
        pointer,
        overflow,
        flags,
        entries,
    }
}

/// Decode the body of a Record Route / source-route option.
fn parse_route_option(opt_type: u8, body: &[u8]) -> Ipv4Option {
    if body.is_empty() {
        // A route option with no body (length 2) is malformed.
        return Ipv4Option::Unknown {
            option_type: opt_type,
            data: Vec::new(),
        };
    }

    let pointer = body[0];
    let mut addresses = Vec::new();
    let mut e = 1;
    while e + 4 <= body.len() {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&body[e..e + 4]);
        addresses.push(addr);
        e += 4;
    }

    match opt_type {
        IPOPT_RR => Ipv4Option::RecordRoute {
            pointer,
            route: addresses,
        },
        IPOPT_LSR => Ipv4Option::LooseSourceRoute { pointer, addresses },
        IPOPT_SSR => Ipv4Option::StrictSourceRoute { pointer, addresses },
        _ => unreachable!("route parser called with non-route option"),
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn empty_options_parses_to_empty_vec() {
        let opts = parse_ipv4_options(&[]);
        assert!(opts.is_empty());
    }

    #[test]
    fn noop_and_eol_are_skipped() {
        // NOPs (type 1) are preserved but skipped; EOL (type 0) ends the list.
        let data = [1, 1, 0, 0, 0, 0];
        let opts = parse_ipv4_options(&data);
        assert_eq!(
            opts,
            vec![
                Ipv4Option::NoOperation,
                Ipv4Option::NoOperation,
                Ipv4Option::EndOfList,
            ]
        );
    }

    #[test]
    fn parse_timestamp_option() {
        // Type=68, Len=8 (RFC 791 packs overflow and flags into a single
        // byte: 1+1+1+1+4), Ptr=5, Overflow=0, Flags=0, ts=12345678.
        let data = [
            68, 8, 5, 0, // type, len, ptr, overflow|flags
            0, 188, 97, 78, // timestamp 12345678 = 0x00BC614E
        ];
        let opts = parse_ipv4_options(&data);
        assert_eq!(opts.len(), 1);
        match &opts[0] {
            Ipv4Option::Timestamp {
                pointer,
                overflow,
                flags,
                entries,
            } => {
                assert_eq!(*pointer, 5);
                assert_eq!(*overflow, 0);
                assert_eq!(*flags, 0);
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], [0, 188, 97, 78]);
            }
            other => panic!("expected Timestamp, got {other:?}"),
        }
    }

    #[test]
    fn parse_record_route_option() {
        // Type=7, Len=11, Ptr=5, then two router addresses.
        let data = [7, 11, 5, 10, 0, 0, 1, 10, 0, 0, 2];
        let opts = parse_ipv4_options(&data);
        assert_eq!(opts.len(), 1);
        match &opts[0] {
            Ipv4Option::RecordRoute { pointer, route } => {
                assert_eq!(*pointer, 5);
                assert_eq!(route.len(), 2);
                assert_eq!(route[0], [10, 0, 0, 1]);
                assert_eq!(route[1], [10, 0, 0, 2]);
            }
            other => panic!("expected RecordRoute, got {other:?}"),
        }
    }

    #[test]
    fn parse_strict_source_route_option() {
        // Type=137, Len=7, Ptr=4, one router address.
        let data = [137, 7, 4, 192, 168, 1, 254];
        let opts = parse_ipv4_options(&data);
        assert_eq!(opts.len(), 1);
        match &opts[0] {
            Ipv4Option::StrictSourceRoute { pointer, addresses } => {
                assert_eq!(*pointer, 4);
                assert_eq!(addresses.len(), 1);
                assert_eq!(addresses[0], [192, 168, 1, 254]);
            }
            other => panic!("expected StrictSourceRoute, got {other:?}"),
        }
    }

    #[test]
    fn unknown_option_is_preserved() {
        let data = [200, 4, 1, 2];
        let opts = parse_ipv4_options(&data);
        assert_eq!(
            opts,
            vec![Ipv4Option::Unknown {
                option_type: 200,
                data: vec![1, 2],
            }]
        );
    }

    #[test]
    fn invalid_length_handling() {
        // Timestamp claims length 9 but only 3 bytes remain — the walker
        // must stop rather than read past the end of the buffer.
        let truncated_len = parse_ipv4_options(&[68, 9, 5]);
        assert!(truncated_len.is_empty(), "truncated option must be dropped");

        // An option that claims a sub-2 length is equally malformed.
        let bad_len = parse_ipv4_options(&[7, 1]);
        assert!(bad_len.is_empty(), "length < 2 must be rejected");
    }
}
