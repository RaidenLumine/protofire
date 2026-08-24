//! src/kernel/network/mdns.rs
//!
//! Minimal multicast DNS (mDNS, RFC 6762) responder.
//!
//! The responder announces the host's `<hostname>.local` A record on the
//! link-local multicast group 224.0.0.251:5353 and answers multicast queries
//! for that name (and for `_services._dns-sd._udp.local` service discovery)
//! with the kernel's local IPv4 address.
//!
//! Startup follows the RFC 6762 probe → announce sequence:
//! - `PROBE_COUNT` probe queries are sent every `PROBE_INTERVAL` ticks to
//!   detect a name conflict,
//! - once the probes complete, a single unsolicited announcement is emitted.
//! After that the responder only answers inbound queries (see
//! [`MdnsResponder::handle_packet`]).

#![allow(clippy::doc_lazy_continuation)]
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::stack::NetworkStack;
use crate::kernel::network::udp;

/// mDNS listens on UDP port 5353 (RFC 6762 §6).
pub const MDNS_PORT: u16 = 5353;

/// The link-local multicast group used by mDNS (RFC 6762 §3).
pub const MDNS_IPV4_ADDR: Ipv4Addr = [224, 0, 0, 251];

/// Number of probe packets sent before announcing a name (RFC 6762 §8.1).
const PROBE_COUNT: u32 = 3;
/// Interval between probe packets in ticks (250 ms at 100 Hz = 25 ticks).
const PROBE_INTERVAL: u64 = 25;
/// Default TTL for mDNS records (120 seconds per RFC 6762 §10).
const DEFAULT_TTL: u32 = 120;

/// Per-host mDNS responder state.
pub struct MdnsResponder {
    /// Hostname announced as `<hostname>.local`.
    hostname: String,
    /// Number of probe packets already sent.
    probes_sent: u32,
    /// Tick of the last probe packet.
    last_probe_tick: u64,
    /// Whether the name has been announced.
    announced: bool,
}

impl MdnsResponder {
    /// Create a responder for `hostname` (the `.local` suffix is implied).
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: String::from(hostname),
            probes_sent: 0,
            last_probe_tick: 0,
            announced: false,
        }
    }

    /// Advance the probe/announce state machine.  Returns a full UDP datagram
    /// (UDP header + mDNS message) to transmit when one is due, or `None`.
    ///
    /// Called from [`NetworkStack::advance_tick`]; the returned datagram is
    /// sent to [`MDNS_IPV4_ADDR`]:[`MDNS_PORT`].
    pub fn tick(&mut self, tick: u64) -> Option<Vec<u8>> {
        if self.announced {
            return None;
        }
        if self.probes_sent < PROBE_COUNT {
            let due =
                self.probes_sent == 0 || tick.wrapping_sub(self.last_probe_tick) >= PROBE_INTERVAL;
            if !due {
                return None;
            }
            let probe = self.build_probe();
            self.probes_sent += 1;
            self.last_probe_tick = tick;
            return Some(probe);
        }
        // All probes sent — emit the announcement exactly once.
        self.announced = true;
        self.build_announcement()
    }

    /// Handle an inbound mDNS query (the UDP payload of a datagram addressed
    /// to port 5353).  Returns a DNS response message to send back, or `None`
    /// when the query does not concern this host.
    pub fn handle_packet(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 12 {
            return None;
        }
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        // Only answer queries (QR == 0); responses and other messages are
        // ignored.
        if flags & 0x8000 != 0 {
            return None;
        }
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount == 0 {
            return None;
        }

        let (name, pos) = parse_mdns_name(payload, 12)?;
        if pos + 4 > payload.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let _qclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);

        let our_name = self.fqdn();
        let ip = self.local_ip()?;

        let mut answers: Vec<Vec<u8>> = Vec::new();
        match qtype {
            1 => {
                // A query for our hostname — answer with an A record.
                if !name.eq_ignore_ascii_case(&our_name) {
                    return None;
                }
                answers.push(build_a_record(&our_name, ip));
            }
            12 => {
                // PTR query — only service discovery is handled.  Answer with
                // a PTR record for our instance plus an additional A record.
                if !name.eq_ignore_ascii_case("_services._dns-sd._udp.local") {
                    return None;
                }
                let target = encode_mdns_name(&our_name);
                let mut ptr = Vec::with_capacity(64);
                ptr.extend_from_slice(&encode_mdns_name(&name));
                ptr.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
                ptr.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                ptr.extend_from_slice(&DEFAULT_TTL.to_be_bytes());
                ptr.extend_from_slice(&(target.len() as u16).to_be_bytes());
                ptr.extend_from_slice(&target);
                answers.push(ptr);
                answers.push(build_a_record(&our_name, ip));
            }
            _ => return None,
        }

        // Build the response: echo the request ID and the question section,
        // set QR|AA, then append the answer records.
        let mut resp = Vec::with_capacity(256);
        resp.extend_from_slice(&payload[..2]); // request ID
        resp.extend_from_slice(&0x8400u16.to_be_bytes()); // QR + AA
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        resp.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        resp.extend_from_slice(&payload[12..pos + 4]); // echoed question
        for rr in answers {
            resp.extend_from_slice(&rr);
        }
        Some(resp)
    }

    /// The fully-qualified mDNS name `<hostname>.local`.
    fn fqdn(&self) -> String {
        format!("{}.local", self.hostname)
    }

    /// Our IPv4 address from the global network stack (used in A records).
    fn local_ip(&self) -> Option<Ipv4Addr> {
        NetworkStack::global().map(|stack| stack.local_ip())
    }

    /// Build a probe: a query for our `<hostname>.local` A record with the QU
    /// (unicast response) bit set in the question class, wrapped in UDP.
    fn build_probe(&self) -> Vec<u8> {
        let name = self.fqdn();
        let mut msg = Vec::with_capacity(12 + name.len() + 2 + 4);
        // Header: ID 0, flags 0 (query), QDCOUNT 1.
        msg.extend_from_slice(&[0u8; 12]);
        msg[5] = 1;
        msg.extend_from_slice(&encode_mdns_name(&name));
        msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        msg.extend_from_slice(&(1u16 | 0x8000).to_be_bytes()); // QCLASS IN | QU
        wrap_udp(msg)
    }

    /// Build an announcement: an unsolicited answer (QR|AA, no question) with
    /// our `<hostname>.local` A record, wrapped in UDP.
    fn build_announcement(&self) -> Option<Vec<u8>> {
        let ip = self.local_ip()?;
        let name = self.fqdn();
        let mut msg = Vec::with_capacity(12 + name.len() + 2 + 10 + 4);
        // Header: ID 0, flags QR|AA, QDCOUNT 0, ANCOUNT 1.
        msg.extend_from_slice(&[0u8; 12]);
        msg[2] = 0x84;
        msg[3] = 0x00;
        msg[7] = 1;
        msg.extend_from_slice(&build_a_record(&name, ip));
        Some(wrap_udp(msg))
    }
}

/// Build one A-record answer RR (name, TYPE A, CLASS IN, TTL, RDLENGTH, addr).
fn build_a_record(name: &str, addr: Ipv4Addr) -> Vec<u8> {
    let mut rr = Vec::with_capacity(64);
    rr.extend_from_slice(&encode_mdns_name(name));
    rr.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    rr.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    rr.extend_from_slice(&DEFAULT_TTL.to_be_bytes());
    rr.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    rr.extend_from_slice(&addr);
    rr
}

/// Encode a name as DNS wire labels (uncompressed), terminated by a root byte.
fn encode_mdns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let len = label.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&label.as_bytes()[..len]);
    }
    out.push(0);
    out
}

/// Parse a DNS name from `data` at `pos`, following compression pointers.
///
/// Returns the decoded name and the offset immediately after the name in the
/// original message.
fn parse_mdns_name(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = pos;
    let mut jumped = false;
    let mut jumps = 0;
    loop {
        let len = *data.get(pos)?;
        if len == 0 {
            if !jumped {
                end = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            let offset = (((len as usize) & 0x3F) << 8) | *data.get(pos + 1)? as usize;
            if !jumped {
                end = pos + 2;
            }
            jumped = true;
            pos = offset;
            jumps += 1;
            if jumps > 10 {
                return None; // pointer loop
            }
            continue;
        }
        pos += 1;
        let label_len = len as usize;
        if pos + label_len > data.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &data[pos..pos + label_len] {
            name.push(b as char);
        }
        pos += label_len;
    }
    Some((name, end))
}

/// Wrap an mDNS message in a UDP datagram to/from port 5353.
fn wrap_udp(dns_message: Vec<u8>) -> Vec<u8> {
    let header = udp::UdpHeader {
        source_port: MDNS_PORT,
        destination_port: MDNS_PORT,
        length: 0, // recomputed by build_datagram
        checksum: 0,
    };
    udp::build_datagram(&header, &dns_message)
}
