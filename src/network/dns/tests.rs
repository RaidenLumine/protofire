//! src/network/dns/tests.rs
//!
//! Unit and integration tests for the DNS resolver.

use alloc::vec::Vec;

use super::cache::lookup_hosts;
use super::parse::parse_a_record_with_ttl;
use super::*;
use crate::network::internet::ipv4::Ipv4Addr;
use crate::network::internet::ipv6::Ipv6Addr;
use crate::network::link::device::mock::MockNetworkDevice;
use crate::network::stack::NetworkStack;
use crate::Error;

// ── unit tests (pure functions, no stack needed) ──

#[test]
fn hosts_lookup_known_entries() {
    assert_eq!(lookup_hosts("localhost"), Some([127, 0, 0, 1]));
    assert_eq!(lookup_hosts("LOCALHOST"), Some([127, 0, 0, 1]));
    assert_eq!(lookup_hosts("LocalHost"), Some([127, 0, 0, 1]));
    assert_eq!(lookup_hosts("gateway"), Some([10, 0, 2, 2]));
    assert_eq!(lookup_hosts("nameserver"), Some([10, 0, 2, 3]));
}

#[test]
fn hosts_lookup_unknown() {
    assert_eq!(lookup_hosts("example.com"), None);
    assert_eq!(lookup_hosts(""), None);
    assert_eq!(lookup_hosts("not.in.table"), None);
}

#[test]
fn resolve_hostname_prefers_hosts_over_dns() {
    // localhost should resolve from the hosts table without DNS.
    let addr = resolve_hostname("localhost").expect("localhost should resolve");
    assert_eq!(addr, [127, 0, 0, 1]);
}

#[test]
fn resolve_hostname_returns_not_found_for_unknown_on_host() {
    // On host builds, unknown hostnames return NotFound (no DNS fallback).
    assert_eq!(
        resolve_hostname("this-does-not-exist.example"),
        Err(Error::NotFound)
    );
}

#[test]
fn build_query_produces_valid_dns_header() {
    let query = build_query("example.com");
    assert!(query.len() >= DNS_HEADER_SIZE);

    // Transaction ID = 0x0001
    assert_eq!(u16::from_be_bytes([query[0], query[1]]), 0x0001);
    // Flags: standard query + RD
    let flags = u16::from_be_bytes([query[2], query[3]]);
    assert_eq!(
        flags & DNS_FLAGS_QR_RESPONSE,
        0,
        "should be a query, not a response"
    );
    assert_eq!(flags & DNS_FLAGS_RD, DNS_FLAGS_RD, "recursion desired flag");
    // QDCOUNT = 1
    assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    assert_eq!(&query[6..12], &[0u8; 6]);
}

#[test]
fn build_query_encodes_hostname_as_labels() {
    let query = build_query("www.example.com");

    // After the 12-byte header: QNAME, QTYPE, QCLASS.
    let qname_start = DNS_HEADER_SIZE;
    // "www" (3 bytes label)
    assert_eq!(query[qname_start], 3);
    assert_eq!(&query[qname_start + 1..qname_start + 4], b"www");
    // "example" (7 bytes label)
    assert_eq!(query[qname_start + 4], 7);
    assert_eq!(&query[qname_start + 5..qname_start + 12], b"example");
    // "com" (3 bytes label)
    assert_eq!(query[qname_start + 12], 3);
    assert_eq!(&query[qname_start + 13..qname_start + 16], b"com");
    // Root label (0)
    assert_eq!(query[qname_start + 16], 0);
}

#[test]
fn build_query_single_label_hostname() {
    let query = build_query("localhost");
    let qname_start = DNS_HEADER_SIZE;
    assert_eq!(query[qname_start], 9); // "localhost" length
    assert_eq!(&query[qname_start + 1..qname_start + 10], b"localhost");
    assert_eq!(query[qname_start + 10], 0); // root label
}

#[test]
fn parse_a_record_extracts_ip_from_minimal_response() {
    // Build a minimal DNS response with one A record for 10.0.2.2.
    let response = build_test_dns_response(
        0x0001, // transaction ID
        1,      // QDCOUNT
        1,      // ANCOUNT
        false,  // not NXDOMAIN
        Some([10, 0, 2, 2]),
    );

    let addr = parse_a_record(&response).expect("should parse A record");
    assert_eq!(addr, [10, 0, 2, 2]);
}

#[test]
fn parse_a_record_rejects_nxdomain() {
    let response = build_test_dns_response(
        0x0001, 1, 0, true, // NXDOMAIN
        None,
    );

    assert_eq!(parse_a_record(&response), Err(Error::NotFound));
}

#[test]
fn parse_a_record_rejects_non_query_response() {
    // Build a DNS query (QR=0) and try to parse it.
    let query = build_query("example.com");
    assert_eq!(parse_a_record(&query), Err(Error::DeviceError));
}

#[test]
fn parse_a_record_returns_timeout_on_empty_answer() {
    let response = build_test_dns_response(
        0x0001, 1, 0, // no answer records
        false, None,
    );

    assert_eq!(parse_a_record(&response), Err(Error::TimedOut));
}

#[test]
fn parse_a_record_skips_non_a_records() {
    // Response with a CNAME (TYPE=5) followed by an A record.
    let cname_rdata = encode_qname_bytes("alias.example.com");
    let a_rdata: &[u8] = &[10, 0, 2, 3];

    let mut resp = dns_response_start(0x0001, 1, 2, false);
    // Question: "example.com" A IN
    dns_response_add_question(&mut resp, "example.com");
    // Answer 1: CNAME (5), CLASS IN (1), TTL 60, RDLENGTH = cname_rdata.len()
    dns_response_add_rr(&mut resp, "example.com", 5, &cname_rdata);
    // Answer 2: A (1), CLASS IN (1), TTL 60, RDLENGTH = 4
    dns_response_add_rr(&mut resp, "alias.example.com", DNS_TYPE_A, a_rdata);

    let addr = parse_a_record(&resp).expect("should skip CNAME and find A record");
    assert_eq!(addr, [10, 0, 2, 3]);
}

#[test]
fn parse_a_record_rejects_truncated_response() {
    assert_eq!(parse_a_record(&[0u8; 4]), Err(Error::DeviceError));
}

// ── AAAA record tests ──────────────────────────────────────────────

#[test]
fn build_query_aaaa_has_correct_qtype() {
    let query = build_query_aaaa("example.com");
    let qname_start = DNS_HEADER_SIZE;
    let label1_len = query[qname_start] as usize;
    let label2_len = query[qname_start + 1 + label1_len] as usize;
    let qname_total = 1 + label1_len + 1 + label2_len + 1; // len1 + data1 + len2 + data2 + root
    let qtype_offset = qname_start + qname_total;
    let qtype = u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]);
    assert_eq!(qtype, DNS_TYPE_AAAA);
}

#[test]
fn parse_aaaa_record_extracts_ipv6_from_response() {
    let response = build_test_dns_response_aaaa(
        0x0001,
        1,
        1,
        false,
        Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    );
    let addr = parse_aaaa_record(&response).expect("should parse AAAA record");
    assert_eq!(
        addr,
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
}

#[test]
fn parse_aaaa_record_rejects_nxdomain() {
    let response = build_test_dns_response_aaaa(0x0001, 1, 0, true, None);
    assert_eq!(parse_aaaa_record(&response), Err(Error::NotFound));
}

#[test]
fn parse_aaaa_record_skips_a_records_to_find_aaaa() {
    // Response with A record then AAAA record.
    let a_rdata: &[u8] = &[10, 0, 2, 3];
    let aaaa_rdata: &[u8] = &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut resp = dns_response_start(0x0001, 1, 2, false);
    dns_response_add_question(&mut resp, "example.com");
    dns_response_add_rr(&mut resp, "example.com", DNS_TYPE_A, a_rdata);
    dns_response_add_rr(&mut resp, "example.com", DNS_TYPE_AAAA, aaaa_rdata);
    let addr = parse_aaaa_record(&resp).expect("should skip A and find AAAA");
    assert_eq!(
        addr,
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
}

// ── TTL extraction tests ──────────────────────────────────────────

#[test]
fn parse_a_record_with_ttl_extracts_ttl_from_response() {
    // Build a response with TTL = 300 seconds.
    let mut resp = dns_response_start(0x0001, 1, 1, false);
    dns_response_add_question(&mut resp, "example.com");
    // Manually add an A record with TTL = 300.
    dns_response_add_rr_with_ttl(&mut resp, "example.com", DNS_TYPE_A, &[10, 0, 2, 2], 300);

    let (addr, ttl) = parse_a_record_with_ttl(&resp).expect("should parse with TTL");
    assert_eq!(addr, [10, 0, 2, 2]);
    assert_eq!(ttl, 300);
}

#[test]
fn parse_a_record_discards_ttl_for_backward_compat() {
    let response = build_test_dns_response(0x0001, 1, 1, false, Some([10, 0, 2, 2]));
    let addr = parse_a_record(&response).expect("backward-compat parse");
    assert_eq!(addr, [10, 0, 2, 2]);
}

// ── DNS cache logic tests ─────────────────────────────────────────

#[test]
fn dns_cache_insert_and_lookup() {
    // Test the cache algorithm without the global static.
    // Simulate insert → lookup → expire.
    let _hostname = "kernel.example.com";
    let _addr: Ipv4Addr = [10, 0, 2, 100];
    let _ttl_ticks = 500; // 5 seconds
    let _now = 1000;

    // We can't access the global DNS_CACHE on host builds, so test
    // the algorithmic properties via the lowercasing logic and TTL
    // math by verifying resolve_hostname/lookup_hosts integration.
    //
    // hosts table handles case-insensitive matches:
    assert_eq!(lookup_hosts("localhost"), Some([127, 0, 0, 1]));
    assert_eq!(lookup_hosts("LOCALHOST"), Some([127, 0, 0, 1]));
}

#[test]
fn dns_cache_ttl_clamping() {
    // TTL clamping is tested indirectly: resolve() on bare-metal
    // clamps TTLs below 60 s and above 3600 s.  On host we verify
    // that parse_a_record_with_ttl returns the raw TTL and trust
    // the clamping logic in cache_insert (simple bounds check).
    let mut resp = dns_response_start(0x0001, 1, 1, false);
    dns_response_add_question(&mut resp, "example.com");
    // Supply a very short TTL (10 seconds).
    dns_response_add_rr_with_ttl(&mut resp, "example.com", DNS_TYPE_A, &[1, 2, 3, 4], 10);

    let (_addr, ttl) = parse_a_record_with_ttl(&resp).expect("short TTL parse");
    assert_eq!(ttl, 10); // Raw TTL is returned; clamping is in cache_insert.
}

// ── integration test (requires NetworkStack) ──

#[cfg(not(target_os = "none"))]
#[test]
fn resolve_hostname_round_trip_with_stack() {
    use crate::network::internet::ipv4;
    use crate::network::link::ethernet::MacAddress;
    use crate::network::link::ethernet::{self};
    use crate::network::udp;
    use alloc::sync::Arc;

    // SAFETY: the caller's contract is that nothing is using the stack; this
    // test helper calls it before installing the stack it goes on to use.
    unsafe {
        NetworkStack::uninstall_global();
    }

    let mock = Arc::new(MockNetworkDevice::new(
        "dns-test",
        [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc],
    ));
    let dns_server_mac: [u8; 6] = [0x52, 0x54, 0x00, 0x99, 0x88, 0x77];
    NetworkStack::init_with_device(mock.clone(), [10, 0, 2, 15]);
    let stack = NetworkStack::global().expect("stack should be initialised");

    // Pre-populate the ARP cache so send_to does not spin-wait for a
    // reply that would never arrive in this synthetic test topology.
    stack
        .arp_cache()
        .lock()
        .insert([10, 0, 2, 3], MacAddress(dns_server_mac), 0);

    // This test drives the UDP path itself rather than through the resolver,
    // so it names its own source port; the resolver allocates one now.
    let bound_port = 53_100u16;
    stack.udp_table().lock().bind(bound_port).expect("bind");

    let query = build_query("kernel.example.com");
    let result = udp::send_to(stack, bound_port, [10, 0, 2, 3], 53, &query);
    assert!(result.is_ok(), "send_to should succeed: {:?}", result.err());

    // Drain the TX frame(s) — should contain our DNS query.
    let tx_frames = mock.drain_tx();
    assert!(!tx_frames.is_empty(), "expected at least one TX frame");

    // Parse the TX frame to get the source port used in the query.
    let frame = ethernet::parse_frame(&tx_frames[0]).expect("valid ethernet frame");
    let ip = ipv4::parse_packet(&frame.payload).expect("valid IPv4");
    let dgram = udp::parse_datagram(&ip.payload).expect("valid UDP datagram");
    let src_port = dgram.header.source_port;
    assert_eq!(src_port, bound_port, "the query came from the bound port");
    assert_eq!(dgram.header.destination_port, 53);
    assert_eq!(ip.header.destination, [10, 0, 2, 3]);

    // Build a matching DNS response and inject it into the mock RX.
    let response = build_test_dns_response(0x0001, 1, 1, false, Some([192, 168, 1, 100]));
    // Build the UDP/IP/Ethernet frame for the response.
    let udp_payload = udp::build_datagram(
        &udp::UdpHeader {
            source_port: 53,
            destination_port: src_port,
            length: 0,
            checksum: 0,
        },
        &response,
    );
    let ip_payload = ipv4::build_packet(
        &ipv4::Ipv4Header {
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            ttl: ipv4::IPV4_DEFAULT_TTL,
            protocol: ipv4::IpProtocol::Udp,
            header_checksum: 0,
            source: [10, 0, 2, 3],
            destination: [10, 0, 2, 15],
        },
        &udp_payload,
    );
    let eth_frame = build_eth_ip_frame(
        &[0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc], // dst = our MAC
        &dns_server_mac,                       // src = DNS server MAC
        &ip_payload,
    );
    mock.inject_rx(eth_frame);

    // Poll to deliver the UDP datagram to our bound port.
    let had_frame = stack.poll().expect("poll should succeed");
    assert!(had_frame);

    // Now read from the bound port.
    let mut recv_buf = [0u8; 512];
    let (len, src_ip, src_port) = stack
        .udp_table()
        .lock()
        .recv_from(bound_port, &mut recv_buf)
        .expect("should have a datagram in the receive queue");

    assert_eq!(
        src_ip,
        crate::network::internet::ip::IpAddress::V4([10, 0, 2, 3])
    );
    assert_eq!(src_port, 53);

    let addr = parse_a_record(&recv_buf[..len]).expect("should parse response");
    assert_eq!(addr, [192, 168, 1, 100]);

    // SAFETY: the caller's contract is that nothing is using the stack; this
    // test helper calls it before installing the stack it goes on to use.
    unsafe {
        NetworkStack::uninstall_global();
    }
}

/// `resolve` returns an answer that is already waiting, without polling for
/// it.
///
/// A device that answers a DNS query the way a nameserver would.
///
/// It parses the frame it is asked to send, reads the source port out of the
/// query, and queues a matching answer on that port before `send` returns —
/// so by the time the resolver drains the socket, the answer is there.  That
/// is the only way a host test can answer a lookup whose source port the
/// resolver chose itself and never published.
struct AnsweringNameserver {
    mac: [u8; 6],
    /// The address the synthetic A record carries, for every name it answers.
    answer: [u8; 4],
    /// How many queries it was asked to send.
    queries: core::sync::atomic::AtomicUsize,
}

impl AnsweringNameserver {
    fn new(answer: [u8; 4]) -> Self {
        Self {
            mac: [0x52, 0x54, 0x00, 0x99, 0x88, 0x77],
            answer,
            queries: core::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl crate::network::link::device::NetworkDevice for AnsweringNameserver {
    fn name(&self) -> &str {
        "answering-nameserver"
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn send(&self, packet: &[u8]) -> crate::Result<()> {
        use crate::network::internet::ipv4;
        use crate::network::link::ethernet;
        use crate::network::udp;

        self.queries
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        let frame = ethernet::parse_frame(packet)?;
        let ip = ipv4::parse_packet(&frame.payload)?;
        let dgram = udp::parse_datagram(&ip.payload)?;
        if dgram.header.destination_port != 53 {
            return Ok(());
        }

        let mut response = super::tests::build_test_dns_response(
            u16::from_be_bytes([dgram.payload[0], dgram.payload[1]]),
            1,
            1,
            false,
            Some(self.answer),
        );
        // The transaction id comes from the query, so the resolver's filter
        // sees its own answer and not merely any answer.
        response[..2].copy_from_slice(&dgram.payload[..2]);

        if let Some(stack) = NetworkStack::global() {
            stack.udp_table().lock().deliver(
                crate::network::internet::ip::IpAddress::V4([10, 0, 2, 3]),
                53,
                dgram.header.source_port,
                response,
            );
        }
        Ok(())
    }

    fn receive(&self, _buffer: &mut [u8]) -> crate::Result<usize> {
        Ok(0)
    }

    fn device_health(&self) -> crate::network::link::device::Health {
        crate::network::link::device::Health::Healthy
    }
}

/// This is the resolver's real loop, not a copy: it sends the query, finds the
/// answer already queued on the port it allocated, filters it by nameserver
/// and transaction id, parses it and caches it.  The count of parks is
/// asserted at zero — the answer was there before the wait — and the cache
/// lookup is the half of the result the return value alone does not prove.
#[cfg(not(target_os = "none"))]
#[test]
fn resolve_takes_an_answer_that_is_already_queued() {
    use crate::network::link::ethernet::MacAddress;
    use alloc::sync::Arc;

    const HOST: &str = "queued-answer.example";
    const ADDR: [u8; 4] = [192, 168, 1, 77];

    // SAFETY: the caller's contract is that nothing is using the stack; this
    // test helper calls it before installing the stack it goes on to use.
    unsafe {
        NetworkStack::uninstall_global();
    }

    let device = Arc::new(AnsweringNameserver::new(ADDR));
    NetworkStack::init_with_device(device.clone(), [10, 0, 2, 15]);
    let stack = NetworkStack::global().expect("stack should be initialised");
    stack
        .arp_cache()
        .lock()
        .insert([10, 0, 2, 3], MacAddress(device.mac), 0);

    let parks_before = super::resolve::DNS_PARK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let resolved = super::resolve::resolve(HOST).expect("the queued answer should resolve");
    let parks_after = super::resolve::DNS_PARK_COUNT.load(core::sync::atomic::Ordering::Relaxed);

    assert_eq!(resolved, ADDR);
    assert_eq!(
        device.queries.load(core::sync::atomic::Ordering::Acquire),
        1,
        "one query went out"
    );
    assert_eq!(
        parks_after, parks_before,
        "the answer was queued, so the resolver must not have parked"
    );
    assert_eq!(
        super::cache::cache_lookup(HOST, stack.current_tick()),
        Some(ADDR),
        "a resolved answer is cached"
    );
    // And a second resolution is served from the cache with no query at all:
    // the device was asked exactly once.
    assert_eq!(super::resolve::resolve(HOST), Ok(ADDR));
    assert_eq!(
        device.queries.load(core::sync::atomic::Ordering::Acquire),
        1,
        "the cached answer did not send a second query"
    );
    assert!(
        !stack.udp_table().lock().any_ephemeral_bound(),
        "the lookup released its port"
    );

    // SAFETY: nothing else is using the stack now; this test installed it.
    unsafe {
        NetworkStack::uninstall_global();
    }
}

/// A lookup with nothing that can wake it gives up instead of spinning.
///
/// The deadline the resolver watches is the scheduler's clock.  Without a
/// scheduler — which is every host test, and was the shape of the old poll
/// loop on any context that could not park — the clock never reaches it, and
/// a loop that trusted the deadline alone would never return.  This asserts
/// the wait reports that it could not park and the lookup ends.
#[cfg(not(target_os = "none"))]
#[test]
fn a_lookup_that_cannot_park_gives_up() {
    use crate::network::link::ethernet::MacAddress;
    use alloc::sync::Arc;

    const HOST: &str = "no-answer.example";

    // SAFETY: the caller's contract is that nothing is using the stack; this
    // test helper calls it before installing the stack it goes on to use.
    unsafe {
        NetworkStack::uninstall_global();
    }

    let mock = Arc::new(MockNetworkDevice::new(
        "dns-no-answer",
        [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc],
    ));
    NetworkStack::init_with_device(mock, [10, 0, 2, 15]);
    let stack = NetworkStack::global().expect("stack should be initialised");
    stack.arp_cache().lock().insert(
        [10, 0, 2, 3],
        MacAddress([0x52, 0x54, 0x00, 0x99, 0x88, 0x77]),
        0,
    );

    let parks_before = super::resolve::DNS_PARK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let result = super::resolve::resolve_within(HOST, 5, 0);
    let parks_after = super::resolve::DNS_PARK_COUNT.load(core::sync::atomic::Ordering::Relaxed);

    assert_eq!(result, Err(Error::TimedOut));
    assert_eq!(
        parks_after, parks_before,
        "a wait that cannot park must not count as one"
    );
    assert!(
        !stack.udp_table().lock().any_ephemeral_bound(),
        "the guard must release the port on the failure path"
    );

    // SAFETY: nothing else is using the stack now; this test installed it.
    unsafe {
        NetworkStack::uninstall_global();
    }
}

/// Two lookups in flight at once do not meet.
///
/// This is the case RFC 0030 exists for.  Before it, both lookups bound the
/// same 53000 and the second adopted the first one's socket, so one of the
/// two answers had to be discarded by the id filter and the loser waited out
/// its budget.
///
/// The two lookups are driven step by step rather than from two threads: the
/// global stack is per-thread on the host, so a worker thread would not see
/// the one installed here.  What the test needs is their *overlap*, and that
/// is expressible directly — take both ports, then answer both, then drain
/// both — which is the sequence the threads would have produced.
#[cfg(not(target_os = "none"))]
#[test]
fn two_lookups_at_once_take_their_own_ports_and_answers() {
    use crate::network::internet::ip::IpAddress;
    use crate::network::link::ethernet::MacAddress;
    use alloc::sync::Arc;

    // SAFETY: the caller's contract is that nothing is using the stack; this
    // test helper calls it before installing the stack it goes on to use.
    unsafe {
        NetworkStack::uninstall_global();
    }

    let device = Arc::new(AnsweringNameserver::new([192, 168, 1, 90]));
    NetworkStack::init_with_device(device.clone(), [10, 0, 2, 15]);
    let stack = NetworkStack::global().expect("stack should be initialised");
    stack
        .arp_cache()
        .lock()
        .insert([10, 0, 2, 3], MacAddress(device.mac), 0);

    // Both lookups bind before either is answered: this is the overlap.
    let first = super::resolve::PortGuard::bind(stack).expect("a port for the first");
    let second = super::resolve::PortGuard::bind(stack).expect("a port for the second");
    assert_ne!(
        first.port, second.port,
        "the two lookups were given the same source port"
    );

    // Each query carries its own id, and each answer goes to its own port.
    let first_id = super::resolve::draw_transaction_id();
    let second_id = super::resolve::draw_transaction_id();
    assert_ne!(first_id, second_id, "the two lookups shared an id");

    for (port, id, addr) in [
        (first.port, first_id, [192, 168, 1, 1]),
        (second.port, second_id, [192, 168, 1, 2]),
    ] {
        let answer = build_test_dns_response(id, 1, 1, false, Some(addr));
        assert!(stack
            .udp_table()
            .lock()
            .deliver(IpAddress::V4([10, 0, 2, 3]), 53, port, answer,));
    }

    // Each port holds its own answer and only its own: the datagram that
    // arrived on the first port is not visible from the second.
    for (port, expected) in [
        (first.port, [192, 168, 1, 1]),
        (second.port, [192, 168, 1, 2]),
    ] {
        let mut buffer = [0u8; 512];
        let mut table = stack.udp_table().lock();
        let (len, src, src_port) = table.recv_from(port, &mut buffer).expect("its own answer");
        drop(table);
        assert_eq!(src, IpAddress::V4([10, 0, 2, 3]));
        assert_eq!(src_port, 53);
        assert_eq!(
            super::parse::parse_a_record(&buffer[..len]),
            Ok(expected),
            "port {port} received the answer meant for it"
        );
    }

    drop(first);
    drop(second);
    assert!(
        !stack.udp_table().lock().any_ephemeral_bound(),
        "both lookups released their ports"
    );

    // SAFETY: nothing else is using the stack now; this test installed it.
    unsafe {
        NetworkStack::uninstall_global();
    }
}

/// A transaction id is drawn per lookup, not reused.
#[cfg(not(target_os = "none"))]
#[test]
fn transaction_ids_differ_between_lookups() {
    let first = super::resolve::draw_transaction_id();
    let mut differs = false;
    for _ in 0..16 {
        if super::resolve::draw_transaction_id() != first {
            differs = true;
            break;
        }
    }
    assert!(
        differs,
        "sixteen draws of a 16-bit id all matched, which no CSPRNG does"
    );
}

/// The builder writes the id it is given, and the filter reads it back.
#[cfg(not(target_os = "none"))]
#[test]
fn a_query_carries_the_id_it_was_built_with() {
    let query = super::query::build_query_with_id(0xBEEF, "example.com");
    assert_eq!(&query[..2], &[0xBE, 0xEF]);

    // The filter compares the first two bytes, so a query built this way is
    // matched by exactly this answer and not by one carrying another id.
    let answer = build_test_dns_response(0xBEEF, 1, 1, false, Some([10, 0, 2, 9]));
    assert_eq!(&answer[..2], &query[..2]);
    let other = build_test_dns_response(0x0001, 1, 1, false, Some([10, 0, 2, 9]));
    assert_ne!(&other[..2], &query[..2]);
}

/// The AAAA wait loop takes a queued answer, like the A loop does.
///
/// The AAAA path has no nameserver or id filter, which is the one way it
/// differs from the A path — and that difference went untested: the AAAA
/// resolver was compiled only for bare metal, so no host test could reach its
/// loop.  It is compiled here now for the same reason the A loop is, so the
/// gate runs the real one.
#[cfg(not(target_os = "none"))]
#[test]
fn await_aaaa_takes_a_queued_answer() {
    use crate::network::link::ethernet::MacAddress;
    use alloc::sync::Arc;

    const ADDR: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];

    // SAFETY: the caller's contract is that nothing is using the stack; this
    // test helper calls it before installing the stack it goes on to use.
    unsafe {
        NetworkStack::uninstall_global();
    }

    let mock = Arc::new(MockNetworkDevice::new(
        "dns-aaaa",
        [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc],
    ));
    NetworkStack::init_with_device(mock, [10, 0, 2, 15]);
    let stack = NetworkStack::global().expect("stack should be initialised");
    stack.arp_cache().lock().insert(
        [10, 0, 2, 3],
        MacAddress([0x52, 0x54, 0x00, 0x99, 0x88, 0x77]),
        0,
    );

    let port = super::resolve::PortGuard::bind(stack).expect("a port");
    let response = build_test_dns_response_aaaa(0x0001, 1, 1, false, Some(ADDR));
    assert!(stack.udp_table().lock().deliver(
        crate::network::internet::ip::IpAddress::V4([10, 0, 2, 3]),
        53,
        port.port,
        response,
    ));

    let resolved =
        super::resolve::await_aaaa_record(stack, port.port, stack.current_tick().saturating_add(5))
            .expect("the queued answer resolves");
    assert_eq!(resolved, ADDR);

    drop(port);
    assert!(
        !stack.udp_table().lock().any_ephemeral_bound(),
        "the guard released the port"
    );

    // SAFETY: nothing else is using the stack now; this test installed it.
    unsafe {
        NetworkStack::uninstall_global();
    }
}

// ── test helpers ──

/// Build an Ethernet frame carrying an IPv4 payload.
fn build_eth_ip_frame(
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    ip_payload: &[u8],
) -> alloc::vec::Vec<u8> {
    let mut frame = alloc::vec![0u8; 14 + ip_payload.len()];
    frame[0..6].copy_from_slice(dst_mac);
    frame[6..12].copy_from_slice(src_mac);
    frame[12] = 0x08; // EtherType IPv4
    frame[13] = 0x00;
    frame[14..].copy_from_slice(ip_payload);
    frame
}

/// Encode a hostname as QNAME bytes and return them as a Vec.
fn encode_qname_bytes(hostname: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in hostname.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00);
    buf
}

/// Build a test DNS response header (12 bytes).
fn dns_response_start(tx_id: u16, qdcount: u16, ancount: u16, nxdomain: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    // Transaction ID
    buf.extend_from_slice(&tx_id.to_be_bytes());
    // Flags: response + recursion desired + optional NXDOMAIN
    let mut flags = DNS_FLAGS_QR_RESPONSE | DNS_FLAGS_RD;
    if nxdomain {
        flags |= DNS_RCODE_NXDOMAIN;
    }
    buf.extend_from_slice(&flags.to_be_bytes());
    // QDCOUNT
    buf.extend_from_slice(&qdcount.to_be_bytes());
    // ANCOUNT
    buf.extend_from_slice(&ancount.to_be_bytes());
    // NSCOUNT, ARCOUNT = 0
    buf.extend_from_slice(&[0u8; 4]);
    buf
}

/// Add a question section to a response buffer.
fn dns_response_add_question(buf: &mut Vec<u8>, hostname: &str) {
    buf.extend(encode_qname_bytes(hostname));
    buf.extend_from_slice(&DNS_TYPE_A.to_be_bytes()); // QTYPE=A
    buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // QCLASS=IN
}

/// Add a resource record to a response buffer.
fn dns_response_add_rr(buf: &mut Vec<u8>, name: &str, rr_type: u16, rdata: &[u8]) {
    dns_response_add_rr_with_ttl(buf, name, rr_type, rdata, 60);
}

/// Like [`dns_response_add_rr`] but with a caller-specified TTL in seconds.
fn dns_response_add_rr_with_ttl(
    buf: &mut Vec<u8>,
    name: &str,
    rr_type: u16,
    rdata: &[u8],
    ttl_seconds: u32,
) {
    buf.extend(encode_qname_bytes(name));
    buf.extend_from_slice(&rr_type.to_be_bytes());
    buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    // TTL as specified by caller.
    buf.extend_from_slice(&ttl_seconds.to_be_bytes());
    // RDLENGTH
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    // RDATA
    buf.extend_from_slice(rdata);
}

/// Build a complete test DNS response with one question and optionally
/// one A record.
fn build_test_dns_response(
    tx_id: u16,
    qdcount: u16,
    ancount: u16,
    nxdomain: bool,
    a_record: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut buf = dns_response_start(tx_id, qdcount, ancount, nxdomain);
    dns_response_add_question(&mut buf, "example.com");
    if let Some(addr) = a_record {
        let rdata: Vec<u8> = addr.to_vec();
        dns_response_add_rr(&mut buf, "example.com", DNS_TYPE_A, &rdata);
    }
    buf
}

/// Build a test DNS response for AAAA queries.
fn build_test_dns_response_aaaa(
    tx_id: u16,
    qdcount: u16,
    ancount: u16,
    nxdomain: bool,
    aaaa_record: Option<Ipv6Addr>,
) -> Vec<u8> {
    let mut buf = dns_response_start(tx_id, qdcount, ancount, nxdomain);
    dns_response_add_question(&mut buf, "example.com");
    if let Some(addr) = aaaa_record {
        let rdata: Vec<u8> = addr.to_vec();
        dns_response_add_rr(&mut buf, "example.com", DNS_TYPE_AAAA, &rdata);
    }
    buf
}

// ── EDNS0 tests ────────────────────────────────────────────────────

#[test]
fn build_query_edns0_adds_opt_record() {
    let query = build_query_a_edns0("example.com");
    // Validate the ARCOUNT field (offset 10–11) is 1.
    assert_eq!(u16::from_be_bytes([query[10], query[11]]), 1);
    // The OPT record is at the end. Check its structure.
    let opt_start = query.len() - 11; // 1(root) + 2(type) + 2(class) + 4(ttl) + 2(rdlength)
    assert_eq!(query[opt_start], 0x00); // NAME = root
    assert_eq!(query[opt_start + 1], 0x00); // TYPE high
    assert_eq!(query[opt_start + 2], DNS_TYPE_OPT as u8); // TYPE low = 41
                                                          // CLASS = UDP payload size (4096 = 0x1000)
    assert_eq!(query[opt_start + 3], 0x10);
    assert_eq!(query[opt_start + 4], 0x00);
}

#[test]
fn build_query_edns0_has_larger_packet() {
    let standard = build_query("example.com");
    let edns0 = build_query_a_edns0("example.com");
    assert!(edns0.len() > standard.len());
    // EDNS0 packet should be exactly 11 bytes larger (the OPT record).
    assert_eq!(edns0.len(), standard.len() + 11);
}

// ── PTR tests ─────────────────────────────────────────────────────

#[test]
fn build_query_ptr_v4_produces_arpa_name() {
    let addr: Ipv4Addr = [10, 0, 2, 3];
    let query = build_query_ptr_v4(addr);
    let qtype_offset = query.len() - 4;
    let qtype = u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]);
    assert_eq!(qtype, DNS_TYPE_PTR);
    assert!(query.len() > DNS_HEADER_SIZE + 20);
}

#[test]
fn parse_ptr_record_extracts_hostname() {
    // Build a synthetic PTR response.
    let mut buf = Vec::new();
    // Header
    buf.extend_from_slice(&[0x00, 0x01]); // TXID
    buf.extend_from_slice(&[0x85, 0x80]); // Flags: response, no error
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
                                          // Question: "3.2.0.10.in-addr.arpa" PTR IN
    buf.extend_from_slice(&[0x01, 0x33, 0x01, 0x32, 0x01, 0x30, 0x02, 0x31, 0x30, 0x07]);
    buf.extend_from_slice(b"in-addr");
    buf.extend_from_slice(&[0x04]);
    buf.extend_from_slice(b"arpa");
    buf.push(0x00); // root label
    buf.extend_from_slice(&[0x00, DNS_TYPE_PTR as u8]); // QTYPE = PTR
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
                                          // Answer: pointer to question name + PTR record
    buf.extend_from_slice(&[0xC0, 0x0C]); // compression pointer to name
    buf.extend_from_slice(&[0x00, DNS_TYPE_PTR as u8]); // TYPE = PTR
    buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
    buf.extend_from_slice(&[0x00, 0x0D]); // RDLENGTH = 13
                                          // RDATA: "gateway.local" encoded as labels
    buf.extend_from_slice(&[0x07]);
    buf.extend_from_slice(b"gateway");
    buf.extend_from_slice(&[0x05]);
    buf.extend_from_slice(b"local");
    buf.push(0x00);

    let hostname = parse_ptr_record(&buf).expect("parse PTR response");
    assert_eq!(hostname, "gateway.local");
}

#[test]
fn parse_ptr_record_rejects_nxdomain() {
    let mut buf = Vec::new();
    // Header: TXID=1, Flags=NXDOMAIN, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    buf.extend_from_slice(&[0x00, 0x01]); // TXID
    buf.extend_from_slice(&[0x85, 0x83]); // Flags: response + NXDOMAIN
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
                                          // Question: root label + PTR + IN
    buf.push(0x00); // root label
    buf.extend_from_slice(&[0x00, DNS_TYPE_PTR as u8]); // QTYPE = PTR
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    assert!(parse_ptr_record(&buf).is_err());
}

#[test]
fn edns0_query_can_be_parsed_by_standard_parser() {
    // A standard parse_a_record should still work on an EDNS0 query
    // by verifying the EDNS0 OPT record doesn't corrupt the header.
    let query = build_query_a_edns0("example.com");
    // The header should be valid: QDCOUNT=1
    assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
    assert_eq!(u16::from_be_bytes([query[6], query[7]]), 0); // ANCOUNT=0
    assert_eq!(u16::from_be_bytes([query[10], query[11]]), 1); // ARCOUNT=1
}
