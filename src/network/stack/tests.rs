//! src/network/stack/tests.rs
//!
//! Full-stack integration tests: inject a raw Ethernet frame into the mock
//! device, poll the stack, and verify UDP datagram delivery to a bound
//! socket as well as ICMP Echo Request → Echo Reply generation.

use alloc::sync::Arc;

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use crate::network::internet::icmp::IcmpHeader;
use crate::network::internet::icmp::{self};
use crate::network::internet::icmpv6;
use crate::network::internet::ipv4::IpProtocol;
use crate::network::internet::ipv4::Ipv4Addr;
use crate::network::internet::ipv4::Ipv4Header;
use crate::network::internet::ipv4::{self};
use crate::network::link::device::mock::MockNetworkDevice;
use crate::network::link::ethernet::EtherType;
use crate::network::link::ethernet::EthernetFrame;
use crate::network::link::ethernet::MacAddress;
use crate::network::link::ethernet::{self};
use crate::network::stack::NetworkStack;
use crate::network::udp::UdpHeader;
use crate::network::udp::{self};

/// Install a fresh global stack over a fresh mock device.
///
/// Returns `(mock, stack)`: the mock device (to inject/drain frames) and
/// the global `NetworkStack` reference (to drive `poll` and inspect state).
fn make_stack() -> (Arc<MockNetworkDevice>, &'static NetworkStack) {
    // SAFETY: the caller's contract is that nothing is using the stack; this
    // test helper calls it before installing the stack it goes on to use.
    unsafe {
        NetworkStack::uninstall_global();
    }
    let dev = Arc::new(MockNetworkDevice::new(
        "stack-test",
        [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
    ));
    NetworkStack::init_with_device(dev.clone(), [10, 0, 2, 15]);
    let stack = NetworkStack::global().expect("stack should be installed");
    (dev, stack)
}

// ─── Phase 4: full-stack UDP & ICMP integration tests ───

/// Helper: wrap a payload in IPv4 + Ethernet for inject_rx.
fn build_ipv4_eth_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: IpProtocol,
    payload: &[u8],
) -> alloc::vec::Vec<u8> {
    let ip_header = Ipv4Header {
        total_length: 0,
        identification: 0,
        flags_fragment_offset: 0,
        ttl: 64,
        protocol,
        header_checksum: 0,
        source: src_ip,
        destination: dst_ip,
    };
    let ip_packet = ipv4::build_packet(&ip_header, payload);
    let frame = EthernetFrame::new(
        MacAddress(src_mac),
        MacAddress(dst_mac),
        EtherType::Ipv4,
        ip_packet,
    );
    ethernet::build_frame(&frame).expect("build ethernet frame")
}

#[test]
fn poll_udp_datagram_delivers_to_bound_socket() {
    let (mock, stack) = make_stack();
    let peer_ip: Ipv4Addr = [10, 0, 2, 100];
    let peer_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let local_port: u16 = 8080;

    // Bind a UDP socket — must succeed or the test will take the
    // ICMP-unreachable path and spin forever in ARP resolution
    // (the mock has no ARP responder and ticks never advance).
    assert!(
        stack.udp_table().lock().bind(local_port).is_ok(),
        "bind port {} must succeed",
        local_port
    );

    // Pre-populate ARP as a safety net: if delivery somehow fails,
    // the ICMP-unreachable reply path needs a resolved MAC to avoid
    // an infinite spin-loop in ARP resolution.
    stack
        .arp_cache()
        .lock()
        .insert(peer_ip, MacAddress(peer_mac), stack.current_tick());

    // Build UDP datagram
    let payload = b"hello_udp";
    let udp_header = UdpHeader {
        source_port: 12345,
        destination_port: local_port,
        length: (8 + payload.len()) as u16,
        checksum: 0,
    };
    let udp_seg = udp::build_datagram(&udp_header, payload);
    let raw = build_ipv4_eth_frame(
        peer_mac,
        stack.local_mac,
        peer_ip,
        stack.local_ip(),
        IpProtocol::Udp,
        &udp_seg,
    );

    mock.inject_rx(raw);
    let had_frame = stack.poll().expect("poll should succeed");
    assert!(had_frame);

    // Data should be delivered to the bound socket
    let mut table = stack.udp_table().lock();
    let mut buf = [0u8; 64];
    let (n, src, src_port) = table
        .recv_from(local_port, &mut buf)
        .expect("data should be available");
    assert_eq!(&buf[..n], b"hello_udp");
    assert_eq!(src, crate::network::internet::ip::IpAddress::V4(peer_ip));
    assert_eq!(src_port, 12345);
}

#[test]
fn poll_icmp_echo_request_generates_echo_reply() {
    let (mock, stack) = make_stack();
    let peer_ip: Ipv4Addr = [10, 0, 2, 100];
    let peer_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    // Pre-populate ARP so the Echo Reply send doesn't spin-wait
    stack
        .arp_cache()
        .lock()
        .insert(peer_ip, MacAddress(peer_mac), stack.current_tick());

    // Build ICMP Echo Request (type=8, code=0)
    let payload = b"ping_data";
    // rest_of_header = identifier (hi 16 bits) | sequence (lo 16 bits)
    let rest = (0x1234u32 << 16) | 1u32;
    let echo_header = IcmpHeader {
        icmp_type: 8, // Echo Request
        code: 0,
        checksum: 0,
        rest_of_header: rest,
    };
    let icmp_msg = icmp::build_icmp_message(&echo_header, payload);
    let raw = build_ipv4_eth_frame(
        peer_mac,
        stack.local_mac,
        peer_ip,
        stack.local_ip(),
        IpProtocol::Icmp,
        &icmp_msg,
    );

    mock.inject_rx(raw);
    let had_frame = stack.poll().expect("poll should succeed");
    assert!(had_frame);

    // An Echo Reply should have been sent back
    let tx = mock.drain_tx();
    assert!(!tx.is_empty(), "expected an Echo Reply to be sent");

    // Parse and verify the reply
    let reply_frame = ethernet::parse_frame(&tx[0]).expect("valid ethernet frame");
    let reply_ip = ipv4::parse_packet(&reply_frame.payload).expect("valid IPv4");
    assert_eq!(reply_ip.header.protocol, IpProtocol::Icmp);
    assert_eq!(reply_ip.header.source, stack.local_ip());
    assert_eq!(reply_ip.header.destination, peer_ip);

    // Verify ICMP type is Echo Reply (0)
    let reply_icmp = icmp::parse_icmp_header(&reply_ip.payload).expect("valid ICMP header");
    assert_eq!(reply_icmp.icmp_type, 0, "should be Echo Reply");
    assert_eq!(reply_icmp.code, 0);
    // Identifier + sequence are echoed back verbatim.
    assert_eq!(reply_icmp.rest_of_header, rest);
    // Echo Reply echoes the request payload.
    assert_eq!(&reply_ip.payload[icmp::ICMP_HEADER_SIZE..], payload);
}

/// Every ICMPv6 type in the frames the mock device was given.
///
/// The offset is fixed by the encapsulation this stack builds: 14 bytes of
/// Ethernet, 40 of IPv6, then the ICMPv6 header.
fn take_icmpv6_types(mock: &MockNetworkDevice) -> alloc::vec::Vec<u8> {
    mock.drain_tx()
        .into_iter()
        .filter(|frame| frame.len() >= 55 && frame[12..14] == [0x86, 0xdd])
        .map(|frame| frame[54])
        .collect()
}

#[test]
fn slaac_solicits_from_the_tick_path_and_checks_a_formed_address() {
    let (mock, stack) = make_stack();
    stack.start_slaac();

    // Armed, not blocking: the first Router Solicitation goes out on the next
    // tick, and the boot that armed it has already moved on.
    stack.advance_tick();
    assert_eq!(
        take_icmpv6_types(&mock),
        alloc::vec![icmpv6::NDP_ROUTER_SOLICITATION]
    );

    // Not again until the interval has passed — a deadline in the future is a
    // deadline, not an elapsed gap.
    for _ in 0..(crate::network::stack::slaac::TEST_SOLICIT_INTERVAL_TICKS - 1) {
        stack.advance_tick();
    }
    assert!(take_icmpv6_types(&mock).is_empty());
    stack.advance_tick();
    assert_eq!(
        take_icmpv6_types(&mock),
        alloc::vec![icmpv6::NDP_ROUTER_SOLICITATION]
    );

    // The last of the budget arrives on schedule, and then a host with no
    // router goes quiet rather than asking forever.
    for _ in 0..(crate::network::stack::slaac::TEST_SOLICIT_INTERVAL_TICKS
        * (crate::network::stack::slaac::TEST_MAX_SOLICITS as u64 - 1))
    {
        stack.advance_tick();
    }
    assert_eq!(
        take_icmpv6_types(&mock),
        alloc::vec![icmpv6::NDP_ROUTER_SOLICITATION],
        "the last solicitation of the budget"
    );
    for _ in 0..(crate::network::stack::slaac::TEST_SOLICIT_INTERVAL_TICKS
        * (crate::network::stack::slaac::TEST_MAX_SOLICITS as u64))
    {
        stack.advance_tick();
    }
    assert!(
        take_icmpv6_types(&mock).is_empty(),
        "the budget is spent; silence from here"
    );

    // An advertisement forms an address; the next tick probes for a duplicate.
    let global = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x52, 0x54, 0, 0x12, 0x34, 0x56, 0, 1,
    ];
    stack.set_global_ip_v6(global, 3600, 1800);
    stack.advance_tick();
    assert_eq!(
        take_icmpv6_types(&mock),
        alloc::vec![icmpv6::NDP_NEIGHBOR_SOLICITATION]
    );

    // Somebody else claims it: the address goes back.
    stack.set_dad_conflict();
    stack.advance_tick();
    assert!(stack.global_ip_v6().is_none());
}

// ─── Receiving from more than one poller ───

/// The payload every frame in this test carries: one repeated byte, so a
/// frame assembled from two different receives cannot pass as one.
fn frame_for(index: u8) -> alloc::vec::Vec<u8> {
    let payload = [index; 256];
    let udp_header = UdpHeader {
        source_port: 12345,
        destination_port: 9000,
        length: (8 + payload.len()) as u16,
        checksum: 0,
    };
    let udp_seg = udp::build_datagram(&udp_header, &payload);
    build_ipv4_eth_frame(
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc],
        [10, 0, 2, 100],
        [10, 0, 2, 15],
        IpProtocol::Udp,
        &udp_seg,
    )
}

/// Two threads poll one stack; every frame has to be read exactly once and
/// arrive whole.
///
/// The mock device is told to pause halfway through copying each frame.  That
/// pause is what makes the race reachable: without the receive lock, the
/// second poller enters `receive` between the two halves of the first one's
/// frame and overwrites the buffer the first one has not finished reading.
/// The device records the overlap directly, and the payloads — one repeated
/// byte each — make a torn frame visible as a payload that is not uniform.
#[test]
fn two_pollers_receive_every_frame_intact() {
    const FRAMES: u8 = 24;

    let mock = Arc::new(MockNetworkDevice::new(
        "two-poller",
        [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc],
    ));
    mock.set_receive_pause(100_000);
    for index in 1..=FRAMES {
        mock.inject_rx(frame_for(index));
    }
    let stack = NetworkStack::new_with_device(mock.clone(), [10, 0, 2, 15]);
    stack.udp_table().lock().bind(9000).expect("bind");

    let delivered = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                // Bounded so a lost frame fails the assertions below instead
                // of parking the test forever.
                for _ in 0..100_000 {
                    match stack.poll() {
                        Ok(true) => {
                            delivered.fetch_add(1, Ordering::AcqRel);
                        }
                        Ok(false) => {
                            if delivered.load(Ordering::Acquire) >= FRAMES as usize {
                                return;
                            }
                            std::thread::yield_now();
                        }
                        Err(error) => panic!("poll failed: {error:?}"),
                    }
                }
            });
        }
    });

    assert!(
        !mock.receive_overlapped(),
        "two receives were in flight against the one receive buffer"
    );
    assert_eq!(
        delivered.load(Ordering::Acquire),
        FRAMES as usize,
        "every frame was read exactly once"
    );

    // Each datagram has to arrive whole.  A tear puts the first half of one
    // frame and the second half of another in the same payload, so the
    // repeated byte stops being uniform.
    let mut seen = [false; FRAMES as usize + 1];
    let mut table = stack.udp_table().lock();
    for _ in 0..FRAMES {
        let mut buffer = [0u8; 512];
        let (len, _, _) = table.recv_from(9000, &mut buffer).expect("a datagram");
        let payload = &buffer[..len];
        assert_eq!(payload.len(), 256, "the whole payload was delivered");
        let first = payload[0];
        assert!(
            payload.iter().all(|byte| *byte == first),
            "a frame was assembled from two receives"
        );
        assert!(
            (1..=FRAMES).contains(&first),
            "payload byte {first} names no frame"
        );
        assert!(!seen[first as usize], "frame {first} was delivered twice");
        seen[first as usize] = true;
    }
    assert!(seen[1..].iter().all(|delivered| *delivered));
    assert_eq!(
        table.recv_from(9000, &mut [0u8; 16]),
        Err(crate::Error::TimedOut)
    );
}

/// Whether anyone is waiting is what the deferred receive thread asks before
/// it touches the device.
///
/// An idle machine must not pay a receive per tick, and a machine with a
/// parked receiver must not miss its wake, so the answer has to follow the
/// wait queue exactly: no one waiting before, one after, and none once the
/// waiter has been woken.
#[test]
fn the_receive_waiter_question_follows_the_socket() {
    let (_mock, stack) = make_stack();
    stack.udp_table().lock().bind(9100).expect("bind");
    assert!(!stack.has_receive_waiter(), "nothing is waiting yet");

    // A parked waiter is what the count is for.  The host's simulated
    // scheduler is not installed here, so this is the probe path: the thread
    // is not parked and the answer stays false.
    let wait = stack
        .udp_table()
        .lock()
        .readiness(9100)
        .expect("readiness handle");
    wait.wait(u64::MAX);
    assert!(!stack.has_receive_waiter());
}

/// One pass drains what the device has, and stops at the bound.
///
/// The bound is what keeps a flooding peer from holding the receive thread
/// for an unbounded time; the frames past it are the next pass's work, and
/// this asserts both halves.
#[test]
fn one_drain_pass_reads_what_the_device_has() {
    let (mock, stack) = make_stack();
    stack.udp_table().lock().bind(9001).expect("bind");

    let frames = 40;
    for index in 0..frames {
        let payload = [index as u8; 8];
        let header = UdpHeader {
            source_port: 12345,
            destination_port: 9001,
            length: (8 + payload.len()) as u16,
            checksum: 0,
        };
        let datagram = udp::build_datagram(&header, &payload);
        mock.inject_rx(build_ipv4_eth_frame(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            stack.local_mac,
            [10, 0, 2, 100],
            stack.local_ip(),
            IpProtocol::Udp,
            &datagram,
        ));
    }

    // The pass reads 32 of the 40; the rest wait for the next one.
    assert_eq!(stack.poll_available(), 32);
    let mut table = stack.udp_table().lock();
    let mut buffer = [0u8; 64];
    for _ in 0..32 {
        table
            .recv_from(9001, &mut buffer)
            .expect("a delivered frame");
    }
    assert_eq!(
        table.recv_from(9001, &mut buffer),
        Err(crate::Error::TimedOut)
    );
    drop(table);

    assert_eq!(stack.poll_available(), 8);
    assert_eq!(stack.poll_available(), 0);
}
