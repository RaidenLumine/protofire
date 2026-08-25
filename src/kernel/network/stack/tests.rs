//! src/kernel/network/stack/tests.rs
//!
//! Full-stack integration tests: inject a raw Ethernet frame into the mock
//! device, poll the stack, and verify UDP datagram delivery to a bound
//! socket as well as ICMP Echo Request → Echo Reply generation.

use alloc::sync::Arc;

use crate::kernel::network::internet::icmp::IcmpHeader;
use crate::kernel::network::internet::icmp::{self};
use crate::kernel::network::internet::ipv4::IpProtocol;
use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::internet::ipv4::Ipv4Header;
use crate::kernel::network::internet::ipv4::{self};
use crate::kernel::network::link::device::mock::MockNetworkDevice;
use crate::kernel::network::link::ethernet::EtherType;
use crate::kernel::network::link::ethernet::EthernetFrame;
use crate::kernel::network::link::ethernet::MacAddress;
use crate::kernel::network::link::ethernet::{self};
use crate::kernel::network::stack::NetworkStack;
use crate::kernel::network::udp::UdpHeader;
use crate::kernel::network::udp::{self};

/// Install a fresh global stack over a fresh mock device.
///
/// Returns `(mock, stack)`: the mock device (to inject/drain frames) and
/// the global `NetworkStack` reference (to drive `poll` and inspect state).
fn make_stack() -> (Arc<MockNetworkDevice>, &'static NetworkStack) {
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
    assert_eq!(
        src,
        crate::kernel::network::internet::ip::IpAddress::V4(peer_ip)
    );
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
