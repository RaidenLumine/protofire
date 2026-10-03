//! fuzz/fuzz_targets/packet_parsers.rs
//!
//! Coverage-guided fuzzing for the network packet parsers: link, internet,
//! transport, and the TLS record/certificate readers.
//!
//! The parsers that take more than a byte slice get the fixed addresses and
//! traffic keys the deterministic harness uses, so the property under test
//! stays "never panic" rather than "never parse".

#![no_main]

use libfuzzer_sys::fuzz_target;

use protofire::network::dccp::parse_segment;
use protofire::network::dhcp::parse_dhcp_reply;
use protofire::network::dns::parse_a_record;
use protofire::network::dns::parse_aaaa_record;
use protofire::network::dns::parse_ptr_record;
use protofire::network::internet::icmpv6::parse_icmpv6_error_info;
use protofire::network::internet::icmpv6::parse_icmpv6_header;
use protofire::network::internet::igmp::parse_igmp_message;
use protofire::network::internet::ip::IpAddress;
use protofire::network::internet::ipv4::parse_ipv4_header;
use protofire::network::internet::ipv4::parse_packet as parse_ipv4_packet;
use protofire::network::internet::ipv6::parse_fragment_header;
use protofire::network::internet::ipv6::parse_packet as parse_ipv6_packet;
use protofire::network::ppp::parse_lcp_options;
use protofire::network::ppp::parse_lcp_packet;
use protofire::network::pppoe::parse_tags;
use protofire::network::sctp::chunk::parse_init_params;
use protofire::network::sctp::parse_common_header;
use protofire::network::sctp::parse_sctp_packet;
use protofire::network::tcp::parse_tcp_header;
use protofire::network::tls::certificate::parse_x509_certificate;
use protofire::network::tls::handshake::parse_plaintext_tls_record;
use protofire::network::tls::record::parse_tls_record;
use protofire::network::tls::record::CipherSuite;
use protofire::network::tls::record::TrafficKeys;
use protofire::network::udp::parse_datagram;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ipv4_packet(data);
    let _ = parse_ipv6_packet(data);
    let _ = parse_tcp_header(data);
    let _ = parse_datagram(data);
    let _ = parse_a_record(data);
    let _ = parse_aaaa_record(data);
    let _ = parse_ptr_record(data);
    let _ = parse_common_header(data);
    let _ = parse_sctp_packet(data);
    let _ = parse_init_params(data);
    let _ = parse_lcp_packet(data);
    let _ = parse_lcp_options(data);
    let _ = parse_icmpv6_header(data);
    let _ = parse_igmp_message(data);
    let _ = parse_ipv4_header(data);
    let _ = parse_fragment_header(data);
    let _ = parse_tags(data);
    let _ = parse_icmpv6_error_info(data);
    let _ = parse_x509_certificate(data);
    let _ = parse_plaintext_tls_record(data);
    let _ = parse_dhcp_reply(data);

    let mut keys = TrafficKeys::new(
        vec![0xAA; 16],
        [0u8; 12],
        vec![0xBB; 16],
        [0u8; 12],
        CipherSuite::Aes128GcmSha256,
    );
    let _ = parse_tls_record(&mut keys, data);

    let source = IpAddress::V4([10, 0, 0, 1]);
    let destination = IpAddress::V4([10, 0, 0, 2]);
    let _ = parse_segment(data, source, destination);
    let _ = protofire::network::dccp::options::parse_options(data);
});
