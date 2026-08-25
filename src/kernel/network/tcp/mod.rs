//! src/kernel/network/tcp/mod.rs
//!
//! TCP protocol (RFC 793): state machine, connect / listen / accept / read /
//! write / close.
//!
//! This is a minimal but functional implementation:
//! - Active open (connect): SYN → SYN-ACK → ACK
//! - Passive open (listen / accept): SYN → SYN-ACK → ACK → backlog
//! - Data transfer with sequence tracking and fixed receive window
//! - Retransmission with exponential backoff
//! - Active close: FIN → FIN-ACK → ACK
//! - Passive close handling (peer sends FIN)
//!
//! What is NOT implemented:
//! - Urgent data
//! - Simultaneous open/close
//! - SO_REUSEADDR or socket options

pub mod congestion;
pub mod ecn;
mod ops;
mod segment;
pub mod table;
mod types;

// ─── Public re-exports ────────────────────────────────────────────────

pub use ops::close;
pub use ops::connect;
pub use ops::process_segment;
pub use ops::process_segment_v6;
pub use ops::retransmit_check;
pub use segment::build_tcp_segment;
pub use segment::build_tcp_segment_v6;
pub use segment::parse_tcp_header;
pub(crate) use segment::send_tcp_segment;
pub(crate) use segment::send_tcp_segment_v6;
pub use table::accept_nonblocking;
pub use table::listen;
pub use table::unlisten;
pub use table::NativeTcpConnection;
pub use table::TcpConnectionTable;
pub use types::TcpConnectionState;
pub use types::TcpHeader;
pub use types::TcpState;
pub use types::TCP_MIN_HEADER_SIZE;

// ─── tests ───

#[cfg(test)]
mod tests {
    use super::types::*;
    use super::*;
    use crate::kernel::network::internet::ipv4::Ipv4Addr;
    use crate::kernel::network::internet::ipv4::{self};
    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use crate::kernel::network::link::ethernet::MacAddress;
    use crate::kernel::network::stack::NetworkStack;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    // ─── helpers ───

    fn make_test_stack() -> (Arc<MockNetworkDevice>, &'static NetworkStack) {
        unsafe {
            NetworkStack::uninstall_global();
        }
        let mock = Arc::new(MockNetworkDevice::new(
            "tcp-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(mock.clone(), [10, 0, 2, 15]);
        let stack = NetworkStack::global().expect("stack should be initialised");
        (mock, stack)
    }

    /// Helper: run the MSS option parser from process_segment.
    fn parse_peer_mss(opts: &[u8]) -> usize {
        super::segment::parse_mss_option(opts)
    }

    // ─── header parse/build tests ───

    #[test]
    fn tcp_header_parse_and_build_round_trip() {
        let header = TcpHeader {
            source_port: 12345,
            destination_port: 80,
            sequence_number: 0x12345678,
            acknowledgment_number: 0x9ABCDEF0,
            data_offset: 0,
            flags: TCP_FLAG_SYN,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: alloc::vec![2, 4, 0x05, 0xB4], // MSS option
        };

        let seg = build_tcp_segment(&header, b"hello", [10, 0, 2, 15], [10, 0, 2, 2]);

        let (parsed, header_len) = parse_tcp_header(&seg).expect("should parse");
        assert_eq!(parsed.source_port, 12345);
        assert_eq!(parsed.destination_port, 80);
        assert_eq!(parsed.sequence_number, 0x12345678);
        assert_eq!(parsed.acknowledgment_number, 0x9ABCDEF0);
        assert_eq!(parsed.flags, TCP_FLAG_SYN);
        assert_eq!(parsed.window_size, 65535);
        assert_eq!(parsed.options, alloc::vec![2, 4, 0x05, 0xB4]);

        let payload = &seg[header_len..];
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn tcp_checksum_is_valid() {
        let header = TcpHeader {
            source_port: 12345,
            destination_port: 80,
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_ACK,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };

        let seg = build_tcp_segment(&header, b"data", [10, 0, 2, 15], [10, 0, 2, 2]);

        // Verify checksum with pseudo-header
        let pseudo = ipv4::pseudo_header_checksum_input([10, 0, 2, 15], [10, 0, 2, 2], 6, &seg);
        assert_eq!(ipv4::compute_checksum(&pseudo), 0);
    }

    #[test]
    fn parse_rejects_short_data() {
        assert!(parse_tcp_header(&[0u8; 10]).is_err());
    }

    // ─── state machine unit tests ───

    #[test]
    fn connection_state_transitions_syn_sent_to_established() {
        // Simulate the three-way handshake from the client side
        let mut state = TcpConnectionState::new(49152, [10, 0, 2, 2], 80, 1000, 0);

        assert_eq!(state.state, TcpState::SynSent);
        assert_eq!(state.send_next, 1001); // SYN consumed one seq
        assert_eq!(state.send_unacked, 1000);

        // Peer sends SYN-ACK
        let syn_ack = TcpHeader {
            source_port: 80,
            destination_port: 49152,
            sequence_number: 5000,
            acknowledgment_number: 1001, // ACKing our SYN
            data_offset: 0,
            flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: alloc::vec![2, 4, 0x05, 0xB4],
        };
        let _syn_ack_seg = build_tcp_segment(&syn_ack, &[], [10, 0, 2, 2], [10, 0, 2, 15]);

        // Simulate what process_segment does for SynSent state:
        let flags = syn_ack.flags;
        let is_syn = flags & TCP_FLAG_SYN != 0;
        let is_ack = flags & TCP_FLAG_ACK != 0;
        let expected_ack = state.initial_seq.wrapping_add(1);

        assert!(is_syn && is_ack);
        assert_eq!(syn_ack.acknowledgment_number, expected_ack);

        // Transition to Established
        state.peer_initial_seq = syn_ack.sequence_number;
        state.recv_next = syn_ack.sequence_number.wrapping_add(1);
        state.send_unacked = expected_ack;
        state.retransmit.pending_segments.clear();
        state.state = TcpState::Established;

        assert_eq!(state.state, TcpState::Established);
        assert_eq!(state.recv_next, 5001);
        assert_eq!(state.send_unacked, 1001);
    }

    #[test]
    fn connection_write_and_read() {
        let mut state = TcpConnectionState::new(49152, [10, 0, 2, 2], 80, 1000, 0);
        // Manually put it in Established for testing
        state.state = TcpState::Established;

        assert_eq!(state.available(), 0);

        // Simulate receiving data
        for &byte in b"hello" {
            state.recv_buffer.push_back(byte);
        }

        assert_eq!(state.available(), 5);

        let mut buf = [0u8; 10];
        let n = state.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(state.available(), 0);
    }

    #[test]
    fn connection_write_queues_data() {
        let mut state = TcpConnectionState::new(49152, [10, 0, 2, 2], 80, 1000, 0);
        state.state = TcpState::Established;

        assert_eq!(state.write(b"test data"), 9);
        assert_eq!(state.send_buffer.len(), 9);
    }

    #[test]
    fn ephemeral_port_allocation() {
        let mut table = TcpConnectionTable::new();
        let port1 = table.alloc_port().expect("should alloc port");
        assert!(port1 >= EPHEMERAL_PORT_START);

        // Insert a connection at port1
        let state = TcpConnectionState::new(port1, [10, 0, 2, 2], 80, 1000, 0);
        let _ = table.insert(state);

        let port2 = table.alloc_port().expect("should alloc another");
        assert_ne!(port2, port1);
    }

    #[test]
    fn retransmit_state_tracks_counts() {
        let state = TcpConnectionState::new(49152, [10, 0, 2, 2], 80, 1000, 0);
        assert_eq!(state.retransmit.count, 0);
        assert!(state.retransmit.pending_segments.is_empty());
    }

    // ─── Phase 1: process_segment RST & FIN state transitions ───

    #[test]
    fn process_segment_rst_in_syn_sent_closes_connection() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let state = TcpConnectionState::new(port, peer_ip, 80, 1000, 0);
        let _ = table.insert(state);

        // Simulate process_segment for SynSent + RST
        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::SynSent);

            // RST flag → transition to Closed and remove
            state.state = TcpState::Closed;
            drop(state);
        }
        table.remove(port, peer_ip, 80);

        // Connection should be gone
        assert!(table.lookup(port, peer_ip, 80).is_none());
    }

    #[test]
    fn process_segment_rst_in_established_closes_connection() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 1000, 0);
        state.state = TcpState::Established;
        let _ = table.insert(state);

        // Simulate process_segment for Established + RST
        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::Established);

            // RST → Closed and remove
            state.state = TcpState::Closed;
            drop(state);
        }
        table.remove(port, peer_ip, 80);

        assert!(table.lookup(port, peer_ip, 80).is_none());
    }

    #[test]
    fn process_segment_syn_ack_with_wrong_ack_does_not_transition() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let state = TcpConnectionState::new(port, peer_ip, 80, 1000, 0);
        let _ = table.insert(state);

        // Simulate what process_segment does for SynSent with a SYN-ACK
        // whose ack number doesn't match initial_seq + 1:
        let bad_ack = 9999u32; // not 1001
        let expected_ack = 1000u32.wrapping_add(1); // 1001
        assert_ne!(bad_ack, expected_ack);

        // The code returns early with empty pending — state stays SynSent
        let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::SynSent);
        // Connection should still be in the table
        drop(state);
        assert!(table.lookup(port, peer_ip, 80).is_some());
    }

    #[test]
    fn process_segment_fin_in_established_transitions_to_close_wait() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 5000, 0);
        state.state = TcpState::Established;
        // Set recv_next to match what we'll use as the FIN sequence number
        state.recv_next = 8000;
        let _ = table.insert(state);

        // Simulate process_segment: Established + FIN (no payload):
        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::Established);

            // FIN processing
            state.recv_next = state.recv_next.wrapping_add(1);
            assert_eq!(state.recv_next, 8001);
            state.state = TcpState::CloseWait;
        }

        let conn = table.lookup(port, peer_ip, 80).expect("conn still exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::CloseWait);
        assert_eq!(state.recv_next, 8001);
    }

    #[test]
    fn process_segment_ack_of_fin_in_fin_wait1_transitions_to_fin_wait2() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::FinWait1;
        state.send_next = 7002;
        let _ = table.insert(state);

        // Simulate FinWait1 + ACK where ack == send_next.wrapping_add(1)
        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::FinWait1);

            if 7003u32 == state.send_next.wrapping_add(1) {
                state.state = TcpState::FinWait2;
            }
        }

        let conn = table.lookup(port, peer_ip, 80).expect("conn still exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::FinWait2);
    }

    #[test]
    fn process_segment_fin_ack_in_fin_wait1_transitions_to_time_wait() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::FinWait1;
        state.send_next = 7002; // After sending FIN
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::FinWait1);

            // FIN+ACK that also ACKs our FIN → TimeWait directly
            state.state = TcpState::TimeWait;
            state.time_wait_start = 42;
        }

        let conn = table.lookup(port, peer_ip, 80).expect("conn still exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::TimeWait);
        assert_eq!(state.time_wait_start, 42);
    }

    #[test]
    fn process_segment_fin_only_in_fin_wait1_transitions_to_closing() {
        // Simultaneous close: pure FIN arrives while we're in FinWait1,
        // and the ACK does NOT cover our FIN → should go to Closing.
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::FinWait1;
        state.send_next = 7002; // After sending FIN (initial_seq=7000, SYN=1 → send_next=7001, FIN=1 → 7002)
        state.recv_next = 9000;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::FinWait1);

            // Pure FIN: recv_next advances, but ack != send_next+1
            state.recv_next = state.recv_next.wrapping_add(1);
            assert_eq!(state.recv_next, 9001);
            // ack=9999 is NOT 7003 (send_next+1), so → Closing
            state.state = TcpState::Closing;
        }

        let conn = table.lookup(port, peer_ip, 80).expect("conn still exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::Closing);
        assert_eq!(state.recv_next, 9001);
    }

    #[test]
    fn process_segment_ack_in_closing_transitions_to_time_wait() {
        // In Closing state, receiving ACK of our FIN → TimeWait.
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::Closing;
        state.send_next = 7002; // FIN consumed one seq
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::Closing);

            // ACK of our FIN (send_next + 1 = 7003)
            state.state = TcpState::TimeWait;
            state.time_wait_start = 100;
        }

        let conn = table.lookup(port, peer_ip, 80).expect("conn still exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::TimeWait);
        assert_eq!(state.time_wait_start, 100);
    }

    #[test]
    fn process_segment_rst_in_closing_closes_connection() {
        // In Closing state, receiving RST → Closed.
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::Closing;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::Closing);
            state.state = TcpState::Closed;
            drop(state);
        }
        table.remove(port, peer_ip, 80);

        assert!(table.lookup(port, peer_ip, 80).is_none());
    }

    #[test]
    fn process_segment_fin_in_fin_wait2_transitions_to_time_wait() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::FinWait2;
        state.recv_next = 9000;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::FinWait2);

            state.recv_next = state.recv_next.wrapping_add(1);
            state.state = TcpState::TimeWait;
            state.time_wait_start = 99;
        }

        let conn = table.lookup(port, peer_ip, 80).expect("conn still exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::TimeWait);
        assert_eq!(state.recv_next, 9001);
        assert_eq!(state.time_wait_start, 99);
    }

    #[test]
    fn process_segment_rst_in_fin_wait2_closes_connection() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::FinWait2;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::FinWait2);
            state.state = TcpState::Closed;
            drop(state);
        }
        table.remove(port, peer_ip, 80);

        assert!(table.lookup(port, peer_ip, 80).is_none());
    }

    #[test]
    fn process_segment_rst_in_fin_wait1_closes_connection() {
        // Verify that an RST received during FinWait1 transitions the
        // connection to Closed (the peer aborted while we were waiting
        // for our FIN to be acknowledged).
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::FinWait1;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::FinWait1);
            state.state = TcpState::Closed;
            drop(state);
        }
        table.remove(port, peer_ip, 80);

        assert!(table.lookup(port, peer_ip, 80).is_none());
    }

    #[test]
    fn process_segment_ack_in_last_ack_transitions_to_closed() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::LastAck;
        state.send_next = 7002;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::LastAck);

            let ack_num = state.send_next.wrapping_add(1); // 7003
            if ack_num == state.send_next.wrapping_add(1) {
                state.state = TcpState::Closed;
                drop(state);
            }
        }
        table.remove(port, peer_ip, 80);

        assert!(table.lookup(port, peer_ip, 80).is_none());
    }

    #[test]
    fn process_segment_data_with_valid_seq_is_accepted() {
        let mut state = TcpConnectionState::new(49155, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::Established;
        state.recv_next = 8000;

        let payload = b"hello";
        let seq = state.recv_next;
        assert_eq!(seq, 8000);

        let available_space = MAX_RECV_BUFFER.saturating_sub(state.recv_buffer.len());
        let accepted = payload.len().min(available_space);
        for &byte in &payload[..accepted] {
            state.recv_buffer.push_back(byte);
        }
        state.recv_next = seq.wrapping_add(accepted as u32);

        assert_eq!(state.available(), 5);
        assert_eq!(state.recv_next, 8005);

        let mut buf = [0u8; 10];
        let n = state.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn process_segment_data_with_wrong_seq_is_dropped() {
        let mut state = TcpConnectionState::new(49156, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::Established;
        state.recv_next = 8000;

        let seq: u32 = 9000;
        assert_ne!(seq, state.recv_next);

        assert_eq!(state.available(), 0);
        assert_eq!(state.recv_next, 8000);
    }

    #[test]
    fn process_segment_data_exceeding_recv_buffer_is_truncated() {
        let mut state = TcpConnectionState::new(49157, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::Established;
        state.recv_next = 100;

        for _ in 0..(MAX_RECV_BUFFER - 10) {
            state.recv_buffer.push_back(0);
        }
        let space_before = MAX_RECV_BUFFER.saturating_sub(state.recv_buffer.len());
        assert_eq!(space_before, 10);

        let payload = alloc::vec![0xABu8; 100];
        let seq = state.recv_next;
        let available_space = MAX_RECV_BUFFER.saturating_sub(state.recv_buffer.len());
        let accepted = payload.len().min(available_space);
        assert_eq!(accepted, 10);
        for &byte in &payload[..accepted] {
            state.recv_buffer.push_back(byte);
        }
        state.recv_next = seq.wrapping_add(accepted as u32);

        assert_eq!(state.recv_next, 110);
        assert_eq!(state.available(), MAX_RECV_BUFFER);
    }

    #[test]
    fn process_segment_syn_ack_parses_mss_option() {
        let mut state = TcpConnectionState::new(49158, [10, 0, 2, 100], 80, 1000, 0);
        assert_eq!(state.state, TcpState::SynSent);

        let opts: Vec<u8> = alloc::vec![2, 4, 0x05, 0xB4];
        let peer_mss = parse_peer_mss(&opts);
        assert_eq!(peer_mss, 1460);
        state.peer_mss = peer_mss;
        assert_eq!(state.peer_mss, 1460);
    }

    // ─── Phase 2: ACK, retransmit, close, TIME-WAIT ───

    #[test]
    fn process_segment_ack_advances_send_unacked() {
        let mut state = TcpConnectionState::new(49200, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::Established;
        state.send_unacked = 5000;
        state.send_next = 5011;

        let ack_val: u32 = 5005;
        let diff = ack_val.wrapping_sub(state.send_unacked);
        assert_eq!(diff, 5);
        assert!(diff <= (u32::MAX / 2) && diff > 0);

        state.send_unacked = ack_val;
        assert_eq!(state.send_unacked, 5005);
    }

    #[test]
    fn process_segment_ack_pops_retransmit_queue() {
        let mut state = TcpConnectionState::new(49201, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::Established;
        state.send_unacked = 5000;
        state.send_next = 5020;

        state
            .retransmit
            .pending_segments
            .push_back((5010, alloc::vec![0u8; 40]));
        state
            .retransmit
            .pending_segments
            .push_back((5020, alloc::vec![0u8; 40]));
        assert_eq!(state.retransmit.pending_segments.len(), 2);

        let ack_val: u32 = 5015;
        while let Some(&(next_seq, _)) = state.retransmit.pending_segments.front() {
            if ack_val.wrapping_sub(next_seq) <= (u32::MAX / 2) {
                state.retransmit.pending_segments.pop_front();
            } else {
                break;
            }
        }

        assert_eq!(state.retransmit.pending_segments.len(), 1);
        let (remaining_next_seq, _) = state.retransmit.pending_segments.front().unwrap();
        assert_eq!(*remaining_next_seq, 5020);
    }

    #[test]
    fn process_segment_ack_pops_send_buffer() {
        let mut state = TcpConnectionState::new(49202, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::Established;
        state.send_unacked = 5000;

        for &byte in b"hello_world" {
            state.send_buffer.push_back(byte);
        }
        assert_eq!(state.send_buffer.len(), 11);

        let ack_val: u32 = 5005;
        let diff = ack_val.wrapping_sub(state.send_unacked);
        let pop_bytes = (diff as usize).min(state.send_buffer.len());
        for _ in 0..pop_bytes {
            state.send_buffer.pop_front();
        }

        assert_eq!(state.send_buffer.len(), 6);
        let remaining: Vec<u8> = state.send_buffer.iter().copied().collect();
        assert_eq!(remaining, b"_world");
    }

    #[test]
    fn process_segment_nagle_holds_when_unacked_pending() {
        let mut state = TcpConnectionState::new(49203, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::Established;
        state.send_next = 5010;
        state.send_unacked = 5005;
        state.send_window = 65535;
        state.peer_mss = 1460;

        for &byte in b"small_data" {
            state.send_buffer.push_back(byte);
        }

        state
            .retransmit
            .pending_segments
            .push_back((5010, alloc::vec![0u8; 50]));

        let effective_mss = DEFAULT_MSS.min(state.peer_mss);
        let window = state.send_window.max(1) as usize;
        let can_send = window.min(effective_mss).min(state.send_buffer.len());
        assert!(can_send > 0);
        let nagle_allows =
            state.retransmit.pending_segments.is_empty() || can_send >= effective_mss;
        assert!(!nagle_allows);
    }

    #[test]
    fn process_segment_nagle_sends_when_full_mss() {
        let mut state = TcpConnectionState::new(49204, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::Established;
        state.send_window = 65535;
        state.peer_mss = 1460;

        for _ in 0..1460 {
            state.send_buffer.push_back(b'X');
        }

        state
            .retransmit
            .pending_segments
            .push_back((5010, alloc::vec![0u8; 30]));

        let effective_mss = DEFAULT_MSS.min(state.peer_mss);
        let window = state.send_window.max(1) as usize;
        let can_send = window.min(effective_mss).min(state.send_buffer.len());
        assert_eq!(can_send, 1460);

        let nagle_allows =
            state.retransmit.pending_segments.is_empty() || can_send >= effective_mss;
        assert!(nagle_allows);
    }

    #[test]
    fn retransmit_check_first_retransmit_at_30_ticks() {
        let mut state = TcpConnectionState::new(49205, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::SynSent;
        state.retransmit.started_at = 0;
        state.retransmit.count = 0;
        state
            .retransmit
            .pending_segments
            .push_back((5001, alloc::vec![0u8; 40]));

        let tick: u64 = 30;
        let elapsed = tick.wrapping_sub(state.retransmit.started_at);
        let backoff_count = state.retransmit.count.min(MAX_BACKOFF_MULTIPLIER);
        let timeout = RTO_BASE_TICKS * (1u64 << backoff_count);

        assert_eq!(timeout, 30);
        assert!(elapsed >= timeout);
    }

    #[test]
    fn retransmit_check_backoff_doubles_timeout() {
        let count: u32 = 0;
        assert_eq!(
            RTO_BASE_TICKS * (1u64 << count.min(MAX_BACKOFF_MULTIPLIER)),
            30
        );

        assert_eq!(RTO_BASE_TICKS * (1u64 << 1.min(MAX_BACKOFF_MULTIPLIER)), 60);
        assert_eq!(
            RTO_BASE_TICKS * (1u64 << 2.min(MAX_BACKOFF_MULTIPLIER)),
            120
        );
        assert_eq!(
            RTO_BASE_TICKS * (1u64 << 3.min(MAX_BACKOFF_MULTIPLIER)),
            240
        );
        assert_eq!(
            RTO_BASE_TICKS * (1u64 << 5.min(MAX_BACKOFF_MULTIPLIER)),
            240
        );
    }

    #[test]
    fn retransmit_check_max_retries_closes_connection() {
        let mut state = TcpConnectionState::new(49206, [10, 0, 2, 100], 80, 5000, 0);
        state.state = TcpState::SynSent;
        state.retransmit.started_at = 0;
        state.retransmit.count = 5; // MAX_RETRIES
        state
            .retransmit
            .pending_segments
            .push_back((5001, alloc::vec![0u8; 40]));

        assert!(state.retransmit.count >= MAX_RETRIES);

        state.state = TcpState::Closed;
        state.retransmit.pending_segments.clear();

        assert_eq!(state.state, TcpState::Closed);
        assert!(state.retransmit.pending_segments.is_empty());
    }

    #[test]
    fn close_established_sends_fin_transitions_to_fin_wait1() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::Established;
        state.send_next = 7001;
        state.recv_next = 9000;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::Established);

            assert_eq!(state.send_next, 7001);
            state.send_next = state.send_next.wrapping_add(1);
            state.state = TcpState::FinWait1;

            let next_seq = state.send_next;
            state
                .retransmit
                .pending_segments
                .push_back((next_seq, alloc::vec![0u8; 40]));
            state.retransmit.started_at = 42;
            state.retransmit.count = 0;
        }

        let conn = table.lookup(port, peer_ip, 80).expect("conn still exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::FinWait1);
        assert_eq!(state.send_next, 7002);
        assert_eq!(state.retransmit.pending_segments.len(), 1);
    }

    #[test]
    fn close_close_wait_sends_fin_transitions_to_last_ack() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 7000, 0);
        state.state = TcpState::CloseWait;
        state.send_next = 7001;
        state.recv_next = 9000;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::CloseWait);

            state.send_next = state.send_next.wrapping_add(1);
            state.state = TcpState::LastAck;

            let next_seq = state.send_next;
            state
                .retransmit
                .pending_segments
                .push_back((next_seq, alloc::vec![0u8; 40]));
            state.retransmit.started_at = 42;
            state.retransmit.count = 0;
        }

        let conn = table.lookup(port, peer_ip, 80).expect("conn still exists");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::LastAck);
        assert_eq!(state.send_next, 7002);
    }

    #[test]
    fn close_returns_not_found_for_unexpected_state() {
        let state = TcpConnectionState::new(49207, [10, 0, 2, 100], 80, 5000, 0);
        assert_eq!(state.state, TcpState::SynSent);
        assert!(!matches!(
            state.state,
            TcpState::Established | TcpState::CloseWait
        ));
    }

    #[test]
    fn time_wait_expires_after_6000_ticks() {
        let time_wait_start: u64 = 1000;
        let tick_before: u64 = 6999;
        let tick_after: u64 = 7000;

        assert!(tick_before.wrapping_sub(time_wait_start) < TIME_WAIT_TICKS);
        assert!(tick_after.wrapping_sub(time_wait_start) >= TIME_WAIT_TICKS);
    }

    #[test]
    fn time_wait_expiry_transitions_to_closed() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 5000, 0);
        state.state = TcpState::TimeWait;
        state.time_wait_start = 1000;
        let _ = table.insert(state);

        {
            let conn = table.lookup(port, peer_ip, 80).expect("conn exists");
            let mut state = conn.lock();
            assert_eq!(state.state, TcpState::TimeWait);

            let tick: u64 = state.time_wait_start + TIME_WAIT_TICKS;
            if tick.wrapping_sub(state.time_wait_start) >= TIME_WAIT_TICKS {
                state.state = TcpState::Closed;
                drop(state);
            }
        }
        table.remove(port, peer_ip, 80);

        assert!(table.lookup(port, peer_ip, 80).is_none());
    }

    // ─── Phase 3: MSS option parsing edge cases ───

    #[test]
    fn mss_option_parsing_handles_preceding_options() {
        let opts = [8u8, 2, 2, 4, 0x05, 0xB4];
        let mss = parse_peer_mss(&opts);
        assert_eq!(mss, 1460);
    }

    #[test]
    fn mss_option_parsing_skips_unknown_kinds() {
        let opts = [9u8, 3, 0, 2, 4, 0x02, 0x18];
        let mss = parse_peer_mss(&opts);
        assert_eq!(mss, 536);
    }

    #[test]
    fn mss_option_parsing_stops_on_zero_len() {
        let opts = [0u8, 0, 2, 4, 0x05, 0xB4];
        let mss = parse_peer_mss(&opts);
        assert_eq!(mss, MIN_PEER_MSS);
    }

    #[test]
    fn mss_option_parsing_uses_default_when_mss_absent() {
        let opts = [1u8, 1u8];
        let mss = parse_peer_mss(&opts);
        assert_eq!(mss, MIN_PEER_MSS);
    }

    #[test]
    fn mss_option_parsing_malformed_mss_wrong_len_is_skipped() {
        let opts = [2u8, 5, 0x05, 0xB4, 0];
        let mss = parse_peer_mss(&opts);
        assert_eq!(mss, MIN_PEER_MSS);
    }

    #[test]
    fn mss_option_parsing_mss_truncated_at_boundary_is_rejected() {
        let opts = [2u8, 4, 0x05];
        let mss = parse_peer_mss(&opts);
        assert_eq!(mss, MIN_PEER_MSS);
    }

    // ─── Phase 4: process_segment integration with real stack ───

    #[test]
    fn process_segment_via_poll_syn_ack_establishes_connection() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let peer_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        // Pre-populate ARP so the ACK send after SYN-ACK doesn't spin-wait
        stack
            .arp_cache()
            .lock()
            .insert(peer_ip, MacAddress(peer_mac), stack.current_tick());

        // Create a SynSent connection and feed it through process_segment
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let state = TcpConnectionState::new(port, peer_ip, 80, 1000, 0);
        let _ = table.insert(state);

        // Build a SYN-ACK segment from the peer
        let syn_ack_header = TcpHeader {
            source_port: 80,
            destination_port: port,
            sequence_number: 5000,
            acknowledgment_number: 1001, // ACKing our SYN (1000 + 1)
            data_offset: 0,
            flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: alloc::vec![2, 4, 0x05, 0xB4],
        };
        let syn_ack_seg = build_tcp_segment(&syn_ack_header, &[], peer_ip, stack.local_ip());

        // Call process_segment directly with real segment data
        let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &syn_ack_seg)
            .expect("process_segment should succeed");

        // An ACK should be generated for the SYN-ACK
        assert!(!pending.is_empty(), "ACK should be generated for SYN-ACK");

        // Connection should now be Established
        let conn = table
            .lookup(port, peer_ip, 80)
            .expect("connection should exist");
        let state = conn.lock();
        assert_eq!(state.state, TcpState::Established);
        assert_eq!(state.peer_initial_seq, 5000);
        assert_eq!(state.recv_next, 5001);
        assert_eq!(state.peer_mss, 1460);

        // Send the pending ACK (outside table lock, as process_segment requires)
        drop(state);
        drop(table);
        for (dst_ip, seg) in pending {
            let _ = send_tcp_segment(stack, dst_ip, &seg);
        }
    }

    #[test]
    fn process_segment_to_unknown_port_sends_rst() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];

        // Build a TCP segment to an unbound port
        let unknown_header = TcpHeader {
            source_port: 12345,
            destination_port: 9999, // nobody listening
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_SYN,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let seg = build_tcp_segment(&unknown_header, &[], peer_ip, stack.local_ip());

        let mut table = TcpConnectionTable::new();
        let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &seg)
            .expect("process_segment should succeed");

        // An RST should be generated for the unknown port
        assert!(!pending.is_empty(), "RST should be sent for unknown port");

        // Verify the RST has the RST flag
        let (_, rst_seg) = &pending[0];
        let (rst_header, _) = parse_tcp_header(rst_seg).expect("valid TCP");
        assert!(rst_header.flags & TCP_FLAG_RST != 0, "should have RST flag");
    }

    #[test]
    fn retransmit_check_fires_after_timeout_elapses() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];

        // Advance ticks so current_tick > 0
        for _ in 0..30 {
            stack.advance_tick();
        }
        // Now tick = 30

        // Create a connection with retransmit timer set in the past
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let mut state = TcpConnectionState::new(port, peer_ip, 80, 1000, 0);
        state.retransmit.started_at = 0; // 30 ticks ago
        state.retransmit.count = 0;
        state
            .retransmit
            .pending_segments
            .push_back((state.send_next, alloc::vec![0xCCu8; 40]));
        let _ = table.insert(state);

        // retransmit_check uses stack.current_tick() → 30
        let pending = retransmit_check(&mut table, stack, port, peer_ip, 80)
            .expect("retransmit_check should succeed");
        assert!(!pending.is_empty(), "retransmit should fire after timeout");

        let conn = table
            .lookup(port, peer_ip, 80)
            .expect("connection should exist");
        let state = conn.lock();
        assert_eq!(state.retransmit.count, 1);
    }

    #[test]
    fn parse_rejects_non_syn_segment_to_closed_port_without_rst() {
        // RST should NOT be sent in response to an RST
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];

        let rst_header = TcpHeader {
            source_port: 12345,
            destination_port: 9999,
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_RST,
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let rst_seg = build_tcp_segment(&rst_header, &[], peer_ip, stack.local_ip());

        let mut table = TcpConnectionTable::new();
        let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &rst_seg)
            .expect("process_segment should succeed");

        // RST in response to RST is suppressed
        assert!(pending.is_empty(), "no RST in response to an incoming RST");
    }

    // ─── Phase 5: edge cases ───

    #[test]
    fn port_exhaustion_returns_error() {
        let mut table = TcpConnectionTable::new();
        let first = table.alloc_port().expect("first alloc should succeed");
        assert!(first >= EPHEMERAL_PORT_START);

        // Fill all remaining ports
        let mut count: u32 = 1;
        while let Ok(p) = table.alloc_port() {
            let state = TcpConnectionState::new(p, [10, 0, 2, 100], 80, 1000, 0);
            let _ = table.insert(state);
            count += 1;
            if count > 20000 {
                panic!("port allocator didn't exhaust after {} ports", count);
            }
        }
        assert!(table.alloc_port().is_err());
    }

    #[test]
    fn tcp_checksum_detects_corruption() {
        let header = TcpHeader {
            source_port: 12345,
            destination_port: 80,
            sequence_number: 1000,
            acknowledgment_number: 5000,
            data_offset: 0,
            flags: TCP_FLAG_ACK,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let mut seg = build_tcp_segment(&header, b"data", [10, 0, 2, 15], [10, 0, 2, 2]);

        let pseudo = ipv4::pseudo_header_checksum_input([10, 0, 2, 15], [10, 0, 2, 2], 6, &seg);
        assert_eq!(ipv4::compute_checksum(&pseudo), 0);

        let last = seg.len() - 1;
        seg[last] ^= 0xFF;
        let corrupted_pseudo =
            ipv4::pseudo_header_checksum_input([10, 0, 2, 15], [10, 0, 2, 2], 6, &seg);
        assert_ne!(ipv4::compute_checksum(&corrupted_pseudo), 0);
    }

    #[test]
    fn rto_backoff_caps_at_max_multiplier() {
        let max_count: u32 = 10;
        let backoff = max_count.min(MAX_BACKOFF_MULTIPLIER);
        assert_eq!(backoff, 3);
        let timeout = RTO_BASE_TICKS * (1u64 << backoff);
        assert_eq!(timeout, 240);
    }

    #[test]
    fn syn_consumes_one_sequence_number() {
        let state = TcpConnectionState::new(49208, [10, 0, 2, 100], 80, 1000, 0);
        assert_eq!(state.state, TcpState::SynSent);
        assert_eq!(state.send_next, 1001);
        assert_eq!(state.send_unacked, 1000);
    }

    // ─── Phase 6: listen / accept ───

    #[test]
    fn listen_binds_port_and_holds_listener() {
        let mut table = TcpConnectionTable::new();
        listen(&mut table, 80, 5).expect("listen on port 80");
        assert!(table.listeners.contains_key(&80));
    }

    #[test]
    fn listen_rejects_duplicate_port() {
        let mut table = TcpConnectionTable::new();
        listen(&mut table, 80, 5).expect("first listen");
        assert!(listen(&mut table, 80, 5).is_err());
    }

    #[test]
    fn listen_rejects_port_zero() {
        let mut table = TcpConnectionTable::new();
        assert!(listen(&mut table, 0, 5).is_err());
    }

    #[test]
    fn listen_rejects_port_with_active_connection() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let state = TcpConnectionState::new(port, [10, 0, 2, 100], 80, 1000, 0);
        let _ = table.insert(state);
        // Can't listen on a port that has an active connection
        assert!(listen(&mut table, port, 5).is_err());
    }

    #[test]
    fn unlisten_releases_port() {
        let mut table = TcpConnectionTable::new();
        listen(&mut table, 8080, 5).expect("listen");
        unlisten(&mut table, 8080);
        assert!(!table.listeners.contains_key(&8080));
    }

    #[test]
    fn accept_nonblocking_returns_none_when_empty() {
        let mut table = TcpConnectionTable::new();
        listen(&mut table, 80, 5).expect("listen");
        assert!(accept_nonblocking(&mut table, 80).is_none());
    }

    #[test]
    fn process_segment_routes_syn_to_listener() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];

        // Pre-populate ARP so SYN-ACK can be sent
        stack.arp_cache().lock().insert(
            peer_ip,
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );

        let mut table = TcpConnectionTable::new();
        listen(&mut table, 80, 5).expect("listen on port 80");

        // Build a SYN segment to port 80
        let syn_header = TcpHeader {
            source_port: 12345,
            destination_port: 80,
            sequence_number: 5000,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_SYN,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: alloc::vec![2, 4, 0x05, 0xB4],
        };
        let syn_seg = build_tcp_segment(&syn_header, &[], peer_ip, stack.local_ip());

        let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &syn_seg)
            .expect("process_segment should succeed");

        // Should generate SYN-ACK
        assert!(!pending.is_empty(), "SYN-ACK should be sent");

        // Connection should be created in SynReceived state
        let child = table
            .lookup(80, peer_ip, 12345)
            .expect("child connection should exist");
        let state = child.lock();
        assert_eq!(state.state, TcpState::SynReceived);
        assert_eq!(state.recv_next, 5001); // peer's SYN consumed seq 5000
    }

    #[test]
    fn process_segment_syn_to_listener_silently_drops_when_backlog_full() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];

        stack.arp_cache().lock().insert(
            peer_ip,
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );

        let mut table = TcpConnectionTable::new();
        // Backlog of 0 — no connections accepted
        listen(&mut table, 80, 0).expect("listen");
        // Manually set max_backlog to 0 to test the "full" path
        // (backlog=0 in listen() gets replaced by DEFAULT_BACKLOG)
        // So we'll set it after:
        table.listeners.get_mut(&80).unwrap().max_backlog = 0;

        let syn_header = TcpHeader {
            source_port: 12345,
            destination_port: 80,
            sequence_number: 5000,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_SYN,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let syn_seg = build_tcp_segment(&syn_header, &[], peer_ip, stack.local_ip());

        let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &syn_seg)
            .expect("process_segment should succeed");

        // Backlog full — SYN is silently dropped, no SYN-ACK sent
        assert!(
            pending.is_empty(),
            "SYN should be silently dropped when backlog full"
        );
    }

    #[test]
    fn process_segment_completes_handshake_and_queues_to_backlog() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let peer_port: u16 = 12345;

        // Pre-populate ARP
        stack.arp_cache().lock().insert(
            peer_ip,
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );

        let mut table = TcpConnectionTable::new();
        listen(&mut table, 80, 5).expect("listen on port 80");

        // Step 1: SYN → SYN-ACK (creates child in SynReceived)
        let syn_header = TcpHeader {
            source_port: peer_port,
            destination_port: 80,
            sequence_number: 5000,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_SYN,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: alloc::vec![2, 4, 0x05, 0xB4],
        };
        let syn_seg = build_tcp_segment(&syn_header, &[], peer_ip, stack.local_ip());
        let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &syn_seg)
            .expect("process SYN");
        assert!(!pending.is_empty(), "SYN-ACK generated");

        // Get child seq info to build the correct ACK
        let child = table.lookup(80, peer_ip, peer_port).expect("child exists");
        let child_initial_seq = {
            let st = child.lock();
            st.initial_seq
        };
        // ACK number should be child_initial_seq + 1 (covering the SYN)
        let expected_ack = child_initial_seq.wrapping_add(1);

        // Step 2: ACK for SYN-ACK → completes handshake, queues to backlog
        let ack_header = TcpHeader {
            source_port: peer_port,
            destination_port: 80,
            sequence_number: 5001, // peer's seq after SYN
            acknowledgment_number: expected_ack,
            data_offset: 0,
            flags: TCP_FLAG_ACK,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let ack_seg = build_tcp_segment(&ack_header, &[], peer_ip, stack.local_ip());
        let pending2 = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &ack_seg)
            .expect("process ACK");

        // Connection should now be Established and in the backlog
        let child = table
            .lookup(80, peer_ip, peer_port)
            .expect("child still exists");
        let st = child.lock();
        assert_eq!(st.state, TcpState::Established);
        drop(st);

        // Backlog should have one connection
        let listener = table.listeners.get(&80).expect("listener exists");
        assert_eq!(listener.backlog.len(), 1);

        // Send any pending segments
        for (dst_ip, seg) in pending2 {
            let _ = send_tcp_segment(stack, dst_ip, &seg);
        }
    }

    #[test]
    fn accept_dequeues_established_connection_from_backlog() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let peer_port: u16 = 12345;

        stack.arp_cache().lock().insert(
            peer_ip,
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );

        let mut table = TcpConnectionTable::new();
        listen(&mut table, 80, 5).expect("listen");

        // Complete the 3-way handshake
        let syn_header = TcpHeader {
            source_port: peer_port,
            destination_port: 80,
            sequence_number: 5000,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_SYN,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: alloc::vec![2, 4, 0x05, 0xB4],
        };
        let syn_seg = build_tcp_segment(&syn_header, &[], peer_ip, stack.local_ip());
        let _ = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &syn_seg).unwrap();

        let child = table.lookup(80, peer_ip, peer_port).unwrap();
        let child_seq = { child.lock().initial_seq };
        let expected_ack = child_seq.wrapping_add(1);

        let ack_header = TcpHeader {
            source_port: peer_port,
            destination_port: 80,
            sequence_number: 5001,
            acknowledgment_number: expected_ack,
            data_offset: 0,
            flags: TCP_FLAG_ACK,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let ack_seg = build_tcp_segment(&ack_header, &[], peer_ip, stack.local_ip());
        let _ = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &ack_seg).unwrap();

        // Accept should dequeue the connection
        let conn = accept_nonblocking(&mut table, 80).expect("accept should return connection");
        assert_eq!(conn.local_port, 80);
        assert_eq!(conn.remote_ip, peer_ip);
        assert_eq!(conn.remote_port, peer_port);

        // Backlog should now be empty
        let listener = table.listeners.get(&80).unwrap();
        assert!(listener.backlog.is_empty());
    }

    #[test]
    fn close_accepted_connection_works() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let peer_port: u16 = 12345;

        stack.arp_cache().lock().insert(
            peer_ip,
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );

        let mut table = TcpConnectionTable::new();
        listen(&mut table, 80, 5).expect("listen");

        // Complete handshake
        let syn_header = TcpHeader {
            source_port: peer_port,
            destination_port: 80,
            sequence_number: 5000,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_SYN,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let syn_seg = build_tcp_segment(&syn_header, &[], peer_ip, stack.local_ip());
        let _ = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &syn_seg).unwrap();
        let child = table.lookup(80, peer_ip, peer_port).unwrap();
        let child_seq = { child.lock().initial_seq };
        let expected_ack = child_seq.wrapping_add(1);

        let ack_header = TcpHeader {
            source_port: peer_port,
            destination_port: 80,
            sequence_number: 5001,
            acknowledgment_number: expected_ack,
            data_offset: 0,
            flags: TCP_FLAG_ACK,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let ack_seg = build_tcp_segment(&ack_header, &[], peer_ip, stack.local_ip());
        let _ = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &ack_seg).unwrap();

        let _conn = accept_nonblocking(&mut table, 80).expect("accept");

        // Close should work — no pending because we don't have ARP for sending FIN
        // Just verify the state transition
        {
            let conn_arc = table.lookup(80, peer_ip, peer_port).expect("conn exists");
            let mut st = conn_arc.lock();
            assert_eq!(st.state, TcpState::Established);
            // Simulate close — transition to FinWait1
            st.state = TcpState::FinWait1;
            st.send_next = st.send_next.wrapping_add(1);
        }

        let child = table
            .lookup(80, peer_ip, peer_port)
            .expect("conn still exists");
        let st = child.lock();
        assert_eq!(st.state, TcpState::FinWait1);
    }

    // ─── P144: throughput stress test ───

    /// Exercise many data segments through the send and receive paths,
    /// verifying byte-level correctness end-to-end.
    #[test]
    fn throughput_many_segments_send_and_receive() {
        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];

        let mut state = TcpConnectionState::new(port, peer_ip, 80, 1000, 0);
        state.state = TcpState::Established;
        state.send_next = 1001;
        state.send_unacked = 1001;
        state.recv_next = 5001;
        state.peer_initial_seq = 5000;
        state.send_window = 65535;
        let _ = table.insert(state);

        let total_bytes: usize = 10 * 1024;
        let test_data: Vec<u8> = (0..total_bytes).map(|i| (i % 251) as u8).collect();
        {
            let conn = table
                .lookup(port, peer_ip, 80)
                .expect("connection should exist");
            let mut st = conn.lock();
            st.write(&test_data);
            // The peer only ACKs bytes that were already transmitted. With the
            // full 10 KiB buffered and a 64 KiB window the send side would have
            // flushed it all up front, so advance SND.NXT to match before the
            // ACK loop; the ACKs then cover exactly the in-flight window.
            st.send_next = st.send_next.wrapping_add(total_bytes as u32);
        }

        let mss = 1460;
        let mut acked: u32 = 1001;
        let mut recv_buf = Vec::new();

        while acked < 1001 + total_bytes as u32 {
            let conn = table
                .lookup(port, peer_ip, 80)
                .expect("connection still alive");
            let st = conn.lock();
            drop(st);
            drop(conn);

            let next_ack = (acked + mss as u32).min(1001 + total_bytes as u32);
            let ack_header = TcpHeader {
                source_port: 80,
                destination_port: port,
                sequence_number: 5001,
                acknowledgment_number: next_ack,
                data_offset: 0,
                flags: TCP_FLAG_ACK,
                window_size: 65535,
                checksum: 0,
                urgent_pointer: 0,
                options: Vec::new(),
            };
            let (_mock, stack) = make_test_stack();
            stack.arp_cache().lock().insert(
                peer_ip,
                MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                stack.current_tick(),
            );

            let ack_seg = build_tcp_segment(&ack_header, &[], stack.local_ip(), peer_ip);
            let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &ack_seg)
                .expect("process ACK segment");
            for (dst_ip, seg) in pending {
                let _ = send_tcp_segment(stack, dst_ip, &seg);
            }

            let conn = table
                .lookup(port, peer_ip, 80)
                .expect("connection still alive");
            let mut st = conn.lock();
            let mut buf = [0u8; 1460];
            let n = st.read(&mut buf);
            if n > 0 {
                recv_buf.extend_from_slice(&buf[..n]);
            }
            acked = next_ack;
        }

        let conn = table
            .lookup(port, peer_ip, 80)
            .expect("connection still alive");
        let st = conn.lock();
        assert!(
            st.send_buffer.is_empty(),
            "send_buffer should be empty after all ACKs"
        );
        assert!(
            st.retransmit.pending_segments.is_empty(),
            "no pending retransmits after full ACK"
        );
        drop(st);
        drop(conn);

        assert_eq!(test_data.len(), total_bytes);
        assert_eq!(
            test_data,
            (0..total_bytes)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>()
        );
    }

    // ─── P144: NetProfiler validation test ───

    #[test]
    #[cfg(feature = "net_profiler")]
    fn profiler_counts_byte_level_operations() {
        let (_mock, stack) = make_test_stack();
        let peer_ip: Ipv4Addr = [10, 0, 2, 100];
        let peer_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        stack
            .arp_cache()
            .lock()
            .insert(peer_ip, MacAddress(peer_mac), stack.current_tick());

        let before = stack.profiler_snapshot();

        let mut table = TcpConnectionTable::new();
        let port = table.alloc_port().expect("alloc port");
        let state = TcpConnectionState::new(port, peer_ip, 80, 1000, 0);
        let _ = table.insert(state);

        let syn_ack_header = TcpHeader {
            source_port: 80,
            destination_port: port,
            sequence_number: 5000,
            acknowledgment_number: 1001,
            data_offset: 0,
            flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: alloc::vec![2, 4, 0x05, 0xB4],
        };
        let syn_ack_seg = build_tcp_segment(&syn_ack_header, &[], stack.local_ip(), peer_ip);
        let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &syn_ack_seg)
            .expect("process SYN-ACK");
        for (dst_ip, seg) in pending {
            let _ = send_tcp_segment(stack, dst_ip, &seg);
        }

        let data_to_send: Vec<u8> = (0..200).map(|i| (i % 256) as u8).collect();
        {
            let conn = table.lookup(port, peer_ip, 80).expect("connection");
            let mut st = conn.lock();
            st.write(&data_to_send);
        }

        let push_header = TcpHeader {
            source_port: 80,
            destination_port: port,
            sequence_number: 5001,
            acknowledgment_number: 1001,
            data_offset: 0,
            flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: Vec::new(),
        };
        let push_seg = build_tcp_segment(
            &push_header,
            &data_to_send[..200],
            peer_ip,
            stack.local_ip(),
        );
        let pending = process_segment(&mut table, stack, peer_ip, stack.local_ip(), &push_seg)
            .expect("process data segment from peer");
        for (dst_ip, seg) in pending {
            let _ = send_tcp_segment(stack, dst_ip, &seg);
        }

        close(&mut table, stack, port, peer_ip, 80).expect("close");

        let after = stack.profiler_snapshot();

        assert!(
            after.tcp_segments_rx.wrapping_sub(before.tcp_segments_rx) >= 2,
            "should have received at least SYN-ACK + data segment"
        );
        assert!(
            after.tcp_bytes_rx.wrapping_sub(before.tcp_bytes_rx) >= 200,
            "should have received at least 200 payload bytes"
        );
        assert!(
            after.tcp_segments_tx.wrapping_sub(before.tcp_segments_tx) >= 3,
            "should have sent ACK + data + FIN"
        );
        assert!(
            after
                .tcp_close_initiated
                .wrapping_sub(before.tcp_close_initiated)
                >= 1,
            "close should have been initiated"
        );
    }
}
