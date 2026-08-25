//! src/kernel/network/dccp/ops.rs
//!
//! DCCP state machine (RFC 4340 §8) and user-space connection operations.

use alloc::vec::Vec;

use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::internet::ipv4::IpProtocol;
use crate::kernel::network::internet::ipv4::Ipv4Header;
use crate::kernel::network::internet::ipv4::{self};
use crate::kernel::network::internet::ipv6::Ipv6Header;
use crate::kernel::network::internet::ipv6::Ipv6NextHeader;
use crate::kernel::network::internet::ipv6::{self};
use crate::kernel::network::stack::NetworkStack;
use crate::Error;
use crate::Result;

use super::ccid2::decode_ack_vector_value;
use super::header::parse_segment;
use super::header::DccpHeader;
use super::header::DccpPacketBuilder;
use super::header::DccpPacketType;
use super::header::DccpSegment;
use super::options;
use super::table::seq_between;
use super::table::DccpConnKey;
use super::table::DccpConnectionState;
use super::table::DccpConnectionTable;
use super::table::DccpState;
use super::table::NativeDccpConnection;
use super::table::SEQ_MASK;

/// DCCP reset codes (RFC 4340 §5.6).
pub const RESET_CODE_UNSPECIFIED: u8 = 0;
pub const RESET_CODE_CONNECTION_REFUSED: u8 = 7;
pub const RESET_CODE_CONNECTION_RESET: u8 = 4;

/// Retransmit interval (1 second at 100 Hz).
const RETRANSMIT_INTERVAL_TICKS: u64 = 100;
/// Maximum retransmissions before giving up.
const MAX_RETRANSMITS: u32 = 3;
/// TimeWait duration (240 seconds at 100 Hz).
const TIMEWAIT_TICKS: u64 = 24_000;

/// The local source address matching the address family of `remote`.
fn local_source(stack: &NetworkStack, remote: IpAddress) -> IpAddress {
    match remote {
        IpAddress::V4(_) => IpAddress::V4(stack.local_ip()),
        IpAddress::V6(_) => IpAddress::V6(stack.local_ip_v6()),
    }
}

/// Build a Reset segment.
fn build_reset(
    local_port: u16,
    remote_port: u16,
    ack: Option<u64>,
    reset_code: u8,
    src: IpAddress,
    dst: IpAddress,
) -> Vec<u8> {
    let header = DccpHeader {
        packet_type: DccpPacketType::Reset,
        seq: crate::kernel::random::random_u64() & SEQ_MASK,
        ack,
        service_code: None,
        reset_code: Some(reset_code),
        ccval: 0,
        cscov: 0,
    };
    DccpPacketBuilder::new(local_port, remote_port, header).finalize(src, dst, &[])
}

/// Wrap a DCCP segment in an IP packet and send it.
pub fn send_packet(stack: &NetworkStack, dst: IpAddress, dccp_bytes: &[u8]) -> Result<()> {
    match dst {
        IpAddress::V4(dst_v4) => {
            let ip_header = Ipv4Header {
                total_length: 0,
                identification: 0,
                flags_fragment_offset: 0,
                ttl: ipv4::IPV4_DEFAULT_TTL,
                protocol: IpProtocol::Dccp,
                header_checksum: 0,
                source: stack.local_ip(),
                destination: dst_v4,
            };
            let raw = ipv4::build_packet(&ip_header, dccp_bytes);
            stack.send_ipv4_packet(dst_v4, raw)
        }
        IpAddress::V6(dst_v6) => {
            let ip_header = Ipv6Header {
                traffic_class: 0,
                flow_label: 0,
                payload_length: 0,
                next_header: Ipv6NextHeader::Dccp,
                hop_limit: ipv6::IPV6_DEFAULT_HOP_LIMIT,
                source: stack.local_ip_v6(),
                destination: dst_v6,
            };
            let raw = ipv6::build_packet(&ip_header, dccp_bytes);
            stack.send_ipv6_packet(dst_v6, raw)
        }
    }
}

/// Initiate a DCCP connection: send a Request and return a handle.
pub fn connect(
    stack: &NetworkStack,
    dst: IpAddress,
    dst_port: u16,
    service_code: u32,
) -> Result<NativeDccpConnection> {
    let mut table = stack.dccp_table().lock();
    let local_port = table.alloc_ephemeral_port();
    if local_port == 0 {
        return Err(Error::Busy);
    }

    let iss = crate::kernel::random::random_u64() & SEQ_MASK;
    let key = DccpConnKey {
        local_port,
        remote: dst,
        remote_port: dst_port,
    };
    let mut state = DccpConnectionState::new(key, iss, service_code);

    let src = local_source(stack, dst);
    let header = DccpHeader {
        packet_type: DccpPacketType::Request,
        seq: iss,
        ack: None,
        service_code: Some(service_code),
        reset_code: None,
        ccval: 0,
        cscov: 0,
    };
    let mut builder = DccpPacketBuilder::new(local_port, dst_port, header);
    builder.push_option(&options::build_change_l_ccid(2));
    let segment = builder.finalize(src, dst, &[]);

    state.ccid2.on_packet_sent(iss);
    state.retransmit_deadline = Some(stack.current_tick() + RETRANSMIT_INTERVAL_TICKS);
    state.retransmit_count = 0;
    state.retransmit_packet = Some((dst, segment.clone()));
    table.insert(state)?;

    let conn = NativeDccpConnection {
        local_port,
        remote_ip: dst,
        remote_port: dst_port,
    };
    drop(table);
    send_packet(stack, dst, &segment)?;
    Ok(conn)
}

/// Pop a pending connection key from a listener, if any.
pub fn accept_nonblocking(
    stack: &NetworkStack,
    listener_port: u16,
) -> Result<Option<NativeDccpConnection>> {
    let mut table = stack.dccp_table().lock();
    let listener = table.listener_mut(listener_port).ok_or(Error::NotFound)?;
    match listener.pending.pop_front() {
        Some(key) => Ok(Some(NativeDccpConnection {
            local_port: key.local_port,
            remote_ip: key.remote,
            remote_port: key.remote_port,
        })),
        None => Ok(None),
    }
}

/// Send one DCCP datagram on an established connection.
pub fn send(stack: &NetworkStack, conn: &NativeDccpConnection, payload: &[u8]) -> Result<usize> {
    let table = stack.dccp_table().lock();
    let state = table.lookup(&conn.key()).ok_or(Error::NotFound)?;
    let mut state = state.lock();
    if !matches!(state.state, DccpState::Open | DccpState::PartOpen) {
        return Err(Error::ConnectionReset);
    }

    let seq = (state.gss + 1) & SEQ_MASK;
    state.gss = seq;
    state.ccid2.on_packet_sent(seq);

    // Reply to any unacknowledged inbound data with a DataAck; otherwise a
    // plain Data packet.
    let ptype = if state.gsr != 0 {
        DccpPacketType::DataAck
    } else {
        DccpPacketType::Data
    };
    let header = DccpHeader {
        packet_type: ptype,
        seq,
        ack: if state.gsr != 0 {
            Some(state.gsr)
        } else {
            None
        },
        service_code: None,
        reset_code: None,
        ccval: 0,
        cscov: 0,
    };
    let mut builder = DccpPacketBuilder::new(conn.local_port, conn.remote_port, header);
    let ack_vector = state.ccid2.build_ack_vector_option();
    builder.push_option(&ack_vector);
    let src = local_source(stack, conn.remote_ip);
    let segment = builder.finalize(src, conn.remote_ip, payload);

    drop(state);
    drop(table);
    send_packet(stack, conn.remote_ip, &segment)?;
    Ok(payload.len())
}

/// Receive one DCCP datagram (non-blocking).  Returns
/// `(bytes_read, peer_ip, peer_port)` or [`Error::TimedOut`] when empty.
pub fn recv(
    stack: &NetworkStack,
    conn: &NativeDccpConnection,
    buffer: &mut [u8],
) -> Result<(usize, IpAddress, u16)> {
    let table = stack.dccp_table().lock();
    let state = table.lookup(&conn.key()).ok_or(Error::NotFound)?;
    let mut state = state.lock();
    let datagram = state.receive_queue.pop_front().ok_or(Error::TimedOut)?;
    let n = datagram.len().min(buffer.len());
    buffer[..n].copy_from_slice(&datagram[..n]);
    Ok((n, conn.remote_ip, conn.remote_port))
}

/// Gracefully close a DCCP connection (sends Close → CLOSING).
pub fn close(stack: &NetworkStack, conn: &NativeDccpConnection) -> Result<()> {
    let table = stack.dccp_table().lock();
    let state = table.lookup(&conn.key()).ok_or(Error::NotFound)?;
    let mut state = state.lock();
    if !matches!(state.state, DccpState::Open | DccpState::PartOpen) {
        return Ok(());
    }

    let seq = (state.gss + 1) & SEQ_MASK;
    state.gss = seq;
    let header = DccpHeader {
        packet_type: DccpPacketType::Close,
        seq,
        ack: if state.gsr != 0 {
            Some(state.gsr)
        } else {
            None
        },
        service_code: None,
        reset_code: None,
        ccval: 0,
        cscov: 0,
    };
    let src = local_source(stack, conn.remote_ip);
    let segment = DccpPacketBuilder::new(conn.local_port, conn.remote_port, header).finalize(
        src,
        conn.remote_ip,
        &[],
    );
    state.state = DccpState::Closing;
    state.retransmit_deadline = Some(stack.current_tick() + RETRANSMIT_INTERVAL_TICKS);
    state.retransmit_count = 0;
    state.retransmit_packet = Some((conn.remote_ip, segment.clone()));

    drop(state);
    drop(table);
    send_packet(stack, conn.remote_ip, &segment)
}

/// Whether the incoming sequence number falls inside the connection's
/// receive window.
fn seq_acceptable(state: &DccpConnectionState, seq: u64) -> bool {
    if state.gsr == 0 {
        return true; // first packet on the connection is trusted
    }
    let low = (state.gsr + 1) & SEQ_MASK;
    let high = (state.gsr + state.features.seq_window as u64) & SEQ_MASK;
    seq_between(seq, low, high)
}

/// Process an Ack/DataAck's options (Ack Vector) to drive CCID 2.
fn process_ack_options(state: &mut DccpConnectionState, segment: &DccpSegment) {
    let Ok(parsed) = options::parse_options(&segment.options) else {
        return;
    };
    for option in &parsed {
        if option.kind == options::OPT_ACK_VECTOR {
            let (acked, lost) = decode_ack_vector_value(&option.data);
            state.ccid2.on_ack(acked, lost);
        }
    }
    options::apply_features(&mut state.features, &parsed);
}

/// Update `gsr`/`last_recv_seq` when a packet's sequence number is accepted.
fn note_received_seq(state: &mut DccpConnectionState, seq: u64) {
    if seq_acceptable(state, seq) {
        state.gsr = seq;
        state.last_recv_seq = Some(seq);
    }
}

/// Handle an inbound DCCP segment for an existing connection.  Returns the
/// reply packets to send.
fn handle_established(
    stack: &NetworkStack,
    state: &mut DccpConnectionState,
    segment: &DccpSegment,
    src: IpAddress,
    dst: IpAddress,
) -> Vec<(IpAddress, Vec<u8>)> {
    let mut pending = Vec::new();
    let ptype = segment.header.packet_type;
    let remote_port = segment.src_port;
    let local_port = segment.dst_port;

    match ptype {
        DccpPacketType::Response => {
            // Client in REQUEST accepts the server's Response.  The pristine
            // header encoding (carries_ack) gives Response packets no
            // acknowledgement-number field, so there is no ack to echo-check
            // here; the 4-tuple key already scopes the Response to our
            // outstanding Request.
            if state.state == DccpState::Request {
                state.isr = segment.header.seq;
                state.gsr = segment.header.seq;
                state.last_recv_seq = Some(segment.header.seq);
                state.state = DccpState::PartOpen;
                state.retransmit_packet = None;
                state.retransmit_deadline = None;
                // Send Ack and move to OPEN.
                let ack_seq = (state.gss + 1) & SEQ_MASK;
                state.gss = ack_seq;
                let header = DccpHeader {
                    packet_type: DccpPacketType::Ack,
                    seq: ack_seq,
                    ack: Some(segment.header.seq),
                    service_code: None,
                    reset_code: None,
                    ccval: 0,
                    cscov: 0,
                };
                let mut builder = DccpPacketBuilder::new(local_port, remote_port, header);
                builder.push_option(&state.ccid2.build_ack_vector_option());
                let packet = builder.finalize(dst, src, &[]);
                state.state = DccpState::Open;
                pending.push((src, packet));
            }
        }

        DccpPacketType::Data | DccpPacketType::DataAck => {
            if !matches!(
                state.state,
                DccpState::Open | DccpState::PartOpen | DccpState::Respond
            ) {
                return pending;
            }
            if !seq_acceptable(state, segment.header.seq) {
                return pending; // out-of-window: drop
            }
            let new_data = !segment.payload.is_empty();
            if new_data {
                state.receive_queue.push_back(segment.payload.clone());
            }
            note_received_seq(state, segment.header.seq);
            state.ccid2.record_outcome(segment.header.seq, true);
            // Process the ack carried by a DataAck.
            if ptype == DccpPacketType::DataAck {
                process_ack_options(state, segment);
            }

            let ack_seq = (state.gss + 1) & SEQ_MASK;
            state.gss = ack_seq;
            let header = DccpHeader {
                packet_type: DccpPacketType::Ack,
                seq: ack_seq,
                ack: Some(segment.header.seq),
                service_code: None,
                reset_code: None,
                ccval: 0,
                cscov: 0,
            };
            let mut builder = DccpPacketBuilder::new(local_port, remote_port, header);
            builder.push_option(&state.ccid2.build_ack_vector_option());
            let packet = builder.finalize(dst, src, &[]);
            pending.push((src, packet));
        }

        DccpPacketType::Ack => {
            if !matches!(
                state.state,
                DccpState::Open | DccpState::PartOpen | DccpState::Respond
            ) {
                return pending;
            }
            if !seq_acceptable(state, segment.header.seq) {
                return pending;
            }
            note_received_seq(state, segment.header.seq);
            state.ccid2.record_outcome(segment.header.seq, true);
            process_ack_options(state, segment);
            // The server's RESPOND → OPEN transition happens on the client's
            // final handshake Ack.
            if state.state == DccpState::Respond {
                state.state = DccpState::Open;
            }
        }

        DccpPacketType::CloseReq => {
            if !matches!(state.state, DccpState::Open | DccpState::PartOpen) {
                return pending;
            }
            // Reply Close → CLOSING.
            let ack_seq = (state.gss + 1) & SEQ_MASK;
            state.gss = ack_seq;
            let header = DccpHeader {
                packet_type: DccpPacketType::Close,
                seq: ack_seq,
                ack: Some(segment.header.seq),
                service_code: None,
                reset_code: None,
                ccval: 0,
                cscov: 0,
            };
            let packet =
                DccpPacketBuilder::new(local_port, remote_port, header).finalize(dst, src, &[]);
            state.state = DccpState::Closing;
            state.timewait_deadline = Some(stack.current_tick() + TIMEWAIT_TICKS);
            pending.push((src, packet));
        }

        DccpPacketType::Close => {
            if !matches!(
                state.state,
                DccpState::Open | DccpState::PartOpen | DccpState::Respond | DccpState::Closing
            ) {
                return pending;
            }
            let ack_seq = (state.gss + 1) & SEQ_MASK;
            state.gss = ack_seq;
            let header = DccpHeader {
                packet_type: DccpPacketType::Close,
                seq: ack_seq,
                ack: Some(segment.header.seq),
                service_code: None,
                reset_code: None,
                ccval: 0,
                cscov: 0,
            };
            let packet =
                DccpPacketBuilder::new(local_port, remote_port, header).finalize(dst, src, &[]);
            if state.state == DccpState::Closing {
                // We initiated the close and the peer acknowledged it.
                state.state = DccpState::TimeWait;
                state.timewait_deadline = Some(stack.current_tick() + TIMEWAIT_TICKS);
            } else {
                state.state = DccpState::Closing;
                state.timewait_deadline = Some(stack.current_tick() + TIMEWAIT_TICKS);
            }
            pending.push((src, packet));
        }

        DccpPacketType::Reset => {
            // Peer aborted the connection.
            state.state = DccpState::Closed;
        }

        DccpPacketType::Sync => {
            // The peer's sequence numbers are out of sync — reply SyncAck
            // echoing our greatest received sequence number.
            let ack_seq = (state.gss + 1) & SEQ_MASK;
            state.gss = ack_seq;
            let header = DccpHeader {
                packet_type: DccpPacketType::SyncAck,
                seq: ack_seq,
                ack: Some(state.gsr),
                service_code: None,
                reset_code: None,
                ccval: 0,
                cscov: 0,
            };
            let packet =
                DccpPacketBuilder::new(local_port, remote_port, header).finalize(dst, src, &[]);
            pending.push((src, packet));
        }

        DccpPacketType::SyncAck => {
            // Synchronization confirmed; nothing to send.
        }

        DccpPacketType::Request => {
            // A Request on an established connection is invalid.
        }
    }

    pending
}

/// Main dispatch entry: process an inbound DCCP segment.  Returns pending
/// reply segments (destination + DCCP bytes) for the caller to send.
pub fn process_segment(
    stack: &NetworkStack,
    table: &mut DccpConnectionTable,
    src: IpAddress,
    dst: IpAddress,
    payload: &[u8],
) -> Result<Vec<(IpAddress, Vec<u8>)>> {
    let segment = parse_segment(payload, src, dst)?;
    let ptype = segment.header.packet_type;
    let mut pending = Vec::new();

    // Server side: a Request targets a listener.
    if ptype == DccpPacketType::Request {
        let local_port = segment.dst_port;
        let has_listener = table.listener(local_port).is_some();
        if !has_listener {
            // No listener: refuse with a Reset.
            pending.push((
                src,
                build_reset(
                    local_port,
                    segment.src_port,
                    None,
                    RESET_CODE_CONNECTION_REFUSED,
                    dst,
                    src,
                ),
            ));
            return Ok(pending);
        }
        let listener_sc = table
            .listener(local_port)
            .map(|l| l.service_code)
            .unwrap_or(0);
        let requested_sc = segment.header.service_code.unwrap_or(0);
        if listener_sc != 0 && listener_sc != requested_sc {
            pending.push((
                src,
                build_reset(
                    local_port,
                    segment.src_port,
                    Some(segment.header.seq),
                    RESET_CODE_CONNECTION_REFUSED,
                    dst,
                    src,
                ),
            ));
            return Ok(pending);
        }

        let iss = crate::kernel::random::random_u64() & SEQ_MASK;
        let key = DccpConnKey {
            local_port,
            remote: src,
            remote_port: segment.src_port,
        };
        let mut state = DccpConnectionState::new(key, iss, requested_sc);
        state.state = DccpState::Respond;
        state.isr = segment.header.seq;
        state.gsr = segment.header.seq;
        state.last_recv_seq = Some(segment.header.seq);

        let response = {
            let header = DccpHeader {
                packet_type: DccpPacketType::Response,
                seq: iss,
                ack: Some(segment.header.seq),
                service_code: Some(requested_sc),
                reset_code: None,
                ccval: 0,
                cscov: 0,
            };
            let mut builder = DccpPacketBuilder::new(local_port, segment.src_port, header);
            builder.push_option(&options::build_confirm_l_ccid(2));
            builder.push_option(&options::build_init_cookie(&[0u8; 16]));
            builder.finalize(dst, src, &[])
        };
        state.ccid2.on_packet_sent(iss);
        table.insert(state)?;
        if let Some(listener) = table.listener_mut(local_port) {
            if listener.pending.len() < listener.backlog as usize {
                listener.pending.push_back(key);
            }
        }
        pending.push((src, response));
        return Ok(pending);
    }

    // Established-connection path.
    let key = DccpConnKey {
        local_port: segment.dst_port,
        remote: src,
        remote_port: segment.src_port,
    };
    let Some(connection) = table.lookup(&key) else {
        if matches!(
            ptype,
            DccpPacketType::Data | DccpPacketType::DataAck | DccpPacketType::Ack
        ) {
            pending.push((
                src,
                build_reset(
                    segment.dst_port,
                    segment.src_port,
                    Some(segment.header.seq),
                    RESET_CODE_CONNECTION_RESET,
                    dst,
                    src,
                ),
            ));
        }
        return Ok(pending);
    };

    let mut state = connection.lock();
    let replies = handle_established(stack, &mut state, &segment, src, dst);
    pending.extend(replies);

    // Remove the connection when the state machine reached CLOSED (e.g. a
    // Reset) or TimeWait has been reached with a closed peer.
    if state.state == DccpState::Closed {
        drop(state);
        table.remove(&key);
        table.unbind(key.local_port);
    }

    Ok(pending)
}

/// Periodic maintenance: retransmit Requests/Closes and expire TimeWait.
pub fn tick_maintenance(
    table: &mut DccpConnectionTable,
    stack: &NetworkStack,
) -> Vec<(IpAddress, Vec<u8>)> {
    let tick = stack.current_tick();
    let mut pending = Vec::new();
    let mut expired = Vec::new();

    for (key, connection) in table.connections.iter() {
        let mut state = connection.lock();
        match state.state {
            DccpState::TimeWait => {
                if let Some(deadline) = state.timewait_deadline {
                    // `deadline` is the tick at which TIME_WAIT ends (set to
                    // `now + TIMEWAIT_TICKS` when TimeWait was entered).
                    // Expire once the current tick has reached it, using a
                    // wrapping-safe comparison.
                    if tick.wrapping_sub(deadline) < (1u64 << 63) {
                        expired.push(*key);
                    }
                }
            }
            DccpState::Request | DccpState::Closing => {
                if let Some(deadline) = state.retransmit_deadline {
                    if tick.wrapping_sub(deadline) >= RETRANSMIT_INTERVAL_TICKS {
                        if state.retransmit_count < MAX_RETRANSMITS {
                            state.retransmit_count += 1;
                            state.retransmit_deadline = Some(tick + RETRANSMIT_INTERVAL_TICKS);
                            if let Some((dst, packet)) = &state.retransmit_packet {
                                pending.push((*dst, packet.clone()));
                            }
                        } else {
                            expired.push(*key);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for key in expired {
        table.remove(&key);
        table.unbind(key.local_port);
    }
    pending
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use alloc::sync::Arc;

    fn make_stack() -> (&'static NetworkStack, Arc<MockNetworkDevice>) {
        unsafe {
            NetworkStack::uninstall_global();
        }
        let dev = Arc::new(MockNetworkDevice::new(
            "dccp-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(dev.clone(), [10, 0, 2, 15]);
        (NetworkStack::global().expect("stack"), dev)
    }

    #[test]
    fn connect_sends_request() {
        let (stack, dev) = make_stack();
        let peer = IpAddress::V4([10, 0, 2, 100]);
        stack.arp_cache().lock().insert(
            [10, 0, 2, 100],
            crate::kernel::network::link::ethernet::MacAddress([
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            ]),
            stack.current_tick(),
        );
        let conn = connect(stack, peer, 5000, 0x1234).expect("connect");
        assert_eq!(conn.remote_port, 5000);

        let tx = dev.drain_tx();
        assert_eq!(tx.len(), 1);
        let frame = crate::kernel::network::link::ethernet::parse_frame(&tx[0]).unwrap();
        let ip = ipv4::parse_packet(&frame.payload).unwrap();
        assert_eq!(ip.header.protocol, IpProtocol::Dccp);
        let seg = parse_segment(&ip.payload, peer, IpAddress::V4([10, 0, 2, 15])).unwrap();
        assert_eq!(seg.header.packet_type, DccpPacketType::Request);
        assert_eq!(seg.header.service_code, Some(0x1234));

        stack.dccp_table().lock().remove(&conn.key());
        unsafe {
            NetworkStack::uninstall_global();
        }
    }

    #[test]
    fn full_handshake_and_data_exchange() {
        let (stack, dev) = make_stack();
        let peer = IpAddress::V4([10, 0, 2, 100]);
        let peer_mac = crate::kernel::network::link::ethernet::MacAddress([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ]);
        stack
            .arp_cache()
            .lock()
            .insert([10, 0, 2, 100], peer_mac, 0);

        // Server listens.
        let mut table = stack.dccp_table().lock();
        table.listen(5000, 4, 0x1234).expect("listen");
        drop(table);

        // Client connects (sends Request).
        let conn = connect(stack, peer, 5000, 0x1234).expect("connect");
        let tx = dev.drain_tx();
        let request_frame = crate::kernel::network::link::ethernet::parse_frame(&tx[0]).unwrap();
        let request_ip = ipv4::parse_packet(&request_frame.payload).unwrap();
        let _request_seg =
            parse_segment(&request_ip.payload, peer, IpAddress::V4([10, 0, 2, 15])).unwrap();

        // Inject the Request into the stack for the server side.
        let mut table = stack.dccp_table().lock();
        let replies = process_segment(
            stack,
            &mut table,
            IpAddress::V4([10, 0, 2, 15]),
            peer,
            &request_ip.payload,
        )
        .expect("process request");
        assert_eq!(replies.len(), 1);
        drop(table);

        // Client receives the Response.  The server's Response is sent back
        // to the client at this stack's local address.
        let mut table = stack.dccp_table().lock();
        let (dst, response) = &replies[0];
        assert_eq!(*dst, IpAddress::V4([10, 0, 2, 15]));
        let replies2 = process_segment(
            stack,
            &mut table,
            peer,
            IpAddress::V4([10, 0, 2, 15]),
            response,
        )
        .expect("process response");
        // Client sends the final Ack → both sides OPEN.
        assert_eq!(replies2.len(), 1);
        drop(table);

        // Server receives the client's Ack → OPEN.  The client's Ack is sent
        // to the server at `peer`; the server sees it arriving from the
        // client at this stack's local address.
        let mut table = stack.dccp_table().lock();
        let (dst2, ack) = &replies2[0];
        let replies3 =
            process_segment(stack, &mut table, IpAddress::V4([10, 0, 2, 15]), *dst2, ack)
                .expect("process ack");
        assert!(replies3.is_empty());
        drop(table);

        // Verify both ends are OPEN.
        let table = stack.dccp_table().lock();
        let lookup_key = DccpConnKey {
            local_port: 5000,
            remote: IpAddress::V4([10, 0, 2, 15]),
            remote_port: conn.local_port,
        };
        let server_conn = table.lookup(&lookup_key).expect("server connection exists");
        assert_eq!(server_conn.lock().state, DccpState::Open);
        drop(table);

        // Client sends data → server receives.
        let n = send(stack, &conn, b"dccp_data").expect("send");
        assert_eq!(n, 9);
        let tx = dev.drain_tx();
        let data_frame = crate::kernel::network::link::ethernet::parse_frame(&tx[0]).unwrap();
        let data_ip = ipv4::parse_packet(&data_frame.payload).unwrap();

        let mut table = stack.dccp_table().lock();
        let data_replies = process_segment(
            stack,
            &mut table,
            IpAddress::V4([10, 0, 2, 15]),
            peer,
            &data_ip.payload,
        )
        .expect("process data");
        assert_eq!(data_replies.len(), 1); // Ack reply
        drop(table);

        let table = stack.dccp_table().lock();
        let server_conn = table
            .lookup(&DccpConnKey {
                local_port: 5000,
                remote: IpAddress::V4([10, 0, 2, 15]),
                remote_port: conn.local_port,
            })
            .expect("server connection");
        let server = server_conn.lock();
        assert_eq!(server.receive_queue.len(), 1);
        assert_eq!(server.receive_queue.front(), Some(&b"dccp_data".to_vec()));
        drop(table);
    }

    #[test]
    fn close_reaches_timewait_and_expires() {
        let (stack, _dev) = make_stack();
        let peer = IpAddress::V4([10, 0, 2, 100]);
        let conn = NativeDccpConnection {
            local_port: 7000,
            remote_ip: peer,
            remote_port: 5000,
        };
        let mut table = stack.dccp_table().lock();
        let mut state = DccpConnectionState::new(conn.key(), 100, 0);
        state.state = DccpState::Open;
        state.gsr = 100;
        table.insert(state).expect("insert");
        drop(table);

        // close() sends a Close packet, so the peer MAC must be resolvable.
        stack.arp_cache().lock().insert(
            [10, 0, 2, 100],
            crate::kernel::network::link::ethernet::MacAddress([
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            ]),
            stack.current_tick(),
        );

        // close() sends Close → CLOSING.
        close(stack, &conn).expect("close");
        let table = stack.dccp_table().lock();
        let conn_state = table.lookup(&conn.key()).expect("connection");
        assert_eq!(conn_state.lock().state, DccpState::Closing);
        drop(table);

        // Peer replies Close → TimeWait.
        let table = stack.dccp_table().lock();
        let mut table = table;
        let reply = {
            let header = DccpHeader {
                packet_type: DccpPacketType::Close,
                seq: 200,
                ack: Some(101),
                service_code: None,
                reset_code: None,
                ccval: 0,
                cscov: 0,
            };
            DccpPacketBuilder::new(5000, 7000, header).finalize(
                peer,
                IpAddress::V4([10, 0, 2, 15]),
                &[],
            )
        };
        process_segment(
            stack,
            &mut table,
            peer,
            IpAddress::V4([10, 0, 2, 15]),
            &reply,
        )
        .expect("process close");
        drop(table);

        let table = stack.dccp_table().lock();
        let conn_state = table.lookup(&conn.key()).expect("connection in timewait");
        assert_eq!(conn_state.lock().state, DccpState::TimeWait);
        drop(table);

        // Advance far past the TimeWait duration and run maintenance.
        for _ in 0..=TIMEWAIT_TICKS {
            stack.advance_tick();
        }
        let mut table = stack.dccp_table().lock();
        tick_maintenance(&mut table, stack);
        drop(table);
        let table = stack.dccp_table().lock();
        assert!(table.lookup(&conn.key()).is_none(), "TimeWait must expire");
        drop(table);
    }
}
