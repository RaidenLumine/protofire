//! src/kernel/network/tcp/ops.rs
//!
//! High-level TCP operations: connect, process segment, retransmit, close, and
//! reassembly.

use alloc::vec::Vec;

use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::internet::ipv6::Ipv6Addr;
use crate::kernel::network::stack::NetworkStack;
use crate::{Error, Result};

use super::ecn::{TCP_FLAG_CWR, TCP_FLAG_ECE};
use super::segment::{
    ack_options_with_sack, advance_timestamp, build_tcp_segment, build_timestamp_option,
    has_sack_permitted, parse_mss_option, parse_sack_option, parse_tcp_header,
    parse_timestamp_option, parse_window_scale_option, send_tcp_segment, timestamped_options,
};
use super::table::TcpConnectionTable;
use super::types::{
    advertised_mss_v4, build_mss_option, simple_initial_seq, TcpConnectionState, TcpHeader,
    TcpState, DEFAULT_MSS, MAX_BACKOFF_MULTIPLIER, MAX_RECV_BUFFER, MAX_RETRIES, RTO_BASE_TICKS,
    SACK_PERMITTED_OPTION_BYTES, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST,
    TCP_FLAG_SYN, TIME_WAIT_TICKS, WINDOW_SCALE_OPTION_BYTES,
};

/// Connect timeout in ticks (3 seconds at 100 Hz).
const CONNECT_TIMEOUT_TICKS: u64 = 300;

// ─── Active open: connect ─────────────────────────────────────────────

/// Initiate an active TCP connection to a remote endpoint.
pub fn connect(
    stack: &NetworkStack,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Result<super::table::NativeTcpConnection> {
    let local_port;
    let syn_segment;

    {
        let mut table = stack.tcp_table().lock();
        local_port = table.alloc_port()?;
        let initial_seq = simple_initial_seq(stack.current_tick());
        let mut state = TcpConnectionState::new(
            local_port,
            remote_ip,
            remote_port,
            initial_seq,
            stack.current_tick(),
        );

        let syn_header = TcpHeader {
            source_port: local_port,
            destination_port: remote_port,
            sequence_number: initial_seq,
            acknowledgment_number: 0,
            data_offset: 0,
            flags: TCP_FLAG_SYN | state.ecn.syn_flags(),
            window_size: state.recv_window(),
            checksum: 0,
            urgent_pointer: 0,
            options: {
                let mss = build_mss_option(advertised_mss_v4(stack.mtu()));
                let ws = WINDOW_SCALE_OPTION_BYTES;
                let sack_p = SACK_PERMITTED_OPTION_BYTES;
                let ts = build_timestamp_option(state.ts_val, 0);
                let mut opts = alloc::vec![0u8; mss.len() + ws.len() + sack_p.len() + ts.len()];
                opts[..4].copy_from_slice(&mss);
                opts[4..7].copy_from_slice(&ws);
                opts[7..9].copy_from_slice(&sack_p);
                opts[9..19].copy_from_slice(&ts);
                opts
            },
        };
        syn_segment = build_tcp_segment(&syn_header, &[], stack.local_ip(), remote_ip);

        state
            .retransmit
            .pending_segments
            .push_back((state.send_next, syn_segment.clone()));
        state.retransmit.started_at = stack.current_tick();
        state.retransmit.count = 0;

        let _ = table.insert(state);
    }

    let _ = send_tcp_segment(stack, remote_ip, &syn_segment);

    let start_tick = stack.current_tick();
    loop {
        let _ = stack.poll();

        let tick = stack.current_tick();
        if tick.wrapping_sub(start_tick) >= CONNECT_TIMEOUT_TICKS {
            stack
                .tcp_table()
                .lock()
                .remove(local_port, remote_ip, remote_port);
            stack.profiler.inc_tcp_connects_failed();
            return Err(Error::TimedOut);
        }

        {
            let mut table = stack.tcp_table().lock();
            let pending = retransmit_check(&mut table, stack, local_port, remote_ip, remote_port)?;
            drop(table);
            for (dst_ip, seg) in pending {
                let _ = send_tcp_segment(stack, dst_ip, &seg);
            }
        }

        {
            let table = stack.tcp_table().lock();
            let conn = match table.lookup(local_port, remote_ip, remote_port) {
                Some(c) => c,
                None => return Err(Error::NotFound),
            };
            let current_state = conn.lock().state;
            if current_state == TcpState::Established {
                break;
            }
        }
    }

    stack.profiler.inc_tcp_connects();
    Ok(super::table::NativeTcpConnection {
        local_port,
        remote_ip,
        remote_port,
    })
}

// ─── Process segment (IPv6) ───────────────────────────────────────────

/// Process an incoming TCP segment (IPv6) and update connection state.
///
/// IPv6 TCP is not implemented: the connection table, the listener
/// registry, and the whole TCP state machine are keyed on IPv4 addresses
/// (`TcpConnectionTable` / `TcpConnectionState` hold an `Ipv4Addr`), so
/// there is nowhere to keep IPv6 connection state.  The previous version of
/// this function was a stateless stub that fabricated SYN-ACK / ACK / RST
/// replies without recording any connection state, so IPv6 TCP appeared to
/// work while never actually establishing a connection.
///
/// Rather than silently pretending to process the segment, IPv6 TCP is
/// dropped: nothing is delivered to any connection and nothing is
/// transmitted.  The dispatchers (`dispatch.rs` and `ppp.rs`) consume the
/// returned pending list and have nothing to send.
///
/// TODO: implement IPv6 TCP by mirroring [`process_segment`] once the
/// connection table supports IPv6 keys.
pub fn process_segment_v6(
    _table: &mut TcpConnectionTable,
    stack: &NetworkStack,
    _src_ip: Ipv6Addr,
    _dst_ip: Ipv6Addr,
    _tcp_data: &[u8],
) -> Result<Vec<(Ipv6Addr, Vec<u8>)>> {
    // IPv6 TCP is unsupported — see the note above.  Count the segment as
    // received for profiling, then drop it.
    stack.profiler.inc_tcp_segments_rx();
    Ok(alloc::vec![])
}

// ─── Output (proactive TX) ────────────────────────────────────────────

/// Drain queued data from `state.send_buffer`, build TCP segments, and
/// return them as `(dst_ip, segment_bytes)` tuples.  Must be called with
/// the connection state lock held.  The caller is responsible for sending
/// each returned segment via [`send_tcp_segment`].
///
/// This is extracted from [`process_segment`] so that
/// [`NativeTcpConnection::write_all`] can trigger transmission without waiting
/// for an incoming ACK.
pub(crate) fn try_flush_tcp_output(
    stack: &NetworkStack,
    state: &mut TcpConnectionState,
    dst_ip: Ipv4Addr,
) -> Vec<(Ipv4Addr, Vec<u8>)> {
    let mut pending = Vec::new();
    if state.state != TcpState::Established || state.send_buffer.is_empty() {
        return pending;
    }

    let effective_mss = DEFAULT_MSS.min(state.peer_mss);
    let window = state.send_window.max(1) as usize;
    // Skip bytes already sent but not yet acknowledged (the in-flight prefix
    // of the send buffer) so they are never re-sent as new data.
    let ahead = state.send_next.wrapping_sub(state.send_unacked) as usize;
    let can_send = window
        .min(effective_mss)
        .min(state.send_buffer.len().saturating_sub(ahead));
    let nagle_allows = state.retransmit.pending_segments.is_empty() || can_send >= effective_mss;

    if can_send > 0 && nagle_allows {
        let mut data = Vec::with_capacity(can_send);
        data.extend(state.send_buffer.iter().skip(ahead).take(can_send));
        let data_len = data.len() as u32;
        stack.profiler.add_tcp_bytes_tx(data_len as u64);
        state.ts_val = state.ts_val.wrapping_add(1);
        let tx_flags = TCP_FLAG_ACK | TCP_FLAG_PSH | state.ecn.ack_flags();
        let push = TcpHeader {
            source_port: state.local_port,
            destination_port: state.remote_port,
            sequence_number: state.send_next,
            acknowledgment_number: state.recv_next,
            data_offset: 0,
            flags: tx_flags,
            window_size: state.recv_window(),
            checksum: 0,
            urgent_pointer: 0,
            options: timestamped_options(state),
        };
        let seg = build_tcp_segment(&push, &data, stack.local_ip(), state.remote_ip);
        state.ecn.on_segment_sent(tx_flags);
        state.send_next = state.send_next.wrapping_add(data_len);
        let was_empty = state.retransmit.pending_segments.is_empty();
        let next_seq = state.send_next;
        state
            .retransmit
            .pending_segments
            .push_back((next_seq, seg.clone()));
        if was_empty {
            state.retransmit.started_at = stack.current_tick();
            state.retransmit.count = 0;
        }
        pending.push((dst_ip, seg));
    }

    pending
}

// ─── Process segment (IPv4) ───────────────────────────────────────────

/// Advance the send state in response to an incoming acknowledgement:
/// move `send_unacked` forward, pop acknowledged segments from the
/// retransmit queue, and drain the acknowledged bytes from the send buffer.
///
/// Shared by the Established/CloseWait path and the FinWait1/LastAck/Closing
/// close-path arms so that closing a connection with data still in flight
/// continues to track ACKs (otherwise the retransmit queue never advances).
///
/// Only acknowledgements at or below SND.NXT are honoured; a bogus ack
/// beyond what we have sent would otherwise freeze the send side.
fn process_data_ack(state: &mut TcpConnectionState, ack_val: u32) {
    let diff = ack_val.wrapping_sub(state.send_unacked);
    if diff > 0 && diff <= (u32::MAX / 2) && state.send_next.wrapping_sub(ack_val) <= (u32::MAX / 2)
    {
        state.send_unacked = ack_val;
        while let Some(&(next_seq, _)) = state.retransmit.pending_segments.front() {
            if ack_val.wrapping_sub(next_seq) <= (u32::MAX / 2) {
                state.retransmit.pending_segments.pop_front();
            } else {
                break;
            }
        }
        pop_sacked_segments(state);
        if state.retransmit.pending_segments.is_empty() {
            state.retransmit.count = 0;
        }
        let pop_bytes = (diff as usize).min(state.send_buffer.len());
        state.send_buffer.drain(..pop_bytes);
    }
}

/// Process an incoming TCP segment (IPv4) and update connection state.
pub fn process_segment(
    table: &mut TcpConnectionTable,
    stack: &NetworkStack,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tcp_data: &[u8],
) -> Result<Vec<(Ipv4Addr, Vec<u8>)>> {
    let (header, header_len) = parse_tcp_header(tcp_data)?;
    let payload = &tcp_data[header_len..];

    stack.profiler.inc_tcp_segments_rx();

    let local_port = header.destination_port;
    let remote_port = header.source_port;

    let mut pending: Vec<(Ipv4Addr, Vec<u8>)> = Vec::new();

    let conn = match table.lookup(local_port, src_ip, remote_port) {
        Some(c) => c,
        None => {
            let is_syn = header.flags & TCP_FLAG_SYN != 0;
            let is_ack = header.flags & TCP_FLAG_ACK != 0;

            if is_syn && !is_ack {
                if let Some(listener) = table.listeners.get(&local_port) {
                    if listener.backlog.len() < listener.max_backlog {
                        let initial_seq = simple_initial_seq(stack.current_tick());
                        let mut child = TcpConnectionState::new_child(
                            local_port,
                            src_ip,
                            remote_port,
                            header.sequence_number,
                            initial_seq,
                            stack.current_tick(),
                        );

                        child.peer_mss = parse_mss_option(&header.options);
                        child.peer_window_scale = parse_window_scale_option(&header.options);
                        child.peer_sack_ok = has_sack_permitted(&header.options);
                        if let Some((peer_ts, _)) = parse_timestamp_option(&header.options) {
                            child.peer_timestamps = true;
                            child.peer_ts_val = peer_ts;
                        }

                        // ECN negotiation: if SYN had ECE+CWR, enable ECN.
                        child.ecn.on_recv_syn(header.flags);

                        let syn_ack = TcpHeader {
                            source_port: local_port,
                            destination_port: remote_port,
                            sequence_number: initial_seq,
                            acknowledgment_number: child.recv_next,
                            data_offset: 0,
                            flags: TCP_FLAG_SYN | TCP_FLAG_ACK | child.ecn.syn_ack_flags(),
                            window_size: child.recv_window(),
                            checksum: 0,
                            urgent_pointer: 0,
                            options: {
                                let mss = build_mss_option(advertised_mss_v4(stack.mtu()));
                                let ws = WINDOW_SCALE_OPTION_BYTES;
                                let sack_p = SACK_PERMITTED_OPTION_BYTES;
                                let ts = build_timestamp_option(child.ts_val, child.peer_ts_val);
                                let mut opts = alloc::vec![0u8; mss.len() + ws.len() + sack_p.len() + ts.len()];
                                opts[..4].copy_from_slice(&mss);
                                opts[4..7].copy_from_slice(&ws);
                                opts[7..9].copy_from_slice(&sack_p);
                                opts[9..19].copy_from_slice(&ts);
                                opts
                            },
                        };
                        let syn_ack_seg = build_tcp_segment(&syn_ack, &[], dst_ip, src_ip);

                        let next_seq = child.send_next;
                        child
                            .retransmit
                            .pending_segments
                            .push_back((next_seq, syn_ack_seg.clone()));
                        child.retransmit.started_at = stack.current_tick();

                        let _ = table.insert(child);
                        pending.push((src_ip, syn_ack_seg));
                        return Ok(pending);
                    }
                    return Ok(pending);
                }
            }

            if header.flags & TCP_FLAG_RST == 0 {
                let rst = TcpHeader {
                    source_port: header.destination_port,
                    destination_port: header.source_port,
                    sequence_number: if header.flags & TCP_FLAG_ACK != 0 {
                        header.acknowledgment_number
                    } else {
                        0
                    },
                    acknowledgment_number: 0,
                    data_offset: 0,
                    flags: TCP_FLAG_RST | TCP_FLAG_ACK,
                    window_size: 0,
                    checksum: 0,
                    urgent_pointer: 0,
                    options: Vec::new(),
                };
                let rst_seg = build_tcp_segment(&rst, &[], dst_ip, src_ip);
                pending.push((src_ip, rst_seg));
            }
            return Ok(pending);
        }
    };

    let mut state = conn.lock();
    let flags = header.flags;
    let seq = header.sequence_number;
    let is_syn = flags & TCP_FLAG_SYN != 0;
    let is_ack = flags & TCP_FLAG_ACK != 0;
    let is_fin = flags & TCP_FLAG_FIN != 0;
    let is_rst = flags & TCP_FLAG_RST != 0;

    match state.state {
        TcpState::SynSent => {
            if is_rst {
                state.state = TcpState::Closed;
                drop(state);
                table.remove(local_port, src_ip, remote_port);
                return Ok(pending);
            }
            if is_syn && is_ack {
                let expected_ack = state.initial_seq.wrapping_add(1);
                if header.acknowledgment_number != expected_ack {
                    drop(state);
                    return Ok(pending);
                }
                state.peer_initial_seq = header.sequence_number;
                state.recv_next = header.sequence_number.wrapping_add(1);
                state.send_unacked = expected_ack;
                state.peer_mss = parse_mss_option(&header.options);
                state.peer_window_scale = parse_window_scale_option(&header.options);
                state.peer_sack_ok = has_sack_permitted(&header.options);
                if let Some((peer_ts, _)) = parse_timestamp_option(&header.options) {
                    state.peer_timestamps = true;
                    state.peer_ts_val = peer_ts;
                }
                // ECN: verify server confirmed ECN in SYN-ACK.
                state.ecn.on_recv_syn_ack(flags);
                state.retransmit.pending_segments.clear();
                state.retransmit.count = 0;
                state.ts_val = state.ts_val.wrapping_add(1);
                let ack_flags = TCP_FLAG_ACK | state.ecn.ack_flags();
                let ack = TcpHeader {
                    source_port: state.local_port,
                    destination_port: state.remote_port,
                    sequence_number: state.send_next,
                    acknowledgment_number: state.recv_next,
                    data_offset: 0,
                    flags: ack_flags,
                    window_size: state.recv_window(),
                    checksum: 0,
                    urgent_pointer: 0,
                    options: timestamped_options(&state),
                };
                let ack_seg = build_tcp_segment(&ack, &[], stack.local_ip(), state.remote_ip);
                state.ecn.on_segment_sent(ack_flags);
                pending.push((src_ip, ack_seg));
                state.state = TcpState::Established;
            }
        }

        TcpState::SynReceived => {
            if is_rst {
                state.state = TcpState::Closed;
                drop(state);
                table.remove(local_port, src_ip, remote_port);
                return Ok(pending);
            }
            if is_ack {
                let expected_ack = state.initial_seq.wrapping_add(1);
                if header.acknowledgment_number != expected_ack {
                    drop(state);
                    return Ok(pending);
                }
                let conn_key = (local_port, src_ip, remote_port);
                if let Some(listener) = table.listeners.get_mut(&local_port) {
                    if listener.backlog.len() < listener.max_backlog {
                        state.send_unacked = expected_ack;
                        state.retransmit.pending_segments.clear();
                        state.retransmit.count = 0;
                        state.state = TcpState::Established;
                        drop(state);
                        if let Some(arc) = table.connections.get(&conn_key).cloned() {
                            listener.backlog.push_back(arc);
                        }
                        return Ok(pending);
                    }
                    let rst_header = TcpHeader {
                        source_port: local_port,
                        destination_port: remote_port,
                        sequence_number: expected_ack,
                        acknowledgment_number: header.sequence_number,
                        data_offset: 5,
                        flags: TCP_FLAG_RST | TCP_FLAG_ACK,
                        window_size: 0,
                        checksum: 0,
                        urgent_pointer: 0,
                        options: Vec::new(),
                    };
                    let rst_segment = build_tcp_segment(&rst_header, &[], dst_ip, src_ip);
                    pending.push((src_ip, rst_segment));
                    state.state = TcpState::Closed;
                    drop(state);
                    table.remove(local_port, src_ip, remote_port);
                    return Ok(pending);
                }
                state.send_unacked = expected_ack;
                state.retransmit.pending_segments.clear();
                state.retransmit.count = 0;
                state.state = TcpState::Established;
            }
        }

        TcpState::Established | TcpState::CloseWait => {
            if is_rst {
                state.state = TcpState::Closed;
                drop(state);
                table.remove(local_port, src_ip, remote_port);
                return Ok(pending);
            }

            // ── ECN: process received ECN flags ────────────────────
            if flags & TCP_FLAG_CWR != 0 {
                state.ecn.on_cwr_received();
            }
            if flags & TCP_FLAG_ECE != 0 && state.ecn.on_ece_ack() {
                // Congestion reaction per RFC 3168: same as single loss.
                // Both cwnd and ssthresh are in MSS units.
                let prev = state.congestion.cwnd;
                state.congestion.ssthresh = core::cmp::max(prev / 2, 2);
                state.congestion.cwnd = state.congestion.ssthresh;
            }

            if let Some((peer_ts, _)) = parse_timestamp_option(&header.options) {
                advance_timestamp(&mut state, peer_ts);
            }
            if is_ack {
                state.peer_sack_blocks = parse_sack_option(&header.options);
            }

            if !payload.is_empty() && state.state != TcpState::Closed {
                // RFC 793 §2.8 / RFC 1122 §4.2.2.2: record a push boundary
                // when PSH is set so readers can return data promptly.
                if flags & TCP_FLAG_PSH != 0 {
                    state.push_boundary = true;
                }
                if seq == state.recv_next {
                    let available_space = MAX_RECV_BUFFER.saturating_sub(state.recv_buffer.len());
                    let accepted = payload.len().min(available_space);
                    state.recv_buffer.extend(&payload[..accepted]);
                    state.recv_next = seq.wrapping_add(accepted as u32);
                    stack.profiler.add_tcp_bytes_rx(accepted as u64);
                    stack
                        .profiler
                        .add_tcp_bytes_rx(deliver_ooo(&mut state) as u64);
                } else {
                    let diff = seq.wrapping_sub(state.recv_next);
                    // A retransmission may start before recv_next yet still carry
                    // fresh in-order bytes beyond it (seq < recv_next < seq+len).
                    // Accept that in-order tail instead of silently dropping it.
                    let overlap = state.recv_next.wrapping_sub(seq);
                    if overlap > 0 && overlap < payload.len() as u32 {
                        let start = overlap as usize;
                        let available_space =
                            MAX_RECV_BUFFER.saturating_sub(state.recv_buffer.len());
                        let accepted = (payload.len() - start).min(available_space);
                        state.recv_buffer.extend(&payload[start..start + accepted]);
                        state.recv_next = state.recv_next.wrapping_add(accepted as u32);
                        stack.profiler.add_tcp_bytes_rx(accepted as u64);
                        stack
                            .profiler
                            .add_tcp_bytes_rx(deliver_ooo(&mut state) as u64);
                    } else if diff <= (u32::MAX / 2) && diff > 0 && state.peer_sack_ok {
                        let ooo_data = Vec::from(payload);
                        enqueue_ooo(&mut state, seq, ooo_data);
                    }
                }

                state.ts_val = state.ts_val.wrapping_add(1);
                let ack_flags = TCP_FLAG_ACK | state.ecn.ack_flags();
                let ack = TcpHeader {
                    source_port: state.local_port,
                    destination_port: state.remote_port,
                    sequence_number: state.send_next,
                    acknowledgment_number: state.recv_next,
                    data_offset: 0,
                    flags: ack_flags,
                    window_size: state.recv_window(),
                    checksum: 0,
                    urgent_pointer: 0,
                    options: ack_options_with_sack(&state),
                };
                let ack_seg = build_tcp_segment(&ack, &[], stack.local_ip(), state.remote_ip);
                state.ecn.on_segment_sent(ack_flags);
                pending.push((src_ip, ack_seg));
            }

            if is_ack {
                let ack_val = header.acknowledgment_number;
                let diff = ack_val.wrapping_sub(state.send_unacked);
                if diff == 0 && !state.retransmit.pending_segments.is_empty() {
                    stack.profiler.inc_tcp_duplicate_acks();
                }
                // Advance the send state, honouring only ack <= SND.NXT (the
                // helper rejects acks beyond what we have actually sent).
                process_data_ack(&mut state, ack_val);
                state.send_window = (header.window_size as u32) << state.peer_window_scale;
            }

            if is_fin {
                // The FIN occupies the sequence-number slot immediately after
                // the segment payload. Only consume it once all preceding data
                // is in order — a FIN riding on a partially-accepted payload
                // must not be acknowledged, or truncated bytes are ACKed as if
                // they had been delivered.
                let fin_seq = seq.wrapping_add(payload.len() as u32);
                if fin_seq == state.recv_next {
                    state.recv_next = state.recv_next.wrapping_add(1);
                    deliver_ooo(&mut state);
                    if state.state == TcpState::Established {
                        state.state = TcpState::CloseWait;
                        state.ts_val = state.ts_val.wrapping_add(1);
                        let fin_flags = TCP_FLAG_ACK | state.ecn.ack_flags();
                        let fin_ack = TcpHeader {
                            source_port: state.local_port,
                            destination_port: state.remote_port,
                            sequence_number: state.send_next,
                            acknowledgment_number: state.recv_next,
                            data_offset: 0,
                            flags: fin_flags,
                            window_size: state.recv_window(),
                            checksum: 0,
                            urgent_pointer: 0,
                            options: timestamped_options(&state),
                        };
                        state.ecn.on_segment_sent(fin_flags);
                        let ack_seg =
                            build_tcp_segment(&fin_ack, &[], stack.local_ip(), state.remote_ip);
                        pending.push((src_ip, ack_seg));
                    } else if state.state == TcpState::FinWait2 {
                        state.state = TcpState::TimeWait;
                        state.time_wait_start = stack.current_tick();
                    }
                }
            }

            if state.state == TcpState::Established && !state.send_buffer.is_empty() {
                let effective_mss = DEFAULT_MSS.min(state.peer_mss);
                let window = state.send_window.max(1) as usize;
                // Skip bytes already sent but not yet acknowledged.
                let ahead = state.send_next.wrapping_sub(state.send_unacked) as usize;
                // The peer's advertised window covers the whole in-flight window
                // (SND.WND - (SND.NXT - SND.UNA)); subtract `ahead` so we never
                // exceed the flow-control budget by up to a full MSS.
                let can_send = window
                    .saturating_sub(ahead)
                    .min(effective_mss)
                    .min(state.send_buffer.len().saturating_sub(ahead));
                let nagle_allows =
                    state.retransmit.pending_segments.is_empty() || can_send >= effective_mss;
                if can_send > 0 && nagle_allows {
                    let mut data = Vec::with_capacity(can_send);
                    data.extend(state.send_buffer.iter().skip(ahead).take(can_send));
                    let data_len = data.len() as u32;
                    stack.profiler.add_tcp_bytes_tx(data_len as u64);
                    state.ts_val = state.ts_val.wrapping_add(1);
                    let push = TcpHeader {
                        source_port: state.local_port,
                        destination_port: state.remote_port,
                        sequence_number: state.send_next,
                        acknowledgment_number: state.recv_next,
                        data_offset: 0,
                        flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
                        window_size: state.recv_window(),
                        checksum: 0,
                        urgent_pointer: 0,
                        options: timestamped_options(&state),
                    };
                    let seg = build_tcp_segment(&push, &data, stack.local_ip(), state.remote_ip);
                    state.send_next = state.send_next.wrapping_add(data_len);
                    let was_empty = state.retransmit.pending_segments.is_empty();
                    let next_seq = state.send_next;
                    state
                        .retransmit
                        .pending_segments
                        .push_back((next_seq, seg.clone()));
                    if was_empty {
                        state.retransmit.started_at = stack.current_tick();
                        state.retransmit.count = 0;
                    }
                    pending.push((src_ip, seg));
                }
            }
        }

        TcpState::FinWait1 => {
            if is_rst {
                state.state = TcpState::Closed;
                drop(state);
                table.remove(local_port, src_ip, remote_port);
                return Ok(pending);
            }
            if is_ack {
                // Keep tracking data ACKs while closing so the retransmit
                // queue advances and in-flight data is eventually drained.
                process_data_ack(&mut state, header.acknowledgment_number);
                // Our FIN is acknowledged when ack == send_next: the FIN
                // occupies the single slot at send_next - 1, so a compliant
                // peer ACKs it with send_next (not send_next + 1).
                if header.acknowledgment_number == state.send_next {
                    if is_fin {
                        state.state = TcpState::TimeWait;
                        state.time_wait_start = stack.current_tick();
                    } else {
                        state.state = TcpState::FinWait2;
                    }
                } else if is_fin {
                    state.state = TcpState::Closing;
                }
            } else if is_fin {
                state.state = TcpState::Closing;
            }
        }

        TcpState::LastAck => {
            if is_ack {
                process_data_ack(&mut state, header.acknowledgment_number);
                // Our FIN is acknowledged when ack == send_next (the FIN's slot
                // is at send_next - 1).
                if header.acknowledgment_number == state.send_next {
                    state.state = TcpState::Closed;
                    drop(state);
                    table.remove(local_port, src_ip, remote_port);
                    return Ok(pending);
                }
            }
        }

        TcpState::FinWait2 => {
            if is_rst {
                state.state = TcpState::Closed;
                drop(state);
                table.remove(local_port, src_ip, remote_port);
                return Ok(pending);
            }
            if is_fin {
                state.recv_next = state.recv_next.wrapping_add(1);
                state.state = TcpState::TimeWait;
                state.time_wait_start = stack.current_tick();
                state.ts_val = state.ts_val.wrapping_add(1);
                let fin_ack = TcpHeader {
                    source_port: state.local_port,
                    destination_port: state.remote_port,
                    sequence_number: state.send_next,
                    acknowledgment_number: state.recv_next,
                    data_offset: 0,
                    flags: TCP_FLAG_ACK,
                    window_size: state.recv_window(),
                    checksum: 0,
                    urgent_pointer: 0,
                    options: timestamped_options(&state),
                };
                let ack_seg = build_tcp_segment(&fin_ack, &[], stack.local_ip(), state.remote_ip);
                pending.push((src_ip, ack_seg));
            }
        }

        TcpState::Closing => {
            if is_rst {
                state.state = TcpState::Closed;
                drop(state);
                table.remove(local_port, src_ip, remote_port);
                return Ok(pending);
            }
            if is_ack {
                process_data_ack(&mut state, header.acknowledgment_number);
                if header.acknowledgment_number == state.send_next {
                    state.state = TcpState::TimeWait;
                    state.time_wait_start = stack.current_tick();
                }
            }
        }

        TcpState::TimeWait => {
            if stack.current_tick().wrapping_sub(state.time_wait_start) >= TIME_WAIT_TICKS {
                state.state = TcpState::Closed;
                drop(state);
                table.remove(local_port, src_ip, remote_port);
                return Ok(pending);
            }
        }

        TcpState::Closed => {
            drop(state);
            table.remove(local_port, src_ip, remote_port);
            return Ok(pending);
        }

        TcpState::Listen => {
            drop(state);
            table.remove(local_port, src_ip, remote_port);
            return Ok(pending);
        }
    }

    drop(state);

    Ok(pending)
}

// ─── Retransmission ───────────────────────────────────────────────────

/// Check for and retransmit any timed-out segments for a connection.
pub fn retransmit_check(
    table: &mut TcpConnectionTable,
    stack: &NetworkStack,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Result<Vec<(Ipv4Addr, Vec<u8>)>> {
    let mut pending: Vec<(Ipv4Addr, Vec<u8>)> = Vec::new();

    let conn = match table.lookup(local_port, remote_ip, remote_port) {
        Some(c) => c,
        None => return Ok(pending),
    };
    let mut state = conn.lock();
    let tick = stack.current_tick();

    if state.state == TcpState::TimeWait {
        if tick.wrapping_sub(state.time_wait_start) >= TIME_WAIT_TICKS {
            state.state = TcpState::Closed;
            drop(state);
            table.remove(local_port, remote_ip, remote_port);
            return Ok(pending);
        }
        return Ok(pending);
    }

    if state.state == TcpState::Closed {
        drop(state);
        table.remove(local_port, remote_ip, remote_port);
        return Ok(pending);
    }

    if let Some((_, pending_seg)) = state.retransmit.pending_segments.front() {
        let elapsed = tick.wrapping_sub(state.retransmit.started_at);
        let backoff_count = state.retransmit.count.min(MAX_BACKOFF_MULTIPLIER);
        let timeout = RTO_BASE_TICKS * (1u64 << backoff_count);

        if elapsed >= timeout {
            if state.retransmit.count >= MAX_RETRIES {
                state.state = TcpState::Closed;
                state.retransmit.pending_segments.clear();
                drop(state);
                table.remove(local_port, remote_ip, remote_port);
                stack.profiler.inc_tcp_connects_failed();
                return Err(Error::TimedOut);
            }

            let seg = pending_seg.clone();
            state.retransmit.count += 1;
            state.retransmit.started_at = tick;
            let dest_ip = state.remote_ip;
            drop(state);

            let seg_len = seg.len() as u64;
            stack.profiler.inc_tcp_retransmits();
            stack.profiler.add_tcp_retransmit_bytes(seg_len);
            pending.push((dest_ip, seg));
        }
    }

    Ok(pending)
}

// ─── Close ────────────────────────────────────────────────────────────

/// Close a TCP connection gracefully.
pub fn close(
    table: &mut TcpConnectionTable,
    stack: &NetworkStack,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Result<Vec<(Ipv4Addr, Vec<u8>)>> {
    let conn = table
        .lookup(local_port, remote_ip, remote_port)
        .ok_or(Error::NotFound)?;
    let mut state = conn.lock();

    stack.profiler.inc_tcp_close_initiated();

    match state.state {
        TcpState::Established => {
            state.ts_val = state.ts_val.wrapping_add(1);
            let fin_flags = TCP_FLAG_FIN | TCP_FLAG_ACK | state.ecn.ack_flags();
            let fin = TcpHeader {
                source_port: state.local_port,
                destination_port: state.remote_port,
                sequence_number: state.send_next,
                acknowledgment_number: state.recv_next,
                data_offset: 0,
                flags: fin_flags,
                window_size: state.recv_window(),
                checksum: 0,
                urgent_pointer: 0,
                options: timestamped_options(&state),
            };
            let fin_seg = build_tcp_segment(&fin, &[], stack.local_ip(), state.remote_ip);
            state.ecn.on_segment_sent(fin_flags);
            state.send_next = state.send_next.wrapping_add(1);
            state.state = TcpState::FinWait1;
            let next_seq = state.send_next;
            state
                .retransmit
                .pending_segments
                .push_back((next_seq, fin_seg.clone()));
            state.retransmit.started_at = stack.current_tick();
            state.retransmit.count = 0;
            let dest_ip = state.remote_ip;
            drop(state);
            Ok(alloc::vec![(dest_ip, fin_seg)])
        }
        TcpState::CloseWait => {
            state.ts_val = state.ts_val.wrapping_add(1);
            let fin_flags = TCP_FLAG_FIN | TCP_FLAG_ACK | state.ecn.ack_flags();
            let fin = TcpHeader {
                source_port: state.local_port,
                destination_port: state.remote_port,
                sequence_number: state.send_next,
                acknowledgment_number: state.recv_next,
                data_offset: 0,
                flags: fin_flags,
                window_size: state.recv_window(),
                checksum: 0,
                urgent_pointer: 0,
                options: timestamped_options(&state),
            };
            let fin_seg = build_tcp_segment(&fin, &[], stack.local_ip(), state.remote_ip);
            state.ecn.on_segment_sent(fin_flags);
            state.send_next = state.send_next.wrapping_add(1);
            state.state = TcpState::LastAck;
            let next_seq = state.send_next;
            state
                .retransmit
                .pending_segments
                .push_back((next_seq, fin_seg.clone()));
            state.retransmit.started_at = stack.current_tick();
            state.retransmit.count = 0;
            let dest_ip = state.remote_ip;
            drop(state);
            Ok(alloc::vec![(dest_ip, fin_seg)])
        }
        _ => Err(Error::NotFound),
    }
}

// ─── Out-of-order reassembly ──────────────────────────────────────────

/// Attempt to deliver any out-of-order queued segments that are now in-order.
fn deliver_ooo(state: &mut TcpConnectionState) -> usize {
    let mut delivered = 0;
    while let Some(&(start_seq, _)) = state.ooo_queue.front() {
        if start_seq != state.recv_next {
            break;
        }
        let Some((_, data)) = state.ooo_queue.pop_front() else {
            break;
        };
        let available = MAX_RECV_BUFFER.saturating_sub(state.recv_buffer.len());
        let accept = data.len().min(available);
        state.recv_buffer.extend(&data[..accept]);
        state.recv_next = state.recv_next.wrapping_add(accept as u32);
        delivered += accept;
        if accept < data.len() {
            break;
        }
    }
    delivered
}

/// Insert an out-of-order segment into the queue, maintaining sort order.
fn enqueue_ooo(state: &mut TcpConnectionState, start_seq: u32, data: Vec<u8>) {
    let end_seq = start_seq.wrapping_add(data.len() as u32);
    if end_seq != state.recv_next {
        let diff = state.recv_next.wrapping_sub(end_seq);
        if diff <= (u32::MAX / 2) {
            return;
        }
    }
    for i in 0..state.ooo_queue.len() {
        let (s, ref d) = state.ooo_queue[i];
        let e = s.wrapping_add(d.len() as u32);
        if start_seq == s {
            if data.len() > d.len() {
                state.ooo_queue[i] = (start_seq, data);
            }
            return;
        }
        let diff = s.wrapping_sub(start_seq);
        if diff > 0 && diff <= (u32::MAX / 2) {
            if i > 0 {
                let (ps, ref pd) = state.ooo_queue[i - 1];
                let pe = ps.wrapping_add(pd.len() as u32);
                let diff = pe.wrapping_sub(start_seq);
                if diff > 0 && diff <= (u32::MAX / 2) {
                    let new_end = end_seq.max(pe);
                    let merged_len = new_end.wrapping_sub(ps) as usize;
                    if merged_len > pd.len() {
                        let mut merged = Vec::with_capacity(merged_len);
                        merged.extend_from_slice(pd);
                        let overlap = pe.wrapping_sub(start_seq) as usize;
                        if overlap < data.len() {
                            merged.extend_from_slice(&data[overlap..]);
                        }
                        state.ooo_queue[i - 1] = (ps, merged);
                    }
                    return;
                }
            }
            state.ooo_queue.insert(i, (start_seq, data));
            while state.ooo_queue.len() > 64 {
                state.ooo_queue.pop_back();
            }
            return;
        }
        let diff = e.wrapping_sub(start_seq);
        if diff > 0 && diff <= (u32::MAX / 2) {
            let new_end = end_seq.max(e);
            let merged_len = new_end.wrapping_sub(s) as usize;
            if merged_len > d.len() {
                let mut merged = Vec::with_capacity(merged_len);
                merged.extend_from_slice(d);
                let overlap = e.wrapping_sub(start_seq) as usize;
                if overlap < data.len() {
                    merged.extend_from_slice(&data[overlap..]);
                }
                state.ooo_queue[i] = (s, merged);
            }
            return;
        }
    }
    state.ooo_queue.push_back((start_seq, data));
    while state.ooo_queue.len() > 64 {
        state.ooo_queue.pop_back();
    }
}

/// Remove pending retransmit segments that are fully covered by peer SACK
/// blocks.
fn pop_sacked_segments(state: &mut TcpConnectionState) {
    if state.peer_sack_blocks.is_empty() || state.retransmit.pending_segments.is_empty() {
        return;
    }
    let mut to_remove: Vec<usize> = Vec::new();
    let mut start = state.send_unacked;
    for (i, &(next_seq, _)) in state.retransmit.pending_segments.iter().enumerate() {
        let end = next_seq;
        let covered = state
            .peer_sack_blocks
            .iter()
            .any(|&(sack_left, sack_right)| {
                let left_ok = start.wrapping_sub(sack_left) <= (u32::MAX / 2) || start == sack_left;
                let right_ok = sack_right.wrapping_sub(end) <= (u32::MAX / 2) || sack_right == end;
                left_ok && right_ok
            });
        if covered && i > 0 {
            to_remove.push(i);
        }
        start = next_seq;
    }
    for &i in to_remove.iter().rev() {
        state.retransmit.pending_segments.remove(i);
    }
}
