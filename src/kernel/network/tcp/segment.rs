//! src/kernel/network/tcp/segment.rs
//! TCP segment parsing, building, sending, and option handling.

use alloc::vec::Vec;

use crate::kernel::network::ipv4::{self, IpProtocol, Ipv4Addr, Ipv4Header};
use crate::kernel::network::ipv6::{self, Ipv6Addr, Ipv6Header, Ipv6NextHeader};
use crate::kernel::network::stack::NetworkStack;
use crate::{Error, Result};

use super::types::{
    TcpConnectionState, TcpHeader, MAX_SACK_BLOCKS, MIN_PEER_MSS, TCP_MIN_HEADER_SIZE,
    TCP_OPT_KIND_MSS, TCP_OPT_KIND_SACK, TCP_OPT_KIND_SACK_PERMITTED, TCP_OPT_KIND_TIMESTAMP,
    TCP_OPT_KIND_WINDOW_SCALE, TCP_OPT_LEN_TIMESTAMP,
};

// ─── Header parse / build ─────────────────────────────────────────────

/// Parse a TCP header from a raw byte slice. Returns the header and the data payload.
pub fn parse_tcp_header(data: &[u8]) -> Result<(TcpHeader, usize)> {
    if data.len() < TCP_MIN_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    let source_port = u16::from_be_bytes([data[0], data[1]]);
    let destination_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
    let data_offset = ((data_offset_flags >> 12) & 0x0F) as u8;
    let flags = (data_offset_flags & 0x01FF) as u8;
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent = u16::from_be_bytes([data[18], data[19]]);

    if data_offset < 5 {
        return Err(Error::InvalidArgument);
    }

    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len {
        return Err(Error::InvalidArgument);
    }

    let options = if header_len > TCP_MIN_HEADER_SIZE {
        Vec::from(&data[TCP_MIN_HEADER_SIZE..header_len])
    } else {
        Vec::new()
    };

    Ok((
        TcpHeader {
            source_port,
            destination_port,
            sequence_number: seq,
            acknowledgment_number: ack,
            data_offset,
            flags,
            window_size: window,
            checksum,
            urgent_pointer: urgent,
            options,
        },
        header_len,
    ))
}

/// Build a TCP segment (IPv4) with the given header fields and payload.
pub fn build_tcp_segment(
    header: &TcpHeader,
    payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Vec<u8> {
    let data_offset = 5 + (header.options.len() as u8).div_ceil(4);
    let header_len = data_offset as usize * 4;
    let mut buf = Vec::with_capacity(header_len + payload.len());

    buf.extend_from_slice(&header.source_port.to_be_bytes());
    buf.extend_from_slice(&header.destination_port.to_be_bytes());
    buf.extend_from_slice(&header.sequence_number.to_be_bytes());
    buf.extend_from_slice(&header.acknowledgment_number.to_be_bytes());
    let dof = ((data_offset as u16) << 12) | (header.flags as u16 & 0x01FF);
    buf.extend_from_slice(&dof.to_be_bytes());
    buf.extend_from_slice(&header.window_size.to_be_bytes());
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(&header.urgent_pointer.to_be_bytes());
    buf.extend_from_slice(&header.options);
    while buf.len() < header_len {
        buf.push(0);
    }
    buf.extend_from_slice(payload);

    let mut sum: u32 = 0;
    ipv4::pseudo_header_checksum_add(&mut sum, src_ip, dst_ip, 6, buf.len() as u16);
    ipv4::checksum_add(&mut sum, &buf);
    let checksum = ipv4::checksum_finalize(sum);
    buf[16] = (checksum >> 8) as u8;
    buf[17] = checksum as u8;

    buf
}

/// Build a TCP segment (IPv6) with the given header fields and payload.
pub fn build_tcp_segment_v6(
    header: &TcpHeader,
    payload: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
) -> Vec<u8> {
    let data_offset = 5 + (header.options.len() as u8).div_ceil(4);
    let header_len = data_offset as usize * 4;
    let mut buf = Vec::with_capacity(header_len + payload.len());

    buf.extend_from_slice(&header.source_port.to_be_bytes());
    buf.extend_from_slice(&header.destination_port.to_be_bytes());
    buf.extend_from_slice(&header.sequence_number.to_be_bytes());
    buf.extend_from_slice(&header.acknowledgment_number.to_be_bytes());
    let dof = ((data_offset as u16) << 12) | (header.flags as u16 & 0x01FF);
    buf.extend_from_slice(&dof.to_be_bytes());
    buf.extend_from_slice(&header.window_size.to_be_bytes());
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(&header.urgent_pointer.to_be_bytes());
    buf.extend_from_slice(&header.options);
    while buf.len() < header_len {
        buf.push(0);
    }
    buf.extend_from_slice(payload);

    let mut sum: u32 = 0;
    ipv6::pseudo_header_checksum_add(
        &mut sum,
        src_ip,
        dst_ip,
        Ipv6NextHeader::Tcp.to_u8(),
        buf.len() as u32,
    );
    ipv4::checksum_add(&mut sum, &buf);
    let checksum = ipv4::checksum_finalize(sum);
    buf[16] = (checksum >> 8) as u8;
    buf[17] = checksum as u8;

    buf
}

// ─── Send helpers ─────────────────────────────────────────────────────

pub(crate) fn send_tcp_segment(
    stack: &NetworkStack,
    dst_ip: Ipv4Addr,
    segment: &[u8],
) -> Result<()> {
    stack.profiler.inc_tcp_segments_tx();
    let ip_header = Ipv4Header {
        total_length: 0,
        identification: 0,
        flags_fragment_offset: 0,
        ttl: ipv4::IPV4_DEFAULT_TTL,
        protocol: IpProtocol::Tcp,
        header_checksum: 0,
        source: stack.local_ip(),
        destination: dst_ip,
    };
    let raw_ip = ipv4::build_packet(&ip_header, segment);
    stack.send_ipv4_packet(dst_ip, raw_ip)
}

/// Send a TCP segment via IPv6.
pub(crate) fn send_tcp_segment_v6(
    stack: &NetworkStack,
    dst_ip: Ipv6Addr,
    segment: &[u8],
) -> Result<()> {
    stack.profiler.inc_tcp_segments_tx();
    let ip_header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: Ipv6NextHeader::Tcp,
        hop_limit: ipv6::IPV6_DEFAULT_HOP_LIMIT,
        source: stack.local_ip_v6(),
        destination: dst_ip,
    };
    let raw_ip = ipv6::build_packet(&ip_header, segment);
    stack.send_ipv6_packet(dst_ip, raw_ip)
}

// ─── Option parsing / building ────────────────────────────────────────

/// Parse the Maximum Segment Size from TCP options.
pub(crate) fn parse_mss_option(options: &[u8]) -> usize {
    let mut peer_mss = MIN_PEER_MSS;
    let mut opt_idx = 0;
    while opt_idx + 1 < options.len() {
        let kind = options[opt_idx];
        let len = options[opt_idx + 1] as usize;
        if kind == TCP_OPT_KIND_MSS && len == 4 && opt_idx + 4 <= options.len() {
            peer_mss = u16::from_be_bytes([options[opt_idx + 2], options[opt_idx + 3]]) as usize;
            break;
        }
        if len == 0 {
            break;
        }
        opt_idx += len.max(1);
    }
    peer_mss
}

/// Parse the Window Scale option from TCP options.
pub(crate) fn parse_window_scale_option(options: &[u8]) -> u8 {
    let mut opt_idx = 0;
    while opt_idx + 1 < options.len() {
        let kind = options[opt_idx];
        let len = options[opt_idx + 1] as usize;
        if kind == TCP_OPT_KIND_WINDOW_SCALE && len == 3 && opt_idx + 3 <= options.len() {
            return options[opt_idx + 2].min(14);
        }
        if len == 0 {
            break;
        }
        opt_idx += len.max(1);
    }
    0
}

/// Parse the SACK option (kind=5) from TCP options.
pub(crate) fn parse_sack_option(options: &[u8]) -> Vec<(u32, u32)> {
    let mut blocks = Vec::new();
    let mut opt_idx = 0;
    while opt_idx + 1 < options.len() {
        let kind = options[opt_idx];
        let len = options[opt_idx + 1] as usize;
        if kind == TCP_OPT_KIND_SACK && len >= 10 && opt_idx + len <= options.len() {
            let body = &options[opt_idx + 2..opt_idx + len];
            let n_blocks = body.len() / 8;
            for i in 0..n_blocks {
                let base = i * 8;
                if base + 8 > body.len() {
                    break;
                }
                let left = u32::from_be_bytes([
                    body[base],
                    body[base + 1],
                    body[base + 2],
                    body[base + 3],
                ]);
                let right = u32::from_be_bytes([
                    body[base + 4],
                    body[base + 5],
                    body[base + 6],
                    body[base + 7],
                ]);
                blocks.push((left, right));
            }
            break;
        }
        if len == 0 {
            break;
        }
        opt_idx += len.max(1);
    }
    blocks
}

/// Parse the Timestamp option (kind=8) from TCP options.
pub(crate) fn parse_timestamp_option(options: &[u8]) -> Option<(u32, u32)> {
    let mut opt_idx = 0;
    while opt_idx + 1 < options.len() {
        let kind = options[opt_idx];
        let len = options[opt_idx + 1] as usize;
        if kind == TCP_OPT_KIND_TIMESTAMP && len == 10 && opt_idx + 10 <= options.len() {
            let tsval = u32::from_be_bytes([
                options[opt_idx + 2],
                options[opt_idx + 3],
                options[opt_idx + 4],
                options[opt_idx + 5],
            ]);
            let tsecr = u32::from_be_bytes([
                options[opt_idx + 6],
                options[opt_idx + 7],
                options[opt_idx + 8],
                options[opt_idx + 9],
            ]);
            return Some((tsval, tsecr));
        }
        if len == 0 {
            break;
        }
        opt_idx += len.max(1);
    }
    None
}

/// Build a Timestamp option (kind=8, len=10).
pub(super) fn build_timestamp_option(tsval: u32, tsecr: u32) -> [u8; 10] {
    [
        TCP_OPT_KIND_TIMESTAMP,
        TCP_OPT_LEN_TIMESTAMP,
        (tsval >> 24) as u8,
        (tsval >> 16) as u8,
        (tsval >> 8) as u8,
        tsval as u8,
        (tsecr >> 24) as u8,
        (tsecr >> 16) as u8,
        (tsecr >> 8) as u8,
        tsecr as u8,
    ]
}

/// Build a SACK option (kind=5) from a list of blocks.
pub(super) fn build_sack_option(blocks: &[(u32, u32)]) -> Vec<u8> {
    let n = blocks.len().min(MAX_SACK_BLOCKS);
    if n == 0 {
        return Vec::new();
    }
    let mut opts = Vec::with_capacity(2 + n * 8);
    opts.push(TCP_OPT_KIND_SACK);
    opts.push((2 + n * 8) as u8);
    for &(left, right) in &blocks[..n] {
        opts.extend_from_slice(&left.to_be_bytes());
        opts.extend_from_slice(&right.to_be_bytes());
    }
    opts
}

/// Check whether the SACK-permitted option is present in options.
pub(crate) fn has_sack_permitted(options: &[u8]) -> bool {
    let mut opt_idx = 0;
    while opt_idx + 1 < options.len() {
        let kind = options[opt_idx];
        let len = options[opt_idx + 1] as usize;
        if kind == TCP_OPT_KIND_SACK_PERMITTED && len >= 2 {
            return true;
        }
        if len == 0 {
            break;
        }
        opt_idx += len.max(1);
    }
    false
}

/// Build the options for an outgoing segment with optional timestamps.
pub(super) fn timestamped_options(state: &TcpConnectionState) -> Vec<u8> {
    if state.peer_timestamps {
        let ts = build_timestamp_option(state.ts_val, state.peer_ts_val);
        Vec::from(ts.as_slice())
    } else {
        Vec::new()
    }
}

/// Build options for an outgoing ACK with timestamp and SACK blocks.
pub(super) fn ack_options_with_sack(state: &TcpConnectionState) -> Vec<u8> {
    let ts_opts = timestamped_options(state);
    let sack_blocks: Vec<(u32, u32)> = state
        .ooo_queue
        .iter()
        .map(|&(start, ref data)| (start, start.wrapping_add(data.len() as u32)))
        .collect();
    let sack_opts = build_sack_option(&sack_blocks);
    if sack_opts.is_empty() {
        return ts_opts;
    }
    let mut opts = ts_opts;
    opts.extend_from_slice(&sack_opts);
    opts
}

/// Bump our timestamp clock and record the peer's most recent TSval.
pub(super) fn advance_timestamp(state: &mut TcpConnectionState, peer_tsval: u32) {
    state.peer_ts_val = peer_tsval;
    state.ts_val = state.ts_val.wrapping_add(1);
}
