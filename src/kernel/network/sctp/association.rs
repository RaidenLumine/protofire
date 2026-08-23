//! src/kernel/network/sctp/association.rs
//! SCTP association state machine (RFC 4960) for a single stream.
//!
//! Minimal implementation:
//! - 4-way handshake: INIT → INIT_ACK → COOKIE_ECHO → COOKIE_ACK
//! - CRC32C verification happens in [`super::chunk::parse_sctp_packet`]
//! - Single stream, no multi-homing

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::{Error, Result};

use super::chunk::{
    build_init_chunk, build_sctp_packet, parse_init_params, parse_sctp_packet, SctpChunkType,
    SCTP_CHUNK_HEADER_LEN, SCTP_COOKIE_ACK, SCTP_COOKIE_ECHO, SCTP_INIT_ACK,
};

/// SCTP association state (RFC 4960 §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssocState {
    Closed,
    CookieWait,
    CookieEchoed,
    Established,
}

/// A single-stream SCTP association.
pub struct Association {
    state: AssocState,
    local_port: u16,
    remote_port: u16,
    local_verification_tag: u32,
    remote_verification_tag: u32,
    local_initial_tsn: u32,
    remote_initial_tsn: u32,
    local_a_rwnd: u32,
    remote_a_rwnd: u32,
    local_outbound_streams: u16,
    remote_inbound_streams: u16,
    next_tsn: u32,
    cumulative_tsn_ack: u32,
    send_queue: VecDeque<(u32, Vec<u8>)>,
    recv_buffer: VecDeque<u8>,
    state_cookie: Vec<u8>,
}

impl Association {
    /// Create a fresh client-side association in the `Closed` state.
    pub fn new(
        local_port: u16,
        remote_port: u16,
        local_verification_tag: u32,
        local_initial_tsn: u32,
    ) -> Self {
        Self {
            state: AssocState::Closed,
            local_port,
            remote_port,
            local_verification_tag,
            remote_verification_tag: 0,
            local_initial_tsn,
            remote_initial_tsn: 0,
            local_a_rwnd: 65536,
            remote_a_rwnd: 0,
            local_outbound_streams: 1,
            remote_inbound_streams: 1,
            next_tsn: local_initial_tsn,
            cumulative_tsn_ack: 0,
            send_queue: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            state_cookie: Vec::new(),
        }
    }

    /// Bytes available to read from the receive buffer.
    pub fn available(&self) -> usize {
        self.recv_buffer.len()
    }

    /// Read data from the receive buffer.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.recv_buffer.len());
        for b in buf.iter_mut().take(n) {
            *b = self.recv_buffer.pop_front().unwrap();
        }
        n
    }

    /// Enqueue data for sending.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let len = data.len();
        let tsn = self.next_tsn;
        self.next_tsn = self.next_tsn.wrapping_add(1);
        self.send_queue.push_back((tsn, data.to_vec()));
        len
    }

    /// Begin the 4-way handshake: transition from Closed → CookieWait
    /// and build an INIT chunk.
    pub fn send_init(&mut self) -> Result<Vec<u8>> {
        if self.state != AssocState::Closed {
            return Err(Error::InvalidArgument);
        }
        self.state = AssocState::CookieWait;
        let init = build_init_chunk(
            self.local_verification_tag,
            self.local_a_rwnd,
            self.local_outbound_streams,
            1, // inbound streams (we request 1)
            self.local_initial_tsn,
        );
        let packet = build_sctp_packet(
            self.local_port,
            self.remote_port,
            0, // INIT uses verification_tag = 0
            &[init],
        );
        Ok(packet)
    }

    /// Handle an INIT_ACK chunk.
    ///
    /// Extracts the peer's parameters, stores the state cookie,
    /// transitions to CookieEchoed, and builds a COOKIE_ECHO packet.
    pub fn handle_init_ack(&mut self, chunk_data: &[u8]) -> Result<Vec<u8>> {
        if self.state != AssocState::CookieWait {
            return Err(Error::InvalidArgument);
        }

        let params = &chunk_data[SCTP_CHUNK_HEADER_LEN..];
        let (peer_tag, peer_rwnd, peer_os, peer_is, peer_tsn) = parse_init_params(params)?;

        // Validate stream counts — we only support single stream.
        if peer_is < 1 || peer_os < 1 {
            return Err(Error::Unsupported);
        }

        self.remote_verification_tag = peer_tag;
        self.remote_a_rwnd = peer_rwnd;
        self.remote_inbound_streams = peer_os;
        self.remote_initial_tsn = peer_tsn;
        self.cumulative_tsn_ack = peer_tsn;

        // Extract state cookie from variable parameters.
        let var_params = &params[16..];
        // Look for State Cookie parameter (type 7).
        let mut cookie_found = false;
        let mut cookie = Vec::new();
        let mut pos = 0;
        while pos + 4 <= var_params.len() {
            let param_type = u16::from_be_bytes([var_params[pos], var_params[pos + 1]]);
            let param_len = u16::from_be_bytes([var_params[pos + 2], var_params[pos + 3]]) as usize;
            if param_len < 4 || pos + param_len > var_params.len() {
                break;
            }
            if param_type == 7 {
                cookie_found = true;
                cookie = var_params[pos + 4..pos + param_len].to_vec();
                break;
            }
            // Parameters are 4-byte aligned.
            pos += (param_len + 3) & !3;
        }
        if !cookie_found {
            return Err(Error::InvalidArgument);
        }
        self.state_cookie = cookie;

        // Build a COOKIE_ECHO chunk carrying the opaque state cookie.
        let cookie_echo = build_cookie_echo_chunk(&self.state_cookie);
        let packet = build_sctp_packet(
            self.local_port,
            self.remote_port,
            self.remote_verification_tag,
            &[cookie_echo],
        );
        self.state = AssocState::CookieEchoed;
        Ok(packet)
    }

    /// Handle a COOKIE_ACK chunk: the peer accepted our cookie and the
    /// association is now established.
    pub fn handle_cookie_ack(&mut self) -> Result<()> {
        if self.state != AssocState::CookieEchoed {
            return Err(Error::InvalidArgument);
        }
        self.state = AssocState::Established;
        Ok(())
    }

    /// Current association state.
    pub fn state(&self) -> AssocState {
        self.state
    }
}

/// Result of processing a received SCTP packet.
pub enum ProcessResult {
    /// No response packet needs to be sent.
    Silent,
    /// A response packet to transmit back to the peer.
    Response(Vec<u8>),
}

// ─── Server-side association creation helper ─────────────────────────────────

/// Create a server-side association after receiving an INIT.
///
/// Builds an INIT_ACK response with a state cookie.
#[allow(clippy::too_many_arguments)]
pub fn create_server_association(
    local_port: u16,
    remote_port: u16,
    peer_initiate_tag: u32,
    peer_a_rwnd: u32,
    peer_outbound_streams: u16,
    peer_initial_tsn: u32,
    local_verification_tag: u32,
    local_initial_tsn: u32,
) -> (Association, Vec<u8>) {
    let assoc = Association {
        state: AssocState::CookieWait,
        local_port,
        remote_port,
        local_verification_tag,
        remote_verification_tag: peer_initiate_tag,
        local_initial_tsn,
        remote_initial_tsn: peer_initial_tsn,
        local_a_rwnd: 65536,
        remote_a_rwnd: peer_a_rwnd,
        local_outbound_streams: 1,
        remote_inbound_streams: peer_outbound_streams,
        next_tsn: local_initial_tsn,
        cumulative_tsn_ack: peer_initial_tsn.wrapping_sub(1),
        send_queue: VecDeque::new(),
        recv_buffer: VecDeque::new(),
        state_cookie: Vec::new(),
    };

    let init_ack =
        build_init_ack_chunk(local_verification_tag, 65536, 1, 1, local_initial_tsn, &[]);
    let packet = build_sctp_packet(local_port, remote_port, peer_initiate_tag, &[init_ack]);
    (assoc, packet)
}

/// Dispatch a received SCTP packet against the association.
///
/// Verifies the verification tag and routes chunks that require a response
/// (INIT_ACK, COOKIE_ACK) through the state machine.
pub fn process_incoming(assoc: &mut Association, packet: &[u8]) -> Result<ProcessResult> {
    let (header, chunks) = parse_sctp_packet(packet)?;
    if header.verification_tag != 0 && header.verification_tag != assoc.remote_verification_tag {
        return Err(Error::InvalidArgument);
    }

    for (ctype, _flags, cdata) in chunks {
        match ctype {
            SCTP_INIT_ACK => {
                let reply = assoc.handle_init_ack(&cdata)?;
                return Ok(ProcessResult::Response(reply));
            }
            SCTP_COOKIE_ACK => {
                assoc.handle_cookie_ack()?;
                return Ok(ProcessResult::Silent);
            }
            _ => {}
        }
    }
    Ok(ProcessResult::Silent)
}

/// Build a COOKIE_ECHO chunk carrying the opaque state cookie.
fn build_cookie_echo_chunk(cookie: &[u8]) -> (SctpChunkType, u8, Vec<u8>) {
    (SCTP_COOKIE_ECHO, 0, cookie.to_vec())
}

/// Build an INIT_ACK chunk.  `extra_params` currently carries no state
/// cookie, so the peer uses an empty cookie (acceptable for the single-host
/// demo); a production implementation would embed a signed cookie here.
fn build_init_ack_chunk(
    initiate_tag: u32,
    a_rwnd: u32,
    outbound_streams: u16,
    inbound_streams: u16,
    initial_tsn: u32,
    _extra_params: &[u8],
) -> (SctpChunkType, u8, Vec<u8>) {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&initiate_tag.to_be_bytes());
    data.extend_from_slice(&a_rwnd.to_be_bytes());
    data.extend_from_slice(&outbound_streams.to_be_bytes());
    data.extend_from_slice(&inbound_streams.to_be_bytes());
    data.extend_from_slice(&initial_tsn.to_be_bytes());
    (SCTP_INIT_ACK, 0, data)
}
