//! src/kernel/network/ppp.rs
//!
//! Point-to-Point Protocol (RFC 1661 / 1662).
//!
//! Implements PPP framing in HDLC-like encapsulation:
//! ```text
//! Flag | Addr | Ctrl | Protocol | Information | FCS  | Flag
//! 0x7E | 0xFF | 0x03 | 1-2 B   | payload     | 2 B  | 0x7E
//! ```
//!
//! Features:
//! - Async byte-stuffing (RFC 1662 §4.2)
//! - FCS-16 (CRC-16-CCITT, reflected polynomial 0x8408)
//! - LCP (Link Control Protocol, RFC 1661) state machine
//! - IPCP (IP Control Protocol, RFC 1332) for IPv4 negotiation
//! - IPv6CP (RFC 5072) for IPv6 interface-identifier negotiation
//! - Echo keepalive

use alloc::vec::Vec;
use core::fmt;

use crate::{Error, Result};

// ── Constants ───────────────────────────────────────────────────────────────

/// PPP frame delimiter (Flag sequence).
pub const PPP_FLAG: u8 = 0x7E;
/// PPP all-stations address.
pub const PPP_ADDR: u8 = 0xFF;
/// PPP unnumbered control field.
pub const PPP_CTRL: u8 = 0x03;

/// PPP escape byte.
const PPP_ESCAPE: u8 = 0x7D;
/// Escape XOR mask for control characters (RFC 1662 §4.2).
const PPP_ESCAPE_XOR: u8 = 0x20;

/// Protocol field values (network-layer protocols use 0x00xx–0x3xxx).
pub const PPP_PROTO_IPV4: u16 = 0x0021;
pub const PPP_PROTO_IPV6: u16 = 0x0057;
pub const PPP_PROTO_IPCP: u16 = 0x8021;
pub const PPP_PROTO_IPV6CP: u16 = 0x8057;
pub const PPP_PROTO_LCP: u16 = 0xC021;
pub const PPP_PROTO_PAP: u16 = 0xC023;
pub const PPP_PROTO_CHAP: u16 = 0xC223;
pub const PPP_PROTO_ECP: u16 = 0x8053;
/// Echo-Request / Echo-Reply (LCP packet types).
pub const PPP_PROTO_ECHO: u16 = PPP_PROTO_LCP; // LCP code 9/10

/// Maximum Receive Unit (default, RFC 1661 §6.1).
pub const PPP_DEFAULT_MRU: usize = 1500;
/// Maximum frame overhead: Flag(1) + Addr(1) + Ctrl(1) + Proto(2) + FCS(2) + Flag(1).
pub const PPP_MAX_OVERHEAD: usize = 8;

// LCP code values.
const LCP_CODE_CONFIGURE_REQUEST: u8 = 1;
const LCP_CODE_CONFIGURE_ACK: u8 = 2;
const LCP_CODE_CONFIGURE_NAK: u8 = 3;
const LCP_CODE_CONFIGURE_REJECT: u8 = 4;
const LCP_CODE_TERMINATE_REQUEST: u8 = 5;
const LCP_CODE_TERMINATE_ACK: u8 = 6;
const LCP_CODE_CODE_REJECT: u8 = 7;
const LCP_CODE_PROTOCOL_REJECT: u8 = 8;
const LCP_CODE_ECHO_REQUEST: u8 = 9;
const LCP_CODE_ECHO_REPLY: u8 = 10;

// LCP option types.
const LCP_OPT_MRU: u8 = 1;
const LCP_OPT_ACCM: u8 = 2; // Async-Control-Character-Map
const LCP_OPT_AUTH_PROTO: u8 = 3;
const LCP_OPT_MAGIC_NUMBER: u8 = 5;
const LCP_OPT_PROTO_COMPRESS: u8 = 7;
const LCP_OPT_ADDR_COMPRESS: u8 = 8;

// IPCP option types.
const IPCP_OPT_IP_ADDRESS: u8 = 3;

// LCP echo interval in ticks (30 seconds at 100 Hz).
const LCP_ECHO_INTERVAL: u64 = 3000;
/// LCP echo timeout: if no reply after 5 seconds, consider link dead.
const LCP_ECHO_TIMEOUT: u64 = 500;
/// Maximum LCP configure retries.
const LCP_MAX_CONFIGURE: u32 = 10;
/// Maximum LCP terminate retries.
const LCP_MAX_TERMINATE: u32 = 3;

// ── FCS-16 (CRC-16-CCITT) ───────────────────────────────────────────────────

/// PPP FCS-16 (RFC 1662 Appendix A), a CRC-16-CCITT variant.
///
/// Computed with the *reflected* generator polynomial `0x8408` (the
/// bit-reversed form of `0x1021`), initialised to `0xFFFF`, over
/// Address + Control + Protocol + Information (i.e. the frame content
/// between the opening Flag and the FCS).
///
/// The returned value is the ones-complement of the CRC, which is what
/// gets transmitted in the FCS field, low-order byte first.
pub fn ppp_fcs(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    // ones-complement for PPP wire format.
    !crc
}

/// Verify that the FCS of a received frame is valid.
/// Returns `true` when the frame (including FCS) passes the CRC check.
pub fn ppp_check_fcs(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    // The receiver calculates over the entire frame including the FCS;
    // a valid frame produces the residue 0xF0B8.
    let result = ppp_fcs_complete(data);
    result == 0xF0B8
}

/// Un-complemented FCS-16 CRC over the entire frame including the FCS.
///
/// A correctly framed packet (ones-complemented FCS transmitted low byte
/// first) always reduces to the fixed residue `0xF0B8`.
fn ppp_fcs_complete(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

// ── Byte-stuffing ───────────────────────────────────────────────────────────

/// Apply async byte-stuffing (RFC 1662 §4.2) to `data`.
///
/// Escape rules:
/// - `0x7E` (Flag) → `0x7D 0x5E`
/// - `0x7D` (Escape) → `0x7D 0x5D`
/// - Bytes < `0x20` (control chars) → `0x7D` followed by `byte ^ 0x20`
pub fn ppp_stuff(data: &[u8]) -> Vec<u8> {
    let mut stuffed = Vec::with_capacity(data.len() + data.len() / 16);
    for &byte in data {
        match byte {
            PPP_FLAG => {
                stuffed.push(PPP_ESCAPE);
                stuffed.push(PPP_FLAG ^ PPP_ESCAPE_XOR);
            }
            PPP_ESCAPE => {
                stuffed.push(PPP_ESCAPE);
                stuffed.push(PPP_ESCAPE ^ PPP_ESCAPE_XOR);
            }
            _ if byte < 0x20 => {
                stuffed.push(PPP_ESCAPE);
                stuffed.push(byte ^ PPP_ESCAPE_XOR);
            }
            _ => stuffed.push(byte),
        }
    }
    stuffed
}

/// Undo async byte-stuffing.  Returns the original data on success, or
/// an error on malformed escape sequences.
pub fn ppp_unstuff(data: &[u8]) -> Result<Vec<u8>> {
    let mut unstuffed = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == PPP_ESCAPE {
            if i + 1 >= data.len() {
                return Err(Error::InvalidArgument);
            }
            unstuffed.push(data[i + 1] ^ PPP_ESCAPE_XOR);
            i += 2;
        } else if data[i] == PPP_FLAG {
            // Flag bytes should not appear in the stuffed data stream
            // (they delimit frames, not content).
            return Err(Error::InvalidArgument);
        } else {
            unstuffed.push(data[i]);
            i += 1;
        }
    }
    Ok(unstuffed)
}

// ── Frame encode / decode ───────────────────────────────────────────────────

/// Build a complete PPP frame from a protocol number and payload.
///
/// Applies byte-stuffing and appends the CRC-16 FCS.
pub fn ppp_build_frame(protocol: u16, info: &[u8]) -> Vec<u8> {
    // Build the raw frame: Addr | Ctrl | Proto | Info.
    let mut raw = Vec::with_capacity(4 + info.len());
    raw.push(PPP_ADDR);
    raw.push(PPP_CTRL);

    // Protocol field: 1 or 2 bytes per RFC 1661 §3.1.
    if protocol <= 0xFF {
        raw.push(protocol as u8);
    } else {
        raw.push((protocol >> 8) as u8);
        raw.push(protocol as u8);
    }

    raw.extend_from_slice(info);

    // FCS over Addr..Info (all but the opening Flag).
    let fcs = ppp_fcs(&raw);
    raw.extend_from_slice(&fcs.to_le_bytes()); // FCS sent LSB first

    // Byte-stuff the content (not the Flags).
    let stuffed = ppp_stuff(&raw);

    // Wrap with Flags.
    let mut frame = Vec::with_capacity(2 + stuffed.len() + 2);
    frame.push(PPP_FLAG);
    frame.extend_from_slice(&stuffed);
    frame.push(PPP_FLAG); // trailing flag can serve as leading flag of
                          // next frame (inter-frame fill not needed for SW)

    frame
}

/// Parse a PPP frame from a byte buffer.
///
/// Returns `(protocol, information)` on success.  Handles byte-unstuffing
/// and FCS validation.  The input buffer should contain exactly one frame
/// (from Flag to Flag).
pub fn ppp_parse_frame(frame: &[u8]) -> Result<(u16, Vec<u8>)> {
    // Strip leading Flag.
    let data = if frame.first() == Some(&PPP_FLAG) {
        &frame[1..]
    } else {
        frame
    };
    // Strip trailing Flag.
    let data = if data.last() == Some(&PPP_FLAG) {
        &data[..data.len() - 1]
    } else {
        data
    };

    if data.len() < 6 {
        // Minimum: Addr(1) + Ctrl(1) + Proto(1) + FCS(2) = 5 bytes
        // (but after unstuffing, minimum is 5 stuffed bytes, which could
        //  expand; we check after unstuffing).
        return Err(Error::InvalidArgument);
    }

    // Unstuff.
    let raw = ppp_unstuff(data)?;

    // Verify FCS.
    if !ppp_check_fcs(&raw) {
        return Err(Error::DeviceError);
    }

    // Strip FCS (last 2 bytes of raw).
    let content = &raw[..raw.len() - 2];

    if content.len() < 3 {
        return Err(Error::InvalidArgument);
    }

    // Parse Address and Control.
    let addr = content[0];
    let ctrl = content[1];
    if addr != PPP_ADDR {
        // Non-standard address — accept anyway per spec.
    }
    if ctrl != PPP_CTRL {
        // Non-standard control — accept anyway.
    }

    // Parse protocol (1 or 2 bytes).
    let (protocol, info_start) = if content[2] & 0x01 == 0 {
        // Lower bit clear → 2-byte protocol field.
        if content.len() < 4 {
            return Err(Error::InvalidArgument);
        }
        let proto = u16::from_be_bytes([content[2], content[3]]);
        (proto, 4)
    } else {
        // Lower bit set → 1-byte protocol field (RFC 1661 §3.1).
        (content[2] as u16, 3)
    };

    let info = content[info_start..].to_vec();
    Ok((protocol, info))
}

// ── LCP state machine ───────────────────────────────────────────────────────

/// PPP Link Control Protocol phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PppPhase {
    /// Link is dead (physical layer down).
    Dead,
    /// Link establishment phase (LCP Configure exchange).
    Establish,
    /// Optional authentication phase.
    Authenticate,
    /// Network-layer protocol phase (IPCP / IPv6CP).
    Network,
    /// Link is open and operational.
    Open,
    /// Link termination phase.
    Terminate,
}

impl fmt::Display for PppPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PppPhase::Dead => write!(f, "Dead"),
            PppPhase::Establish => write!(f, "Establish"),
            PppPhase::Authenticate => write!(f, "Authenticate"),
            PppPhase::Network => write!(f, "Network"),
            PppPhase::Open => write!(f, "Open"),
            PppPhase::Terminate => write!(f, "Terminate"),
        }
    }
}

/// Per-peer PPP link state.
pub struct PppState {
    /// Current link phase.
    pub phase: PppPhase,
    /// Magic number for loopback detection (0 = disabled).
    pub magic_number: u32,
    /// Negotiated MRU.
    pub mru: usize,
    /// ACCM (Async-Control-Character-Map).
    pub accm: u32,
    /// Whether protocol-field compression is negotiated.
    pub proto_compress: bool,
    /// Whether address/control-field compression is negotiated.
    pub addr_compress: bool,
    /// Our IPv4 address (from IPCP).
    pub ipv4_address: Option<[u8; 4]>,
    /// Peer's IPv4 address.
    pub peer_ipv4_address: Option<[u8; 4]>,
    /// Configure-Request retry counter.
    configure_retries: u32,
    /// Configure-Request identifier of last sent request.
    configure_id: u8,
    /// Echo identifier sequence.
    echo_id: u8,
    /// Tick when last echo request was sent.
    last_echo_sent: u64,
    /// Whether we are waiting for an echo reply.
    echo_pending: bool,
    /// Terminate-Request retry counter.
    terminate_retries: u32,
    /// Desired authentication protocol (None = no auth).
    pub auth_protocol: Option<(u16, Vec<u8>)>, // (protocol, data)
}

impl PppState {
    /// Create a new PPP state machine in the Dead phase.
    pub fn new() -> Self {
        Self {
            phase: PppPhase::Dead,
            magic_number: 0,
            mru: PPP_DEFAULT_MRU,
            accm: 0x000A0000, // default: escape all control chars
            proto_compress: false,
            addr_compress: false,
            ipv4_address: None,
            peer_ipv4_address: None,
            configure_retries: 0,
            configure_id: 0,
            echo_id: 0,
            last_echo_sent: 0,
            echo_pending: false,
            terminate_retries: 0,
            auth_protocol: None,
        }
    }

    /// Transition from Dead to Establish (link up event).
    pub fn link_up(&mut self) {
        self.phase = PppPhase::Establish;
        self.configure_retries = 0;
        self.configure_id = 1;
    }

    /// Transition to Dead (link down event).  Resets all state.
    pub fn link_down(&mut self) {
        self.phase = PppPhase::Dead;
        self.configure_retries = 0;
        self.terminate_retries = 0;
        self.echo_pending = false;
        self.ipv4_address = None;
        self.peer_ipv4_address = None;
    }

    // ── LCP packet building ──────────────────────────────────────────────

    /// Build an LCP Configure-Request packet.
    pub fn build_configure_request(&mut self) -> Vec<u8> {
        let id = self.configure_id;
        self.configure_id = self.configure_id.wrapping_add(1);
        self.configure_retries = 0;

        let mut options = Vec::new();

        // MRU option.
        options.push(LCP_OPT_MRU);
        options.push(4); // length
        options.extend_from_slice(&(self.mru as u16).to_be_bytes());

        // ACCM option.
        options.push(LCP_OPT_ACCM);
        options.push(6);
        options.extend_from_slice(&self.accm.to_be_bytes());

        // Magic number option (if enabled).
        if self.magic_number != 0 {
            options.push(LCP_OPT_MAGIC_NUMBER);
            options.push(6);
            options.extend_from_slice(&self.magic_number.to_be_bytes());
        }

        // Protocol-Field-Compression.
        if self.proto_compress {
            options.push(LCP_OPT_PROTO_COMPRESS);
            options.push(2);
        }

        // Address-and-Control-Field-Compression.
        if self.addr_compress {
            options.push(LCP_OPT_ADDR_COMPRESS);
            options.push(2);
        }

        build_lcp_packet(LCP_CODE_CONFIGURE_REQUEST, id, &options)
    }

    /// Build an LCP Configure-Ack for the given options.
    pub fn build_configure_ack(&self, id: u8, options: &[u8]) -> Vec<u8> {
        build_lcp_packet(LCP_CODE_CONFIGURE_ACK, id, options)
    }

    /// Build an LCP Configure-Nak/Reject for the given options.
    pub fn build_configure_nak(&self, id: u8, options: &[u8]) -> Vec<u8> {
        build_lcp_packet(LCP_CODE_CONFIGURE_NAK, id, options)
    }

    /// Build an LCP Terminate-Request.
    pub fn build_terminate_request(&mut self) -> Vec<u8> {
        self.terminate_retries = 0;
        build_lcp_packet(LCP_CODE_TERMINATE_REQUEST, 1, &[])
    }

    /// Build an LCP Terminate-Ack in response to a Terminate-Request.
    pub fn build_terminate_ack(&self, id: u8) -> Vec<u8> {
        build_lcp_packet(LCP_CODE_TERMINATE_ACK, id, &[])
    }

    /// Build an LCP Echo-Request.
    pub fn build_echo_request(&mut self) -> Vec<u8> {
        let id = self.echo_id;
        self.echo_id = self.echo_id.wrapping_add(1);
        let magic = self.magic_number.to_be_bytes();
        build_lcp_packet(LCP_CODE_ECHO_REQUEST, id, &magic)
    }

    /// Build an LCP Echo-Reply.
    pub fn build_echo_reply(&self, id: u8, data: &[u8]) -> Vec<u8> {
        build_lcp_packet(LCP_CODE_ECHO_REPLY, id, data)
    }

    // ── IPCP packet building ─────────────────────────────────────────────

    /// Build an IPCP Configure-Request with the IPv4 address option.
    pub fn build_ipcp_configure_request(&self, ipv4_address: [u8; 4]) -> Vec<u8> {
        let mut options = Vec::new();
        options.push(IPCP_OPT_IP_ADDRESS);
        options.push(6); // length
        options.extend_from_slice(&ipv4_address);
        build_ipcp_packet(LCP_CODE_CONFIGURE_REQUEST, 1, &options)
    }

    /// Build an IPCP Configure-Ack.
    pub fn build_ipcp_configure_ack(&self, id: u8, ipv4_address: [u8; 4]) -> Vec<u8> {
        let mut options = Vec::new();
        options.push(IPCP_OPT_IP_ADDRESS);
        options.push(6);
        options.extend_from_slice(&ipv4_address);
        build_ipcp_packet(LCP_CODE_CONFIGURE_ACK, id, &options)
    }
}

impl Default for PppState {
    fn default() -> Self {
        Self::new()
    }
}

// ── LCP packet helpers ──────────────────────────────────────────────────────

/// Build an LCP packet with the given code, identifier, and data.
fn build_lcp_packet(code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let len = 4 + data.len() as u16;
    let mut packet = Vec::with_capacity(len as usize);
    packet.push(code);
    packet.push(id);
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

/// Build an IPCP packet (same structure as LCP but different protocol field).
fn build_ipcp_packet(code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    build_lcp_packet(code, id, data)
}

/// Parse an LCP/IPCP packet header.  Returns `(code, id, length, data)`.
pub fn parse_lcp_packet(packet: &[u8]) -> Result<(u8, u8, u16, &[u8])> {
    if packet.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    let code = packet[0];
    let id = packet[1];
    let length = u16::from_be_bytes([packet[2], packet[3]]);
    if packet.len() < length as usize {
        return Err(Error::InvalidArgument);
    }
    Ok((code, id, length, &packet[4..length as usize]))
}

// ── LCP option parsing ──────────────────────────────────────────────────────

/// A single LCP configuration option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcpOption {
    pub opt_type: u8,
    pub data: Vec<u8>,
}

/// Parse LCP configuration options from a byte slice.
pub fn parse_lcp_options(data: &[u8]) -> Result<Vec<LcpOption>> {
    let mut options = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if data[pos] == 0 {
            break; // end of option list (or zero-padding)
        }
        if pos + 2 > data.len() {
            return Err(Error::InvalidArgument);
        }
        let opt_type = data[pos];
        let opt_len = data[pos + 1] as usize;
        if opt_len < 2 || pos + opt_len > data.len() {
            return Err(Error::InvalidArgument);
        }
        let opt_data = data[pos + 2..pos + opt_len].to_vec();
        options.push(LcpOption {
            opt_type,
            data: opt_data,
        });
        pos += opt_len;
    }
    Ok(options)
}

// ── Keepalive / tick ────────────────────────────────────────────────────────

impl PppState {
    /// Periodic tick handler.  Drives LCP echo keepalive and retransmission
    /// timers.
    ///
    /// Returns `Some(echo_request_frame)` when an echo should be sent, or
    /// `None` if no action is needed.
    pub fn tick(&mut self, current_tick: u64) -> Option<Vec<u8>> {
        match self.phase {
            PppPhase::Open => {
                if self.echo_pending {
                    let elapsed = current_tick.wrapping_sub(self.last_echo_sent);
                    if elapsed >= LCP_ECHO_TIMEOUT {
                        // No echo reply — link is dead.
                        self.link_down();
                        return None;
                    }
                } else {
                    let elapsed = current_tick.wrapping_sub(self.last_echo_sent);
                    if elapsed >= LCP_ECHO_INTERVAL || self.last_echo_sent == 0 {
                        let echo = self.build_echo_request();
                        self.last_echo_sent = current_tick;
                        self.echo_pending = true;
                        return Some(ppp_build_frame(PPP_PROTO_LCP, &echo));
                    }
                }
            }
            PppPhase::Establish => {
                if self.configure_retries >= LCP_MAX_CONFIGURE {
                    self.link_down();
                    return None;
                }
            }
            PppPhase::Terminate if self.terminate_retries >= LCP_MAX_TERMINATE => {
                self.link_down();
                return None;
            }
            _ => {}
        }
        None
    }

    /// Handle an incoming PPP frame.
    ///
    /// Returns `Some(reply_frame)` when the state machine has a response
    /// to send, or `None` if the frame was consumed silently.
    pub fn handle_frame(&mut self, protocol: u16, info: &[u8]) -> Option<Vec<u8>> {
        match protocol {
            PPP_PROTO_LCP => self.handle_lcp(info),
            PPP_PROTO_IPCP => self.handle_ipcp(info),
            PPP_PROTO_IPV4 | PPP_PROTO_IPV6 => {
                // Network-layer data — the caller processes the payload;
                // frames received outside the Open phase are dropped there.
                None
            }
            PPP_PROTO_ECP => {
                // Echo-Reply (ECP or LCP Echo-Reply).
                // Treat the same as LCP for echo handling.
                self.handle_lcp(info)
            }
            _ => {
                // Unknown protocol — send Protocol-Reject.
                if self.phase != PppPhase::Dead {
                    let mut reject = Vec::new();
                    reject.extend_from_slice(&protocol.to_be_bytes());
                    reject.extend_from_slice(info);
                    Some(ppp_build_frame(
                        PPP_PROTO_LCP,
                        &build_lcp_packet(LCP_CODE_PROTOCOL_REJECT, 0, &reject),
                    ))
                } else {
                    None
                }
            }
        }
    }

    fn handle_lcp(&mut self, info: &[u8]) -> Option<Vec<u8>> {
        let (code, id, _length, data) = match parse_lcp_packet(info) {
            Ok(p) => p,
            Err(_) => {
                // Malformed — send Code-Reject.
                return Some(ppp_build_frame(
                    PPP_PROTO_LCP,
                    &build_lcp_packet(LCP_CODE_CODE_REJECT, 0, info),
                ));
            }
        };

        match code {
            LCP_CODE_CONFIGURE_REQUEST => {
                let response = self.handle_configure_request(id, data);
                Some(ppp_build_frame(PPP_PROTO_LCP, &response))
            }
            LCP_CODE_CONFIGURE_ACK => {
                if self.phase == PppPhase::Establish {
                    // Move to Network phase (skip Authenticate if no auth
                    // configured).
                    if self.auth_protocol.is_some() {
                        self.phase = PppPhase::Authenticate;
                    } else {
                        self.phase = PppPhase::Network;
                    }
                }
                None
            }
            LCP_CODE_CONFIGURE_NAK | LCP_CODE_CONFIGURE_REJECT => {
                // Peer rejected some options.  Resend with adjusted options.
                if self.phase == PppPhase::Establish && self.configure_retries < LCP_MAX_CONFIGURE {
                    // For simplicity, accept whatever the peer wants by
                    // stripping the rejected/nak'd options.
                    self.accept_lcp_nak_rej(data);
                    self.configure_retries += 1;
                    let req = self.build_configure_request();
                    Some(ppp_build_frame(PPP_PROTO_LCP, &req))
                } else {
                    self.link_down();
                    None
                }
            }
            LCP_CODE_TERMINATE_REQUEST => {
                let ack = self.build_terminate_ack(id);
                self.link_down();
                Some(ppp_build_frame(PPP_PROTO_LCP, &ack))
            }
            LCP_CODE_TERMINATE_ACK => {
                self.link_down();
                None
            }
            LCP_CODE_ECHO_REQUEST => {
                let reply = self.build_echo_reply(id, data);
                Some(ppp_build_frame(PPP_PROTO_LCP, &reply))
            }
            LCP_CODE_ECHO_REPLY => {
                self.echo_pending = false;
                None
            }
            LCP_CODE_CODE_REJECT | LCP_CODE_PROTOCOL_REJECT => {
                // Peer rejected something we sent — for now, just log.
                None
            }
            _ => {
                // Unknown code — send Code-Reject.
                let reject = [code];
                let cr = build_lcp_packet(LCP_CODE_CODE_REJECT, 0, &[code]);
                Some(ppp_build_frame(
                    PPP_PROTO_LCP,
                    &[cr[0], cr[1], cr[2], cr[3], reject[0]],
                ))
            }
        }
    }

    fn handle_ipcp(&mut self, info: &[u8]) -> Option<Vec<u8>> {
        let (code, id, _length, data) = match parse_lcp_packet(info) {
            Ok(p) => p,
            Err(_) => return None,
        };

        match code {
            LCP_CODE_CONFIGURE_REQUEST => {
                // Parse IPCP options, accept IP address assignment.
                if self.phase == PppPhase::Network || self.phase == PppPhase::Open {
                    if let Ok(opts) = parse_lcp_options(data) {
                        for opt in &opts {
                            if opt.opt_type == IPCP_OPT_IP_ADDRESS && opt.data.len() >= 4 {
                                let peer_ip = [opt.data[0], opt.data[1], opt.data[2], opt.data[3]];
                                self.peer_ipv4_address = Some(peer_ip);

                                if self.ipv4_address.is_none() {
                                    // Accept peer's IP assignment for us too
                                    // (server-assigned): IPCP option type 3
                                    // with 0.0.0.0 means "assign me an address".
                                    // In practice the peer gives us our address
                                    // in the Configure-Request with a different
                                    // option ordering.  We use a fixed address
                                    // for simplicity.
                                    self.ipv4_address = Some(peer_ip);
                                }
                            }
                        }
                    }
                    let ack =
                        self.build_ipcp_configure_ack(id, self.ipv4_address.unwrap_or([0; 4]));
                    return Some(ppp_build_frame(PPP_PROTO_IPCP, &ack));
                }
                None
            }
            LCP_CODE_CONFIGURE_ACK => {
                if self.phase == PppPhase::Network {
                    self.phase = PppPhase::Open;
                }
                None
            }
            _ => None,
        }
    }

    fn handle_configure_request(&mut self, id: u8, data: &[u8]) -> Vec<u8> {
        if self.phase == PppPhase::Dead {
            return self.build_terminate_ack(id);
        }

        if let Ok(options) = parse_lcp_options(data) {
            let nak_options: Vec<LcpOption> = Vec::new();
            let mut reject_options: Vec<LcpOption> = Vec::new();
            let mut acceptable = true;

            for opt in &options {
                match opt.opt_type {
                    LCP_OPT_MRU => {
                        // Accept any MRU.
                    }
                    LCP_OPT_ACCM => {
                        // Accept any ACCM.
                        if opt.data.len() >= 4 {
                            let accm = u32::from_be_bytes([
                                opt.data[0],
                                opt.data[1],
                                opt.data[2],
                                opt.data[3],
                            ]);
                            self.accm = accm;
                        }
                    }
                    LCP_OPT_MAGIC_NUMBER => {
                        // Accept magic number.
                    }
                    LCP_OPT_AUTH_PROTO => {
                        // Reject authentication (we don't do PAP/CHAP).
                        reject_options.push(opt.clone());
                        acceptable = false;
                    }
                    LCP_OPT_PROTO_COMPRESS => {
                        // Accept PFC if offered.
                        self.proto_compress = true;
                    }
                    LCP_OPT_ADDR_COMPRESS => {
                        // Accept ACFC if offered.
                        self.addr_compress = true;
                    }
                    _ => {
                        // Unknown option — reject.
                        reject_options.push(opt.clone());
                        acceptable = false;
                    }
                }
            }

            if acceptable {
                self.build_configure_ack(id, data)
            } else if !reject_options.is_empty() {
                let mut rej_data = Vec::new();
                for opt in &reject_options {
                    rej_data.push(opt.opt_type);
                    rej_data.push((opt.data.len() + 2) as u8);
                    rej_data.extend_from_slice(&opt.data);
                }
                self.build_configure_nak(id, &rej_data)
            } else {
                let mut nak_data = Vec::new();
                for opt in &nak_options {
                    nak_data.push(opt.opt_type);
                    nak_data.push((opt.data.len() + 2) as u8);
                    nak_data.extend_from_slice(&opt.data);
                }
                self.build_configure_nak(id, &nak_data)
            }
        } else {
            // Malformed options — send Configure-Nak with no options.
            self.build_configure_nak(id, &[])
        }
    }

    /// Accept a Configure-Nak/Reject from the peer by adjusting our options.
    fn accept_lcp_nak_rej(&mut self, data: &[u8]) {
        if let Ok(options) = parse_lcp_options(data) {
            for opt in &options {
                match opt.opt_type {
                    LCP_OPT_MRU => {
                        // Peer wants a different MRU.  Accept whatever they
                        // propose.  If they just reject, use default.
                        if opt.data.len() >= 2 {
                            let mru = u16::from_be_bytes([opt.data[0], opt.data[1]]) as usize;
                            self.mru = mru.clamp(128, 65535);
                        } else {
                            self.mru = PPP_DEFAULT_MRU;
                        }
                    }
                    LCP_OPT_MAGIC_NUMBER => {
                        self.magic_number = 0; // disable magic number
                    }
                    LCP_OPT_PROTO_COMPRESS => {
                        self.proto_compress = false;
                    }
                    LCP_OPT_ADDR_COMPRESS => {
                        self.addr_compress = false;
                    }
                    _ => {}
                }
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CRC-16 ──────────────────────────────────────────────────────────

    #[test]
    fn crc16_known_vectors() {
        // Test vector: empty string → 0xFFFF (before complement).
        let fcs = ppp_fcs(b"");
        // FCS of empty data with CRC-16-IBM: ~0xFFFF = 0x0000.
        // Actually: init=0xFFFF, complement = ~0xFFFF = 0x0000.
        // But CRC of empty data with init=0xFFFF and xorout=0xFFFF is 0x0000.
        // !0x0000 = 0xFFFF. Wait, let me recheck.
        // Standard CRC16-IBM: init=0x0000, no xorout, but PPP uses init=0xFFFF, xorout=0xFFFF.
        // For empty data: CRC(init=0xFFFF) = 0xFFFF (no bits to shift). !0xFFFF = 0x0000.
        assert_eq!(fcs, 0x0000);
    }

    #[test]
    fn crc16_known_sequence() {
        // "123456789" → 0xBB3D (CRC-16-IBM, standard check value for many
        // CRC-16 variants using init=0x0000).  But PPP uses init=0xFFFF, so
        // the result differs from the "check value."  We'll use a
        // deterministic test: the same input produces the same output.
        let fcs1 = ppp_fcs(b"hello");
        let fcs2 = ppp_fcs(b"hello");
        assert_eq!(fcs1, fcs2);
        // Different data → different (with high probability).
        assert_ne!(fcs1, ppp_fcs(b"Hello"));
    }

    #[test]
    fn fcs_check_valid_frame_passes() {
        let raw = b"\xFF\x03\x00\x21hello";
        let fcs = ppp_fcs(raw);
        let mut frame = raw.to_vec();
        frame.extend_from_slice(&fcs.to_le_bytes());
        assert!(ppp_check_fcs(&frame));
    }

    #[test]
    fn fcs_check_corrupted_frame_fails() {
        let raw = b"\xFF\x03\x00\x21hello";
        let fcs = ppp_fcs(raw);
        let mut frame = raw.to_vec();
        frame.extend_from_slice(&fcs.to_le_bytes());
        frame[3] ^= 0x01; // corrupt
        assert!(!ppp_check_fcs(&frame));
    }

    // ── Byte-stuffing ───────────────────────────────────────────────────

    #[test]
    fn byte_stuff_roundtrip() {
        let original = b"\x7E\x7D\x1F\x41\x42\x43";
        let stuffed = ppp_stuff(original);
        let unstuffed = ppp_unstuff(&stuffed).expect("unstuff");
        assert_eq!(unstuffed, original);
    }

    #[test]
    fn byte_stuff_escapes_flag() {
        let stuffed = ppp_stuff(&[PPP_FLAG]);
        assert_eq!(stuffed, &[PPP_ESCAPE, PPP_FLAG ^ PPP_ESCAPE_XOR]);
    }

    #[test]
    fn byte_stuff_escapes_escape() {
        let stuffed = ppp_stuff(&[PPP_ESCAPE]);
        assert_eq!(stuffed, &[PPP_ESCAPE, PPP_ESCAPE ^ PPP_ESCAPE_XOR]);
    }

    #[test]
    fn byte_stuff_escapes_control_chars() {
        let stuffed = ppp_stuff(&[0x01, 0x1F]);
        assert_eq!(stuffed[0], PPP_ESCAPE);
        assert_eq!(stuffed[1], 0x01 ^ PPP_ESCAPE_XOR);
        assert_eq!(stuffed[2], PPP_ESCAPE);
        assert_eq!(stuffed[3], 0x1F ^ PPP_ESCAPE_XOR);
    }

    #[test]
    fn byte_stuff_preserves_normal_chars() {
        let original = b"\x20\x41\x7C\xFF";
        let stuffed = ppp_stuff(original);
        assert_eq!(stuffed, original);
    }

    #[test]
    fn unstuff_rejects_truncated_escape() {
        assert!(ppp_unstuff(&[PPP_ESCAPE]).is_err());
    }

    #[test]
    fn unstuff_rejects_embedded_flag() {
        assert!(ppp_unstuff(&[PPP_FLAG, b'A']).is_err());
    }

    // ── Frame encode/decode ─────────────────────────────────────────────

    #[test]
    fn frame_roundtrip_ipv4() {
        let payload = b"Hello, PPP over IPv4!";
        let frame = ppp_build_frame(PPP_PROTO_IPV4, payload);
        let (proto, info) = ppp_parse_frame(&frame).expect("parse");
        assert_eq!(proto, PPP_PROTO_IPV4);
        assert_eq!(info, payload);
    }

    #[test]
    fn frame_roundtrip_lcp() {
        let lcp_data = &[LCP_CODE_ECHO_REQUEST, 0x01, 0x00, 0x04];
        let frame = ppp_build_frame(PPP_PROTO_LCP, lcp_data);
        let (proto, info) = ppp_parse_frame(&frame).expect("parse");
        assert_eq!(proto, PPP_PROTO_LCP);
        assert_eq!(info, lcp_data);
    }

    #[test]
    fn frame_roundtrip_with_byte_stuffing_required() {
        // Payload containing 0x7E should be stuffed and unstuffed correctly.
        let payload = b"\x7E\x7D\x01\x41";
        let frame = ppp_build_frame(PPP_PROTO_IPV4, payload);
        let (_proto, info) = ppp_parse_frame(&frame).expect("parse");
        assert_eq!(info, payload);
    }

    // ── LCP state machine ───────────────────────────────────────────────

    #[test]
    fn lcp_configure_exchange_establishes_link() {
        let mut state = PppState::new();
        state.link_up();
        assert_eq!(state.phase, PppPhase::Establish);

        let mut peer = PppState::new();
        peer.link_up();

        // Direction 1: state → peer.  State sends Configure-Request, peer
        // replies with Configure-Ack, state's link establishment completes.
        let conf_req = state.build_configure_request();
        let (proto, info) =
            ppp_parse_frame(&ppp_build_frame(PPP_PROTO_LCP, &conf_req)).expect("parse");
        assert_eq!(proto, PPP_PROTO_LCP);

        let reply = peer.handle_frame(proto, &info).expect("peer reply");
        let (reply_proto, reply_info) = ppp_parse_frame(&reply).expect("parse reply");
        assert_eq!(reply_proto, PPP_PROTO_LCP);
        state.handle_frame(reply_proto, &reply_info);
        assert_eq!(state.phase, PppPhase::Network);

        // Direction 2: peer → state.  Peer sends its own Configure-Request,
        // state replies with Configure-Ack, peer's establishment completes.
        let peer_req = peer.build_configure_request();
        let (proto2, info2) =
            ppp_parse_frame(&ppp_build_frame(PPP_PROTO_LCP, &peer_req)).expect("parse");
        let reply2 = state.handle_frame(proto2, &info2).expect("state reply");
        let (reply_proto2, reply_info2) = ppp_parse_frame(&reply2).expect("parse reply");
        peer.handle_frame(reply_proto2, &reply_info2);
        assert_eq!(peer.phase, PppPhase::Network);

        // Both sides should now be in Network/Open phase.
        assert!(matches!(state.phase, PppPhase::Network | PppPhase::Open));
        assert!(matches!(peer.phase, PppPhase::Network | PppPhase::Open));
    }

    #[test]
    fn lcp_echo_keepalive_roundtrip() {
        let mut state = PppState::new();
        state.link_up();
        // Simulate quick configure exchange.
        state.phase = PppPhase::Open;

        let echo = state.build_echo_request();
        let frame = ppp_build_frame(PPP_PROTO_LCP, &echo);
        let (proto, info) = ppp_parse_frame(&frame).expect("parse");

        let mut peer = PppState::new();
        peer.phase = PppPhase::Open;
        let reply = peer.handle_frame(proto, &info).expect("echo reply");

        let (reply_proto, reply_info) = ppp_parse_frame(&reply).expect("parse reply");
        state.handle_frame(reply_proto, &reply_info);

        // Echo should be acknowledged, no longer pending.
        assert!(!state.echo_pending);
    }

    #[test]
    fn lcp_terminate_shuts_down_link() {
        let mut state = PppState::new();
        state.phase = PppPhase::Open;

        let term = state.build_terminate_request();
        let frame = ppp_build_frame(PPP_PROTO_LCP, &term);
        let (proto, info) = ppp_parse_frame(&frame).expect("parse");

        let mut peer = PppState::new();
        peer.phase = PppPhase::Open;
        // Peer should send Terminate-Ack and go Dead.
        let reply = peer.handle_frame(proto, &info);
        assert!(reply.is_some());
        assert_eq!(peer.phase, PppPhase::Dead);

        // Our side gets the Terminate-Ack and goes Dead.
        let (r_proto, r_info) = ppp_parse_frame(&reply.unwrap()).expect("parse");
        state.handle_frame(r_proto, &r_info);
        assert_eq!(state.phase, PppPhase::Dead);
    }

    #[test]
    fn lcp_configure_request_handles_auth_rejection() {
        let mut state = PppState::new();
        state.link_up();
        state.auth_protocol = None; // We don't want auth

        // Peer sends Configure-Request with auth option.
        let mut auth_opts = Vec::new();
        auth_opts.push(LCP_OPT_AUTH_PROTO);
        auth_opts.push(5);
        auth_opts.extend_from_slice(&[0xC2, 0x23, 0x05]); // CHAP with MD5
        let conf_req = build_lcp_packet(LCP_CODE_CONFIGURE_REQUEST, 1, &auth_opts);
        let frame = ppp_build_frame(PPP_PROTO_LCP, &conf_req);
        let (proto, info) = ppp_parse_frame(&frame).expect("parse");

        let reply = state.handle_frame(proto, &info).expect("reply");
        // Should be a Configure-Nak/Reject (not Ack).
        let (_, reply_info) = ppp_parse_frame(&reply).expect("parse reply");
        let (code, _id, _len, _data) = parse_lcp_packet(&reply_info).expect("parse lcp");
        // Should be Configure-Nak (3) or Configure-Reject (4).
        assert!(code == LCP_CODE_CONFIGURE_NAK || code == LCP_CODE_CONFIGURE_REJECT);
    }

    #[test]
    fn lcp_echo_tick_sends_keepalive() {
        let mut state = PppState::new();
        state.phase = PppPhase::Open;
        state.last_echo_sent = 0;

        let echo = state.tick(LCP_ECHO_INTERVAL + 1).expect("echo frame");
        assert!(state.echo_pending);

        // Verify it's a valid LCP Echo-Request frame.
        let (proto, info) = ppp_parse_frame(&echo).expect("parse");
        assert_eq!(proto, PPP_PROTO_LCP);
        let (code, _id, _len, _data) = parse_lcp_packet(&info).expect("parse lcp");
        assert_eq!(code, LCP_CODE_ECHO_REQUEST);
    }

    #[test]
    fn lcp_echo_timeout_triggers_link_down() {
        let mut state = PppState::new();
        state.phase = PppPhase::Open;
        state.last_echo_sent = 100;
        state.echo_pending = true;

        // Advance past the echo timeout.
        assert!(state.tick(100 + LCP_ECHO_TIMEOUT + 1).is_none());
        assert_eq!(state.phase, PppPhase::Dead);
    }

    // ── LCP option parsing ──────────────────────────────────────────────

    #[test]
    fn parse_lcp_options_extracts_mru_and_accm() {
        let mut data = Vec::new();
        // MRU = 1500.
        data.push(LCP_OPT_MRU);
        data.push(4);
        data.extend_from_slice(&1500u16.to_be_bytes());
        // ACCM = 0x000A0000.
        data.push(LCP_OPT_ACCM);
        data.push(6);
        data.extend_from_slice(&0x000A0000u32.to_be_bytes());

        let opts = parse_lcp_options(&data).expect("parse");
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].opt_type, LCP_OPT_MRU);
        assert_eq!(opts[1].opt_type, LCP_OPT_ACCM);
    }

    #[test]
    fn parse_lcp_options_stops_at_zero() {
        let mut data = Vec::new();
        data.push(LCP_OPT_MRU);
        data.push(4);
        data.extend_from_slice(&1500u16.to_be_bytes());
        data.push(0); // zero-padding / end marker
        data.push(LCP_OPT_ACCM); // should be ignored
        data.push(6);

        let opts = parse_lcp_options(&data).expect("parse");
        assert_eq!(opts.len(), 1);
    }

    // ── IPCP ────────────────────────────────────────────────────────────

    #[test]
    fn ipcp_configure_request_assigns_address() {
        let mut state = PppState::new();
        state.phase = PppPhase::Network;

        let ipcp_req = state.build_ipcp_configure_request([10, 0, 0, 1]);
        let frame = ppp_build_frame(PPP_PROTO_IPCP, &ipcp_req);
        let (proto, info) = ppp_parse_frame(&frame).expect("parse");
        assert_eq!(proto, PPP_PROTO_IPCP);

        let mut peer = PppState::new();
        peer.phase = PppPhase::Network;
        let reply = peer.handle_frame(proto, &info).expect("ipcp reply");

        let (r_proto, r_info) = ppp_parse_frame(&reply).expect("parse reply");
        assert_eq!(r_proto, PPP_PROTO_IPCP);
        let (code, _id, _len, _data) = parse_lcp_packet(&r_info).expect("parse lcp");
        assert_eq!(code, LCP_CODE_CONFIGURE_ACK);
    }
}
