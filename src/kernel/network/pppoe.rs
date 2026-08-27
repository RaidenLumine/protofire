//! src/kernel/network/pppoe.rs
//!
//! PPPoE (RFC 2516) session layer — a consumer for the PPP integration.
//!
//! PPPoE rides inside Ethernet frames tagged with EtherType `0x8863`
//! (Discovery) or `0x8864` (Session).  Discovery establishes a session via
//! the PADI → PADO → PADR → PADS handshake; once PADS assigns a non-zero
//! session-id, PPP frames flow inside session packets.
//!
//! The PPP frame carried in a PPPoE session payload contains only the
//! Protocol field and the Information field — no HDLC Flag / Address /
//! Control / FCS octets (RFC 2516 §2.1) — so this module pairs with the
//! [`crate::kernel::network::ppp`] `ppp_pppoe_build_payload` /
//! `ppp_pppoe_parse_payload` helpers rather than the HDLC framer.

use alloc::vec::Vec;

use crate::kernel::network::link::ethernet::build_frame;
use crate::kernel::network::link::ethernet::EtherType;
use crate::kernel::network::link::ethernet::EthernetFrame;
use crate::kernel::network::link::ethernet::MacAddress;
use crate::kernel::network::stack::NetworkStack;
use crate::Error;
use crate::Result;

/// EtherType for PPPoE discovery packets.
pub const ETHERTYPE_PPPOE_DISCOVERY: u16 = 0x8863;
/// EtherType for PPPoE session packets.
pub const ETHERTYPE_PPPOE_SESSION: u16 = 0x8864;

/// PPPoE header size: Ver/Type (1) + Code (1) + Session-Id (2) + Length (2).
pub const PPPOE_HEADER_SIZE: usize = 6;

/// Session packet carrying a PPP frame.
pub const PPPOE_CODE_SESSION: u8 = 0x00;
/// PADI — host to AC, broadcast (discovery initiation).
pub const PPPOE_CODE_PADI: u8 = 0x09;
/// PADO — AC to host, unicast (offer of service).
pub const PPPOE_CODE_PADO: u8 = 0x07;
/// PADR — host to AC, unicast (accept the offer).
pub const PPPOE_CODE_PADR: u8 = 0x19;
/// PADS — AC to host (session established, carries the session-id).
pub const PPPOE_CODE_PADS: u8 = 0x65;
/// PADT — either side, tear the session down.
pub const PPPOE_CODE_PADT: u8 = 0xA7;

/// Service-Name tag (PADI / PADR).
pub const TAG_SERVICE_NAME: u16 = 0x0101;
/// AC-Name tag (PADO).
pub const TAG_AC_NAME: u16 = 0x0102;
/// Host-Uniq tag (optional discriminator).
pub const TAG_HOST_UNIQ: u16 = 0x0103;
/// AC-Cookie tag (PADO), echoed in PADR to prove liveness.
pub const TAG_AC_COOKIE: u16 = 0x0104;

/// Maximum PADI retransmissions before discovery is abandoned.
pub const PADI_RETRY_MAX: u32 = 5;
/// Retransmit PADI every N scheduler ticks (1 second at 100 Hz).
pub const PADI_RETRY_TICKS: u64 = 100;

/// PPPoE session phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PppoePhase {
    /// No session; idle.
    Idle,
    /// Discovery in progress (PADI sent, awaiting PADO / PADS).
    Discovery,
    /// PPP session established; PPP frames flow with this session-id.
    Session,
}

/// A single PPPoE tag (TLV-encoded, RFC 2516 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppoeTag {
    pub tag_type: u16,
    pub value: Vec<u8>,
}

/// PPPoE session state machine.
pub struct PppoeSession {
    /// Current session phase.
    pub phase: PppoePhase,
    /// Session-id assigned by the AC in PADS.  0 during discovery.
    pub session_id: u16,
    /// Peer (Access Concentrator) MAC, learned from PADO.
    pub peer_mac: Option<MacAddress>,
    /// Service name requested in PADI / PADR (empty = any service).
    pub service_name: Vec<u8>,
    /// AC-Cookie from PADO, echoed in PADR.
    ac_cookie: Option<Vec<u8>>,
    /// Number of PADIs sent.
    padi_retries: u32,
    /// Tick at which the most recent discovery packet was sent.
    last_discovery_sent: u64,
}

impl PppoeSession {
    /// Create a session in the Idle phase.
    pub fn new() -> Self {
        Self {
            phase: PppoePhase::Idle,
            session_id: 0,
            peer_mac: None,
            service_name: Vec::new(),
            ac_cookie: None,
            padi_retries: 0,
            last_discovery_sent: 0,
        }
    }

    /// Whether a PPP session is established and ready for PPP frames.
    pub fn in_session(&self) -> bool {
        self.phase == PppoePhase::Session
    }

    /// Begin discovery: build a PADI addressed to the broadcast MAC with a
    /// Service-Name tag.  Returns the raw Ethernet frame to transmit.
    pub fn start_discovery(&mut self, local_mac: [u8; 6], tick: u64) -> Result<Vec<u8>> {
        self.phase = PppoePhase::Discovery;
        self.session_id = 0;
        self.peer_mac = None;
        self.padi_retries += 1;
        self.last_discovery_sent = tick;
        let payload = build_tag(TAG_SERVICE_NAME, &self.service_name);
        pppoe_eth_frame(
            MacAddress::BROADCAST,
            MacAddress(local_mac),
            EtherType::PppoeDiscovery,
            PPPOE_CODE_PADI,
            0,
            &payload,
        )
    }

    /// Handle a PADO from the AC.  Stores the AC MAC (and any AC-Cookie),
    /// then builds a PADR echoing the Service-Name and cookie.  Returns the
    /// raw Ethernet frame to transmit, or `None` if not in discovery.
    pub fn handle_pado(
        &mut self,
        ac_mac: MacAddress,
        local_mac: [u8; 6],
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        if self.phase != PppoePhase::Discovery {
            return None;
        }
        self.peer_mac = Some(ac_mac);
        for tag in parse_tags(payload) {
            if tag.tag_type == TAG_AC_COOKIE {
                self.ac_cookie = Some(tag.value);
            }
        }
        let mut payload = build_tag(TAG_SERVICE_NAME, &self.service_name);
        if let Some(cookie) = &self.ac_cookie {
            payload.extend_from_slice(&build_tag(TAG_AC_COOKIE, cookie));
        }
        pppoe_eth_frame(
            ac_mac,
            MacAddress(local_mac),
            EtherType::PppoeDiscovery,
            PPPOE_CODE_PADR,
            0,
            &payload,
        )
        .ok()
    }

    /// Handle a PADS: the session is established with the given session-id.
    /// Returns `true` when the session transitioned to `Session`.
    pub fn handle_pads(&mut self, session_id: u16) -> bool {
        if self.phase != PppoePhase::Discovery || session_id == 0 {
            return false;
        }
        self.session_id = session_id;
        self.phase = PppoePhase::Session;
        true
    }

    /// Handle a PADT: tear the session down and return to Idle.
    pub fn handle_padt(&mut self) {
        self.phase = PppoePhase::Idle;
        self.session_id = 0;
        self.peer_mac = None;
        self.ac_cookie = None;
    }

    /// Periodic maintenance.  While in Discovery, retransmits PADI every
    /// [`PADI_RETRY_TICKS`]; gives up (back to Idle) after
    /// [`PADI_RETRY_MAX`] attempts.  Returns a frame to transmit, or `None`.
    pub fn tick(&mut self, local_mac: [u8; 6], tick: u64) -> Option<Vec<u8>> {
        if self.phase != PppoePhase::Discovery {
            return None;
        }
        let elapsed = tick.wrapping_sub(self.last_discovery_sent);
        if elapsed < PADI_RETRY_TICKS {
            return None;
        }
        if self.padi_retries >= PADI_RETRY_MAX {
            self.phase = PppoePhase::Idle;
            return None;
        }
        self.start_discovery(local_mac, tick).ok()
    }

    /// Wrap a PPPoE session payload (a `ppp::ppp_pppoe_build_payload`
    /// result) in the PPPoE session header and Ethernet header.
    ///
    /// Fails with [`Error::Unsupported`] when no session is established.
    pub fn build_session_frame(&self, local_mac: [u8; 6], ppp_payload: &[u8]) -> Result<Vec<u8>> {
        if self.phase != PppoePhase::Session {
            return Err(Error::Unsupported);
        }
        let peer = self.peer_mac.ok_or(Error::Unsupported)?;
        pppoe_eth_frame(
            peer,
            MacAddress(local_mac),
            EtherType::PppoeSession,
            PPPOE_CODE_SESSION,
            self.session_id,
            ppp_payload,
        )
    }
}

impl Default for PppoeSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── Wire helpers ────────────────────────────────────────────────────────────

/// Wrap a PPPoE packet (code + session-id + payload) in an Ethernet frame.
fn pppoe_eth_frame(
    dst: MacAddress,
    src: MacAddress,
    ethertype: EtherType,
    code: u8,
    session_id: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut pppoe = Vec::with_capacity(PPPOE_HEADER_SIZE + payload.len());
    pppoe.push(0x11); // ver = 1, type = 1
    pppoe.push(code);
    pppoe.extend_from_slice(&session_id.to_be_bytes());
    let len = payload.len();
    pppoe.push((len >> 8) as u8);
    pppoe.push((len & 0xFF) as u8);
    pppoe.extend_from_slice(payload);
    build_frame(&EthernetFrame::new(dst, src, ethertype, pppoe))
}

/// Parse a PPPoE packet header.  Returns `(code, session_id, length,
/// payload)` where `length` is the declared PPPoE payload length and
/// `payload` is the exact-length slice after the 6-byte header.
///
/// Rejects packets whose Ver/Type is not `0x11` or whose declared length
/// exceeds the received bytes.
pub fn pppoe_parse_header(data: &[u8]) -> Result<(u8, u16, u16, &[u8])> {
    if data.len() < PPPOE_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    if data[0] != 0x11 {
        return Err(Error::InvalidArgument);
    }
    let code = data[1];
    let session_id = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]) as usize;
    if data.len() < PPPOE_HEADER_SIZE + length {
        return Err(Error::InvalidArgument);
    }
    Ok((
        code,
        session_id,
        length as u16,
        &data[PPPOE_HEADER_SIZE..PPPOE_HEADER_SIZE + length],
    ))
}

/// Build a PPPoE tag: Tag-Type (2) + Tag-Length (2) + Tag-Value.
pub fn build_tag(tag_type: u16, value: &[u8]) -> Vec<u8> {
    let mut tag = Vec::with_capacity(4 + value.len());
    tag.extend_from_slice(&tag_type.to_be_bytes());
    tag.extend_from_slice(&(value.len() as u16).to_be_bytes());
    tag.extend_from_slice(value);
    tag
}

/// Parse a PPPoE tag list.  Malformed trailing bytes are ignored.
pub fn parse_tags(data: &[u8]) -> Vec<PppoeTag> {
    let mut tags = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let tag_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let tag_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if pos + 4 + tag_len > data.len() {
            break;
        }
        tags.push(PppoeTag {
            tag_type,
            value: data[pos + 4..pos + 4 + tag_len].to_vec(),
        });
        pos += 4 + tag_len;
    }
    tags
}

// ── NetworkStack integration ────────────────────────────────────────────────

impl NetworkStack {
    /// Handle an incoming PPPoE Ethernet frame (Discovery or Session).
    ///
    /// Called from `poll()` after EtherType demux.  Discovery frames drive
    /// the PADI → PADO → PADR → PADS session establishment; session frames
    /// are unwrapped and fed into the PPP protocol stack.
    pub(crate) fn handle_pppoe_frame(&self, frame: &EthernetFrame) -> Result<()> {
        if !self.pppoe_enabled() {
            return Ok(());
        }
        let (code, session_id, _length, payload) = match pppoe_parse_header(&frame.payload) {
            Ok(header) => header,
            Err(_) => return Ok(()), // malformed PPPoE header — drop
        };
        let local_mac = self.local_mac;
        match code {
            PPPOE_CODE_PADO => {
                let reply = {
                    let mut session = self.pppoe().lock();
                    session.handle_pado(frame.source, local_mac, payload)
                };
                if let Some(padr) = reply {
                    let _ = self.device().send(&padr);
                }
            }
            PPPOE_CODE_PADS => {
                let established = {
                    let mut session = self.pppoe().lock();
                    session.handle_pads(session_id)
                };
                if established {
                    // Session up: begin PPP LCP negotiation over the session.
                    let _ = self.ppp_negotiate_link();
                }
            }
            PPPOE_CODE_PADT => {
                let mut session = self.pppoe().lock();
                session.handle_padt();
            }
            PPPOE_CODE_SESSION => {
                let is_ours = {
                    let session = self.pppoe().lock();
                    session.in_session() && session.session_id == session_id
                };
                if is_ours {
                    // The PPPoE payload is a PPP frame without HDLC framing
                    // (RFC 2516 §2.1): protocol + information only.
                    if let Ok((proto, info)) =
                        crate::kernel::network::ppp::ppp_pppoe_parse_payload(payload)
                    {
                        let _ = self.dispatch_ppp_protocol(proto, info);
                    }
                }
            }
            _ => {
                // Unknown discovery codes are ignored.
            }
        }
        Ok(())
    }

    /// Wrap a PPPoE session payload (a `ppp::ppp_pppoe_build_payload`
    /// result) in the PPPoE session header + Ethernet header and transmit it
    /// via the attached device.
    pub(crate) fn send_pppoe_session_frame(&self, ppp_payload: Vec<u8>) -> Result<()> {
        let local_mac = self.local_mac;
        let raw = {
            let session = self.pppoe().lock();
            session.build_session_frame(local_mac, &ppp_payload)?
        };
        self.device().send(&raw)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use crate::kernel::network::link::ethernet::parse_frame;
    use crate::kernel::network::stack::NetworkStack;

    /// Install a fresh global stack over a fresh mock device.
    fn make_stack() -> (Arc<MockNetworkDevice>, &'static NetworkStack) {
        unsafe {
            NetworkStack::uninstall_global();
        }
        let dev = Arc::new(MockNetworkDevice::new(
            "pppoe-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(dev.clone(), [10, 0, 2, 15]);
        let stack = NetworkStack::global().expect("stack should be installed");
        (dev, stack)
    }

    // ── Frame glue ────────────────────────────────────────────────────

    #[test]
    fn pppoe_header_roundtrip_with_session_id() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let raw = pppoe_eth_frame(
            MacAddress([0x02; 6]),
            MacAddress([0x03; 6]),
            EtherType::PppoeSession,
            PPPOE_CODE_SESSION,
            0x1234,
            &payload,
        )
        .expect("build");

        let eth = parse_frame(&raw).expect("eth parse");
        assert_eq!(eth.ethertype, EtherType::PppoeSession);
        let (code, session_id, len, parsed_payload) =
            pppoe_parse_header(&eth.payload).expect("pppoe parse");
        assert_eq!(code, PPPOE_CODE_SESSION);
        assert_eq!(session_id, 0x1234);
        assert_eq!(len as usize, payload.len());
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn pppoe_parse_rejects_bad_ver_type() {
        // ver/type byte must be 0x11.
        let data = [0x10, PPPOE_CODE_PADI, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(pppoe_parse_header(&data), Err(Error::InvalidArgument));
    }

    #[test]
    fn pppoe_parse_rejects_declared_length_overflow() {
        // Header claims 0xFFFF bytes of payload but the buffer is only 6.
        let data = [0x11, PPPOE_CODE_PADI, 0x00, 0x00, 0xFF, 0xFF];
        assert_eq!(pppoe_parse_header(&data), Err(Error::InvalidArgument));
    }

    #[test]
    fn tags_build_and_parse_roundtrip() {
        let mut payload = build_tag(TAG_SERVICE_NAME, b"");
        payload.extend_from_slice(&build_tag(TAG_AC_NAME, b"AC0"));
        payload.extend_from_slice(&build_tag(TAG_AC_COOKIE, &[0xaa; 8]));

        let tags = parse_tags(&payload);
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].tag_type, TAG_SERVICE_NAME);
        assert!(tags[0].value.is_empty());
        assert_eq!(tags[1].tag_type, TAG_AC_NAME);
        assert_eq!(tags[1].value, b"AC0");
        assert_eq!(tags[2].tag_type, TAG_AC_COOKIE);
        assert_eq!(tags[2].value.len(), 8);
        assert!(tags[2].value.iter().all(|&b| b == 0xaa));
    }

    #[test]
    fn tags_ignore_truncated_tail() {
        let mut payload = build_tag(TAG_SERVICE_NAME, b"x");
        payload.extend_from_slice(&[0x01, 0x02, 0x00]); // truncated tag
        let tags = parse_tags(&payload);
        assert_eq!(tags.len(), 1);
    }

    // ── State machine ─────────────────────────────────────────────────

    #[test]
    fn discovery_flow_assigns_session() {
        let mut session = PppoeSession::new();
        assert!(!session.in_session());

        // PADI → broadcast, session-id 0.
        let padi = session
            .start_discovery([0x02; 6], 0)
            .expect("start discovery");
        assert_eq!(session.phase, PppoePhase::Discovery);
        let eth = parse_frame(&padi).expect("eth");
        assert_eq!(eth.ethertype, EtherType::PppoeDiscovery);
        assert_eq!(eth.destination, MacAddress::BROADCAST);
        let (code, sid, _len, _payload) = pppoe_parse_header(&eth.payload).expect("pppoe");
        assert_eq!(code, PPPOE_CODE_PADI);
        assert_eq!(sid, 0);

        // PADO → PADR, now addressed to the AC.
        let ac_mac = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let padr = session
            .handle_pado(ac_mac, [0x02; 6], &build_tag(TAG_AC_NAME, b"AC0"))
            .expect("handle pado");
        let eth = parse_frame(&padr).expect("eth");
        assert_eq!(eth.ethertype, EtherType::PppoeDiscovery);
        assert_eq!(eth.destination, ac_mac);
        let (code, sid, _len, _payload) = pppoe_parse_header(&eth.payload).expect("pppoe");
        assert_eq!(code, PPPOE_CODE_PADR);
        assert_eq!(sid, 0);

        // PADS assigns a session-id → Session.
        assert!(session.handle_pads(0x5678));
        assert!(session.in_session());
        assert_eq!(session.session_id, 0x5678);
        assert_eq!(session.peer_mac, Some(ac_mac));
    }

    #[test]
    fn pads_rejects_zero_session_id() {
        let mut session = PppoeSession::new();
        session
            .start_discovery([0x02; 6], 0)
            .expect("start discovery");
        assert!(!session.handle_pads(0));
        assert!(!session.in_session());
    }

    #[test]
    fn padt_tears_down_session() {
        let mut session = PppoeSession::new();
        session
            .start_discovery([0x02; 6], 0)
            .expect("start discovery");
        assert!(session.handle_pads(0x1234));
        assert!(session.in_session());

        session.handle_padt();
        assert!(!session.in_session());
        assert_eq!(session.session_id, 0);
        assert_eq!(session.phase, PppoePhase::Idle);
    }

    #[test]
    fn tick_retransmits_padi_and_gives_up() {
        let mut session = PppoeSession::new();
        session
            .start_discovery([0x02; 6], 100)
            .expect("start discovery");

        // Before the retransmit window: no frame.
        assert!(session
            .tick([0x02; 6], 100 + PADI_RETRY_TICKS - 1)
            .is_none());
        // At the window: a retransmitted PADI.
        assert!(session.tick([0x02; 6], 100 + PADI_RETRY_TICKS).is_some());
        // Give up after exhausting retries.
        let mut exhausted = PppoeSession::new();
        exhausted.phase = PppoePhase::Discovery;
        exhausted.padi_retries = PADI_RETRY_MAX;
        exhausted.last_discovery_sent = 0;
        assert!(exhausted.tick([0x02; 6], PADI_RETRY_TICKS).is_none());
        assert_eq!(exhausted.phase, PppoePhase::Idle);
    }

    #[test]
    fn build_session_frame_rejects_without_session() {
        let session = PppoeSession::new();
        assert_eq!(
            session.build_session_frame([0x02; 6], &[0x00, 0x21]),
            Err(Error::Unsupported)
        );
    }

    // ── End-to-end over the mock device ───────────────────────────────

    #[test]
    fn mock_device_padi_to_pads_session_flow() {
        let (mock, stack) = make_stack();
        stack.set_pppoe_enabled(true);

        // The first maintenance tick auto-starts discovery → PADI on the
        // wire.  The tick also drives other maintenance (e.g. mDNS), so
        // locate the broadcast PPPoE discovery frame among the drain.
        stack.advance_tick();
        let tx = mock.drain_tx();
        let padi_raw = tx
            .iter()
            .find(|raw| {
                parse_frame(raw)
                    .map(|eth| eth.ethertype == EtherType::PppoeDiscovery)
                    .unwrap_or(false)
            })
            .expect("a PADI on the first maintenance tick");
        let padi = parse_frame(padi_raw).expect("padi eth frame");
        assert_eq!(padi.ethertype, EtherType::PppoeDiscovery);
        assert_eq!(padi.destination, MacAddress::BROADCAST);
        let (code, sid, _len, payload) = pppoe_parse_header(&padi.payload).expect("pppoe hdr");
        assert_eq!(code, PPPOE_CODE_PADI);
        assert_eq!(sid, 0);
        assert!(parse_tags(payload)
            .iter()
            .any(|t| t.tag_type == TAG_SERVICE_NAME));

        // The AC answers with a PADO, unicast to us.
        let ac_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let pado = pppoe_eth_frame(
            MacAddress(stack.local_mac),
            MacAddress(ac_mac),
            EtherType::PppoeDiscovery,
            PPPOE_CODE_PADO,
            0,
            &build_tag(TAG_AC_NAME, b"AC0"),
        )
        .expect("build pado");
        mock.inject_rx(pado);
        assert!(stack.poll().expect("poll pado"));

        // We reply with PADR, unicast to the AC.
        let tx = mock.drain_tx();
        assert_eq!(tx.len(), 1, "expected a PADR after PADO");
        let padr = parse_frame(&tx[0]).expect("padr eth frame");
        assert_eq!(padr.ethertype, EtherType::PppoeDiscovery);
        assert_eq!(padr.destination, MacAddress(ac_mac));
        let (code, sid, _len, _payload) = pppoe_parse_header(&padr.payload).expect("pppoe hdr");
        assert_eq!(code, PPPOE_CODE_PADR);
        assert_eq!(sid, 0);

        // The AC assigns a session-id with PADS → session established, and
        // the kernel kicks off PPP LCP negotiation over the session.
        let session_id = 0x1234u16;
        let pads = pppoe_eth_frame(
            MacAddress(stack.local_mac),
            MacAddress(ac_mac),
            EtherType::PppoeSession,
            PPPOE_CODE_PADS,
            session_id,
            &[],
        )
        .expect("build pads");
        mock.inject_rx(pads);
        assert!(stack.poll().expect("poll pads"));

        let tx = mock.drain_tx();
        assert_eq!(tx.len(), 1, "expected an LCP Configure-Request");
        let session_frame = parse_frame(&tx[0]).expect("session eth frame");
        assert_eq!(session_frame.ethertype, EtherType::PppoeSession);
        assert_eq!(session_frame.destination, MacAddress(ac_mac));
        let (code, sid, _len, payload) =
            pppoe_parse_header(&session_frame.payload).expect("pppoe hdr");
        assert_eq!(code, PPPOE_CODE_SESSION);
        assert_eq!(sid, session_id);
        // The PPPoE payload is the LCP Configure-Request (protocol 0xC021).
        let (proto, info) =
            crate::kernel::network::ppp::ppp_pppoe_parse_payload(payload).expect("ppp payload");
        assert_eq!(proto, crate::kernel::network::ppp::PPP_PROTO_LCP);
        assert_eq!(info[0], 1); // LCP Configure-Request code
    }
}
