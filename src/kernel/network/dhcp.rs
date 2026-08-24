//! src/kernel/network/dhcp.rs
//!
//! DHCP (RFC 2131) client: boot-time address discovery and lease renewal.
//!
//! Discovery binds UDP/68, broadcasts a `DHCPDISCOVER` to `255.255.255.255:67`,
//! then completes the DISCOVER → OFFER → REQUEST → ACK handshake and returns
//! the negotiated lease.  Renewal (`try_renew_lease`) sends a unicast
//! `DHCPREQUEST` to the current server.

use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::stack::NetworkStack;
use crate::kernel::network::udp;
use crate::{Error, Result};

/// Ticks per second (the stack tick is 100 Hz).
pub const TICKS_PER_SECOND: u64 = 100;

/// A DHCP lease obtained from a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpLease {
    /// The client's assigned IPv4 address.
    pub yiaddr: Ipv4Addr,
    /// Optional DNS server address (option 6).
    pub dns_server: Option<Ipv4Addr>,
    /// Optional default gateway (option 3).
    pub router: Option<Ipv4Addr>,
    /// Optional subnet mask (option 1).
    pub subnet_mask: Option<Ipv4Addr>,
    /// Lease lifetime in ticks.
    pub lease_ticks: u64,
    /// Time before renewal (T1) in ticks.
    pub renewal_ticks: u64,
    /// Time before rebinding (T2) in ticks.
    pub rebinding_ticks: u64,
}

/// DHCP lease renewal state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Lease acquired and valid.
    Bound,
    /// In T1…T2 — attempt renewal with the current server.
    Renewing,
    /// Past T2 — attempt rebinding with any server.
    Rebinding,
    /// Lease has elapsed; the client must re-discover.
    Expired,
}

// ── Protocol constants (RFC 2131 / 2132) ───────────────────────────────

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;
/// BOOTP header size (236 bytes) before the options field.
const BOOTP_HEADER_SIZE: usize = 236;
const MAGIC_COOKIE: u32 = 0x6382_5363;

/// DHCP message types (option 53).
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
// NAK (6) needs no constant here: NAKs are intentionally ignored by the
// client (a failed REQUEST just falls through to the next renewal attempt).

/// DHCP option codes.
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS_SERVER: u8 = 6;
const OPT_HOST_NAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_IP_LEASE_TIME: u8 = 51;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_IDENTIFIER: u8 = 54;
const OPT_PARAMETER_REQUEST_LIST: u8 = 55;
const OPT_RENEWAL_TIME: u8 = 58;
const OPT_REBINDING_TIME: u8 = 59;
const OPT_CLIENT_IDENTIFIER: u8 = 61;
const OPT_END: u8 = 255;

/// Default lease duration if the server omits option 51 (24 h).
const DEFAULT_LEASE_TICKS: u64 = 24 * 3600 * TICKS_PER_SECOND;
/// Default T1 if omitted: half the lease.
const DEFAULT_RENEWAL_TICKS: u64 = DEFAULT_LEASE_TICKS / 2;
/// Default T2 if omitted: 7/8 of the lease.
const DEFAULT_REBINDING_TICKS: u64 = DEFAULT_LEASE_TICKS * 7 / 8;

/// How many ticks to wait for each DHCP response before timing out.
const RESPONSE_TIMEOUT_TICKS: u64 = 200; // 2 s at 100 Hz

// ── Option parsing helpers ─────────────────────────────────────────────

/// Walk the DHCP options field, invoking `visitor` for each option.
///
/// Stops at the first `END` option (the options field is padded with `PAD`s
/// after the end marker).
fn for_each_option(options: &[u8], mut visitor: impl FnMut(u8, &[u8])) {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => {
                i += 1; // PAD
            }
            255 => break, // END
            code => {
                let len = options[i + 1] as usize;
                let val = &options[i + 2..(i + 2 + len).min(options.len())];
                visitor(code, val);
                i += 2 + len;
            }
        }
    }
}

fn read_u32_be(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_ipv4(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() < 4 {
        return None;
    }
    Some([bytes[0], bytes[1], bytes[2], bytes[3]])
}

// ── Message builders ───────────────────────────────────────────────────

/// Build a BOOTP header with the given message type and options appended.
fn build_bootp_message(
    stack: &NetworkStack,
    msg_type: u8,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut msg = vec![0u8; BOOTP_HEADER_SIZE + 4]; // header + magic cookie
    msg[0] = BOOTREQUEST;
    msg[1] = HTYPE_ETHERNET;
    msg[2] = HLEN_ETHERNET;
    msg[3] = 0; // hops
                // xid (bytes 4..8): derived from the MAC so consecutive renewals from the
                // same interface carry a stable transaction id.
    msg[4..8].copy_from_slice(&stack.local_mac[0..4]);
    // secs (8..10) = 0; flags (10..12) = 0x8000 (broadcast).
    msg[10] = 0x80;
    msg[11] = 0x00;
    // ciaddr = 0.0.0.0, yiaddr = 0, siaddr = 0, giaddr = 0 — already zero.
    // chaddr (28..44): client MAC (zero-padded to 16 bytes).
    msg[28..34].copy_from_slice(&stack.local_mac);
    // Magic cookie at offset 236.
    msg[236..240].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());

    // Message type, client identifier (option 61): hardware type + MAC.
    let mut opts = vec![
        OPT_MESSAGE_TYPE,
        1,
        msg_type,
        OPT_CLIENT_IDENTIFIER,
        7,
        HTYPE_ETHERNET,
    ];
    opts.extend_from_slice(&stack.local_mac);
    // Requested IP (only meaningful in REQUEST).
    if let Some(ip) = requested_ip {
        opts.push(OPT_REQUESTED_IP);
        opts.push(4);
        opts.extend_from_slice(&ip);
    }
    // Server identifier (option 54): identifies the server in REQUEST.
    if let Some(srv) = server_id {
        opts.push(OPT_SERVER_IDENTIFIER);
        opts.push(4);
        opts.extend_from_slice(&srv);
    }
    // Host name (option 12).
    opts.push(OPT_HOST_NAME);
    opts.push(7);
    opts.extend_from_slice(b"protofire");
    // Parameter request list (option 55).
    opts.push(OPT_PARAMETER_REQUEST_LIST);
    opts.push(7);
    opts.extend_from_slice(&[
        OPT_SUBNET_MASK,
        OPT_ROUTER,
        OPT_DNS_SERVER,
        OPT_IP_LEASE_TIME,
        OPT_RENEWAL_TIME,
        OPT_REBINDING_TIME,
        54,
    ]);
    // End.
    opts.push(OPT_END);

    msg.extend_from_slice(&opts);
    msg
}

// ── Lease parsing ──────────────────────────────────────────────────────

/// Parse a DHCPOFFER / DHCPACK message into a [`DhcpLease`].
///
/// `msg` is the raw UDP payload received from the DHCP server.
fn parse_dhcp_reply(msg: &[u8]) -> Option<DhcpLease> {
    if msg.len() < BOOTP_HEADER_SIZE + 4 {
        return None;
    }
    if msg[0] != BOOTREPLY {
        return None;
    }
    let yiaddr = [msg[16], msg[17], msg[18], msg[19]];
    // Magic cookie check.
    let cookie = u32::from_be_bytes([
        msg[BOOTP_HEADER_SIZE],
        msg[BOOTP_HEADER_SIZE + 1],
        msg[BOOTP_HEADER_SIZE + 2],
        msg[BOOTP_HEADER_SIZE + 3],
    ]);
    if cookie != MAGIC_COOKIE {
        return None;
    }

    let mut msg_type = None;
    let mut server_id = None;
    let mut dns_server = None;
    let mut router = None;
    let mut subnet_mask = None;
    let mut lease_ticks = DEFAULT_LEASE_TICKS;
    let mut renewal_ticks = DEFAULT_RENEWAL_TICKS;
    let mut rebinding_ticks = DEFAULT_REBINDING_TICKS;

    for_each_option(&msg[BOOTP_HEADER_SIZE + 4..], |code, val| match code {
        OPT_MESSAGE_TYPE => {
            if !val.is_empty() {
                msg_type = Some(val[0]);
            }
        }
        OPT_SERVER_IDENTIFIER => server_id = read_ipv4(val),
        OPT_DNS_SERVER => dns_server = read_ipv4(val),
        OPT_ROUTER => router = read_ipv4(val),
        OPT_SUBNET_MASK => subnet_mask = read_ipv4(val),
        OPT_IP_LEASE_TIME => {
            if let Some(secs) = read_u32_be(val) {
                lease_ticks = u64::from(secs) * TICKS_PER_SECOND;
            }
        }
        OPT_RENEWAL_TIME => {
            if let Some(secs) = read_u32_be(val) {
                renewal_ticks = u64::from(secs) * TICKS_PER_SECOND;
            }
        }
        OPT_REBINDING_TIME => {
            if let Some(secs) = read_u32_be(val) {
                rebinding_ticks = u64::from(secs) * TICKS_PER_SECOND;
            }
        }
        _ => {}
    });

    // Accept only OFFER (2) and ACK (5) messages; ignore NAKs.
    match msg_type {
        Some(DHCP_OFFER) | Some(DHCP_ACK) => {}
        _ => return None,
    }

    Some(DhcpLease {
        yiaddr,
        dns_server,
        router,
        subnet_mask,
        lease_ticks,
        renewal_ticks,
        rebinding_ticks,
    })
}

// ── Public API ─────────────────────────────────────────────────────────

/// Perform the DISCOVER → OFFER → REQUEST → ACK handshake and return the
/// negotiated lease.
///
/// Binds UDP/68, broadcasts a DISCOVER, waits for the server's OFFER, then
/// confirms with a REQUEST (including the offered address and server id) and
/// waits for the ACK.  The lease is *not* installed on the stack — the caller
/// applies it via [`NetworkStack::set_dhcp_lease`].
pub fn discover_and_request() -> Result<DhcpLease> {
    let stack = NetworkStack::global().ok_or(Error::Unsupported)?;

    // Bind the client port.
    {
        let mut table = stack.udp_table().lock();
        if !table.is_bound(DHCP_CLIENT_PORT) {
            table.bind(DHCP_CLIENT_PORT)?;
        }
    }

    // DISCOVER (no requested IP / server id).
    let discover = build_bootp_message(stack, DHCP_DISCOVER, None, None);
    udp::send_to(
        stack,
        DHCP_CLIENT_PORT,
        [255, 255, 255, 255],
        DHCP_SERVER_PORT,
        &discover,
    )?;

    // Wait for the OFFER.
    let (offer, offer_server) = receive_dhcp_message(DHCP_OFFER)?;

    // REQUEST — confirm the offered address with the selected server.
    // Per RFC 2131 §4.3.2 the client MUST echo the server identifier (54)
    // from the OFFER so the intended server answers.  When the OFFER omits
    // it (single-server broadcast networks) we fall back to a broadcast
    // REQUEST with no server id, matching the renewal path.
    let request = build_bootp_message(stack, DHCP_REQUEST, Some(offer.yiaddr), offer_server);
    udp::send_to(
        stack,
        DHCP_CLIENT_PORT,
        [255, 255, 255, 255],
        DHCP_SERVER_PORT,
        &request,
    )?;

    // Wait for the ACK.
    let (ack, _) = receive_dhcp_message(DHCP_ACK)?;
    Ok(ack)
}

/// Attempt to renew the current lease by unicasting a DHCPREQUEST to the
/// lease's server.
///
/// Best-effort: failures (no lease, server unreachable, NAK) are silently
/// ignored — the periodic renewal check in the stack will try again.
pub fn try_renew_lease() {
    let Ok(stack) = NetworkStack::global().ok_or(Error::Unsupported) else {
        return;
    };
    // Clone the current lease (if any) so we can address the request.
    let lease = match stack.dhcp_lease() {
        Some(lease) => lease,
        None => return,
    };

    let request = build_bootp_message(stack, DHCP_REQUEST, Some(lease.yiaddr), None);
    // Renewal is unicast to the current server (or broadcast if unknown).
    let server = lease
        .router
        .filter(|gw| *gw != [0, 0, 0, 0])
        .unwrap_or([255, 255, 255, 255]);
    // An ACK arriving later will be picked up by the normal poll path.
    let _ = udp::send_to(stack, DHCP_CLIENT_PORT, server, DHCP_SERVER_PORT, &request);
}

/// Poll the network device until a DHCP reply of `want_type` arrives on the
/// client port, then parse and return the lease together with the server
/// identifier (option 54) carried in the reply, if any.
fn receive_dhcp_message(want_type: u8) -> Result<(DhcpLease, Option<Ipv4Addr>)> {
    let stack = NetworkStack::global().ok_or(Error::Unsupported)?;
    let deadline = stack.current_tick().wrapping_add(RESPONSE_TIMEOUT_TICKS);
    let mut buf = vec![0u8; 512];

    while stack.current_tick() != deadline {
        // Process any pending frames so the server's reply lands in the UDP
        // table before we attempt to dequeue it.
        let _ = stack.poll();

        let (n, _src_ip, _src_port) = match stack
            .udp_table()
            .lock()
            .recv_from(DHCP_CLIENT_PORT, &mut buf)
        {
            Ok(ok) => ok,
            Err(Error::TimedOut) => continue,
            Err(e) => return Err(e),
        };
        if let Some(lease) = parse_dhcp_reply(&buf[..n]) {
            // Skip non-target message types (e.g. an OFFER while awaiting ACK).
            if is_message_type(&buf[..n], want_type) {
                return Ok((lease, offer_server_identifier(&buf[..n])));
            }
        }
    }
    Err(Error::TimedOut)
}

/// Whether `msg` carries the given DHCP message type option.
fn is_message_type(msg: &[u8], want: u8) -> bool {
    let mut found = false;
    if msg.len() < BOOTP_HEADER_SIZE + 4 {
        return false;
    }
    for_each_option(&msg[BOOTP_HEADER_SIZE + 4..], |code, val| {
        if code == OPT_MESSAGE_TYPE && !val.is_empty() {
            found = val[0] == want;
        }
    });
    found
}

/// Extract the server identifier (option 54) from a DHCP reply, if present.
fn offer_server_identifier(msg: &[u8]) -> Option<Ipv4Addr> {
    let mut server = None;
    if msg.len() < BOOTP_HEADER_SIZE + 4 {
        return None;
    }
    for_each_option(&msg[BOOTP_HEADER_SIZE + 4..], |code, val| {
        if code == OPT_SERVER_IDENTIFIER {
            server = read_ipv4(val);
        }
    });
    server
}
