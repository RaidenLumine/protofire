//! src/kernel/network/ntp.rs
//!
//! Minimal NTP (RFC 5905) client used to discipline the system clock.
//!
//! The client sends a standard 48-byte SNTP request to a configured server
//! (resolved via DNS on first use) and, when a response arrives on UDP port
//! 123, computes an offset between the server's notion of "now" and the local
//! RTC.  The offset is exposed via [`NtpClient::offset`] for the clock
//! disciplining layer.

use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::{Error, Result};

/// Well-known NTP UDP port.
pub const NTP_PORT: u16 = 123;

/// NTP epoch: seconds between 1900-01-01 and 1970-01-01 (the Unix epoch).
pub const NTP_EPOCH_DELTA: u64 = 2_208_988_800;

/// Initial poll interval exponent (6 → 64 seconds).
const INITIAL_POLL_EXP: u8 = 6;

/// NTP version used in client requests (RFC 5905 §7.3).
const NTP_VERSION: u8 = 4;
/// NTP mode: client (RFC 5905 §7.3).
const NTP_MODE_CLIENT: u8 = 3;

/// Size of a full NTP packet (RFC 5905 §7.3).
const NTP_PACKET_SIZE: usize = 48;

/// A received NTP packet (48 bytes).
///
/// The transmit timestamp (seconds since the NTP epoch of 1900-01-01) lives at
/// offset 40 and is what a client uses to discipline its clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpPacket {
    /// LI (2) | VN (3) | Mode (3).
    pub li_vn_mode: u8,
    /// Peer stratum (0 = unspecified / client).
    pub stratum: u8,
    /// Poll interval as a signed exponent of 2.
    pub poll: u8,
    /// Clock precision as a signed exponent of 2.
    pub precision: i8,
    /// Round-trip delay in 16.16 fixed-point seconds.
    pub root_delay: u32,
    /// Nominal error in 16.16 fixed-point seconds.
    pub root_dispersion: u32,
    /// Reference identifier.
    pub reference_id: u32,
    /// Originate timestamp (seconds since 1900).
    pub originate_time_secs: u64,
    /// Receive timestamp (seconds since 1900).
    pub receive_time_secs: u64,
    /// Transmit timestamp (seconds since 1900).
    pub transmit_time_secs: u64,
}

impl NtpPacket {
    /// Parse a 48-byte NTP packet from `data`.
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is too short to contain a
    /// full NTP packet.
    pub fn from_bytes(data: &[u8]) -> Result<NtpPacket> {
        if data.len() < NTP_PACKET_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(NtpPacket {
            li_vn_mode: data[0],
            stratum: data[1],
            poll: data[2],
            precision: data[3] as i8,
            root_delay: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            root_dispersion: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            reference_id: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            originate_time_secs: u64::from_be_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
            receive_time_secs: u64::from_be_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]),
            transmit_time_secs: u64::from_be_bytes([
                data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
            ]),
        })
    }

    /// The transmit timestamp converted from the NTP epoch to Unix seconds.
    pub fn transmit_time_unix(&self) -> u64 {
        self.transmit_time_secs.saturating_sub(NTP_EPOCH_DELTA)
    }
}

/// An outgoing NTP client request (48 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpRequest {
    /// Transmit timestamp (seconds since 1900).
    transmit_time: u64,
    /// Poll interval exponent.
    poll: u8,
}

impl NtpRequest {
    /// Serialise the request into a 48-byte NTP packet.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; NTP_PACKET_SIZE];
        buf[0] = (NTP_VERSION << 3) | NTP_MODE_CLIENT; // LI=0, VN, Mode=client
        buf[1] = 0; // stratum = unspecified
        buf[2] = self.poll;
        buf[3] = 0; // precision
                    // Remaining header fields (root delay/dispersion, reference id and
                    // the three earlier timestamps) stay zero; only the transmit
                    // timestamp is populated.
        buf[40..48].copy_from_slice(&self.transmit_time.to_be_bytes());
        Vec::from(buf)
    }
}

/// Minimal NTP client state.
pub struct NtpClient {
    /// Server hostname, resolved to an IP on first poll.
    server: String,
    /// Resolved server address (cached after the first successful lookup).
    server_ip: Option<Ipv4Addr>,
    /// Scheduler ticks per second (converts poll intervals to ticks).
    ticks_per_second: u64,
    /// Tick of the last transmitted poll.
    last_poll_tick: u64,
    /// Estimated clock offset in seconds (positive = RTC is behind the server).
    offset_secs: Option<i64>,
}

impl NtpClient {
    /// Create an NTP client for `server` (a hostname or dotted-quad address).
    pub fn new(server: &str, ticks_per_second: u64) -> Self {
        Self {
            server: String::from(server),
            server_ip: None,
            ticks_per_second,
            last_poll_tick: 0,
            offset_secs: None,
        }
    }

    /// Poll interval in scheduler ticks (64 seconds at the configured rate).
    fn poll_interval_ticks(&self) -> u64 {
        (1u64 << INITIAL_POLL_EXP).saturating_mul(self.ticks_per_second)
    }

    /// Whether a poll is due at `tick`.  Advances the internal timer only when
    /// a poll is actually due.
    pub fn should_poll(&mut self, tick: u64) -> bool {
        let due = if self.last_poll_tick == 0 {
            // First poll shortly after boot (1 second) so DNS is usable.
            tick >= self.ticks_per_second
        } else {
            tick.wrapping_sub(self.last_poll_tick) >= self.poll_interval_ticks()
        };
        if due {
            self.last_poll_tick = tick;
        }
        due
    }

    /// The server's resolved IPv4 address, resolved (and cached) on first use.
    pub fn server_ip(&mut self) -> Option<Ipv4Addr> {
        if let Some(ip) = self.server_ip {
            return Some(ip);
        }
        let resolved = crate::kernel::network::dns::resolve_hostname(&self.server).ok();
        self.server_ip = resolved;
        resolved
    }

    /// Build an NTP client request with the transmit timestamp taken from the
    /// current RTC (converted to the NTP epoch).
    pub fn build_request(&self, rtc_now_unix: u64, _current_tick: u64) -> NtpRequest {
        NtpRequest {
            transmit_time: rtc_now_unix.saturating_add(NTP_EPOCH_DELTA),
            poll: INITIAL_POLL_EXP,
        }
    }

    /// Apply a server response, computing and storing the clock offset.
    ///
    /// The offset is `server_now − rtc_now` in seconds (positive when the RTC
    /// is behind the server).  Returns the computed offset, or `None` when the
    /// response carries no usable transmit timestamp.
    pub fn process_response(
        &mut self,
        packet: &NtpPacket,
        rtc_now_unix: u64,
        _current_tick: u64,
    ) -> Option<i64> {
        if packet.transmit_time_secs == 0 {
            return None;
        }
        let server_unix = packet.transmit_time_secs.saturating_sub(NTP_EPOCH_DELTA) as i64;
        let offset = server_unix - rtc_now_unix as i64;
        self.offset_secs = Some(offset);
        Some(offset)
    }

    /// The most recently estimated clock offset in seconds.
    pub fn offset(&self) -> Option<i64> {
        self.offset_secs
    }
}
