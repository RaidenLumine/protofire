//! src/kernel/network/tcp/types.rs
//!
//! TCP types: constants, flags, state machine, header, and connection state.
use alloc::collections::vec_deque::VecDeque;
use alloc::vec::Vec;

// ─── Socket options ─────────────────────────────────────────────────────────

/// Socket-level and protocol-level options set via `setsockopt` syscall.
#[derive(Debug, Clone)]
pub struct SocketOptions {
    /// SO_KEEPALIVE: enable TCP keep-alive probes on idle connections.
    pub keepalive: bool,
    /// SO_REUSEADDR: allow rebinding to a port in TIME_WAIT state.
    pub reuseaddr: bool,
    /// SO_RCVTIMEO: receive timeout in ticks (0 = no timeout, block forever).
    pub rcvtimeo: u64,
    /// SO_SNDTIMEO: send timeout in ticks (0 = no timeout, block forever).
    pub sndtimeo: u64,
    /// SO_RCVBUF: desired receive buffer size hint.
    pub rcvbuf: usize,
    /// SO_SNDBUF: desired send buffer size hint.
    pub sndbuf: usize,
    /// TCP_NODELAY: disable Nagle's algorithm (send small segments immediately).
    pub nodelay: bool,
    /// TCP_KEEPIDLE: idle time in seconds before keep-alive probes begin.
    pub keepidle: u32,
    /// TCP_KEEPINTVL: interval in seconds between keep-alive probes.
    pub keepintvl: u32,
    /// TCP_KEEPCNT: number of keep-alive probes before declaring the
    /// connection dead.
    pub keepcnt: u32,
    /// TCP_MAXSEG: maximum segment size (MSS) advertisement in bytes.
    pub maxseg: usize,
    /// TCP_ECN: enable Explicit Congestion Notification (RFC 3168).
    pub ecn_enabled: bool,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            keepalive: false,
            reuseaddr: false,
            rcvtimeo: 0,
            sndtimeo: 0,
            rcvbuf: 65536,
            sndbuf: 65536,
            nodelay: true,  // Match typical "nodelay by default" kernel policy.
            keepidle: 7200, // 2 hours (typical default)
            keepintvl: 75,  // 75 seconds
            keepcnt: 9,     // 9 probes
            maxseg: 1460,   // Ethernet standard
            ecn_enabled: true,
        }
    }
}

// ─── TCP constants ───

/// Minimum TCP header size (no options).
pub const TCP_MIN_HEADER_SIZE: usize = 20;

/// Default Maximum Segment Size.
pub(super) const DEFAULT_MSS: usize = 1460; // 1500 Ethernet - 20 IPv4 - 20 TCP

/// Minimum MSS per RFC 1122 Section 4.2.2.6.
pub(super) const MIN_PEER_MSS: usize = 536;

/// Maximum receive buffer size in bytes.  When the buffer reaches this
/// limit the advertised window shrinks to zero, telling the peer to
/// stop sending data.
pub(super) const MAX_RECV_BUFFER: usize = 65536;

/// Initial retransmission timeout in ticks (300 ms at 100 Hz).
pub(super) const RTO_BASE_TICKS: u64 = 30;

/// Maximum retransmission count before giving up.
pub(super) const MAX_RETRIES: u32 = 5;

/// Maximum exponential backoff multiplier (capped at 3x).
pub(super) const MAX_BACKOFF_MULTIPLIER: u32 = 3;

/// TimeWait duration (2 × MSL ≈ 60 seconds → 6000 ticks).
pub(super) const TIME_WAIT_TICKS: u64 = 6000;

// ─── TCP flags ───

pub(super) const TCP_FLAG_FIN: u8 = 0x01;
pub(super) const TCP_FLAG_SYN: u8 = 0x02;
pub(super) const TCP_FLAG_RST: u8 = 0x04;
pub(super) const TCP_FLAG_PSH: u8 = 0x08;
pub(super) const TCP_FLAG_ACK: u8 = 0x10;
pub(super) const TCP_OPT_KIND_MSS: u8 = 2;
pub(super) const TCP_OPT_LEN_MSS: u8 = 4;
pub(super) const TCP_OPT_KIND_WINDOW_SCALE: u8 = 3;
pub(super) const TCP_OPT_LEN_WINDOW_SCALE: u8 = 3;
pub(super) const TCP_OPT_KIND_SACK_PERMITTED: u8 = 4;
pub(super) const TCP_OPT_LEN_SACK_PERMITTED: u8 = 2;
pub(super) const TCP_OPT_KIND_SACK: u8 = 5;
pub(super) const TCP_OPT_KIND_TIMESTAMP: u8 = 8;
pub(super) const TCP_OPT_LEN_TIMESTAMP: u8 = 10;

/// Maximum number of SACK blocks to include in an ACK segment.
pub(super) const MAX_SACK_BLOCKS: usize = 3;

/// Pre-built SACK-permitted option bytes: kind=4, len=2.
pub(super) const SACK_PERMITTED_OPTION_BYTES: [u8; 2] =
    [TCP_OPT_KIND_SACK_PERMITTED, TCP_OPT_LEN_SACK_PERMITTED];

/// Our advertised window scale shift count (RFC 7323 §2.2).
pub(super) const DEFAULT_WINDOW_SCALE: u8 = 6;

/// Build a 4-byte MSS TCP option from a u16 value.
pub(super) fn build_mss_option(mss: u16) -> [u8; 4] {
    [
        TCP_OPT_KIND_MSS,
        TCP_OPT_LEN_MSS,
        (mss >> 8) as u8,
        mss as u8,
    ]
}

/// Pre-built window scale option bytes.
pub(super) const WINDOW_SCALE_OPTION_BYTES: [u8; 3] = [
    TCP_OPT_KIND_WINDOW_SCALE,
    TCP_OPT_LEN_WINDOW_SCALE,
    DEFAULT_WINDOW_SCALE,
];

/// Compute the MSS we advertise in SYN / SYN-ACK segments from the device MTU.
pub(super) fn advertised_mss_v4(mtu: usize) -> u16 {
    mtu.saturating_sub(40)
        .max(MIN_PEER_MSS)
        .min(u16::MAX as usize) as u16
}

// ─── Ephemeral port range ───

pub(crate) const EPHEMERAL_PORT_START: u16 = 49152;
pub(crate) const EPHEMERAL_PORT_END: u16 = 65535;

// ─── TCP state ───

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    CloseWait,
    LastAck,
    TimeWait,
}

// ─── TCP header ───

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8, // in 32-bit words
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
}

// ─── Retransmit state ───

pub(super) struct RetransmitState {
    /// Tick when the retransmit timer was started.
    pub(super) started_at: u64,
    /// Number of retransmissions for the oldest pending segment.
    pub(super) count: u32,
    /// Unacknowledged segments in send order (oldest first).
    pub(super) pending_segments: VecDeque<(u32, Vec<u8>)>,
}

// ─── TCP connection state ───

/// Per-connection TCP state machine.
pub struct TcpConnectionState {
    pub state: TcpState,
    pub local_port: u16,
    pub remote_ip: crate::kernel::network::internet::ipv4::Ipv4Addr,
    pub remote_port: u16,
    // Sender state
    pub(super) send_next: u32,    // SND.NXT
    pub(super) send_unacked: u32, // SND.UNA
    pub(super) send_window: u32,  // peer's advertised window
    pub(super) initial_seq: u32,
    // Receiver state
    pub(super) recv_next: u32, // RCV.NXT
    // Buffers
    pub(super) send_buffer: VecDeque<u8>,
    pub(super) recv_buffer: VecDeque<u8>,
    // Retransmission
    pub(super) retransmit: RetransmitState,
    // TimeWait entry tick
    pub(super) time_wait_start: u64,
    // Peer's initial sequence (for validation)
    pub(super) peer_initial_seq: u32,
    // Peer's MSS
    pub(super) peer_mss: usize,
    // Peer's window scale shift
    pub(super) peer_window_scale: u8,
    // SACK (RFC 2018)
    pub(super) ooo_queue: VecDeque<(u32, Vec<u8>)>,
    pub(super) peer_sack_blocks: Vec<(u32, u32)>,
    pub(super) peer_sack_ok: bool,
    // TCP Timestamps (RFC 7323)
    pub(super) ts_val: u32,
    pub(super) peer_ts_val: u32,
    pub(super) peer_timestamps: bool,
    /// Set when a segment with PSH flag arrives.  Readers should return
    /// buffered data up to this point even if the caller's buffer isn't
    /// full yet (RFC 793 §2.8, RFC 1122 §4.2.2.2).
    pub(super) push_boundary: bool,
    /// Socket options set via `setsockopt`.
    pub options: SocketOptions,
    /// Congestion control state (cwnd, ssthresh, recovery).
    pub congestion: super::congestion::CongestionState,
    /// ECN state (RFC 3168).
    pub ecn: super::ecn::EcnState,
}

impl TcpConnectionState {
    pub(super) fn new(
        local_port: u16,
        remote_ip: crate::kernel::network::internet::ipv4::Ipv4Addr,
        remote_port: u16,
        initial_seq: u32,
        current_tick: u64,
    ) -> Self {
        Self {
            state: TcpState::SynSent,
            local_port,
            remote_ip,
            remote_port,
            send_next: initial_seq + 1,
            send_unacked: initial_seq,
            send_window: 65535,
            initial_seq,
            recv_next: 0,
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            retransmit: RetransmitState {
                started_at: current_tick,
                count: 0,
                pending_segments: VecDeque::new(),
            },
            time_wait_start: 0,
            peer_initial_seq: 0,
            peer_mss: MIN_PEER_MSS,
            peer_window_scale: 0,
            ooo_queue: VecDeque::new(),
            peer_sack_blocks: Vec::new(),
            peer_sack_ok: false,
            ts_val: (current_tick as u32).wrapping_mul(10_000),
            peer_ts_val: 0,
            peer_timestamps: false,
            push_boundary: false,
            options: SocketOptions::default(),
            congestion: super::congestion::CongestionState::default(),
            ecn: super::ecn::EcnState::new_active(),
        }
    }

    /// Create a child connection for a listening socket.
    pub(super) fn new_child(
        local_port: u16,
        remote_ip: crate::kernel::network::internet::ipv4::Ipv4Addr,
        remote_port: u16,
        peer_initial_seq: u32,
        initial_seq: u32,
        current_tick: u64,
    ) -> Self {
        Self {
            state: TcpState::SynReceived,
            local_port,
            remote_ip,
            remote_port,
            send_next: initial_seq + 1,
            send_unacked: initial_seq,
            send_window: 65535,
            initial_seq,
            recv_next: peer_initial_seq.wrapping_add(1),
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            retransmit: RetransmitState {
                started_at: current_tick,
                count: 0,
                pending_segments: VecDeque::new(),
            },
            time_wait_start: 0,
            peer_initial_seq,
            peer_mss: MIN_PEER_MSS,
            peer_window_scale: 0,
            ooo_queue: VecDeque::new(),
            peer_sack_blocks: Vec::new(),
            peer_sack_ok: false,
            ts_val: (current_tick as u32).wrapping_mul(10_000),
            peer_ts_val: 0,
            peer_timestamps: false,
            push_boundary: false,
            options: SocketOptions::default(),
            congestion: super::congestion::CongestionState::default(),
            ecn: super::ecn::EcnState::new_passive(),
        }
    }

    /// Return the number of bytes available to read.
    pub fn available(&self) -> usize {
        self.recv_buffer.len()
    }

    /// Read up to `len` bytes from the receive buffer.
    pub fn read(&mut self, buffer: &mut [u8]) -> usize {
        let len = buffer.len().min(self.recv_buffer.len());
        for (i, byte) in self.recv_buffer.drain(..len).enumerate() {
            buffer[i] = byte;
        }
        len
    }

    /// Buffer `data` for transmission. Returns bytes accepted.
    pub fn write(&mut self, data: &[u8]) -> usize {
        self.send_buffer.extend(data.iter());
        data.len()
    }

    /// Compute the current receive window to advertise.
    pub(super) fn recv_window(&self) -> u16 {
        let available = MAX_RECV_BUFFER.saturating_sub(self.recv_buffer.len());
        (available >> DEFAULT_WINDOW_SCALE) as u16
    }
}

// ─── Connection key type ───

/// Uniquely identifies a TCP connection by (local_port, remote_ip, remote_port).
pub(super) type ConnKey = (u16, crate::kernel::network::internet::ipv4::Ipv4Addr, u16);

// ─── Helpers ───

pub(super) fn simple_initial_seq(tick: u64) -> u32 {
    (tick as u32).wrapping_mul(0x9E37_79B9)
}
