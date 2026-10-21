//! src/network/tcp/types.rs
//!
//! TCP types: constants, flags, state machine, header, and connection state.

use alloc::collections::vec_deque::VecDeque;
use alloc::vec::Vec;

use crate::kernel::process::wait::WaitQueue;
use crate::kernel::sync::Mutex;
use crate::network::internet::ip::IpAddress;

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
    /// TCP_NODELAY: disable Nagle's algorithm (send small segments
    /// immediately).
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

/// The most bytes one connection may hold waiting for the peer to accept them.
///
/// The receive side has had a bound since it was written; the send side had
/// none, so a peer that stopped reading grew the kernel's memory for as long
/// as the writer kept writing (RFC 0032).  The number matches the receive
/// side's: there is no measurement that says a connection wants more, and
/// symmetry is the honest default when the choice is between two numbers
/// nothing distinguishes.
pub const MAX_SEND_BUFFER: usize = 65536;

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

/// Compute the MSS we advertise in SYN / SYN-ACK segments from the device MTU
/// for an IPv4 peer (40 bytes of IPv4 + TCP headers).
pub(super) fn advertised_mss_v4(mtu: usize) -> u16 {
    mtu.saturating_sub(40)
        .max(MIN_PEER_MSS)
        .min(u16::MAX as usize) as u16
}

/// Compute the MSS we advertise in SYN / SYN-ACK segments from the device MTU
/// for an IPv6 peer (60 bytes of IPv6 + TCP headers).
pub(super) fn advertised_mss_v6(mtu: usize) -> u16 {
    mtu.saturating_sub(60)
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
/// A handle on one connection's read readiness.
///
/// Taken under the table lock and waited on without any lock: the connection's
/// own `Mutex` is held by whoever is delivering, and a reader that held it
/// across a park would deadlock against the segment that would wake it.
/// The handle names the wait queue through an `Arc`, so a connection that is
/// removed while a reader is parked still has something to be woken on.
#[derive(Clone)]
pub struct TcpReadWait {
    pub(super) readable: WaitQueue<usize>,
}

impl TcpReadWait {
    /// Block until bytes are buffered or `deadline` passes.
    ///
    /// The outcome is the same three-way answer a datagram wait gives, for the
    /// same reasons: `CannotPark` ends a loop watching a clock that cannot
    /// advance, `AlreadyQueued` says the data arrived before the park, and
    /// `Parked` is the one a caller can count as evidence it really slept.
    pub fn wait(&self, deadline: u64) -> crate::network::udp::DatagramWaitOutcome {
        use crate::network::udp::DatagramWaitOutcome;

        if self.queued() != 0 {
            return DatagramWaitOutcome::AlreadyQueued;
        }
        let Some(scheduler) = crate::kernel::process::Scheduler::global() else {
            return DatagramWaitOutcome::CannotPark;
        };
        if scheduler.current_thread().is_none() {
            return DatagramWaitOutcome::CannotPark;
        }

        let parked =
            self.readable
                .block_current_until_if(deadline, |available, waiters, thread| {
                    if *available != 0 {
                        false
                    } else {
                        waiters.push_back(thread.clone());
                        true
                    }
                });
        if parked {
            DatagramWaitOutcome::Parked
        } else {
            DatagramWaitOutcome::AlreadyQueued
        }
    }

    /// How many bytes are buffered right now.
    pub fn queued(&self) -> usize {
        self.readable.with_lock(|available, _| *available)
    }
}

/// Wakes a connection's readers when it goes out of scope.
///
/// `process_segment` has a dozen return paths and several of them can end a
/// connection.  Putting the wake at each one means the next return added is a
/// reader parked forever; putting it in a guard means the next return is
/// covered by construction.  The guard holds the connection through an `Arc`,
/// so the wake still reaches the queue after the table has dropped its entry.
pub struct ReaderNotifier {
    conn: alloc::sync::Arc<Mutex<TcpConnectionState>>,
}

impl ReaderNotifier {
    pub(super) fn new(conn: &alloc::sync::Arc<Mutex<TcpConnectionState>>) -> Self {
        Self {
            conn: alloc::sync::Arc::clone(conn),
        }
    }
}

impl Drop for ReaderNotifier {
    fn drop(&mut self) {
        let state = self.conn.lock();
        if state.state == TcpState::Closed {
            // Nothing will ever fill the buffer again, and there may be bytes
            // buffered before the close: leave the count alone so a reader
            // drains what arrived, then wake it to read and see EOF.
            let pending = state.recv_buffer.len();
            state
                .readable
                .with_lock(|available, _| *available = pending);
            state.readable.wake_all();
        } else {
            state.wake_reader();
        }
    }
}

pub struct TcpConnectionState {
    pub state: TcpState,
    pub local_port: u16,
    pub remote_ip: IpAddress,
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
    /// Waiters on this connection's receive buffer.
    ///
    /// Its state is the buffer's length, so a reader decides whether to park
    /// without the connection's lock — which it cannot take, because it is
    /// already holding it when it asks.  `process_segment` bumps the count
    /// and wakes one waiter after extending the buffer, and a close wakes
    /// every waiter so nobody sleeps through EOF.
    pub(super) readable: WaitQueue<usize>,
}

impl TcpConnectionState {
    pub(super) fn new(
        local_port: u16,
        remote_ip: impl Into<IpAddress>,
        remote_port: u16,
        initial_seq: u32,
        current_tick: u64,
    ) -> Self {
        Self {
            state: TcpState::SynSent,
            local_port,
            remote_ip: remote_ip.into(),
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
            readable: WaitQueue::with_state(0),
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
        remote_ip: impl Into<IpAddress>,
        remote_port: u16,
        peer_initial_seq: u32,
        initial_seq: u32,
        current_tick: u64,
    ) -> Self {
        Self {
            state: TcpState::SynReceived,
            local_port,
            remote_ip: remote_ip.into(),
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
            readable: WaitQueue::with_state(0),
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
        // Publish the shorter buffer, so a waiter that is about to check the
        // count sees what the pop left behind.
        self.readable
            .with_lock(|available, _| *available = self.recv_buffer.len());
        len
    }

    /// Announce newly buffered bytes and wake one reader.
    ///
    /// Called after `recv_buffer` grew, under the connection's lock, so the
    /// bytes are visible before the wake: a reader that wakes and finds the
    /// buffer empty can only be looking at data another reader took.
    pub(super) fn wake_reader(&self) {
        let pending = self.recv_buffer.len();
        self.readable.wake_with(|available, waiters, waking| {
            *available = pending;
            if let Some(thread) = WaitQueue::<usize>::take_next_waiter(waiters) {
                waking.push(thread);
            }
        });
    }

    /// How many threads are parked waiting to read.
    pub fn waiter_count(&self) -> usize {
        self.readable.waiter_count()
    }

    /// How many bytes are buffered for transmission and not yet acknowledged.
    ///
    /// There is no upper bound: `write` accepts every byte it is handed, so
    /// this grows while the peer does not read.  Exposed so a test can show
    /// that, and so the day a bound is chosen there is a reader for it.
    pub fn unacknowledged_bytes(&self) -> usize {
        self.send_buffer.len()
    }

    /// How many bytes are buffered for reading.
    pub fn buffered(&self) -> usize {
        self.recv_buffer.len()
    }

    /// A handle a reader can park on without holding the connection's lock.
    pub fn reader(&self) -> TcpReadWait {
        TcpReadWait {
            readable: self.readable.clone(),
        }
    }

    /// Buffer `data` for transmission.  Returns bytes accepted.
    ///
    /// Stops at [`MAX_SEND_BUFFER`]: whatever does not fit is left for the
    /// caller to retry once the peer acknowledges some of the backlog.  The
    /// short count is the only signal the ABI has, and it is enough — a caller
    /// that ignores it is asking the kernel to remember data forever.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let room = MAX_SEND_BUFFER.saturating_sub(self.send_buffer.len());
        let accepted = data.len().min(room);
        self.send_buffer.extend(data[..accepted].iter());
        accepted
    }

    /// Compute the current receive window to advertise.
    pub(super) fn recv_window(&self) -> u16 {
        let available = MAX_RECV_BUFFER.saturating_sub(self.recv_buffer.len());
        (available >> DEFAULT_WINDOW_SCALE) as u16
    }
}

// ─── Connection key type ───

/// Uniquely identifies a TCP connection by (local_port, remote_ip,
/// remote_port).  `remote_ip` is dual-stack: an `IpAddress` so the same table
/// holds IPv4 and IPv6 connections (RFC 793 / RFC 2460).
pub(super) type ConnKey = (u16, IpAddress, u16);

// ─── Helpers ───

pub(super) fn simple_initial_seq(tick: u64) -> u32 {
    (tick as u32).wrapping_mul(0x9E37_79B9)
}
