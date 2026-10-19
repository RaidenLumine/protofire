//! src/network/udp.rs
//!
//! UDP protocol (RFC 768): datagram send / receive with port-based
//! demultiplexing and optional checksum.

use alloc::collections::btree_map::BTreeMap;
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::process::wait::Event;
use crate::kernel::process::wait::WaitQueue;
use crate::network::internet::ip::IpAddress;
use crate::network::internet::ipv4::IpProtocol;
use crate::network::internet::ipv4::Ipv4Addr;
use crate::network::internet::ipv4::Ipv4Header;
use crate::network::internet::ipv4::{self};
use crate::network::internet::ipv6::Ipv6Addr;
use crate::network::internet::ipv6::Ipv6Header;
use crate::network::internet::ipv6::Ipv6NextHeader;
use crate::network::internet::ipv6::{self};
use crate::Error;
use crate::Result;

// ─── UDP constants ───

/// UDP header size in bytes.
pub const UDP_HEADER_SIZE: usize = 8;

// ─── UDP header ───

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub header: UdpHeader,
    pub payload: Vec<u8>,
}

// ─── Parse / build ───

/// Parse a UDP datagram from a byte slice.
pub fn parse_datagram(data: &[u8]) -> Result<UdpDatagram> {
    if data.len() < UDP_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    let source_port = u16::from_be_bytes([data[0], data[1]]);
    let destination_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    let payload_len = (length as usize).saturating_sub(UDP_HEADER_SIZE);
    let payload = if payload_len > 0 && UDP_HEADER_SIZE + payload_len <= data.len() {
        Vec::from(&data[UDP_HEADER_SIZE..UDP_HEADER_SIZE + payload_len])
    } else if data.len() > UDP_HEADER_SIZE {
        Vec::from(&data[UDP_HEADER_SIZE..])
    } else {
        Vec::new()
    };

    Ok(UdpDatagram {
        header: UdpHeader {
            source_port,
            destination_port,
            length,
            checksum,
        },
        payload,
    })
}

/// Build a UDP datagram from header and payload.
pub fn build_datagram(header: &UdpHeader, payload: &[u8]) -> Vec<u8> {
    let total_len = (UDP_HEADER_SIZE + payload.len()) as u16;
    let mut buf = Vec::with_capacity(total_len as usize);
    buf.extend_from_slice(&header.source_port.to_be_bytes());
    buf.extend_from_slice(&header.destination_port.to_be_bytes());
    buf.extend_from_slice(&total_len.to_be_bytes());
    // Checksum placeholder (0 = no checksum for now)
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(payload);
    buf
}

/// Build a UDP datagram with a real checksum computed over the IPv4/IPv6
/// pseudo-header + UDP header + payload.
///
/// Per RFC 768 (IPv4) a zero checksum is legal, but RFC 8200 §8.1 makes a
/// zero UDP checksum *illegal* for IPv6 — receivers MUST discard such
/// datagrams — so outbound IPv6 UDP must always carry a real checksum.
/// A computed checksum of 0 is transmitted as 0xFFFF (the RFC 768
/// exception), which also guarantees the IPv6 field is never 0.
///
/// `src_ip` and `dst_ip` must be the same address family ([`IpAddress::V4`]
/// or [`IpAddress::V6`]); mismatched families produce a zero checksum as a
/// safe fallback.
pub fn build_datagram_with_checksum(
    header: &UdpHeader,
    payload: &[u8],
    src_ip: IpAddress,
    dst_ip: IpAddress,
) -> Vec<u8> {
    debug_assert!(
        UDP_HEADER_SIZE + payload.len() <= u16::MAX as usize,
        "UDP datagram exceeds maximum length"
    );
    let total_len = (UDP_HEADER_SIZE + payload.len()) as u16;
    let mut buf = Vec::with_capacity(total_len as usize);
    buf.extend_from_slice(&header.source_port.to_be_bytes());
    buf.extend_from_slice(&header.destination_port.to_be_bytes());
    buf.extend_from_slice(&total_len.to_be_bytes());
    // Checksum placeholder — zeroed during computation
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(payload);

    // Compute checksum over pseudo-header + UDP header + payload.
    let mut sum: u32 = 0;
    match (&src_ip, &dst_ip) {
        (IpAddress::V4(src), IpAddress::V4(dst)) => {
            ipv4::pseudo_header_checksum_add(
                &mut sum,
                *src,
                *dst,
                IpProtocol::Udp.to_u8(),
                total_len,
            );
        }
        (IpAddress::V6(src), IpAddress::V6(dst)) => {
            ipv6::pseudo_header_checksum_add(
                &mut sum,
                *src,
                *dst,
                Ipv6NextHeader::Udp.to_u8(),
                total_len as u32,
            );
        }
        _ => {
            // Mismatched address families — leave checksum as 0.
        }
    }
    ipv4::checksum_add(&mut sum, &buf);
    let checksum = ipv4::checksum_finalize(sum);
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };

    buf[6] = (checksum >> 8) as u8;
    buf[7] = checksum as u8;
    buf
}

// ─── UDP socket table ───

/// A bound UDP socket with a receive queue and a wait queue.
pub struct UdpSocket {
    pub local_port: u16,
    /// Queue of (source_ip, source_port, data) tuples.
    /// The source IP is an [`IpAddress`] to support both IPv4 and IPv6 peers.
    receive_queue: VecDeque<(IpAddress, u16, Vec<u8>)>,
    /// Waiters on this socket's receive queue.
    ///
    /// Its state is the number of datagrams waiting, which is also the length
    /// of `receive_queue`: `deliver` increments it after pushing and
    /// `recv_from` decrements it after popping.  Keeping the count on the wait
    /// queue is what lets a waiter decide whether to park without taking the
    /// socket table's lock — the lock order is table then wait queue, and a
    /// waiter holding the wait queue's lock while reaching back for the table
    /// would invert it against `deliver`.
    ready: WaitQueue<u64>,
}

impl UdpSocket {
    pub fn new(local_port: u16) -> Self {
        Self {
            local_port,
            receive_queue: VecDeque::new(),
            ready: WaitQueue::with_state(0),
        }
    }
}

/// A handle on one socket's readiness, taken under the table lock so the
/// handle outlives it.
///
/// The handle names the socket's wait queue through an `Arc`, so a waiter that
/// is still parked when the socket unbinds keeps a live queue to be woken on.
/// `wait` never touches the table: a caller must drain the socket with
/// `recv_from` before waiting again, which is the ordinary condition-variable
/// discipline.
///
/// It also carries the table's receive-request event, which it signals at the
/// moment it parks.  That is how the deferred receive thread learns that
/// somebody is waiting: without it the thread would have to wake on a timer
/// to look, and on an SMP machine each of those wakeups is a reschedule IPI
/// on a machine with nothing to do.
#[derive(Clone)]
pub struct DatagramWait {
    ready: WaitQueue<u64>,
    /// The table's receive-request event; see the type's own note.
    request: Arc<Event>,
}

impl DatagramWait {
    /// How many datagrams are queued right now.
    pub fn queued(&self) -> u64 {
        self.ready.with_lock(|pending, _| *pending)
    }

    /// Block until a datagram is queued or `deadline` passes.
    ///
    /// It does not say which of those happened, on purpose: whether the queue
    /// now has a datagram is a question the caller asks with `recv_from`, and
    /// whether its deadline passed is one it asks of the clock.  Both wakes —
    /// a delivery and the timer — are therefore the same event to this
    /// function, and the caller rechecks rather than trusting which one it
    /// was.  That is the standard condition-variable shape, and it is also the
    /// only one that means the same thing on a context switch and under the
    /// host's simulated scheduler, where the parked thread's frame does not
    /// resume.
    ///
    /// What it does answer is whether waiting was possible at all.  `true`
    /// means a datagram was already queued, or the thread parked and was
    /// resumed; `false` means there is no scheduler (or none is running a
    /// thread) and a datagram is not queued either.  A caller that loops on
    /// this question would otherwise spin forever on a clock that cannot
    /// advance, because the deadline it is watching is the scheduler's.
    ///
    /// The park is announced on the table's receive event before it happens.
    /// Order matters: the receiver thread is woken by that event, and if it
    /// ran first it would find nobody waiting and go back to sleep.  Signalled
    /// first, the thread is guaranteed to look after the waiter is linked.
    ///
    /// A delivery that lands between the caller's failed `recv_from` and this
    /// call is not lost: the queue's count is checked under the wait queue's
    /// own lock before the thread is added to it.
    pub fn wait(&self, deadline: u64) -> bool {
        if self.queued() != 0 {
            return true;
        }
        let Some(scheduler) = crate::kernel::process::Scheduler::global() else {
            return false;
        };
        // A scheduler with no current thread is a boot-time context: there is
        // nothing to park, and `block_current_until_if` would return without
        // parking, which the caller would read as a wake that never comes.
        if scheduler.current_thread().is_none() {
            return false;
        }

        let _ = self
            .ready
            .block_current_until_if(deadline, |pending, waiters, thread| {
                if *pending != 0 {
                    false
                } else {
                    waiters.push_back(thread.clone());
                    // Link first, then signal: the reverse order lets the
                    // receiver consume the signal, find nobody waiting and go
                    // back to sleep in the window before this thread is on the
                    // queue.  The wake runs with this socket's wait-queue lock
                    // held (the event releases its own first), which is safe
                    // because the lock order is one-way: the receive thread
                    // takes the table lock and then this queue, never the
                    // reverse, and the scheduler's own locks are released
                    // before a woken thread is dispatched.
                    self.request.signal();
                    true
                }
            });
        true
    }
}

/// First port the kernel hands to a UDP socket that asks for one.
///
/// Above NAT's translation range (`32768..=60999`, allocated in a table keyed
/// by port alone), so a port this allocator hands out cannot be one NAT would
/// translate a different connection to.  TCP and DCCP start at 49152 and stay
/// inside that overlap; their port space is separate from UDP's, which is why
/// only this one has to avoid it.
pub const UDP_EPHEMERAL_PORT_START: u16 = 61000;

/// Last port in the range.  The top of the IANA dynamic block.
pub const UDP_EPHEMERAL_PORT_END: u16 = 65535;

/// Table of bound UDP sockets, keyed by local port.
pub struct UdpSocketTable {
    sockets: BTreeMap<u16, UdpSocket>,
    /// Signalled when a receiver parks, and consumed by the deferred receive
    /// thread.
    ///
    /// It is an auto-reset event rather than a flag so a park that happens
    /// while the thread is between "I have no work" and "I am asleep" is not
    /// lost: the signal stays set until somebody takes it.
    receive_request: Arc<Event>,
    /// Where the next ephemeral allocation looks first.
    ///
    /// A cursor rather than a scan from the bottom: consecutive allocations
    /// land on different ports, so a datagram delayed from one lookup is not
    /// waiting on the port the next one is given.
    next_ephemeral_port: u16,
}

impl Default for UdpSocketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpSocketTable {
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            receive_request: Arc::new(Event::auto_reset(false)),
            next_ephemeral_port: UDP_EPHEMERAL_PORT_START,
        }
    }

    /// The event a waiter signals when it parks, and the receive thread waits
    /// on.  Cloned so the thread can hold it without the table's lock.
    pub fn receive_request(&self) -> Arc<Event> {
        Arc::clone(&self.receive_request)
    }

    /// Bind a UDP socket to `port`.
    pub fn bind(&mut self, port: u16) -> Result<()> {
        if self.sockets.contains_key(&port) {
            return Err(Error::AlreadyExists);
        }
        self.sockets.insert(port, UdpSocket::new(port));
        Ok(())
    }

    /// Bind whichever port in the dynamic range is free, and return it.
    ///
    /// The range is walked once, from the cursor, wrapping at the end.  The
    /// cursor advances past the port handed out, so two allocations in a row
    /// differ unless only one port is free.  `AlreadyExists` means the range
    /// is exhausted — the same answer, for the same condition, that
    /// `TcpConnectionTable::alloc_port` gives.
    pub fn bind_ephemeral(&mut self) -> Result<u16> {
        let span = UDP_EPHEMERAL_PORT_END - UDP_EPHEMERAL_PORT_START;
        for _ in 0..=span {
            let port = self.next_ephemeral_port;
            self.next_ephemeral_port = if port == UDP_EPHEMERAL_PORT_END {
                UDP_EPHEMERAL_PORT_START
            } else {
                port + 1
            };
            if let alloc::collections::btree_map::Entry::Vacant(slot) = self.sockets.entry(port) {
                slot.insert(UdpSocket::new(port));
                return Ok(port);
            }
        }
        Err(Error::AlreadyExists)
    }

    /// Unbind the socket at `port`.
    ///
    /// Waiters parked on the socket are woken so they can observe its absence
    /// rather than sleeping until their deadlines; the wait queue itself stays
    /// alive through their handles.  The count goes back to zero first: the
    /// datagrams went with the socket, and a waiter that saw a stale count
    /// would return to a queue that is no longer there and spin.
    pub fn unbind(&mut self, port: u16) {
        if let Some(socket) = self.sockets.remove(&port) {
            socket.ready.with_lock(|pending, _| *pending = 0);
            socket.ready.wake_all();
        }
    }

    /// Take a readiness handle for the socket bound at `port`.
    ///
    /// `None` when nothing is bound.  The handle is meant to be taken, the
    /// table lock released, and the handle waited on; a waiter that finds the
    /// queue empty parks on the socket and is woken by `deliver`.
    pub fn readiness(&self, port: u16) -> Option<DatagramWait> {
        self.sockets.get(&port).map(|socket| DatagramWait {
            ready: socket.ready.clone(),
            request: Arc::clone(&self.receive_request),
        })
    }

    /// Deliver a datagram to the bound socket at `dst_port`.
    /// Returns `true` if delivered, `false` if no socket is bound to the port.
    /// `src_ip` is an [`IpAddress`] to support both IPv4 and IPv6 peers.
    ///
    /// The datagram is queued before a waiter is woken, under the same lock
    /// that publishes the count, so a waiter that observes a wake and finds
    /// the queue empty can only be looking at a datagram another waiter took.
    pub fn deliver(
        &mut self,
        src_ip: impl Into<IpAddress>,
        src_port: u16,
        dst_port: u16,
        data: Vec<u8>,
    ) -> bool {
        if let Some(socket) = self.sockets.get_mut(&dst_port) {
            socket
                .receive_queue
                .push_back((src_ip.into(), src_port, data));
            socket.ready.wake_with(|pending, waiters, waking| {
                *pending = pending.saturating_add(1);
                if let Some(thread) = WaitQueue::<u64>::take_next_waiter(waiters) {
                    waking.push(thread);
                }
            });
            true
        } else {
            false
        }
    }

    /// Receive a datagram from `port`'s queue.
    /// Returns `(bytes_read, src_ip, src_port)` on success.
    /// Returns `Err(TimedOut)` when the queue is empty (non-blocking).
    pub fn recv_from(&mut self, port: u16, buffer: &mut [u8]) -> Result<(usize, IpAddress, u16)> {
        let socket = self.sockets.get_mut(&port).ok_or(Error::NotFound)?;
        match socket.receive_queue.pop_front() {
            Some((src_ip, src_port, data)) => {
                let len = data.len().min(buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                // Keep the wait-queue count equal to the queue length; it is
                // what a waiter reads to decide whether to park.
                socket
                    .ready
                    .with_lock(|pending, _| *pending = pending.saturating_sub(1));
                Ok((len, src_ip, src_port))
            }
            None => Err(Error::TimedOut),
        }
    }

    /// Check whether the socket at `port` has a datagram queued for receive.
    pub fn has_pending(&self, port: u16) -> bool {
        self.sockets
            .get(&port)
            .is_some_and(|socket| !socket.receive_queue.is_empty())
    }

    /// Whether any bound socket has a parked receiver.
    ///
    /// This is the question the deferred receive thread asks before deciding
    /// to drive the device: work somebody is waiting for, or a receive nobody
    /// asked for.  It reads the wait queues rather than a separate
    /// registration counter, so there is no count to underflow on a timeout or
    /// to leave raised for a waiter that was cancelled — a thread that is no
    /// longer waiting is pruned by `waiter_count`.
    pub fn any_waiter(&self) -> bool {
        self.sockets
            .values()
            .any(|socket| socket.ready.waiter_count() != 0)
    }

    /// Whether any port in the dynamic range is bound.
    ///
    /// What a leak check asks: a lookup that returned, however it returned,
    /// must not leave its port behind.
    #[cfg(any(test, not(target_os = "none")))]
    pub fn any_ephemeral_bound(&self) -> bool {
        self.sockets
            .keys()
            .any(|port| (UDP_EPHEMERAL_PORT_START..=UDP_EPHEMERAL_PORT_END).contains(port))
    }

    /// Check if a port is bound.
    pub fn is_bound(&self, port: u16) -> bool {
        self.sockets.contains_key(&port)
    }

    /// Number of bound sockets.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Returns true when no sockets are bound.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
}

// ─── Integration helpers ───

/// Build an IPv4 packet containing a UDP datagram.
pub fn build_udp_ipv4_packet(
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let header = UdpHeader {
        source_port,
        destination_port: dest_port,
        length: 0, // computed by build_datagram_with_checksum
        checksum: 0,
    };
    let udp_bytes = build_datagram_with_checksum(
        &header,
        payload,
        IpAddress::V4(source_ip),
        IpAddress::V4(dest_ip),
    );

    let ip_header = Ipv4Header {
        total_length: 0,
        identification: 0,
        flags_fragment_offset: 0,
        ttl: ipv4::IPV4_DEFAULT_TTL,
        protocol: IpProtocol::Udp,
        header_checksum: 0,
        source: source_ip,
        destination: dest_ip,
    };

    ipv4::build_packet(&ip_header, &udp_bytes)
}

/// Build an IPv6 packet containing a UDP datagram.
pub fn build_udp_ipv6_packet(
    source_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
    source_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let header = UdpHeader {
        source_port,
        destination_port: dest_port,
        length: 0,
        checksum: 0,
    };
    let udp_bytes = build_datagram_with_checksum(
        &header,
        payload,
        IpAddress::V6(source_ip),
        IpAddress::V6(dest_ip),
    );

    let ip_header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: Ipv6NextHeader::Udp,
        hop_limit: ipv6::IPV6_DEFAULT_HOP_LIMIT,
        source: source_ip,
        destination: dest_ip,
    };

    ipv6::build_packet(&ip_header, &udp_bytes)
}

/// Send a UDP datagram through the network stack (IPv4).
///
/// The source port must have been previously bound via
/// [`UdpSocketTable::bind`].  This function verifies the binding under
/// a short-lived lock, then releases it before calling into the network
/// stack send path — avoiding the deadlock that would arise from
/// holding the UDP table lock across `send_ipv4_packet` → ARP resolution
/// → `poll()`.
///
/// Returns [`Error::NotFound`](crate::Error::NotFound) if `src_port`
/// is not bound.
pub fn send_to(
    stack: &crate::network::stack::NetworkStack,
    src_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    payload: &[u8],
) -> Result<()> {
    // Verify the port is bound (short-lived lock — released before
    // we call into the send path so poll() can safely acquire the
    // UDP table lock for incoming datagram delivery).
    {
        let table = stack.udp_table().lock();
        if !table.is_bound(src_port) {
            return Err(Error::NotFound);
        }
    }

    let raw = build_udp_ipv4_packet(stack.local_ip(), dest_ip, src_port, dest_port, payload);
    stack.profiler.inc_udp_datagrams_tx();
    stack.send_ipv4_packet(dest_ip, raw)
}

/// Send a UDP datagram through the network stack (IPv6).
///
/// Same contract as [`send_to`] but uses IPv6 addressing and NDP for
/// MAC resolution.
pub fn send_to_v6(
    stack: &crate::network::stack::NetworkStack,
    src_port: u16,
    dest_ip: Ipv6Addr,
    dest_port: u16,
    payload: &[u8],
) -> Result<()> {
    {
        let table = stack.udp_table().lock();
        if !table.is_bound(src_port) {
            return Err(Error::NotFound);
        }
    }

    let src = stack.local_ip_v6();
    let raw = build_udp_ipv6_packet(src, dest_ip, src_port, dest_port, payload);
    stack.profiler.inc_udp_datagrams_tx();
    stack.send_ipv6_packet(dest_ip, raw)
}

// ─── tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_build_round_trip() {
        let header = UdpHeader {
            source_port: 12345,
            destination_port: 53,
            length: 0,
            checksum: 0,
        };
        let raw = build_datagram(&header, b"dns query");
        let parsed = parse_datagram(&raw).expect("should parse");

        assert_eq!(parsed.header.source_port, 12345);
        assert_eq!(parsed.header.destination_port, 53);
        assert_eq!(parsed.header.length, 8 + 9); // header + payload
        assert_eq!(&parsed.payload, b"dns query");
    }

    #[test]
    fn parse_rejects_short_data() {
        assert_eq!(parse_datagram(&[0u8; 4]), Err(Error::InvalidArgument));
    }

    #[test]
    fn bind_and_unbind() {
        let mut table = UdpSocketTable::new();
        assert!(table.is_empty());

        table.bind(8080).expect("bind should succeed");
        assert!(table.is_bound(8080));
        assert_eq!(table.len(), 1);

        // Duplicate bind should fail
        assert_eq!(table.bind(8080), Err(Error::AlreadyExists));

        table.unbind(8080);
        assert!(!table.is_bound(8080));
        assert!(table.is_empty());
    }

    /// Every allocation is distinct, in range, and the next one differs.
    ///
    /// A rotating cursor is the reason the second half matters: two lookups
    /// in a row must not be given the same port, or a datagram delayed from
    /// the first is waiting on the second's socket.
    #[test]
    fn ephemeral_allocations_are_distinct_and_in_range() {
        let mut table = UdpSocketTable::new();
        let mut seen = alloc::collections::BTreeSet::new();
        for _ in 0..64 {
            let port = table.bind_ephemeral().expect("a free port");
            assert!(
                (UDP_EPHEMERAL_PORT_START..=UDP_EPHEMERAL_PORT_END).contains(&port),
                "port {port} is outside the dynamic range"
            );
            assert!(seen.insert(port), "port {port} was handed out twice");
        }
        // Consecutive allocations differ, which is the cursor rather than a
        // scan from the bottom.
        let first = table.bind_ephemeral().expect("a free port");
        let second = table.bind_ephemeral().expect("a free port");
        assert_ne!(first, second);
    }

    /// The range is finite and says so when it is spent.
    #[test]
    fn exhausting_the_range_answers_already_exists() {
        let mut table = UdpSocketTable::new();
        let mut bound = 0u32;
        while table.bind_ephemeral().is_ok() {
            bound += 1;
            assert!(
                bound <= 10_000,
                "the allocator handed out more ports than the range holds"
            );
        }
        assert_eq!(
            bound,
            (UDP_EPHEMERAL_PORT_END - UDP_EPHEMERAL_PORT_START + 1) as u32,
            "every port in the range was handed out once"
        );
        assert_eq!(table.bind_ephemeral(), Err(Error::AlreadyExists));

        // Releasing one is enough to get an allocation again.
        table.unbind(UDP_EPHEMERAL_PORT_START);
        assert_eq!(table.bind_ephemeral(), Ok(UDP_EPHEMERAL_PORT_START));
    }

    #[test]
    fn send_and_receive() {
        let mut table = UdpSocketTable::new();
        table.bind(9000).expect("bind");

        // Deliver a datagram
        assert!(table.deliver([10, 0, 2, 100], 12345, 9000, b"hello udp".to_vec()));

        // Receive it
        let mut buf = [0u8; 64];
        let (n, src_ip, src_port) = table.recv_from(9000, &mut buf).expect("should recv");
        assert_eq!(n, 9);
        assert_eq!(&buf[..n], b"hello udp");
        assert_eq!(
            src_ip,
            crate::network::internet::ip::IpAddress::V4([10, 0, 2, 100])
        );
        assert_eq!(src_port, 12345);

        // Queue should be empty now
        assert_eq!(table.recv_from(9000, &mut buf), Err(Error::TimedOut));
    }

    #[test]
    fn deliver_to_unbound_port_returns_false() {
        let mut table = UdpSocketTable::new();
        let delivered = table.deliver([10, 0, 2, 1], 53, 9999, b"drop me".to_vec());
        assert!(!delivered);
        assert!(table.is_empty());
    }

    #[test]
    fn recv_from_unbound_port_returns_not_found() {
        let mut table = UdpSocketTable::new();
        let mut buf = [0u8; 64];
        assert_eq!(table.recv_from(9999, &mut buf), Err(Error::NotFound));
    }

    /// The wait queue's count is the receive queue's length, at every step.
    ///
    /// The count is what a waiter reads to decide whether to park, so a drift
    /// between it and the queue is a waiter that either sleeps through a
    /// datagram or returns to an empty queue forever.  Both operations that
    /// move one move the other, and this pins that they move together —
    /// including the unbind that throws the queue away.
    #[test]
    fn the_wait_queues_count_is_the_receive_queues_length() {
        let mut table = UdpSocketTable::new();
        table.bind(9100).expect("bind");
        let wait = table.readiness(9100).expect("readiness handle");
        assert_eq!(wait.queued(), 0);

        for index in 0..3 {
            assert!(table.deliver([10, 0, 2, 1], 53, 9100, alloc::vec![index as u8]));
            assert_eq!(wait.queued(), index + 1);
        }

        let mut buffer = [0u8; 8];
        for remaining in (0..3).rev() {
            table.recv_from(9100, &mut buffer).expect("a datagram");
            assert_eq!(wait.queued(), remaining);
        }

        // A queued datagram that unbind discards must not leave a count
        // behind: the handle outlives the socket, and a waiter that still
        // held one would return to a queue that is gone.
        assert!(table.deliver([10, 0, 2, 1], 53, 9100, alloc::vec![0]));
        assert_eq!(wait.queued(), 1);
        table.unbind(9100);
        assert_eq!(wait.queued(), 0);
    }

    #[test]
    fn recv_truncates_to_buffer() {
        let mut table = UdpSocketTable::new();
        table.bind(1).expect("bind");
        assert!(table.deliver([0; 4], 0, 1, b"long message".to_vec()));

        let mut buf = [0u8; 4];
        let (n, _, _) = table.recv_from(1, &mut buf).expect("should recv");
        assert_eq!(n, 4);
        assert_eq!(&buf, b"long");
    }

    #[test]
    fn build_udp_ipv4_is_valid_packet() {
        let raw = build_udp_ipv4_packet([10, 0, 2, 15], [10, 0, 2, 2], 12345, 53, b"test");

        // Should be parseable as IPv4
        let ip_packet = ipv4::parse_packet(&raw).expect("should parse IPv4");
        assert_eq!(ip_packet.header.protocol, IpProtocol::Udp);
        assert_eq!(ip_packet.header.source, [10, 0, 2, 15]);
        assert_eq!(ip_packet.header.destination, [10, 0, 2, 2]);

        // Should be parseable as UDP
        let udp = parse_datagram(&ip_packet.payload).expect("should parse UDP");
        assert_eq!(udp.header.source_port, 12345);
        assert_eq!(udp.header.destination_port, 53);
        assert_eq!(&udp.payload, b"test");
    }

    // ─── send_to tests (needs a NetworkStack with mock device) ───

    use crate::network::link::device::mock::MockNetworkDevice;
    use crate::network::link::ethernet::MacAddress;
    use crate::network::stack::NetworkStack;
    use alloc::sync::Arc;

    fn make_test_stack() -> &'static NetworkStack {
        // SAFETY: the caller's contract is that nothing is using the stack; this
        // test helper calls it before installing the stack it goes on to use.
        unsafe {
            NetworkStack::uninstall_global();
        }
        let dev = Arc::new(MockNetworkDevice::new(
            "udp-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(dev, [10, 0, 2, 15]);
        NetworkStack::global().expect("stack should be initialised")
    }

    #[test]
    fn send_to_rejects_unbound_port() {
        let stack = make_test_stack();
        // No port bound, and send_to checks binding before touching
        // ARP — so this works even without a populated ARP cache.
        assert_eq!(
            send_to(stack, 9000, [10, 0, 2, 100], 53, b"data"),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn send_to_succeeds_for_bound_port() {
        let stack = make_test_stack();
        {
            stack.udp_table().lock().bind(9000).expect("bind");
        } // release lock before calling send_to
          // Pre-populate the ARP cache so resolve_mac doesn't spin-wait
          // (ticks never advance in test — no scheduler running).
        stack.arp_cache().lock().insert(
            [10, 0, 2, 100],
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );
        assert!(send_to(stack, 9000, [10, 0, 2, 100], 53, b"hello").is_ok());
    }

    #[test]
    fn udp_bind_send_recv_round_trip() {
        let stack = make_test_stack();
        {
            let mut table = stack.udp_table().lock();
            table.bind(9000).expect("bind");
        }

        // Pre-populate ARP cache so send_to's resolve_mac won't hang.
        stack.arp_cache().lock().insert(
            [10, 0, 2, 100],
            MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            stack.current_tick(),
        );

        // Send a datagram through the stack.
        send_to(stack, 9000, [10, 0, 2, 100], 53, b"ping").expect("send_to");

        // Simulate the peer replying by delivering a response directly
        // to the socket's receive queue.
        {
            let mut table = stack.udp_table().lock();
            assert!(table.deliver([10, 0, 2, 100], 53, 9000, b"pong".to_vec()));
        }

        // Receive the reply.
        let mut table = stack.udp_table().lock();
        let mut buf = [0u8; 64];
        let (n, src_ip, src_port) = table.recv_from(9000, &mut buf).expect("recv_from");
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(
            src_ip,
            crate::network::internet::ip::IpAddress::V4([10, 0, 2, 100])
        );
        assert_eq!(src_port, 53);
    }
}
