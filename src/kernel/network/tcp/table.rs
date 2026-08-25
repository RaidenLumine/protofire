//! src/kernel/network/tcp/table.rs
//!
//! TCP connection table: registry of established connections, listeners with
//! their accept backlogs, and the native connection handle returned to the
//! socket layer.

use alloc::collections::btree_set::BTreeSet;
use alloc::collections::vec_deque::VecDeque;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::stack::NetworkStack;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

use super::types::ConnKey;
use super::types::SocketOptions;
use super::types::TcpConnectionState;
use super::types::TcpState;
use super::types::EPHEMERAL_PORT_END;
use super::types::EPHEMERAL_PORT_START;

/// Listener state: the listening port, the backlog of half-open / accepted
/// connections waiting for `accept`, and the configured backlog limit.
pub struct TcpListener {
    pub port: u16,
    pub backlog: VecDeque<Arc<Mutex<TcpConnectionState>>>,
    pub max_backlog: usize,
}

impl TcpListener {
    fn new(port: u16, max_backlog: usize) -> Self {
        Self {
            port,
            backlog: VecDeque::new(),
            max_backlog,
        }
    }
}

/// The central TCP registry: every established connection keyed by
/// `(local_port, remote_ip, remote_port)` and every listening socket keyed by
/// local port.
pub struct TcpConnectionTable {
    pub connections: BTreeMap<ConnKey, Arc<Mutex<TcpConnectionState>>>,
    pub listeners: BTreeMap<u16, TcpListener>,
    next_ephemeral_port: u16,
    /// Every local port currently reserved by a listener or a connection.
    used_ports: BTreeSet<u16>,
}

impl Default for TcpConnectionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpConnectionTable {
    pub fn new() -> Self {
        Self {
            connections: BTreeMap::new(),
            listeners: BTreeMap::new(),
            next_ephemeral_port: EPHEMERAL_PORT_START,
            used_ports: BTreeSet::new(),
        }
    }

    /// Allocate the next free ephemeral source port (49152..=65535).
    pub fn alloc_port(&mut self) -> Result<u16> {
        for _ in 0..=u16::MAX as usize {
            let port = self.next_ephemeral_port;
            self.next_ephemeral_port = if port == EPHEMERAL_PORT_END {
                EPHEMERAL_PORT_START
            } else {
                port + 1
            };
            if !self.used_ports.contains(&port) {
                self.used_ports.insert(port);
                return Ok(port);
            }
        }
        Err(Error::AlreadyExists)
    }

    /// Look up a connection by its full 4-tuple.
    pub fn lookup(
        &self,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<Arc<Mutex<TcpConnectionState>>> {
        self.connections
            .get(&(local_port, remote_ip, remote_port))
            .cloned()
    }

    /// Insert a connection state, keyed by its own 4-tuple.
    pub fn insert(&mut self, state: TcpConnectionState) -> Result<()> {
        let key = (state.local_port, state.remote_ip, state.remote_port);
        if self.connections.contains_key(&key) {
            return Err(Error::AlreadyExists);
        }
        self.used_ports.insert(state.local_port);
        self.connections.insert(key, Arc::new(Mutex::new(state)));
        Ok(())
    }

    /// Remove and return a connection by its 4-tuple.
    pub fn remove(
        &mut self,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<Arc<Mutex<TcpConnectionState>>> {
        self.connections
            .remove(&(local_port, remote_ip, remote_port))
    }

    /// Run per-tick retransmission and TimeWait expiry checks for every
    /// connection in the table.
    ///
    /// Returns the list of `(destination_ip, segment_bytes)` segments that
    /// need to be retransmitted.  The caller transmits them after releasing
    /// the table lock (dispatch does this in `advance_tick`).
    ///
    /// Connections that reach the retransmit limit or whose TimeWait period
    /// has elapsed are removed from the table.
    pub fn tick_maintenance(
        &mut self,
        stack: &crate::kernel::network::stack::NetworkStack,
    ) -> Vec<(Ipv4Addr, Vec<u8>)> {
        let keys: Vec<ConnKey> = self.connections.keys().cloned().collect();
        let mut pending: Vec<(Ipv4Addr, Vec<u8>)> = Vec::new();
        for (local_port, remote_ip, remote_port) in keys {
            let _ = super::ops::retransmit_check(self, stack, local_port, remote_ip, remote_port)
                .map(|mut segs| pending.append(&mut segs));
        }
        pending
    }
}

/// A lightweight, owned handle to an established TCP connection, returned by
/// `connect` / `accept` to the socket layer.
#[derive(Debug, Clone)]
pub struct NativeTcpConnection {
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
}

impl NativeTcpConnection {
    /// Render the remote endpoint as `"ip:port"`.
    pub fn endpoint(&self) -> String {
        let [a, b, c, d] = self.remote_ip;
        alloc::format!("{a}.{b}.{c}.{d}:{}", self.remote_port)
    }

    /// Read up to `buffer.len()` bytes from the connection's receive buffer
    /// (bare-metal only).
    ///
    /// When no data is available this spins on the tick counter until data
    /// arrives, the connection closes, or `timeout_ticks` elapse.
    /// `timeout_ticks == 0` is a non-blocking poll and returns `Ok(0)`
    /// immediately if nothing is buffered.
    pub fn read(
        &self,
        stack: &NetworkStack,
        buffer: &mut [u8],
        timeout_ticks: u64,
    ) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let start = stack.current_tick();
        loop {
            let conn = stack
                .tcp_table()
                .lock()
                .lookup(self.local_port, self.remote_ip, self.remote_port)
                .ok_or(Error::NotFound)?;
            let mut state = conn.lock();
            let n = state.read(buffer);
            let is_closed = state.state == TcpState::Closed;
            drop(state);
            if n > 0 || is_closed {
                return Ok(n);
            }
            if timeout_ticks == 0 {
                return Ok(0);
            }
            if stack.current_tick().wrapping_sub(start) >= timeout_ticks {
                return Err(Error::TimedOut);
            }
        }
    }

    /// Buffer `buffer` into the connection's send queue and flush as much as
    /// the peer's advertised window allows (bare-metal only).
    ///
    /// Returns the number of bytes accepted into the send queue.
    pub fn write(&self, table: &TcpConnectionTable, buffer: &[u8]) -> Result<usize> {
        let stack = NetworkStack::global().ok_or(Error::Unsupported)?;
        let conn = table
            .lookup(self.local_port, self.remote_ip, self.remote_port)
            .ok_or(Error::NotFound)?;
        let mut state = conn.lock();
        if state.state != TcpState::Established {
            return Err(Error::ConnectionReset);
        }
        let accepted = state.write(buffer);
        let pending = super::ops::try_flush_tcp_output(stack, &mut state, self.remote_ip);
        drop(state);
        for (dst, seg) in pending {
            let _ = super::segment::send_tcp_segment(stack, dst, &seg);
        }
        Ok(accepted)
    }

    /// Write the entire `buffer`, looping over partial writes until every
    /// byte has been accepted (bare-metal only).
    pub fn write_all(&self, stack: &NetworkStack, buffer: &[u8]) -> Result<()> {
        let mut written = 0;
        while written < buffer.len() {
            let table = stack.tcp_table().lock();
            let n = self.write(&table, &buffer[written..])?;
            drop(table);
            if n == 0 {
                return Err(Error::InternalError);
            }
            written += n;
        }
        Ok(())
    }

    /// Initiate an orderly close (FIN handshake) of this connection
    /// (bare-metal only).
    pub fn close(&self, stack: &NetworkStack) -> Result<()> {
        let mut table = stack.tcp_table().lock();
        let pending = super::ops::close(
            &mut table,
            stack,
            self.local_port,
            self.remote_ip,
            self.remote_port,
        )?;
        drop(table);
        for (dst, seg) in pending {
            let _ = super::segment::send_tcp_segment(stack, dst, &seg);
        }
        Ok(())
    }
}

/// Start listening on `port` with the given backlog limit.
///
/// Port 0 is rejected (it means "pick an ephemeral port" for a client
/// socket) and a port already reserved by a listener or an active
/// connection is rejected (RFC 793 §2.2).
pub fn listen(table: &mut TcpConnectionTable, port: u16, backlog: usize) -> Result<()> {
    if port == 0 {
        return Err(Error::InvalidArgument);
    }
    if table.used_ports.contains(&port) {
        return Err(Error::AlreadyExists);
    }
    table.used_ports.insert(port);
    table
        .listeners
        .insert(port, TcpListener::new(port, backlog));
    Ok(())
}

/// Stop listening on `port`.
pub fn unlisten(table: &mut TcpConnectionTable, port: u16) {
    table.listeners.remove(&port);
}

/// Pop the oldest pending connection off `port`'s backlog, or `None` if no
/// connection is waiting.
pub fn accept_nonblocking(
    table: &mut TcpConnectionTable,
    port: u16,
) -> Option<NativeTcpConnection> {
    let listener = table.listeners.get_mut(&port)?;
    let pending = listener.backlog.pop_front()?;
    let state = pending.lock();
    Some(NativeTcpConnection {
        local_port: state.local_port,
        remote_ip: state.remote_ip,
        remote_port: state.remote_port,
    })
}

/// Whether any connection is pending accept on `port`.
pub fn listener_has_pending(table: &TcpConnectionTable, port: u16) -> bool {
    table
        .listeners
        .get(&port)
        .is_some_and(|l| !l.backlog.is_empty())
}

// ─── Socket options ─────────────────────────────────────────────────────────

/// Apply a socket option to a TCP connection.
pub fn set_option(
    table: &TcpConnectionTable,
    conn: &NativeTcpConnection,
    level: u32,
    name: u32,
    val: &[u8],
) -> Result<()> {
    let conn_state = table
        .lookup(conn.local_port, conn.remote_ip, conn.remote_port)
        .ok_or(Error::NotFound)?;
    let mut state = conn_state.lock();
    set_option_impl(&mut state.options, level, name, val)
}

/// Read a socket option from a TCP connection.
pub fn get_option(
    table: &TcpConnectionTable,
    conn: &NativeTcpConnection,
    level: u32,
    name: u32,
) -> Result<Vec<u8>> {
    let conn_state = table
        .lookup(conn.local_port, conn.remote_ip, conn.remote_port)
        .ok_or(Error::NotFound)?;
    let state = conn_state.lock();
    get_option_impl(&state.options, level, name)
}

fn set_option_impl(opts: &mut SocketOptions, level: u32, name: u32, val: &[u8]) -> Result<()> {
    match level {
        1 => {
            // SOL_SOCKET
            match name {
                1 => opts.keepalive = read_bool(val)?,
                2 => opts.reuseaddr = read_bool(val)?,
                3 => opts.rcvtimeo = read_u64(val)?,
                4 => opts.sndtimeo = read_u64(val)?,
                5 => opts.rcvbuf = read_usize(val)?,
                6 => opts.sndbuf = read_usize(val)?,
                _ => return Err(Error::InvalidArgument),
            }
        }
        6 => {
            // IPPROTO_TCP
            match name {
                1 => opts.nodelay = read_bool(val)?,
                2 => opts.keepidle = read_u32(val)?,
                3 => opts.keepintvl = read_u32(val)?,
                4 => opts.keepcnt = read_u32(val)?,
                5 => opts.maxseg = read_usize(val)?,
                6 => opts.ecn_enabled = read_bool(val)?,
                _ => return Err(Error::InvalidArgument),
            }
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

fn get_option_impl(opts: &SocketOptions, level: u32, name: u32) -> Result<Vec<u8>> {
    match level {
        1 => match name {
            1 => Ok(alloc::vec![opts.keepalive as u8]),
            2 => Ok(alloc::vec![opts.reuseaddr as u8]),
            3 => Ok(opts.rcvtimeo.to_ne_bytes().to_vec()),
            4 => Ok(opts.sndtimeo.to_ne_bytes().to_vec()),
            5 => Ok((opts.rcvbuf as u64).to_ne_bytes().to_vec()),
            6 => Ok((opts.sndbuf as u64).to_ne_bytes().to_vec()),
            7 => Ok(0u32.to_ne_bytes().to_vec()), // SO_ERROR
            _ => Err(Error::InvalidArgument),
        },
        6 => match name {
            1 => Ok(alloc::vec![opts.nodelay as u8]),
            2 => Ok(opts.keepidle.to_ne_bytes().to_vec()),
            3 => Ok(opts.keepintvl.to_ne_bytes().to_vec()),
            4 => Ok(opts.keepcnt.to_ne_bytes().to_vec()),
            5 => Ok((opts.maxseg as u32).to_ne_bytes().to_vec()),
            6 => Ok(alloc::vec![opts.ecn_enabled as u8]),
            _ => Err(Error::InvalidArgument),
        },
        _ => Err(Error::InvalidArgument),
    }
}

fn read_bool(val: &[u8]) -> Result<bool> {
    if val.is_empty() {
        return Err(Error::InvalidArgument);
    }
    Ok(val[0] != 0)
}

fn read_u32(val: &[u8]) -> Result<u32> {
    if val.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    Ok(u32::from_ne_bytes([val[0], val[1], val[2], val[3]]))
}

fn read_u64(val: &[u8]) -> Result<u64> {
    if val.len() < 8 {
        return Err(Error::InvalidArgument);
    }
    Ok(u64::from_ne_bytes([
        val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
    ]))
}

fn read_usize(val: &[u8]) -> Result<usize> {
    if val.len() < core::mem::size_of::<usize>() {
        return Err(Error::InvalidArgument);
    }
    let mut bytes = [0u8; 8];
    bytes[..core::mem::size_of::<usize>()].copy_from_slice(&val[..core::mem::size_of::<usize>()]);
    Ok(usize::from_ne_bytes(bytes))
}
