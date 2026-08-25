//! src/kernel/network/dccp/table.rs
//!
//! DCCP connection table, listeners, and per-connection state.

use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use alloc::collections::vec_deque::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

use super::ccid2::Ccid2State;
use super::options::FeatureState;

/// Mask for 48-bit sequence-number arithmetic.
pub const SEQ_MASK: u64 = 0xFFFF_FFFF_FFFF;

/// Return `true` if `value` lies within `[low, high]` in 48-bit wraparound
/// sequence-number space (RFC 4340 §7.1).
pub fn seq_between(value: u64, low: u64, high: u64) -> bool {
    let value = value & SEQ_MASK;
    let low = low & SEQ_MASK;
    let high = high & SEQ_MASK;
    let distance = value.wrapping_sub(low) & SEQ_MASK;
    let span = high.wrapping_sub(low) & SEQ_MASK;
    distance <= span
}

/// Connection key: the local port plus the remote endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DccpConnKey {
    pub local_port: u16,
    pub remote: IpAddress,
    pub remote_port: u16,
}

/// DCCP connection state (RFC 4340 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DccpState {
    Closed,
    Listen,
    /// Client has sent Request, awaiting Response.
    Request,
    /// Server has sent Response, awaiting Ack.
    Respond,
    /// Client has received Response (server waits for Ack).
    PartOpen,
    Open,
    /// Received CloseReq, awaiting Close.
    CloseReq,
    /// Sent Close, awaiting Close.
    Closing,
    TimeWait,
}

/// Per-connection DCCP state machine state.
#[derive(Debug, Clone)]
pub struct DccpConnectionState {
    pub key: DccpConnKey,
    pub state: DccpState,
    /// Initial sent sequence number.
    pub iss: u64,
    /// Greatest sequence number sent.
    pub gss: u64,
    /// Initial received sequence number.
    pub isr: u64,
    /// Greatest sequence number received.
    pub gsr: u64,
    /// Sequence window low / high bounds.
    pub swl: u64,
    pub swh: u64,
    pub service_code: u32,
    pub features: FeatureState,
    pub ccid2: Ccid2State,
    /// Inbound application data, one DCCP datagram per entry.
    pub receive_queue: VecDeque<Vec<u8>>,
    /// Sequence number of the last packet requiring a reply (for Ack).
    pub last_recv_seq: Option<u64>,
    /// Retransmission deadline (tick) for the active request/sync.
    pub retransmit_deadline: Option<u64>,
    pub retransmit_count: u32,
    /// The pending packet to retransmit (destination + DCCP segment), set
    /// while in `Request` / `Closing`.
    pub retransmit_packet: Option<(IpAddress, Vec<u8>)>,
    /// TimeWait expiry deadline (tick).
    pub timewait_deadline: Option<u64>,
}

impl DccpConnectionState {
    /// A freshly allocated connection with the given initial sent sequence.
    pub fn new(key: DccpConnKey, iss: u64, service_code: u32) -> Self {
        Self {
            key,
            state: DccpState::Request,
            iss,
            gss: iss,
            isr: 0,
            gsr: 0,
            swl: 0,
            swh: 0,
            service_code,
            features: FeatureState::default(),
            ccid2: Ccid2State::new(),
            receive_queue: VecDeque::new(),
            last_recv_seq: None,
            retransmit_deadline: None,
            retransmit_count: 0,
            retransmit_packet: None,
            timewait_deadline: None,
        }
    }
}

/// A listening DCCP socket.
#[derive(Debug, Clone)]
pub struct DccpListener {
    pub port: u16,
    pub backlog: u16,
    pub service_code: u32,
    /// Connection keys waiting to be accepted.
    pub pending: VecDeque<DccpConnKey>,
}

/// The per-stack DCCP connection table.
#[derive(Default)]
pub struct DccpConnectionTable {
    pub(crate) connections: BTreeMap<DccpConnKey, Arc<Mutex<DccpConnectionState>>>,
    listeners: BTreeMap<u16, DccpListener>,
    used_ports: BTreeSet<u16>,
    next_ephemeral_port: u16,
}

impl DccpConnectionTable {
    pub fn new() -> Self {
        Self {
            connections: BTreeMap::new(),
            listeners: BTreeMap::new(),
            used_ports: BTreeSet::new(),
            next_ephemeral_port: 49152,
        }
    }

    pub fn lookup(&self, key: &DccpConnKey) -> Option<Arc<Mutex<DccpConnectionState>>> {
        self.connections.get(key).cloned()
    }

    pub fn insert(&mut self, state: DccpConnectionState) -> Result<()> {
        let key = state.key;
        if self.connections.contains_key(&key) {
            return Err(Error::AlreadyExists);
        }
        self.used_ports.insert(key.local_port);
        self.connections.insert(key, Arc::new(Mutex::new(state)));
        Ok(())
    }

    pub fn remove(&mut self, key: &DccpConnKey) -> Option<Arc<Mutex<DccpConnectionState>>> {
        self.connections.remove(key)
    }

    pub fn listener(&self, port: u16) -> Option<&DccpListener> {
        self.listeners.get(&port)
    }

    pub fn listener_mut(&mut self, port: u16) -> Option<&mut DccpListener> {
        self.listeners.get_mut(&port)
    }

    /// Reserve `port` for a local socket (bind).
    pub fn bind(&mut self, port: u16) -> Result<()> {
        if port == 0 || self.used_ports.contains(&port) {
            return Err(Error::AlreadyExists);
        }
        self.used_ports.insert(port);
        Ok(())
    }

    /// Release a previously reserved port.
    pub fn unbind(&mut self, port: u16) {
        self.used_ports.remove(&port);
    }

    /// Install a listener on `port`.
    pub fn listen(&mut self, port: u16, backlog: u16, service_code: u32) -> Result<()> {
        if self.listeners.contains_key(&port) {
            return Err(Error::AlreadyExists);
        }
        self.used_ports.insert(port);
        self.listeners.insert(
            port,
            DccpListener {
                port,
                backlog,
                service_code,
                pending: VecDeque::new(),
            },
        );
        Ok(())
    }

    /// Whether the listener at `port` has pending connection keys.
    pub fn listener_has_pending(&self, port: u16) -> bool {
        self.listeners
            .get(&port)
            .map(|listener| !listener.pending.is_empty())
            .unwrap_or(false)
    }

    /// Remove the listener at `port`.
    pub fn remove_listener(&mut self, port: u16) {
        self.listeners.remove(&port);
    }

    /// Allocate an ephemeral local port not currently in use.
    pub fn alloc_ephemeral_port(&mut self) -> u16 {
        for _ in 0..=0xFFFF {
            let port = self.next_ephemeral_port;
            self.next_ephemeral_port = self.next_ephemeral_port.wrapping_add(1).max(49152);
            if !self.used_ports.contains(&port) && !self.listeners.contains_key(&port) {
                self.used_ports.insert(port);
                return port;
            }
        }
        0
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

/// User-space handle to an established DCCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeDccpConnection {
    pub local_port: u16,
    pub remote_ip: IpAddress,
    pub remote_port: u16,
}

impl NativeDccpConnection {
    pub fn key(&self) -> DccpConnKey {
        DccpConnKey {
            local_port: self.local_port,
            remote: self.remote_ip,
            remote_port: self.remote_port,
        }
    }

    pub fn endpoint(&self) -> String {
        match self.remote_ip {
            IpAddress::V4(v4) => {
                alloc::format!(
                    "{}.{}.{}.{}:{}",
                    v4[0],
                    v4[1],
                    v4[2],
                    v4[3],
                    self.remote_port
                )
            }
            IpAddress::V6(_) => alloc::format!("[v6]:{}", self.remote_port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> DccpConnKey {
        DccpConnKey {
            local_port: port,
            remote: IpAddress::V4([10, 0, 2, 100]),
            remote_port: 5000,
        }
    }

    #[test]
    fn bind_and_unbind_port() {
        let mut table = DccpConnectionTable::new();
        assert!(table.bind(9000).is_ok());
        assert!(table.bind(9000).is_err(), "double bind must fail");
        table.unbind(9000);
        assert!(table.bind(9000).is_ok(), "rebind after unbind");
    }

    #[test]
    fn ephemeral_ports_are_unique() {
        let mut table = DccpConnectionTable::new();
        let _ = table.bind(49152);
        let port = table.alloc_ephemeral_port();
        assert_ne!(port, 49152);
        assert!(!table.used_ports.contains(&49153) || port == 49153);
    }

    #[test]
    fn listener_and_accept_queue() {
        let mut table = DccpConnectionTable::new();
        assert!(table.listen(8000, 4, 0x1234).is_ok());
        assert!(table.listen(8000, 4, 0x1234).is_err(), "double listen");
        let listener = table.listener(8000).expect("listener exists");
        assert_eq!(listener.service_code, 0x1234);
        assert!(!table.listener_has_pending(8000));
    }

    #[test]
    fn insert_lookup_remove() {
        let mut table = DccpConnectionTable::new();
        let k = key(7000);
        assert!(table.insert(DccpConnectionState::new(k, 5, 0)).is_ok());
        assert!(table.insert(DccpConnectionState::new(k, 5, 0)).is_err());
        assert!(table.lookup(&k).is_some());
        table.remove(&k);
        assert!(table.lookup(&k).is_none());
    }

    #[test]
    fn sequence_window_arithmetic() {
        // Within the window (bounds inclusive).
        assert!(seq_between(100, 90, 110));
        assert!(seq_between(90, 90, 110));
        assert!(seq_between(110, 90, 110));
        // Far outside.
        assert!(!seq_between(200, 90, 110));
        assert!(!seq_between(80, 90, 110));
        // Wraparound: the window [MAX-1, 10] wraps across zero.
        assert!(seq_between(0xFFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFE, 10));
        assert!(seq_between(0, 0xFFFF_FFFF_FFFE, 10));
        assert!(seq_between(5, 0xFFFF_FFFF_FFFE, 10));
        assert!(seq_between(10, 0xFFFF_FFFF_FFFE, 10));
        // Below the low bound of the wrapped window.
        assert!(!seq_between(0xFFFF_FFFF_FFFF - 5, 0xFFFF_FFFF_FFFE, 10));
    }
}
