//! src/kernel/audit/types.rs
//! Audit event type definitions, record format, and enable-mask constants.

use core::fmt;

/// Type of audit event.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    /// Syscall entry/exit.
    Syscall = 0,
    /// File open, close, read, write, etc.
    FileOp = 1,
    /// Process fork, spawn, exec, exit.
    ProcessCreate = 2,
    /// TCP/UDP connect, bind, send, recv.
    NetworkConnect = 3,
    /// Authentication events (login, password change).
    AuthEvent = 4,
    /// Kernel or security configuration changes.
    ConfigChange = 5,
    /// A mandatory-access-control (MAC) policy denial.
    MacDenial = 6,
}

impl AuditEventType {
    /// Convert to a human-readable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syscall => "syscall",
            Self::FileOp => "file_op",
            Self::ProcessCreate => "process_create",
            Self::NetworkConnect => "network_connect",
            Self::AuthEvent => "auth_event",
            Self::ConfigChange => "config_change",
            Self::MacDenial => "mac_denial",
        }
    }
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Enable-mask bit constants ─────────────────────────────────────────────
//
// These bits are used in the per-process `audit_enable_mask` to selectively
// enable/disable audit event types, avoiding any overhead when auditing is
// not needed.

pub const AUDIT_ENABLE_SYSCALL: u64 = 1 << 0;
pub const AUDIT_ENABLE_FILE_OP: u64 = 1 << 1;
pub const AUDIT_ENABLE_PROCESS_CREATE: u64 = 1 << 2;
pub const AUDIT_ENABLE_NETWORK_CONNECT: u64 = 1 << 3;
pub const AUDIT_ENABLE_AUTH_EVENT: u64 = 1 << 4;
pub const AUDIT_ENABLE_CONFIG_CHANGE: u64 = 1 << 5;
pub const AUDIT_ENABLE_MAC: u64 = 1 << 6;

/// Mask covering all known audit enable bits.
pub const AUDIT_ENABLE_ALL: u64 = AUDIT_ENABLE_SYSCALL
    | AUDIT_ENABLE_FILE_OP
    | AUDIT_ENABLE_PROCESS_CREATE
    | AUDIT_ENABLE_NETWORK_CONNECT
    | AUDIT_ENABLE_AUTH_EVENT
    | AUDIT_ENABLE_CONFIG_CHANGE
    | AUDIT_ENABLE_MAC;

/// Return the enable-mask bit for a given `AuditEventType`.
pub const fn audit_enable_bit(event_type: AuditEventType) -> u64 {
    1 << (event_type as u8)
}

// ── AuditRecord ───────────────────────────────────────────────────────────
//
// Fixed-size (256-byte) record stored in the kernel's audit ring buffer.
// The ring buffer uses lock-free atomics and needs deterministic entry sizes.
//
// repr(C) layout (natural alignment):
//
//   offset  size  field
//       0     8   id        (u64)
//       8     8   sequence  (u64)
//      16     8   timestamp (u64)
//      24     4   pid       (u32)
//      28     4   uid       (u32)
//      32     8   result    (i64)
//      40     4   data_len  (u32)
//      44     1   event_type(u8)
//      45   211   data      ([u8; 211])
//
// Total: 45 + 211 = 256 bytes.  256 is a multiple of max alignment (8) so no
// trailing padding is required.

/// Fixed-size audit record (exactly 256 bytes).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct AuditRecord {
    /// Monotonically increasing record identifier.
    pub id: u64,
    /// Same as `id` — kept as a separate field for backward compat.
    pub sequence: u64,
    /// Timestamp (scheduler tick) at which the event was captured.
    pub timestamp: u64,
    /// PID of the process that triggered the event.
    pub pid: u32,
    /// UID of the user that owns the process.
    pub uid: u32,
    /// Syscall return value or status (0 = success, negative = error).
    pub result: i64,
    /// Length of meaningful data in the `data` field.
    pub data_len: u32,
    /// One of [`AuditEventType`] as a raw byte.
    pub event_type: u8,
    /// Variable payload padded to fill the record (211 bytes).
    pub data: [u8; 211],
}

// Compile-time size check: AuditRecord must be exactly 256 bytes.
const _: [(); 256] = [(); core::mem::size_of::<AuditRecord>()];

impl AuditRecord {
    /// Create a zero-initialised audit record.
    pub const fn zeroed() -> Self {
        Self {
            id: 0,
            sequence: 0,
            timestamp: 0,
            pid: 0,
            uid: 0,
            result: 0,
            data_len: 0,
            event_type: 0,
            data: [0; 211],
        }
    }

    /// Fill a record from its components.
    #[allow(clippy::too_many_arguments)]
    pub fn fill(
        &mut self,
        id: u64,
        sequence: u64,
        timestamp: u64,
        event_type: AuditEventType,
        pid: u32,
        uid: u32,
        result: i64,
        payload: &[u8],
    ) {
        self.id = id;
        self.sequence = sequence;
        self.timestamp = timestamp;
        self.event_type = event_type as u8;
        self.pid = pid;
        self.uid = uid;
        self.result = result;
        let copy_len = payload.len().min(self.data.len());
        self.data[..copy_len].copy_from_slice(&payload[..copy_len]);
        self.data_len = copy_len as u32;
    }

    /// Return the event type as an `AuditEventType`, defaulting to `Syscall`
    /// if the raw byte is out of range.
    pub fn event_type_enum(&self) -> AuditEventType {
        match self.event_type {
            0 => AuditEventType::Syscall,
            1 => AuditEventType::FileOp,
            2 => AuditEventType::ProcessCreate,
            3 => AuditEventType::NetworkConnect,
            4 => AuditEventType::AuthEvent,
            5 => AuditEventType::ConfigChange,
            6 => AuditEventType::MacDenial,
            _ => AuditEventType::Syscall,
        }
    }

    /// Return the payload as a byte slice.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.data_len as usize]
    }
}

impl fmt::Debug for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditRecord")
            .field("id", &self.id)
            .field("sequence", &self.sequence)
            .field("timestamp", &self.timestamp)
            .field("event_type", &self.event_type_enum())
            .field("pid", &self.pid)
            .field("uid", &self.uid)
            .field("result", &self.result)
            .field("data_len", &self.data_len)
            .finish()
    }
}
