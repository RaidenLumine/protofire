//! src/user/shared/abi/io_uring.rs
//!
//! src/abi/io_uring.rs
//! Shared ABI types for the io_uring asynchronous I/O subsystem.
//!
//! These types are `#[repr(C)]` and must remain binary-stable across kernel
//! revisions.  Both the kernel and ring3 user-space programs use these
//! definitions to interpret syscall arguments for io_uring operations.

/// Size of a single submission-queue entry (SQE) in bytes.
///
/// The struct contains two `u64` fields (user_data, reserved), one `[u8; 8]`
/// buffer (addr), three `u32` fields (fd, len, timeout_ticks), two `u16`
/// fields (poll_events, ioprio), and two `u8` fields (opcode, flags) plus
/// trailing padding to the largest alignment requirement.
pub const IO_URING_SQE_SIZE: usize = 48;

/// Size of a single completion-queue entry (CQE) in bytes.
pub const IO_URING_CQE_SIZE: usize = 16;

// ── Opcodes ──────────────────────────────────────────────────────────

/// No-operation (immediate completion with result=0).
pub const IORING_OP_NOP: u8 = 0;
/// Read from a file descriptor into a user buffer.
pub const IORING_OP_READ: u8 = 1;
/// Write from a user buffer to a file descriptor.
pub const IORING_OP_WRITE: u8 = 2;
/// Poll a file descriptor for readiness (POLLIN / POLLOUT).
pub const IORING_OP_POLL_ADD: u8 = 3;
/// Timer operation — completes after a tick-based timeout.
pub const IORING_OP_TIMEOUT: u8 = 4;

// ── Setup flags (IoUringSetup arg1) ──────────────────────────────────

/// Enable I/O polling for poll-capable devices (reserved for future use).
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;

// ── Enter flags (IoUringEnter arg5) ─────────────────────────────────

/// Wait for at least `min_complete` completions before returning.
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;

// ── SQE flags ────────────────────────────────────────────────────────

/// Use fixed file table index (reserved — must be 0 for now).
pub const IORING_SQE_FIXED_FILE: u8 = 1 << 0;

// ── Poll events (IORING_OP_POLL_ADD) ──────────────────────────────────

pub const IORING_POLL_IN: u16 = 1 << 0;
pub const IORING_POLL_OUT: u16 = 1 << 1;
pub const IORING_POLL_ERR: u16 = 1 << 2;
pub const IORING_POLL_HUP: u16 = 1 << 3;

/// A single submission-queue entry (SQE) for the IoUringEnter syscall.
///
/// All fields are explicitly sized and packed so that the struct has no
/// padding on common architectures.  The kernel reads this from user
/// memory during `io_uring_enter`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoUringSqe {
    /// Operation code: IORING_OP_NOP / READ / WRITE / POLL_ADD / TIMEOUT.
    pub opcode: u8,
    /// SQE flags (IORING_SQE_FIXED_FILE — reserved).
    pub flags: u8,
    /// I/O priority class (0 = default).
    pub ioprio: u16,
    /// Target file descriptor for the operation.
    pub fd: i32,
    /// Buffer address (user-space pointer) for READ / WRITE operations.
    pub addr: [u8; 8],
    /// Buffer length for READ / WRITE operations.
    pub len: u32,
    /// Poll events (POLLIN / POLLOUT) for IORING_OP_POLL_ADD.
    pub poll_events: u16,
    /// Timeout in kernel ticks for IORING_OP_TIMEOUT (0 = immediate).
    pub timeout_ticks: u32,
    /// User-space correlation cookie — returned unchanged in the CQE.
    pub user_data: u64,
    /// Reserved for future use (must be 0).
    pub reserved: u64,
}

/// A single completion-queue entry (CQE) produced by the kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoUringCqe {
    /// User data copied from the original SQE.
    pub user_data: u64,
    /// Result: positive byte count (READ/WRITE), 0 (NOP/POLL_ADD success),
    /// or negative errno code (e.g. -Error::NotFound as i32).
    pub result: i32,
    /// Flags (reserved — must be 0).
    pub flags: u32,
}

/// The maximum number of SQEs that can be submitted in one `IoUringEnter` call.
pub const IO_URING_MAX_ENTRIES: u32 = 256;

/// Default timeout for blocking waits inside IoUringEnter (in ticks).
/// At 100 Hz this is ~1 second.
pub const IO_URING_DEFAULT_ENTER_TIMEOUT: u64 = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_uring_sqe_size_is_stable() {
        assert_eq!(
            core::mem::size_of::<IoUringSqe>(),
            IO_URING_SQE_SIZE,
            "IoUringSqe size changed — update IO_URING_SQE_SIZE"
        );
    }

    #[test]
    fn io_uring_cqe_size_is_stable() {
        assert_eq!(
            core::mem::size_of::<IoUringCqe>(),
            IO_URING_CQE_SIZE,
            "IoUringCqe size changed — update IO_URING_CQE_SIZE"
        );
    }

    #[test]
    fn io_uring_opcode_constants_are_stable() {
        assert_eq!(IORING_OP_NOP, 0);
        assert_eq!(IORING_OP_READ, 1);
        assert_eq!(IORING_OP_WRITE, 2);
        assert_eq!(IORING_OP_POLL_ADD, 3);
        assert_eq!(IORING_OP_TIMEOUT, 4);
    }

    #[test]
    fn io_uring_flag_constants_are_stable() {
        assert_eq!(IORING_SETUP_IOPOLL, 1 << 0);
        assert_eq!(IORING_ENTER_GETEVENTS, 1 << 0);
        assert_eq!(IORING_SQE_FIXED_FILE, 1 << 0);
    }

    #[test]
    fn io_uring_poll_events_are_stable() {
        assert_eq!(IORING_POLL_IN, 1 << 0);
        assert_eq!(IORING_POLL_OUT, 1 << 1);
        assert_eq!(IORING_POLL_ERR, 1 << 2);
        assert_eq!(IORING_POLL_HUP, 1 << 3);
    }

    #[test]
    fn io_uring_sqe_opcode_field_offset() {
        // Verify that the opcode is at offset 0 (important for fast dispatch).
        let sqe = IoUringSqe {
            opcode: 42,
            flags: 0,
            ioprio: 0,
            fd: 0,
            addr: [0u8; 8],
            len: 0,
            poll_events: 0,
            timeout_ticks: 0,
            user_data: 0,
            reserved: 0,
        };
        let bytes: &[u8; IO_URING_SQE_SIZE] =
            unsafe { &*(&sqe as *const IoUringSqe as *const [u8; IO_URING_SQE_SIZE]) };
        assert_eq!(bytes[0], 42, "opcode must be at byte offset 0");
    }
}
