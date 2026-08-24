//! src/abi/io_uring_extended.rs
//!
//! Extended io_uring opcodes and flags
//! Additional opcodes beyond the basic io_uring implementation

/// Fsync a file descriptor.
pub const IORING_OP_FSYNC: u8 = 5;

/// Read from a file descriptor into a fixed buffer.
pub const IORING_OP_READ_FIXED: u8 = 6;

/// Write to a file descriptor from a fixed buffer.
pub const IORING_OP_WRITE_FIXED: u8 = 7;

/// Poll a file descriptor for readiness (POLLEXCL).
pub const IORING_OP_POLL_REMOVE: u8 = 8;

/// Send a message on a socket.
pub const IORING_OP_SEND: u8 = 9;

/// Receive a message from a socket.
pub const IORING_OP_RECV: u8 = 10;

/// Send a message on a socket with flags.
pub const IORING_OP_SENDMSG: u8 = 11;

/// Receive a message from a socket with flags.
pub const IORING_OP_RECVMSG: u8 = 12;

/// Accept a connection on a socket.
pub const IORING_OP_ACCEPT: u8 = 13;

/// Cancel an io_uring operation.
pub const IORING_OP_ASYNC_CANCEL: u8 = 14;

/// Timeout with timespec.
pub const IORING_OP_TIMEOUT_REMOVE: u8 = 15;

/// Connect a socket.
pub const IORING_OP_CONNECT: u8 = 16;

/// Preadv2 system call.
pub const IORING_OP_PREADV2: u8 = 17;

/// Pwritev2 system call.
pub const IORING_OP_PWRITEV2: u8 = 18;

/// Enter flags
pub const IORING_ENTER_SQWAIT: u32 = 1 << 2;
pub const IORING_ENTER_SQWAIT_ASYNC: u32 = 1 << 3;
pub const IORING_ENTER_GETEVENTS_TIMEOUT: u32 = 1 << 4;
pub const IORING_ENTER_GETEVENTS_TIMEOUT_ASYNC: u32 = 1 << 5;

/// Poll events
pub const IORING_POLL_PRI: u16 = 1 << 4;
pub const IORING_POLL_MSG: u16 = 1 << 5;
pub const IORING_POLL_BAND: u16 = 1 << 6;

/// SQE flags
pub const IORING_SQE_BUFFER_SELECT: u8 = 1 << 1;
pub const IORING_SQE_FIXED_BUFFER_BIT: u16 = 1 << 15;
pub const IORING_SQE_FIXED_BUFFER_MASK: u16 = 0x3FFF;

/// CQE flags
pub const IORING_CQE_F_CANCELED: u32 = 1 << 2;
pub const IORING_CQE_F_FAILED: u32 = 1 << 3;
