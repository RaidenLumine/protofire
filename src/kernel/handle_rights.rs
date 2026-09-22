//! src/kernel/handle_rights.rs
//!
//! What a handle may do: the rights carried by a handle-table entry.
//!
//! Two bit flags, and every layer names them — a device descriptor declares
//! which rights its device supports, the filesystem checks them before it
//! answers a read, the audit log opens its own file with one, and the handle
//! table stores them.  A set of flags that everyone needs is not a reason for
//! those layers to depend on each other, so they sit at the bottom, below
//! `device`, `fs`, `audit` and `process` alike.

/// Open for reading.
pub const HANDLE_RIGHT_READ: u32 = 1 << 0;

/// Open for writing.
pub const HANDLE_RIGHT_WRITE: u32 = 1 << 1;
