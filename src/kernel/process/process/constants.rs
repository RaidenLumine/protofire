//! src/kernel/process/process/constants.rs
//!
//! Process subsystem type aliases and constants.

pub type ProcessId = u32;
pub type Handle = u64;
pub type FileDescriptor = usize;
pub type SignalHandler = fn(i32);

// Identities and the rights a handle can carry belong to the security layer,
// which the filesystem can reach without going through this module.  They are
// re-exported here because every path that already says `process::UserId` is
// naming the same type.
pub use crate::kernel::handle_rights::HANDLE_RIGHT_READ;
pub use crate::kernel::handle_rights::HANDLE_RIGHT_WRITE;
pub use crate::kernel::security::GroupId;
pub use crate::kernel::security::UserId;
pub use crate::kernel::security::DEFAULT_GUEST_GROUP_ID;
pub use crate::kernel::security::DEFAULT_GUEST_USER_ID;
pub use crate::kernel::security::ROOT_GROUP_ID;
pub use crate::kernel::security::ROOT_USER_ID;

/// Map a user id to its home directory path.
///
/// # Current policy
///
/// | UID    | Path                    |
/// |--------|-------------------------|
/// | 0      | `/root`                 |
/// | 1000   | `/data/users/guest`     |
/// | other  | `/data/users/uid-{uid}` |
///
/// This is intentionally a pure function (no allocation / no global lookup)
/// so the kernel can determine the home path at any point without depending on
/// a user database being mounted.
// Canonical stdio descriptor numbers used across process and syscall layers.
pub const STDIN_FD: FileDescriptor = 0;
pub const STDOUT_FD: FileDescriptor = 1;
pub const STDERR_FD: FileDescriptor = 2;
pub(crate) const STANDARD_FD_COUNT: usize = STDERR_FD + 1;
pub(crate) const FIRST_EXPLICIT_FD: FileDescriptor = STANDARD_FD_COUNT;

// Keep cooperative process signals bounded so one sender cannot grow an
// unbounded heap queue inside another process.
pub(crate) const PENDING_PROCESS_SIGNAL_CAPACITY: usize = 64;
