//! src/kernel/process/process/constants.rs
//! Process subsystem type aliases and constants.

pub type ProcessId = u32;
pub type Handle = u64;
pub type FileDescriptor = usize;
pub type SignalHandler = fn(i32);
pub type UserId = u32;
pub type GroupId = u32;

pub const ROOT_USER_ID: UserId = 0;
pub const ROOT_GROUP_ID: GroupId = 0;
pub const DEFAULT_GUEST_USER_ID: UserId = 1000;
pub const DEFAULT_GUEST_GROUP_ID: GroupId = 1000;

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

// Handle rights are bitflags combined in handle table entries.
pub const HANDLE_RIGHT_READ: u32 = 1 << 0;
pub const HANDLE_RIGHT_WRITE: u32 = 1 << 1;
// Keep cooperative process signals bounded so one sender cannot grow an
// unbounded heap queue inside another process.
pub(crate) const PENDING_PROCESS_SIGNAL_CAPACITY: usize = 64;
