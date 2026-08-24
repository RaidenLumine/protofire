//! src/abi/seccomp_extended.rs
//!
//! Extended seccomp constants for full seccomp support
//! Additional constants beyond the basic seccomp implementation

/// Get the current seccomp mode.
pub const SECCOMP_GET_MODE_FILTER: i32 = 2;

/// Get the current seccomp filter as a rule array.
pub const SECCOMP_GET_ACTION_AVAIL: i32 = 3;

/// Get the current seccomp TSYNC flag.
pub const SECCOMP_GET_TSYNC_FLAG: i32 = 4;

/// Set the seccomp TSYNC flag.
pub const SECCOMP_SET_TSYNC_FLAG: i32 = 5;

/// Trace the syscall and notify a tracer.
pub const SECCOMP_ACTION_TRACE: u32 = 3;

/// Return an error code to the caller.
pub const SECCOMP_ACTION_ERRNO: u32 = 4;

/// Architecture-specific seccomp operations
pub const SECCOMP_SET_MODE_STRICT: i32 = 0;

/// Flag for TSYNC support
pub const SECCOMP_FLAG_TSYNC: u32 = 1;

/// Flag for SECCOMP_FILTER_TSYNC
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;
