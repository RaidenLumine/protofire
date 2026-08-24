//! src/abi/prctl_extended.rs
//!
//! Extended prctl operations
//! Additional prctl constants beyond the basic implementation

/// Get the current process's no_new_privs flag.
pub const PR_GET_NO_NEW_PRIVS: i32 = 38;
/// Set the current process's no_new_privs flag.
pub const PR_SET_NO_NEW_PRIVS: i32 = 39;

/// Get the current process's seccomp mode.
pub const PR_GET_SECCOMP: i32 = 21;
/// Set the current process's seccomp mode.
pub const PR_SET_SECCOMP: i32 = 22;

/// Get the current process's address space protection key.
pub const PR_GET_PKEY: i32 = 43;
/// Set the current process's address space protection key.
pub const PR_SET_PKEY: i32 = 44;

/// Get the current process's capability bounding set.
pub const PR_CAPBSET_READ: i32 = 23;
/// Set the current process's capability bounding set.
pub const PR_CAPBSET_DROP: i32 = 24;

/// Get the current process's securebits.
pub const PR_GET_SECUREBITS: i32 = 25;
/// Set the current process's securebits.
pub const PR_SET_SECUREBITS: i32 = 26;

/// Get the current process's task nice value.
pub const PR_GET_TIMING: i32 = 9;
/// Set the current process's task nice value.
pub const PR_SET_TIMING: i32 = 10;

/// Get the current process's task scheduler priority.
pub const PR_GET_SCHEDULER: i32 = 14;
/// Set the current process's task scheduler priority.
pub const PR_SET_SCHEDULER: i32 = 15;

/// Get the current process's affinity.
pub const PR_GET_AFFINITY: i32 = 29;
/// Set the current process's affinity.
pub const PR_SET_AFFINITY: i32 = 30;

/// Get the current process's core dump filter.
pub const PR_GET_COREDUMP_FILTER: i32 = 51;
/// Set the current process's core dump filter.
pub const PR_SET_COREDUMP_FILTER: i32 = 52;

/// Get the current process's mm map protection.
pub const PR_SET_MM: i32 = 35;
/// Get the current process's mm map protection.
pub const PR_GET_MM: i32 = 36;
