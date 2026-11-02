//! src/user/shared/abi/prctl.rs
//!
//! src/abi/prctl.rs
//! The operation codes `prctl` (#130) accepts, and the name limit that goes
//! with them.
//!
//! These are the codes this kernel implements, not the whole of Linux's set:
//! the handler rejects anything it does not know, so a code listed here is a
//! promise and a code missing here is not implemented rather than merely
//! unlisted.  They used to be `const`s inside the handler, which meant user
//! space had to spell the numbers itself — and a second, unread file in this
//! directory listed a different set, including a code that collided with
//! `PR_GET_NAME` below.

/// Get the current process's dumpable flag.
pub const PR_GET_DUMPABLE: i32 = 3;
/// Set the current process's dumpable flag.
pub const PR_SET_DUMPABLE: i32 = 4;
/// Get the current process's keepcaps flag.
pub const PR_GET_KEEPCAPS: i32 = 7;
/// Set the current process's keepcaps flag.
pub const PR_SET_KEEPCAPS: i32 = 8;
/// Get the current process name.
pub const PR_GET_NAME: i32 = 15;
/// Set the current process name.
pub const PR_SET_NAME: i32 = 16;
/// Get the current process's no_new_privs flag.
pub const PR_GET_NO_NEW_PRIVS: i32 = 38;
/// Set the current process's no_new_privs flag.
pub const PR_SET_NO_NEW_PRIVS: i32 = 39;

/// Maximum process name length, matching Linux's `TASK_COMM_LEN`.
pub const PR_MAX_NAME_LEN: usize = 16;
