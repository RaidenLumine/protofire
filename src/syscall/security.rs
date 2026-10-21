//! src/syscall/security.rs
//!
//! The mandatory-access checkpoints that live at the syscall boundary.
//!
//! A process reaches another process by sending it a signal or tracing it, and
//! it reaches the network through a socket.  Files are checked below this
//! layer, in the VFS hook every operation converges on; processes and sockets
//! are checked here, because a syscall handler is where the caller's token and
//! the operation are both in hand.
//! `docs/rfcs/0033-refuse-a-signal-a-trace-and-a-socket.md` decides the
//! placement and what it leaves ungated.
//!
//! Every helper is permissive while no policy is loaded, so a boot that loads
//! none behaves exactly as it did before these existed.

use crate::kernel::security::mac;
use crate::Result;

/// Check one process' authority over another, given the two labels.
///
/// The caller's label is the subject and the target's is the object.  Callers
/// exempt the self case before reaching here: no authority crosses a process
/// boundary when the sender and the target are one process.
pub(super) fn check_process_access(
    subject: mac::MacType,
    object: mac::MacType,
    perms: mac::MacPermission,
    audit_uid: u32,
) -> Result<()> {
    mac::check_process(subject, object, perms, audit_uid)
}

/// Check that the caller may use the network in the given way.
pub(super) fn check_network_use(perms: mac::MacPermission) -> Result<()> {
    super::runtime::with_current_process(|process| {
        let token = process.security_token();
        mac::check_network(token.mac_type, perms, token.user_id)
    })
}
