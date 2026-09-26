//! src/drivers/virtio_input/absent.rs
//!
//! The virtio-input driver on a machine that has no virtio-input device —
//! x86_64, where PS/2 handles the keyboard, and every host build.  It answers
//! under the same module name as the device half, so the driver above never
//! has to ask which machine it is on.

/// Nothing to probe.
pub(super) fn probe_input() {}

/// Nothing to poll.
pub fn poll_hardware() {}
