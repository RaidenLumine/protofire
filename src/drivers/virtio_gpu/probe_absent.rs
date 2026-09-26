//! src/drivers/virtio_gpu/probe_absent.rs
//!
//! A host has no bus to probe, so there is no GPU to find.

/// Host-side / non-x86_64 stub: virtio-gpu not available.
#[cfg(not(target_os = "none"))]
pub(super) fn and_init() -> Option<()> {
    None
}
