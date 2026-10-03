//! src/drivers/hda_absent.rs
//!
//! Intel HDA on a machine that has no such controller.
//!
//! The register map and the codec protocol are still here — they are the
//! specification — and the driver still registers, because "this machine has
//! no HDA controller" is what its probe answers.  The audio device node exists
//! and refuses writes, which is what a player must be told.

use alloc::sync::Arc;

use crate::drivers::Driver;
use crate::drivers::DriverCategory;

pub use crate::drivers::hda_protocol::*;

struct HdaDriver;

impl Driver for HdaDriver {
    fn name(&self) -> &'static str {
        "hda"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Audio
    }

    fn init(&self) -> crate::Result<()> {
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(HdaDriver)
}

/// Handle a write to the `/system/dev/audio` device node.
///
/// There is no controller to play through, so this fails the way the kernel's
/// error return is meant to be used.
pub fn device_write(_buffer: &[u8]) -> crate::Result<usize> {
    Err(crate::Error::Unsupported)
}

/// Reading the audio device node is unsupported (playback-only).
pub fn device_read(_buffer: &mut [u8], _timeout_ticks: u64) -> crate::Result<usize> {
    Err(crate::Error::Unsupported)
}

// ── Tests ──────────────────────────────────────────────────────────────

/// The device node exists on this machine and refuses what it cannot do.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_node_write_is_unsupported_without_a_controller() {
        assert!(device_write(&[0x80, 0xBB, 0x00, 0x00, 1, 2]).is_err());
    }

    #[test]
    fn audio_node_read_is_unsupported() {
        let mut buf = [0u8; 8];
        assert!(device_read(&mut buf, 0).is_err());
    }
}
