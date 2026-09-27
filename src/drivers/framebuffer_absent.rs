//! src/drivers/framebuffer_absent.rs
//!
//! bochs-display on a machine that has no such device.
//!
//! The register map and the display record are still here — they describe the
//! device, not the machine — and the driver still registers: there is simply
//! no linear framebuffer to map and no mode to set.

use alloc::sync::Arc;

use crate::drivers::Driver;
use crate::drivers::DriverCategory;

pub use super::framebuffer_protocol::*;

struct FramebufferDriver;

impl Driver for FramebufferDriver {
    fn name(&self) -> &'static str {
        "bochs-fb"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Console
    }

    fn init(&self) -> crate::Result<()> {
        Err(crate::Error::DeviceError)
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(FramebufferDriver)
}

/// No display was probed, so there is no framebuffer to describe.
pub fn framebuffer_info() -> Option<FramebufferInfo> {
    None
}
