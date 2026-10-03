//! src/drivers/xhci_absent.rs
//!
//! xHCI on a machine that has no USB host controller of its own.
//!
//! The register map and the USB structures are still here — they are the
//! specification — and the driver still registers, because "this machine has
//! no xHCI controller" is what its probe answers.  There is no controller to
//! publish, so nothing else is compiled.

use alloc::sync::Arc;

use crate::drivers::Driver;
use crate::drivers::DriverCategory;

pub use crate::drivers::xhci_protocol::*;

struct XhciDriver;

impl Driver for XhciDriver {
    fn name(&self) -> &'static str {
        "xhci"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Bus
    }

    fn init(&self) -> crate::Result<()> {
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(XhciDriver)
}

/// There is no event ring to poll.
pub fn xhci_poll() -> bool {
    false
}
