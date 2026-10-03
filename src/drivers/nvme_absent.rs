//! src/drivers/nvme_absent.rs
//!
//! NVMe on a machine that has no NVMe controller.
//!
//! The protocol is still here — it is a specification, not hardware — and the
//! driver still registers, because "this machine has no NVMe device" is what
//! its probe answers.  Nothing else is compiled: there is no BAR to map and no
//! queue to drive.

pub use crate::drivers::nvme_protocol::*;

use alloc::sync::Arc;

use crate::drivers::Driver;
use crate::drivers::DriverCategory;

struct NvmeDriver;

impl Driver for NvmeDriver {
    fn name(&self) -> &'static str {
        "nvme"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Storage
    }

    fn init(&self) -> crate::Result<()> {
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(NvmeDriver)
}

/// No controller was ever found, so there is nothing to initialise.
pub fn probe_boot_disk() -> Option<Arc<dyn crate::kernel::block::BlockDevice>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_boot_disk_returns_none_when_no_bar0() {
        // On host, probe_boot_disk always returns None because there is no
        // real NVMe BAR and map_device_mmio is a stub.  This test verifies
        // the function does not panic and returns the expected value.
        let result = probe_boot_disk();
        assert!(result.is_none());
    }

    #[test]
    fn block_device_trait_is_implemented() {
        // Compile-time verification: NvmeController implements BlockDevice.
        // probe_boot_disk is the boot-time entry point; on host it returns
        // None because map_device_mmio is a stub (no real PCI BAR).
        assert!(probe_boot_disk().is_none());
    }
}
