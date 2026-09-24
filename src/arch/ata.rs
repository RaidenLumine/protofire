//! src/arch/ata.rs
//!
//! The ATA disk driver this architecture offers, if any.
//!
//! ATA over the legacy task-file registers is programmed port by port, which
//! is an x86_64 thing; a machine without that either has its controller behind
//! another interface (AHCI, VirtIO, NVMe) or has none.  The driver registry
//! asks here and gets either the real driver or one that claims the category
//! and does nothing, so the boot's driver list has the same shape everywhere
//! and only the implementation differs.

#[cfg(target_arch = "x86_64")]
pub use super::x86_64::ata::driver;
#[cfg(target_arch = "x86_64")]
pub use super::x86_64::ata::probe_boot_disk;

/// Everywhere else: a driver that is registered and finds nothing.
#[cfg(not(target_arch = "x86_64"))]
mod absent {
    use alloc::sync::Arc;

    use crate::kernel::block::BlockDevice;
    use crate::kernel::drivers::Driver;

    struct AtaDriver;

    impl Driver for AtaDriver {
        fn name(&self) -> &'static str {
            "ata"
        }

        fn category(&self) -> crate::kernel::drivers::DriverCategory {
            crate::kernel::drivers::DriverCategory::Storage
        }

        fn init(&self) -> crate::Result<()> {
            // Nothing to probe: the registers this driver speaks are not on
            // this machine, and a boot disk will have to come from one of the
            // other storage drivers.
            Ok(())
        }
    }

    pub fn driver() -> Arc<dyn Driver> {
        Arc::new(AtaDriver)
    }

    pub fn probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
        None
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub use absent::driver;
#[cfg(not(target_arch = "x86_64"))]
pub use absent::probe_boot_disk;
