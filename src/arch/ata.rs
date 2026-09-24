//! src/arch/ata.rs
//!
//! The storage drivers this architecture offers, if any.
//!
//! ATA over the legacy task-file registers and AHCI over a PCI BAR are
//! programmed through interfaces this kernel only implements on x86_64
//! (`arch::x86_64::port`, `arch::x86_64::pci`); the machines that have
//! neither put their disks behind VirtIO or NVMe.  The registry asks here and
//! gets either the real drivers or ones that claim their category and do
//! nothing, so the boot's driver list has the same shape everywhere and only
//! the implementation differs.

#[cfg(target_arch = "x86_64")]
pub use super::x86_64::ahci::driver as ahci_driver;
#[cfg(target_arch = "x86_64")]
pub use super::x86_64::ahci::probe_boot_disk as ahci_probe_boot_disk;
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

    struct AhciDriver;

    impl Driver for AhciDriver {
        fn name(&self) -> &'static str {
            "ahci"
        }

        fn category(&self) -> crate::kernel::drivers::DriverCategory {
            crate::kernel::drivers::DriverCategory::Storage
        }

        fn init(&self) -> crate::Result<()> {
            // As for ATA: the controller this driver speaks is behind a PCI
            // BAR this machine does not have.
            Ok(())
        }
    }

    pub fn ahci_driver() -> Arc<dyn Driver> {
        Arc::new(AhciDriver)
    }

    pub fn ahci_probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
        None
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub use absent::ahci_driver;
#[cfg(not(target_arch = "x86_64"))]
pub use absent::ahci_probe_boot_disk;
#[cfg(not(target_arch = "x86_64"))]
pub use absent::driver;
#[cfg(not(target_arch = "x86_64"))]
pub use absent::probe_boot_disk;
