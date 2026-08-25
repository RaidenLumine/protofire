//! src/kernel/drivers/usb_msd_driver.rs
//!
//! USB mass-storage driver bridge implementing the kernel Driver interface.

use crate::kernel::drivers::{Driver, DriverCategory};
use crate::Result;

pub struct UsbMsdDriver;

impl Driver for UsbMsdDriver {
    fn name(&self) -> &'static str {
        "usb-msd"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Storage
    }

    fn init(&self) -> Result<()> {
        // The actual initialization happens when a device is detected
        // This is just a placeholder to register the driver
        println!("[usbmsd] USB Mass Storage driver initialized");
        Ok(())
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
    fn compatible_strings(&self) -> &[&'static str] {
        &[
            "usb_mass_storage",
            "usbmass",
        ]
    }
}

