//! src/arch/aarch64/devices.rs
//!
//! Which of the machine's own devices this architecture has a driver for.
//!
//! None of the PC drivers: the bochs display, Intel HDA, NVMe, xHCI and the
//! PIT speaker are reached through the x86_64 configuration mechanism, and
//! this machine does not have it.  What it has instead is VirtIO — the MMIO
//! devices its device tree names, and the PCIe devices behind the ECAM window
//! — and those drivers live in `src/drivers/` and are compiled everywhere.
//!
//! So the five names below resolve to the stubs that answer under the same
//! module name and report that the hardware is not there, and the two
//! capability constants say the same thing.  See the x86_64 module for why
//! the driver files are reached through `#[path]` and why the names they use
//! are re-exported here.

use alloc::sync::Arc;

use crate::kernel::block::BlockDevice;

pub use crate::drivers::framebuffer_protocol;
pub use crate::drivers::hda_protocol;
pub use crate::drivers::nvme_protocol;
pub use crate::drivers::xhci_protocol;
pub use crate::drivers::Driver;
pub use crate::drivers::DriverCategory;

/// This machine has no PC speaker.
pub const HAS_PC_SPEAKER: bool = false;

/// This machine has no xHCI bus, so there is no USB boot disk to ask for.
pub fn usb_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    None
}

#[path = "../../drivers/framebuffer_absent.rs"]
pub mod framebuffer;
#[path = "../../drivers/hda_absent.rs"]
pub mod hda;
#[path = "../../drivers/nvme_absent.rs"]
pub mod nvme;
#[path = "../../drivers/pcspkr_absent.rs"]
pub mod pcspkr;
#[path = "../../drivers/xhci_absent.rs"]
pub mod xhci;
