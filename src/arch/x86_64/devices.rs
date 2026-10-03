//! src/arch/x86_64/devices.rs
//!
//! Which of the machine's own devices this architecture has a driver for.
//!
//! The drivers themselves live in `src/drivers/`, where the rest of the
//! kernel finds them; what this module answers is *which of them a PC
//! actually has*.  The five below are reached through the x86_64
//! configuration mechanism: the bochs display, the Intel HDA controller,
//! NVMe, xHCI, and the PIT channel-2 speaker.  A bare-metal x86_64 compiles
//! the driver; an x86_64 host has none of that hardware, so it compiles the
//! stub that answers under the same name.  The other architectures say the
//! same thing in their own `devices.rs`, which is what lets
//! `drivers/mod.rs` name no architecture at all.
//!
//! The modules are compiled through `#[path]` because they belong to the
//! driver framework rather than to this directory.  `super::` inside them
//! therefore resolves to this module, which is why the names they expect are
//! re-exported below.

use alloc::sync::Arc;

use crate::kernel::block::BlockDevice;

pub use crate::drivers::framebuffer_protocol;
pub use crate::drivers::hda_protocol;
pub use crate::drivers::nvme_protocol;
pub use crate::drivers::xhci_protocol;
pub use crate::drivers::Driver;
pub use crate::drivers::DriverCategory;

/// Whether this machine has a PC speaker (PIT channel 2).
///
/// The host build of this architecture does not: it is not a PC, and the
/// speaker would be programmed through port I/O a host process cannot issue.
pub const HAS_PC_SPEAKER: bool = cfg!(target_os = "none");

/// Ask this machine's USB bus for a boot disk, if it has one.
///
/// The mass-storage driver is bare-metal only, for the same reason the
/// speaker is: it drives xHCI through the machine's own registers.  The
/// answer is `None` rather than a compile error so the driver framework can
/// ask unconditionally.
pub fn usb_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    #[cfg(target_os = "none")]
    {
        crate::drivers::usb_msd::probe_boot_disk()
    }
    #[cfg(not(target_os = "none"))]
    {
        None
    }
}

#[cfg(target_os = "none")]
#[path = "../../drivers/framebuffer.rs"]
pub mod framebuffer;
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/framebuffer_absent.rs"]
pub mod framebuffer;

#[cfg(target_os = "none")]
#[path = "../../drivers/hda.rs"]
pub mod hda;
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/hda_absent.rs"]
pub mod hda;

#[cfg(target_os = "none")]
#[path = "../../drivers/nvme.rs"]
pub mod nvme;
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/nvme_absent.rs"]
pub mod nvme;

#[cfg(target_os = "none")]
#[path = "../../drivers/xhci.rs"]
pub mod xhci;
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/xhci_absent.rs"]
pub mod xhci;

#[cfg(target_os = "none")]
#[path = "../../drivers/pcspkr.rs"]
pub mod pcspkr;
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/pcspkr_absent.rs"]
pub mod pcspkr;
