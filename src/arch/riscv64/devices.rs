//! src/arch/riscv64/devices.rs
//!
//! Which of the machine's own devices this architecture has a driver for.
//!
//! None of the PC drivers: the bochs display, Intel HDA, NVMe, xHCI and the
//! PIT speaker are reached through the x86_64 configuration mechanism.  This
//! machine's own devices are VirtIO — MMIO from its device tree, PCIe from
//! its ECAM window — and those drivers live in `src/drivers/` and are
//! compiled everywhere.
//!
//! So the five names below resolve to the stubs, and the two capability
//! constants say so too.  See the x86_64 module for why the driver files are
//! reached through `#[path]`.

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

/// The VirtIO input wire format: the device half below translates its events
/// into Set-1 scancodes, and the driver's host tests check the translation.
#[cfg(any(test, target_os = "none"))]
#[path = "../../drivers/virtio_input/protocol.rs"]
pub(crate) mod protocol;

/// The device half: a VirtIO MMIO input device on a bare-metal machine, and
/// the stub that answers under the same name on a host.
#[cfg(target_os = "none")]
#[path = "../../drivers/virtio_input/mmio.rs"]
pub(crate) mod virtio_input_mmio;
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/virtio_input/absent.rs"]
pub(crate) mod virtio_input_mmio;

/// The driver's own constructor, which the probe below hands its transport to.
#[cfg(target_os = "none")]
use crate::drivers::virtio_gpu::init_gpu_device;

/// How this machine finds a virtio-gpu device: on the VirtIO MMIO bus its
/// device tree describes.
#[cfg(target_os = "none")]
#[path = "../../drivers/virtio_gpu/probe_mmio.rs"]
pub(crate) mod virtio_gpu_probe;
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/virtio_gpu/probe_absent.rs"]
pub(crate) mod virtio_gpu_probe;

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
