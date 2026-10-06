//! src/arch/aarch64/devices.rs
//!
//! Which of the machine's own devices this architecture has a driver for.
//!
//! Most of the PC drivers: the bochs display, Intel HDA, xHCI and the PIT
//! speaker are reached through the x86_64 configuration mechanism, and this
//! machine does not have it.  What it has instead is VirtIO — the MMIO devices
//! its device tree names, and the PCIe devices behind the ECAM window — and
//! NVMe, whose registers are the same on any PCIe bus; both live in
//! `src/drivers/` and are compiled wherever that bus is.
//!
//! So the five names below resolve to the stubs that answer under the same
//! module name and report that the hardware is not there, and the two
//! capability constants say the same thing.  See the x86_64 module for why the
//! driver files are reached through `#[path]`.

use alloc::sync::Arc;

use crate::kernel::block::BlockDevice;

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

/// How this machine finds a virtio-gpu device: on the VirtIO MMIO bus its
/// device tree describes.
#[cfg(target_os = "none")]
#[path = "../../drivers/virtio_gpu/probe_mmio.rs"]
pub(crate) mod virtio_gpu_probe;
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/virtio_gpu/probe_absent.rs"]
pub(crate) mod virtio_gpu_probe;

/// The generic platform probe already reaches this machine's PCIe devices
/// (`arch::platform::pci_register_window`), so there is nothing extra to add.
#[cfg(target_os = "none")]
pub(crate) fn pci_net_device() -> Option<Arc<dyn crate::network::link::device::NetworkDevice>> {
    None
}

/// This machine has no xHCI bus, so there is no USB boot disk to ask for.
pub fn usb_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    None
}

#[path = "../../drivers/framebuffer_absent.rs"]
pub mod framebuffer;
#[path = "../../drivers/hda_absent.rs"]
pub mod hda;
/// The NVMe driver, which this machine reaches through its PCIe window: the
/// class is the same one an x86_64 controller has, and the platform's window
/// helper is what maps the BAR here.
#[cfg(target_os = "none")]
#[path = "../../drivers/nvme.rs"]
pub mod nvme;
/// Nothing to answer on a host build of this architecture.
#[cfg(not(target_os = "none"))]
#[path = "../../drivers/nvme_absent.rs"]
pub mod nvme;
#[path = "../../drivers/pcspkr_absent.rs"]
pub mod pcspkr;
#[path = "../../drivers/xhci_absent.rs"]
pub mod xhci;
