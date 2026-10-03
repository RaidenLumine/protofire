//! src/drivers/virtio_gpu/probe_mmio.rs
//!
//! Finding the GPU on the device-tree machines: it answers on the VirtIO MMIO
//! bus, on one of the slots the machine described.

use alloc::boxed::Box;

use crate::drivers::virtio::VirtIoMmio;
use crate::println;

/// Find a virtio-gpu MMIO device on the VirtIO MMIO bus, initialise it, and
/// install the framebuffer console.  Returns `Some(())` on success.
pub(crate) fn and_init() -> Option<()> {
    use crate::drivers::virtio::BareMmioRegion;

    for addr in crate::drivers::virtio::mmio_slot_addresses() {
        // SAFETY: `addr` is a VirtIO MMIO register block discovered from the
        // FDT or the fixed MMIO window; it stays mapped for the kernel's
        // lifetime and access is serialised by the transport.
        let region = unsafe { BareMmioRegion::new(addr) };
        let mut transport = VirtIoMmio::new(Box::new(region));

        if transport.discover().is_err() {
            continue;
        }
        if transport.device_id() != crate::drivers::virtio::DEVICE_ID_GPU {
            continue;
        }
        println!("[virtio-gpu] found virtio-gpu at 0x{:x}", addr);
        return super::init_gpu_device(transport).map(|_| ());
    }
    None
}
