//! src/drivers/virtio_gpu/probe_pci.rs
//!
//! Finding the GPU on x86_64: it is a PCI function, its BAR is mapped, and the
//! transport above the BAR answers as a VirtIO device.

use alloc::boxed::Box;

use crate::drivers::virtio::VirtIoMmio;
use crate::println;

/// Red Hat / QEMU VirtIO vendor ID.
const VIRTIO_VENDOR: u16 = 0x1af4;
/// VirtIO GPU transitional PCI device ID (QEMU virtio-gpu-pci).
const VIRTIO_GPU_PCI_DEVICE_ID: u16 = 0x1050;

/// Find a virtio-gpu PCI device, initialise it, and install the framebuffer
/// console.  Returns `Some(())` on success.
pub(crate) fn and_init() -> Option<()> {
    use crate::arch::mmu::map_device_mmio;
    use crate::arch::x86_64::pci::pci_config_read_u16;
    use crate::arch::x86_64::pci::pci_config_write_u16;
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::arch::x86_64::pci::PciAddress;
    use crate::arch::x86_64::pci::COMMAND;
    use crate::arch::x86_64::virtio_pci::PciLegacyMmioRegion;
    use crate::drivers::virtio_pci_modern::PciModernRegion;

    const CMD_IO_SPACE: u16 = 1 << 0;
    const CMD_MEMORY_SPACE: u16 = 1 << 1;
    const CMD_BUS_MASTER: u16 = 1 << 2;

    let devices = pci_enumerate_buses();
    let device = devices
        .iter()
        .find(|d| d.vendor_id == VIRTIO_VENDOR && d.device_id == VIRTIO_GPU_PCI_DEVICE_ID)?;

    println!(
        "[virtio-gpu] found device at {:02x}:{:02x}.{:x}",
        device.bus, device.device, device.function
    );

    let pci_addr = PciAddress::new(device.bus, device.device, device.function);

    // Enable IO Space, Memory Space, and Bus Master.
    // SAFETY: the command register of a function the PCI scan enumerated,
    // inside its own config space.
    let cmd = unsafe { pci_config_read_u16(pci_addr, COMMAND) };
    // SAFETY: as above — writing that register to enable the spaces and bus
    // mastering the transport needs.
    unsafe {
        pci_config_write_u16(
            pci_addr,
            COMMAND,
            cmd | CMD_IO_SPACE | CMD_MEMORY_SPACE | CMD_BUS_MASTER,
        );
    }

    // ── Try modern PCI transport via MMIO BAR ──
    let result = if let Some(mmio_bar) = device
        .bars
        .iter()
        .find(|bar| bar.is_mmio && bar.base_address != 0)
    {
        println!(
            "[virtio-gpu] modern transport: MMIO BAR base=0x{:x} size=0x{:x}",
            mmio_bar.base_address, mmio_bar.size
        );

        // Map the MMIO BAR into kernel page tables (identity-mapped).
        // SAFETY: `mmio_bar` is a BAR the enumeration decoded, so the range is
        // live MMIO; the BAR size is what the device answered.
        let mapping = unsafe { map_device_mmio(mmio_bar.base_address, mmio_bar.size as usize) };
        if mapping.is_none() {
            println!("[virtio-gpu] failed to map MMIO BAR");
            return None;
        }

        let region = Box::new(PciModernRegion::new(
            mmio_bar.base_address as usize,
            device.device_id,
            device.vendor_id,
        ));
        let mut transport = VirtIoMmio::new(region);

        // Verify it's a valid VirtIO device.
        if transport.discover().is_err() {
            println!("[virtio-gpu] modern transport: discover failed");
            return None;
        }

        super::init_gpu_device(transport)
    } else {
        // ── Fallback: legacy IO-port BAR ──
        let io_bar = device
            .bars
            .first()
            .filter(|bar| !bar.is_mmio && bar.base_address != 0)?;
        let io_base = io_bar.base_address as u16;

        println!("[virtio-gpu] legacy transport: IO BAR base=0x{:x}", io_base);

        let region = Box::new(PciLegacyMmioRegion::new(
            io_base,
            device.device_id,
            device.vendor_id,
        ));
        let mut transport = VirtIoMmio::new(region);

        if transport.discover().is_err() {
            println!("[virtio-gpu] legacy transport: discover failed");
            return None;
        }

        super::init_gpu_device(transport)
    };

    let (_w, _h) = result?;

    Some(())
}
