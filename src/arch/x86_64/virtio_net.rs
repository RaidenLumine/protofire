//! src/arch/x86_64/virtio_net.rs
//!
//! Finding a virtio-net device on this machine's PCI bus.
//!
//! The driver asks the machine how to reach a device; what "reach" means here
//! is PCI configuration space and port I/O, which is this architecture's and
//! nobody else's.  So the enumeration, the bus-master enable, the BAR mapping
//! and the legacy IO-port fallback live here, and the driver supplies only the
//! other half of the question — hand it a transport and it says whether the
//! device behind it is a NIC (`crate::drivers::virtio_net`).

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::arch::x86_64::pci::pci_config_read_u16;
use crate::arch::x86_64::pci::pci_config_write_u16;
use crate::arch::x86_64::pci::pci_enumerate_buses;
use crate::arch::x86_64::pci::PciAddress;
use crate::arch::x86_64::pci::COMMAND;
use crate::arch::x86_64::virtio_pci::PciLegacyMmioRegion;
use crate::drivers::virtio::VirtIoMmio;
use crate::drivers::virtio_net::try_virtio_net_device;
use crate::drivers::virtio_pci_modern::PciModernRegion;
use crate::network::link::device::NetworkDevice;

/// Probe this machine's PCI bus for a VirtIO network device.
///
/// Uses PCI enumeration to find a device with VirtIO vendor (0x1af4)
/// and network controller device ID (0x1000).  Tries the **modern**
/// (1.0) PCI transport via the MMIO BAR (BAR4) first, falling back
/// to the legacy IO-port BAR (BAR0) if no MMIO BAR is available.
pub(crate) fn pci_net_device() -> Option<Arc<dyn NetworkDevice>> {
    const VIRTIO_VENDOR: u16 = 0x1af4;
    const VIRTIO_NET_DEVICE: u16 = 0x1000;
    const CMD_IO_SPACE: u16 = 1 << 0;
    const CMD_MEMORY_SPACE: u16 = 1 << 1;
    const CMD_BUS_MASTER: u16 = 1 << 2;

    let devices = pci_enumerate_buses();
    for device in &devices {
        if device.vendor_id != VIRTIO_VENDOR || device.device_id != VIRTIO_NET_DEVICE {
            continue;
        }

        let pci_addr = PciAddress::new(device.bus, device.device, device.function);

        // Enable IO Space, Memory Space, and Bus Master.
        // SAFETY: the command register of a function this scan enumerated,
        // inside its own config space.
        let cmd = unsafe { pci_config_read_u16(pci_addr, COMMAND) };
        // SAFETY: as above — writing that register to enable the three spaces
        // the transport needs.
        unsafe {
            pci_config_write_u16(
                pci_addr,
                COMMAND,
                cmd | CMD_IO_SPACE | CMD_MEMORY_SPACE | CMD_BUS_MASTER,
            );
        }

        // ── Try modern PCI transport via the modern MMIO BAR ─────
        // QEMU's transitional `virtio-net-pci` exposes two MMIO BARs: a
        // legacy 0x1000 device region (BAR1) and the modern transport
        // BAR (BAR4, 0x4000, 64-bit prefetchable) that holds the common
        // config, device config and notification areas at the offsets
        // `PciModernRegion` expects.  Selecting the *first* MMIO BAR
        // picked the legacy region, so the notify write landed outside
        // any mapped BAR and page-faulted.  Always prefer the modern BAR:
        // it is the larger, prefetchable MMIO region.
        if let Some(mmio_bar) = device
            .bars
            .iter()
            .filter(|bar| bar.is_mmio && bar.base_address != 0)
            .max_by_key(|bar| (bar.is_prefetchable, bar.size))
        {
            crate::println!(
                "[drivers] virtio-net PCI: trying modern transport BAR base=0x{:x} size=0x{:x}",
                mmio_bar.base_address,
                mmio_bar.size
            );

            // Map the MMIO BAR into kernel page tables.
            // SAFETY: `mmio_bar` is a BAR the enumeration decoded, so the range
            // is live MMIO.
            let _mapping = unsafe {
                crate::arch::mmu::map_device_mmio(mmio_bar.base_address, mmio_bar.size as usize)
            };
            if _mapping.is_none() {
                crate::println!(
                    "[drivers] virtio-net PCI: failed to map MMIO BAR at 0x{:x}",
                    mmio_bar.base_address
                );
            } else {
                let region = Box::new(PciModernRegion::new(
                    mmio_bar.base_address as usize,
                    device.device_id,
                    device.vendor_id,
                ));
                let transport = VirtIoMmio::new(region);
                if let Some(net) = try_virtio_net_device(transport) {
                    crate::println!("[drivers] virtio-net device found (PCI modern)");
                    return Some(net);
                }
                crate::println!("[drivers] virtio-net PCI: modern transport failed, trying legacy");
            }
        }

        // ── Fallback: legacy IO-port BAR ─────────────────────────
        if let Some(io_bar) = device
            .bars
            .first()
            .filter(|bar| !bar.is_mmio && bar.base_address != 0)
        {
            let io_base = io_bar.base_address as u16;
            crate::println!(
                "[drivers] virtio-net PCI: trying legacy IO BAR base=0x{:x}",
                io_base
            );

            let region = Box::new(PciLegacyMmioRegion::new(
                io_base,
                device.device_id,
                device.vendor_id,
            ));
            let transport = VirtIoMmio::new(region);
            if let Some(net) = try_virtio_net_device(transport) {
                crate::println!("[drivers] virtio-net device found (PCI legacy IO)");
                return Some(net);
            }
        }
    }

    None
}
