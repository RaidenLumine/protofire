//! src/arch/riscv64/pci.rs
//!
//! RISC-V 64 PCIe: where the ECAM window is, and wiring MSI-X to the IMSIC.
//!
//! Configuration space itself is the shared walk in [`crate::arch::pci`] —
//! the register offsets, the BAR probes, the capability chain, the bus scan —
//! and it is the same code the other architectures run.  What is here is the
//! platform's part:
//!
//! - **Discovery.**  The device tree describes the window with a `compatible =
//!   "pci-host-ecam-generic"` node, and QEMU `virt` places it at `0x3000_0000`,
//!   inside the identity-mapped device window, so the walk can read the
//!   physical address directly.
//! - **MSI-X to the IMSIC.**  [`pci_enable_msix`] is the RISC-V half of an
//!   interrupt path with no callers yet; the module note in
//!   [`super::aia_imsic`] records what finishing it needs, which is a
//!   `siselect`/`sireg` rework of that controller rather than anything here.
//!
//! ## References
//!
//! - PCI Firmware Specification, Revision 3.0, § 4.1 (ECAM)
//! - `linux/Documentation/devicetree/bindings/pci/host-generic-pci.txt`

use crate::arch::fdt;
use crate::arch::pci::EcamRegion;

// The walk, re-exported so a caller naming this platform finds the whole
// vocabulary in one place.
pub use crate::arch::pci::cap_id;
pub use crate::arch::pci::find_device;
pub use crate::arch::pci::log_pci_devices;
pub use crate::arch::pci::pci_capability_find;
pub use crate::arch::pci::pci_capability_msi;
pub use crate::arch::pci::pci_capability_msix;
pub use crate::arch::pci::pci_capability_pcie;
pub use crate::arch::pci::pci_device_exists;
pub use crate::arch::pci::pci_enable_memory_and_bus_master;
pub use crate::arch::pci::pci_enumerate_buses;
pub use crate::arch::pci::pci_program_bar_64;
pub use crate::arch::pci::pci_read_bar_64;
pub use crate::arch::pci::pcie_check_hotplug_event;
pub use crate::arch::pci::pcie_read_slot_status;
pub use crate::arch::pci::probe_bar_size;
pub use crate::arch::pci::ConfigSpace;
pub use crate::arch::pci::MsiCapability;
pub use crate::arch::pci::MsixCapability;
pub use crate::arch::pci::PciBarInfo;
pub use crate::arch::pci::PciDeviceInfo;
pub use crate::arch::pci::PcieCapability;
pub use crate::arch::pci::PcieSlotCapabilities;

/// Hardcoded ECAM fallback for the QEMU `virt` machine without a device tree.
///
/// QEMU 8.x places the window at `0x3000_0000`, covering 256 buses.  The
/// address is inside the identity-mapped device window
/// (`0x0000_0000..0x4000_0000`), so no translation is needed.
const ECAM_QEMU_VIRT_BASE: usize = 0x3000_0000;
const ECAM_QEMU_VIRT_START_BUS: u8 = 0;
const ECAM_QEMU_VIRT_END_BUS: u8 = 255;

/// The window the device tree describes, if it describes one.
pub fn discover_ecam() -> Option<EcamRegion> {
    let info = fdt::platform_info();
    info.ecam_base.map(|base| {
        EcamRegion::new(
            base,
            info.ecam_start_bus.unwrap_or(0),
            info.ecam_end_bus.unwrap_or(255),
        )
    })
}

/// The discovered window, or the address QEMU `virt` fixes it at.
pub fn ecam_or_fallback() -> EcamRegion {
    discover_ecam().unwrap_or(EcamRegion::new(
        ECAM_QEMU_VIRT_BASE,
        ECAM_QEMU_VIRT_START_BUS,
        ECAM_QEMU_VIRT_END_BUS,
    ))
}

/// Program MSI-X for a PCIe device, delivering into the RISC-V AIA IMSIC.
///
/// Finds the device's MSI-X capability, derives the table address from the
/// capability's BAR indicator and offset, programs `count` entries through
/// [`crate::arch::riscv64::aia_imsic::configure_msix`] so they deliver
/// `base_irq..base_irq + count` to `target_cpu`'s IMSIC file, and enables the
/// capability.
///
/// Returns the first interrupt identity on success.  The caller registers a
/// handler with [`crate::arch::riscv64::aia_imsic::register_irq_handler`]
/// before the device raises interrupts.
///
/// Nothing calls this yet, and the module note in [`super::aia_imsic`] says
/// why: the IMSIC controller on the other side of it is written against an
/// interface its target does not have, so a device wired here would deliver
/// messages nobody receives.
pub fn pci_enable_msix(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    target_cpu: u32,
    base_irq: u32,
) -> Result<u32, crate::Error> {
    use crate::arch::riscv64::aia_imsic;

    if !aia_imsic::has_aia_imsic() {
        return Err(crate::Error::NotImplemented);
    }

    let cap_off = pci_capability_find(region, bus, device, function, cap_id::MSI_X)
        .ok_or(crate::Error::NotImplemented)?;

    // SAFETY: `cap_off` is the offset of the MSI-X capability the walk just
    // found on this function.
    let msix = unsafe { pci_capability_msix(region, bus, device, function, cap_off) };

    // Table BIR is bits 2:0 of the Table register; the offset is bits 31:3.
    let table_bir = (msix.table_bir_and_offset & 0x07) as u16;
    if table_bir >= 6 {
        return Err(crate::Error::InvalidArgument);
    }
    let table_offset = (msix.table_bir_and_offset & 0xFFFF_FFF8) as u64;

    // The table writes, and the messages that follow, go nowhere until the
    // device decodes MMIO and may act as a bus master.
    pci_enable_memory_and_bus_master(region, bus, device, function);

    // A BAR of zero is a BAR nobody has assigned an address to; programming
    // entries through it would write over whatever physical address that is.
    let bar_base = pci_read_bar_64(
        region,
        bus,
        device,
        function,
        crate::arch::pci::reg::BAR0 + table_bir * 4,
    );
    if bar_base == 0 {
        return Err(crate::Error::InvalidArgument);
    }
    let table_phys = bar_base
        .checked_add(table_offset)
        .ok_or(crate::Error::InvalidArgument)?;

    // Table size is (Message Control bits 10:0) + 1 entries.
    let table_size = ((msix.message_control & 0x07FF) as u32) + 1;

    let first_irq = aia_imsic::configure_msix(table_phys, table_size, target_cpu, base_irq)?;

    // Enable MSI-X (bit 15) and clear the function mask (bit 14) so the device
    // may raise interrupts.
    let new_control = (msix.message_control | (1u16 << 15)) & !(1u16 << 14);
    // SAFETY: the message-control half of the MSI-X capability the walk found,
    // inside this function's configuration space.
    unsafe {
        region.write_u16(bus, device, function, cap_off as u16 + 2, new_control);
    }

    crate::println!(
        "[pci   ] RISC-V MSI-X enabled on {:02x}:{:02x}.{} ({} entr{}, irq {})",
        bus,
        device,
        function,
        table_size,
        if table_size == 1 { "y" } else { "ies" },
        first_irq
    );

    Ok(first_irq)
}
