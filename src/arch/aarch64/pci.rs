//! src/arch/aarch64/pci.rs
//!
//! AArch64 PCIe: where the ECAM window is, and how it gets reached.
//!
//! Everything about configuration space that is not the window itself lives
//! in [`crate::arch::pci`] — the register offsets, the BAR probes, the
//! capability chain, the bus scan — and it is the same code the other
//! architectures run.  What is here is the platform's part:
//!
//! - **Discovery.**  The device tree describes the window with a `compatible =
//!   "pci-host-ecam-generic"` node whose `reg` property gives the base and
//!   whose `bus-range` gives the buses it covers.  [`discover_ecam`] turns that
//!   into an [`EcamRegion`].
//! - **Reaching it.**  QEMU `virt` places the window at `0x4010_0000_0000`,
//!   above the 39-bit `TTBR0` range the kernel maps with, so
//!   [`probe_and_enumerate`] maps it through a low virtual alias before the
//!   walk runs.  Reading the physical address directly is a level-0 translation
//!   fault, not a slow path.
//!
//! ## References
//!
//! - PCI Firmware Specification, Revision 3.0, § 4.1 (ECAM)
//! - `linux/Documentation/devicetree/bindings/pci/host-generic-pci.txt`

use alloc::vec::Vec;

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
pub use crate::arch::pci::MsiCapability;
pub use crate::arch::pci::MsixCapability;
pub use crate::arch::pci::PciBarInfo;
pub use crate::arch::pci::PciDeviceInfo;
pub use crate::arch::pci::PcieCapability;
pub use crate::arch::pci::PcieSlotCapabilities;

/// Hardcoded ECAM fallback for the QEMU `virt` machine without a device tree.
///
/// QEMU 8.x places the window at `0x4010_0000_0000`, covering 256 buses.  The
/// address is sign-extended for the 39-bit virtual space the kernel maps with
/// (`T0SZ=25`): bit 38 is set, so bits 63:39 must all be one, which is what
/// [`ECAM_QEMU_VIRT_BASE_VA`] does.
const ECAM_QEMU_VIRT_BASE_PA: u64 = 0x4010_0000_0000;
const ECAM_QEMU_VIRT_BASE_VA: usize = 0xFFFF_FFC0_1000_0000;
const ECAM_QEMU_VIRT_START_BUS: u8 = 0;
const ECAM_QEMU_VIRT_END_BUS: u8 = 255;

/// Size of the QEMU `virt` ECAM window: one MiB per bus, 256 buses.
pub const ECAM_QEMU_VIRT_SIZE: usize = 256 * 1024 * 1024;

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
        ECAM_QEMU_VIRT_BASE_VA,
        ECAM_QEMU_VIRT_START_BUS,
        ECAM_QEMU_VIRT_END_BUS,
    ))
}

/// Physical base of the QEMU `virt` window, for the MMU's sake.
pub const fn ecam_phys_base() -> u64 {
    ECAM_QEMU_VIRT_BASE_PA
}

/// The QEMU `virt` window at its physical address, which a 48-bit virtual
/// space (`T0SZ=16`) can address directly.
pub fn ecam_identity() -> EcamRegion {
    // Only bus 0 is scanned where the devices are, as in `probe_and_enumerate`.
    EcamRegion::new(ECAM_QEMU_VIRT_BASE_PA as usize, ECAM_QEMU_VIRT_START_BUS, 0)
}

/// A mapped window and the devices found on it.
pub struct EcamProbe {
    /// The window, reached through the alias [`probe_and_enumerate`] mapped.
    pub region: EcamRegion,
    /// Devices discovered on the enumerated buses.
    pub devices: Vec<PciDeviceInfo>,
}

/// Discover the window, map it through a low alias, and enumerate the bus.
///
/// The window's physical address is above the 39-bit `TTBR0` range on QEMU
/// `virt`, so it is mapped through an alias covering bus 0, which is where
/// QEMU places every PCIe device.  Returns `None` when no window is described
/// or the mapping fails.
pub fn probe_and_enumerate() -> Option<EcamProbe> {
    use crate::arch::aarch64::mmu::map_device_mmio_at;

    let discovered = discover_ecam()?;
    let ecam_pa = discovered.base_address() as u64;

    const ECAM_VA: usize = 0x2_0000_0000; // 8 GiB, L1 index 8 (unused)
    const ECAM_MAP_SIZE: usize = 2 * 1024 * 1024; // 2 MiB covers bus 0

    // SAFETY: the device tree named this range as the platform's ECAM window,
    // which is a live MMIO range, and `ECAM_VA` is a fixed address this
    // platform reserves for device windows.
    unsafe { map_device_mmio_at(ECAM_VA, ecam_pa, ECAM_MAP_SIZE)? };

    crate::println!(
        "[pci   ] AArch64 PCIe ECAM mapped PA={:#018x} -> VA={:#018x}",
        ecam_pa,
        ECAM_VA
    );

    let region = EcamRegion::new(ECAM_VA, 0, 0);
    let devices = pci_enumerate_buses(&region, region.buses());
    log_pci_devices(&region, &devices);

    Some(EcamProbe { region, devices })
}
