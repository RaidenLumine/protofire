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

/// The window the device tree describes, if it describes one.
///
/// There is deliberately no hardcoded fallback beside it.  The arm64 `Image`
/// boot path is always handed a device tree, and this platform's window sits
/// above the range the kernel maps — so a boot that fell back to a constant
/// address would either fault or quietly enumerate nothing, which is exactly
/// the failure the runtime check's "the device tree arrived and was used"
/// assertion exists to catch.  A machine that describes no window has none.
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
