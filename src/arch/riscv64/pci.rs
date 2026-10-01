//! src/arch/riscv64/pci.rs
//!
//! RISC-V 64 PCIe: the shared walk, and wiring MSI-X to the IMSIC.
//!
//! Configuration space itself is the shared walk in [`crate::arch::pci`] —
//! the register offsets, the BAR probes, the capability chain, the bus scan —
//! and it is the same code the other architectures run.  What is left for
//! this platform to add is the enumeration: nothing here finds a window and
//! walks it, so nothing here says where one is.  The device-tree node it
//! would read is the same `pci-host-ecam-generic` one aarch64 reads, and QEMU
//! `virt` places the window at `0x3000_0000`, inside the identity-mapped
//! device window — a boot-time scan is the missing piece, and `ROADMAP.md`
//! lists it as one.
//!
//! What *is* here is the interrupt half: [`pci_enable_msix`] finds a device's
//! MSI-X capability and programs its table through the RISC-V AIA IMSIC.  It
//! is called by [`probe_first_msix`], which the boot runs once the bus it
//! found devices on: that is the half of a driver's contract which can be
//! checked without a driver — capability found, table's BAR and offset
//! decoded, entries written through the IMSIC and read back — and it leaves
//! the function masked, because a device nobody drives must not signal.
//!
//! ## References
//!
//! - PCI Firmware Specification, Revision 3.0, § 4.1 (ECAM)
//! - `linux/Documentation/devicetree/bindings/pci/host-generic-pci.txt`

use alloc::vec::Vec;

use crate::arch::fdt;
use crate::arch::pci::EcamRegion;

/// The window the device tree describes, if it describes one.
///
/// Unlike the AArch64 copy of this, there is nothing to alias: QEMU `virt`
/// puts this machine's window at `0x3000_0000`, inside the identity-mapped
/// device window the kernel boots with, so the walk reads it where the device
/// tree says it is.  A machine that describes none has none — no constant
/// stands in for a window nobody named.
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

/// A discovered window and the devices found on it.
pub struct EcamProbe {
    /// The window, read at the address the device tree named.
    pub region: EcamRegion,
    /// Devices discovered on the enumerated buses.
    pub devices: Vec<PciDeviceInfo>,
}

/// Enumerate the devices a window covers.
///
/// The device tree says this machine's window covers buses 0 through 255 and
/// its devices are all on bus 0, so bus 0 is walked first and the rest only if
/// it answered nothing: a full walk is 65 536 config-space probes of space
/// that QEMU's machine leaves empty, at every boot.  A machine that hung its
/// devices off a bridge is still enumerated, at that price.
fn enumerate(region: &EcamRegion) -> Vec<PciDeviceInfo> {
    let first_bus = *region.buses().start();
    let devices = pci_enumerate_buses(region, first_bus..=first_bus);
    if !devices.is_empty() {
        return devices;
    }
    pci_enumerate_buses(region, region.buses())
}

/// Discover the window and enumerate what is attached to it.
pub fn probe_and_enumerate() -> Option<EcamProbe> {
    let region = discover_ecam()?;
    crate::println!(
        "[pci   ] RISC-V PCIe ECAM at {:#018x}, buses {}..={}",
        region.base_address(),
        region.buses().start(),
        region.buses().end()
    );
    let devices = enumerate(&region);
    log_pci_devices(&region, &devices);
    Some(EcamProbe { region, devices })
}

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

/// What programming a device's MSI-X table did.
#[derive(Clone, Copy)]
pub struct MsixProgramming {
    /// The first interrupt identity the table's entries deliver.
    pub first_irq: u32,
    /// Where the table is, inside the identity-mapped device window.
    pub table_phys: u64,
    /// How many entries were programmed.
    pub table_size: u32,
}

/// Program MSI-X for a PCIe device, delivering into the RISC-V AIA IMSIC.
///
/// Finds the device's MSI-X capability, derives the table address from the
/// capability's BAR indicator and offset, programs `count` entries through
/// [`crate::arch::riscv64::aia_imsic::configure_msix`] so they deliver
/// `base_irq..base_irq + count` to `target_cpu`'s IMSIC file, and enables the
/// capability.
///
/// Returns where the entries went and which identity they deliver; the caller
/// registers a handler with
/// [`crate::arch::riscv64::aia_imsic::register_irq_handler`] before the device
/// raises interrupts.
pub fn pci_enable_msix(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    target_cpu: u32,
    base_irq: u32,
) -> Result<MsixProgramming, crate::Error> {
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

    Ok(MsixProgramming {
        first_irq,
        table_phys,
        table_size,
    })
}

/// The identity a device probe takes.
///
/// The IMSIC's identities are allocated by whoever registers a handler; a
/// probe that leaves its function masked is not competing for one, so it takes
/// the first identity that is not the boot self-test's.
const PROBE_BASE_IRQ: u32 = 1;

/// Exercise the MSI-X manager on the first device that has one.
///
/// This is not a driver: nothing here talks to the device.  It is the half of
/// a driver's contract that can be checked without one — the capability is
/// found, the table's BAR and offset are decoded, the entries are written
/// through the IMSIC, and then read back, which is what proves the BAR decodes
/// MMIO at all.  The function is masked again afterwards, so a device nobody
/// drives cannot raise an interrupt into an identity no handler owns.
///
/// A driver will do the same thing with a handler registered for its
/// identities, and then unmask.
pub fn probe_first_msix(region: &EcamRegion, devices: &[PciDeviceInfo]) -> Option<MsixProgramming> {
    use crate::arch::riscv64::aia_imsic;

    let device = devices.iter().find(|d| {
        pci_capability_find(region, d.bus, d.device, d.function, cap_id::MSI_X).is_some()
    })?;

    let programmed = pci_enable_msix(
        region,
        device.bus,
        device.device,
        device.function,
        0,
        PROBE_BASE_IRQ,
    )
    .map_err(|error| {
        // Say why rather than returning nothing: the interesting case is a
        // device whose MSI-X table has no address yet, because nothing assigned
        // one.  QEMU boots this kernel directly, with no firmware to run a PCI
        // resource pass, so a device's memory BARs read back as zero until
        // something assigns them — and an MSI-X table lives in a BAR.
        crate::println!(
            "[pci   ] RISC-V MSI-X on {:02x}:{:02x}.{} not programmed: {} — a \
             device whose BAR has no assigned address has no table to write",
            device.bus,
            device.device,
            device.function,
            error.as_str()
        );
    })
    .ok()?;

    // Read the table back.  QEMU's devices decode their BAR, so the four words
    // that went in are the four words that come out; a table nobody wrote
    // would read as zeroes (or as a fault) and this is where that shows.
    let entry_bytes = core::mem::size_of::<aia_imsic::MsixTableEntry>();
    for index in 0..programmed.table_size {
        let expected = aia_imsic::compose_msix_entry(0, programmed.first_irq + index);
        let entry = programmed.table_phys as usize + index as usize * entry_bytes;
        let read = aia_imsic::read_msix_entry(entry);
        if read != expected {
            crate::println!(
                "[pci   ] RISC-V MSI-X read-back mismatch on entry {} of {:02x}:{:02x}.{}",
                index,
                device.bus,
                device.device,
                device.function
            );
            return None;
        }
    }
    crate::println!(
        "[pci   ] RISC-V MSI-X probe: {} entries read back on {:02x}:{:02x}.{}",
        programmed.table_size,
        device.bus,
        device.device,
        device.function
    );

    // Mask the function again.  `pci_enable_msix` enabled it so a driver could
    // use the entries immediately; a probe that leaves no handler behind has to
    // put it back.
    if let Some(cap_off) = pci_capability_find(
        region,
        device.bus,
        device.device,
        device.function,
        cap_id::MSI_X,
    ) {
        // SAFETY: `cap_off` is the offset of the MSI-X capability the walk just
        // found on this function.
        let msix = unsafe {
            pci_capability_msix(region, device.bus, device.device, device.function, cap_off)
        };
        let masked = msix.message_control | (1u16 << 15) | (1u16 << 14);
        // SAFETY: as above — the message-control half of that same capability.
        unsafe {
            region.write_u16(
                device.bus,
                device.device,
                device.function,
                cap_off as u16 + 2,
                masked,
            );
        }
    }

    Some(programmed)
}

/// Program the first MSI-X-capable device, once the interrupt controller is up.
///
/// The boot enumerates its buses before the interrupt controller is
/// initialised, because drivers want the device list early — but an MSI-X
/// table is programmed *through* that controller, so the interrupt half has to
/// wait for it.  Re-walking the bus here costs a handful of config-space reads
/// and avoids threading the device list through the init sequence; the walk
/// itself is silent, so the boot still logs the devices once.
pub fn program_first_msix() -> Option<MsixProgramming> {
    let region = discover_ecam()?;
    let devices = enumerate(&region);
    if devices.is_empty() {
        return None;
    }
    probe_first_msix(&region, &devices)
}
