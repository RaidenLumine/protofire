//! src/arch/pci/walk.rs
//!
//! The configuration-space walk, once.
//!
//! What is here is everything about configuration space that does not depend
//! on how a byte of it is fetched: whether a function answers, what its BARs
//! are, what the capability chain holds, and which functions a bus has.  The
//! mechanism arrives as a [`ConfigSpace`] — an ECAM window on aarch64 and
//! riscv64, the legacy port pair on x86_64 — and this module is the reason
//! adding a machine means writing a backend rather than a bus scan.
//!
//! It was three copies before: one over the port pair, two over ECAM.  The two
//! ECAM copies had already drifted in small ways (one re-read a BAR's upper
//! dword without checking the type field, one masked the multifunction bit out
//! of the header type it stored), which is what copies do.  Where they
//! disagreed, the reading that the specification supports is the one here.

use alloc::vec::Vec;
use core::ops::RangeInclusive;

use super::cap_id;
use super::reg;
use super::ConfigSpace;
use super::MsiCapability;
use super::MsixCapability;
use super::PcieCapability;
use super::PcieSlotCapabilities;

// ---------------------------------------------------------------------------
// What a scan finds
// ---------------------------------------------------------------------------

/// Decoded Base Address Register information.
#[derive(Debug, Clone, Copy)]
pub struct PciBarInfo {
    /// Physical base address (zero if the BAR is unimplemented).
    pub base_address: u64,
    /// Size of the region in bytes (zero if unimplemented).
    pub size: u64,
    /// True for 64-bit BARs (occupies two consecutive BAR slots).
    pub is_64bit: bool,
    /// True if the region is prefetchable.
    pub is_prefetchable: bool,
    /// True if the BAR is memory-mapped; false for I/O-mapped.
    pub is_mmio: bool,
}

impl PciBarInfo {
    const UNIMPLEMENTED: Self = Self {
        base_address: 0,
        size: 0,
        is_64bit: false,
        is_prefetchable: false,
        is_mmio: false,
    };
}

/// Information about a discovered PCI/PCIe device.
#[derive(Debug, Clone)]
pub struct PciDeviceInfo {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub revision_id: u8,
    pub bars: [PciBarInfo; 6],
    pub capability_ptr: Option<u8>,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciDeviceInfo {
    /// Returns `true` if this is a multi-function device (header type bit 7).
    pub fn is_multifunction(&self) -> bool {
        self.header_type & 0x80 != 0
    }

    /// Human-readable class name.
    ///
    /// The class code is three bytes: class, subclass, programming interface.
    /// Only the first two select the name — a device that reports a class we
    /// do not know is "Other", which is a truer answer than an empty label.
    pub fn class_name(&self) -> &'static str {
        match (self.class_code, self.subclass) {
            (0x00, _) => "Unclassified",
            (0x01, 0x00) => "SCSI",
            (0x01, 0x01) => "IDE",
            (0x01, 0x06) => "SATA",
            (0x01, 0x08) => "NVMe",
            (0x02, 0x00) => "Ethernet",
            (0x03, 0x00) => "VGA",
            (0x03, 0x01) => "XGA",
            (0x04, 0x00) => "Video",
            (0x04, 0x01) => "Audio Device",
            (0x04, 0x03) => "HD Audio Controller",
            (0x06, 0x00) => "Host Bridge",
            (0x06, 0x01) => "ISA Bridge",
            (0x06, 0x04) => "PCI-to-PCI Bridge",
            (0x0C, 0x03) => "USB",
            _ => "Other",
        }
    }
}

// ---------------------------------------------------------------------------
// Presence and the COMMAND register
// ---------------------------------------------------------------------------

/// Returns `true` if a function answers at this address.
///
/// Absent functions answer `0xFFFF` in the vendor-ID register — that is the
/// convention the probe is built on, not a heuristic.
pub fn pci_device_exists<C: ConfigSpace>(cfg: &C, bus: u8, device: u8, function: u8) -> bool {
    // SAFETY: the caller's contract covers `cfg`; the vendor-ID register is
    // defined for every bus/device/function triple, which is exactly what
    // makes it the presence probe — an absent function answers all-ones.
    let vendor = unsafe { cfg.read_u16(bus, device, function, reg::VENDOR_ID) };
    vendor != reg::VENDOR_ID_NONE
}

/// Enable memory-space access and bus mastering for a function.
///
/// Without this the device's MMIO BARs are inaccessible and DMA is
/// suppressed, which is the state a device comes out of reset in.
pub fn pci_enable_memory_and_bus_master<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
) {
    // SAFETY: the command register of the function the caller named, inside
    // the configuration space `cfg` describes.
    let command = unsafe { cfg.read_u16(bus, device, function, reg::COMMAND) };
    let new_command = command | reg::COMMAND_MEMORY | reg::COMMAND_BUS_MASTER;
    if new_command != command {
        // SAFETY: writing back the same register, with only the two bits the
        // operation is defined to set changed.
        unsafe { cfg.write_u16(bus, device, function, reg::COMMAND, new_command) };
    }
}

// ---------------------------------------------------------------------------
// BARs
// ---------------------------------------------------------------------------

/// Program a 64-bit memory BAR with a physical address.
///
/// The lower 32 bits go to `bar_offset` and the upper 32 to `bar_offset + 4`.
pub fn pci_program_bar_64<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
    bar_offset: u16,
    phys_addr: u64,
) {
    let lo = (phys_addr & 0xFFFF_FFF0) as u32;
    let hi = ((phys_addr >> 32) & 0xFFFF_FFFF) as u32;
    // SAFETY: both halves of the 64-bit BAR belong to the function the caller
    // named, and both offsets lie inside its configuration space.
    unsafe {
        cfg.write_u32(bus, device, function, bar_offset, lo);
        cfg.write_u32(bus, device, function, bar_offset + 4, hi);
    }
}

/// Read a BAR as a 64-bit address.
///
/// The register at `bar_offset + 4` is the upper half of *this* BAR only when
/// the type field (bits 2:1 of the low dword) says the BAR is 64-bit wide.
/// For a 32-bit BAR that register belongs to a different BAR, so reading it as
/// an upper half would corrupt the address.
pub fn pci_read_bar_64<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
    bar_offset: u16,
) -> u64 {
    // SAFETY: the low dword of a BAR of the function the caller named, inside
    // the configuration space `cfg` describes.
    let lo = unsafe { cfg.read_u32(bus, device, function, bar_offset) };
    let is_64bit = (lo & 0x0000_0006) == 0x0000_0004;
    let hi = if is_64bit {
        // SAFETY: as the read above — the high dword of the same 64-bit BAR,
        // taken only because the type field says the register is its upper
        // half rather than a separate BAR.
        unsafe { cfg.read_u32(bus, device, function, bar_offset + 4) }
    } else {
        0
    };
    ((hi as u64) << 32) | (lo as u64 & 0xFFFF_FFF0)
}

/// Probe the size of a BAR by writing all-ones, reading the size mask back,
/// and restoring the original value.
///
/// Returns the size in bytes, or 0 when the BAR is unimplemented (it reads
/// back all-ones) or reads back zero.
///
/// Only the low dword is probed, so a 64-bit BAR larger than 4 GiB is
/// under-reported.  QEMU `virt` and `q35` both place their BARs below 4 GiB,
/// so the limit is not reached here; the caller that needs it would probe the
/// upper dword too.
pub fn probe_bar_size<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
    bar_offset: u16,
) -> u64 {
    // SAFETY: the BAR register of the function the caller named, inside the
    // configuration space `cfg` describes.
    let bar_raw = unsafe { cfg.read_u32(bus, device, function, bar_offset) };
    let is_mmio = (bar_raw & 0x01) == 0;

    // SAFETY: the all-ones write that BAR sizing is defined in terms of, to
    // the same register just read.
    unsafe { cfg.write_u32(bus, device, function, bar_offset, 0xFFFF_FFFF) };
    // SAFETY: reading back the mask the device answers with.
    let size_mask = unsafe { cfg.read_u32(bus, device, function, bar_offset) };
    // SAFETY: restoring the value read at entry, so the probe leaves the
    // device as it found it.
    unsafe { cfg.write_u32(bus, device, function, bar_offset, bar_raw) };

    if size_mask == 0 || size_mask == 0xFFFF_FFFF {
        return 0;
    }
    let raw_size = if is_mmio {
        size_mask & 0xFFFF_FFF0
    } else {
        size_mask & 0xFFFF_FFFC
    };
    (!raw_size).wrapping_add(1) as u64
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// Walk the capability linked list and return the offset of the first
/// capability with `cap_id`, or `None`.
pub fn pci_capability_find<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
    cap_id: u8,
) -> Option<u8> {
    // SAFETY: the status register of a function on this bus; status bit 4 is
    // what says whether the list the next read heads exists.
    let status = unsafe { cfg.read_u16(bus, device, function, reg::STATUS) };
    if status & 0x0010 == 0 {
        return None;
    }

    // SAFETY: the capabilities-pointer byte of the same standard header.
    let mut ptr: u8 = unsafe { cfg.read_u8(bus, device, function, reg::CAP_PTR) };
    // Capability pointers sit dword-aligned in the first 256 bytes of the
    // header, and the count bounds a malformed chain.
    let mut visited = 0;
    while ptr >= 0x40 && visited < 48 {
        // SAFETY: `ptr` is a byte the loop keeps at or above 0x40, so it lands
        // inside the function's own 256-byte head of configuration space.
        let this_id = unsafe { cfg.read_u8(bus, device, function, ptr as u16) };
        if this_id == cap_id {
            return Some(ptr);
        }
        // SAFETY: the next-capability byte, the byte after the one just read.
        let next = unsafe { cfg.read_u8(bus, device, function, ptr as u16 + 1) };
        if next < 0x40 {
            break;
        }
        ptr = next;
        visited += 1;
    }
    None
}

/// Parse the MSI capability at `offset`.
///
/// # Safety
///
/// `offset` must be the offset of a valid MSI capability of this function, as
/// [`pci_capability_find`] returns.
pub unsafe fn pci_capability_msi<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
) -> MsiCapability {
    let off = offset as u16;
    // SAFETY: the caller's contract says `offset` names a valid MSI
    // capability of this function, so the message-control half is inside its
    // configuration space.
    let message_control = unsafe { cfg.read_u16(bus, device, function, off + 2) };
    let is_64bit = (message_control & 0x0080) != 0;
    let per_vector_mask = (message_control & 0x0100) != 0;

    // SAFETY: as above — the message-address dword of the same capability.
    let message_address = unsafe { cfg.read_u32(bus, device, function, off + 4) };
    let (message_upper_address, data_offset) = if is_64bit {
        (
            // SAFETY: the upper address dword, present only because the
            // capability reports the 64-bit layout.
            Some(unsafe { cfg.read_u32(bus, device, function, off + 8) }),
            off + 12,
        )
    } else {
        (None, off + 8)
    };

    // SAFETY: the message-data half, at the offset the layout puts it for the
    // width this capability reports.
    let message_data = unsafe { cfg.read_u16(bus, device, function, data_offset) };

    let (mask_bits, pending_bits) = if per_vector_mask {
        (
            // SAFETY: the per-vector mask dword, present only when the
            // capability reports per-vector masking.
            Some(unsafe { cfg.read_u32(bus, device, function, data_offset + 2) }),
            // SAFETY: the pending-bits dword that follows it.
            Some(unsafe { cfg.read_u32(bus, device, function, data_offset + 6) }),
        )
    } else {
        (None, None)
    };

    MsiCapability {
        offset,
        message_control,
        message_address,
        message_upper_address,
        message_data,
        mask_bits,
        pending_bits,
    }
}

/// Parse the MSI-X capability at `offset`.
///
/// # Safety
///
/// `offset` must be the offset of a valid MSI-X capability of this function,
/// as [`pci_capability_find`] returns.
pub unsafe fn pci_capability_msix<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
) -> MsixCapability {
    let off = offset as u16;
    // SAFETY: the caller's contract says `offset` names a valid MSI-X
    // capability of this function, so the three structure members below are
    // inside its configuration space.
    let message_control = unsafe { cfg.read_u16(bus, device, function, off + 2) };
    // SAFETY: as above — the table's BIR and offset dword.
    let table_bir_and_offset = unsafe { cfg.read_u32(bus, device, function, off + 4) };
    // SAFETY: as above — the pending-bit array's BIR and offset dword.
    let pba_bir_and_offset = unsafe { cfg.read_u32(bus, device, function, off + 8) };

    MsixCapability {
        offset,
        message_control,
        table_bir_and_offset,
        pba_bir_and_offset,
    }
}

/// Parse the PCI Express capability at `offset`.
///
/// # Safety
///
/// `offset` must be the offset of a valid PCIe capability of this function, as
/// [`pci_capability_find`] returns.
pub unsafe fn pci_capability_pcie<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
) -> PcieCapability {
    let off = offset as u16;
    // SAFETY: the caller's contract says `offset` names a valid PCIe
    // capability of this function, so the register halves read below are
    // inside its configuration space at the offsets the layout fixes.
    let pcie_caps = unsafe { cfg.read_u16(bus, device, function, off + 2) };
    // SAFETY: as above — the device-capabilities dword.
    let device_caps = unsafe { cfg.read_u32(bus, device, function, off + 4) };
    // SAFETY: as above — the device-control half.
    let device_control = unsafe { cfg.read_u16(bus, device, function, off + 8) };
    // SAFETY: as above — the link-capabilities dword.
    let link_caps = unsafe { cfg.read_u32(bus, device, function, off + 12) };
    // SAFETY: as above — the link-status half that closes the layout.
    let link_status = unsafe { cfg.read_u16(bus, device, function, off + 18) };

    PcieCapability {
        offset,
        pcie_caps,
        device_caps,
        device_control,
        link_caps,
        link_status,
    }
}

/// Read the slot capabilities and status of a PCIe port.
///
/// Only a root port or a downstream port that implements a slot has anything
/// meaningful here; an upstream port answers zero, which reads as a slot that
/// is neither hotplug-capable nor occupied.
pub fn pcie_read_slot_status<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
) -> Option<PcieSlotCapabilities> {
    let pcie_off = pci_capability_find(cfg, bus, device, function, cap_id::PCI_EXPRESS)?;

    // SAFETY: the slot structure sits at +0x14 of a PCIe capability the walk
    // just found, inside the same function's configuration space.
    unsafe {
        let slot_caps = cfg.read_u32(bus, device, function, pcie_off as u16 + 0x14);
        let slot_control = cfg.read_u16(bus, device, function, pcie_off as u16 + 0x18);
        let slot_status = cfg.read_u16(bus, device, function, pcie_off as u16 + 0x1A);

        Some(PcieSlotCapabilities {
            slot_caps,
            slot_control,
            slot_status,
            // Hotplug-capable: slot capabilities bit 6.  Card present:
            // slot status bit 6 (presence detect state).
            hotplug_capable: (slot_caps & (1 << 6)) != 0,
            presence_detect_state: (slot_status & (1 << 6)) != 0,
        })
    }
}

/// Check a PCIe slot for a hotplug event.
///
/// Returns `Some(true)` when a card was inserted, `Some(false)` when one was
/// removed, and `None` when nothing changed.  The two status bits that report
/// the change are write-1-to-clear, so this clears them.
pub fn pcie_check_hotplug_event<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
) -> Option<bool> {
    let pcie_off = pci_capability_find(cfg, bus, device, function, cap_id::PCI_EXPRESS)?;

    // SAFETY: the slot-status half of a PCIe capability the walk just found,
    // inside the same function's configuration space.
    unsafe {
        let slot_status = cfg.read_u16(bus, device, function, pcie_off as u16 + 0x1A);

        // Bit 3: presence detect changed.  Bit 7: data link layer state
        // changed.
        let presence_changed = (slot_status & (1 << 3)) != 0;
        let link_changed = (slot_status & (1 << 7)) != 0;
        if !presence_changed && !link_changed {
            return None;
        }

        // Writing one to a write-1-to-clear bit clears it, and is the only way
        // to re-arm the event.
        cfg.write_u16(
            bus,
            device,
            function,
            pcie_off as u16 + 0x1A,
            (1 << 3) | (1 << 7),
        );
        let after = cfg.read_u16(bus, device, function, pcie_off as u16 + 0x1A);
        Some((after & (1 << 6)) != 0)
    }
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// Read everything the walk reports about one function.
fn read_device_info<C: ConfigSpace>(
    cfg: &C,
    bus: u8,
    device: u8,
    function: u8,
) -> Option<PciDeviceInfo> {
    // SAFETY: the vendor ID decides whether this function exists; the address
    // is the first dword of its configuration space.
    let vendor_id = unsafe { cfg.read_u16(bus, device, function, reg::VENDOR_ID) };
    if vendor_id == reg::VENDOR_ID_NONE {
        return None;
    }

    // SAFETY: the registers below are all part of the standard header that the
    // read above identified, at the offsets the specification fixes.
    let (device_id, class_code, subclass, prog_if, header_type, revision_id) = unsafe {
        (
            cfg.read_u16(bus, device, function, reg::DEVICE_ID),
            cfg.read_u8(bus, device, function, reg::CLASS),
            cfg.read_u8(bus, device, function, reg::CLASS - 1),
            cfg.read_u8(bus, device, function, reg::CLASS - 2),
            // The whole byte: bit 7 is the multifunction flag, and the
            // enumerator and the report both read it from here.
            cfg.read_u8(bus, device, function, reg::HEADER_TYPE),
            cfg.read_u8(bus, device, function, reg::REVISION_ID),
        )
    };
    // SAFETY: the interrupt line and the pin that follows it are the last two
    // bytes of the same standard header.
    let (interrupt_line, interrupt_pin, status) = unsafe {
        (
            cfg.read_u8(bus, device, function, reg::INTERRUPT_LINE),
            cfg.read_u8(bus, device, function, reg::INTERRUPT_LINE + 1),
            cfg.read_u16(bus, device, function, reg::STATUS),
        )
    };
    let capability_ptr = if status & 0x0010 != 0 {
        // SAFETY: the capabilities pointer, read only when the status register
        // says the function has a list behind it.
        Some(unsafe { cfg.read_u8(bus, device, function, reg::CAP_PTR) })
    } else {
        None
    };

    let mut bars = [PciBarInfo::UNIMPLEMENTED; 6];
    let bar_offsets = [
        reg::BAR0,
        reg::BAR1,
        reg::BAR2,
        reg::BAR3,
        reg::BAR4,
        reg::BAR5,
    ];
    let mut index = 0;
    while index < 6 {
        let offset = bar_offsets[index];
        // SAFETY: the low dword of BAR `index`, inside this function's own
        // configuration space.
        let bar_lo = unsafe { cfg.read_u32(bus, device, function, offset) };
        if bar_lo == 0 {
            index += 1;
            continue;
        }

        let is_mmio = (bar_lo & 0x01) == 0;
        let is_64bit = is_mmio && ((bar_lo >> 1) & 0x03) == 0x02;
        let is_prefetchable = is_mmio && ((bar_lo >> 3) & 0x01) == 1;

        let mut base_address = if is_mmio {
            (bar_lo & 0xFFFF_FFF0) as u64
        } else {
            (bar_lo & 0xFFFF_FFFC) as u64
        };

        if is_64bit && index + 1 < 6 {
            // SAFETY: the high dword of the same 64-bit BAR, which the index
            // bound keeps inside the six-BAR table.
            let bar_hi = unsafe { cfg.read_u32(bus, device, function, bar_offsets[index + 1]) };
            base_address |= (bar_hi as u64) << 32;
        }

        bars[index] = PciBarInfo {
            base_address,
            size: probe_bar_size(cfg, bus, device, function, offset),
            is_64bit,
            is_prefetchable,
            is_mmio,
        };

        // A 64-bit BAR consumes its neighbour's slot.
        index += if is_64bit { 2 } else { 1 };
    }

    Some(PciDeviceInfo {
        bus,
        device,
        function,
        vendor_id,
        device_id,
        class_code,
        subclass,
        prog_if,
        header_type,
        revision_id,
        bars,
        capability_ptr,
        interrupt_line,
        interrupt_pin,
    })
}

/// Enumerate the functions on `buses`.
///
/// Only function 0 is probed unless the header says the device is
/// multi-function, which is what the header type's bit 7 means.
pub fn pci_enumerate_buses<C: ConfigSpace>(
    cfg: &C,
    buses: RangeInclusive<u8>,
) -> Vec<PciDeviceInfo> {
    let mut devices: Vec<PciDeviceInfo> = Vec::new();

    for bus in buses {
        let mut bus_has_devices = false;

        for device in 0u8..32u8 {
            if !pci_device_exists(cfg, bus, device, 0) {
                continue;
            }
            bus_has_devices = true;

            // SAFETY: the header type of a function the vendor-ID probe just
            // found, in the same configuration space that probe read.
            let header_type = unsafe { cfg.read_u8(bus, device, 0, reg::HEADER_TYPE) };
            let functions = if header_type & 0x80 != 0 { 8 } else { 1 };

            for function in 0u8..functions {
                if !pci_device_exists(cfg, bus, device, function) {
                    continue;
                }
                if let Some(info) = read_device_info(cfg, bus, device, function) {
                    devices.push(info);
                }
            }
        }

        // A machine with no device on bus 0 has none on the buses behind it
        // either, and a scan of 256 empty buses is not free.
        if !bus_has_devices && bus > 16 && devices.is_empty() {
            break;
        }
    }

    devices
}

/// Print one line per device, plus a line per implemented BAR.
pub fn log_pci_devices<C: ConfigSpace>(cfg: &C, devices: &[PciDeviceInfo]) {
    crate::println!("[pci   ] PCI: {} device(s) found", devices.len());
    for dev in devices {
        let multifunction = if dev.is_multifunction() { " [MF]" } else { "" };
        crate::println!(
            "[pci   ]   {:02x}:{:02x}.{} vend={:04x} dev={:04x}  class={:02x}:{:02x}:{:02x}{}  {}",
            dev.bus,
            dev.device,
            dev.function,
            dev.vendor_id,
            dev.device_id,
            dev.class_code,
            dev.subclass,
            dev.prog_if,
            multifunction,
            dev.class_name(),
        );

        for (i, bar) in dev.bars.iter().enumerate() {
            if bar.size == 0 {
                continue;
            }
            crate::println!(
                "[pci   ]     BAR{}: {}{} {}  base=0x{:016X}  size=0x{:X}",
                i,
                if bar.is_mmio { "MMIO" } else { "IO" },
                if bar.is_prefetchable { " pref" } else { "" },
                if bar.is_64bit { "64" } else { "32" },
                bar.base_address,
                bar.size,
            );
        }

        if dev.capability_ptr.is_some() {
            let mut caps: [&str; 4] = ["", "", "", ""];
            let mut n = 0;
            if pci_capability_find(cfg, dev.bus, dev.device, dev.function, cap_id::PCI_EXPRESS)
                .is_some()
            {
                caps[n] = "PCIe";
                n += 1;
            }
            let msix = pci_capability_find(cfg, dev.bus, dev.device, dev.function, cap_id::MSI_X)
                .is_some();
            if msix {
                caps[n] = "MSI-X";
                n += 1;
            }
            let msi =
                pci_capability_find(cfg, dev.bus, dev.device, dev.function, cap_id::MSI).is_some();
            if msi && !msix {
                caps[n] = "MSI";
                n += 1;
            }
            if n > 0 {
                crate::print!("[pci   ]     caps:");
                for (i, cap) in caps[..n].iter().enumerate() {
                    if i > 0 {
                        crate::print!(",");
                    }
                    crate::print!(" {}", cap);
                }
                crate::println!();
            }
        }
    }
}

/// Find the first device matching `vendor_id` and, when supplied, `device_id`.
pub fn find_device(
    devices: &[PciDeviceInfo],
    vendor_id: u16,
    device_id: Option<u16>,
) -> Option<&PciDeviceInfo> {
    devices
        .iter()
        .find(|dev| dev.vendor_id == vendor_id && device_id.is_none_or(|id| dev.device_id == id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    const VENDOR: u16 = 0x1AF4;
    const DEVICE: u16 = 0x1000;
    /// A 32-bit MMIO BAR at a plausible address.
    const BAR0_VALUE: u32 = 0xFE00_0000;
    /// The lower half of a 64-bit MMIO BAR, and its upper half.
    const BAR2_VALUE: u32 = 0xC000_0004;
    const BAR2_HIGH: u32 = 0x0000_0001;
    /// What a 4 KiB BAR answers to the all-ones sizing write.
    const BAR_MASK: u32 = 0xFFFF_F000;
    /// The MSI-X capability's offset in the chain.
    const MSIX_OFFSET: u8 = 0x40;

    /// A configuration space that is memory rather than MMIO.
    ///
    /// One function answers — bus 0, device 0, function 0 — and every other
    /// address answers all-ones, which is what an absent function does.  It
    /// exists so the walk can run without a machine: the same code that reads
    /// through an ECAM window or a port pair reads through this, and a
    /// regression in it is a failing unit test rather than a boot that finds
    /// no devices.
    struct MockConfig {
        words: RefCell<[u32; 1024]>,
        /// What each BAR slot answers with after the all-ones sizing write.
        /// Zero means the slot is unimplemented.
        bar_masks: [u32; 6],
    }

    impl MockConfig {
        fn new() -> Self {
            let mut words = [0u32; 1024];
            words[reg::VENDOR_ID as usize / 4] = ((DEVICE as u32) << 16) | VENDOR as u32;
            // The dword at 0x08 is revision, programming interface, subclass
            // and class, low byte first: class 0x02 / subclass 0x00 / prog-if
            // 0x00 is an Ethernet controller.
            words[reg::REVISION_ID as usize / 4] = 0x0200_0000;
            // Status bit 4: the function has a capability list.
            words[reg::STATUS as usize / 4] = 0x0010_0000;
            // The list starts at 0x40 and holds one capability: MSI-X.
            words[reg::CAP_PTR as usize / 4] = MSIX_OFFSET as u32;
            let cap = MSIX_OFFSET as usize / 4;
            words[cap] = cap_id::MSI_X as u32; // id, and a null next pointer
            words[cap + 1] = 0x0000_2000; // table in BAR 0 at offset 0x2000
            words[cap + 2] = 0x0000_3000; // pending-bit array in BAR 0
                                          // BAR 0: 32-bit MMIO.  BAR 2 and 3: one 64-bit MMIO BAR.
            words[reg::BAR0 as usize / 4] = BAR0_VALUE;
            words[reg::BAR2 as usize / 4] = BAR2_VALUE;
            words[reg::BAR2 as usize / 4 + 1] = BAR2_HIGH;

            Self {
                words: RefCell::new(words),
                bar_masks: [BAR_MASK, 0, BAR_MASK, 0, 0, 0],
            }
        }

        fn bar_slot(offset: u16) -> Option<usize> {
            let slots = [
                reg::BAR0,
                reg::BAR1,
                reg::BAR2,
                reg::BAR3,
                reg::BAR4,
                reg::BAR5,
            ];
            slots.iter().position(|slot| *slot == offset)
        }

        fn read_word(&self, bus: u8, device: u8, function: u8, offset: u16) -> u32 {
            if (bus, device, function) != (0, 0, 0) {
                return 0xFFFF_FFFF;
            }
            self.words.borrow()[(offset as usize & 0xFFC) / 4]
        }

        fn write_word(&self, bus: u8, device: u8, function: u8, offset: u16, value: u32) {
            if (bus, device, function) != (0, 0, 0) {
                return;
            }
            // A sizing write is not stored: the device answers it with the
            // mask for the slot, which is what makes the probe work.
            let stored = match Self::bar_slot(offset) {
                Some(slot) if value == 0xFFFF_FFFF => self.bar_masks[slot],
                _ => value,
            };
            self.words.borrow_mut()[(offset as usize & 0xFFC) / 4] = stored;
        }
    }

    impl ConfigSpace for &MockConfig {
        unsafe fn read_u8(&self, bus: u8, device: u8, function: u8, offset: u16) -> u8 {
            let word = self.read_word(bus, device, function, offset & 0xFFFC);
            (word >> (8 * (offset & 0x3))) as u8
        }

        unsafe fn read_u16(&self, bus: u8, device: u8, function: u8, offset: u16) -> u16 {
            let word = self.read_word(bus, device, function, offset & 0xFFFC);
            (word >> (8 * (offset & 0x2))) as u16
        }

        unsafe fn read_u32(&self, bus: u8, device: u8, function: u8, offset: u16) -> u32 {
            self.read_word(bus, device, function, offset)
        }

        unsafe fn write_u8(&self, bus: u8, device: u8, function: u8, offset: u16, value: u8) {
            let aligned = offset & 0xFFFC;
            let shift = 8 * (offset & 0x3);
            let word = self.read_word(bus, device, function, aligned);
            self.write_word(
                bus,
                device,
                function,
                aligned,
                (word & !(0xFF << shift)) | ((value as u32) << shift),
            );
        }

        unsafe fn write_u16(&self, bus: u8, device: u8, function: u8, offset: u16, value: u16) {
            let aligned = offset & 0xFFFC;
            let shift = 8 * (offset & 0x2);
            let word = self.read_word(bus, device, function, aligned);
            self.write_word(
                bus,
                device,
                function,
                aligned,
                (word & !(0xFFFF << shift)) | ((value as u32) << shift),
            );
        }

        unsafe fn write_u32(&self, bus: u8, device: u8, function: u8, offset: u16, value: u32) {
            self.write_word(bus, device, function, offset, value);
        }
    }

    #[test]
    fn the_walk_finds_the_device_and_both_of_its_bars() {
        let mock = MockConfig::new();
        let devices = pci_enumerate_buses(&&mock, 0..=0);

        assert_eq!(devices.len(), 1, "one function answers on this bus");
        let dev = &devices[0];
        assert_eq!((dev.vendor_id, dev.device_id), (VENDOR, DEVICE));
        assert_eq!(dev.class_name(), "Ethernet");
        assert!(!dev.is_multifunction());

        let bar0 = &dev.bars[0];
        assert!(bar0.is_mmio && !bar0.is_64bit, "BAR 0 is 32-bit MMIO");
        assert_eq!(bar0.base_address, BAR0_VALUE as u64);
        assert_eq!(bar0.size, 0x1000, "the sizing write answered 4 KiB");

        assert_eq!(dev.bars[1].size, 0, "BAR 1 is unimplemented");
        let bar2 = &dev.bars[2];
        assert!(bar2.is_mmio && bar2.is_64bit, "BAR 2 is a 64-bit MMIO BAR");
        assert_eq!(
            bar2.base_address,
            ((BAR2_HIGH as u64) << 32) | (BAR2_VALUE as u64 & 0xFFFF_FFF0),
            "the upper dword belongs to this BAR"
        );
        assert_eq!(dev.bars[3].size, 0, "BAR 3 is the upper half, not a BAR");
    }

    #[test]
    fn the_size_probe_leaves_the_bar_as_it_found_it() {
        let mock = MockConfig::new();
        let before = mock.read_word(0, 0, 0, reg::BAR0);

        assert_eq!(probe_bar_size(&&mock, 0, 0, 0, reg::BAR0), 0x1000);

        assert_eq!(
            mock.read_word(0, 0, 0, reg::BAR0),
            before,
            "the all-ones write is undone, so the device keeps its address"
        );
    }

    #[test]
    fn the_capability_chain_holds_msix_at_the_offset_it_says() {
        let mock = MockConfig::new();

        let found = pci_capability_find(&&mock, 0, 0, 0, cap_id::MSI_X);
        assert_eq!(found, Some(MSIX_OFFSET));
        assert_eq!(
            pci_capability_find(&&mock, 0, 0, 0, cap_id::MSI),
            None,
            "a capability that is not in the chain is not reported"
        );

        // SAFETY: the walk just returned this offset as the MSI-X capability
        // of this function, which is what the parse requires.
        let msix = unsafe { pci_capability_msix(&&mock, 0, 0, 0, found.unwrap()) };
        assert_eq!(msix.offset, MSIX_OFFSET);
        assert_eq!(msix.message_control, 0, "one table entry, not masked");
        assert_eq!(msix.table_bir_and_offset, 0x0000_2000);
        assert_eq!(msix.pba_bir_and_offset, 0x0000_3000);
    }

    #[test]
    fn an_absent_function_answers_all_ones_and_is_not_a_device() {
        let mock = MockConfig::new();

        assert!(pci_device_exists(&&mock, 0, 0, 0));
        assert!(!pci_device_exists(&&mock, 0, 0, 1));
        assert!(!pci_device_exists(&&mock, 1, 0, 0));
        assert!(pci_enumerate_buses(&&mock, 1..=3).is_empty());
    }
}
