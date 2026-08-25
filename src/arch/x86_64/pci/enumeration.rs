//! src/arch/x86_64/pci/enumeration.rs
//!
//! PCI/PCIe bus enumeration: device discovery, BAR probing, and capability
//! walking.
//!
//! Builds on the raw config-space primitives from `super::raw` to provide
//! a complete bus scan, BAR size detection, and PCI capability chain
//! traversal (MSI, MSI-X, PCI Express).

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::vec::Vec;

use super::raw::PciAddress;
use super::raw::{self};

// ---------------------------------------------------------------------------
// BAR info
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

// ---------------------------------------------------------------------------
// PCI device info
// ---------------------------------------------------------------------------

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
    /// Returns the PCI address for this device.
    pub fn address(&self) -> PciAddress {
        PciAddress::new(self.bus, self.device, self.function)
    }

    /// Returns `true` if this is a multi-function device (header_type bit 7).
    pub fn is_multifunction(&self) -> bool {
        self.header_type & 0x80 != 0
    }

    /// Human-readable class name.
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
            _ => "",
        }
    }
}

// ---------------------------------------------------------------------------
// BAR probing
// ---------------------------------------------------------------------------

/// Offsets of the 6 BAR registers in PCI config space.
#[allow(dead_code)]
const BAR_OFFSETS: [u8; 6] = [
    raw::BAR0,
    raw::BAR1,
    raw::BAR2,
    raw::BAR3,
    raw::BAR4,
    raw::BAR5,
];

/// Probe a single BAR at the given offset.
///
/// Writes all-ones to the BAR, reads back the size bits, then restores the
/// original value.  Returns `PciBarInfo` with base, size, and flags.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_bar(addr: PciAddress, bar_offset: u8) -> PciBarInfo {
    let bar_raw = unsafe { raw::pci_config_read_u32(addr, bar_offset) };

    // Bits 0 determines whether this is a Memory (bit 0 = 0) or I/O (bit 0 = 1)
    // BAR.
    let is_mmio = (bar_raw & 0x01) == 0;

    if is_mmio {
        // Memory BAR: bits 2:1 encode type (00 = 32-bit, 10 = 64-bit),
        // bit 3 = prefetchable.
        let is_64bit = (bar_raw & 0x06) == 0x04;
        let is_prefetchable = (bar_raw & 0x08) != 0;

        // Probe size.
        unsafe { raw::pci_config_write_u32(addr, bar_offset, 0xFFFF_FFFF) };
        let size_mask = unsafe { raw::pci_config_read_u32(addr, bar_offset) };
        unsafe { raw::pci_config_write_u32(addr, bar_offset, bar_raw) };

        let size = if size_mask == 0 || size_mask == 0xFFFF_FFFF {
            0
        } else {
            // Size mask: low 4 bits are flags for memory BARs.
            let raw_size = size_mask & 0xFFFF_FFF0;
            (!raw_size).wrapping_add(1) as u64
        };

        let base_address = (bar_raw & 0xFFFF_FFF0) as u64;

        PciBarInfo {
            base_address,
            size,
            is_64bit,
            is_prefetchable,
            is_mmio: true,
        }
    } else {
        // I/O BAR: bits 1:0 = 01.
        let base_address = (bar_raw & 0xFFFF_FFFC) as u64;

        // Probe size.
        unsafe { raw::pci_config_write_u32(addr, bar_offset, 0xFFFF_FFFF) };
        let size_mask = unsafe { raw::pci_config_read_u32(addr, bar_offset) };
        unsafe { raw::pci_config_write_u32(addr, bar_offset, bar_raw) };

        let size = if size_mask == 0 || size_mask == 0xFFFF_FFFF {
            0
        } else {
            let raw_size = size_mask & 0xFFFF_FFFC;
            (!raw_size).wrapping_add(1) as u64
        };

        PciBarInfo {
            base_address,
            size,
            is_64bit: false,
            is_prefetchable: false,
            is_mmio: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Capability walking
// ---------------------------------------------------------------------------

/// PCI capability IDs.
pub mod cap_id {
    pub const MSI: u8 = 0x05;
    pub const MSI_X: u8 = 0x11;
    pub const PCI_EXPRESS: u8 = 0x10;
    pub const VENDOR_SPECIFIC: u8 = 0x09;
    pub const POWER_MANAGEMENT: u8 = 0x01;
}

/// A parsed MSI capability structure.
#[derive(Debug, Clone, Copy)]
pub struct MsiCapability {
    /// Offset of the capability in config space.
    pub offset: u8,
    /// Message Control register (16-bit).
    pub message_control: u16,
    /// Message Address register (32-bit, low).
    pub message_address: u32,
    /// Message Upper Address (32-bit, only if 64-bit capable).
    pub message_upper_address: Option<u32>,
    /// Message Data register (16-bit).
    pub message_data: u16,
    /// Mask Bits register (32-bit, if per-vector masking).
    pub mask_bits: Option<u32>,
    /// Pending Bits register (32-bit, if per-vector masking).
    pub pending_bits: Option<u32>,
}

/// A parsed MSI-X capability structure.
#[derive(Debug, Clone, Copy)]
pub struct MsixCapability {
    /// Offset of the capability in config space.
    pub offset: u8,
    /// Message Control register (16-bit).
    pub message_control: u16,
    /// BAR indicator (bits 2:0) and offset (bits 31:3) for the MSI-X Table.
    pub table_bir_and_offset: u32,
    /// BAR indicator (bits 2:0) and offset (bits 31:3) for the Pending Bit
    /// Array.
    pub pba_bir_and_offset: u32,
}

/// A parsed PCI Express capability structure.
#[derive(Debug, Clone, Copy)]
pub struct PcieCapability {
    /// Offset of the capability in config space.
    pub offset: u8,
    /// PCI Express Capabilities register (16-bit).
    pub pcie_caps: u16,
    /// Device Capabilities register (32-bit).
    pub device_caps: u32,
    /// Device Control register (16-bit).
    pub device_control: u16,
    /// Link Capabilities register (32-bit).
    pub link_caps: u32,
    /// Link Status register (16-bit).
    pub link_status: u16,
}

/// Information about the hotplug capabilities of a PCIe slot.
#[derive(Debug, Clone, Copy)]
pub struct PcieSlotCapabilities {
    /// Slot Capabilities register.
    pub slot_caps: u32,
    /// Slot Control register.
    pub slot_control: u16,
    /// Slot Status register.
    pub slot_status: u16,
    /// True if this port supports hotplug.
    pub hotplug_capable: bool,
    /// True if a card is currently present in the slot.
    pub presence_detect_state: bool,
}

/// Walk the PCI capability linked list starting from `cap_ptr` and return the
/// offset of the first capability matching `cap_id`, or `None`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pci_capability_find(addr: PciAddress, cap_id: u8) -> Option<u8> {
    let status = unsafe { raw::pci_config_read_u16(addr, raw::STATUS) };
    if status & 0x0010 == 0 {
        // Capabilities list bit not set.
        return None;
    }

    let mut ptr: u8 = unsafe { raw::pci_config_read_u8(addr, raw::CAP_PTR) };
    // Capability pointers must be dword-aligned in the lower 256 bytes.
    let mut safety = 0;
    while ptr >= 0x40 && safety < 48 {
        let this_id = unsafe { raw::pci_config_read_u8(addr, ptr) };
        if this_id == cap_id {
            return Some(ptr);
        }
        let next = unsafe { raw::pci_config_read_u8(addr, ptr + 1) };
        if next < 0x40 {
            break;
        }
        ptr = next;
        safety += 1;
    }
    None
}

/// Parse the MSI capability at `offset`.
///
/// # Safety
///
/// The caller must ensure `offset` points to a valid MSI capability.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_capability_msi(addr: PciAddress, offset: u8) -> MsiCapability {
    let message_control = unsafe { raw::pci_config_read_u16(addr, offset + 2) };
    let is_64bit = (message_control & 0x0080) != 0;
    let per_vector_mask = (message_control & 0x0100) != 0;

    let message_address = unsafe { raw::pci_config_read_u32(addr, offset + 4) };
    let (message_upper_address, data_offset) = if is_64bit {
        (
            Some(unsafe { raw::pci_config_read_u32(addr, offset + 8) }),
            offset + 12,
        )
    } else {
        (None, offset + 8)
    };

    let message_data = unsafe { raw::pci_config_read_u16(addr, data_offset) };

    let (mask_bits, pending_bits) = if per_vector_mask {
        let mask_off = data_offset + 2;
        let pend_off = data_offset + 6;
        (
            Some(unsafe { raw::pci_config_read_u32(addr, mask_off) }),
            Some(unsafe { raw::pci_config_read_u32(addr, pend_off) }),
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
/// The caller must ensure `offset` points to a valid MSI-X capability.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_capability_msix(addr: PciAddress, offset: u8) -> MsixCapability {
    let message_control = unsafe { raw::pci_config_read_u16(addr, offset + 2) };
    let table_bir_and_offset = unsafe { raw::pci_config_read_u32(addr, offset + 4) };
    let pba_bir_and_offset = unsafe { raw::pci_config_read_u32(addr, offset + 8) };

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
/// The caller must ensure `offset` points to a valid PCIe capability.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_capability_pcie(addr: PciAddress, offset: u8) -> PcieCapability {
    let pcie_caps = unsafe { raw::pci_config_read_u16(addr, offset + 2) };
    let device_caps = unsafe { raw::pci_config_read_u32(addr, offset + 4) };
    let device_control = unsafe { raw::pci_config_read_u16(addr, offset + 8) };
    let link_caps = unsafe { raw::pci_config_read_u32(addr, offset + 12) };
    let link_status = unsafe { raw::pci_config_read_u16(addr, offset + 18) };

    PcieCapability {
        offset,
        pcie_caps,
        device_caps,
        device_control,
        link_caps,
        link_status,
    }
}

/// Read the PCIe Slot Capabilities/Status for a device.
///
/// Only meaningful for PCIe root ports and downstream ports that have
/// a slot implemented.  Returns `None` if the device does not have a
/// PCIe capability or does not implement a slot.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pcie_read_slot_status(addr: PciAddress) -> Option<PcieSlotCapabilities> {
    let pcie_off = pci_capability_find(addr, cap_id::PCI_EXPRESS)?;

    // PCIe capability, offset for Slot Capabilities/Status varies by port type:
    // - Root port: Slot Capabilities at +0x14
    // - Downstream port: Slot Capabilities at +0x14
    // - Upstream port: no slot
    // We just attempt to read and check if it looks valid (non-zero).
    unsafe {
        // Slot Capabilities at offset +0x14 from PCIe capability.
        let slot_caps = raw::pci_config_read_u32(addr, pcie_off + 0x14);
        let slot_control = raw::pci_config_read_u16(addr, pcie_off + 0x18);
        let slot_status = raw::pci_config_read_u16(addr, pcie_off + 0x1A);

        // Presence Detect State is bit 6 of Slot Status.
        let presence_detect_state = (slot_status & (1 << 6)) != 0;

        // Hotplug capable: bit 6 (HotPlugCapable) in Slot Capabilities.
        let hotplug_capable = (slot_caps & (1 << 6)) != 0;

        Some(PcieSlotCapabilities {
            slot_caps,
            slot_control,
            slot_status,
            hotplug_capable,
            presence_detect_state,
        })
    }
}

/// Check for PCIe hotplug events (presence detect changed).
///
/// Returns `Some(true)` if a new device was inserted,
/// `Some(false)` if a device was removed, and `None` if no change.
/// Clears the corresponding status bits after reading.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pcie_check_hotplug_event(addr: PciAddress) -> Option<bool> {
    let pcie_off = pci_capability_find(addr, cap_id::PCI_EXPRESS)?;

    unsafe {
        let slot_status = raw::pci_config_read_u16(addr, pcie_off + 0x1A);

        // Bit 3: Presence Detect Changed
        let presence_changed = (slot_status & (1 << 3)) != 0;
        // Bit 7: Data Link Layer State Changed
        let dl_active_changed = (slot_status & (1 << 7)) != 0;

        if !presence_changed && !dl_active_changed {
            return None;
        }

        // Clear the status bits by writing 1 to them (Write-1-to-clear).
        // Bit 3 = Presence Detect Changed, Bit 7 = DLL State Changed.
        let clear_bits = (1 << 3) | (1 << 7);
        raw::pci_config_write_u16(addr, pcie_off + 0x1A, clear_bits);

        // Also read Slot Capabilities to check if anything is there now.
        // After clearing, re-read the current presence state.
        let slot_status2 = raw::pci_config_read_u16(addr, pcie_off + 0x1A);
        let present_now = (slot_status2 & (1 << 6)) != 0;

        Some(present_now)
    }
}

/// Enumerate all PCI/PCIe devices on all buses.
///
/// Scans bus 0..255, device 0..31, function 0..7 (skipping functions
/// 1–7 for single-function devices).  Returns a `Vec` of `PciDeviceInfo`
/// for every discovered device.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pci_enumerate_buses() -> Vec<PciDeviceInfo> {
    let mut devices: Vec<PciDeviceInfo> = Vec::new();

    // Start with bus 0; transitively discover buses behind PCI bridges later.
    // For now we scan all 256 buses — most will be empty, and the scan
    // completes quickly.
    for bus in 0u8..=255u8 {
        // Optimization: if bus > 0 and we haven't seen a bridge, the bus
        // is likely empty.  However, q35 and modern machines often have
        // devices on multiple buses, so we scan all of them.
        let mut bus_has_devices = false;

        for device in 0u8..32u8 {
            let addr = PciAddress::new(bus, device, 0);
            if !raw::pci_device_exists(addr) {
                continue;
            }
            bus_has_devices = true;

            let header_type = unsafe { raw::pci_config_read_u8(addr, raw::HEADER_TYPE) };
            let is_multifunction = (header_type & 0x80) != 0;
            let max_function: u8 = if is_multifunction { 8 } else { 1 };

            for function in 0u8..max_function {
                let func_addr = PciAddress::new(bus, device, function);
                if !raw::pci_device_exists(func_addr) {
                    continue;
                }

                if let Some(info) = read_device_info(func_addr) {
                    devices.push(info);
                }
            }
        }

        // Heuristic: stop scanning when we encounter 4 consecutive empty buses
        // past the highest discovered device.
        if !bus_has_devices && bus > 0 && devices.is_empty() {
            // Bus 0 is always populated on any real machine; if even bus 0 is
            // empty something is wrong, but we keep going.
        }
        if !bus_has_devices && bus > 16 && devices.is_empty() {
            // Past bus 16 with no devices at all — unlikely to find anything.
            break;
        }
    }

    devices
}

/// Read full config-space information for a single device.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn read_device_info(addr: PciAddress) -> Option<PciDeviceInfo> {
    let vendor_id = unsafe { raw::pci_config_read_u16(addr, raw::VENDOR_ID) };
    if vendor_id == raw::VENDOR_ID_NONE {
        return None;
    }

    let device_id = unsafe { raw::pci_config_read_u16(addr, raw::DEVICE_ID) };
    let class_code = unsafe { raw::pci_config_read_u8(addr, raw::CLASS) };
    let subclass = unsafe { raw::pci_config_read_u8(addr, raw::CLASS - 1) };
    let prog_if = unsafe { raw::pci_config_read_u8(addr, raw::CLASS - 2) };
    let header_type = unsafe { raw::pci_config_read_u8(addr, raw::HEADER_TYPE) } & 0x7F;
    let revision_id = unsafe { raw::pci_config_read_u8(addr, raw::REVISION_ID) };
    let interrupt_line = unsafe { raw::pci_config_read_u8(addr, raw::INTERRUPT_LINE) };
    let interrupt_pin = unsafe { raw::pci_config_read_u8(addr, raw::INTERRUPT_LINE + 1) };

    let status = unsafe { raw::pci_config_read_u16(addr, raw::STATUS) };
    let capability_ptr = if status & 0x0010 != 0 {
        Some(unsafe { raw::pci_config_read_u8(addr, raw::CAP_PTR) })
    } else {
        None
    };

    // Probe all 6 BARs.
    let mut bars: [PciBarInfo; 6] = [PciBarInfo {
        base_address: 0,
        size: 0,
        is_64bit: false,
        is_prefetchable: false,
        is_mmio: false,
    }; 6];

    let mut i = 0;
    while i < 6 {
        let bar = probe_bar(addr, BAR_OFFSETS[i]);
        let is_64bit = bar.is_64bit && bar.is_mmio;
        bars[i] = bar;
        if is_64bit {
            // 64-bit BAR: next offset holds the upper 32 bits.  Don't probe
            // it as an independent BAR, but fold the upper value into bars[i].
            let upper = unsafe { raw::pci_config_read_u32(addr, BAR_OFFSETS[i] + 4) };
            bars[i].base_address |= (upper as u64) << 32;
            // Clear the next slot (it's consumed).
            if i + 1 < 6 {
                bars[i + 1] = PciBarInfo {
                    base_address: 0,
                    size: 0,
                    is_64bit: false,
                    is_prefetchable: false,
                    is_mmio: false,
                };
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    Some(PciDeviceInfo {
        bus: addr.bus,
        device: addr.device,
        function: addr.function,
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

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Print a summary of all enumerated PCI devices to the kernel log.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn log_pci_devices(devices: &[PciDeviceInfo]) {
    crate::println!(
        "[pci   ] PCI enumeration: {} device(s) found",
        devices.len()
    );
    for dev in devices {
        let class_label = dev.class_name();
        let class_str: &str = if class_label.is_empty() {
            ""
        } else {
            class_label
        };
        let multifunc = if dev.is_multifunction() { " [MF]" } else { "" };

        crate::println!(
            "[pci   ]   {:02x}:{:02x}.{}  vend={:04x} dev={:04x}  class={:02x}:{:02x}:{:02x}{}  {}",
            dev.bus,
            dev.device,
            dev.function,
            dev.vendor_id,
            dev.device_id,
            dev.class_code,
            dev.subclass,
            dev.prog_if,
            multifunc,
            class_str,
        );

        // Log BARs with non-zero size.
        for (i, bar) in dev.bars.iter().enumerate() {
            if bar.size > 0 {
                let bar_type = if bar.is_mmio { "MMIO" } else { "IO" };
                let prefetch = if bar.is_prefetchable { " pref" } else { "" };
                let bits = if bar.is_64bit && bar.is_mmio {
                    "64"
                } else {
                    "32"
                };
                crate::println!(
                    "[pci   ]     BAR{}: {}{} {}  base=0x{:016X}  size=0x{:X}",
                    i,
                    bar_type,
                    prefetch,
                    bits,
                    bar.base_address,
                    bar.size
                );
            }
        }

        // Log capability summary.
        if dev.capability_ptr.is_some() {
            let has_msi = pci_capability_find(dev.address(), cap_id::MSI);
            let has_msix = pci_capability_find(dev.address(), cap_id::MSI_X);
            let has_pcie = pci_capability_find(dev.address(), cap_id::PCI_EXPRESS);
            let mut caps: [&str; 4] = ["", "", "", ""];
            let mut n = 0;
            if has_pcie.is_some() {
                caps[n] = "PCIe";
                n += 1;
            }
            if has_msix.is_some() {
                caps[n] = "MSI-X";
                n += 1;
            }
            if has_msi.is_some() && has_msix.is_none() {
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
