//! src/arch/riscv64/pci.rs
//!
//! RISC-V 64 PCIe ECAM (Enhanced Configuration Access Mechanism) enumeration.
//!
//! On RISC-V platforms (including QEMU `virt` with `-device pcie-ecam`),
//! PCIe configuration space is memory-mapped via ECAM rather than accessed
//! through x86-style IO ports.  This module discovers the ECAM region from
//! the FDT, then enumerates PCIe buses to find attached devices.
//!
//! ## ECAM address layout
//!
//! Each PCIe function's 4 KiB configuration space is mapped at:
//!   `ecam_base + (bus << 20) + (device << 15) + (function << 12) + offset`
//!
//! ## RISC-V QEMU virt layout
//!
//! ECAM is typically placed at `0x3000_0000` (physical), which falls within
//! the Sv39 identity-mapped device MMIO window (0x0000_0000..0x4000_0000).
//!
//! ## References
//!
//! - PCI Firmware Specification, Revision 3.0, §4.1 (ECAM)
//! - `linux/Documentation/devicetree/bindings/pci/host-generic-pci.txt`

use alloc::vec::Vec;
use core::ptr;

use crate::arch::fdt;

// ---------------------------------------------------------------------------
// PCI configuration space register offsets (same as x86_64 / aarch64)
// ---------------------------------------------------------------------------

const VENDOR_ID: u16 = 0x00;
const DEVICE_ID: u16 = 0x02;
#[allow(dead_code)]
const COMMAND: u16 = 0x04;
#[allow(dead_code)]
const STATUS: u16 = 0x06;
const REVISION_ID: u16 = 0x08;
const CLASS: u16 = 0x0B;
const HEADER_TYPE: u16 = 0x0E;
const BAR0: u16 = 0x10;
const BAR1: u16 = 0x14;
const BAR2: u16 = 0x18;
const BAR3: u16 = 0x1C;
const BAR4: u16 = 0x20;
const BAR5: u16 = 0x24;
const CAP_PTR: u16 = 0x34;
const INTERRUPT_LINE: u16 = 0x3C;

const VENDOR_ID_NONE: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// ECAM region
// ---------------------------------------------------------------------------

/// Describes a single ECAM (MMCONFIG) region discovered from FDT.
#[derive(Debug, Clone, Copy)]
pub struct EcamRegion {
    pub base_address: usize,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl EcamRegion {
    pub const fn new(base_address: usize, start_bus: u8, end_bus: u8) -> Self {
        Self {
            base_address,
            start_bus,
            end_bus,
        }
    }

    fn address(&self, bus: u8, device: u8, function: u8, offset: u16) -> usize {
        self.base_address
            + ((bus as usize) << 20)
            + ((device as usize) << 15)
            + ((function as usize) << 12)
            + (offset as usize)
    }
}

// ---------------------------------------------------------------------------
// ECAM config-space access
// ---------------------------------------------------------------------------

/// # Safety
///
/// The caller must ensure `region` points to a valid ECAM region and that
/// `(bus, device, function, offset)` identify a valid PCIe function.
unsafe fn ecam_read_u32(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> u32 {
    let addr = region.address(bus, device, function, offset);
    // SAFETY: addr is within the ECAM MMIO window which is identity-mapped
    // on RISC-V QEMU virt (device MMIO window at 0x0000_0000..0x4000_0000).
    unsafe { ptr::read_volatile(addr as *const u32) }
}

/// # Safety
///
/// See [`ecam_read_u32`].
unsafe fn ecam_read_u16(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> u16 {
    let dword_aligned = offset & 0xFFFC;
    let dword = unsafe { ecam_read_u32(region, bus, device, function, dword_aligned) };
    let shift = (offset & 0x02) * 8;
    ((dword >> shift) & 0xFFFF) as u16
}

/// # Safety
///
/// See [`ecam_read_u32`].
unsafe fn ecam_read_u8(region: &EcamRegion, bus: u8, device: u8, function: u8, offset: u16) -> u8 {
    let dword_aligned = offset & 0xFFFC;
    let dword = unsafe { ecam_read_u32(region, bus, device, function, dword_aligned) };
    let shift = (offset & 0x03) * 8;
    ((dword >> shift) & 0xFF) as u8
}

/// # Safety
///
/// The caller must ensure `region` points to a valid ECAM region and that
/// `(bus, device, function, offset)` identify a valid PCIe function.
unsafe fn ecam_write_u32(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    value: u32,
) {
    let addr = region.address(bus, device, function, offset);
    // SAFETY: addr is within the ECAM MMIO window, identity-mapped on
    // RISC-V QEMU virt.
    unsafe { ptr::write_volatile(addr as *mut u32, value) };
}

/// # Safety
///
/// See [`ecam_write_u32`].
unsafe fn ecam_write_u16(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    value: u16,
) {
    let dword_aligned = offset & 0xFFFC;
    let mut dword = unsafe { ecam_read_u32(region, bus, device, function, dword_aligned) };
    let shift = (offset & 0x02) * 8;
    dword &= !(0xFFFF << shift);
    dword |= (value as u32) << shift;
    unsafe { ecam_write_u32(region, bus, device, function, dword_aligned, dword) };
}

/// Write a single byte to ECAM config space (read-modify-write on the
/// containing dword).
///
/// # Safety
///
/// See [`ecam_write_u32`].
#[allow(dead_code)]
unsafe fn ecam_write_u8(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    value: u8,
) {
    let dword_aligned = offset & 0xFFFC;
    let mut dword = unsafe { ecam_read_u32(region, bus, device, function, dword_aligned) };
    let shift = (offset & 0x03) * 8;
    dword &= !(0xFF << shift);
    dword |= (value as u32) << shift;
    unsafe { ecam_write_u32(region, bus, device, function, dword_aligned, dword) };
}

fn pci_device_exists(region: &EcamRegion, bus: u8, device: u8, function: u8) -> bool {
    // SAFETY: ECAM access to a potentially absent device; reads 0xFFFF on
    // missing devices, which is safe on all platforms.
    let vendor = unsafe { ecam_read_u16(region, bus, device, function, VENDOR_ID) };
    vendor != VENDOR_ID_NONE
}

// ─── PCI configuration space manipulation ───

/// Bit 1 in the COMMAND register: enable memory space access.
const PCI_COMMAND_MEMORY: u16 = 1 << 1;
/// Bit 2 in the COMMAND register: enable bus mastering.
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Enable memory-space and bus-master access for a PCIe device.
///
/// Without this, the device's MMIO BARs are inaccessible and DMA is
/// suppressed.  This is required before reading VirtIO registers through
/// a memory BAR on the legacy transitional interface.
pub fn pci_enable_memory_and_bus_master(region: &EcamRegion, bus: u8, device: u8, function: u8) {
    // SAFETY: ECAM access to a validated existing device.
    let command = unsafe { ecam_read_u16(region, bus, device, function, COMMAND) };
    let new_command = command | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER;
    if new_command != command {
        // SAFETY: Writing back to the same register of a validated device.
        unsafe {
            ecam_write_u16(region, bus, device, function, COMMAND, new_command);
        }
    }
}

/// Program a 64-bit memory BAR with a physical address.
///
/// Writes the lower 32 bits to `bar_offset` and the upper 32 bits to
/// `bar_offset + 4`.
pub fn pci_program_bar_64(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    bar_offset: u16,
    phys_addr: u64,
) {
    let lo = (phys_addr & 0xFFFF_FFF0) as u32;
    let hi = ((phys_addr >> 32) & 0xFFFF_FFFF) as u32;
    // SAFETY: ECAM writes to a validated device's BAR registers.
    unsafe {
        ecam_write_u32(region, bus, device, function, bar_offset, lo);
        ecam_write_u32(region, bus, device, function, bar_offset + 4, hi);
    }
}

/// Read the current BAR value as a u64 (lower 32 bits at `bar_offset`; the
/// upper 32 bits at `bar_offset + 4` are read only when the BAR is 64-bit).
///
/// For a 32-bit memory BAR the register at `bar_offset + 4` is a different
/// BAR (or reserved space), so reading it as the "upper dword" would corrupt
/// the address; a 64-bit BAR is flagged by the type field (bits 2:1 == 0b10)
/// in the low dword.
pub fn pci_read_bar_64(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    bar_offset: u16,
) -> u64 {
    // SAFETY: ECAM reads from a validated device's BAR registers.
    let lo = unsafe { ecam_read_u32(region, bus, device, function, bar_offset) };
    let is_64bit = (lo & 0x0000_0006) == 0x0000_0004;
    let hi = if is_64bit {
        unsafe { ecam_read_u32(region, bus, device, function, bar_offset + 4) }
    } else {
        0
    };
    ((hi as u64) << 32) | (lo as u64 & 0xFFFF_FFF0)
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

/// Walk the PCI capability linked list starting from the capabilities-pointer
/// register and return the offset of the first capability matching `cap_id`,
/// or `None`.
pub fn pci_capability_find(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    cap_id: u8,
) -> Option<u8> {
    // SAFETY: ECAM reads on a validated device; the capabilities-list bit is
    // checked first and pointer walk is bounded.
    let status = unsafe { ecam_read_u16(region, bus, device, function, STATUS) };
    if status & 0x0010 == 0 {
        // Capabilities list bit not set.
        return None;
    }

    let mut ptr: u8 = unsafe { ecam_read_u8(region, bus, device, function, CAP_PTR) };
    // Capability pointers must be dword-aligned in the lower 256 bytes.
    let mut safety = 0;
    while ptr >= 0x40 && safety < 48 {
        let this_id = unsafe { ecam_read_u8(region, bus, device, function, ptr as u16) };
        if this_id == cap_id {
            return Some(ptr);
        }
        let next = unsafe { ecam_read_u8(region, bus, device, function, ptr as u16 + 1) };
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
pub unsafe fn pci_capability_msi(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
) -> MsiCapability {
    let off = offset as u16;
    let message_control = unsafe { ecam_read_u16(region, bus, device, function, off + 2) };
    let is_64bit = (message_control & 0x0080) != 0;
    let per_vector_mask = (message_control & 0x0100) != 0;

    let message_address = unsafe { ecam_read_u32(region, bus, device, function, off + 4) };
    let (message_upper_address, data_offset) = if is_64bit {
        (
            Some(unsafe { ecam_read_u32(region, bus, device, function, off + 8) }),
            off + 12,
        )
    } else {
        (None, off + 8)
    };

    let message_data = unsafe { ecam_read_u16(region, bus, device, function, data_offset) };

    let (mask_bits, pending_bits) = if per_vector_mask {
        let mask_off = data_offset + 2;
        let pend_off = data_offset + 6;
        (
            Some(unsafe { ecam_read_u32(region, bus, device, function, mask_off) }),
            Some(unsafe { ecam_read_u32(region, bus, device, function, pend_off) }),
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
pub unsafe fn pci_capability_msix(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
) -> MsixCapability {
    let off = offset as u16;
    let message_control = unsafe { ecam_read_u16(region, bus, device, function, off + 2) };
    let table_bir_and_offset = unsafe { ecam_read_u32(region, bus, device, function, off + 4) };
    let pba_bir_and_offset = unsafe { ecam_read_u32(region, bus, device, function, off + 8) };

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
pub unsafe fn pci_capability_pcie(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
) -> PcieCapability {
    let off = offset as u16;
    let pcie_caps = unsafe { ecam_read_u16(region, bus, device, function, off + 2) };
    let device_caps = unsafe { ecam_read_u32(region, bus, device, function, off + 4) };
    let device_control = unsafe { ecam_read_u16(region, bus, device, function, off + 8) };
    let link_caps = unsafe { ecam_read_u32(region, bus, device, function, off + 12) };
    let link_status = unsafe { ecam_read_u16(region, bus, device, function, off + 18) };

    PcieCapability {
        offset,
        pcie_caps,
        device_caps,
        device_control,
        link_caps,
        link_status,
    }
}

/// Probe the size of a memory or I/O BAR by writing all-ones, reading back the
/// size bits, and restoring the original value.
///
/// Returns the BAR's size in bytes, or 0 if the BAR is unimplemented (all-ones
/// read-back) or reads back zero.
///
/// Note: only the low dword is probed, so a 64-bit BAR larger than 4 GiB is
/// under-reported (same limitation as the x86_64 mirror); not hit on QEMU
/// `virt`, where PCIe BARs sit below 4 GiB.
pub fn probe_bar_size(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    bar_offset: u16,
) -> u64 {
    // SAFETY: ECAM access on a validated device's BAR register.
    let bar_raw = unsafe { ecam_read_u32(region, bus, device, function, bar_offset) };
    let is_mmio = (bar_raw & 0x01) == 0;

    unsafe {
        ecam_write_u32(region, bus, device, function, bar_offset, 0xFFFF_FFFF);
    }
    let size_mask = unsafe { ecam_read_u32(region, bus, device, function, bar_offset) };
    unsafe {
        ecam_write_u32(region, bus, device, function, bar_offset, bar_raw);
    }

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
// FDT discovery
// ---------------------------------------------------------------------------

/// Try to discover an ECAM region from the FDT platform info.
///
/// QEMU `virt` with `-device pcie-ecam` places the ECAM region at a
/// platform-specific address (typically 0x3000_0000 on RISC-V virt
/// when PCIe is enabled).
pub fn discover_ecam() -> Option<EcamRegion> {
    let info = fdt::platform_info();
    info.ecam_base.map(|base| {
        let start_bus = info.ecam_start_bus.unwrap_or(0);
        let end_bus = info.ecam_end_bus.unwrap_or(255);
        EcamRegion::new(base, start_bus, end_bus)
    })
}

/// Hardcoded ECAM fallback for QEMU `virt` machine on RISC-V.
///
/// On QEMU 8.x+ with the `virt` machine and PCIe, the ECAM is placed at
/// `0x3000_0000` (physical), covering 256 buses (256 MiB).  This address
/// is within the identity-mapped device MMIO window so no virtual address
/// transation is needed.
const ECAM_QEMU_VIRT_BASE: usize = 0x3000_0000;
const ECAM_QEMU_VIRT_START_BUS: u8 = 0;
const ECAM_QEMU_VIRT_END_BUS: u8 = 255;

/// Return an ECAM region, using the hardcoded QEMU virt fallback when FDT
/// discovery fails.
pub fn ecam_or_fallback() -> EcamRegion {
    discover_ecam().unwrap_or(EcamRegion::new(
        ECAM_QEMU_VIRT_BASE,
        ECAM_QEMU_VIRT_START_BUS,
        ECAM_QEMU_VIRT_END_BUS,
    ))
}

// ---------------------------------------------------------------------------
// Device info (shared with aarch64 / x86_64 enumeration)
// ---------------------------------------------------------------------------

/// Decoded Base Address Register information.
#[derive(Debug, Clone, Copy)]
pub struct PciBarInfo {
    pub base_address: u64,
    pub size: u64,
    pub is_64bit: bool,
    pub is_prefetchable: bool,
    pub is_mmio: bool,
}

/// Information about a discovered PCIe device.
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
    pub fn class_name(&self) -> &'static str {
        match (self.class_code, self.subclass) {
            (0x00, _) => "Unclassified",
            (0x01, 0x00) => "SCSI",
            (0x01, 0x01) => "IDE",
            (0x01, 0x06) => "SATA",
            (0x01, 0x08) => "NVMe",
            (0x02, 0x00) => "Ethernet",
            (0x03, 0x00) => "VGA",
            (0x06, 0x00) => "Host Bridge",
            (0x06, 0x04) => "PCI-to-PCI Bridge",
            (0x0C, 0x03) => "USB",
            _ => "Other",
        }
    }

    pub fn is_multifunction(&self) -> bool {
        self.header_type & 0x80 != 0
    }
}

// ---------------------------------------------------------------------------
// Bus enumeration
// ---------------------------------------------------------------------------

/// Read config-space info for a single device.
fn read_device_info(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
) -> Option<PciDeviceInfo> {
    // SAFETY: ECAM reads on potentially absent devices; vendor_id check
    // below filters out non-existent functions.
    let vendor_id = unsafe { ecam_read_u16(region, bus, device, function, VENDOR_ID) };
    if vendor_id == VENDOR_ID_NONE {
        return None;
    }

    let device_id = unsafe { ecam_read_u16(region, bus, device, function, DEVICE_ID) };
    let class_hi = unsafe { ecam_read_u8(region, bus, device, function, CLASS) };
    let subclass = unsafe { ecam_read_u8(region, bus, device, function, CLASS - 1) };
    let prog_if = unsafe { ecam_read_u8(region, bus, device, function, CLASS - 2) };
    let header_type = unsafe { ecam_read_u8(region, bus, device, function, HEADER_TYPE) };
    let revision_id = unsafe { ecam_read_u8(region, bus, device, function, REVISION_ID) };
    let interrupt_line = unsafe { ecam_read_u8(region, bus, device, function, INTERRUPT_LINE) };
    let interrupt_pin = unsafe { ecam_read_u8(region, bus, device, function, INTERRUPT_LINE + 1) };

    let cap_ptr_raw = unsafe { ecam_read_u8(region, bus, device, function, CAP_PTR) };
    let capability_ptr = (cap_ptr_raw >= 0x40).then_some(cap_ptr_raw);

    // Probe BARs.
    let mut bars: [PciBarInfo; 6] = [PciBarInfo {
        base_address: 0,
        size: 0,
        is_64bit: false,
        is_prefetchable: false,
        is_mmio: false,
    }; 6];

    let bar_offsets = [BAR0, BAR1, BAR2, BAR3, BAR4, BAR5];
    let mut bar_index = 0;
    while bar_index < 6 {
        let offset = bar_offsets[bar_index];
        // SAFETY: ECAM read on a validated device.
        let bar_lo = unsafe { ecam_read_u32(region, bus, device, function, offset) };
        if bar_lo == 0 {
            bar_index += 1;
            continue;
        }

        let is_mmio = (bar_lo & 0x01) == 0;
        let is_64bit = is_mmio && ((bar_lo >> 1) & 0x03) == 0x02;
        let is_prefetchable = is_mmio && ((bar_lo >> 3) & 0x01) == 1;

        let mut base_address: u64 = if is_mmio {
            (bar_lo & 0xFFFF_FFF0) as u64
        } else {
            (bar_lo & 0xFFFF_FFFC) as u64
        };

        if is_64bit && bar_index + 1 < 6 {
            let bar_hi =
                // SAFETY: ECAM read on a validated device, next BAR register.
                unsafe { ecam_read_u32(region, bus, device, function, bar_offsets[bar_index + 1]) };
            base_address |= (bar_hi as u64) << 32;
        }

        // Probe the BAR size via write-all-ones / read-back / restore.
        let size = probe_bar_size(region, bus, device, function, offset);

        bars[bar_index] = PciBarInfo {
            base_address,
            size,
            is_64bit,
            is_prefetchable,
            is_mmio,
        };

        bar_index += if is_64bit { 2 } else { 1 };
    }

    Some(PciDeviceInfo {
        bus,
        device,
        function,
        vendor_id,
        device_id,
        class_code: class_hi,
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

/// Enumerate all PCIe buses accessible via the given ECAM region.
pub fn pci_enumerate_buses(region: &EcamRegion) -> Vec<PciDeviceInfo> {
    let mut devices: Vec<PciDeviceInfo> = Vec::new();

    for bus in region.start_bus..=region.end_bus {
        let mut bus_has_devices = false;

        for device in 0u8..32u8 {
            if !pci_device_exists(region, bus, device, 0) {
                continue;
            }
            bus_has_devices = true;

            // SAFETY: ECAM read on a device known to exist.
            let header_type = unsafe { ecam_read_u8(region, bus, device, 0, HEADER_TYPE) };
            let is_multifunction = (header_type & 0x80) != 0;
            let max_function: u8 = if is_multifunction { 8 } else { 1 };

            for function in 0u8..max_function {
                if !pci_device_exists(region, bus, device, function) {
                    continue;
                }

                if let Some(info) = read_device_info(region, bus, device, function) {
                    devices.push(info);
                }
            }
        }

        // Stop scanning past bus 16 if no devices found.
        if !bus_has_devices && bus > 16 && devices.is_empty() {
            break;
        }
    }

    devices
}

/// Log discovered PCIe devices to the serial console.
pub fn log_pci_devices(devices: &[PciDeviceInfo]) {
    crate::println!("[pci   ] RISC-V PCIe: {} device(s) found", devices.len());
    for dev in devices {
        crate::println!(
            "[pci   ] {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:02x}.{:02x} ({})",
            dev.bus,
            dev.device,
            dev.function,
            dev.vendor_id,
            dev.device_id,
            dev.class_code,
            dev.subclass,
            dev.class_name(),
        );
        for (i, bar) in dev.bars.iter().enumerate() {
            if bar.base_address != 0 {
                crate::println!(
                    "[pci   ]   BAR{}: base={:#018x} size={:#x} mmio={} 64bit={} prefetch={}",
                    i,
                    bar.base_address,
                    bar.size,
                    bar.is_mmio,
                    bar.is_64bit,
                    bar.is_prefetchable,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MSI-X wiring (RISC-V AIA)
// ---------------------------------------------------------------------------

/// Program MSI-X for a PCIe device, wiring it to the RISC-V AIA IMSIC.
///
/// Locates the device's MSI-X capability, derives the MSI-X table address
/// from the capability's BAR indicator and offset, programmes `count` entries
/// via [`crate::arch::riscv64::aia_imsic::configure_msix`] so they deliver
/// `base_irq..base_irq + count` to `target_cpu`'s IMSIC file, then enables
/// MSI-X in the capability's Message Control register.
///
/// Returns the first interrupt identity on success.  The caller is
/// responsible for registering a handler with
/// [`crate::arch::riscv64::aia_imsic::register_irq_handler`] before the
/// device raises interrupts.
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

    // Walk the capability list to find the MSI-X capability.
    let cap_off = pci_capability_find(region, bus, device, function, cap_id::MSI_X)
        .ok_or(crate::Error::NotImplemented)?;

    // SAFETY: `cap_off` points to a validated MSI-X capability.
    let msix = unsafe { pci_capability_msix(region, bus, device, function, cap_off) };

    // Table BIR is bits 2:0 of the Table register; the offset is bits 31:3.
    let table_bir = (msix.table_bir_and_offset & 0x07) as u16;
    if table_bir >= 6 {
        return Err(crate::Error::InvalidArgument);
    }
    let table_offset = (msix.table_bir_and_offset & 0xFFFF_FFF8) as u64;

    // The device must decode MMIO and be a bus master before the MSI-X table
    // writes (and later message delivery) can go anywhere.
    pci_enable_memory_and_bus_master(region, bus, device, function);

    // The table lives in the BAR indicated by `table_bir`.  A reset BAR (0)
    // means no address has been assigned yet — programming entries through it
    // would scribble over low physical memory, so refuse.
    let bar_base = pci_read_bar_64(region, bus, device, function, BAR0 + table_bir * 4);
    if bar_base == 0 {
        return Err(crate::Error::InvalidArgument);
    }
    let table_phys = bar_base
        .checked_add(table_offset)
        .ok_or(crate::Error::InvalidArgument)?;

    // Table size is (Message Control bits 10:0) + 1 entries.
    let table_size = ((msix.message_control & 0x07FF) as u32) + 1;

    let first_irq = aia_imsic::configure_msix(table_phys, table_size, target_cpu, base_irq)?;

    // Enable MSI-X (bit 15) and clear the function mask (bit 14) so the
    // device may raise interrupts.
    let new_control = (msix.message_control | (1u16 << 15)) & !(1u16 << 14);
    // SAFETY: writing to the validated capability's Message Control register.
    unsafe {
        ecam_write_u16(
            region,
            bus,
            device,
            function,
            cap_off as u16 + 2,
            new_control,
        );
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
