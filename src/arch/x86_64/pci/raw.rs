//! src/arch/x86_64/pci/raw.rs
//!
//! PCI configuration space access primitives (legacy IO-port mechanism).
//!
//! Provides low-level read/write helpers for the PCI configuration space via
//! the CONFIG_ADDRESS / CONFIG_DATA ports at 0xCF8/0xCFC.
//!
//! All functions are gated behind `x86_64` + `target_os = "none"` so they
//! are only compiled for bare-metal x86_64 targets.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::super::port::Port;

// ---------------------------------------------------------------------------
// PCI configuration-space I/O ports (legacy access mechanism)
// ---------------------------------------------------------------------------

/// PCI Configuration Address port (32-bit).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CONFIG_ADDRESS: u16 = 0x0CF8;
/// PCI Configuration Data port (8/16/32-bit).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CONFIG_DATA: u16 = 0x0CFC;

// ---------------------------------------------------------------------------
// PCI configuration space offsets (standardised header, first 64 bytes)
// ---------------------------------------------------------------------------

/// Vendor ID (16-bit, read-only).
pub const VENDOR_ID: u8 = 0x00;
/// Device ID (16-bit, read-only).
pub const DEVICE_ID: u8 = 0x02;
/// Command register (16-bit).
pub const COMMAND: u8 = 0x04;
/// Status register (16-bit, read-only for most bits).
pub const STATUS: u8 = 0x06;
/// Revision ID (8-bit, read-only).
pub const REVISION_ID: u8 = 0x08;
/// Class code / subclass / prog-if (24-bit: 0x0B class, 0x0A subclass, 0x09
/// prog-if).
pub const CLASS: u8 = 0x0B;
/// Header type (8-bit, bit 7 = multi-function).
pub const HEADER_TYPE: u8 = 0x0E;
/// Base Address Register 0–5 (32-bit each, at offsets 0x10–0x27).
pub const BAR0: u8 = 0x10;
pub const BAR1: u8 = 0x14;
pub const BAR2: u8 = 0x18;
pub const BAR3: u8 = 0x1C;
pub const BAR4: u8 = 0x20;
pub const BAR5: u8 = 0x24;
/// Capabilities pointer (8-bit, valid if Status bit 4 is set).
pub const CAP_PTR: u8 = 0x34;
/// Interrupt line (8-bit).
pub const INTERRUPT_LINE: u8 = 0x3C;

/// Vendor ID sentinel: returned for absent devices.
pub const VENDOR_ID_NONE: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Typed PCI address
// ---------------------------------------------------------------------------

/// A fully-qualified PCI device address: bus, device, function.
///
/// - `bus`: 0–255 (up to 256 buses)
/// - `device`: 0–31 (up to 32 devices per bus)
/// - `function`: 0–7 (up to 8 functions per device)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    /// Create a new PCI address.
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// Encode the PCI address and register offset into the CONFIG_ADDRESS
    /// format expected by the legacy PCI access mechanism.
    ///
    /// Layout:
    ///   Bit 31    — Enable bit (must be 1)
    ///   Bits 30:24 — Reserved (0)
    ///   Bits 23:16 — Bus number
    ///   Bits 15:11 — Device number
    ///   Bits 10:8  — Function number
    ///   Bits 7:2   — Register offset (dword-aligned)
    ///   Bits 1:0   — 0
    pub fn to_config_address(self, offset: u8) -> u32 {
        let enable = 1u32 << 31;
        let bus = (self.bus as u32 & 0xFF) << 16;
        let device = (self.device as u32 & 0x1F) << 11;
        let function = (self.function as u32 & 0x07) << 8;
        // Offset must be dword-aligned: clear low 2 bits and mask to 6 bits (0–255).
        let reg = (offset as u32 & 0xFC) & 0xFF;
        enable | bus | device | function | reg
    }
}

// ---------------------------------------------------------------------------
// Raw config-space access
// ---------------------------------------------------------------------------

/// Select a PCI configuration register by writing to CONFIG_ADDRESS.
///
/// # Safety
///
/// The caller must ensure that `addr` and `offset` refer to a valid device.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn select_config_address(addr: PciAddress, offset: u8) {
    let config_addr = addr.to_config_address(offset);
    unsafe {
        Port::<u32>::new(CONFIG_ADDRESS).write(config_addr);
    }
}

/// Read a 32-bit value from a PCI configuration space register.
///
/// # Safety
///
/// The caller must ensure that a device exists at `addr` and that `offset`
/// is a valid, dword-aligned offset into the configuration space (0–255,
/// low 2 bits clear).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_config_read_u32(addr: PciAddress, offset: u8) -> u32 {
    unsafe {
        select_config_address(addr, offset);
        Port::<u32>::new(CONFIG_DATA).read()
    }
}

/// Read a 16-bit value from a PCI configuration space register.
///
/// # Safety
///
/// Same preconditions as `pci_config_read_u32`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_config_read_u16(addr: PciAddress, offset: u8) -> u16 {
    let aligned = offset & 0xFC;
    let dword = unsafe { pci_config_read_u32(addr, aligned) };
    let shift = (offset & 0x02) * 8;
    ((dword >> shift) & 0xFFFF) as u16
}

/// Read an 8-bit value from a PCI configuration space register.
///
/// # Safety
///
/// Same preconditions as `pci_config_read_u32`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_config_read_u8(addr: PciAddress, offset: u8) -> u8 {
    let aligned = offset & 0xFC;
    let dword = unsafe { pci_config_read_u32(addr, aligned) };
    let shift = (offset & 0x03) * 8;
    ((dword >> shift) & 0xFF) as u8
}

/// Write a 32-bit value to a PCI configuration space register.
///
/// # Safety
///
/// The caller must ensure that a device exists at `addr`, that `offset` is
/// a valid, dword-aligned offset, and that writing the value does not violate
/// the device's programming model.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_config_write_u32(addr: PciAddress, offset: u8, value: u32) {
    unsafe {
        select_config_address(addr, offset);
        Port::<u32>::new(CONFIG_DATA).write(value);
    }
}

/// Write a 16-bit value to a PCI configuration space register.
///
/// # Safety
///
/// Same preconditions as `pci_config_write_u32`.  This performs a
/// read-modify-write on the enclosing dword.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_config_write_u16(addr: PciAddress, offset: u8, value: u16) {
    let aligned = offset & 0xFC;
    let dword = unsafe { pci_config_read_u32(addr, aligned) };
    let shift = (offset & 0x02) * 8;
    let mask = 0xFFFFu32 << shift;
    let new_dword = (dword & !mask) | ((value as u32) << shift);
    unsafe { pci_config_write_u32(addr, aligned, new_dword) };
}

/// Write an 8-bit value to a PCI configuration space register.
///
/// # Safety
///
/// Same preconditions as `pci_config_write_u32`.  This performs a
/// read-modify-write on the enclosing dword.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_config_write_u8(addr: PciAddress, offset: u8, value: u8) {
    let aligned = offset & 0xFC;
    let dword = unsafe { pci_config_read_u32(addr, aligned) };
    let shift = (offset & 0x03) * 8;
    let mask = 0xFFu32 << shift;
    let new_dword = (dword & !mask) | ((value as u32) << shift);
    unsafe { pci_config_write_u32(addr, aligned, new_dword) };
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Returns `true` if a PCI device exists at `addr`.
///
/// A device is considered present when its Vendor ID is not 0xFFFF.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pci_device_exists(addr: PciAddress) -> bool {
    unsafe { pci_config_read_u16(addr, VENDOR_ID) != VENDOR_ID_NONE }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_address_to_config_address_bus_0_device_0_function_0_offset_0() {
        let addr = PciAddress::new(0, 0, 0);
        assert_eq!(addr.to_config_address(0), 0x8000_0000);
    }

    #[test]
    fn pci_address_to_config_address_bus_1_device_2_function_3_offset_4() {
        let addr = PciAddress::new(1, 2, 3);
        assert_eq!(addr.to_config_address(4), 0x8001_1304);
    }

    #[test]
    fn pci_address_to_config_address_offset_is_dword_aligned() {
        let addr = PciAddress::new(0, 0, 0);
        assert_eq!(addr.to_config_address(0x10), 0x8000_0010);
        assert_eq!(addr.to_config_address(0x0B), 0x8000_0008);
        assert_eq!(addr.to_config_address(0xFF), 0x8000_00FC);
    }

    #[test]
    fn pci_address_to_config_address_max_bus_device_function() {
        let addr = PciAddress::new(255, 31, 7);
        let expected = 0x8000_0000 | ((255u32) << 16) | ((31u32) << 11) | ((7u32) << 8);
        assert_eq!(addr.to_config_address(0), expected);
    }
}
