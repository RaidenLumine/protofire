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

// The offsets are the specification's and are listed once, in
// `crate::arch::pci::reg`; these are the same numbers in the byte width this
// port-I/O API addresses with, so a register the specification moves moves in
// one place.

/// Vendor ID (16-bit, read-only).
pub const VENDOR_ID: u8 = crate::arch::pci::reg::VENDOR_ID as u8;
/// Device ID (16-bit, read-only).
pub const DEVICE_ID: u8 = crate::arch::pci::reg::DEVICE_ID as u8;
/// Command register (16-bit).
pub const COMMAND: u8 = crate::arch::pci::reg::COMMAND as u8;
/// Status register (16-bit, read-only for most bits).
pub const STATUS: u8 = crate::arch::pci::reg::STATUS as u8;
/// Revision ID (8-bit, read-only).
pub const REVISION_ID: u8 = crate::arch::pci::reg::REVISION_ID as u8;
/// Class code / subclass / prog-if (24-bit: 0x0B class, 0x0A subclass, 0x09
/// prog-if).
pub const CLASS: u8 = crate::arch::pci::reg::CLASS as u8;
/// Header type (8-bit, bit 7 = multi-function).
pub const HEADER_TYPE: u8 = crate::arch::pci::reg::HEADER_TYPE as u8;
/// Base Address Register 0–5 (32-bit each, at offsets 0x10–0x27).
pub const BAR0: u8 = crate::arch::pci::reg::BAR0 as u8;
pub const BAR1: u8 = crate::arch::pci::reg::BAR1 as u8;
pub const BAR2: u8 = crate::arch::pci::reg::BAR2 as u8;
pub const BAR3: u8 = crate::arch::pci::reg::BAR3 as u8;
pub const BAR4: u8 = crate::arch::pci::reg::BAR4 as u8;
pub const BAR5: u8 = crate::arch::pci::reg::BAR5 as u8;
/// Capabilities pointer (8-bit, valid if Status bit 4 is set).
pub const CAP_PTR: u8 = crate::arch::pci::reg::CAP_PTR as u8;
/// Interrupt line (8-bit).
pub const INTERRUPT_LINE: u8 = crate::arch::pci::reg::INTERRUPT_LINE as u8;

/// Vendor ID sentinel: returned for absent devices.
pub const VENDOR_ID_NONE: u16 = crate::arch::pci::reg::VENDOR_ID_NONE;

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
    // SAFETY: 0xCF8 is the configuration-address port on every PC; the value is
    // the address word the caller's contract describes.
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
    // SAFETY: the caller's contract says the device at `addr` exists and
    // `offset` is a dword-aligned register; the address port is selected first
    // and the data port then reads that register.
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
    // SAFETY: `aligned` is the dword containing `offset`, which the caller's
    // contract covers; the half-word is extracted below.
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
    // SAFETY: as for the 16-bit read — the dword containing `offset`.
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
    // SAFETY: the caller's contract covers the device, the offset and the
    // value's meaning; the two port writes are the legacy mechanism's.
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
    // SAFETY: the read half of the read-modify-write, on the dword the
    // caller's offset lies in.
    let dword = unsafe { pci_config_read_u32(addr, aligned) };
    let shift = (offset & 0x02) * 8;
    let mask = 0xFFFFu32 << shift;
    let new_dword = (dword & !mask) | ((value as u32) << shift);
    // SAFETY: the write half — same dword, with only the caller's 16 bits
    // replaced.
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
    // SAFETY: the read half of the read-modify-write, on the dword the
    // caller's offset lies in.
    let dword = unsafe { pci_config_read_u32(addr, aligned) };
    let shift = (offset & 0x03) * 8;
    let mask = 0xFFu32 << shift;
    let new_dword = (dword & !mask) | ((value as u32) << shift);
    // SAFETY: the write half — same dword, with only the caller's 8 bits
    // replaced.
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
    // SAFETY: the vendor-ID register is defined for every function of every
    // bus/device/function triple, so the read is valid even where no device
    // answers — that is exactly what it detects.
    unsafe { pci_config_read_u16(addr, VENDOR_ID) != VENDOR_ID_NONE }
}

// ---------------------------------------------------------------------------
// The port pair as a configuration space
// ---------------------------------------------------------------------------

/// The legacy port pair, as the walk's [`ConfigSpace`].
///
/// There is nothing to discover and nothing to map on this mechanism: the pair
/// is fixed by the architecture and present on every machine that has it, so
/// the unit value *is* the configuration space.  That is why this backend
/// needs no argument where [`crate::arch::pci::EcamRegion`] carries the address
/// of its window.
///
/// It reaches only the 256-byte head of configuration space, because the
/// address register holds a six-bit dword offset.  An offset past `0xFF` is
/// therefore masked to that head — the mechanism's own limit, stated here —
/// rather than made to address a register it cannot name.  The extended PCIe
/// registers beyond it are reachable only through ECAM.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct LegacyConfig;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl crate::arch::pci::ConfigSpace for LegacyConfig {
    unsafe fn read_u8(&self, bus: u8, device: u8, function: u8, offset: u16) -> u8 {
        let addr = PciAddress::new(bus, device, function);
        // SAFETY: the caller's contract covers the address and the register;
        // the mask below is the mechanism's six-bit dword offset, and the
        // primitive's own contract is the caller's.
        unsafe { pci_config_read_u8(addr, (offset & 0xFF) as u8) }
    }

    unsafe fn read_u16(&self, bus: u8, device: u8, function: u8, offset: u16) -> u16 {
        let addr = PciAddress::new(bus, device, function);
        // SAFETY: as the byte read above, one width up.
        unsafe { pci_config_read_u16(addr, (offset & 0xFF) as u8) }
    }

    unsafe fn read_u32(&self, bus: u8, device: u8, function: u8, offset: u16) -> u32 {
        let addr = PciAddress::new(bus, device, function);
        // SAFETY: as the byte read above, at the dword width the primitive
        // requires.
        unsafe { pci_config_read_u32(addr, (offset & 0xFF) as u8) }
    }

    unsafe fn write_u8(&self, bus: u8, device: u8, function: u8, offset: u16, value: u8) {
        let addr = PciAddress::new(bus, device, function);
        // SAFETY: the caller's contract covers the address, the register and
        // what the register holds — a write is not undone by a read.
        unsafe { pci_config_write_u8(addr, (offset & 0xFF) as u8, value) }
    }

    unsafe fn write_u16(&self, bus: u8, device: u8, function: u8, offset: u16, value: u16) {
        let addr = PciAddress::new(bus, device, function);
        // SAFETY: as the byte write above, one width up.
        unsafe { pci_config_write_u16(addr, (offset & 0xFF) as u8, value) }
    }

    unsafe fn write_u32(&self, bus: u8, device: u8, function: u8, offset: u16, value: u32) {
        let addr = PciAddress::new(bus, device, function);
        // SAFETY: as the byte write above, at the dword width the primitive
        // requires.
        unsafe { pci_config_write_u32(addr, (offset & 0xFF) as u8, value) }
    }
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
