//! src/arch/pci/ecam.rs
//!
//! The ECAM (Enhanced Configuration Access Mechanism) backend.
//!
//! ECAM is a memory window in which each function owns 4 KiB of
//! configuration space, placed at
//!
//!   `base + (bus << 20) + (device << 15) + (function << 12) + offset`
//!
//! Unlike the legacy port pair, it reaches the extended PCIe registers above
//! offset `0xFF`, which is what MSI-X tables live behind.
//!
//! The window belongs to the platform: the device tree names it on aarch64
//! and riscv64, and QEMU's q35 machine fixes it at
//! [`crate::arch::x86_64::pci::Q35_MMCONFIG_BASE`].  Finding it and mapping
//! it is that platform's job; this type is what the walk reads through once
//! that has happened, and it is the same type on every machine that uses the
//! mechanism.

use core::ops::RangeInclusive;
use core::ptr;

use super::ConfigSpace;

/// A function-addressed window of configuration space.
#[derive(Debug, Clone, Copy)]
pub struct EcamRegion {
    base_address: usize,
    start_bus: u8,
    end_bus: u8,
}

impl EcamRegion {
    /// Describe an ECAM window covering `start_bus..=end_bus`.
    ///
    /// Describing one is not the same as reading through it; see the
    /// [`ConfigSpace`] methods' safety sections for the window's obligation.
    pub const fn new(base_address: usize, start_bus: u8, end_bus: u8) -> Self {
        Self {
            base_address,
            start_bus,
            end_bus,
        }
    }

    /// The base address of the window.
    pub const fn base_address(&self) -> usize {
        self.base_address
    }

    /// The buses this window covers.
    pub const fn buses(&self) -> RangeInclusive<u8> {
        self.start_bus..=self.end_bus
    }

    /// The address of a register of one function.
    fn address(&self, bus: u8, device: u8, function: u8, offset: u16) -> usize {
        self.base_address
            + ((bus as usize) << 20)
            + ((device as usize) << 15)
            + ((function as usize) << 12)
            + (offset as usize)
    }
}

impl ConfigSpace for EcamRegion {
    unsafe fn read_u8(&self, bus: u8, device: u8, function: u8, offset: u16) -> u8 {
        let dword_aligned = offset & 0xFFFC;
        // SAFETY: the caller's contract covers the region and the offset;
        // `dword_aligned` is the dword containing `offset`, so it inherits
        // both, and the byte is extracted below.
        let dword = unsafe { self.read_u32(bus, device, function, dword_aligned) };
        let shift = (offset & 0x03) * 8;
        ((dword >> shift) & 0xFF) as u8
    }

    unsafe fn read_u16(&self, bus: u8, device: u8, function: u8, offset: u16) -> u16 {
        let dword_aligned = offset & 0xFFFC;
        // SAFETY: as the byte read above — the dword containing `offset`.
        let dword = unsafe { self.read_u32(bus, device, function, dword_aligned) };
        let shift = (offset & 0x02) * 8;
        ((dword >> shift) & 0xFFFF) as u16
    }

    unsafe fn read_u32(&self, bus: u8, device: u8, function: u8, offset: u16) -> u32 {
        let addr = self.address(bus, device, function, offset);
        // SAFETY: `self` describes an ECAM window and the caller's contract
        // says it is mapped; `addr` composes the bus, device, function and
        // offset into it at the dword alignment the caller passes, so the
        // read stays inside that window.
        unsafe { ptr::read_volatile(addr as *const u32) }
    }

    unsafe fn write_u8(&self, bus: u8, device: u8, function: u8, offset: u16, value: u8) {
        let dword_aligned = offset & 0xFFFC;
        let shift = (offset & 0x03) * 8;
        // SAFETY: the dword containing the byte, which the caller's contract
        // covers, read so its neighbours can be written back untouched.
        let mut dword = unsafe { self.read_u32(bus, device, function, dword_aligned) };
        dword = (dword & !(0xFF << shift)) | ((value as u32) << shift);
        // SAFETY: writing that same dword back, inside the same window.
        unsafe { self.write_u32(bus, device, function, dword_aligned, dword) };
    }

    unsafe fn write_u16(&self, bus: u8, device: u8, function: u8, offset: u16, value: u16) {
        let dword_aligned = offset & 0xFFFC;
        let shift = (offset & 0x02) * 8;
        // SAFETY: as the byte write above — the dword containing the half-word.
        let mut dword = unsafe { self.read_u32(bus, device, function, dword_aligned) };
        dword = (dword & !(0xFFFF << shift)) | ((value as u32) << shift);
        // SAFETY: writing that same dword back, inside the same window.
        unsafe { self.write_u32(bus, device, function, dword_aligned, dword) };
    }

    unsafe fn write_u32(&self, bus: u8, device: u8, function: u8, offset: u16, value: u32) {
        let addr = self.address(bus, device, function, offset);
        // SAFETY: as `read_u32`, on the write side — the address is the same
        // composition into the same window the caller's contract covers.
        unsafe { ptr::write_volatile(addr as *mut u32, value) };
    }
}
