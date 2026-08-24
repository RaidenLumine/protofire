//! src/arch/x86_64/pci/ecam.rs
//!
//! PCI Express memory-mapped configuration access (ECAM / MMCONFIG).
//!
//! On QEMU's q35 machine the PCIe ECAM region is fixed at
//! [`Q35_MMCONFIG_BASE`] (`0xB000_0000`) and covers bus 0 only by default.
//! Configuration space for a device is addressed as:
//!
//!   `base + (bus << 20) + (device << 15) + (function << 12) + offset`
//!
//! Unlike the legacy IO-port path ([`super::raw`]), ECAM gives 4 KiB of
//! configuration space per device/function, including the extended PCIe
//! capability registers above offset 0xFF.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::ptr;

/// Default Q35 MMCONFIG (ECAM) base physical address.
pub const Q35_MMCONFIG_BASE: usize = 0xB000_0000;

/// Describes a single ECAM (MMCONFIG) region.
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

    /// Compute the config-space address of a device within this region.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn address(&self, bus: u8, device: u8, function: u8, offset: u16) -> usize {
        self.base_address
            + ((bus as usize) << 20)
            + ((device as usize) << 15)
            + ((function as usize) << 12)
            + (offset as usize)
    }
}

/// Return the Q35 ECAM region (bus 0 only, covering the four default slots
/// exposed by q35's root complex).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn ecam_discover() -> EcamRegion {
    EcamRegion::new(Q35_MMCONFIG_BASE, 0, 0)
}

// ---------------------------------------------------------------------------
// ECAM config-space access
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn ecam_read_u32_raw(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> u32 {
    let addr = region.address(bus, device, function, offset);
    unsafe { ptr::read_volatile(addr as *const u32) }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn ecam_read_u32(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> u32 {
    unsafe { ecam_read_u32_raw(region, bus, device, function, offset) }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn ecam_read_u16(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> u16 {
    let dword_aligned = offset & 0xFFFC;
    let dword = unsafe { ecam_read_u32_raw(region, bus, device, function, dword_aligned) };
    let shift = (offset & 0x02) * 8;
    ((dword >> shift) & 0xFFFF) as u16
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn ecam_read_u8(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) -> u8 {
    let dword_aligned = offset & 0xFFFC;
    let dword = unsafe { ecam_read_u32_raw(region, bus, device, function, dword_aligned) };
    let shift = (offset & 0x03) * 8;
    ((dword >> shift) & 0xFF) as u8
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn ecam_write_u32(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    value: u32,
) {
    let addr = region.address(bus, device, function, offset);
    unsafe { ptr::write_volatile(addr as *mut u32, value) };
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn ecam_write_u16(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    value: u16,
) {
    let dword_aligned = offset & 0xFFFC;
    let shift = (offset & 0x02) * 8;
    let mut dword = unsafe { ecam_read_u32_raw(region, bus, device, function, dword_aligned) };
    dword = (dword & !(0xFFFF << shift)) | ((value as u32) << shift);
    unsafe { ecam_write_u32(region, bus, device, function, dword_aligned, dword) };
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn ecam_write_u8(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    value: u8,
) {
    let dword_aligned = offset & 0xFFFC;
    let shift = (offset & 0x03) * 8;
    let mut dword = unsafe { ecam_read_u32_raw(region, bus, device, function, dword_aligned) };
    dword = (dword & !(0xFF << shift)) | ((value as u32) << shift);
    unsafe { ecam_write_u32(region, bus, device, function, dword_aligned, dword) };
}
