//! src/kernel/drivers/framebuffer.rs
//!
//! Framebuffer management and drawing primitives.
//! Framebuffer driver for QEMU bochs-display (PCI vendor 0x1234, device
//! 0x1111).
//!
//! The device provides:
//! - BAR0: Linear framebuffer (MMIO, default 16 MiB at high address)
//! - BAR2: VBE_DISPI MMIO registers
//!
//! Two register layouts exist in practice (see `VbeLayout`):
//! - QEMU std VGA maps the bochs dispi registers *flat*: 16-bit register `i` at
//!   BAR2 + 0x500 + 2*i, with no index/data handshake.
//! - A discrete bochs-display uses a classic index/data port pair at BAR2 + 0x0
//!   / BAR2 + 0x4.
//!
//! ## Activation
//!
//! Requires the kernel page tables to support high-MMIO addresses (>1 GiB)
//! for BAR0 access.  This module compiles and passes tests; runtime
//! activation is deferred until the paging infrastructure is extended.

// ---------------------------------------------------------------------------
// PCI identifiers
// ---------------------------------------------------------------------------

/// Bochs/QEMU VGA vendor ID.
pub const BOCHS_VENDOR_ID: u16 = 0x1234;
/// Bochs/QEMU display device ID.
pub const BOCHS_DEVICE_ID: u16 = 0x1111;

// ---------------------------------------------------------------------------
// VBE_DISPI register indices (written to VBE_DISPI_INDEX at BAR2+0x500)
// ---------------------------------------------------------------------------

pub const VBE_DISPI_INDEX_ID: u16 = 0;
pub const VBE_DISPI_INDEX_XRES: u16 = 1;
pub const VBE_DISPI_INDEX_YRES: u16 = 2;
pub const VBE_DISPI_INDEX_BPP: u16 = 3;
pub const VBE_DISPI_INDEX_ENABLE: u16 = 4;
pub const VBE_DISPI_INDEX_BANK: u16 = 5;
pub const VBE_DISPI_INDEX_VIRT_WIDTH: u16 = 6;
pub const VBE_DISPI_INDEX_VIRT_HEIGHT: u16 = 7;
pub const VBE_DISPI_INDEX_X_OFFSET: u16 = 8;
pub const VBE_DISPI_INDEX_Y_OFFSET: u16 = 9;

// VBE_DISPI_INDEX_ID response values.
pub const VBE_DISPI_ID0: u16 = 0xB0C0;
pub const VBE_DISPI_ID1: u16 = 0xB0C1;
pub const VBE_DISPI_ID2: u16 = 0xB0C2;
pub const VBE_DISPI_ID3: u16 = 0xB0C3;
pub const VBE_DISPI_ID4: u16 = 0xB0C4;
pub const VBE_DISPI_ID5: u16 = 0xB0C5;

// VBE_DISPI_ENABLE flags.
pub const VBE_DISPI_ENABLED: u16 = 1 << 0;
pub const VBE_DISPI_LFB_ENABLED: u16 = 1 << 6; // Use linear framebuffer
pub const VBE_DISPI_NOCLEARMEM: u16 = 1 << 7; // Don't clear on mode switch

// BAR2 register offsets.
//
// QEMU std VGA exposes the bochs dispi registers *flat* inside the MMIO BAR:
// 16-bit register `i` lives at BAR2 + VBE_DISPI_FLAT_BASE + 2*i, with no
// index/data handshake.  A discrete bochs-display instead provides a classic
// index/data port pair at BAR2 + VBE_DISPI_IO_INDEX / VBE_DISPI_IO_DATA.
pub const VBE_DISPI_FLAT_BASE: usize = 0x500;
pub const VBE_DISPI_IO_INDEX: usize = 0x0;
pub const VBE_DISPI_IO_DATA: usize = 0x4;

// ---------------------------------------------------------------------------
// Framebuffer info
// ---------------------------------------------------------------------------

/// Framebuffer descriptor returned after successful initialization.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical base address of the linear framebuffer (BAR0).
    pub physical_address: usize,
    /// Framebuffer size in bytes.
    pub size: usize,
    /// Horizontal resolution in pixels.
    pub width: u16,
    /// Vertical resolution in pixels.
    pub height: u16,
    /// Bits per pixel.
    pub bpp: u16,
    /// Bytes per scanline (pitch).
    pub pitch: u32,
}

impl FramebufferInfo {
    /// Compute the pixel format from BPP.
    pub fn pixel_bytes(&self) -> usize {
        (self.bpp as usize) / 8
    }

    /// Offset into framebuffer for pixel (x, y).
    pub fn pixel_offset(&self, x: u16, y: u16) -> usize {
        (y as usize) * (self.pitch as usize) + (x as usize) * self.pixel_bytes()
    }
}

// ---------------------------------------------------------------------------
// Driver integration
// ---------------------------------------------------------------------------

use crate::kernel::drivers::Driver;
use crate::kernel::drivers::DriverCategory;
use crate::kernel::sync::spinlock::SpinLock;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

/// How the bochs VBE_DISPI registers are exposed by the device.
///
/// QEMU's std VGA maps them *flat* into the MMIO BAR: 16-bit register `i`
/// lives at `BAR2 + VBE_DISPI_FLAT_BASE + 2*i`, with no index/data
/// handshake.  A discrete bochs-display instead uses the classic index/data
/// port pair (`index` at `BAR2 + 0x0`, `data` at `BAR2 + 0x4`).  Probe both
/// during init, preferring the flat layout.
///
/// Only used by the bare-metal `probe_and_init` path; the host build has no
/// real VBE device to talk to.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
enum VbeLayout {
    Flat,
    IndexData,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl VbeLayout {
    /// 16-bit read of VBE register `index`.
    unsafe fn read_reg(&self, base: usize, index: u16) -> u16 {
        match self {
            VbeLayout::Flat => core::ptr::read_volatile(
                (base + VBE_DISPI_FLAT_BASE + (index as usize) * 2) as *const u16,
            ),
            VbeLayout::IndexData => {
                core::ptr::write_volatile((base as *mut u16).add(VBE_DISPI_IO_INDEX / 2), index);
                core::ptr::read_volatile((base as *const u16).add(VBE_DISPI_IO_DATA / 2))
            }
        }
    }

    /// 16-bit write of VBE register `index`.
    unsafe fn write_reg(&self, base: usize, index: u16, val: u16) {
        match self {
            VbeLayout::Flat => core::ptr::write_volatile(
                (base + VBE_DISPI_FLAT_BASE + (index as usize) * 2) as *mut u16,
                val,
            ),
            VbeLayout::IndexData => {
                core::ptr::write_volatile((base as *mut u16).add(VBE_DISPI_IO_INDEX / 2), index);
                core::ptr::write_volatile((base as *mut u16).add(VBE_DISPI_IO_DATA / 2), val);
            }
        }
    }
}

static FB_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FB_INFO: SpinLock<Option<FramebufferInfo>> = SpinLock::new(None);

/// Global framebuffer info after successful initialization.
pub fn framebuffer_info() -> Option<FramebufferInfo> {
    *FB_INFO.lock()
}

struct FramebufferDriver;

impl Driver for FramebufferDriver {
    fn name(&self) -> &'static str {
        "bochs-fb"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Console
    }

    fn init(&self) -> crate::Result<()> {
        if FB_INITIALIZED.swap(true, Ordering::Acquire) {
            return Ok(());
        }
        probe_and_init().ok_or(crate::Error::DeviceError)
    }
}

/// Public constructor registered in DriverManager.
pub fn driver() -> Arc<dyn Driver> {
    Arc::new(FramebufferDriver)
}

/// Find the bochs-display PCI device, map BARs, and initialize the
/// framebuffer mode.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_and_init() -> Option<()> {
    use crate::arch::mmu::map_device_mmio;
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::println;
    use core::ptr;

    // If a console is already active (e.g. from virtio-gpu), skip.
    if crate::kernel::drivers::framebuffer_console::console_dimensions().is_some() {
        println!("[fb    ] console already installed; skipping bochs-display");
        return None;
    }

    let devices = pci_enumerate_buses();
    let info = devices
        .iter()
        .find(|d| d.vendor_id == BOCHS_VENDOR_ID && d.device_id == BOCHS_DEVICE_ID)?;

    println!(
        "[fb    ] found bochs-display at {:02x}:{:02x}.{:x}",
        info.bus, info.device, info.function
    );

    // Map BAR0 (linear framebuffer).
    let bar0 = &info.bars[0];
    if !bar0.is_mmio || bar0.size == 0 {
        println!("[fb    ] BAR0 is not a valid MMIO region");
        return None;
    }
    let fb_ptr = unsafe { map_device_mmio(bar0.base_address, bar0.size as usize)? };
    println!(
        "[fb    ] BAR0 mapped: phys={:#018x} size={} MiB",
        bar0.base_address,
        bar0.size / (1024 * 1024)
    );

    // Map BAR2 (VBE_DISPI registers).
    let bar2 = &info.bars[2];
    if !bar2.is_mmio || bar2.size == 0 {
        println!("[fb    ] BAR2 is not a valid MMIO region");
        return None;
    }
    let vbe_ptr = unsafe { map_device_mmio(bar2.base_address, bar2.size as usize)? };
    let vbe_base = vbe_ptr as usize;

    unsafe {
        // Probe the VBE_DISPI ID register in both layouts.  QEMU std VGA
        // maps the dispi registers flat at BAR2+0x500 (16-bit register `i`
        // at +0x500 + 2*i); a discrete bochs-display uses an index/data
        // port pair at BAR2+0x0/+0x4.
        let flat_id = ptr::read_volatile((vbe_base + VBE_DISPI_FLAT_BASE) as *const u16);
        let layout = if (VBE_DISPI_ID0..=VBE_DISPI_ID5).contains(&flat_id) {
            VbeLayout::Flat
        } else {
            let io_layout = VbeLayout::IndexData;
            let io_id = io_layout.read_reg(vbe_base, VBE_DISPI_INDEX_ID);
            if (VBE_DISPI_ID0..=VBE_DISPI_ID5).contains(&io_id) {
                VbeLayout::IndexData
            } else {
                println!("[fb    ] unknown VBE_DISPI ID: {:#06x}", flat_id);
                return None;
            }
        };

        let id = layout.read_reg(vbe_base, VBE_DISPI_INDEX_ID);
        println!("[fb    ] VBE_DISPI ID: {:#06x}", id);

        // Set resolution 1024×768×32.
        layout.write_reg(vbe_base, VBE_DISPI_INDEX_XRES, 1024);
        layout.write_reg(vbe_base, VBE_DISPI_INDEX_YRES, 768);
        layout.write_reg(vbe_base, VBE_DISPI_INDEX_BPP, 32);

        // Enable the linear framebuffer.
        layout.write_reg(
            vbe_base,
            VBE_DISPI_INDEX_ENABLE,
            VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM,
        );

        // Now the framebuffer is live. Clear it to dark blue.
        let framebuffer = fb_ptr;
        let framebuffer_u32 = framebuffer as *mut u32;
        let pixel_count = (bar0.size as usize) / 4;
        for i in 0..pixel_count.min(1024 * 768) {
            ptr::write_volatile(framebuffer_u32.add(i), 0x00_000080_u32); // dark blue (BGRx)
        }
    }

    let fb_info = FramebufferInfo {
        physical_address: bar0.base_address as usize,
        size: bar0.size as usize,
        width: 1024,
        height: 768,
        bpp: 32,
        pitch: 1024 * 4,
    };

    println!(
        "[fb    ] initialized {}×{}×{} framebuffer ({} MiB)",
        fb_info.width,
        fb_info.height,
        fb_info.bpp,
        fb_info.size / (1024 * 1024)
    );

    *FB_INFO.lock() = Some(fb_info);

    // Wire the framebuffer console so println!/print! output renders on screen.
    unsafe {
        crate::kernel::drivers::framebuffer_console::install_console(fb_ptr, fb_info);
    }
    println!(
        "[fb    ] console installed ({}×{} chars)",
        fb_info.width / 8,
        fb_info.height / 16,
    );

    Some(())
}

/// Host-side / non-x86_64 stub: framebuffer not available.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn probe_and_init() -> Option<()> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framebuffer_pixel_offset_32bpp() {
        let info = FramebufferInfo {
            physical_address: 0xFD00_0000,
            size: 1024 * 768 * 4,
            width: 1024,
            height: 768,
            bpp: 32,
            pitch: 1024 * 4,
        };
        assert_eq!(info.pixel_bytes(), 4);
        assert_eq!(info.pixel_offset(0, 0), 0);
        assert_eq!(info.pixel_offset(1, 0), 4);
        assert_eq!(info.pixel_offset(0, 1), 4096);
        assert_eq!(info.pixel_offset(512, 384), 384 * 4096 + 512 * 4);
    }

    #[test]
    fn vbe_dispi_constants() {
        assert_eq!(VBE_DISPI_ID0, 0xB0C0);
        assert_ne!(VBE_DISPI_ENABLED, VBE_DISPI_LFB_ENABLED);
    }
}
