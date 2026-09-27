//! src/drivers/framebuffer_protocol.rs
//!
//! The bochs-display's register block, and the display record its consumers
//! share.
//!
//! The `VBE_DISPI_*` indices, the two layouts the device offers (a flat
//! register window or the classic index/data port pair) and `FramebufferInfo` —
//! what a probe hands to the console and to virtio-gpu — are descriptions, not
//! hardware access.  They compile everywhere; the probe that talks to the
//! device is compiled where such a device exists.

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

pub enum VbeLayout {
    Flat,
    IndexData,
}

impl VbeLayout {
    /// 16-bit read of VBE register `index`.
    ///
    /// # Safety
    ///
    /// `base` must be the device's mapped register block, from the probe that
    /// mapped BAR2 — the offsets below are within it.
    pub unsafe fn read_reg(&self, base: usize, index: u16) -> u16 {
        // SAFETY: the caller's contract says `base` is the mapped register
        // block; every offset read here is one the device defines inside it.
        unsafe {
            match self {
                VbeLayout::Flat => core::ptr::read_volatile(
                    (base + VBE_DISPI_FLAT_BASE + (index as usize) * 2) as *const u16,
                ),
                VbeLayout::IndexData => {
                    core::ptr::write_volatile(
                        (base as *mut u16).add(VBE_DISPI_IO_INDEX / 2),
                        index,
                    );
                    core::ptr::read_volatile((base as *const u16).add(VBE_DISPI_IO_DATA / 2))
                }
            }
        }
    }

    /// 16-bit write of VBE register `index`.
    ///
    /// # Safety
    ///
    /// As [`read_reg`](Self::read_reg): `base` must be the device's mapped
    /// register block.
    pub unsafe fn write_reg(&self, base: usize, index: u16, val: u16) {
        // SAFETY: as `read_reg` — the caller's contract covers `base`, and the
        // offsets written are the device's own registers.
        unsafe {
            match self {
                VbeLayout::Flat => core::ptr::write_volatile(
                    (base + VBE_DISPI_FLAT_BASE + (index as usize) * 2) as *mut u16,
                    val,
                ),
                VbeLayout::IndexData => {
                    core::ptr::write_volatile(
                        (base as *mut u16).add(VBE_DISPI_IO_INDEX / 2),
                        index,
                    );
                    core::ptr::write_volatile((base as *mut u16).add(VBE_DISPI_IO_DATA / 2), val);
                }
            }
        }
    }
}
