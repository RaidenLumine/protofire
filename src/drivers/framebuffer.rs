//! src/drivers/framebuffer.rs
//!
//! The bochs-display driver, on the machines that have one.
//!
//! The device is found on PCI (vendor 0x1234, device 0x1111), its linear
//! framebuffer and its VBE register block are mapped, a mode is set, and the
//! framebuffer console is installed.  The register map and the record its
//! consumers share are in [`super::framebuffer_protocol`]; this file is the
//! machine's half, so it is compiled where that device exists, and a machine
//! without one answers under the same module name from `framebuffer_absent.rs`.

use crate::drivers::Driver;
use crate::drivers::DriverCategory;
use crate::kernel::sync::spinlock::SpinLock;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

pub use super::framebuffer_protocol::*;

// ---------------------------------------------------------------------------
// PCI identifiers
// ---------------------------------------------------------------------------

/// Bochs/QEMU VGA vendor ID.

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
fn probe_and_init() -> Option<()> {
    use crate::arch::mmu::map_device_mmio;
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::println;
    use core::ptr;

    // If a console is already active (e.g. from virtio-gpu), skip.
    if crate::drivers::framebuffer_console::console_dimensions().is_some() {
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
        crate::drivers::framebuffer_console::install_console(fb_ptr, fb_info);
    }
    println!(
        "[fb    ] console installed ({}×{} chars)",
        fb_info.width / 8,
        fb_info.height / 16,
    );

    Some(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
