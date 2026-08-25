//! src/kernel/drivers/hda.rs
//!
//! High-Definition Audio (HDA) controller driver.
//! Intel High Definition Audio (HDA) controller driver.
//!
//! The HDA controller is discovered via PCI (class 0x04, subclass 0x03).
//! It exposes MMIO registers via BAR0.
//!
//! ## Implementation status
//!
//! - PCI discovery and BAR0 MMIO mapping: done
//! - Controller reset and initialization: done
//! - CORB/RIRB setup and verb delivery: done
//! - Codec enumeration (VENDOR_ID): done
//! - Audio stream data-path: not yet

// ---------------------------------------------------------------------------
// PCI identifiers
// ---------------------------------------------------------------------------

/// HDA class code (Audio device).
pub const HDA_CLASS: u8 = 0x04;
/// HDA subclass (HD Audio Controller).
pub const HDA_SUBCLASS: u8 = 0x03;

// ---------------------------------------------------------------------------
// HDA global registers (offset from BAR0)
// ---------------------------------------------------------------------------

/// Capabilities register (16-bit).
pub const HDA_CAP: usize = 0x00;
/// Version register (16-bit): VMIN [7:0], VMAJ [15:8].
pub const HDA_VERSION: usize = 0x02;
/// Global Control register (32-bit).
pub const HDA_GCTL: usize = 0x08;
/// Wake Enable register (16-bit).
pub const HDA_WAKEEN: usize = 0x0C;
/// State Change Status register (16-bit).
pub const HDA_STATESTS: usize = 0x0E;
/// Global Status register (16-bit).
pub const HDA_GSTS: usize = 0x10;

// GCTL bits.
pub const GCTL_CRST: u32 = 1 << 0; // Controller Reset

// STATESTS bits — bit i signals SDI pin i (codec i).
pub const STATESTS_SDI0: u16 = 1 << 0;

// ---------------------------------------------------------------------------
// CORB registers (BAR0 + 0x40)
// ---------------------------------------------------------------------------

/// CORB Lower Base Address (32-bit).
pub const HDA_CORBLBASE: usize = 0x40;
/// CORB Upper Base Address (32-bit).
pub const HDA_CORBUBASE: usize = 0x44;
/// CORB Write Pointer (16-bit).
pub const HDA_CORBWP: usize = 0x48;
/// CORB Read Pointer (16-bit).
pub const HDA_CORBRP: usize = 0x4A;
/// CORB Control (8-bit).
pub const HDA_CORBCTL: usize = 0x4C;
/// CORB Status (8-bit).
pub const HDA_CORBSTS: usize = 0x4D;
/// CORB Size (8-bit).
pub const HDA_CORBSIZE: usize = 0x4E;

// CORBCTL bits.
pub const CORBCTL_CMEIE: u8 = 1 << 0; // CORB Memory Error Interrupt Enable
pub const CORBCTL_CORBRUN: u8 = 1 << 1; // CORB DMA Engine Run

// CORBSTS bits.
pub const CORBSTS_CMEI: u8 = 1 << 0; // CORB Memory Error Indicator

// CORBSIZE fields.
pub const CORBSIZE_CAP_SHIFT: u8 = 0; // bit 0: size programmable capability
pub const CORBSIZE_SIZE_SHIFT: u8 = 4; // bits 5:4: size mode
pub const CORBSIZE_SIZE_MASK: u8 = 0x30;
pub const CORBSIZE_2: u8 = 0x00;
pub const CORBSIZE_16: u8 = 0x01;
pub const CORBSIZE_256: u8 = 0x02;

// ---------------------------------------------------------------------------
// RIRB registers (BAR0 + 0x50)
// ---------------------------------------------------------------------------

/// RIRB Lower Base Address (32-bit).
pub const HDA_RIRBLBASE: usize = 0x50;
/// RIRB Upper Base Address (32-bit).
pub const HDA_RIRBUBASE: usize = 0x54;
/// RIRB Write Pointer (16-bit).
pub const HDA_RIRBWP: usize = 0x58;
/// Response Interrupt Count (16-bit).
pub const HDA_RINTCNT: usize = 0x5A;
/// RIRB Control (8-bit).
pub const HDA_RIRBCTL: usize = 0x5C;
/// RIRB Status (8-bit).
pub const HDA_RIRBSTS: usize = 0x5D;
/// RIRB Size (8-bit).
pub const HDA_RIRBSIZE: usize = 0x5E;

// RIRBCTL bits.
pub const RIRBCTL_RINTCTL: u8 = 1 << 0; // Response Interrupt Enable
pub const RIRBCTL_DMAEN: u8 = 1 << 1; // RIRB DMA Enable
pub const RIRBCTL_OIC: u8 = 1 << 2; // Overrun Interrupt Control

// RIRBSTS bits.
pub const RIRBSTS_RINTFL: u8 = 1 << 0; // Response Interrupt Flag
pub const RIRBSTS_OIS: u8 = 1 << 2; // Overrun Interrupt Status

// RIRBSIZE fields.
pub const RIRBSIZE_SIZE_SHIFT: u8 = 4; // bits 5:4
pub const RIRBSIZE_SIZE_MASK: u8 = 0x30;
pub const RIRBSIZE_256: u8 = 0x02;

// ---------------------------------------------------------------------------
// DMA Position Buffer (BAR0 + 0x70)
// ---------------------------------------------------------------------------

/// DMA Position Lower Base (32-bit).
pub const HDA_DPLBASE: usize = 0x70;
/// DMA Position Upper Base (32-bit).
pub const HDA_DPUBASE: usize = 0x74;

// ---------------------------------------------------------------------------
// Stream descriptor registers (BAR0 + 0x80, stride 0x20 per stream)
// ---------------------------------------------------------------------------

pub const HDA_SD_BASE: usize = 0x80;
pub const HDA_SD_STRIDE: usize = 0x20;

// Offsets relative to stream base.
pub const HDA_SDCTL: usize = 0x00; // Stream Descriptor Control (32-bit)
pub const HDA_SDSTS: usize = 0x03; // Stream Descriptor Status (8-bit)
pub const HDA_SDLPIB: usize = 0x04; // Link Position in Buffer (32-bit)
pub const HDA_SDCBL: usize = 0x08; // Cyclic Buffer Length (32-bit)
pub const HDA_SDLVI: usize = 0x0C; // Last Valid Index (16-bit)
pub const HDA_SDFIFOD: usize = 0x10; // FIFO Depth (16-bit)
pub const HDA_SDFMT: usize = 0x12; // Format (16-bit)
pub const HDA_SDBDPL: usize = 0x18; // BDL Pointer Low (32-bit)
pub const HDA_SDBDPU: usize = 0x1C; // BDL Pointer High (32-bit)

// ---------------------------------------------------------------------------
// HDA verb definitions
// ---------------------------------------------------------------------------

/// Get Parameter verb (12-bit verb ID).
pub const VERB_GET_PARAMETER: u16 = 0xF00;

/// Parameter IDs for GET_PARAMETER.
pub mod param_id {
    /// Vendor ID (32-bit: vendor in upper 16 bits, device in lower 16 bits).
    pub const VENDOR_ID: u8 = 0x00;
    /// Revision ID.
    pub const REVISION_ID: u8 = 0x02;
    /// Subordinate Node Count.
    pub const SUBORDINATE_NODE_COUNT: u8 = 0x04;
    /// Function Group Type.
    pub const FUNCTION_GROUP_TYPE: u8 = 0x05;
    /// Audio Function Group capabilities.
    pub const AFG_CAPABILITIES: u8 = 0x08;
    /// Audio Widget capabilities.
    pub const AW_CAPABILITIES: u8 = 0x09;
    /// Supported PCM sizes and rates.
    pub const SUPPORTED_PCM: u8 = 0x0A;
    /// Supported audio formats.
    pub const CONFIG_DEFAULT: u8 = 0x1C;
}

/// Build a 32-bit HDA verb value.
///
/// Format per the Intel HDA specification:
///
/// | Bits     | Field           |
/// |----------|-----------------|
/// | 31:28    | Codec Address   |
/// | 27:20    | Node ID         |
/// | 19:8     | Verb ID         |
/// | 7:0      | Payload         |
pub const fn hda_verb(cad: u8, nid: u8, verb_id: u16, payload: u8) -> u32 {
    ((cad as u32) << 28) | ((nid as u32) << 20) | ((verb_id as u32) << 8) | (payload as u32)
}

/// Build a GET_PARAMETER verb.
pub const fn get_param(cad: u8, nid: u8, param: u8) -> u32 {
    hda_verb(cad, nid, VERB_GET_PARAMETER, param)
}

// ---------------------------------------------------------------------------
// CORB / RIRB buffer geometry
// ---------------------------------------------------------------------------

/// Number of CORB entries (256 x 4B = 1024 bytes, fits in one 4 KiB page).
#[allow(dead_code)]
const CORB_ENTRIES: usize = 256;
/// Number of RIRB entries (256 x 8B = 2048 bytes, fits in one 4 KiB page).
#[allow(dead_code)]
const RIRB_ENTRIES: usize = 256;

/// Maximum number of codecs on the HDA link (per the specification).
#[allow(dead_code)]
const MAX_CODECS: usize = 15;

// ---------------------------------------------------------------------------
// Controller state (bare-metal only)
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod controller {
    use super::*;
    use crate::arch::mmu::map_device_mmio;
    use crate::kernel::memory::DmaBuffer;
    use crate::println;
    use crate::Result;
    use core::ptr::read_volatile;
    use core::ptr::write_volatile;

    /// MMIO helpers for 32-bit, 16-bit, and 8-bit register access.
    unsafe fn reg_read32(base: *mut u8, offset: usize) -> u32 {
        read_volatile(base.add(offset) as *const u32)
    }
    unsafe fn reg_write32(base: *mut u8, offset: usize, val: u32) {
        write_volatile(base.add(offset) as *mut u32, val);
    }
    unsafe fn reg_read16(base: *mut u8, offset: usize) -> u16 {
        read_volatile(base.add(offset) as *const u16)
    }
    unsafe fn reg_write16(base: *mut u8, offset: usize, val: u16) {
        write_volatile(base.add(offset) as *mut u16, val);
    }
    unsafe fn reg_read8(base: *mut u8, offset: usize) -> u8 {
        read_volatile(base.add(offset) as *const u8)
    }
    unsafe fn reg_write8(base: *mut u8, offset: usize, val: u8) {
        write_volatile(base.add(offset), val);
    }

    /// The HDA host controller.
    pub struct HdaController {
        /// MMIO base virtual address (BAR0 mapped).
        regs: *mut u8,
        /// Capabilities register value.
        #[allow(dead_code)]
        cap: u16,
        /// Number of input streams (from CAP).
        #[allow(dead_code)]
        num_input_streams: u8,
        /// Number of output streams (from CAP).
        #[allow(dead_code)]
        num_output_streams: u8,
        /// Number of bidirectional streams (from CAP).
        #[allow(dead_code)]
        num_bidir_streams: u8,
        /// CORB DMA buffer (256 entries of 4 bytes each).
        corb_buf: DmaBuffer,
        /// RIRB DMA buffer (256 entries of 8 bytes each).
        rirb_buf: DmaBuffer,
        /// CORB write pointer, cached to minimise MMIO reads.
        corb_wp: u16,
        /// Last RIRB write pointer we consumed.
        rirb_rp: u16,
        /// Vendor/device ID of codec 0 (0 = not probed yet).
        pub codec0_vendor: u32,
    }

    // SAFETY: HdaController owns its MMIO mapping and DMA buffers exclusively.
    unsafe impl Send for HdaController {}

    impl HdaController {
        /// Create and initialise a new HDA controller.
        ///
        /// `bar0_phys` is the physical base address of BAR0, `bar0_size`
        /// the length of the MMIO region.
        pub unsafe fn new(bar0_phys: u64, bar0_size: usize) -> Option<Self> {
            let mmio = map_device_mmio(bar0_phys, bar0_size)?;
            let regs = mmio;

            // Read capabilities.
            let cap = reg_read16(regs, HDA_CAP);
            let iss = ((cap >> 12) & 0x0F) as u8;
            let oss = ((cap >> 8) & 0x0F) as u8;
            let bss = ((cap >> 4) & 0x0F) as u8;
            let _nsdo = (cap & 0x0F) as u8;

            println!(
                "[hda   ] CAP=0x{:04x} ISS={} OSS={} BSS={}",
                cap, iss, oss, bss
            );

            // Allocate DMA buffers.
            let corb_buf = DmaBuffer::allocate(1)?; // 4 KiB
            let rirb_buf = DmaBuffer::allocate(1)?; // 4 KiB

            let mut ctrl = Self {
                regs,
                cap,
                num_input_streams: iss,
                num_output_streams: oss,
                num_bidir_streams: bss,
                corb_buf,
                rirb_buf,
                corb_wp: 0,
                rirb_rp: 0xFFFF,
                codec0_vendor: 0,
            };

            // Reset controller.
            ctrl.reset().ok()?;

            // Initialise CORB.
            ctrl.init_corb().ok()?;

            // Initialise RIRB.
            ctrl.init_rirb().ok()?;

            // Check for codecs on the link.
            if !ctrl.detect_codecs() {
                println!("[hda   ] no codecs detected on the link");
                return Some(ctrl); // Still return the controller for later use.
            }

            // Read VENDOR_ID from codec 0, node 0.
            match ctrl.read_codec_param(0, 0, param_id::VENDOR_ID) {
                Ok(vid) => {
                    let vendor = (vid >> 16) as u16;
                    let device = vid as u16;
                    println!(
                        "[hda   ] codec 0 VENDOR_ID = {:#010x} (vendor={:#06x} device={:#06x})",
                        vid, vendor, device
                    );
                    ctrl.codec0_vendor = vid;
                }
                Err(e) => {
                    println!("[hda   ] codec 0 VENDOR_ID read failed: {}", e.as_str());
                }
            }

            println!("[hda   ] controller initialised");
            Some(ctrl)
        }

        // -------------------------------------------------------------------
        // Reset
        // -------------------------------------------------------------------

        /// Reset the controller (GCTL.CRST toggle).
        unsafe fn reset(&mut self) -> Result<()> {
            // Assert reset (CRST = 0).
            reg_write32(self.regs, HDA_GCTL, 0);
            for _ in 0..100_000 {
                if reg_read32(self.regs, HDA_GCTL) & GCTL_CRST == 0 {
                    break;
                }
            }
            if reg_read32(self.regs, HDA_GCTL) & GCTL_CRST != 0 {
                return Err(crate::Error::TimedOut);
            }

            // De-assert reset (CRST = 1).
            reg_write32(self.regs, HDA_GCTL, GCTL_CRST);
            for _ in 0..100_000 {
                if reg_read32(self.regs, HDA_GCTL) & GCTL_CRST != 0 {
                    break;
                }
            }
            if reg_read32(self.regs, HDA_GCTL) & GCTL_CRST == 0 {
                return Err(crate::Error::TimedOut);
            }

            // Wait 50 us for link to stabilise (simple spin loop).
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }

            // Clear STATESTS by writing back the read value (W1C).
            let statests = reg_read16(self.regs, HDA_STATESTS);
            if statests != 0 {
                reg_write16(self.regs, HDA_STATESTS, statests);
            }

            Ok(())
        }

        // -------------------------------------------------------------------
        // CORB setup
        // -------------------------------------------------------------------

        /// Initialise the CORB engine.
        unsafe fn init_corb(&mut self) -> Result<()> {
            // Reset CORB: set CORBRP = 0 (this triggers a reset).
            reg_write16(self.regs, HDA_CORBRP, 0);
            for _ in 0..100_000 {
                if reg_read16(self.regs, HDA_CORBRP) == 0 {
                    break;
                }
            }
            if reg_read16(self.regs, HDA_CORBRP) != 0 {
                return Err(crate::Error::TimedOut);
            }

            // Set CORB size to 256 entries if programmable.
            let corbsize = reg_read8(self.regs, HDA_CORBSIZE);
            let prog = corbsize & (1 << CORBSIZE_CAP_SHIFT);
            if prog != 0 {
                let size_field = (CORBSIZE_256 << CORBSIZE_SIZE_SHIFT) & CORBSIZE_SIZE_MASK;
                reg_write8(
                    self.regs,
                    HDA_CORBSIZE,
                    (corbsize & !CORBSIZE_SIZE_MASK) | size_field,
                );
            }

            // Set CORB base address.
            let corb_phys = self.corb_buf.phys_addr() as u64;
            reg_write32(self.regs, HDA_CORBLBASE, corb_phys as u32);
            reg_write32(self.regs, HDA_CORBUBASE, (corb_phys >> 32) as u32);

            // Set CORBRP = 0 again after programming base.
            reg_write16(self.regs, HDA_CORBRP, 0);
            for _ in 0..100_000 {
                if reg_read16(self.regs, HDA_CORBRP) == 0 {
                    break;
                }
            }
            if reg_read16(self.regs, HDA_CORBRP) != 0 {
                return Err(crate::Error::TimedOut);
            }

            // Start CORB engine.
            reg_write8(self.regs, HDA_CORBCTL, CORBCTL_CORBRUN);
            for _ in 0..100_000 {
                if reg_read8(self.regs, HDA_CORBCTL) & CORBCTL_CORBRUN != 0 {
                    break;
                }
            }
            if reg_read8(self.regs, HDA_CORBCTL) & CORBCTL_CORBRUN == 0 {
                return Err(crate::Error::TimedOut);
            }

            // Initialise write pointer to 0.
            reg_write16(self.regs, HDA_CORBWP, 0);
            self.corb_wp = 0;

            Ok(())
        }

        // -------------------------------------------------------------------
        // RIRB setup
        // -------------------------------------------------------------------

        /// Initialise the RIRB engine.
        unsafe fn init_rirb(&mut self) -> Result<()> {
            // Set RIRB size to 256 entries if programmable.
            let rirbsize = reg_read8(self.regs, HDA_RIRBSIZE);
            let prog = rirbsize & 1; // bit 0: size programmable
            if prog != 0 {
                let size_field = (RIRBSIZE_256 << RIRBSIZE_SIZE_SHIFT) & RIRBSIZE_SIZE_MASK;
                reg_write8(
                    self.regs,
                    HDA_RIRBSIZE,
                    (rirbsize & !RIRBSIZE_SIZE_MASK) | size_field,
                );
            }

            // Set RIRB base address.
            let rirb_phys = self.rirb_buf.phys_addr() as u64;
            reg_write32(self.regs, HDA_RIRBLBASE, rirb_phys as u32);
            reg_write32(self.regs, HDA_RIRBUBASE, (rirb_phys >> 32) as u32);

            // Set Response Interrupt Count to 1 (interrupt after each response).
            reg_write16(self.regs, HDA_RINTCNT, 1);

            // Enable DMA engine and response interrupt.
            reg_write8(
                self.regs,
                HDA_RIRBCTL,
                RIRBCTL_DMAEN | RIRBCTL_RINTCTL | RIRBCTL_OIC,
            );
            for _ in 0..100_000 {
                if reg_read8(self.regs, HDA_RIRBCTL) & RIRBCTL_DMAEN != 0 {
                    break;
                }
            }
            if reg_read8(self.regs, HDA_RIRBCTL) & RIRBCTL_DMAEN == 0 {
                return Err(crate::Error::TimedOut);
            }

            // Read initial RIRBWP (may be 0xFFFF indicating empty).
            self.rirb_rp = reg_read16(self.regs, HDA_RIRBWP);

            Ok(())
        }

        // -------------------------------------------------------------------
        // Codec detection
        // -------------------------------------------------------------------

        /// Check STATESTS to discover which codecs are present.
        ///
        /// Returns `true` if at least one codec is detected.
        unsafe fn detect_codecs(&mut self) -> bool {
            // After reset the STATESTS bits are set for each present codec.
            let statests = reg_read16(self.regs, HDA_STATESTS);
            let mut present = false;
            for i in 0..MAX_CODECS {
                if statests & (1u16 << i) != 0 {
                    println!("[hda   ] codec {} present", i);
                    present = true;
                }
            }
            present
        }

        // -------------------------------------------------------------------
        // Verb submission
        // -------------------------------------------------------------------

        /// Send a verb to a codec node and read the response.
        ///
        /// The verb is written to the CORB and the CORB write pointer is
        /// advanced.  The function then polls the RIRB write pointer for a
        /// response.
        unsafe fn send_verb(&mut self, verb: u32) -> Result<u32> {
            // Write verb to CORB at the next write-pointer position.
            let corb_idx = self.corb_wp as usize % CORB_ENTRIES;
            let corb_ptr = self.corb_buf.as_ptr() as *mut u32;
            write_volatile(corb_ptr.add(corb_idx), verb);

            // Advance CORBWP.
            let new_wp = ((self.corb_wp as usize + 1) % CORB_ENTRIES) as u16;
            reg_write16(self.regs, HDA_CORBWP, new_wp);
            self.corb_wp = new_wp;

            // Poll for a response in the RIRB.
            let last_rp = self.rirb_rp;
            for _ in 0..500_000 {
                let wp = reg_read16(self.regs, HDA_RIRBWP);

                // RIRBWP of 0xFFFF means the buffer is empty.
                if wp == 0xFFFF || wp == last_rp {
                    core::hint::spin_loop();
                    continue;
                }

                // A new response is available. Read it at the WP position.
                let rirb_idx = wp as usize % RIRB_ENTRIES;
                let rirb_ptr = self.rirb_buf.as_ptr() as *const u32;
                let resp_low = read_volatile(rirb_ptr.add(rirb_idx * 2));
                let resp_high = read_volatile(rirb_ptr.add(rirb_idx * 2 + 1));

                // Check the VALID flag: bit 0 of the upper 32-bit word.
                // Per the HDA spec, bit 32 of the 64-bit entry is VALID.
                if resp_high & 0x01 == 0 {
                    // Response not yet valid — spin a bit.
                    core::hint::spin_loop();
                    continue;
                }

                // Consumed — remember this position.
                self.rirb_rp = wp;

                // Clear RIRBSTS interrupt flags (W1C).
                reg_write8(self.regs, HDA_RIRBSTS, RIRBSTS_RINTFL | RIRBSTS_OIS);

                return Ok(resp_low);
            }

            Err(crate::Error::TimedOut)
        }

        /// Read a codec parameter (e.g. VENDOR_ID) via GET_PARAMETER.
        pub unsafe fn read_codec_param(&mut self, cad: u8, nid: u8, param: u8) -> Result<u32> {
            let verb = get_param(cad, nid, param);
            self.send_verb(verb)
        }
    }
}

// ---------------------------------------------------------------------------
// Driver integration
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::sync::Mutex;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use controller::HdaController;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static HDA_CONTROLLER: Mutex<Option<HdaController>> = Mutex::new(None);

use crate::kernel::drivers::Driver;
use crate::kernel::drivers::DriverCategory;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

static HDA_PROBED: AtomicBool = AtomicBool::new(false);

struct HdaDriver;

impl Driver for HdaDriver {
    fn name(&self) -> &'static str {
        "hda"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Audio
    }

    fn init(&self) -> crate::Result<()> {
        if HDA_PROBED.swap(true, Ordering::Acquire) {
            return Ok(());
        }
        probe_hda_pci()
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(HdaDriver)
}

/// Find the HDA controller on PCI and initialise it.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_hda_pci() -> crate::Result<()> {
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::println;

    let devices = pci_enumerate_buses();
    let mut found = false;

    for info in devices
        .iter()
        .filter(|d| d.class_code == HDA_CLASS && d.subclass == HDA_SUBCLASS)
    {
        found = true;
        println!(
            "[hda   ] found HDA controller at {:02x}:{:02x}.{:x} vendor={:#06x} device={:#06x}",
            info.bus, info.device, info.function, info.vendor_id, info.device_id
        );

        let bar0 = &info.bars[0];
        if !bar0.is_mmio || bar0.size == 0 {
            println!("[hda   ] BAR0 is not MMIO — skipping");
            continue;
        }

        println!(
            "[hda   ] BAR0: phys={:#018x} size={} KiB",
            bar0.base_address,
            bar0.size / 1024
        );

        let ctrl = match unsafe { HdaController::new(bar0.base_address, bar0.size as usize) } {
            Some(c) => c,
            None => {
                println!("[hda   ] controller initialisation failed — skipping");
                continue;
            }
        };

        println!("[hda   ] HDA controller ready");

        // Store the controller.
        *HDA_CONTROLLER.lock() = Some(ctrl);

        // Only initialise the first HDA controller.
        break;
    }

    if !found {
        println!("[hda   ] no HDA controllers found");
    }

    Ok(())
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn probe_hda_pci() -> crate::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hda_verb_build_get_param() {
        // GET_PARAMETER VENDOR_ID for codec 0, node 0.
        let v = hda_verb(0, 0, VERB_GET_PARAMETER, 0x00);
        assert_eq!(v, 0x000F0000, "GET_PARAMETER VENDOR_ID verb mismatch");

        // GET_PARAMETER VENDOR_ID for codec 1, node 2.
        let v2 = hda_verb(1, 2, VERB_GET_PARAMETER, 0x00);
        assert_eq!(v2, 0x102F0000, "codec 1 node 2 verb mismatch");
    }

    #[test]
    fn get_param_helper() {
        let v = get_param(0, 0, param_id::VENDOR_ID);
        assert_eq!(v, 0x000F0000);
    }

    #[test]
    fn hda_verb_endian_format() {
        // Verify bit-field placement.
        let v = hda_verb(0x0F, 0xAB, 0x123, 0xCD);
        // CAD=0x0F -> bits 31:28 = 0xF
        // NID=0xAB -> bits 27:20 = 0xAB
        // Verb=0x123 -> bits 19:8 = 0x123
        // Payload=0xCD -> bits 7:0 = 0xCD
        assert_eq!(v, 0xFAB123CDu32, "verb bit layout mismatch");
    }

    #[test]
    fn register_offsets_non_zero() {
        const {
            assert!(HDA_CAP < 0x100);
            assert!(HDA_GCTL >= 0x08);
            assert!(HDA_CORBLBASE == 0x40);
            assert!(HDA_CORBWP == 0x48);
            assert!(HDA_RIRBLBASE == 0x50);
            assert!(HDA_RIRBWP == 0x58);
        }
    }

    #[test]
    fn gctl_bits_defined() {
        assert_ne!(GCTL_CRST, 0);
    }

    #[test]
    fn corbctl_bits_defined() {
        assert_ne!(CORBCTL_CORBRUN, 0);
    }

    #[test]
    fn rirbctl_bits_defined() {
        assert_ne!(RIRBCTL_DMAEN, 0);
    }
}
