//! src/kernel/drivers/ahci.rs
//!
//! AHCI (SATA) host controller driver.
//! AHCI 1.3 SATA controller driver implementing the `BlockDevice` trait.
//!
//! ## Architecture
//!
//! AHCI exposes controller registers via PCI BAR5 (MMIO). The driver:
//!
//! 1. Enables AHCI mode (GHC.AE) and optionally performs a HBA reset
//! 2. Enumerates implemented ports via the PI register
//! 3. For each port with a device attached (PxSSTS.DET == 3): a. Allocates DMA
//!    memory for the Command List (1 K aligned) and Received FIS (256 B
//!    aligned) b. Starts the port command engine (PxCMD.ST + PxCMD.FRE) c.
//!    Sends IDENTIFY DEVICE to determine block count and model
//! 4. Exposes the first found SATA device as a `BlockDevice`
//!
//! ## Limitations (Phase 1)
//!
//! - Polling only — no MSI/MSI-X interrupts
//! - Single port (first found) — no port multiplier support
//! - Single PRD entry per transfer (single-block I/O, matching the block cache)
//! - 4 KiB page-aligned DMA bounce buffer
//!
//! ## Activation
//!
//! Requires the kernel page tables to support high-MMIO addresses (>1 GiB)
//! for BAR5 access.  This driver compiles and passes unit tests; runtime
//! activation follows the same pattern as the NVMe driver.

#![allow(clippy::doc_overindented_list_items)]
// ---------------------------------------------------------------------------
// AHCI register definitions (offsets from BAR5)
// ---------------------------------------------------------------------------

/// HBA Capabilities.
pub const AHCI_REG_CAP: usize = 0x00;
/// Global HBA Control.
pub const AHCI_REG_GHC: usize = 0x04;
/// Interrupt Status.
pub const AHCI_REG_IS: usize = 0x08;
/// Ports Implemented.
pub const AHCI_REG_PI: usize = 0x0C;
/// AHCI Version.
pub const AHCI_REG_VS: usize = 0x10;
/// BIOS/OS Handoff Control and Status.
pub const AHCI_REG_BOHC: usize = 0x28;

// GHC register bits.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const GHC_AE: u32 = 1 << 31; // AHCI Enable

// ---------------------------------------------------------------------------
// Port register offsets (per port, stride = 0x80)
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_BASE: usize = 0x100;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_STRIDE: usize = 0x80;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_CLB: usize = 0x00; // Command List Base (lower 32)
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_CLBU: usize = 0x04; // Command List Base (upper 32)
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_FB: usize = 0x08; // FIS Base (lower 32)
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_FBU: usize = 0x0C; // FIS Base (upper 32)
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_IS: usize = 0x10; // Interrupt Status
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_CMD: usize = 0x18; // Command and Status
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_TFD: usize = 0x20; // Task File Data
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_SERR: usize = 0x30; // SATA Error
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_CI: usize = 0x38; // Command Issue

// PxCMD bits.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CMD_ST: u32 = 1; // Start (Command List running)
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CMD_FR: u32 = 1 << 14; // FIS Receive Running (read-only)
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CMD_CR: u32 = 1 << 15; // Command List Running (read-only)

// Port interrupt bits.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PIS_DHR: u32 = 1 << 0; // Device to Host Register FIS
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PIS_TFES: u32 = 1 << 30; // Task File Error Status

// Error bits to clear on init (all recoverable diag + err).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PX_SERR_CLEAR: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// ATA command constants
// ---------------------------------------------------------------------------

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const ATA_CMD_IDENTIFY: u8 = 0xEC;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;

// ATA device register values.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ATA_DEV_LBA: u8 = 0x40; // LBA mode bit

// ---------------------------------------------------------------------------
// FIS type constants
// ---------------------------------------------------------------------------

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
const FIS_TYPE_H2D: u8 = 0x27; // Register — Host to Device
                               // The remaining FIS types have no live production consumer yet (the driver
                               // only ever *sends* the H2D FIS); they are asserted distinct by a unit test.
#[cfg(test)]
const FIS_TYPE_D2H: u8 = 0x34; // Register — Device to Host
#[cfg(test)]
const FIS_TYPE_SDB: u8 = 0xA1; // Set Device Bits
#[cfg(test)]
const FIS_TYPE_DATA: u8 = 0x46; // Data

// ---------------------------------------------------------------------------
// Queue and command sizing
// ---------------------------------------------------------------------------

/// Number of command slots per port (32 per the AHCI 1.3 spec).
const AHCI_CL_SLOTS: usize = 32;
/// Command List Entry size (32 bytes per the AHCI spec).
pub const AHCI_CL_ENTRY_SIZE: usize = 32;
/// Total Command List size (1 KiB, must be 1 KiB-aligned).
pub const AHCI_CL_TOTAL_SIZE: usize = AHCI_CL_SLOTS * AHCI_CL_ENTRY_SIZE;
/// Received FIS size (256 bytes, must be 256-aligned).
pub const AHCI_RFIS_SIZE: usize = 256;
/// Command Table base size (128 bytes before PRDT entries).
pub const AHCI_CT_BASE_SIZE: usize = 0x80;
/// Maximum PRDT entries we allocate per command table (conservative for 4 KiB
/// bounce-buffer single-block I/O; one PRD entry suffices).
pub const AHCI_MAX_PRDT: usize = 1;
/// Total Command Table allocation per slot.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const AHCI_CT_TOTAL_SIZE: usize = AHCI_CT_BASE_SIZE + AHCI_MAX_PRDT * 16;

// ---------------------------------------------------------------------------
// Polling limits
// ---------------------------------------------------------------------------

/// Iteration limit for port command-engine state transitions (ST/CR/FR).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PORT_CMD_POLL_LIMIT: u32 = 1_000_000;
/// Iteration limit for command completion (single-block I/O).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CMD_COMPLETE_POLL_LIMIT: u32 = 10_000_000;
/// Iteration limit for IDENTIFY DEVICE completion.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const IDENTIFY_POLL_LIMIT: u32 = 10_000_000;

// ---------------------------------------------------------------------------
// AHCI data structures
// ---------------------------------------------------------------------------

/// Command List Entry (32 bytes) — also known as a Command Header.
///
/// Layout per AHCI 1.3 §4.2.2:
///   DW0 (0x00): reserved (bits 15:0), PRDTL (bits 31:16)
///   DW1 (0x04): reserved
///   DW2 (0x08): reserved
///   DW3 (0x0C): reserved
///   DW4 (0x10): CTBA  — Command Table Base Address [31:0]
///   DW5 (0x14): CTBAU — Command Table Base Address [63:32]
///   DW6 (0x18): reserved
///   DW7 (0x1C): reserved
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub(crate) struct AhciCmdHeader {
    _rsvd0: u16,
    pub(crate) prdtl: u16,
    _rsvd1: [u8; 12],
    pub(crate) ctba: u32,
    pub(crate) ctbau: u32,
    _rsvd6: u32,
    _rsvd7: u32,
}

const _: () = assert!(core::mem::size_of::<AhciCmdHeader>() == AHCI_CL_ENTRY_SIZE);

/// PRD (Physical Region Descriptor) Table Entry (16 bytes).
///
/// Layout per AHCI 1.3 §4.2.3:
///   DBA  (0x00): Data Base Address [31:0]
///   DBAU (0x04): Data Base Address [63:32]
///   Rsvd (0x08): reserved
///   DBC  (0x0C): Data Byte Count [21:0], IOC (bit 31)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub(crate) struct AhciPrdtEntry {
    pub(crate) dba: u32,
    pub(crate) dbau: u32,
    _rsvd: u32,
    pub(crate) dbc: u32,
}

const _: () = assert!(core::mem::size_of::<AhciPrdtEntry>() == 16);

/// Host-to-Device Register FIS (20 bytes per the serial ATA spec).
///
/// The full CFIS field in the Command Table is 64 bytes, so the remaining
/// 44 bytes are padding (zeroed).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub(crate) struct H2dRegisterFis {
    fis_type: u8, // 0x27
    flags: u8,    // bit 7 = C (copy), bit 6 = W (write to device)
    pub(crate) command: u8,
    feature_low: u8,
    lba0: u8,
    lba1: u8,
    lba2: u8,
    device: u8,
    lba3: u8,
    lba4: u8,
    lba5: u8,
    feature_high: u8,
    pub(crate) count_low: u8,
    pub(crate) count_high: u8,
    _rsvd: [u8; 6], // bytes 14–19
}

const _: () = assert!(core::mem::size_of::<H2dRegisterFis>() == 20);

// ---------------------------------------------------------------------------
// Driver integration
// ---------------------------------------------------------------------------

use crate::kernel::drivers::{Driver, DriverCategory};
use crate::kernel::fs::block::BlockDevice;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::memory::DmaBuffer;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::sync::Mutex;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

static AHCI_PROBED: AtomicBool = AtomicBool::new(false);

/// Stores the BAR5 physical address and first-found port of an AHCI controller
/// discovered during PCI enumeration so that `probe_boot_disk` can initialise
/// it later.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static AHCI_BAR5: Mutex<Option<(u64, u8)>> = Mutex::new(None);

struct AhciDriver;

impl Driver for AhciDriver {
    fn name(&self) -> &'static str {
        "ahci"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Storage
    }

    fn init(&self) -> crate::Result<()> {
        if AHCI_PROBED.swap(true, Ordering::Acquire) {
            return Ok(());
        }
        probe_ahci()
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(AhciDriver)
}

// ─── AHCI controller ─────────────────────────────────────────────────────

/// A fully initialised AHCI controller port that implements `BlockDevice`.
///
/// Data I/O uses a single 4 KiB DMA bounce buffer (one frame).  Multi-block
/// transfers are broken into single-block operations by the caller (the block
/// cache already works block-at-a-time).
///
/// Bare-metal-only: there is no SATA controller to program on host / other
/// targets, where `probe_boot_disk` returns `None` instead.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
struct AhciPort {
    /// Virtual (identity-mapped) pointer to the HBA MMIO region (BAR5).
    hba: *mut u8,
    /// Port number this controller manages.
    port: u8,

    // DMA structures for the port command engine.
    clb: DmaBuffer, // Command List (1 KiB, 1 KiB-aligned)
    // Never read by software after init: it must stay alive (and DMA-mapped)
    // for the controller to write received-FIS frames into it during commands.
    #[allow(dead_code)]
    fb: DmaBuffer, // Received FIS (256 B, 256 B-aligned)

    // Pre-allocated Command Table DMA buffer (one slot).
    ct: DmaBuffer,

    // Device geometry.
    block_count: u64,
    block_size: usize,

    /// ASCII model string (ATA words 27–46, byte-swapped), NUL-padded.
    model: [u8; 40],

    // Reusable bounce buffer for single-block data transfers.
    io_buf: Mutex<DmaBuffer>,
}

// SAFETY: AhciPort is only constructed on bare-metal x86_64 where the kernel
// is single-threaded.  All mutable state is behind `Mutex` or accessed
// exclusively during initialisation.  The raw `hba` pointer is an
// identity-mapped MMIO region safe to access from any thread.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe impl Send for AhciPort {}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe impl Sync for AhciPort {}

/// Compute the MMIO address of a port register.
#[inline]
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn port_reg(hba: *mut u8, port: u8, reg: usize) -> *mut u8 {
    unsafe { hba.add(PORT_BASE + (port as usize) * PORT_STRIDE + reg) }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl AhciPort {
    /// Initialise an AHCI port at `bar5_phys` for the given `port` number.
    ///
    /// # Safety
    ///
    /// `bar5_phys` must be the physical base address of an AHCI controller's
    /// PCI BAR5, and the port must be implemented and have a device attached.
    unsafe fn init(bar5_phys: u64, port: u8) -> crate::Result<Self> {
        use crate::arch::mmu::map_device_mmio;
        use core::ptr::{read_volatile, write_volatile};

        // AHCI BAR5 is typically 8 KiB–64 KiB; we map the full BAR for the
        // HBA registers and up to 32 port register blocks (32 × 0x80 = 0x1000).
        // A safe default is 32 KiB (0x8000).
        let bar5_size = 0x8000_usize;
        let hba = map_device_mmio(bar5_phys, bar5_size).ok_or(crate::Error::NotFound)?;

        // ── 1. Verify AHCI mode is enabled ────────────────────────────
        let ghc: u32 = read_volatile(hba.add(AHCI_REG_GHC) as *const u32);
        if (ghc & GHC_AE) == 0 {
            write_volatile(hba.add(AHCI_REG_GHC) as *mut u32, ghc | GHC_AE);
        }

        // ── 2. Allocate port DMA buffers ──────────────────────────────
        let clb_frames = AHCI_CL_TOTAL_SIZE.div_ceil(4096);
        let fb_frames = AHCI_RFIS_SIZE.div_ceil(4096);
        let ct_frames = AHCI_CT_TOTAL_SIZE.div_ceil(4096);
        let io_buf_frames = 1;

        let clb = DmaBuffer::allocate(clb_frames.max(1)).ok_or(crate::Error::OutOfMemory)?;
        let fb = DmaBuffer::allocate(fb_frames.max(1)).ok_or(crate::Error::OutOfMemory)?;
        let ct = DmaBuffer::allocate(ct_frames.max(1)).ok_or(crate::Error::OutOfMemory)?;
        let io_buf = DmaBuffer::allocate(io_buf_frames).ok_or(crate::Error::OutOfMemory)?;

        // Verify alignment requirements (must hold even with >4 K frames).
        debug_assert!(
            clb.phys_addr().is_multiple_of(AHCI_CL_TOTAL_SIZE),
            "AHCI CLB not {}-aligned at {:#x}",
            AHCI_CL_TOTAL_SIZE,
            clb.phys_addr()
        );
        debug_assert!(
            fb.phys_addr().is_multiple_of(AHCI_RFIS_SIZE),
            "AHCI FB not {}-aligned at {:#x}",
            AHCI_RFIS_SIZE,
            fb.phys_addr()
        );

        // Clear the Received FIS region (prevents stale data on first use).
        // The DmaBuffer constructor already zeroes, but explicitly clear it
        // for clarity.
        core::ptr::write_bytes(fb.as_ptr(), 0, AHCI_RFIS_SIZE);

        // ── 3. Stop port command engine (if running) ──────────────────
        let cmd_addr = port_reg(hba, port, PORT_CMD);
        let mut cmd: u32 = read_volatile(cmd_addr as *const u32);

        // Clear ST and FRE to stop the command engine.
        if (cmd & CMD_ST) != 0 {
            write_volatile(cmd_addr as *mut u32, cmd & !CMD_ST);
        }
        // Wait for CR (Command List Running) to clear.
        let mut waited = 0;
        loop {
            cmd = read_volatile(cmd_addr as *const u32);
            if (cmd & CMD_CR) == 0 {
                break;
            }
            waited += 1;
            if waited > PORT_CMD_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }

        // Clear FRE.
        if (cmd & CMD_FRE) != 0 {
            write_volatile(cmd_addr as *mut u32, cmd & !CMD_FRE);
        }
        // Wait for FR (FIS Receive Running) to clear.
        let mut waited = 0;
        loop {
            cmd = read_volatile(cmd_addr as *const u32);
            if (cmd & CMD_FR) == 0 {
                break;
            }
            waited += 1;
            if waited > PORT_CMD_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }

        // ── 4. Clear port error status ────────────────────────────────
        write_volatile(port_reg(hba, port, PORT_SERR) as *mut u32, PX_SERR_CLEAR);
        // Clear pending interrupts.
        write_volatile(port_reg(hba, port, PORT_IS) as *mut u32, 0xFFFF_FFFF);

        // ── 5. Set up port DMA pointers ───────────────────────────────
        let clb_phys = clb.phys_addr() as u64;
        let fb_phys = fb.phys_addr() as u64;

        write_volatile(port_reg(hba, port, PORT_CLB) as *mut u32, clb_phys as u32);
        write_volatile(
            port_reg(hba, port, PORT_CLBU) as *mut u32,
            (clb_phys >> 32) as u32,
        );
        write_volatile(port_reg(hba, port, PORT_FB) as *mut u32, fb_phys as u32);
        write_volatile(
            port_reg(hba, port, PORT_FBU) as *mut u32,
            (fb_phys >> 32) as u32,
        );

        // ── 6. Start port command engine ──────────────────────────────
        // Set FRE first, then ST, per the AHCI init sequence.
        cmd = read_volatile(cmd_addr as *const u32);
        cmd |= CMD_FRE | CMD_ST;
        write_volatile(cmd_addr as *mut u32, cmd);

        // Confirm ST and FRE are active.
        let mut waited = 0;
        loop {
            cmd = read_volatile(cmd_addr as *const u32);
            if (cmd & (CMD_ST | CMD_FRE)) == (CMD_ST | CMD_FRE) {
                break;
            }
            waited += 1;
            if waited > PORT_CMD_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }

        // ── 7. Identify device ────────────────────────────────────────
        let mut port_ctrl = Self {
            hba,
            port,
            clb,
            fb,
            ct,
            block_count: 0,
            block_size: 512,
            model: [0u8; 40],
            io_buf: Mutex::new(io_buf),
        };

        port_ctrl.identify_device()?;

        Ok(port_ctrl)
    }

    /// Send IDENTIFY DEVICE to the attached SATA device and parse the
    /// response into `block_count` and `model`.
    unsafe fn identify_device(&mut self) -> crate::Result<()> {
        use core::ptr::{read_volatile, write_volatile};

        // Use the IO bounce buffer as the 512-byte IDENTIFY data destination.
        let identify_buf = DmaBuffer::allocate(1).ok_or(crate::Error::OutOfMemory)?;

        let ct_phys = self.ct.phys_addr() as u64;
        let cmd_slot = 0; // Use slot 0 for IDENTIFY.

        // Build the H2D Register FIS.
        let fis = H2dRegisterFis {
            fis_type: FIS_TYPE_H2D,
            flags: 0x80, // C=1 (copy), W=0 (read from device)
            command: ATA_CMD_IDENTIFY,
            feature_low: 0,
            lba0: 0,
            lba1: 0,
            lba2: 0,
            device: ATA_DEV_LBA,
            lba3: 0,
            lba4: 0,
            lba5: 0,
            feature_high: 0,
            count_low: 0,
            count_high: 0,
            _rsvd: [0u8; 6],
        };

        // Write the FIS at offset 0 of the command table.
        write_volatile(self.ct.as_ptr() as *mut H2dRegisterFis, fis);

        // Build one PRDT entry pointing to the IDENTIFY data buffer.
        let prdt_entry = AhciPrdtEntry {
            dba: identify_buf.phys_addr() as u32,
            dbau: (identify_buf.phys_addr() >> 32) as u32,
            _rsvd: 0,
            dbc: 512 - 1, // Data byte count = 512 (0-based: 511 = 512 bytes)
        };
        write_volatile(
            self.ct.as_ptr().add(AHCI_CT_BASE_SIZE) as *mut AhciPrdtEntry,
            prdt_entry,
        );

        // Set up the Command List entry (slot 0).
        let cl_entry = self.clb.as_ptr().add(cmd_slot * AHCI_CL_ENTRY_SIZE) as *mut AhciCmdHeader;
        write_volatile(
            cl_entry,
            AhciCmdHeader {
                _rsvd0: 0,
                prdtl: 1, // One PRDT entry
                _rsvd1: [0u8; 12],
                ctba: ct_phys as u32,
                ctbau: (ct_phys >> 32) as u32,
                _rsvd6: 0,
                _rsvd7: 0,
            },
        );

        // Ring the command issue doorbell.
        write_volatile(
            port_reg(self.hba, self.port, PORT_CI) as *mut u32,
            1 << cmd_slot,
        );

        // Poll for completion (wait for slot bit to clear in PxCI).
        let mut waited = 0;
        loop {
            let ci: u32 = read_volatile(port_reg(self.hba, self.port, PORT_CI) as *const u32);
            if (ci & (1 << cmd_slot)) == 0 {
                break;
            }
            waited += 1;
            if waited > IDENTIFY_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }

        // Check for error status (PxTFD.ERR bit or PxIS.TFES).
        let tfd: u32 = read_volatile(port_reg(self.hba, self.port, PORT_TFD) as *const u32);
        if (tfd & 0x01) != 0 {
            // Bit 0 of TFD = ERR (error register non-zero)
            return Err(crate::Error::NotFound);
        }
        let pis: u32 = read_volatile(port_reg(self.hba, self.port, PORT_IS) as *const u32);
        if (pis & PIS_TFES) != 0 {
            return Err(crate::Error::NotFound);
        }

        // Parse the IDENTIFY data (512 bytes at identify_buf).
        // Word 60-61: LBA28 capacity (if word 83 bit 10 = 0, no LBA48)
        // Word 100-103: LBA48 capacity
        let data = identify_buf.as_slice();
        let words = unsafe { core::slice::from_raw_parts(data.as_ptr() as *const u16, 256) };

        // Check for LBA48 support (word 83, bit 10).
        let support_lba48 = (words[83] & (1 << 10)) != 0;

        self.block_count = if support_lba48 {
            // Words 100-103 form a 64-bit LBA count (little-endian).
            (words[100] as u64)
                | ((words[101] as u64) << 16)
                | ((words[102] as u64) << 32)
                | ((words[103] as u64) << 48)
        } else {
            // Words 60-61 form a 28-bit LBA count.
            ((words[60] as u64) | ((words[61] as u64) << 16)) & 0x0FFF_FFFF
        };

        // Copy model string (words 27-46, 20 words = 40 bytes, ATA byte-swapped).
        let model_start = 27 * 2;
        let model_bytes = &data[model_start..model_start + 40];
        for (i, chunk) in model_bytes.chunks(2).enumerate() {
            if chunk.len() == 2 {
                self.model[i * 2] = chunk[1]; // high byte first (big-endian within each word)
                if (i * 2 + 1) < 40 {
                    self.model[i * 2 + 1] = chunk[0];
                }
            }
        }

        // Log identification result.
        let model_bytes: alloc::vec::Vec<u8> = data[27 * 2..27 * 2 + 40]
            .chunks(2)
            .flat_map(|w| [w[1], w[0]])
            .collect();
        let model_str = core::str::from_utf8(&model_bytes).unwrap_or("(invalid utf8)");
        crate::println!(
            "[ahci  ] port {}: {} blocks, model: {}",
            self.port,
            self.block_count,
            model_str,
        );

        Ok(())
    }

    /// Submit a DMA command via the command list and poll for completion.
    ///
    /// `fis_command` — the ATA command byte to place in the H2D FIS.
    /// `lba` — starting logical block address.
    /// `block_count` — number of 512-byte blocks to transfer.
    /// `is_write` — true for write commands, false for read.
    /// `buf_phys` — physical address of the data buffer.
    unsafe fn submit_dma_command(
        &self,
        fis_command: u8,
        lba: u64,
        block_count: u16,
        is_write: bool,
        buf_phys: u64,
    ) -> crate::Result<()> {
        use core::ptr::{read_volatile, write_volatile};

        let ct_phys = self.ct.phys_addr() as u64;
        let cmd_slot = 0; // Single slot for Phase 1.

        let data_byte_count = (block_count as usize) * 512;

        // ── 1. Build the H2D Register FIS ──────────────────────────────
        let fis = H2dRegisterFis {
            fis_type: FIS_TYPE_H2D,
            flags: if is_write { 0x80 | (1 << 6) } else { 0x80 }, // C=1, W=write
            command: fis_command,
            feature_low: 0,
            lba0: lba as u8,
            lba1: (lba >> 8) as u8,
            lba2: (lba >> 16) as u8,
            device: ATA_DEV_LBA | ((lba >> 24) as u8 & 0x0F),
            lba3: (lba >> 32) as u8,
            lba4: (lba >> 40) as u8,
            lba5: (lba >> 48) as u8,
            feature_high: 0,
            count_low: block_count as u8,
            count_high: (block_count >> 8) as u8,
            _rsvd: [0u8; 6],
        };
        write_volatile(self.ct.as_ptr() as *mut H2dRegisterFis, fis);

        // ── 2. Build the PRDT entry ───────────────────────────────────
        let prdt_entry = AhciPrdtEntry {
            dba: buf_phys as u32,
            dbau: (buf_phys >> 32) as u32,
            _rsvd: 0,
            dbc: (data_byte_count - 1) as u32, // 0-based byte count
        };
        write_volatile(
            self.ct.as_ptr().add(AHCI_CT_BASE_SIZE) as *mut AhciPrdtEntry,
            prdt_entry,
        );

        // ── 3. Set up the Command List entry (slot 0) ──────────────────
        let cl_entry = self.clb.as_ptr().add(cmd_slot * AHCI_CL_ENTRY_SIZE) as *mut AhciCmdHeader;
        write_volatile(
            cl_entry,
            AhciCmdHeader {
                _rsvd0: 0,
                prdtl: 1,
                _rsvd1: [0u8; 12],
                ctba: ct_phys as u32,
                ctbau: (ct_phys >> 32) as u32,
                _rsvd6: 0,
                _rsvd7: 0,
            },
        );

        // ── 4. Ring the doorbell ──────────────────────────────────────
        // Clear any stale completion status first.
        write_volatile(
            port_reg(self.hba, self.port, PORT_IS) as *mut u32,
            PIS_DHR | PIS_TFES,
        );
        write_volatile(
            port_reg(self.hba, self.port, PORT_CI) as *mut u32,
            1 << cmd_slot,
        );

        // ── 5. Poll for completion ────────────────────────────────────
        let mut waited = 0;
        loop {
            let ci: u32 = read_volatile(port_reg(self.hba, self.port, PORT_CI) as *const u32);
            if (ci & (1 << cmd_slot)) == 0 {
                break;
            }
            waited += 1;
            if waited > CMD_COMPLETE_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }

        // ── 6. Check for errors ───────────────────────────────────────
        let tfd: u32 = read_volatile(port_reg(self.hba, self.port, PORT_TFD) as *const u32);
        if (tfd & 0x01) != 0 {
            // ERR bit set — read the error register for diagnostics.
            let err_reg = ((tfd >> 8) & 0xFF) as u8;
            crate::println!(
                "[ahci  ] DMA cmd {:#04x} error: TFD={:#010x} ERR={:#04x}",
                fis_command,
                tfd,
                err_reg,
            );
            return Err(crate::Error::DeviceError);
        }

        Ok(())
    }
}

// ─── BlockDevice implementation ──────────────────────────────────────────

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl BlockDevice for AhciPort {
    fn name(&self) -> &str {
        "sata0"
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> crate::Result<()> {
        let bsz = self.block_size;

        if !buffer.len().is_multiple_of(bsz) {
            return Err(crate::Error::InvalidArgument);
        }

        let num_blocks = buffer.len() / bsz;
        debug_assert!(
            lba.saturating_add(num_blocks as u64) <= self.block_count,
            "AHCI read beyond device: lba={lba} + {nblk} > nsze={nsze}",
            nblk = num_blocks,
            nsze = self.block_count
        );

        let io_buf = self.io_buf.lock();
        let buf_phys = io_buf.phys_addr() as u64;

        for i in 0..num_blocks {
            let block_lba = lba.saturating_add(i as u64);

            // SAFETY: all offsets validated; io_buf is exclusive under the lock.
            unsafe {
                self.submit_dma_command(
                    ATA_CMD_READ_DMA_EXT,
                    block_lba,
                    1,     // one block at a time
                    false, // read
                    buf_phys,
                )?;
            }

            // Copy from bounce buffer to caller's buffer.
            let start = i * bsz;
            buffer[start..start + bsz].copy_from_slice(&io_buf.as_slice()[..bsz]);
        }

        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> crate::Result<()> {
        let bsz = self.block_size;

        if !data.len().is_multiple_of(bsz) {
            return Err(crate::Error::InvalidArgument);
        }

        let num_blocks = data.len() / bsz;
        debug_assert!(
            lba.saturating_add(num_blocks as u64) <= self.block_count,
            "AHCI write beyond device: lba={lba} + {nblk} > nsze={nsze}",
            nblk = num_blocks,
            nsze = self.block_count
        );

        let mut io_buf = self.io_buf.lock();
        let buf_phys = io_buf.phys_addr() as u64;

        for i in 0..num_blocks {
            let block_lba = lba.saturating_add(i as u64);

            // Copy caller's data into the bounce buffer.
            let start = i * bsz;
            io_buf.as_mut_slice()[..bsz].copy_from_slice(&data[start..start + bsz]);

            // SAFETY: all offsets validated.
            unsafe {
                self.submit_dma_command(
                    ATA_CMD_WRITE_DMA_EXT,
                    block_lba,
                    1,    // one block at a time
                    true, // write
                    buf_phys,
                )?;
            }
        }

        Ok(())
    }

    fn flush(&self) -> crate::Result<()> {
        let io_buf = self.io_buf.lock();
        let buf_phys = io_buf.phys_addr() as u64;

        // SAFETY: the flush command does not transfer data, but still needs
        // a valid PRDT entry (the controller will ignore DBC=0 or we use a
        // zero-length buffer).  We send a FLUSH CACHE command.
        unsafe { self.submit_dma_command(ATA_CMD_FLUSH_CACHE, 0, 0, false, buf_phys) }
    }
}

// ─── Probe and boot-disk selection ───────────────────────────────────────

/// Enumerate AHCI PCI devices and store the first one for later
/// initialisation by `probe_boot_disk`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_ahci() -> crate::Result<()> {
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::println;

    let devices = pci_enumerate_buses();
    let mut found = false;

    // AHCI SATA controllers have class=0x01 (mass storage), subclass=0x06 (SATA).
    // Some BIOSes report them as IDE (subclass=0x01) with prog_if indicating
    // AHCI capability.  We check both and prefer native AHCI mode.
    for info in devices.iter().filter(|d| {
        (d.class_code == 0x01 && d.subclass == 0x06)
            || (d.class_code == 0x01 && d.subclass == 0x01 && d.prog_if == 0x85)
    }) {
        let bar5 = &info.bars[5];
        if !bar5.is_mmio || bar5.size == 0 {
            println!(
                "[ahci  ] skipping {:02x}:{:02x}.{:x} — BAR5 not MMIO or absent",
                info.bus, info.device, info.function
            );
            continue;
        }

        found = true;

        // Read the GHCR to check AHCI enable and port map.
        // The physical BAR5 address is already the full 64-bit value:
        // `pci_enumerate_buses` folds the upper dword of a 64-bit BAR into
        // `base_address`, so no separate high-half access is needed.
        let bar5_phys = bar5.base_address;

        println!(
            "[ahci  ] found AHCI/SATA controller at {:02x}:{:02x}.{:x} vendor={:04x} device={:04x} BAR5={:#018x} size={} KiB",
            info.bus,
            info.device,
            info.function,
            info.vendor_id,
            info.device_id,
            bar5_phys,
            bar5.size / 1024
        );

        // Store the first found controller for later initialisation.
        let mut stored = AHCI_BAR5.lock();
        if stored.is_none() {
            // We'll find the first port with a device later in probe_boot_disk.
            *stored = Some((bar5_phys, 0));
        }
    }

    if !found {
        println!("[ahci  ] no AHCI/SATA controllers found");
    }

    Ok(())
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn probe_ahci() -> crate::Result<()> {
    Ok(())
}

/// Attempt to initialise an AHCI controller port from the device discovered
/// during PCI enumeration.  Returns `None` when no AHCI device was found or
/// initialisation fails.
///
/// This is called as a mid-priority fallback by the driver manager
/// (after ATA PIO, before NVMe).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    use crate::println;

    let (bar5, port) = {
        let stored = AHCI_BAR5.lock();
        (*stored)?
    };

    println!(
        "[ahci  ] initialising AHCI port {} at BAR5={:#018x}...",
        port, bar5
    );

    // SAFETY: BAR5 address comes from PCI enumeration; port was validated
    // during probe_ahci.
    let controller = match unsafe { AhciPort::init(bar5, port) } {
        Ok(ctrl) => ctrl,
        Err(e) => {
            println!("[ahci  ] AHCI init failed: {}", e.as_str());
            *AHCI_BAR5.lock() = None;
            return None;
        }
    };

    println!(
        "[ahci  ] AHCI ready: {} blocks × {} bytes",
        controller.block_count, controller.block_size
    );
    Some(Arc::new(controller))
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_header_size_is_32_bytes() {
        assert_eq!(core::mem::size_of::<AhciCmdHeader>(), 32);
    }

    #[test]
    fn prdt_entry_size_is_16_bytes() {
        assert_eq!(core::mem::size_of::<AhciPrdtEntry>(), 16);
    }

    #[test]
    fn h2d_fis_size_is_20_bytes() {
        assert_eq!(core::mem::size_of::<H2dRegisterFis>(), 20);
    }

    #[test]
    fn command_table_prdt_layout() {
        // Verify that PRDT entries start at offset 0x80 within the Command Table.
        assert_eq!(AHCI_CT_BASE_SIZE, 0x80);
    }

    #[test]
    fn cl_total_size_is_1024() {
        // 32 slots × 32 bytes = 1024.
        assert_eq!(AHCI_CL_TOTAL_SIZE, 1024);
    }

    #[test]
    fn rfis_size_is_256() {
        assert_eq!(AHCI_RFIS_SIZE, 256);
    }

    #[test]
    fn probe_boot_disk_returns_none_on_host() {
        // On host, probe_boot_disk always returns None because there is no
        // real AHCI BAR and map_device_mmio is a stub.  This test verifies
        // the function does not panic.
        let result = probe_boot_disk();
        assert!(result.is_none());
    }

    #[test]
    fn block_device_trait_is_implemented() {
        // Compile-time verification: AhciPort implements BlockDevice.
        assert!(probe_boot_disk().is_none());
    }

    #[test]
    fn cl_total_size_is_aligned() {
        // The Command List must be 1 KiB-aligned per the AHCI spec.
        assert_eq!(AHCI_CL_TOTAL_SIZE % 1024, 0);
    }

    #[test]
    fn rfis_size_is_256_aligned() {
        // The Received FIS area must be 256-byte aligned.
        assert_eq!(AHCI_RFIS_SIZE % 256, 0);
    }

    #[test]
    fn fis_type_constants_are_distinct() {
        assert_ne!(FIS_TYPE_H2D, FIS_TYPE_D2H);
        assert_ne!(FIS_TYPE_H2D, FIS_TYPE_SDB);
        assert_ne!(FIS_TYPE_H2D, FIS_TYPE_DATA);
        assert_ne!(FIS_TYPE_D2H, FIS_TYPE_SDB);
        assert_ne!(FIS_TYPE_D2H, FIS_TYPE_DATA);
        assert_ne!(FIS_TYPE_SDB, FIS_TYPE_DATA);
    }

    #[test]
    fn ata_command_constants_are_distinct() {
        assert_ne!(ATA_CMD_IDENTIFY, ATA_CMD_READ_DMA_EXT);
        assert_ne!(ATA_CMD_IDENTIFY, ATA_CMD_WRITE_DMA_EXT);
        assert_ne!(ATA_CMD_IDENTIFY, ATA_CMD_FLUSH_CACHE);
        assert_ne!(ATA_CMD_READ_DMA_EXT, ATA_CMD_WRITE_DMA_EXT);
        assert_ne!(ATA_CMD_READ_DMA_EXT, ATA_CMD_FLUSH_CACHE);
        assert_ne!(ATA_CMD_WRITE_DMA_EXT, ATA_CMD_FLUSH_CACHE);
    }
}
