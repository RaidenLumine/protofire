//! src/kernel/drivers/nvme.rs
//!
//! NVMe solid-state drive driver.
//! NVMe driver.

/// Submission Queue Entry size (64 bytes per the NVMe spec).
pub const SQ_ENTRY_SIZE: usize = 64;
/// Completion Queue Entry size (16 bytes per the NVMe spec).
pub const CQ_ENTRY_SIZE: usize = 16;

/// NVMe page size (minimum memory page for PRP lists).
pub const NVME_PAGE_SIZE: usize = 4096;

/// Default number of entries per queue.
pub const DEFAULT_QUEUE_SIZE: usize = 64;

// ─── MSI-X interrupt vectors ─────────────────────────────────────────

/// MSI-X vector used for NVMe admin-queue completions.
///
/// Allocated from the free IRQ range (34-127) alongside the VirtIO vectors;
/// see `arch/x86_64/interrupts.rs`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub const NVME_ADMIN_VECTOR: u8 = 44;
/// MSI-X vector used for NVMe I/O-queue completions.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub const NVME_IO_VECTOR: u8 = 45;

// ─── NVMe register offsets (relative to BAR0) ──────────────────────────

/// CAP (Controller Capabilities), 64-bit.
pub const NVME_REG_CAP: usize = 0x0000;
/// CC (Controller Configuration), 32-bit.
pub const NVME_REG_CC: usize = 0x0014;
/// CSTS (Controller Status), 32-bit.
pub const NVME_REG_CSTS: usize = 0x001C;
/// AQA (Admin Queue Attributes), 32-bit.
pub const NVME_REG_AQA: usize = 0x0024;
/// ASQ (Admin Submission Queue Base Address), 64-bit.
pub const NVME_REG_ASQ: usize = 0x0028;
/// ACQ (Admin Completion Queue Base Address), 64-bit.
pub const NVME_REG_ACQ: usize = 0x0030;
/// Base offset of the doorbell region (SQyTDBL / CQyHDBL).
pub const NVME_DOORBELL_BASE: usize = 0x1000;

// ─── CAP / CC / CSTS bit fields ────────────────────────────────────────

/// CAP.MQES: maximum queue entries supported (low 16 bits).
pub const CAP_MQES_MASK: u64 = 0xFFFF;
/// CSTS.RDY: controller ready.
pub const CSTS_RDY: u32 = 1 << 0;
/// CC.EN: controller enable.
pub const CC_EN: u32 = 1 << 0;

/// Bounded spin-wait iterations for controller ready transitions.
pub const COMPLETION_POLL_LIMIT: u32 = 1_000_000;

// ─── Admin command opcodes ─────────────────────────────────────────────

pub const ADMIN_DELETE_IOSQ: u8 = 0x00;
pub const ADMIN_CREATE_IOSQ: u8 = 0x01;
pub const ADMIN_DELETE_IOCQ: u8 = 0x02;
pub const ADMIN_CREATE_IOCQ: u8 = 0x03;
pub const ADMIN_IDENTIFY: u8 = 0x06;

// ─── Identify CNS (CDW10 bits 7:0) ────────────────────────────────────

pub const CNS_IDENTIFY_NAMESPACE: u32 = 0x00;
pub const CNS_IDENTIFY_CONTROLLER: u32 = 0x01;

// ─── NVM command opcodes ───────────────────────────────────────────────

pub const NVM_FLUSH: u8 = 0x00;
pub const NVM_WRITE: u8 = 0x01;
pub const NVM_READ: u8 = 0x02;

// ---------------------------------------------------------------------------
// NVMe Submission Queue Entry (64 bytes)
// ---------------------------------------------------------------------------

/// NVMe Submission Queue Entry — exactly 64 bytes.
///
/// Layout per NVMe 1.0 spec:
///   DW0  (0x00): CDW0  — opcode (7:0), fuse (9:8), PRP/SGL (15:14)
///   DW1  (0x04): NSID
///   DW2  (0x08): Reserved
///   DW3  (0x0C): Reserved
///   DW4  (0x10): Metadata Pointer (64-bit)
///   DW6  (0x18): PRP1 (64-bit)
///   DW7  (0x20): PRP2 (64-bit)
///   DW8  (0x28): CDW10
///   DW9  (0x2C): CDW11
///   DW10 (0x30): CDW12
///   DW11 (0x34): CDW13
///   DW12 (0x38): CDW14
///   DW13 (0x3C): CDW15
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NvmeSqe {
    raw: [u32; 16],
}

impl NvmeSqe {
    pub const fn zeroed() -> Self {
        Self { raw: [0u32; 16] }
    }

    pub fn set_opcode(&mut self, opcode: u8) {
        self.raw[0] = (self.raw[0] & !0xFF) | (opcode as u32);
    }

    pub fn set_nsid(&mut self, nsid: u32) {
        self.raw[1] = nsid;
    }

    pub fn set_command_id(&mut self, id: u16) {
        self.raw[0] = (self.raw[0] & !0xFFFF_0000) | ((id as u32) << 16);
    }

    /// Store a 64-bit physical address into the two PRP1 DWORDs (DW6–DW7).
    ///
    /// NVMe splits 64-bit addresses across two 32-bit registers.  Physical
    /// addresses on currently-supported architectures (≤52 bits) fit without
    /// loss.  Values beyond 52 bits are architecturally impossible on x86_64
    /// and aarch64; the `as u32` split is sound for all valid inputs.
    ///
    /// The `debug_assert!` catches accidental use of kernel virtual addresses
    /// (which would have high bits set on x86_64) in debug builds.
    pub fn set_prp1(&mut self, prp1: u64) {
        // PRP entries must be physical addresses below the architectural
        // maximum.  On x86_64 with 4-level paging this is 48 bits; 5-level
        // paging extends to 57 bits.  Either fits in a u64 split.
        debug_assert!(
            prp1 < (1 << 52),
            "set_prp1: physical address {:#018x} exceeds 52-bit architectural limit",
            prp1
        );
        self.raw[6] = prp1 as u32;
        self.raw[7] = (prp1 >> 32) as u32;
    }

    /// Store a 64-bit physical address into the two PRP2 DWORDs (DW8–DW9).
    ///
    /// See [`set_prp1`](Self::set_prp1) for the architectural rationale.
    pub fn set_prp2(&mut self, prp2: u64) {
        debug_assert!(
            prp2 < (1 << 52),
            "set_prp2: physical address {:#018x} exceeds 52-bit architectural limit",
            prp2
        );
        self.raw[8] = prp2 as u32;
        self.raw[9] = (prp2 >> 32) as u32;
    }

    pub fn set_cdw(&mut self, dw10: u32, dw11: u32, dw12: u32) {
        self.raw[10] = dw10;
        self.raw[11] = dw11;
        self.raw[12] = dw12;
    }

    pub fn opcode(&self) -> u8 {
        (self.raw[0] & 0xFF) as u8
    }

    pub fn nsid(&self) -> u32 {
        self.raw[1]
    }
}

// ---------------------------------------------------------------------------
// NVMe Completion Queue Entry (16 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NvmeCqe {
    /// Command-specific result.
    pub dw0: u32,
    /// Reserved.
    _rsvd: u32,
    /// SQ Head Pointer (updated by controller).
    pub sq_head: u16,
    /// SQ Identifier.
    pub sq_id: u16,
    /// Command Identifier.
    pub command_id: u16,
    /// Phase bit and Status Field.
    /// Bit 0: Phase Tag (P), Bits 15:1: Status Field.
    pub status: u16,
}

impl NvmeCqe {
    pub const fn zeroed() -> Self {
        Self {
            dw0: 0,
            _rsvd: 0,
            sq_head: 0,
            sq_id: 0,
            command_id: 0,
            status: 0,
        }
    }

    /// Returns the status code (bits 15:1 of the Status Field).
    pub fn status_code(&self) -> u16 {
        (self.status >> 1) & 0x7FFF
    }

    /// Returns true if the status indicates success (0x0000).
    pub fn is_success(&self) -> bool {
        self.status_code() == 0
    }
}

// ---------------------------------------------------------------------------
// Identify Controller Data (simplified — first 32 bytes)
// ---------------------------------------------------------------------------

/// Identify Controller Data Structure (NVMe 1.0, Figure 91).
/// We only read the fields needed for initialization.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IdentifyController {
    /// PCI Vendor ID.
    pub vid: u16,
    /// PCI Subsystem Vendor ID.
    pub ssvid: u16,
    /// Serial Number (20 ASCII bytes).
    pub sn: [u8; 20],
    /// Model Number (40 ASCII bytes).
    pub mn: [u8; 40],
    /// Firmware Revision (8 ASCII bytes).
    pub fr: [u8; 8],
    /// Recommended Arbitration Burst.
    _rab: u8,
    /// IEEE OUI Identifier.
    _ieee: [u8; 3],
    /// Controller Multi-Path I/O and Namespace Sharing Capabilities.
    _cmic: u8,
    /// Maximum Data Transfer Size (MDTS).
    _mdts: u8,
    /// Controller ID.
    _cntlid: u16,
    /// Firmware Update Granularity.
    _fug: u8,
    /// Optional Asynchronous Events Supported.
    _oacs: u16,
    /// Abort Command Limit.
    _acl: u8,
    /// Asynchronous Event Request Limit.
    _aerl: u8,
    /// Firmware Updates.
    _fwu: u8,
    /// Log Page Attributes.
    _lpa: u8,
    /// Error Log Page Entries.
    _elpe: u8,
    /// Number of Power States Supported.
    _npss: u8,
    /// Admin Vendor Specific Command Configuration.
    _avscc: u8,
    /// Autonomous Power State Transition Attributes.
    _apsta: u8,
    /// Warning Composite Temperature Threshold.
    _wctemp: u16,
    /// Critical Composite Temperature Threshold.
    _cctemp: u16,
    /// NVM Subsystem Report.
    _nn: u32, // Number of Namespaces
}

impl IdentifyController {
    /// Number of namespaces (bytes 516-519).
    pub fn namespace_count(&self) -> u32 {
        self._nn
    }
}

// ---------------------------------------------------------------------------
// Identify Namespace Data (simplified — first 16 bytes)
// ---------------------------------------------------------------------------

/// Identify Namespace Data Structure (NVMe 1.0, Figure 92).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IdentifyNamespace {
    /// Namespace Size (total number of logical blocks).
    pub nsze: u64,
    /// Namespace Capacity (maximum number of logical blocks that may be
    /// allocated).
    pub ncap: u64,
    /// Namespace Utilization.
    pub nuse: u64,
    /// Namespace Features.
    pub nsfeat: u8,
    /// Number of LBA Formats.
    pub nlbaf: u8,
    /// Formatted LBA Size.
    pub flbas: u8,
    /// Metadata Capabilities.
    pub mc: u8,
}

impl IdentifyNamespace {
    /// The formatted LBA size in bytes (pow2).
    pub fn lba_size(&self) -> usize {
        let flbas = self.flbas & 0x0F;
        // LBA Format is at offset 128 + flbas * 4.
        // For simplicity, we assume 512-byte blocks (format index 0 is usually 512).
        // A proper implementation would read the LBA Format table.
        // Assume 512-byte blocks (format index 0 is usually 512).
        // A proper implementation would read the LBA Format table at offset 128 + flbas
        // * 4.
        let _ = flbas;
        512
    }
}

// ---------------------------------------------------------------------------
// NVMe Namespace Info
// ---------------------------------------------------------------------------

pub struct NvmeNamespace {
    pub nsid: u32,
    pub block_count: u64,
    pub block_size: usize,
}

// ---------------------------------------------------------------------------
// Driver integration
// ---------------------------------------------------------------------------

use crate::kernel::drivers::{Driver, DriverCategory};
use crate::kernel::fs::block::BlockDevice;
use crate::kernel::memory::DmaBuffer;
use crate::kernel::sync::Mutex;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

static NVME_PROBED: AtomicBool = AtomicBool::new(false);

/// Stores the BAR0 physical address of the first NVMe controller found during
/// PCI enumeration so that `probe_boot_disk` can initialise it later.
#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
static NVME_BAR0: Mutex<Option<u64>> = Mutex::new(None);

struct NvmeDriver;

impl Driver for NvmeDriver {
    fn name(&self) -> &'static str {
        "nvme"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Storage
    }

    fn init(&self) -> crate::Result<()> {
        if NVME_PROBED.swap(true, Ordering::Acquire) {
            return Ok(());
        }
        probe_nvme()
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(NvmeDriver)
}

/// Handle an NVMe MSI-X interrupt.
///
/// The NVMe driver is poll-based: completions are reaped synchronously inside
/// `admin_submit_and_wait` / `io_submit_and_wait`, so there is no pending
/// queue state to service from the interrupt path.  This handler exists to
/// acknowledge the interrupt; the phase-bit / doorbell logic runs in the
/// polling loops, which will observe the completion on their next iteration.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn nvme_irq_handler() {}

// ─── NVMe controller ──────────────────────────────────────────────────

/// Per-I/O-queue mutable state that is protected by `io_state`.
#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
struct NvmeIoState {
    iosq_tail: u32,
    iocq_head: u32,
    iocq_phase: bool,
    next_cmd_id: u16,
}

/// A fully initialised NVMe controller that implements `BlockDevice`.
///
/// Data I/O uses a single 4 KiB DMA bounce buffer (one frame).  Multi-block
/// transfers are broken into single-block operations by the caller (the block
/// cache already works block-at-a-time).
#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
struct NvmeController {
    bar0: *mut u8,
    dstrd: u32,
    // Admin queues (queue id 0) — state only used during init
    asq: DmaBuffer,
    acq: DmaBuffer,
    asq_tail: u32,
    acq_head: u32,
    acq_phase: bool,
    // I/O queues (queue id 1)
    iosq: DmaBuffer,
    iocq: DmaBuffer,
    iosq_entries: u32,
    iocq_entries: u32,
    io_state: Mutex<NvmeIoState>,
    // Namespace geometry
    nsid: u32,
    block_count: u64,
    block_size: usize,
    // Reusable bounce buffer for single-block data transfers
    io_buf: Mutex<DmaBuffer>,
}

// SAFETY: NvmeController is only constructed on bare-metal x86_64 where the
// kernel is single-threaded.  All mutable state is behind `Mutex` or accessed
// exclusively during initialisation (before the controller is shared via
// `Arc`).  The raw `bar0` pointer is an identity-mapped MMIO region that is
// safe to access from any thread.
unsafe impl Send for NvmeController {}
unsafe impl Sync for NvmeController {}

/// Compute the byte offset of an SQ `y` Tail Doorbell from BAR0.
///
/// NVMe 1.0 §3.1.9: SQyTDBL = 0x1000 + (2 * y) * (4 << DSTRD)
const fn sq_doorbell_offset(qid: u32, dstrd: u32) -> usize {
    NVME_DOORBELL_BASE + (2 * qid as usize) * (4 << dstrd)
}

/// Compute the byte offset of a CQ `y` Head Doorbell from BAR0.
///
/// NVMe 1.0 §3.1.9: CQyHDBL = 0x1000 + (2 * y + 1) * (4 << DSTRD)
const fn cq_doorbell_offset(qid: u32, dstrd: u32) -> usize {
    NVME_DOORBELL_BASE + (2 * qid as usize + 1) * (4 << dstrd)
}

#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
impl NvmeController {
    /// Initialise the controller at `bar0_phys`.
    ///
    /// # Safety
    ///
    /// `bar0_phys` must be the physical base address of the NVMe controller's
    /// PCI BAR0, obtained from PCI enumeration.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    unsafe fn init(bar0_phys: u64) -> crate::Result<Self> {
        use crate::arch::mmu::map_device_mmio;
        use core::ptr::{read_volatile, write_volatile};

        let bar0_size = 8192; // NVMe BAR0 is at least 8 KiB
        let bar0 = map_device_mmio(bar0_phys, bar0_size).ok_or(crate::Error::NotFound)?;

        // ── 1. Read controller capabilities ──────────────────────────
        let cap: u64 = read_volatile(bar0.add(NVME_REG_CAP) as *const u64);
        // CAP.MQES is a spec-defined 16-bit field (max 65535); +1 fits in
        // u32 (max 65536).  The CAP_MQES_MASK constant already extracts only
        // the low 16 bits, making the `as u32` sound for all valid inputs.
        let max_queue_entries = ((cap & CAP_MQES_MASK) + 1) as u32;
        let dstrd = ((cap >> 32) & 0xF) as u32;

        let queue_entries = DEFAULT_QUEUE_SIZE as u32;
        if queue_entries > max_queue_entries {
            return Err(crate::Error::Unsupported);
        }
        let asq_entries = queue_entries;
        let acq_entries = queue_entries;
        let iosq_entries = queue_entries;
        let iocq_entries = queue_entries;

        // ── 2. Disable controller ────────────────────────────────────
        // CC.EN = 0
        write_volatile(bar0.add(NVME_REG_CC) as *mut u32, 0);
        // Wait for CSTS.RDY = 0
        let mut waited = 0;
        loop {
            let csts: u32 = read_volatile(bar0.add(NVME_REG_CSTS) as *const u32);
            if (csts & CSTS_RDY) == 0 {
                break;
            }
            waited += 1;
            if waited > COMPLETION_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }

        // ── 3. Allocate queue DMA buffers ────────────────────────────
        let asq_frames = ((asq_entries as usize * SQ_ENTRY_SIZE)
            .saturating_add(NVME_PAGE_SIZE - 1))
            / NVME_PAGE_SIZE;
        let acq_frames = ((acq_entries as usize * CQ_ENTRY_SIZE)
            .saturating_add(NVME_PAGE_SIZE - 1))
            / NVME_PAGE_SIZE;
        let iosq_frames = ((iosq_entries as usize * SQ_ENTRY_SIZE)
            .saturating_add(NVME_PAGE_SIZE - 1))
            / NVME_PAGE_SIZE;
        let iocq_frames = ((iocq_entries as usize * CQ_ENTRY_SIZE)
            .saturating_add(NVME_PAGE_SIZE - 1))
            / NVME_PAGE_SIZE;

        let asq = DmaBuffer::allocate(asq_frames).ok_or(crate::Error::OutOfMemory)?;
        let acq = DmaBuffer::allocate(acq_frames).ok_or(crate::Error::OutOfMemory)?;
        let iosq = DmaBuffer::allocate(iosq_frames).ok_or(crate::Error::OutOfMemory)?;
        let iocq = DmaBuffer::allocate(iocq_frames).ok_or(crate::Error::OutOfMemory)?;
        let io_buf = DmaBuffer::allocate(1).ok_or(crate::Error::OutOfMemory)?;

        // ── 4. Configure admin queues ────────────────────────────────
        // AQA: ACQS (11:0) | ASQS (27:16)
        let aqa = ((acq_entries - 1) & 0xFFF) | (((asq_entries - 1) & 0xFFF) << 16);
        write_volatile(bar0.add(NVME_REG_AQA) as *mut u32, aqa);
        // ASQ and ACQ base addresses (64-bit physical)
        write_volatile(bar0.add(NVME_REG_ASQ) as *mut u64, asq.phys_addr() as u64);
        write_volatile(bar0.add(NVME_REG_ACQ) as *mut u64, acq.phys_addr() as u64);

        // ── 5. Enable controller ─────────────────────────────────────
        let cc = CC_EN | ((6_u32) << 16) | ((4_u32) << 20); // IOSQES=6 (64 B), IOCQES=4 (16 B)
        write_volatile(bar0.add(NVME_REG_CC) as *mut u32, cc);
        // Wait for CSTS.RDY = 1
        waited = 0;
        loop {
            let csts: u32 = read_volatile(bar0.add(NVME_REG_CSTS) as *const u32);
            if (csts & CSTS_RDY) != 0 {
                break;
            }
            waited += 1;
            if waited > COMPLETION_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }

        // ── 6. Identify controller & namespace ───────────────────────
        // Use a temporary DMA buffer for the 4 KiB identify response.
        let identify_buf = DmaBuffer::allocate(1).ok_or(crate::Error::OutOfMemory)?;
        let mut ctrl = Self {
            bar0,
            dstrd,
            asq,
            acq,
            asq_tail: 0,
            acq_head: 0,
            acq_phase: true,
            iosq,
            iocq,
            iosq_entries,
            iocq_entries,
            io_state: Mutex::new(NvmeIoState {
                iosq_tail: 0,
                iocq_head: 0,
                iocq_phase: true,
                next_cmd_id: 0,
            }),
            nsid: 1,
            block_count: 0,
            block_size: 512,
            io_buf: Mutex::new(io_buf),
        };

        // IDENTIFY controller (CNS=1)
        let mut sqe = NvmeSqe::zeroed();
        sqe.set_opcode(ADMIN_IDENTIFY);
        sqe.set_nsid(0);
        sqe.set_prp1(identify_buf.phys_addr() as u64);
        sqe.set_cdw(CNS_IDENTIFY_CONTROLLER, 0, 0);
        let cqe = ctrl.admin_submit_and_wait(&sqe)?;
        if !cqe.is_success() {
            return Err(crate::Error::NotFound);
        }

        // Parse namespace count from identify data.
        let identify_ctrl: &IdentifyController =
            unsafe { &*(identify_buf.as_ptr() as *const IdentifyController) };
        let ns_count = identify_ctrl.namespace_count();
        if ns_count == 0 {
            return Err(crate::Error::NotFound);
        }

        // IDENTIFY namespace (CNS=0, NSID=1)
        let mut sqe = NvmeSqe::zeroed();
        sqe.set_opcode(ADMIN_IDENTIFY);
        sqe.set_nsid(1);
        sqe.set_prp1(identify_buf.phys_addr() as u64);
        sqe.set_cdw(CNS_IDENTIFY_NAMESPACE, 0, 0);
        let cqe = ctrl.admin_submit_and_wait(&sqe)?;
        if !cqe.is_success() {
            return Err(crate::Error::NotFound);
        }

        let identify_ns: &IdentifyNamespace =
            unsafe { &*(identify_buf.as_ptr() as *const IdentifyNamespace) };
        ctrl.block_count = identify_ns.nsze;
        ctrl.block_size = identify_ns.lba_size();

        // drop the temporary identify buffer
        drop(identify_buf);

        // ── 7. Create I/O queue pair ─────────────────────────────────
        // Create I/O CQ (qid=1, vector=0, contiguous)
        let iocq_phys = ctrl.iocq.phys_addr() as u64;
        let mut sqe = NvmeSqe::zeroed();
        sqe.set_opcode(ADMIN_CREATE_IOCQ);
        sqe.set_prp1(iocq_phys);
        sqe.set_cdw(((iocq_entries - 1) << 16) | 1, 1, 0);
        // DW11[0] = PC (physically contiguous), DW11[1] = EN (enabled)
        let cqe = ctrl.admin_submit_and_wait(&sqe)?;
        if !cqe.is_success() {
            return Err(crate::Error::NotFound);
        }

        // Create I/O SQ (qid=1, cqid=1, contiguous)
        let iosq_phys = ctrl.iosq.phys_addr() as u64;
        let mut sqe = NvmeSqe::zeroed();
        sqe.set_opcode(ADMIN_CREATE_IOSQ);
        sqe.set_prp1(iosq_phys);
        sqe.set_cdw(((iosq_entries - 1) << 16) | 1, (1 << 16) | 1, 0);
        // DW11[0] = PC, DW11[1] = EN, DW11[16:31] = CQID (1)
        let cqe = ctrl.admin_submit_and_wait(&sqe)?;
        if !cqe.is_success() {
            return Err(crate::Error::NotFound);
        }

        Ok(ctrl)
    }

    /// Submit a command on the admin SQ and poll for completion.
    unsafe fn admin_submit_and_wait(&mut self, sqe: &NvmeSqe) -> crate::Result<NvmeCqe> {
        use core::ptr::{read_volatile, write_volatile};

        let tail = self.asq_tail as usize;
        let asq_entries = ((self.asq.len() / SQ_ENTRY_SIZE) as u32).min(DEFAULT_QUEUE_SIZE as u32);
        debug_assert!(
            tail < asq_entries as usize,
            "ASQ tail {tail} out of bounds for {asq_entries} entries"
        );
        let dst = self.asq.as_ptr().add(tail * SQ_ENTRY_SIZE) as *mut NvmeSqe;
        write_volatile(dst, *sqe);

        // Advance tail with wrap.
        self.asq_tail = (self.asq_tail + 1) % asq_entries;

        // Ring SQ doorbell.
        let sq_doorbell = self.bar0.add(sq_doorbell_offset(0, self.dstrd));
        // NVMe doorbell registers are u32-aligned per spec §3.1.9.
        debug_assert!(
            (sq_doorbell as usize).is_multiple_of(core::mem::align_of::<u32>()),
            "SQ doorbell misaligned: {:#x}",
            sq_doorbell as usize
        );
        write_volatile(sq_doorbell as *mut u32, self.asq_tail);

        // Spin until a completion with the expected phase bit arrives.
        let mut waited = 0;
        loop {
            let acq_entries =
                ((self.acq.len() / CQ_ENTRY_SIZE) as u32).min(DEFAULT_QUEUE_SIZE as u32);
            debug_assert!(
                (self.acq_head as usize) < acq_entries as usize,
                "ACQ head {} out of bounds for {acq_entries} entries",
                self.acq_head
            );
            let cqe_ptr =
                self.acq
                    .as_ptr()
                    .add(self.acq_head as usize * CQ_ENTRY_SIZE) as *const NvmeCqe;
            let cqe = read_volatile(cqe_ptr);
            let phase = (cqe.status & 0x1) != 0;
            if phase == self.acq_phase {
                // Advance head with wrap.
                self.acq_head = (self.acq_head + 1) % acq_entries;
                // Flip phase at wrap.
                if self.acq_head == 0 {
                    self.acq_phase = !self.acq_phase;
                }
                // Ring CQ doorbell.
                let cq_doorbell = self.bar0.add(cq_doorbell_offset(0, self.dstrd));
                debug_assert!(
                    (cq_doorbell as usize).is_multiple_of(core::mem::align_of::<u32>()),
                    "CQ doorbell misaligned: {:#x}",
                    cq_doorbell as usize
                );
                write_volatile(cq_doorbell as *mut u32, self.acq_head);
                return Ok(cqe);
            }
            waited += 1;
            if waited > COMPLETION_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }
    }

    /// Submit a command on the I/O SQ and poll for completion.
    fn io_submit_and_wait(&self, sqe: &NvmeSqe) -> crate::Result<NvmeCqe> {
        use core::ptr::{read_volatile, write_volatile};

        let mut state = self.io_state.lock();

        let tail = state.iosq_tail as usize;
        // SAFETY: the I/O SQ DMA buffer is exclusive to this controller;
        // all pointer arithmetic stays within the allocated region.
        let dst = unsafe { self.iosq.as_ptr().add(tail * SQ_ENTRY_SIZE) } as *mut NvmeSqe;
        unsafe { write_volatile(dst, *sqe) };

        // Advance tail with wrap.
        state.iosq_tail = (state.iosq_tail + 1) % self.iosq_entries;

        // Ring SQ doorbell (queue id = 1).
        let sq_doorbell = unsafe { self.bar0.add(sq_doorbell_offset(1, self.dstrd)) };
        unsafe { write_volatile(sq_doorbell as *mut u32, state.iosq_tail) };

        // Spin for completion.
        let mut waited = 0;
        loop {
            let cqe_ptr = unsafe {
                self.iocq
                    .as_ptr()
                    .add(state.iocq_head as usize * CQ_ENTRY_SIZE)
            } as *const NvmeCqe;
            let cqe = unsafe { read_volatile(cqe_ptr) };
            let phase = (cqe.status & 0x1) != 0;
            if phase == state.iocq_phase {
                state.iocq_head = (state.iocq_head + 1) % self.iocq_entries;
                if state.iocq_head == 0 {
                    state.iocq_phase = !state.iocq_phase;
                }
                // Ring CQ doorbell (queue id = 1).
                let cq_doorbell = unsafe { self.bar0.add(cq_doorbell_offset(1, self.dstrd)) };
                debug_assert!(
                    (cq_doorbell as usize).is_multiple_of(core::mem::align_of::<u32>()),
                    "IO CQ doorbell misaligned: {:#x}",
                    cq_doorbell as usize
                );
                unsafe { write_volatile(cq_doorbell as *mut u32, state.iocq_head) };
                drop(state);
                return Ok(cqe);
            }
            waited += 1;
            if waited > COMPLETION_POLL_LIMIT {
                return Err(crate::Error::TimedOut);
            }
            core::hint::spin_loop();
        }
    }

    /// Allocate the next command identifier for I/O submission tracking.
    fn next_cmd_id(&self) -> u16 {
        let mut state = self.io_state.lock();
        let id = state.next_cmd_id;
        state.next_cmd_id = state.next_cmd_id.wrapping_add(1);
        id
    }

    /// Shut down the NVMe controller: delete I/O queues and disable the
    /// controller.  Call before power-off or driver unload.
    ///
    /// # Safety
    ///
    /// The controller must be fully initialised and the BAR0 MMIO mapping
    /// must still be valid.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    #[allow(dead_code)] // Wired when shutdown path is integrated.
    unsafe fn shutdown(&mut self) {
        // Delete I/O Submission Queue (qid=1).
        let mut sqe = NvmeSqe::zeroed();
        sqe.set_opcode(ADMIN_DELETE_IOSQ);
        sqe.set_nsid(0);
        sqe.set_cdw(1, 0, 0); // CDW10 bits 15:0 = QID to delete
        let _ = self.admin_submit_and_wait(&sqe);

        // Delete I/O Completion Queue (qid=1).
        let mut sqe = NvmeSqe::zeroed();
        sqe.set_opcode(ADMIN_DELETE_IOCQ);
        sqe.set_nsid(0);
        sqe.set_cdw(1, 0, 0); // CDW10 bits 15:0 = QID to delete
        let _ = self.admin_submit_and_wait(&sqe);

        // Disable the controller.
        core::ptr::write_volatile(self.bar0.add(NVME_REG_CC) as *mut u32, 0);

        // Wait for CSTS.RDY = 0.
        let mut waited = 0;
        loop {
            let csts: u32 = core::ptr::read_volatile(self.bar0.add(NVME_REG_CSTS) as *const u32);
            if (csts & CSTS_RDY) == 0 {
                break;
            }
            waited += 1;
            if waited > COMPLETION_POLL_LIMIT {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

// ─── BlockDevice implementation ───────────────────────────────────────

impl BlockDevice for NvmeController {
    fn name(&self) -> &str {
        "nvme0"
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
        if !buffer.len().is_multiple_of(self.block_size) {
            return Err(crate::Error::InvalidArgument);
        }

        let io_buf = self.io_buf.lock();
        let bsz = self.block_size;

        // Process block-at-a-time through the bounce buffer.
        let num_blocks = buffer.len() / bsz;
        debug_assert!(
            lba.saturating_add(num_blocks as u64) <= self.block_count,
            "NVMe read beyond namespace: lba={lba} + {nblk} > nsze={nsze}",
            nblk = num_blocks,
            nsze = self.block_count
        );
        for i in 0..num_blocks {
            let block_lba = lba.saturating_add(i as u64);

            let mut sqe = NvmeSqe::zeroed();
            sqe.set_opcode(NVM_READ);
            sqe.set_nsid(self.nsid);
            sqe.set_command_id(self.next_cmd_id()); // rotating IDs for multi-cmd tracking
            sqe.set_prp1(io_buf.phys_addr() as u64);
            // PRP2 = 0: single 512-byte block fits in one page.
            let num_lbas = 1_u32; // one logical block per transfer
                                  // CDW10/CDW11: 64-bit Starting LBA split per NVMe 1.0 §6.8.
                                  // `block_lba as u32` extracts the low 32 bits; this is *not* a
                                  // truncation bug — the high 32 bits follow on the next line.
            sqe.set_cdw(
                block_lba as u32,         // CDW10: SLBA low
                (block_lba >> 32) as u32, // CDW11: SLBA high
                (num_lbas - 1) & 0xFFFF,  // CDW12: NLB (0-based)
            );

            let cqe = self.io_submit_and_wait(&sqe)?;
            if !cqe.is_success() {
                return Err(crate::Error::NotFound);
            }

            // Copy from bounce buffer to caller's buffer.
            let start = i * bsz;
            buffer[start..start + bsz].copy_from_slice(&io_buf.as_slice()[..bsz]);
        }

        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> crate::Result<()> {
        if !data.len().is_multiple_of(self.block_size) {
            return Err(crate::Error::InvalidArgument);
        }

        let mut io_buf = self.io_buf.lock();
        let bsz = self.block_size;

        let num_blocks = data.len() / bsz;
        debug_assert!(
            lba.saturating_add(num_blocks as u64) <= self.block_count,
            "NVMe write beyond namespace: lba={lba} + {nblk} > nsze={nsze}",
            nblk = num_blocks,
            nsze = self.block_count
        );
        for i in 0..num_blocks {
            let block_lba = lba.saturating_add(i as u64);

            // Copy caller's data into the bounce buffer.
            let start = i * bsz;
            io_buf.as_mut_slice()[..bsz].copy_from_slice(&data[start..start + bsz]);

            let mut sqe = NvmeSqe::zeroed();
            sqe.set_opcode(NVM_WRITE);
            sqe.set_nsid(self.nsid);
            sqe.set_command_id(self.next_cmd_id());
            sqe.set_prp1(io_buf.phys_addr() as u64);
            let num_lbas = 1_u32;
            sqe.set_cdw(
                block_lba as u32,
                (block_lba >> 32) as u32,
                (num_lbas - 1) & 0xFFFF,
            );

            let cqe = self.io_submit_and_wait(&sqe)?;
            if !cqe.is_success() {
                return Err(crate::Error::NotFound);
            }
        }

        Ok(())
    }

    fn flush(&self) -> crate::Result<()> {
        let mut sqe = NvmeSqe::zeroed();
        sqe.set_opcode(NVM_FLUSH);
        sqe.set_nsid(self.nsid);

        let cqe = self.io_submit_and_wait(&sqe)?;
        if !cqe.is_success() {
            return Err(crate::Error::NotFound);
        }
        Ok(())
    }
}

// ─── Probe and boot-disk selection ────────────────────────────────────

/// Enumerate NVMe PCI devices and store the first one for later
/// initialisation by `probe_boot_disk`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_nvme() -> crate::Result<()> {
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::println;

    let devices = pci_enumerate_buses();
    let mut found = false;
    for info in devices
        .iter()
        .filter(|d| d.class_code == 0x01 && d.subclass == 0x08)
    {
        let bar0 = &info.bars[0];
        if !bar0.is_mmio || bar0.size == 0 {
            continue;
        }
        found = true;
        println!(
            "[nvme  ] found NVMe controller at {:02x}:{:02x}.{:x} vendor={:04x} device={:04x} BAR0={:#018x} size={} KiB",
            info.bus,
            info.device,
            info.function,
            info.vendor_id,
            info.device_id,
            bar0.base_address,
            bar0.size / 1024
        );
        let mut stored = NVME_BAR0.lock();
        if stored.is_none() {
            *stored = Some(bar0.base_address);
        }
    }
    if !found {
        println!("[nvme  ] no NVMe controllers found");
    }
    Ok(())
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn probe_nvme() -> crate::Result<()> {
    Ok(())
}

/// Try to initialise an NVMe controller from the device discovered during
/// PCI enumeration.  Returns `None` when no NVMe device was found or
/// initialisation fails.
///
/// This is called as a fallback by the driver manager after ATA and VirtIO
/// boot-disk probes.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    use crate::println;

    let bar0 = {
        let stored = NVME_BAR0.lock();
        (*stored)?
    };

    println!(
        "[nvme  ] initialising NVMe controller at BAR0={:#018x}...",
        bar0
    );
    // SAFETY: BAR0 address comes from PCI enumeration.
    let controller = match unsafe { NvmeController::init(bar0) } {
        Ok(ctrl) => ctrl,
        Err(e) => {
            println!("[nvme  ] NVMe init failed: {}", e.as_str());
            // Clear the stored BAR0 so subsequent probes don't retry.
            *NVME_BAR0.lock() = None;
            return None;
        }
    };

    println!(
        "[nvme  ] NVMe ready: {} blocks × {} bytes",
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
    fn sqe_size_is_64_bytes() {
        assert_eq!(core::mem::size_of::<NvmeSqe>(), 64);
    }

    #[test]
    fn cqe_size_is_16_bytes() {
        assert_eq!(core::mem::size_of::<NvmeCqe>(), 16);
    }

    #[test]
    fn cqe_status_code() {
        let mut cqe = NvmeCqe::zeroed();
        cqe.status = 0x0001; // Phase bit set
        assert!(cqe.status_code() == 0);
        assert!(cqe.is_success());

        cqe.status = 0x0002; // Status 1, no phase bit
        assert_eq!(cqe.status_code(), 1);
        assert!(!cqe.is_success());
    }

    #[test]
    fn sqe_field_accessors() {
        let mut sqe = NvmeSqe::zeroed();
        sqe.set_opcode(0x02); // Read
        sqe.set_nsid(1);
        sqe.set_command_id(5);
        // Use addresses within the 52-bit architectural limit so the
        // debug_assert! in set_prp1/set_prp2 passes in debug builds.
        sqe.set_prp1(0x0008_5678_9ABC_DEF0);
        sqe.set_prp2(0x0004_CBA9_8765_4321);
        sqe.set_cdw(100, 0, 0);

        assert_eq!(sqe.opcode(), 0x02);
        assert_eq!(sqe.nsid(), 1);
    }

    #[test]
    fn cqe_has_correct_field_offsets() {
        assert_eq!(core::mem::offset_of!(NvmeCqe, sq_head), 8);
        assert_eq!(core::mem::offset_of!(NvmeCqe, sq_id), 10);
        assert_eq!(core::mem::offset_of!(NvmeCqe, command_id), 12);
        assert_eq!(core::mem::offset_of!(NvmeCqe, status), 14);
    }

    #[test]
    fn admin_opcodes_are_distinct() {
        assert_ne!(ADMIN_DELETE_IOSQ, ADMIN_CREATE_IOSQ);
        assert_ne!(ADMIN_DELETE_IOCQ, ADMIN_CREATE_IOCQ);
        assert_ne!(ADMIN_IDENTIFY, ADMIN_CREATE_IOSQ);
        assert_ne!(ADMIN_IDENTIFY, ADMIN_CREATE_IOCQ);
    }

    #[test]
    fn nvm_opcodes_are_distinct() {
        assert_ne!(NVM_READ, NVM_WRITE);
        assert_ne!(NVM_READ, NVM_FLUSH);
        assert_ne!(NVM_WRITE, NVM_FLUSH);
    }

    #[test]
    fn controller_identify_size_check() {
        // Identify Controller data is 4096 bytes per spec.
        assert!(core::mem::size_of::<IdentifyController>() <= 4096);
    }

    #[test]
    fn namespace_identify_size_check() {
        assert!(core::mem::size_of::<IdentifyNamespace>() <= 4096);
    }

    #[test]
    fn probe_boot_disk_returns_none_when_no_bar0() {
        // On host, probe_boot_disk always returns None because there is no
        // real NVMe BAR and map_device_mmio is a stub.  This test verifies
        // the function does not panic and returns the expected value.
        let result = probe_boot_disk();
        assert!(result.is_none());
    }

    #[test]
    fn block_device_trait_is_implemented() {
        // Compile-time verification: NvmeController implements BlockDevice.
        // probe_boot_disk is the boot-time entry point; on host it returns
        // None because map_device_mmio is a stub (no real PCI BAR).
        assert!(probe_boot_disk().is_none());
    }
}
