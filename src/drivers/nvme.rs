//! src/drivers/nvme.rs
//!
//! NVMe driver: the controller, on the machines that have one.
//!
//! The wire format lives in [`crate::drivers::nvme_protocol`]; what this file
//! adds is the machine's half — bringing the controller up, driving its
//! queues, and offering the result as a block device.  The probe is PCIe, so
//! this is compiled where that bus exists; a machine without it answers under
//! the same module name from `nvme_absent.rs`.
//!
//! The machine's half of the probe is `arch::platform::pci_register_window`,
//! which is where the differences between the three buses live: on x86_64 the
//! BAR is reached at the address enumeration decoded, on riscv64 the device
//! window is identity-mapped so those are the same address, and on AArch64 the
//! window sits above the range the page tables map, so the platform hands back
//! an alias.  The driver asks for a window and never sees which machine it is
//! on — which is what makes this the second PCIe device *class* the
//! device-tree machines drive.

use crate::drivers::Driver;
use crate::drivers::DriverCategory;
use crate::kernel::block::BlockDevice;
use crate::kernel::sync::Mutex;
use crate::memory::DmaBuffer;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

pub use crate::drivers::nvme_protocol::*;

// ─── Interrupts ───────────────────────────────────────────────────────

/// The fixed IDT vector an x86_64 build reserves for admin-queue completions.
///
/// The driver polls, so nothing claims these and no machine programs a table
/// with them: they are the numbers `arch/x86_64/interrupts.rs` still assigns
/// the class, and wiring them into the claim registry is a follow-up
/// ([docs/status.md](../../docs/status.md) records the gap).
pub const NVME_ADMIN_VECTOR: u8 = 44;
/// The fixed IDT vector an x86_64 build reserves for I/O-queue completions.
pub const NVME_IO_VECTOR: u8 = 45;

static NVME_PROBED: AtomicBool = AtomicBool::new(false);

/// The platform-mapped controller registers of the first NVMe function found
/// during enumeration, held for `probe_boot_disk` to initialise later.
///
/// It is stored as an address rather than a pointer because the static is
/// shared: the mapping itself lives as long as the machine does, and only the
/// boot-disk probe dereferences it.
static NVME_BAR0: Mutex<Option<usize>> = Mutex::new(None);

/// NVMe's class: mass storage (0x01), NVM subsystem (0x08).  The programming
/// interface byte distinguishes an NVMe controller from the other things a
/// mass-storage function can be, and the enumeration already decodes it.
const NVME_CLASS_CODE: u8 = 0x01;
const NVME_SUBCLASS: u8 = 0x08;

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
pub fn nvme_irq_handler() {}

// ─── NVMe controller ──────────────────────────────────────────────────

/// Per-I/O-queue mutable state that is protected by `io_state`.
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

// SAFETY: the controller is constructed on bare metal from a BAR the platform
// mapped, and it owns that mapping for the driver's lifetime.  All mutable
// state is behind `Mutex` or accessed exclusively during initialisation
// (before the controller is shared via `Arc`), so moving the handle between
// threads moves the only path to that state.
unsafe impl Send for NvmeController {}
// SAFETY: the controller owns its BAR0 mapping and its queue memory, which
// live for the driver's lifetime, and the `Arc` that hands it out is what
// serialises access.
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

impl NvmeController {
    /// Initialise the controller at `bar0_phys`.
    ///
    /// # Safety
    ///
    /// `bar0_phys` must be the physical base address of the NVMe controller's
    /// PCI BAR0, obtained from PCI enumeration.
    /// # Safety
    ///
    /// `bar0` must be the platform's mapping of this controller's BAR0, at
    /// least `NVME_BAR0_BYTES` long, and the caller must keep it mapped for as
    /// long as the controller lives.
    unsafe fn init(bar0: *mut u8) -> crate::Result<Self> {
        // SAFETY: the caller's contract is that `bar0` is the controller's own
        // BAR0 mapping, so the range is live MMIO; every register this body
        // touches is one the NVMe specification puts inside those 8 KiB.
        unsafe {
            use core::ptr::read_volatile;
            use core::ptr::write_volatile;

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
                { &*(identify_buf.as_ptr() as *const IdentifyController) };
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
                { &*(identify_buf.as_ptr() as *const IdentifyNamespace) };
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
    }

    /// Submit a command on the admin SQ and poll for completion.
    unsafe fn admin_submit_and_wait(&mut self, sqe: &NvmeSqe) -> crate::Result<NvmeCqe> {
        // SAFETY: the controller's admin queues and `bar0` were set up by
        // `init`, and both are exclusively this controller's; every pointer
        // this block derives stays inside the DMA buffers `init` allocated for
        // the queues.
        unsafe {
            use core::ptr::read_volatile;
            use core::ptr::write_volatile;

            let tail = self.asq_tail as usize;
            let asq_entries =
                ((self.asq.len() / SQ_ENTRY_SIZE) as u32).min(DEFAULT_QUEUE_SIZE as u32);
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
                let cqe_ptr = self
                    .acq
                    .as_ptr()
                    .add(self.acq_head as usize * CQ_ENTRY_SIZE)
                    as *const NvmeCqe;
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
    }

    /// Submit a command on the I/O SQ and poll for completion.
    fn io_submit_and_wait(&self, sqe: &NvmeSqe) -> crate::Result<NvmeCqe> {
        use core::ptr::read_volatile;
        use core::ptr::write_volatile;

        let mut state = self.io_state.lock();

        let tail = state.iosq_tail as usize;
        // SAFETY: the I/O SQ DMA buffer is exclusive to this controller;
        // all pointer arithmetic stays within the allocated region.
        let dst = unsafe { self.iosq.as_ptr().add(tail * SQ_ENTRY_SIZE) } as *mut NvmeSqe;
        // SAFETY: as the note above: `dst` is the submission-queue slot for
        // `tail` inside this controller's own DMA region, and the device reads
        // it as one 64-byte entry.
        unsafe { write_volatile(dst, *sqe) };

        // Advance tail with wrap.
        state.iosq_tail = (state.iosq_tail + 1) % self.iosq_entries;

        // Ring SQ doorbell (queue id = 1).
        // SAFETY: `bar0` is the mapped controller BAR and the doorbell offset
        // is the stride the controller itself reported (`dstrd`), so the
        // address is a register inside that mapping.
        let sq_doorbell = unsafe { self.bar0.add(sq_doorbell_offset(1, self.dstrd)) };
        // SAFETY: as the doorbell address above; the write is volatile because
        // the device, not the kernel, consumes it.
        unsafe { write_volatile(sq_doorbell as *mut u32, state.iosq_tail) };

        // Spin for completion.
        let mut waited = 0;
        loop {
            // SAFETY: the completion-queue slot for `head`, inside the DMA
            // region this controller owns — the same argument as the submission
            // path above.
            let cqe_ptr = unsafe {
                self.iocq
                    .as_ptr()
                    .add(state.iocq_head as usize * CQ_ENTRY_SIZE)
            } as *const NvmeCqe;
            // SAFETY: the completion entry the device writes; the read is
            // volatile because the device owns it, and the phase check below
            // decides whether it has been published yet.
            let cqe = unsafe { read_volatile(cqe_ptr) };
            let phase = (cqe.status & 0x1) != 0;
            if phase == state.iocq_phase {
                state.iocq_head = (state.iocq_head + 1) % self.iocq_entries;
                if state.iocq_head == 0 {
                    state.iocq_phase = !state.iocq_phase;
                }
                // Ring CQ doorbell (queue id = 1).
                // SAFETY: as the submission doorbell above: a register inside
                // the mapped BAR at the controller's own stride.
                let cq_doorbell = unsafe { self.bar0.add(cq_doorbell_offset(1, self.dstrd)) };
                debug_assert!(
                    (cq_doorbell as usize).is_multiple_of(core::mem::align_of::<u32>()),
                    "IO CQ doorbell misaligned: {:#x}",
                    cq_doorbell as usize
                );
                // SAFETY: as the submission doorbell write; volatile for the
                // same reason.
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
    #[allow(dead_code)] // Wired when shutdown path is integrated.
    unsafe fn shutdown(&mut self) {
        // SAFETY: the caller's contract is that the controller is initialised
        // and its BAR0 mapping still valid, which is what the register writes
        // below address through `self.bar0`.
        unsafe {
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
                let csts: u32 =
                    core::ptr::read_volatile(self.bar0.add(NVME_REG_CSTS) as *const u32);
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

/// Ask the platform for an NVMe function and keep its registers for
/// `probe_boot_disk` to initialise.
fn probe_nvme() -> crate::Result<()> {
    use crate::println;

    // The vendor is the controller's maker rather than a compatibility
    // promise — every NVMe controller speaks the same registers — so the class
    // is the whole of the match, and `0` is the platform's "any vendor".
    let Some(window) =
        crate::arch::platform::pci_register_window(0, NVME_CLASS_CODE, NVME_SUBCLASS)
    else {
        println!("[nvme  ] no NVMe controllers found");
        return Ok(());
    };
    println!(
        "[nvme  ] found NVMe controller vendor={:04x} device={:04x} BAR={:#x} size={} KiB",
        window.vendor_id,
        window.device_id,
        window.bar_address,
        window.bar_size / 1024
    );
    *NVME_BAR0.lock() = Some(window.bar_address);
    Ok(())
}

/// Try to initialise an NVMe controller from the device discovered during
/// PCI enumeration.  Returns `None` when no NVMe device was found or
/// initialisation fails.
///
/// This is called as a fallback by the driver manager after ATA and VirtIO
/// boot-disk probes.
pub fn probe_boot_disk() -> Option<Arc<dyn BlockDevice>> {
    use crate::println;

    let bar0 = {
        let stored = NVME_BAR0.lock();
        (*stored)?
    };

    println!(
        "[nvme  ] initialising NVMe controller at BAR={:#x}...",
        bar0
    );
    // SAFETY: `bar0` is the platform's mapping of this function's BAR0, which
    // `probe_nvme` stored and which lives as long as the machine does.
    let controller = match unsafe { NvmeController::init(bar0 as *mut u8) } {
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
    let device = Arc::new(controller);
    crate::drivers::record_bound_device(
        device.name(),
        "nvme",
        crate::drivers::DriverCategory::Storage,
        Some(bar0),
    );
    Some(device)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
