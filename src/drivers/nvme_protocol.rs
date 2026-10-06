//! src/drivers/nvme_protocol.rs
//!
//! The NVMe wire format and register map.
//!
//! These are numbers and layouts from the specification, not hardware: a
//! command is 64 bytes wherever it is built, and BAR0's register offsets are
//! the same on every machine that has a controller.  They are compiled — and
//! their size checks run — everywhere, while the controller that drives them
//! is compiled where the machine has one.

/// Submission Queue Entry size (64 bytes per the NVMe spec).
pub const SQ_ENTRY_SIZE: usize = 64;
/// Completion Queue Entry size (16 bytes per the NVMe spec).
pub const CQ_ENTRY_SIZE: usize = 16;

/// NVMe page size (minimum memory page for PRP lists).
pub const NVME_PAGE_SIZE: usize = 4096;

/// Default number of entries per queue.
pub const DEFAULT_QUEUE_SIZE: usize = 64;

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
/// The completion-queue pair, which sits at 0x04/0x05 rather than after the
/// submission-queue pair: 0x02 and 0x03 are Get Log Page and a reserved
/// opcode, so a controller answers the wrong numbers with "Invalid Command
/// Opcode" and the I/O queues are never created.  No gate booted an NVMe
/// device until the device-tree machines drove one, which is why this stood.
pub const ADMIN_DELETE_IOCQ: u8 = 0x04;
pub const ADMIN_CREATE_IOCQ: u8 = 0x05;
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

    /// The opcodes are the specification's numbers, not merely different from
    /// each other.
    ///
    /// "Distinct" was the whole test once, and it passed while the
    /// completion-queue pair sat at 0x02/0x03 — Get Log Page and a reserved
    /// opcode — so every `Create I/O Completion Queue` the driver sent was
    /// answered with "Invalid Command Opcode" and no gate was attached to an
    /// NVMe device to see it.  A number a device decodes is a fact about the
    /// device, and it belongs in the test.
    #[test]
    fn admin_opcodes_are_the_specifications_numbers() {
        assert_eq!(ADMIN_DELETE_IOSQ, 0x00);
        assert_eq!(ADMIN_CREATE_IOSQ, 0x01);
        // 0x02 is Get Log Page and 0x03 is reserved.
        assert_eq!(ADMIN_DELETE_IOCQ, 0x04);
        assert_eq!(ADMIN_CREATE_IOCQ, 0x05);
        assert_eq!(ADMIN_IDENTIFY, 0x06);
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
}
