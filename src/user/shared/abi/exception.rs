//! src/user/shared/abi/exception.rs
//!
//! src/abi/exception.rs
//! Shared public exception ABI constants, frame layouts, and decode helpers.

use core::mem::{offset_of, size_of};

pub const AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR: u8 = 0x20;

pub const AARCH64_EXCEPTION_DATA_ABORT_VECTOR: u8 = 0x24;

pub const AARCH64_ABORT_ACCESS_KIND_READ: u8 = 0;
pub const AARCH64_ABORT_ACCESS_KIND_WRITE: u8 = 1;
pub const AARCH64_ABORT_ACCESS_KIND_EXECUTE: u8 = 2;
pub const AARCH64_ABORT_ACCESS_KIND_UNKNOWN: u8 = u8::MAX;

// These flag bits are part of the kernel/user exception-handler ABI and must
// remain numerically stable across revisions.
pub const AARCH64_USER_EXCEPTION_HANDLER_FLAG_NONE: usize = 0;
pub const AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT: usize = 1 << 0;
pub const AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK: usize = 1 << 1;
pub const AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED: usize = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AArch64AbortSyndrome {
    // The vector distinguishes instruction aborts from data aborts, while ISS
    // carries the fault-status and access-mode bits needed by user space.
    pub vector: u8,
    pub iss: u32,
}

impl AArch64AbortSyndrome {
    #[inline(always)]
    pub const fn from_exception(vector: u8, error_code: u64) -> Option<Self> {
        match vector {
            AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR | AARCH64_EXCEPTION_DATA_ABORT_VECTOR => {
                Some(Self {
                    vector,
                    iss: error_code as u32,
                })
            }
            _ => None,
        }
    }

    #[inline(always)]
    pub const fn fault_status_code(self) -> u8 {
        (self.iss & 0x3f) as u8
    }

    #[inline(always)]
    pub const fn fault_status_name(self) -> &'static str {
        match self.fault_status_code() {
            0x00 => "address size fault level 0",
            0x01 => "address size fault level 1",
            0x02 => "address size fault level 2",
            0x03 => "address size fault level 3",
            0x04 => "translation fault level 0",
            0x05 => "translation fault level 1",
            0x06 => "translation fault level 2",
            0x07 => "translation fault level 3",
            0x08 => "access flag fault level 0",
            0x09 => "access flag fault level 1",
            0x0a => "access flag fault level 2",
            0x0b => "access flag fault level 3",
            0x0c => "permission fault level 0",
            0x0d => "permission fault level 1",
            0x0e => "permission fault level 2",
            0x0f => "permission fault level 3",
            0x21 => "alignment fault",
            _ => "fault status",
        }
    }

    #[inline(always)]
    pub const fn access_kind_code(self) -> u8 {
        match self.vector {
            AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR => AARCH64_ABORT_ACCESS_KIND_EXECUTE,
            AARCH64_EXCEPTION_DATA_ABORT_VECTOR => {
                if self.iss & (1 << 6) != 0 {
                    AARCH64_ABORT_ACCESS_KIND_WRITE
                } else {
                    AARCH64_ABORT_ACCESS_KIND_READ
                }
            }
            _ => AARCH64_ABORT_ACCESS_KIND_UNKNOWN,
        }
    }

    #[inline(always)]
    pub const fn access_kind(self) -> &'static str {
        match self.access_kind_code() {
            AARCH64_ABORT_ACCESS_KIND_READ => "read",
            AARCH64_ABORT_ACCESS_KIND_WRITE => "write",
            AARCH64_ABORT_ACCESS_KIND_EXECUTE => "execute",
            _ => "access",
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AArch64UserExceptionFrame {
    // This layout is consumed directly by kernel trap glue and user recovery
    // code, so field order and offsets must stay ABI-stable.
    pub vector: u64,
    pub error_code: u64,
    pub fault_address: u64,
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub saved_program_status: u64,
}

impl AArch64UserExceptionFrame {
    #[inline(always)]
    pub const fn abort_syndrome(&self) -> Option<AArch64AbortSyndrome> {
        AArch64AbortSyndrome::from_exception(self.vector as u8, self.error_code)
    }
}

pub const AARCH64_USER_EXCEPTION_FRAME_SIZE: usize = size_of::<AArch64UserExceptionFrame>();

pub const AARCH64_USER_EXCEPTION_FRAME_VECTOR_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, vector);

pub const AARCH64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, error_code);

pub const AARCH64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, fault_address);

// The register offsets below are consumed by assembly payloads and typed user
// helpers; keep them explicit instead of deriving them ad hoc at call sites.
pub const AARCH64_USER_EXCEPTION_FRAME_X0_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x0);
pub const AARCH64_USER_EXCEPTION_FRAME_X1_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x1);
pub const AARCH64_USER_EXCEPTION_FRAME_X2_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x2);
pub const AARCH64_USER_EXCEPTION_FRAME_X3_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x3);
pub const AARCH64_USER_EXCEPTION_FRAME_X4_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x4);
pub const AARCH64_USER_EXCEPTION_FRAME_X5_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x5);
pub const AARCH64_USER_EXCEPTION_FRAME_X6_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x6);
pub const AARCH64_USER_EXCEPTION_FRAME_X7_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x7);
pub const AARCH64_USER_EXCEPTION_FRAME_X8_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x8);
pub const AARCH64_USER_EXCEPTION_FRAME_X9_OFFSET: usize = offset_of!(AArch64UserExceptionFrame, x9);
pub const AARCH64_USER_EXCEPTION_FRAME_X10_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x10);
pub const AARCH64_USER_EXCEPTION_FRAME_X11_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x11);
pub const AARCH64_USER_EXCEPTION_FRAME_X12_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x12);
pub const AARCH64_USER_EXCEPTION_FRAME_X13_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x13);
pub const AARCH64_USER_EXCEPTION_FRAME_X14_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x14);
pub const AARCH64_USER_EXCEPTION_FRAME_X15_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x15);
pub const AARCH64_USER_EXCEPTION_FRAME_X16_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x16);
pub const AARCH64_USER_EXCEPTION_FRAME_X17_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x17);
pub const AARCH64_USER_EXCEPTION_FRAME_X18_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x18);
pub const AARCH64_USER_EXCEPTION_FRAME_X19_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x19);
pub const AARCH64_USER_EXCEPTION_FRAME_X20_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x20);
pub const AARCH64_USER_EXCEPTION_FRAME_X21_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x21);
pub const AARCH64_USER_EXCEPTION_FRAME_X22_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x22);
pub const AARCH64_USER_EXCEPTION_FRAME_X23_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x23);
pub const AARCH64_USER_EXCEPTION_FRAME_X24_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x24);
pub const AARCH64_USER_EXCEPTION_FRAME_X25_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x25);
pub const AARCH64_USER_EXCEPTION_FRAME_X26_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x26);
pub const AARCH64_USER_EXCEPTION_FRAME_X27_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x27);
pub const AARCH64_USER_EXCEPTION_FRAME_X28_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x28);
pub const AARCH64_USER_EXCEPTION_FRAME_X29_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x29);
pub const AARCH64_USER_EXCEPTION_FRAME_X30_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, x30);

pub const AARCH64_USER_EXCEPTION_FRAME_INSTRUCTION_POINTER_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, instruction_pointer);

pub const AARCH64_USER_EXCEPTION_FRAME_STACK_POINTER_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, stack_pointer);

pub const AARCH64_USER_EXCEPTION_FRAME_SAVED_PROGRAM_STATUS_OFFSET: usize =
    offset_of!(AArch64UserExceptionFrame, saved_program_status);

pub const X86_64_EXCEPTION_DEBUG_VECTOR: u8 = 1;

pub const X86_64_EXCEPTION_INVALID_OPCODE_VECTOR: u8 = 6;

pub const X86_64_EXCEPTION_DEVICE_NOT_AVAILABLE_VECTOR: u8 = 7;

pub const X86_64_EXCEPTION_DOUBLE_FAULT_VECTOR: u8 = 8;

pub const X86_64_EXCEPTION_INVALID_TSS_VECTOR: u8 = 10;

pub const X86_64_EXCEPTION_SEGMENT_NOT_PRESENT_VECTOR: u8 = 11;

pub const X86_64_EXCEPTION_STACK_SEGMENT_VECTOR: u8 = 12;

pub const X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR: u8 = 13;

pub const X86_64_EXCEPTION_PAGE_FAULT_VECTOR: u8 = 14;

// These flag bits are also exposed through the public user exception ABI, so
// their bit positions must stay stable.
pub const X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE: usize = 0;

pub const X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT: usize = 1 << 0;

pub const X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK: usize = 1 << 1;

pub const X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED: usize = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64PageFaultError {
    pub present: bool,
    pub write: bool,
    pub user: bool,
    pub reserved_bit_violation: bool,
    pub instruction_fetch: bool,
    pub protection_key: bool,
    pub shadow_stack: bool,
    pub software_guard_ext: bool,
}

impl X86_64PageFaultError {
    pub const fn from_error_code(error_code: u64) -> Self {
        Self {
            present: error_code & (1 << 0) != 0,
            write: error_code & (1 << 1) != 0,
            user: error_code & (1 << 2) != 0,
            reserved_bit_violation: error_code & (1 << 3) != 0,
            instruction_fetch: error_code & (1 << 4) != 0,
            protection_key: error_code & (1 << 5) != 0,
            shadow_stack: error_code & (1 << 6) != 0,
            software_guard_ext: error_code & (1 << 15) != 0,
        }
    }

    pub const fn access_kind(self) -> &'static str {
        if self.instruction_fetch {
            "instruction-fetch"
        } else if self.write {
            "write"
        } else {
            "read"
        }
    }

    pub const fn privilege_level(self) -> &'static str {
        if self.user {
            "user"
        } else {
            "kernel"
        }
    }

    pub const fn reason(self) -> &'static str {
        if self.present {
            "protection-violation"
        } else {
            "not-present"
        }
    }
}

// ── General Protection Fault (#GP) error code decode ──
//
// Bits 0-15: selector index of the faulting segment/interrupt gate
// Bit  14:   table (LDT=0, IDT=1)
// Bit  15:   TI (table indicator — GDT=0, LDT=1)

const GP_ERROR_SELECTOR_MASK: u64 = 0xFFF8;
const GP_ERROR_IDT_BIT: u64 = 1 << 1; // bit 1: IDT (0=GDT/LDT, 1=IDT)
const GP_ERROR_TI_BIT: u64 = 1 << 2; // bit 2: TI (0=GDT, 1=LDT, when IDT=0)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64GeneralProtectionError {
    pub selector_index: u16,
    pub table: &'static str,
    pub external: bool,
    pub idt: bool,
}

impl X86_64GeneralProtectionError {
    pub const fn from_error_code(error_code: u64) -> Self {
        let selector_index = ((error_code & GP_ERROR_SELECTOR_MASK) >> 3) as u16;
        let (table, idt) = if error_code & GP_ERROR_IDT_BIT != 0 {
            ("IDT", true)
        } else if error_code & GP_ERROR_TI_BIT != 0 {
            ("LDT", false)
        } else {
            ("GDT", false)
        };
        Self {
            selector_index,
            table,
            external: error_code & 1 != 0,
            idt,
        }
    }

    pub fn description(self) -> &'static str {
        if self.idt {
            if self.selector_index == 0 {
                "null-interrupt-gate"
            } else {
                "interrupt-gate-violation"
            }
        } else if self.selector_index == 0 {
            "null-segment-selector"
        } else if self.table == "GDT" {
            "gdt-segment-violation"
        } else {
            "ldt-segment-violation"
        }
    }
}

// ── Stack Segment Fault (#SS) error code decode ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64StackSegmentError {
    pub selector_index: u16,
    pub external: bool,
}

impl X86_64StackSegmentError {
    pub const fn from_error_code(error_code: u64) -> Self {
        Self {
            selector_index: ((error_code & GP_ERROR_SELECTOR_MASK) >> 3) as u16,
            external: error_code & 1 != 0,
        }
    }

    pub fn description(self) -> &'static str {
        if self.selector_index == 0 {
            "null-stack-segment"
        } else {
            "stack-segment-violation"
        }
    }
}

// ── Segment Not Present (#NP) error code decode ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64SegmentNotPresentError {
    pub selector_index: u16,
    pub external: bool,
}

impl X86_64SegmentNotPresentError {
    pub const fn from_error_code(error_code: u64) -> Self {
        Self {
            selector_index: ((error_code & GP_ERROR_SELECTOR_MASK) >> 3) as u16,
            external: error_code & 1 != 0,
        }
    }

    pub fn description(self) -> &'static str {
        if self.selector_index == 0 {
            "null-segment-not-present"
        } else {
            "segment-not-present"
        }
    }
}

// ── Invalid TSS (#TS) error code decode ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64InvalidTssError {
    pub selector_index: u16,
    pub external: bool,
    pub idt: bool,
}

impl X86_64InvalidTssError {
    pub const fn from_error_code(error_code: u64) -> Self {
        Self {
            selector_index: ((error_code & GP_ERROR_SELECTOR_MASK) >> 3) as u16,
            external: error_code & 1 != 0,
            idt: error_code & GP_ERROR_IDT_BIT != 0,
        }
    }

    pub fn description(self) -> &'static str {
        if self.idt {
            "task-gate-in-idt"
        } else if self.selector_index == 0 {
            "null-tss-selector"
        } else {
            "tss-selector-violation"
        }
    }
}

// ── User Exception Frame ──

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86_64UserExceptionFrame {
    pub vector: u64,
    pub error_code: u64,
    pub fault_address: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub rflags: u64,
}

impl X86_64UserExceptionFrame {
    pub const fn page_fault_error(&self) -> Option<X86_64PageFaultError> {
        if self.vector == X86_64_EXCEPTION_PAGE_FAULT_VECTOR as u64 {
            Some(X86_64PageFaultError::from_error_code(self.error_code))
        } else {
            None
        }
    }
}

pub const X86_64_USER_EXCEPTION_FRAME_SIZE: usize = size_of::<X86_64UserExceptionFrame>();

pub const X86_64_USER_EXCEPTION_FRAME_VECTOR_OFFSET: usize =
    offset_of!(X86_64UserExceptionFrame, vector);

pub const X86_64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET: usize =
    offset_of!(X86_64UserExceptionFrame, error_code);

pub const X86_64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET: usize =
    offset_of!(X86_64UserExceptionFrame, fault_address);

pub const X86_64_USER_EXCEPTION_FRAME_RAX_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, rax);

pub const X86_64_USER_EXCEPTION_FRAME_RBX_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, rbx);

pub const X86_64_USER_EXCEPTION_FRAME_RCX_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, rcx);

pub const X86_64_USER_EXCEPTION_FRAME_RDX_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, rdx);

pub const X86_64_USER_EXCEPTION_FRAME_RSI_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, rsi);

pub const X86_64_USER_EXCEPTION_FRAME_RDI_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, rdi);

pub const X86_64_USER_EXCEPTION_FRAME_RBP_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, rbp);

pub const X86_64_USER_EXCEPTION_FRAME_R8_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, r8);

pub const X86_64_USER_EXCEPTION_FRAME_R9_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, r9);

pub const X86_64_USER_EXCEPTION_FRAME_R10_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, r10);

pub const X86_64_USER_EXCEPTION_FRAME_R11_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, r11);

pub const X86_64_USER_EXCEPTION_FRAME_R12_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, r12);

pub const X86_64_USER_EXCEPTION_FRAME_R13_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, r13);

pub const X86_64_USER_EXCEPTION_FRAME_R14_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, r14);

pub const X86_64_USER_EXCEPTION_FRAME_R15_OFFSET: usize = offset_of!(X86_64UserExceptionFrame, r15);

pub const X86_64_USER_EXCEPTION_FRAME_RIP_OFFSET: usize =
    offset_of!(X86_64UserExceptionFrame, instruction_pointer);

pub const X86_64_USER_EXCEPTION_FRAME_RSP_OFFSET: usize =
    offset_of!(X86_64UserExceptionFrame, stack_pointer);

pub const X86_64_USER_EXCEPTION_FRAME_RFLAGS_OFFSET: usize =
    offset_of!(X86_64UserExceptionFrame, rflags);

#[cfg(test)]
mod tests {
    use super::{
        AArch64AbortSyndrome, AArch64UserExceptionFrame, AARCH64_ABORT_ACCESS_KIND_EXECUTE,
        AARCH64_ABORT_ACCESS_KIND_WRITE, AARCH64_EXCEPTION_DATA_ABORT_VECTOR,
        AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR, AARCH64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET,
        AARCH64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET,
        AARCH64_USER_EXCEPTION_FRAME_INSTRUCTION_POINTER_OFFSET,
        AARCH64_USER_EXCEPTION_FRAME_SAVED_PROGRAM_STATUS_OFFSET,
        AARCH64_USER_EXCEPTION_FRAME_SIZE, AARCH64_USER_EXCEPTION_FRAME_STACK_POINTER_OFFSET,
        AARCH64_USER_EXCEPTION_FRAME_VECTOR_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X0_OFFSET,
        AARCH64_USER_EXCEPTION_FRAME_X30_OFFSET,
    };
    use super::{
        X86_64GeneralProtectionError, X86_64InvalidTssError, X86_64PageFaultError,
        X86_64SegmentNotPresentError, X86_64StackSegmentError, X86_64UserExceptionFrame,
        X86_64_EXCEPTION_DEVICE_NOT_AVAILABLE_VECTOR, X86_64_EXCEPTION_DOUBLE_FAULT_VECTOR,
        X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR, X86_64_EXCEPTION_INVALID_OPCODE_VECTOR,
        X86_64_EXCEPTION_INVALID_TSS_VECTOR, X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
        X86_64_EXCEPTION_SEGMENT_NOT_PRESENT_VECTOR, X86_64_EXCEPTION_STACK_SEGMENT_VECTOR,
        X86_64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET, X86_64_USER_EXCEPTION_FRAME_R10_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_R11_OFFSET, X86_64_USER_EXCEPTION_FRAME_R12_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_R13_OFFSET, X86_64_USER_EXCEPTION_FRAME_R14_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_R15_OFFSET, X86_64_USER_EXCEPTION_FRAME_R8_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_R9_OFFSET, X86_64_USER_EXCEPTION_FRAME_RAX_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_RBP_OFFSET, X86_64_USER_EXCEPTION_FRAME_RBX_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_RCX_OFFSET, X86_64_USER_EXCEPTION_FRAME_RDI_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_RDX_OFFSET, X86_64_USER_EXCEPTION_FRAME_RFLAGS_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_RIP_OFFSET, X86_64_USER_EXCEPTION_FRAME_RSI_OFFSET,
        X86_64_USER_EXCEPTION_FRAME_RSP_OFFSET, X86_64_USER_EXCEPTION_FRAME_SIZE,
        X86_64_USER_EXCEPTION_FRAME_VECTOR_OFFSET,
    };
    use core::mem::{offset_of, size_of};

    #[test]
    fn x86_64_user_exception_frame_public_offsets_match_layout() {
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_SIZE,
            size_of::<X86_64UserExceptionFrame>()
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_VECTOR_OFFSET,
            offset_of!(X86_64UserExceptionFrame, vector)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET,
            offset_of!(X86_64UserExceptionFrame, error_code)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET,
            offset_of!(X86_64UserExceptionFrame, fault_address)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RAX_OFFSET,
            offset_of!(X86_64UserExceptionFrame, rax)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RBX_OFFSET,
            offset_of!(X86_64UserExceptionFrame, rbx)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RCX_OFFSET,
            offset_of!(X86_64UserExceptionFrame, rcx)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RDX_OFFSET,
            offset_of!(X86_64UserExceptionFrame, rdx)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RSI_OFFSET,
            offset_of!(X86_64UserExceptionFrame, rsi)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RDI_OFFSET,
            offset_of!(X86_64UserExceptionFrame, rdi)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RBP_OFFSET,
            offset_of!(X86_64UserExceptionFrame, rbp)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_R8_OFFSET,
            offset_of!(X86_64UserExceptionFrame, r8)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_R9_OFFSET,
            offset_of!(X86_64UserExceptionFrame, r9)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_R10_OFFSET,
            offset_of!(X86_64UserExceptionFrame, r10)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_R11_OFFSET,
            offset_of!(X86_64UserExceptionFrame, r11)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_R12_OFFSET,
            offset_of!(X86_64UserExceptionFrame, r12)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_R13_OFFSET,
            offset_of!(X86_64UserExceptionFrame, r13)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_R14_OFFSET,
            offset_of!(X86_64UserExceptionFrame, r14)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_R15_OFFSET,
            offset_of!(X86_64UserExceptionFrame, r15)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RIP_OFFSET,
            offset_of!(X86_64UserExceptionFrame, instruction_pointer)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RSP_OFFSET,
            offset_of!(X86_64UserExceptionFrame, stack_pointer)
        );
        assert_eq!(
            X86_64_USER_EXCEPTION_FRAME_RFLAGS_OFFSET,
            offset_of!(X86_64UserExceptionFrame, rflags)
        );
    }

    #[test]
    fn x86_64_page_fault_error_decodes_relevant_bits() {
        let error =
            X86_64PageFaultError::from_error_code((1 << 0) | (1 << 1) | (1 << 4) | (1 << 15));

        assert!(error.present);
        assert!(error.write);
        assert!(!error.user);
        assert!(error.instruction_fetch);
        assert!(error.software_guard_ext);
        assert_eq!(error.access_kind(), "instruction-fetch");
        assert_eq!(error.privilege_level(), "kernel");
        assert_eq!(error.reason(), "protection-violation");
    }

    #[test]
    fn x86_64_user_exception_frame_exposes_page_fault_decoder() {
        let page_fault = X86_64UserExceptionFrame {
            vector: X86_64_EXCEPTION_PAGE_FAULT_VECTOR as u64,
            error_code: (1 << 1) | (1 << 2),
            fault_address: 0xfeed_cafe,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            instruction_pointer: 0x1000,
            stack_pointer: 0x2000,
            rflags: 0x202,
        };
        let non_page_fault = X86_64UserExceptionFrame {
            vector: X86_64_EXCEPTION_INVALID_OPCODE_VECTOR as u64,
            ..page_fault
        };

        let decoded = page_fault.page_fault_error().expect("page fault decode");
        assert!(decoded.write);
        assert!(decoded.user);
        assert_eq!(decoded.access_kind(), "write");
        assert_eq!(decoded.privilege_level(), "user");
        assert_eq!(decoded.reason(), "not-present");
        assert_eq!(non_page_fault.page_fault_error(), None);
    }

    #[test]
    fn aarch64_abort_syndrome_decodes_data_abort_write_permission_fault() {
        let syndrome =
            AArch64AbortSyndrome::from_exception(AARCH64_EXCEPTION_DATA_ABORT_VECTOR, 0x4f)
                .expect("aarch64 data abort decode");

        assert_eq!(syndrome.vector, AARCH64_EXCEPTION_DATA_ABORT_VECTOR);
        assert_eq!(syndrome.iss, 0x4f);
        assert_eq!(syndrome.fault_status_code(), 0x0f);
        assert_eq!(syndrome.fault_status_name(), "permission fault level 3");
        assert_eq!(syndrome.access_kind_code(), AARCH64_ABORT_ACCESS_KIND_WRITE);
        assert_eq!(syndrome.access_kind(), "write");
    }

    #[test]
    fn aarch64_abort_syndrome_decodes_instruction_abort_execute_permission_fault() {
        let syndrome =
            AArch64AbortSyndrome::from_exception(AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR, 0x0f)
                .expect("aarch64 instruction abort decode");

        assert_eq!(syndrome.vector, AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR);
        assert_eq!(syndrome.iss, 0x0f);
        assert_eq!(syndrome.fault_status_code(), 0x0f);
        assert_eq!(syndrome.fault_status_name(), "permission fault level 3");
        assert_eq!(
            syndrome.access_kind_code(),
            AARCH64_ABORT_ACCESS_KIND_EXECUTE
        );
        assert_eq!(syndrome.access_kind(), "execute");
    }

    #[test]
    fn aarch64_abort_syndrome_rejects_non_abort_vectors() {
        assert_eq!(AArch64AbortSyndrome::from_exception(0x15, 0x4f), None);
    }

    #[test]
    fn aarch64_user_exception_frame_size_matches_layout() {
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_SIZE,
            size_of::<AArch64UserExceptionFrame>()
        );
    }

    #[test]
    fn aarch64_user_exception_frame_public_offsets_match_layout() {
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_VECTOR_OFFSET,
            offset_of!(AArch64UserExceptionFrame, vector)
        );
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET,
            offset_of!(AArch64UserExceptionFrame, error_code)
        );
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET,
            offset_of!(AArch64UserExceptionFrame, fault_address)
        );
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_X0_OFFSET,
            offset_of!(AArch64UserExceptionFrame, x0)
        );
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_X30_OFFSET,
            offset_of!(AArch64UserExceptionFrame, x30)
        );
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_INSTRUCTION_POINTER_OFFSET,
            offset_of!(AArch64UserExceptionFrame, instruction_pointer)
        );
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_STACK_POINTER_OFFSET,
            offset_of!(AArch64UserExceptionFrame, stack_pointer)
        );
        assert_eq!(
            AARCH64_USER_EXCEPTION_FRAME_SAVED_PROGRAM_STATUS_OFFSET,
            offset_of!(AArch64UserExceptionFrame, saved_program_status)
        );
    }

    #[test]
    fn aarch64_user_exception_frame_exposes_abort_decoder() {
        let frame = AArch64UserExceptionFrame {
            vector: AARCH64_EXCEPTION_DATA_ABORT_VECTOR as u64,
            error_code: 0x4d,
            fault_address: 0,
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
            x7: 0,
            x8: 0,
            x9: 0,
            x10: 0,
            x11: 0,
            x12: 0,
            x13: 0,
            x14: 0,
            x15: 0,
            x16: 0,
            x17: 0,
            x18: 0,
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            x29: 0,
            x30: 0,
            instruction_pointer: 0,
            stack_pointer: 0,
            saved_program_status: 0,
        };

        let syndrome = frame
            .abort_syndrome()
            .expect("aarch64 exception frame should decode abort syndrome");
        assert_eq!(syndrome.vector, AARCH64_EXCEPTION_DATA_ABORT_VECTOR);
        assert_eq!(syndrome.iss, 0x4d);
    }

    // ── x86 error code decode tests ──

    #[test]
    fn general_protection_error_decodes_gdt_selector() {
        // error_code = 0x10: selector index 2, GDT, external=0
        let error = X86_64GeneralProtectionError::from_error_code(0x10);
        assert_eq!(error.selector_index, 2);
        assert_eq!(error.table, "GDT");
        assert!(!error.idt);
        assert!(!error.external);
        assert_eq!(error.description(), "gdt-segment-violation");
    }

    #[test]
    fn general_protection_error_decodes_null_selector() {
        let error = X86_64GeneralProtectionError::from_error_code(0);
        assert_eq!(error.selector_index, 0);
        assert_eq!(error.table, "GDT");
        assert_eq!(error.description(), "null-segment-selector");
    }

    #[test]
    fn general_protection_error_decodes_idt_entry() {
        // error_code = 0xa: selector index 1, IDT (bit 1 set), external=0
        let error = X86_64GeneralProtectionError::from_error_code((1 << 1) | (1 << 3));
        assert_eq!(error.selector_index, 1);
        assert_eq!(error.table, "IDT");
        assert!(error.idt);
        assert_eq!(error.description(), "interrupt-gate-violation");
    }

    #[test]
    fn general_protection_error_decodes_ldt_selector() {
        // error_code = 0x1c: selector index 3, TI=1 (LDT), external=0
        let error = X86_64GeneralProtectionError::from_error_code((1 << 2) | (3 << 3));
        assert_eq!(error.selector_index, 3);
        assert_eq!(error.table, "LDT");
        assert!(!error.idt);
        assert_eq!(error.description(), "ldt-segment-violation");
    }

    #[test]
    fn general_protection_error_decodes_external_bit() {
        let error = X86_64GeneralProtectionError::from_error_code(1);
        assert!(error.external);
    }

    #[test]
    fn stack_segment_error_decodes_selector() {
        let error = X86_64StackSegmentError::from_error_code((5 << 3) | 1);
        assert_eq!(error.selector_index, 5);
        assert!(error.external);
        assert_eq!(error.description(), "stack-segment-violation");
    }

    #[test]
    fn stack_segment_error_decodes_null_selector() {
        let error = X86_64StackSegmentError::from_error_code(0);
        assert_eq!(error.selector_index, 0);
        assert_eq!(error.description(), "null-stack-segment");
    }

    #[test]
    fn segment_not_present_error_decodes_selector() {
        let error = X86_64SegmentNotPresentError::from_error_code(1 << 3);
        assert_eq!(error.selector_index, 1);
        assert!(!error.external);
        assert_eq!(error.description(), "segment-not-present");
    }

    #[test]
    fn segment_not_present_error_decodes_null_selector() {
        let error = X86_64SegmentNotPresentError::from_error_code(0);
        assert_eq!(error.selector_index, 0);
        assert_eq!(error.description(), "null-segment-not-present");
    }

    #[test]
    fn invalid_tss_error_decodes_tss_selector() {
        let error = X86_64InvalidTssError::from_error_code((2 << 3) | 1);
        assert_eq!(error.selector_index, 2);
        assert!(error.external);
        assert!(!error.idt);
        assert_eq!(error.description(), "tss-selector-violation");
    }

    #[test]
    fn invalid_tss_error_decodes_null_tss() {
        let error = X86_64InvalidTssError::from_error_code(0);
        assert_eq!(error.selector_index, 0);
        assert_eq!(error.description(), "null-tss-selector");
    }

    #[test]
    fn invalid_tss_error_decodes_task_gate_in_idt() {
        let error = X86_64InvalidTssError::from_error_code(1 << 1);
        assert!(error.idt);
        assert_eq!(error.description(), "task-gate-in-idt");
    }

    #[test]
    fn public_vector_constants_are_stable() {
        assert_eq!(X86_64_EXCEPTION_INVALID_OPCODE_VECTOR, 6);
        assert_eq!(X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR, 13);
        assert_eq!(X86_64_EXCEPTION_PAGE_FAULT_VECTOR, 14);
        assert_eq!(X86_64_EXCEPTION_DOUBLE_FAULT_VECTOR, 8);
        assert_eq!(X86_64_EXCEPTION_INVALID_TSS_VECTOR, 10);
        assert_eq!(X86_64_EXCEPTION_SEGMENT_NOT_PRESENT_VECTOR, 11);
        assert_eq!(X86_64_EXCEPTION_STACK_SEGMENT_VECTOR, 12);
        assert_eq!(X86_64_EXCEPTION_DEVICE_NOT_AVAILABLE_VECTOR, 7);
    }
}
