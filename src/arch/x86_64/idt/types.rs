//! src/arch/x86_64/idt/types.rs
//!
//! x86_64 IDT types, constants, and assembly stubs.

use crate::util::sync_unsafe_cell::SyncUnsafeCell;

use crate::abi::syscall as syscall_abi;
use crate::arch::x86_64::gdt;

pub(super) const IDT_ENTRIES: usize = 256;
pub(super) const INTERRUPT_GATE: u8 = 0x8E;
pub(super) const USER_INTERRUPT_GATE: u8 = 0xEE;
pub(super) const SYSCALL_VECTOR: u8 = syscall_abi::X86_64_INTERRUPT_VECTOR;

/// IPI vector: reschedule (wake up another CPU's scheduler).
pub const IPI_RESCHEDULE_VECTOR: u8 = 0x30; // 48
/// IPI vector: TLB shootdown (invalidate a virtual address mapping).
pub const IPI_SHOOTDOWN_VECTOR: u8 = 0x31; // 49

core::arch::global_asm!(
    r#"
.section .text

.macro PUSH_REGS
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
.endm

.macro POP_REGS
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
.endm

.macro ISR_NOERR num
.global interrupt_stub_\num
interrupt_stub_\num:
    push 0
    push \num
    jmp interrupt_common
.endm

.macro ISR_ERR num
.global interrupt_stub_\num
interrupt_stub_\num:
    push \num
    jmp interrupt_common
.endm

.global interrupt_stub_default
interrupt_stub_default:
    push 0
    push 255
    jmp interrupt_common

interrupt_common:
    cld
    // Reserve saved user rsp/ss slots first, then snapshot the general-purpose
    // registers. This keeps user rax/rdx intact instead of clobbering them
    // while we inspect the privilege-change frame.
    push 0
    push 0
    PUSH_REGS
    mov rax, [rsp + 160]
    and eax, 3
    jz .Lframe_ready
    mov rax, [rsp + 176]
    mov [rsp + 120], rax
    mov rax, [rsp + 184]
    mov [rsp + 128], rax
.Lframe_ready:
    mov rdi, rsp
    call interrupt_dispatch
    POP_REGS
    add rsp, 32
    iretq

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29
ISR_ERR   30
ISR_NOERR 31
ISR_NOERR 32
ISR_NOERR 33
ISR_NOERR 34
ISR_NOERR 35
ISR_NOERR 36
ISR_NOERR 37
ISR_NOERR 38
ISR_NOERR 39
ISR_NOERR 40
ISR_NOERR 41
ISR_NOERR 42
ISR_NOERR 43
ISR_NOERR 44
ISR_NOERR 45
ISR_NOERR 46
ISR_NOERR 47
ISR_NOERR 48
ISR_NOERR 49
ISR_NOERR 128
"#
);

type InterruptHandler = unsafe extern "C" fn();

unsafe extern "C" {
    fn interrupt_stub_0();
    fn interrupt_stub_1();
    fn interrupt_stub_2();
    fn interrupt_stub_3();
    fn interrupt_stub_4();
    fn interrupt_stub_5();
    fn interrupt_stub_6();
    fn interrupt_stub_7();
    fn interrupt_stub_8();
    fn interrupt_stub_9();
    fn interrupt_stub_10();
    fn interrupt_stub_11();
    fn interrupt_stub_12();
    fn interrupt_stub_13();
    fn interrupt_stub_14();
    fn interrupt_stub_15();
    fn interrupt_stub_16();
    fn interrupt_stub_17();
    fn interrupt_stub_18();
    fn interrupt_stub_19();
    fn interrupt_stub_20();
    fn interrupt_stub_21();
    fn interrupt_stub_22();
    fn interrupt_stub_23();
    fn interrupt_stub_24();
    fn interrupt_stub_25();
    fn interrupt_stub_26();
    fn interrupt_stub_27();
    fn interrupt_stub_28();
    fn interrupt_stub_29();
    fn interrupt_stub_30();
    fn interrupt_stub_31();
    fn interrupt_stub_32();
    fn interrupt_stub_33();
    fn interrupt_stub_34();
    fn interrupt_stub_35();
    fn interrupt_stub_36();
    fn interrupt_stub_37();
    fn interrupt_stub_38();
    fn interrupt_stub_39();
    fn interrupt_stub_40();
    fn interrupt_stub_41();
    fn interrupt_stub_42();
    fn interrupt_stub_43();
    fn interrupt_stub_44();
    fn interrupt_stub_45();
    fn interrupt_stub_46();
    fn interrupt_stub_47();
    fn interrupt_stub_48();
    fn interrupt_stub_49();
    pub(super) fn interrupt_stub_128();
    pub(super) fn interrupt_stub_default();
}

pub(crate) const EARLY_HANDLERS: [InterruptHandler; 50] = [
    interrupt_stub_0,
    interrupt_stub_1,
    interrupt_stub_2,
    interrupt_stub_3,
    interrupt_stub_4,
    interrupt_stub_5,
    interrupt_stub_6,
    interrupt_stub_7,
    interrupt_stub_8,
    interrupt_stub_9,
    interrupt_stub_10,
    interrupt_stub_11,
    interrupt_stub_12,
    interrupt_stub_13,
    interrupt_stub_14,
    interrupt_stub_15,
    interrupt_stub_16,
    interrupt_stub_17,
    interrupt_stub_18,
    interrupt_stub_19,
    interrupt_stub_20,
    interrupt_stub_21,
    interrupt_stub_22,
    interrupt_stub_23,
    interrupt_stub_24,
    interrupt_stub_25,
    interrupt_stub_26,
    interrupt_stub_27,
    interrupt_stub_28,
    interrupt_stub_29,
    interrupt_stub_30,
    interrupt_stub_31,
    interrupt_stub_32,
    interrupt_stub_33,
    interrupt_stub_34,
    interrupt_stub_35,
    interrupt_stub_36,
    interrupt_stub_37,
    interrupt_stub_38,
    interrupt_stub_39,
    interrupt_stub_40,
    interrupt_stub_41,
    interrupt_stub_42,
    interrupt_stub_43,
    interrupt_stub_44,
    interrupt_stub_45,
    interrupt_stub_46,
    interrupt_stub_47,
    interrupt_stub_48,
    interrupt_stub_49,
];

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct DescriptorTablePointer {
    pub(crate) limit: u16,
    pub(crate) base: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct InterruptGate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl InterruptGate {
    pub(super) const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            attributes: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    pub(super) fn new(handler: InterruptHandler) -> Self {
        Self::new_with_attributes(handler, INTERRUPT_GATE)
    }

    pub(super) fn new_with_attributes(handler: InterruptHandler, attributes: u8) -> Self {
        let address = handler as usize as u64;

        Self {
            offset_low: address as u16,
            selector: gdt::kernel_code_selector(),
            ist: 0,
            attributes,
            offset_mid: (address >> 16) as u16,
            offset_high: (address >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C)]
pub struct InterruptContext {
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
    pub saved_stack_pointer: u64,
    pub saved_stack_segment: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
}

impl InterruptContext {
    pub(crate) fn entered_from_user_mode(&self) -> bool {
        self.cs & 0x3 != 0
    }
}

pub(crate) struct InterruptDescriptorTable {
    pub(crate) gates: [InterruptGate; IDT_ENTRIES],
}

impl InterruptDescriptorTable {
    pub(crate) const fn new() -> Self {
        Self {
            gates: [InterruptGate::missing(); IDT_ENTRIES],
        }
    }
}

pub(crate) static IDT: SyncUnsafeCell<InterruptDescriptorTable> =
    SyncUnsafeCell::new(InterruptDescriptorTable::new());
