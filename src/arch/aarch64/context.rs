//! src/arch/aarch64/context.rs
//!
//! AArch64 context switch and user-mode entry helpers.

use core::arch::asm;
use core::mem::offset_of;

use crate::kernel::process::thread::AArch64UserThreadContext;
use crate::kernel::process::Context;

core::arch::global_asm!(
    r#"
.section .text
.global aarch64_context_switch
aarch64_context_switch:
    stp x19, x20, [x0, #24]
    stp x21, x22, [x0, #40]
    stp x23, x24, [x0, #56]
    stp x25, x26, [x0, #72]
    stp x27, x28, [x0, #88]
    stp x29, x30, [x0, #104]
    mov x9, sp
    str x9, [x0, #8]
    mrs x9, DAIF
    str x9, [x0, #16]
    adr x9, .Lresume
    str x9, [x0, #0]
    stp q8, q9, [x0, #160]
    stp q10, q11, [x0, #192]
    stp q12, q13, [x0, #224]
    stp q14, q15, [x0, #256]

    ldr x9, [x1, #0]
    ldr x10, [x1, #8]
    ldp x19, x20, [x1, #24]
    ldp x21, x22, [x1, #40]
    ldp x23, x24, [x1, #56]
    ldp x25, x26, [x1, #72]
    ldp x27, x28, [x1, #88]
    ldp x29, x30, [x1, #104]
    ldp q8, q9, [x1, #160]
    ldp q10, q11, [x1, #192]
    ldp q12, q13, [x1, #224]
    ldp q14, q15, [x1, #256]
    mov sp, x10
    br x9

.Lresume:
    ret
"#
);

unsafe extern "C" {
    fn aarch64_context_switch(current: *mut Context, next: *const Context);
}

/// Switch execution context from `current` to `next`.
///
/// # Safety
///
/// Both `current` and `next` must point to valid [`Context`] structures.
/// `current` receives the saved register state of the outgoing thread;
/// `next` must contain the saved state of the thread to resume.
/// Interrupts must be disabled before calling this function.
pub unsafe fn switch(current: *mut Context, next: *const Context) {
    unsafe {
        aarch64_context_switch(current, next);
    }
}

/// Enter EL0 (user mode) with the given thread context and never return.
///
/// # Safety
///
/// `context` must contain valid register values for user-mode execution,
/// including a legal ELR_EL1 (user PC) and SPSR_EL1 (user PSTATE).
/// The kernel stack must be correctly set up before calling this function
/// as it irreversibly transfers control to EL0.
pub unsafe fn enter_user_mode_with_context(context: &AArch64UserThreadContext) -> ! {
    unsafe {
        asm!(
            "mov x15, x0",
            "ldr x10, [x15, #{stack_pointer_offset}]",
            "msr SP_EL0, x10",
            "ldr x10, [x15, #{instruction_pointer_offset}]",
            "msr ELR_EL1, x10",
            "ldr x10, [x15, #{saved_program_status_offset}]",
            "msr SPSR_EL1, x10",
            "ldr x30, [x15, #{x30_offset}]",
            "ldr x29, [x15, #{x29_offset}]",
            "ldr x28, [x15, #{x28_offset}]",
            "ldr x27, [x15, #{x27_offset}]",
            "ldr x26, [x15, #{x26_offset}]",
            "ldr x25, [x15, #{x25_offset}]",
            "ldr x24, [x15, #{x24_offset}]",
            "ldr x23, [x15, #{x23_offset}]",
            "ldr x22, [x15, #{x22_offset}]",
            "ldr x21, [x15, #{x21_offset}]",
            "ldr x20, [x15, #{x20_offset}]",
            "ldr x19, [x15, #{x19_offset}]",
            "ldr x18, [x15, #{x18_offset}]",
            "ldr x17, [x15, #{x17_offset}]",
            "ldr x16, [x15, #{x16_offset}]",
            "ldr x14, [x15, #{x14_offset}]",
            "ldr x13, [x15, #{x13_offset}]",
            "ldr x12, [x15, #{x12_offset}]",
            "ldr x11, [x15, #{x11_offset}]",
            "ldr x10, [x15, #{x10_offset}]",
            "ldr x9, [x15, #{x9_offset}]",
            "ldr x8, [x15, #{x8_offset}]",
            "ldr x7, [x15, #{x7_offset}]",
            "ldr x6, [x15, #{x6_offset}]",
            "ldr x5, [x15, #{x5_offset}]",
            "ldr x4, [x15, #{x4_offset}]",
            "ldr x3, [x15, #{x3_offset}]",
            "ldr x2, [x15, #{x2_offset}]",
            "ldr x1, [x15, #{x1_offset}]",
            "ldr x0, [x15, #{x0_offset}]",
            "ldr x15, [x15, #{x15_offset}]",
            "eret",
            in("x0") context,
            x0_offset = const offset_of!(AArch64UserThreadContext, x0),
            x1_offset = const offset_of!(AArch64UserThreadContext, x1),
            x2_offset = const offset_of!(AArch64UserThreadContext, x2),
            x3_offset = const offset_of!(AArch64UserThreadContext, x3),
            x4_offset = const offset_of!(AArch64UserThreadContext, x4),
            x5_offset = const offset_of!(AArch64UserThreadContext, x5),
            x6_offset = const offset_of!(AArch64UserThreadContext, x6),
            x7_offset = const offset_of!(AArch64UserThreadContext, x7),
            x8_offset = const offset_of!(AArch64UserThreadContext, x8),
            x9_offset = const offset_of!(AArch64UserThreadContext, x9),
            x10_offset = const offset_of!(AArch64UserThreadContext, x10),
            x11_offset = const offset_of!(AArch64UserThreadContext, x11),
            x12_offset = const offset_of!(AArch64UserThreadContext, x12),
            x13_offset = const offset_of!(AArch64UserThreadContext, x13),
            x14_offset = const offset_of!(AArch64UserThreadContext, x14),
            x15_offset = const offset_of!(AArch64UserThreadContext, x15),
            x16_offset = const offset_of!(AArch64UserThreadContext, x16),
            x17_offset = const offset_of!(AArch64UserThreadContext, x17),
            x18_offset = const offset_of!(AArch64UserThreadContext, x18),
            x19_offset = const offset_of!(AArch64UserThreadContext, x19),
            x20_offset = const offset_of!(AArch64UserThreadContext, x20),
            x21_offset = const offset_of!(AArch64UserThreadContext, x21),
            x22_offset = const offset_of!(AArch64UserThreadContext, x22),
            x23_offset = const offset_of!(AArch64UserThreadContext, x23),
            x24_offset = const offset_of!(AArch64UserThreadContext, x24),
            x25_offset = const offset_of!(AArch64UserThreadContext, x25),
            x26_offset = const offset_of!(AArch64UserThreadContext, x26),
            x27_offset = const offset_of!(AArch64UserThreadContext, x27),
            x28_offset = const offset_of!(AArch64UserThreadContext, x28),
            x29_offset = const offset_of!(AArch64UserThreadContext, x29),
            x30_offset = const offset_of!(AArch64UserThreadContext, x30),
            instruction_pointer_offset = const offset_of!(AArch64UserThreadContext, instruction_pointer),
            stack_pointer_offset = const offset_of!(AArch64UserThreadContext, stack_pointer),
            saved_program_status_offset = const offset_of!(AArch64UserThreadContext, saved_program_status),
            options(noreturn)
        );
    }
}
