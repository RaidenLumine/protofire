//! src/arch/riscv64/context.rs
//!
//! RISC-V 64 context switch and user-mode entry helpers.

use core::arch::asm;
use core::mem::offset_of;

use crate::kernel::process::thread::RiscV64UserThreadContext;
use crate::kernel::process::Context;

// ── Context switch assembly ──
//
// The Context struct layout:
//   offset 0:   instruction_pointer (usize)
//   offset 8:   stack_pointer (usize)
//   offset 16:  flags (u64)
//   offset 24+: callee_saved [usize; N]
//
// RISC-V callee-saved: s0-s11 (x8-x9, x18-x27), ra (x1), sp (x2)

core::arch::global_asm!(
    r#"
.section .text
.global riscv64_context_switch
riscv64_context_switch:
    /* a0 = *mut current Context, a1 = *const next Context */

    sd ra, 0(a0)
    sd sp, 8(a0)
    sd s0, 24(a0)
    sd s1, 32(a0)
    sd s2, 40(a0)
    sd s3, 48(a0)
    sd s4, 56(a0)
    sd s5, 64(a0)
    sd s6, 72(a0)
    sd s7, 80(a0)
    sd s8, 88(a0)
    sd s9, 96(a0)
    sd s10, 104(a0)
    sd s11, 112(a0)

    ld s0, 24(a1)
    ld s1, 32(a1)
    ld s2, 40(a1)
    ld s3, 48(a1)
    ld s4, 56(a1)
    ld s5, 64(a1)
    ld s6, 72(a1)
    ld s7, 80(a1)
    ld s8, 88(a1)
    ld s9, 96(a1)
    ld s10, 104(a1)
    ld s11, 112(a1)
    ld sp, 8(a1)
    ld ra, 0(a1)
    ret
"#
);

unsafe extern "C" {
    fn riscv64_context_switch(current: *mut Context, next: *const Context);
}

/// Switch execution context from `current` to `next`.
///
/// # Safety
///
/// Both `current` and `next` must point to valid [`Context`] structures.
/// Interrupts must be disabled before calling this function.
pub unsafe fn switch(current: *mut Context, next: *const Context) {
    unsafe {
        riscv64_context_switch(current, next);
    }
}

/// Enter user mode (U-mode) with the given thread context via `sret`.
///
/// # Safety
///
/// The caller must ensure the context represents a valid user-mode
/// execution state.  This function does not return.
pub unsafe fn enter_user_mode_with_context(context: &RiscV64UserThreadContext) -> ! {
    unsafe {
        asm!(
            // Save current kernel sp to sscratch so that the trap entry
            // sequence (csrrw sp, sscratch, sp) can swap back to it.
            "csrw sscratch, sp",

            // Load user general-purpose registers.  a0 (x10) is loaded LAST:
            // a0 currently holds the kernel context pointer used as the base
            // for every `ld` below, so overwriting it mid-sequence would make
            // the subsequent loads dereference the *user's* a0 (e.g. argc),
            // faulting at user_a0 + offset.  Register numbers are embedded in
            // the instruction names.
            "ld x1,  {x1_offset}(a0)",
            "ld x2,  {x2_offset}(a0)",
            "ld x3,  {x3_offset}(a0)",
            "ld x4,  {x4_offset}(a0)",
            "ld x5,  {x5_offset}(a0)",
            "ld x6,  {x6_offset}(a0)",
            "ld x7,  {x7_offset}(a0)",
            "ld x8,  {x8_offset}(a0)",
            "ld x9,  {x9_offset}(a0)",
            "ld x11, {x11_offset}(a0)",
            "ld x12, {x12_offset}(a0)",
            "ld x13, {x13_offset}(a0)",
            "ld x14, {x14_offset}(a0)",
            "ld x15, {x15_offset}(a0)",
            "ld x16, {x16_offset}(a0)",
            "ld x17, {x17_offset}(a0)",
            "ld x18, {x18_offset}(a0)",
            "ld x19, {x19_offset}(a0)",
            "ld x20, {x20_offset}(a0)",
            "ld x21, {x21_offset}(a0)",
            "ld x22, {x22_offset}(a0)",
            "ld x23, {x23_offset}(a0)",
            "ld x24, {x24_offset}(a0)",
            "ld x25, {x25_offset}(a0)",
            "ld x26, {x26_offset}(a0)",
            "ld x27, {x27_offset}(a0)",
            "ld x28, {x28_offset}(a0)",
            "ld x29, {x29_offset}(a0)",
            "ld x30, {x30_offset}(a0)",
            "ld x31, {x31_offset}(a0)",

            // Set up sepc (instruction pointer) and sstatus for sret.
            "ld t0, {instruction_pointer_offset}(a0)",
            "csrw sepc, t0",
            "ld t0, {saved_program_status_offset}(a0)",
            "csrw sstatus, t0",

            // Load the user's a0 (x10) last, just before entering user mode.
            "ld x10, {x10_offset}(a0)",

            "sret",

            in("a0") context,
            x1_offset = const offset_of!(RiscV64UserThreadContext, x1),
            x2_offset = const offset_of!(RiscV64UserThreadContext, x2),
            x3_offset = const offset_of!(RiscV64UserThreadContext, x3),
            x4_offset = const offset_of!(RiscV64UserThreadContext, x4),
            x5_offset = const offset_of!(RiscV64UserThreadContext, x5),
            x6_offset = const offset_of!(RiscV64UserThreadContext, x6),
            x7_offset = const offset_of!(RiscV64UserThreadContext, x7),
            x8_offset = const offset_of!(RiscV64UserThreadContext, x8),
            x9_offset = const offset_of!(RiscV64UserThreadContext, x9),
            x10_offset = const offset_of!(RiscV64UserThreadContext, x10),
            x11_offset = const offset_of!(RiscV64UserThreadContext, x11),
            x12_offset = const offset_of!(RiscV64UserThreadContext, x12),
            x13_offset = const offset_of!(RiscV64UserThreadContext, x13),
            x14_offset = const offset_of!(RiscV64UserThreadContext, x14),
            x15_offset = const offset_of!(RiscV64UserThreadContext, x15),
            x16_offset = const offset_of!(RiscV64UserThreadContext, x16),
            x17_offset = const offset_of!(RiscV64UserThreadContext, x17),
            x18_offset = const offset_of!(RiscV64UserThreadContext, x18),
            x19_offset = const offset_of!(RiscV64UserThreadContext, x19),
            x20_offset = const offset_of!(RiscV64UserThreadContext, x20),
            x21_offset = const offset_of!(RiscV64UserThreadContext, x21),
            x22_offset = const offset_of!(RiscV64UserThreadContext, x22),
            x23_offset = const offset_of!(RiscV64UserThreadContext, x23),
            x24_offset = const offset_of!(RiscV64UserThreadContext, x24),
            x25_offset = const offset_of!(RiscV64UserThreadContext, x25),
            x26_offset = const offset_of!(RiscV64UserThreadContext, x26),
            x27_offset = const offset_of!(RiscV64UserThreadContext, x27),
            x28_offset = const offset_of!(RiscV64UserThreadContext, x28),
            x29_offset = const offset_of!(RiscV64UserThreadContext, x29),
            x30_offset = const offset_of!(RiscV64UserThreadContext, x30),
            x31_offset = const offset_of!(RiscV64UserThreadContext, x31),
            instruction_pointer_offset = const offset_of!(RiscV64UserThreadContext, instruction_pointer),
            saved_program_status_offset = const offset_of!(RiscV64UserThreadContext, saved_program_status),
            options(noreturn)
        );
    }
}
