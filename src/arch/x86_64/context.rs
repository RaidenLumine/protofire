//! src/arch/x86_64/context.rs
//!
//! x86_64 context switch and user-mode entry helpers.

use core::arch::asm;
use core::mem::offset_of;

use crate::kernel::process::thread::X86_64UserThreadContext;
use crate::kernel::process::Context;

core::arch::global_asm!(
    r#"
.section .text
.global x86_64_context_switch
x86_64_context_switch:
    mov [rdi + 24], rbx
    mov [rdi + 32], rbp
    mov [rdi + 40], r12
    mov [rdi + 48], r13
    mov [rdi + 56], r14
    mov [rdi + 64], r15
    mov [rdi + 8], rsp
    pushfq
    pop qword ptr [rdi + 16]
    lea rax, [rip + .Lresume]
    mov [rdi + 0], rax

    // Save XMM0-XMM15 so user-mode SIMD state is preserved across
    // context switches.  Context simd_registers starts at offset 160
    // and each XMM slot is 16 bytes.
    movdqu [rdi + 160], xmm0
    movdqu [rdi + 176], xmm1
    movdqu [rdi + 192], xmm2
    movdqu [rdi + 208], xmm3
    movdqu [rdi + 224], xmm4
    movdqu [rdi + 240], xmm5
    movdqu [rdi + 256], xmm6
    movdqu [rdi + 272], xmm7
    movdqu [rdi + 288], xmm8
    movdqu [rdi + 304], xmm9
    movdqu [rdi + 320], xmm10
    movdqu [rdi + 336], xmm11
    movdqu [rdi + 352], xmm12
    movdqu [rdi + 368], xmm13
    movdqu [rdi + 384], xmm14
    movdqu [rdi + 400], xmm15

    mov rbx, [rsi + 24]
    mov rbp, [rsi + 32]
    mov r12, [rsi + 40]
    mov r13, [rsi + 48]
    mov r14, [rsi + 56]
    mov r15, [rsi + 64]
    mov rsp, [rsi + 8]
    push qword ptr [rsi + 16]
    popfq

    // Restore XMM0-XMM15 from the incoming context.
    movdqu xmm0, [rsi + 160]
    movdqu xmm1, [rsi + 176]
    movdqu xmm2, [rsi + 192]
    movdqu xmm3, [rsi + 208]
    movdqu xmm4, [rsi + 224]
    movdqu xmm5, [rsi + 240]
    movdqu xmm6, [rsi + 256]
    movdqu xmm7, [rsi + 272]
    movdqu xmm8, [rsi + 288]
    movdqu xmm9, [rsi + 304]
    movdqu xmm10, [rsi + 320]
    movdqu xmm11, [rsi + 336]
    movdqu xmm12, [rsi + 352]
    movdqu xmm13, [rsi + 368]
    movdqu xmm14, [rsi + 384]
    movdqu xmm15, [rsi + 400]

    jmp qword ptr [rsi + 0]

.Lresume:
    ret
"#
);

unsafe extern "C" {
    fn x86_64_context_switch(current: *mut Context, next: *const Context);
}

/// Switch the CPU from the `current` context to the `next` context.
///
/// # Safety
///
/// Both pointers must point to valid, properly initialised [`Context`] objects.
/// `current` must be the currently running context and `next` must be a context
/// that is ready to resume (its stack and instruction pointer must be valid).
pub unsafe fn switch(current: *mut Context, next: *const Context) {
    x86_64_context_switch(current, next);
}

/// Enter ring-3 (user mode) with the given thread context and never return
/// to the caller.
///
/// # Safety
///
/// `context` must contain valid segment selectors (user-mode data and code
/// segments), a valid user-mode stack pointer, and a valid user-mode
/// instruction pointer.  The kernel stack used before this call is discarded.
pub unsafe fn enter_user_mode_with_context(context: &X86_64UserThreadContext) -> ! {
    asm!(
        // Load user-mode data segment selectors (DS, ES, FS).
        // GS is intentionally left with the kernel selector so that
        // per-CPU access via gs: segment works after the next interrupt
        // without swapgs MSR state-machine complications.  User programs
        // on this kernel do not yet use GS for thread-local storage.
        "mov ax, word ptr [rdi + {stack_segment_offset}]",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "push qword ptr [rdi + {stack_segment_offset}]",
        "push qword ptr [rdi + {stack_pointer_offset}]",
        "push qword ptr [rdi + {rflags_offset}]",
        "push qword ptr [rdi + {code_segment_offset}]",
        "push qword ptr [rdi + {instruction_pointer_offset}]",
        "mov r15, qword ptr [rdi + {r15_offset}]",
        "mov r14, qword ptr [rdi + {r14_offset}]",
        "mov r13, qword ptr [rdi + {r13_offset}]",
        "mov r12, qword ptr [rdi + {r12_offset}]",
        "mov r11, qword ptr [rdi + {r11_offset}]",
        "mov r10, qword ptr [rdi + {r10_offset}]",
        "mov r9, qword ptr [rdi + {r9_offset}]",
        "mov r8, qword ptr [rdi + {r8_offset}]",
        "mov rbp, qword ptr [rdi + {rbp_offset}]",
        "mov rbx, qword ptr [rdi + {rbx_offset}]",
        "mov rax, qword ptr [rdi + {rax_offset}]",
        "mov rcx, qword ptr [rdi + {rcx_offset}]",
        "mov rdx, qword ptr [rdi + {rdx_offset}]",
        "mov rsi, qword ptr [rdi + {rsi_offset}]",
        "mov rdi, qword ptr [rdi + {rdi_offset}]",
        "iretq",
        in("rdi") context,
        rax_offset = const offset_of!(X86_64UserThreadContext, rax),
        rbx_offset = const offset_of!(X86_64UserThreadContext, rbx),
        rcx_offset = const offset_of!(X86_64UserThreadContext, rcx),
        rdx_offset = const offset_of!(X86_64UserThreadContext, rdx),
        rsi_offset = const offset_of!(X86_64UserThreadContext, rsi),
        rdi_offset = const offset_of!(X86_64UserThreadContext, rdi),
        rbp_offset = const offset_of!(X86_64UserThreadContext, rbp),
        r8_offset = const offset_of!(X86_64UserThreadContext, r8),
        r9_offset = const offset_of!(X86_64UserThreadContext, r9),
        r10_offset = const offset_of!(X86_64UserThreadContext, r10),
        r11_offset = const offset_of!(X86_64UserThreadContext, r11),
        r12_offset = const offset_of!(X86_64UserThreadContext, r12),
        r13_offset = const offset_of!(X86_64UserThreadContext, r13),
        r14_offset = const offset_of!(X86_64UserThreadContext, r14),
        r15_offset = const offset_of!(X86_64UserThreadContext, r15),
        instruction_pointer_offset = const offset_of!(X86_64UserThreadContext, instruction_pointer),
        code_segment_offset = const offset_of!(X86_64UserThreadContext, code_segment),
        rflags_offset = const offset_of!(X86_64UserThreadContext, rflags),
        stack_pointer_offset = const offset_of!(X86_64UserThreadContext, stack_pointer),
        stack_segment_offset = const offset_of!(X86_64UserThreadContext, stack_segment),
        options(noreturn)
    );
}
