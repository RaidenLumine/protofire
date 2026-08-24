/* File: src/arch/aarch64/trap.S */

/* Purpose: AArch64 exception vector assembly stubs that capture CPU state for Rust handlers. */

.set TRAP_FRAME_SIZE, 304
.set TRAP_X0_OFFSET, 0
.set TRAP_X2_OFFSET, 16
.set TRAP_X4_OFFSET, 32
.set TRAP_X6_OFFSET, 48
.set TRAP_X8_OFFSET, 64
.set TRAP_X10_OFFSET, 80
.set TRAP_X12_OFFSET, 96
.set TRAP_X14_OFFSET, 112
.set TRAP_X16_OFFSET, 128
.set TRAP_X18_OFFSET, 144
.set TRAP_X20_OFFSET, 160
.set TRAP_X22_OFFSET, 176
.set TRAP_X24_OFFSET, 192
.set TRAP_X26_OFFSET, 208
.set TRAP_X28_OFFSET, 224
.set TRAP_X30_OFFSET, 240
.set TRAP_STACK_POINTER_OFFSET, 248
.set TRAP_ELR_OFFSET, 256
.set TRAP_SPSR_OFFSET, 264
.set TRAP_ESR_OFFSET, 272
.set TRAP_FAR_OFFSET, 280
.set TRAP_VECTOR_OFFSET, 288

.macro VECTOR_SLOT target
    b \target
    .balign 128
.endm

.macro SAVE_AND_DISPATCH vector_id, from_lower_el
    sub sp, sp, #TRAP_FRAME_SIZE
    stp x0, x1, [sp, #TRAP_X0_OFFSET]
    stp x2, x3, [sp, #TRAP_X2_OFFSET]
    stp x4, x5, [sp, #TRAP_X4_OFFSET]
    stp x6, x7, [sp, #TRAP_X6_OFFSET]
    stp x8, x9, [sp, #TRAP_X8_OFFSET]
    stp x10, x11, [sp, #TRAP_X10_OFFSET]
    stp x12, x13, [sp, #TRAP_X12_OFFSET]
    stp x14, x15, [sp, #TRAP_X14_OFFSET]
    stp x16, x17, [sp, #TRAP_X16_OFFSET]
    stp x18, x19, [sp, #TRAP_X18_OFFSET]
    stp x20, x21, [sp, #TRAP_X20_OFFSET]
    stp x22, x23, [sp, #TRAP_X22_OFFSET]
    stp x24, x25, [sp, #TRAP_X24_OFFSET]
    stp x26, x27, [sp, #TRAP_X26_OFFSET]
    stp x28, x29, [sp, #TRAP_X28_OFFSET]
    str x30, [sp, #TRAP_X30_OFFSET]

    .if \from_lower_el
    mrs x9, sp_el0
    .else
    add x9, sp, #TRAP_FRAME_SIZE
    .endif
    str x9, [sp, #TRAP_STACK_POINTER_OFFSET]

    mrs x10, elr_el1
    str x10, [sp, #TRAP_ELR_OFFSET]

    mrs x11, spsr_el1
    str x11, [sp, #TRAP_SPSR_OFFSET]

    mrs x12, esr_el1
    str x12, [sp, #TRAP_ESR_OFFSET]

    mrs x13, far_el1
    str x13, [sp, #TRAP_FAR_OFFSET]

    mov x14, #\vector_id
    str x14, [sp, #TRAP_VECTOR_OFFSET]

    // Zero EL0-accessible thread-ID registers on kernel entry so that no
    // user-controlled value leaks across privilege boundaries.  TLS support
    // will add per-thread save/restore when user space begins to use these
    // registers.
    msr TPIDR_EL0, xzr
    msr TPIDRRO_EL0, xzr

    mov x0, sp
    bl aarch64_trap_dispatch

    ldr x9, [sp, #TRAP_ELR_OFFSET]
    msr elr_el1, x9

    ldr x9, [sp, #TRAP_SPSR_OFFSET]
    msr spsr_el1, x9

    .if \from_lower_el
    ldr x9, [sp, #TRAP_STACK_POINTER_OFFSET]
    msr sp_el0, x9
    .endif

    ldp x0, x1, [sp, #TRAP_X0_OFFSET]
    ldp x2, x3, [sp, #TRAP_X2_OFFSET]
    ldp x4, x5, [sp, #TRAP_X4_OFFSET]
    ldp x6, x7, [sp, #TRAP_X6_OFFSET]
    ldp x8, x9, [sp, #TRAP_X8_OFFSET]
    ldp x10, x11, [sp, #TRAP_X10_OFFSET]
    ldp x12, x13, [sp, #TRAP_X12_OFFSET]
    ldp x14, x15, [sp, #TRAP_X14_OFFSET]
    ldp x16, x17, [sp, #TRAP_X16_OFFSET]
    ldp x18, x19, [sp, #TRAP_X18_OFFSET]
    ldp x20, x21, [sp, #TRAP_X20_OFFSET]
    ldp x22, x23, [sp, #TRAP_X22_OFFSET]
    ldp x24, x25, [sp, #TRAP_X24_OFFSET]
    ldp x26, x27, [sp, #TRAP_X26_OFFSET]
    ldp x28, x29, [sp, #TRAP_X28_OFFSET]
    ldr x30, [sp, #TRAP_X30_OFFSET]
    add sp, sp, #TRAP_FRAME_SIZE
    eret
.endm

.section .text, "ax"

.align 11
.global __aarch64_exception_vectors
__aarch64_exception_vectors:
    VECTOR_SLOT vector_current_el_sp0_sync
    VECTOR_SLOT vector_current_el_sp0_irq
    VECTOR_SLOT vector_current_el_sp0_fiq
    VECTOR_SLOT vector_current_el_sp0_serror
    VECTOR_SLOT vector_current_el_spx_sync
    VECTOR_SLOT vector_current_el_spx_irq
    VECTOR_SLOT vector_current_el_spx_fiq
    VECTOR_SLOT vector_current_el_spx_serror
    VECTOR_SLOT vector_lower_el_aarch64_sync
    VECTOR_SLOT vector_lower_el_aarch64_irq
    VECTOR_SLOT vector_lower_el_aarch64_fiq
    VECTOR_SLOT vector_lower_el_aarch64_serror
    VECTOR_SLOT vector_lower_el_aarch32_sync
    VECTOR_SLOT vector_lower_el_aarch32_irq
    VECTOR_SLOT vector_lower_el_aarch32_fiq
    VECTOR_SLOT vector_lower_el_aarch32_serror

vector_current_el_sp0_sync:
    SAVE_AND_DISPATCH 0, 0

vector_current_el_sp0_irq:
    SAVE_AND_DISPATCH 1, 0

vector_current_el_sp0_fiq:
    SAVE_AND_DISPATCH 2, 0

vector_current_el_sp0_serror:
    SAVE_AND_DISPATCH 3, 0

vector_current_el_spx_sync:
    SAVE_AND_DISPATCH 4, 0

vector_current_el_spx_irq:
    SAVE_AND_DISPATCH 5, 0

vector_current_el_spx_fiq:
    SAVE_AND_DISPATCH 6, 0

vector_current_el_spx_serror:
    SAVE_AND_DISPATCH 7, 0

vector_lower_el_aarch64_sync:
    SAVE_AND_DISPATCH 8, 1

vector_lower_el_aarch64_irq:
    SAVE_AND_DISPATCH 9, 1

vector_lower_el_aarch64_fiq:
    SAVE_AND_DISPATCH 10, 1

vector_lower_el_aarch64_serror:
    SAVE_AND_DISPATCH 11, 1

vector_lower_el_aarch32_sync:
    SAVE_AND_DISPATCH 12, 1

vector_lower_el_aarch32_irq:
    SAVE_AND_DISPATCH 13, 1

vector_lower_el_aarch32_fiq:
    SAVE_AND_DISPATCH 14, 1

vector_lower_el_aarch32_serror:
    SAVE_AND_DISPATCH 15, 1
