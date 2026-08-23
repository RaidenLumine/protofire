/* File: src/arch/riscv64/trap.S */
/* Purpose: RISC-V 64-bit trap entry assembly stubs that capture CPU state
   for Rust handlers.  Uses the standard S-mode trap frame layout. */

/* ── Trap frame offsets (must match TrapFrame in trap.rs) ── */
.set TRAP_FRAME_SIZE,       320

.set TRAP_RA_OFFSET,          0
.set TRAP_GP_OFFSET,          8
.set TRAP_TP_OFFSET,         16
.set TRAP_T0_OFFSET,         24
.set TRAP_T1_OFFSET,         32
.set TRAP_T2_OFFSET,         40
.set TRAP_S0_OFFSET,         48
.set TRAP_S1_OFFSET,         56
.set TRAP_A0_OFFSET,         64
.set TRAP_A1_OFFSET,         72
.set TRAP_A2_OFFSET,         80
.set TRAP_A3_OFFSET,         88
.set TRAP_A4_OFFSET,         96
.set TRAP_A5_OFFSET,        104
.set TRAP_A6_OFFSET,        112
.set TRAP_A7_OFFSET,        120
.set TRAP_S2_OFFSET,        128
.set TRAP_S3_OFFSET,        136
.set TRAP_S4_OFFSET,        144
.set TRAP_S5_OFFSET,        152
.set TRAP_S6_OFFSET,        160
.set TRAP_S7_OFFSET,        168
.set TRAP_S8_OFFSET,        176
.set TRAP_S9_OFFSET,        184
.set TRAP_S10_OFFSET,       192
.set TRAP_S11_OFFSET,       200
.set TRAP_T3_OFFSET,        208
.set TRAP_T4_OFFSET,        216
.set TRAP_T5_OFFSET,        224
.set TRAP_T6_OFFSET,        232
.set TRAP_SP_OFFSET,        240  /* user stack pointer (sp) */
.set TRAP_SEPC_OFFSET,      248
.set TRAP_SCAUSE_OFFSET,    256
.set TRAP_STVAL_OFFSET,     264
.set TRAP_SSTATUS_OFFSET,   272
.set TRAP_KERNEL_SP_OFFSET, 280  /* saved kernel sp */
.set TRAP_VECTOR_OFFSET,    288

/* ── Macros ── */
.macro SAVE_ALL
    /* Swap sp and sscratch.
       - If coming from U-mode: sscratch = kernel sp → sp gets kernel sp.
       - If coming from S-mode: sscratch = 0 → sp gets 0. */
    csrrw sp, sscratch, sp

    /* Branch: if sp != 0 we came from user mode and already have the
       kernel stack.  If sp == 0 we came from kernel mode and must
       recover the original sp from sscratch. */
    bnez sp, .Lsave_user_\@

    /* Kernel-to-kernel trap: sscratch holds the original kernel sp. */
    csrr sp, sscratch
    j .Lsave_common_\@

.Lsave_user_\@:
    /* User-to-kernel trap: sp already points to the kernel stack;
       sscratch holds the user sp.  Fall through. */

.Lsave_common_\@:
    /* Allocate trap frame space on kernel stack. */
    addi sp, sp, -TRAP_FRAME_SIZE

    /* Save all general-purpose registers. */
    sd ra,  TRAP_RA_OFFSET(sp)
    sd gp,  TRAP_GP_OFFSET(sp)
    sd tp,  TRAP_TP_OFFSET(sp)
    sd t0,  TRAP_T0_OFFSET(sp)
    sd t1,  TRAP_T1_OFFSET(sp)
    sd t2,  TRAP_T2_OFFSET(sp)
    sd s0,  TRAP_S0_OFFSET(sp)
    sd s1,  TRAP_S1_OFFSET(sp)
    sd a0,  TRAP_A0_OFFSET(sp)
    sd a1,  TRAP_A1_OFFSET(sp)
    sd a2,  TRAP_A2_OFFSET(sp)
    sd a3,  TRAP_A3_OFFSET(sp)
    sd a4,  TRAP_A4_OFFSET(sp)
    sd a5,  TRAP_A5_OFFSET(sp)
    sd a6,  TRAP_A6_OFFSET(sp)
    sd a7,  TRAP_A7_OFFSET(sp)
    sd s2,  TRAP_S2_OFFSET(sp)
    sd s3,  TRAP_S3_OFFSET(sp)
    sd s4,  TRAP_S4_OFFSET(sp)
    sd s5,  TRAP_S5_OFFSET(sp)
    sd s6,  TRAP_S6_OFFSET(sp)
    sd s7,  TRAP_S7_OFFSET(sp)
    sd s8,  TRAP_S8_OFFSET(sp)
    sd s9,  TRAP_S9_OFFSET(sp)
    sd s10, TRAP_S10_OFFSET(sp)
    sd s11, TRAP_S11_OFFSET(sp)
    sd t3,  TRAP_T3_OFFSET(sp)
    sd t4,  TRAP_T4_OFFSET(sp)
    sd t5,  TRAP_T5_OFFSET(sp)
    sd t6,  TRAP_T6_OFFSET(sp)

    /* Retrieve the original sp (user or kernel) from sscratch. */
    csrr t0, sscratch
    sd t0, TRAP_SP_OFFSET(sp)

    /* Restore sscratch to zero (indicates we're on the kernel stack). */
    csrw sscratch, zero

    /* Save exception registers. */
    csrr t0, sepc
    sd t0, TRAP_SEPC_OFFSET(sp)
    csrr t0, scause
    sd t0, TRAP_SCAUSE_OFFSET(sp)
    csrr t0, stval
    sd t0, TRAP_STVAL_OFFSET(sp)
    csrr t0, sstatus
    sd t0, TRAP_SSTATUS_OFFSET(sp)

    /* Save kernel sp (before frame allocation) for unwinding. */
    addi t0, sp, TRAP_FRAME_SIZE
    sd t0, TRAP_KERNEL_SP_OFFSET(sp)

    # Compute vector index (same as aarch64 convention):
    # scause top bit = interrupt, low bits = exception code.
    csrr t0, scause
    srli t1, t0, 63      # t1 = interrupt bit
    andi t0, t0, 0x7f    # t0 = exception code
    slli t1, t1, 6       # interrupt bit → bit 6
    or t0, t0, t1        # vector = (interrupt << 6) | code
    sd t0, TRAP_VECTOR_OFFSET(sp)
.endm

.macro RESTORE_ALL
    /* Restore exception registers. */
    ld t0, TRAP_SEPC_OFFSET(sp)
    csrw sepc, t0
    ld t0, TRAP_SSTATUS_OFFSET(sp)
    csrw sstatus, t0

    /* Restore sscratch with the kernel sp so the next U-mode trap's
       `csrrw sp, sscratch, sp` swaps back onto the kernel stack.  Writing the
       user sp here would make the *next* U-mode trap build its frame on the
       user stack.  (For a U-mode trap, TRAP_KERNEL_SP is the kernel sp that
       was saved to sscratch by enter_user_mode; for an S-mode trap it is the
       interrupted kernel sp.) */
    ld t0, TRAP_KERNEL_SP_OFFSET(sp)
    csrw sscratch, t0

    /* Restore all general-purpose registers. */
    ld ra,  TRAP_RA_OFFSET(sp)
    ld gp,  TRAP_GP_OFFSET(sp)
    ld tp,  TRAP_TP_OFFSET(sp)
    ld t0,  TRAP_T0_OFFSET(sp)
    ld t1,  TRAP_T1_OFFSET(sp)
    ld t2,  TRAP_T2_OFFSET(sp)
    ld s0,  TRAP_S0_OFFSET(sp)
    ld s1,  TRAP_S1_OFFSET(sp)
    ld a0,  TRAP_A0_OFFSET(sp)
    ld a1,  TRAP_A1_OFFSET(sp)
    ld a2,  TRAP_A2_OFFSET(sp)
    ld a3,  TRAP_A3_OFFSET(sp)
    ld a4,  TRAP_A4_OFFSET(sp)
    ld a5,  TRAP_A5_OFFSET(sp)
    ld a6,  TRAP_A6_OFFSET(sp)
    ld a7,  TRAP_A7_OFFSET(sp)
    ld s2,  TRAP_S2_OFFSET(sp)
    ld s3,  TRAP_S3_OFFSET(sp)
    ld s4,  TRAP_S4_OFFSET(sp)
    ld s5,  TRAP_S5_OFFSET(sp)
    ld s6,  TRAP_S6_OFFSET(sp)
    ld s7,  TRAP_S7_OFFSET(sp)
    ld s8,  TRAP_S8_OFFSET(sp)
    ld s9,  TRAP_S9_OFFSET(sp)
    ld s10, TRAP_S10_OFFSET(sp)
    ld s11, TRAP_S11_OFFSET(sp)
    ld t3,  TRAP_T3_OFFSET(sp)
    ld t4,  TRAP_T4_OFFSET(sp)
    ld t5,  TRAP_T5_OFFSET(sp)
    ld t6,  TRAP_T6_OFFSET(sp)

    /* Pop the trap frame and restore sp (original user or kernel sp). */
    ld sp, TRAP_SP_OFFSET(sp)
.endm

.section .text.trap, "ax"
.align 6   /* 64-byte alignment for stvec base */

.global __riscv64_trap_entry
__riscv64_trap_entry:
    SAVE_ALL

    /* Load the PerCpuData pointer into tp from the global slot written by
       riscv64_set_tp().  Thread kernel stacks are 32 KiB and only 4 KiB
       aligned, so the old 64 KiB stack-bottom scan (`and sp, ~65535`)
       landed mid-stack and read garbage tp. */
    la tp, RISCV64_PERCPU_PTR
    ld tp, 0(tp)

    /* Call Rust handler: riscv64_trap_dispatch(&mut frame) */
    mv a0, sp
    call riscv64_trap_dispatch

    RESTORE_ALL
    sret
