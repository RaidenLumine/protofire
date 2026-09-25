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

    /* sscratch means "the kernel stack, and only while this CPU is in user
       mode": that is what the next U-mode trap's `csrrw sp, sscratch, sp` has
       to find, so returning to U-mode leaves the kernel sp there.

       Returning to S-mode leaves it *zero*, and that is not symmetry for its
       own sake.  SAVE_ALL decides which kind of trap it is looking at by
       whether sscratch was zero, so a non-zero sscratch in kernel mode sends
       the next kernel trap down the user path with a stack pointer from the
       last one: the frame it builds lands on top of the frames of whatever was
       interrupted, which is a corrupted caller rather than a fault.  One CPU
       survives that for a long time, because the stale pointer is usually only
       a little off; a second hart taking kernel-mode timer interrupts is what
       wears it through. */
    srli t0, t0, 8
    andi t0, t0, 1          /* SPP: 0 = returning to U-mode, 1 = S-mode */
    bnez t0, .Lrestore_to_kernel_\@
    ld t0, TRAP_KERNEL_SP_OFFSET(sp)
    csrw sscratch, t0
    j .Lrestore_sscratch_done_\@
.Lrestore_to_kernel_\@:
    csrw sscratch, zero
.Lrestore_sscratch_done_\@:

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
.align 6   /* 64-byte alignment for the first stub, and so for stvec */

/* ── Per-hart trap entry stubs ─────────────────────────────────────────────
   `stvec` is a per-hart CSR, so each hart points it at its own stub, and the
   stub is little more than the hart's name: one jump, four bytes.  The
   handler then reads back the `stvec` it arrived through and turns the offset
   into the hart's index — see below.  The stubs stay exactly one four-byte
   jump each because that offset is the index; `trap.rs` checks the stride once
   per hart at boot rather than trusting the assembler to have kept it.

   The count must equal `kernel::smp::MAX_CPUS`; `trap.rs` asserts that, so a
   CPU count the table cannot name fails the build instead of a boot. */
.set RISCV64_MAX_HARTS, 17

/* Relaxation and compression both off, so a stub is exactly one four-byte
   `jal`.  Relaxed, it becomes an `auipc` + `jalr` pair that loads an address
   through a register the interrupted context owns — which would corrupt the
   trap frame as well as the layout.  Compressed, it becomes a two-byte `c.j`
   plus whatever padding the assembler picks.  The branches are local, so a
   plain `jal` always reaches. */
.option push
.option norelax
.option norvc

.global RISCV64_TRAP_STUBS
RISCV64_TRAP_STUBS:
.irp hart, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
    .align 2
    .global __riscv64_trap_entry_\hart
__riscv64_trap_entry_\hart:
    jal x0, __riscv64_trap_common
.endr

/* Entry address for a hart, for whoever installs `stvec` (trap.rs).  The
   stride is applied here and in the handler below, and nowhere else. */
.global riscv64_trap_stub_for_hart
riscv64_trap_stub_for_hart:
    la t0, RISCV64_TRAP_STUBS
    slli a0, a0, 2
    add a0, a0, t0
    ret

.option pop

.align 4
__riscv64_trap_common:
    SAVE_ALL

    /* Which hart came in.  `stvec` is this hart's stub, the stubs are four
       bytes each, so the offset names the hart — and the hart names its
       `PerCpuData` slot.  A `stvec` that is not one of ours is not a case the
       kernel can have created; leaving `tp` as the interrupted context left it
       is the honest answer to it, and the handler below still runs.

       This runs after SAVE_ALL, and uses only t0/t1, which SAVE_ALL has
       already spilled and which the vector decode clobbers anyway: the
       interrupted `tp` is in the frame, so nothing about the trap changes. */
    csrr t0, stvec
    la t1, RISCV64_TRAP_STUBS
    sub t0, t0, t1
    srli t0, t0, 2
    li t1, RISCV64_MAX_HARTS
    bgeu t0, t1, .Ltp_kept
    la t1, RISCV64_PERCPU_PTRS
    slli t0, t0, 3
    add t0, t0, t1
    ld tp, 0(t0)
.Ltp_kept:

    /* Call Rust handler: riscv64_trap_dispatch(&mut frame) */
    mv a0, sp
    call riscv64_trap_dispatch

    RESTORE_ALL
    sret
