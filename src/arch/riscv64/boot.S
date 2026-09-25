/* File: src/arch/riscv64/boot.S */

/* Purpose: RISC-V 64-bit bare-metal boot entry that sets up the initial stack
   and transfers control to Rust.  The kernel arrives in S-mode via OpenSBI
   with the FDT pointer in a1.  Includes a secondary-hart entry point for SMP. */

.section .text.boot, "ax"
.align 4
.global _start
.global _secondary_start
.type _start, %function
.type _secondary_start, %function
.extern kernel_entry_riscv64

_start:
    /* Only hart 0 reaches here — OpenSBI already filters secondary harts.
       We arrive in S-mode, so M-mode CSRs (mhartid) are inaccessible. */

    /* Zero tp so percpu::get() uses the early fallback until percpu init. */
    mv tp, zero

    /* Save the hand-off registers to callee-saved registers for Rust.  The
       platform passes the boot hart's ID in a0 and the device-tree blob in
       a1; `mhartid` is not readable from S-mode, so a0 is the only way to
       learn which hart is running. */
    mv s0, a0
    mv s1, a1

    /* Set up the boot stack. */
    la sp, __boot_stack_top

    /* Clear BSS. */
    la t0, __bss_start
    la t1, __bss_end
.Lclear_bss:
    bge t0, t1, .Lbss_done
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lclear_bss
.Lbss_done:

    /* Keep the hart ID and the device-tree pointer where the kernel can find
       them.  Hart discovery reads the CPU list from the blob and has to skip
       the hart it is running on, so losing either one here is what would leave
       the machine on one hart while the others wait for a start they are never
       told about. */
    mv a0, s0
    mv a1, s1
    call riscv64_store_handoff

    /* Pass FDT pointer (s0) as the first argument to the Rust entry. */
    mv a0, s1
    call kernel_entry_riscv64

.Lhang:
    wfi
    j .Lhang

/* ── Secondary hart entry point (SMP) ────────────────────────────────────
   Called by SBI HSM `hart_start` (see riscv64/smp.rs bring_up_aps) with:
       a0 = hart_id
       a1 = opaque (stack top, pre-allocated by the BSP)
   A hart started this way comes up with paging off and `tp` holding whatever
   the firmware left in it, so both are set here, before any Rust code can read
   per-CPU state: the stack from the opaque context, and the hart's
   `PerCpuData` from the slot the BSP filled before it started us.  Then we
   tail-call the Rust ap_entry() (src/arch/riscv64/smp.rs), which never
   returns. */
.align 4
_secondary_start:
    /* Set stack pointer from opaque (passed by BSP via SBI HSM a2). */
    mv sp, a1

    /* tp ← this hart's PerCpuData, from slot `hart_id`. */
    slli t0, a0, 3
    la t1, RISCV64_PERCPU_PTRS
    add t0, t0, t1
    ld tp, 0(t0)

    /* Jump to the Rust entry (tail call — never returns). */
    tail ap_entry
