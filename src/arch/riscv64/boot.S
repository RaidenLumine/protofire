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

    /* Save the FDT pointer (a1) to a callee-saved register for Rust. */
    mv s0, a1

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

    /* Pass FDT pointer (s0) as the first argument to the Rust entry. */
    mv a0, s0
    call kernel_entry_riscv64

.Lhang:
    wfi
    j .Lhang

/* ── Secondary hart entry point (SMP) ────────────────────────────────────
   Called by SBI HSM `hart_start` (see riscv64/smp.rs bring_up_aps) with:
       a0 = hart_id
       a1 = opaque (stack top, pre-allocated by the BSP)
   We set the stack pointer from the opaque context and tail-call the Rust
   ap_entry() function (src/arch/riscv64/smp.rs), which never returns. */
.align 4
_secondary_start:
    /* Set stack pointer from opaque (passed by BSP via SBI HSM a2). */
    mv sp, a1

    /* Jump to the Rust entry (tail call — never returns). */
    tail ap_entry
