/* File: src/arch/aarch64/boot.S */
/* Purpose: AArch64 bare-metal boot entry that sets up the initial stack and transfers control to Rust. */

.section .text.boot, "ax"
.align 11
.global _start
.type _start, %function
.extern kernel_entry_aarch64

_start:
    mrs x1, mpidr_el1
    and x1, x1, #0xff
    cbz x1, 1f           /* CPU 0 → BSP entry */

    /* ── Secondary CPU: spin on spin table entry ── */
    adrp x2, aarch64_spin_table
    add x2, x2, :lo12:aarch64_spin_table
    sub x3, x1, #1       /* index = cpu_id - 1 */
    lsl x3, x3, #4       /* offset = index × 16 (each entry = 16 bytes) */
    add x2, x2, x3       /* x2 = &spin_table[index] */

0:  ldr x4, [x2]         /* Load entry_addr */
    cbz x4, 2f           /* If 0 → WFE and retry */
    ldr x5, [x2, #8]     /* Load stack_top */
    mov sp, x5
    mov x0, x1           /* arg0 = cpu_id (the BSP set x0 expectation) */
    br x4                /* Jump to aarch64_ap_startup */

2:  wfe
    b 0b

    /* ── BSP entry ── */
1:  ldr x1, =__boot_stack_top
    mov sp, x1

    ldr x1, =__bss_start
    ldr x2, =__bss_end

2:
    cmp x1, x2
    b.hs 3f
    str xzr, [x1], #8
    b 2b

3:
    bl kernel_entry_aarch64

4:
    wfe
    b 4b
