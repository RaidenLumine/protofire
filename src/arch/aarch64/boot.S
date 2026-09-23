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
    mov x0, x5           /* arg0 = this AP's stack top */
    br x4                /* Jump to aarch64_ap_startup */

2:  wfe
    b 0b

    /* ── BSP entry ── */
1:  ldr x1, =__boot_stack_top
    mov sp, x1

    /* Park the device tree before the BSS clear below can reach it.
       On this machine the kernel is handed an arm64 `Image` boot, so QEMU
       supplies a device tree — and places it inside the kernel's own BSS,
       where the 512 MiB frame pool lives.  Clearing BSS would erase the blob
       before the kernel ever reads it, which is exactly what used to happen:
       the kernel saw `x0 = 0` on the ELF path and a wiped blob on the Image
       path, and fell back to hardcoded platform constants either way.  Copy it
       into the reserved buffer instead, clamped to the buffer's size, and hand
       that copy to Rust.  `x10` carries the address across the clear. */
    mov x10, xzr                    /* 0: no device tree to hand over */
    cbz x0, 4f
    ldr w2, [x0, #4]                /* FDT totalsize, big-endian */
    rev w2, w2
    ldr x1, =__dtb_copy_start
    ldr x9, =__dtb_copy_end
    add x3, x1, x2
    cmp x3, x9
    b.ls 2f
    mov x3, x9                      /* clamp to the buffer */
2:  mov x4, x0                      /* source cursor */
    mov x5, x1                      /* destination cursor */
3:  cmp x5, x3
    b.hs 4f
    ldr w6, [x4], #4
    str w6, [x5], #4
    b 3b
4:  mov x10, x1                     /* the copy, when there was one */

    ldr x1, =__bss_start
    ldr x2, =__bss_end

5:
    cmp x1, x2
    b.hs 6f
    str xzr, [x1], #8
    b 5b

6:
    /* Hand over the parked blob (or 0 when there was none).  AP discovery
       reads the CPU list from it, and so does every other piece of platform
       discovery the kernel does. */
    mov x0, x10
    bl aarch64_store_handoff

    bl kernel_entry_aarch64

7:
    wfe
    b 7b
