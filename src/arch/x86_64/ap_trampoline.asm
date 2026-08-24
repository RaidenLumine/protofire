/* File: src/arch/x86_64/ap_trampoline.asm                                  */
/*                                                                          */
/* Purpose: AP startup trampoline — 16-bit → 32-bit → 64-bit transition.    */
/*                                                                          */
/* Trampoline data at physical 0x9000 (each field u64, 8-byte aligned):     */
/*   0x00: boot_cr3        — boot page-table root (identity-maps 0–1 GiB)   */
/*   0x08: stack_top       — initial kernel stack pointer (virtual)         */
/*   0x10: entry_point     — virtual address of ap_entry()                  */
/*   0x18: cpu_id          — logical CPU ID (1st argument)                  */
/*   0x20: lapic_id        — local APIC ID (2nd argument)                   */
/*   0x28: percpu_base     — virtual address of PerCpuData for this CPU     */
/*   0x30: ap_started_flag — pointer to AtomicBool (AP sets *flag = 1)      */
/*   0x38: runtime_cr3     — kernel runtime page-table root                 */

.section .text.ap_trampoline, "ax"

.code16
.global ap_trampoline_start
ap_trampoline_start:
    cli
    cld

    /* Load 32-bit GDT. */
    mov eax, offset ap_trampoline_gdt_desc
    sub eax, offset ap_trampoline_start
    add eax, 0x8000
    lgdt [eax]

    /* Enter protected mode. */
    mov eax, cr0
    or al, 1
    mov cr0, eax

    .byte 0x66
    .byte 0xEA
    .long ap_trampoline_prot_mode - ap_trampoline_start + 0x8000
    .word 0x0008

.code32
ap_trampoline_prot_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov ss, ax

    /* Load 64-bit GDT. */
    mov eax, offset ap_trampoline_gdt64_desc
    sub eax, offset ap_trampoline_start
    add eax, 0x8000
    lgdt [eax]

    /* Load boot CR3 (identity-maps first 1 GiB). */
    mov esi, 0x9000
    mov eax, [esi]
    mov cr3, eax

    /* Enable PAE. */
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    /* Enable SSE/SSE2.
     * CR4.OSFXSR (bit 9)  — enable FXSAVE/FXRSTOR and SSE instructions.
     * CR4.OSXMMEXCPT (bit 10) — enable #XM exception for SSE faults.
     * Without these bits, movdqu/movdqa/movaps and other SSE instructions
     * raise #UD (Invalid Opcode).  The BSP inherits these from firmware;
     * the AP must set them explicitly. */
    mov eax, cr4
    or eax, (1 << 9) | (1 << 10)
    mov cr4, eax

    /* Clear CR0.EM (bit 2) so the x87 FPU is used natively rather than
     * emulated.  Set CR0.MP (bit 1) so WAIT/FWAIT is TS-aware.  Reset
     * state may have EM set on some QEMU versions. */
    mov eax, cr0
    and eax, ~(1 << 2)
    or eax, (1 << 1)
    mov cr0, eax

    /* Enable LME + NXE (IA32_EFER).
     * NXE must be set because the runtime page tables use the NX bit (bit 63)
     * on non-executable data/bss/heap pages.  Without NXE, those PTEs contain
     * a reserved bit → #PF(RESVD) → triple fault. */
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8) | (1 << 11)
    wrmsr

    /* Enable paging → enter compatibility mode. */
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax

    .byte 0xEA
    .long ap_trampoline_long_mode - ap_trampoline_start + 0x8000
    .word 0x0008

.code64
ap_trampoline_long_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov ss, ax

    /* Clear CR0.TS (Task Switched) so the first FPU/SSE instruction doesn't
     * raise #NM.  Initialise the x87 FPU to a clean state with fninit. */
    clts
    fninit

    /* Read trampoline data while still under the boot CR3 (identity-maps
     * 0–1 GiB).  Values are stashed in registers that survive the CR3 switch;
     * the runtime page tables may not identity-map the data page at 0x9000. */
    mov rbx, 0x9000
    mov rsp, [rbx + 0x08]       /* stack_top           → rsp */
    mov r8,  [rbx + 0x10]       /* entry_point         → r8  */
    mov edi, [rbx + 0x18]       /* cpu_id              → edi (1st arg) */
    mov esi, [rbx + 0x20]       /* lapic_id            → esi (2nd arg) */
    mov rax, [rbx + 0x38]       /* runtime_cr3         → rax */

    /* Switch to runtime page tables. */
    mov cr3, rax

    /* Jump to ap_entry with the values stashed in registers.
     * Use jmp instead of call — ap_entry has return type ! and never
     * returns, so there's no need to push a return address. */
    jmp r8

/* ── GDT data ─────────────────────────────────────────────────────────── */

.align 8
ap_trampoline_gdt:
    .quad 0x0000000000000000
    .quad 0x00CF9A000000FFFF
    .quad 0x00CF92000000FFFF
ap_trampoline_gdt_end:

ap_trampoline_gdt_desc:
    .word ap_trampoline_gdt_end - ap_trampoline_gdt - 1
    .long ap_trampoline_gdt - ap_trampoline_start + 0x8000

.align 8
ap_trampoline_gdt64:
    .quad 0x0000000000000000
    .quad 0x00AF9A000000FFFF
    .quad 0x00AF92000000FFFF
ap_trampoline_gdt64_end:

ap_trampoline_gdt64_desc:
    .word ap_trampoline_gdt64_end - ap_trampoline_gdt64 - 1
    .quad ap_trampoline_gdt64 - ap_trampoline_start + 0x8000

.global ap_trampoline_end
ap_trampoline_end:
