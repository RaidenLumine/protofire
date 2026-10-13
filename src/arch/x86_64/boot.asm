/* File: src/arch/x86_64/boot.asm */

/* Purpose: x86_64 bootstrap stub that advertises Multiboot2 support and enters long mode. */

.set MULTIBOOT2_MAGIC, 0xE85250D6
.set MULTIBOOT2_ARCH, 0
.set MULTIBOOT2_HEADER_LENGTH, multiboot_header_end - multiboot_header_start
.set MULTIBOOT2_CHECKSUM, -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH + MULTIBOOT2_HEADER_LENGTH)

.section .multiboot_header, "a"
.align 8
multiboot_header_start:
    .long MULTIBOOT2_MAGIC
    .long MULTIBOOT2_ARCH
    .long MULTIBOOT2_HEADER_LENGTH
    .long MULTIBOOT2_CHECKSUM
    .short 0
    .short 0
    .long 8
multiboot_header_end:

/* PVH ELF note — required by QEMU >=8.0 for direct -kernel boot.
 * The PVH boot protocol is specified in the Xen PVH design document;
 * type 18 (XEN_ELFNOTE_PHYS32_ENTRY) tells QEMU the 32-bit entry point.
 * The ELF note layout follows the generic ELF specification (namesz /
 * descsz / type / name / desc), which is an industry-standard ABI. */
.pushsection .note.Xen, "a", @note
.balign 4
.long 2f - 1f       /* namesz = sizeof("Xen") */
.long 3f - 2f       /* descsz = sizeof(entry_point) */
.long 18            /* type  = XEN_ELFNOTE_PHYS32_ENTRY */
1: .asciz "Xen"
2: .balign 4
3: .long _start
.popsection

.section .text._start, "ax"
.code32
.global _start
.extern kernel_entry

_start:
    cli
    mov dword ptr [multiboot_magic], eax
    mov dword ptr [multiboot_info], ebx

    lea esp, [boot_stack_top]
    xor ebp, ebp

    call setup_page_tables
    call enable_long_mode

    lgdt [gdt64_descriptor]
    push 0x08
    lea eax, [long_mode_start]
    push eax
    retf

/* Identity-map the first four gigabytes: PML4[0] -> PDPT, PDPT[0..3] -> four
 * page directories of 2 MiB entries.
 *
 * The window is four gigabytes because the machine's own tables sit where its
 * firmware placed them.  On RAM above 1 GiB, QEMU puts its ACPI tables above
 * the first gigabyte (measured on `q35`: RSDT at 0x3ffe2362 with 1 GiB of RAM,
 * 0x7ffe2351 with 2 GiB), and the boot reads them - RSDT, then MADT/SRAT/SLIT
 * - before the runtime page tables exist.  A one-gigabyte window faulted on
 * the first table entry of such a machine; see
 * `BOOTSTRAP_IDENTITY_MAP_LENGTH` in `paging/types.rs`, which must agree with
 * this count. */
setup_page_tables:
    lea eax, [boot_pdpt]
    or eax, 0x03
    mov dword ptr [boot_pml4], eax
    mov dword ptr [boot_pml4 + 4], 0

    xor ecx, ecx

fill_pdpt_loop:
    lea eax, [boot_pd]
    mov edx, ecx
    shl edx, 12                  /* ecx * 4096: this window's PD page */
    add eax, edx
    or eax, 0x03
    mov edx, ecx
    shl edx, 3                   /* PDPT entries are 8 bytes apart */
    mov dword ptr [boot_pdpt + edx], eax
    mov dword ptr [boot_pdpt + edx + 4], 0
    inc ecx
    cmp ecx, 4
    jne fill_pdpt_loop

    xor ecx, ecx

fill_pd_loop:
    mov eax, ecx
    shl eax, 21
    or eax, 0x83
    mov dword ptr [boot_pd + ecx * 8], eax
    mov dword ptr [boot_pd + ecx * 8 + 4], 0
    inc ecx
    cmp ecx, 2048
    jne fill_pd_loop

    ret

enable_long_mode:
    lea eax, [boot_pml4]
    mov cr3, eax

    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    mov ecx, 0xC0000080
    rdmsr
    # Enable long mode and the NX bit before switching to runtime page tables.
    # The Rust-side paging code already marks non-executable pages with NX.
    or eax, (1 << 8) | (1 << 11)
    wrmsr

    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax
    ret

.align 8
gdt64:
    .quad 0x0000000000000000
    .quad 0x00AF9A000000FFFF
    .quad 0x00AF92000000FFFF
gdt64_end:

gdt64_descriptor:
    .word gdt64_end - gdt64 - 1
    .long gdt64

.code64
long_mode_start:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax

    lea rsp, [rip + boot_stack_top]
    xor rbp, rbp

    mov edi, dword ptr [rip + multiboot_magic]
    mov esi, dword ptr [rip + multiboot_info]
    call kernel_entry

halt_forever:
    hlt
    jmp halt_forever

.section .bss.boot, "aw", @nobits
.align 16
multiboot_magic:
    .skip 4
multiboot_info:
    .skip 4

.align 4096
boot_pml4:
    .skip 4096
boot_pdpt:
    .skip 4096
/* Four page directories, one per gigabyte of the bootstrap window; the fill
   loop above indexes them as one 2048-entry array from `boot_pd`. */
boot_pd:
    .skip 16384

.align 16
boot_stack_bottom:
    .skip 65536
boot_stack_top:
