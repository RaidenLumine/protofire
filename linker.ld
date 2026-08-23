/* File: linker.ld */
/* Purpose: Linker script for the x86_64 bare-metal kernel image. */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

KERNEL_LOAD_ADDRESS = 0x200000;

SECTIONS
{
    . = KERNEL_LOAD_ADDRESS;
    __kernel_start = .;

    /* Multiboot2 header is placed first inside .text so GRUB can find
     * it within the first 32 KiB (at file offset 4 KiB).  The PVH note
     * sits in its own output section at the same page so QEMU >= 8.0
     * -kernel boot can discover it via the NOTE program header.
     * Giving .notes the same AX flags as .text keeps them in a single
     * LOAD segment, avoiding the tiny-R-segment issue with GRUB. */
    . = ALIGN(4K);
    __text_start = .;
    .notes : {
        KEEP(*(.note.Xen))
    }
    .text : {
        KEEP(*(.multiboot_header))
        *(.text .text.*)
        *(.ltext .ltext.*)
        KEEP(*(xiu_demo_program_payload))
        KEEP(*(protofire_demo_program_payload))
        KEEP(*(protofire_shell_payload))
        . = ALIGN(16);
        __start_protofire_demo_program_rust = .;
        KEEP(*(xiu_demo_program_rust))
        KEEP(*(protofire_demo_program_rust))
        __stop_protofire_demo_program_rust = .;
        . = ALIGN(16);
        __start_protofire_demo_program_aarch64_rust = .;
        KEEP(*(protofire_demo_program_aarch64_rust))
        __stop_protofire_demo_program_aarch64_rust = .;
        . = ALIGN(16);
        __start_protofire_demo_program_rust_io = .;
        KEEP(*(xiu_demo_program_rust_io))
        KEEP(*(protofire_demo_program_rust_io))
        __stop_protofire_demo_program_rust_io = .;
    }
    __text_end = .;

    . = ALIGN(4K);
    __rodata_start = .;
    .rodata : {
        *(.lrodata .lrodata.*)
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }
    __rodata_end = .;

    . = ALIGN(4K);
    __data_start = .;
    .data : {
        *(.data .data.*)
        *(.ldata .ldata.*)
        *(.data.rel.ro.local*)
        *(.data.rel.ro*)
        *(.got .got.*)
    }
    __data_end = .;

    . = ALIGN(4K);
    __bss_start = .;
    .bss : {
        *(.bss .bss.*)
        *(.lbss .lbss.*)
        *(COMMON)
    }
    __bss_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }
}
