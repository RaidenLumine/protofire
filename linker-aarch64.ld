/* File: linker-aarch64.ld */
/* Purpose: Linker script for the AArch64 bare-metal kernel image. */

OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(_start)

KERNEL_LOAD_ADDRESS = 0x40080000;

SECTIONS
{
    . = KERNEL_LOAD_ADDRESS;
    __kernel_start = .;

    . = ALIGN(4K);
    __text_start = .;
    .text : {
        *(.text.boot)
        *(.text .text.*)
        . = ALIGN(16);
        __start_protofire_demo_program_aarch64_rust = .;
        KEEP(*(protofire_demo_program_aarch64_rust))
        __stop_protofire_demo_program_aarch64_rust = .;
    }
    __text_end = .;

    . = ALIGN(4K);
    __rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }
    __rodata_end = .;

    . = ALIGN(4K);
    __data_start = .;
    .data : {
        *(.data .data.*)
        *(.data.rel.ro.local*)
        *(.data.rel.ro*)
        *(.got .got.*)
    }
    __data_end = .;

    . = ALIGN(16);
    .boot_stack (NOLOAD) : {
        __boot_stack_bottom = .;
        . += 64K;
        __boot_stack_top = .;
    }

    . = ALIGN(16);
    __bss_start = .;
    .bss (NOLOAD) : {
        *(.bss .bss.*)
        *(COMMON)
    }
    . = ALIGN(16);
    __bss_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }
}
