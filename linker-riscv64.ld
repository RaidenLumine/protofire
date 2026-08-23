/* File: linker-riscv64.ld */
/* Purpose: Linker script for the RISC-V 64-bit bare-metal kernel image. */

OUTPUT_FORMAT(elf64-littleriscv)
OUTPUT_ARCH(riscv)
ENTRY(_start)

KERNEL_LOAD_ADDRESS = 0x80200000;

SECTIONS
{
    . = KERNEL_LOAD_ADDRESS;
    __kernel_start = .;

    . = ALIGN(4K);
    __text_start = .;
    .text : {
        *(.text.boot)
        *(.text .text.*)
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

    . = ALIGN(64K);
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
