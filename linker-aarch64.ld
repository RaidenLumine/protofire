/* File: linker-aarch64.ld */
/* Purpose: Linker script for the AArch64 bare-metal kernel image. */

OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(_start)

KERNEL_LOAD_ADDRESS = 0x40080000;

/* Where the device tree is parked, in bytes.  QEMU's `virt` device tree is
   one megabyte by the time it is padded, and a real machine's can be larger,
   so the buffer is sized to hold one with room to spare.  It is NOLOAD: the
   boot code writes it before anything reads it. */
DTB_COPY_SIZE = 2M;

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

    /* The device tree handed over at boot, parked here before the BSS clear.
       It has to be outside `__bss_start..__bss_end`: the kernel's own frame
       pool is a 512 MiB BSS array, the blob QEMU hands over lands inside it,
       and clearing BSS would otherwise erase the device tree before the kernel
       reads it.  It sits inside the image's own data window so the runtime page
       tables keep it mapped. */
    . = ALIGN(16);
    __dtb_copy_start = .;
    .dtb_copy (NOLOAD) : {
        . += DTB_COPY_SIZE;
    }
    __dtb_copy_end = .;

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
