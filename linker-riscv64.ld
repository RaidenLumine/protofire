/* File: linker-riscv64.ld */
/* Purpose: Linker script for the RISC-V 64-bit bare-metal kernel image. */

OUTPUT_FORMAT(elf64-littleriscv)
OUTPUT_ARCH(riscv)
ENTRY(_start)

KERNEL_LOAD_ADDRESS = 0x80200000;

/* The frame pool's span, in bytes.  It is reserved address space, not storage:
   nothing is loaded there and no boot clear walks it — the allocator zeroes a
   frame when it hands one out.  See `src/memory/frame.rs`.

   The size is derived from the window, not picked: the pool is a reservation
   inside the RAM window the runtime tables identity-map, so its ceiling is
   that window's end (`KERNEL_RAM_BASE + KERNEL_RAM_LENGTH`,
   `src/arch/riscv64/mmu/mod.rs`), and the policy below takes the largest
   256 MiB multiple that leaves `POOL_MARGIN` free — 768 MiB here, where the
   window ends at 0xC000_0000 and the pool starts at 0x8560_0000.  What the
   span buys is frames: on a machine with more RAM than the span the excess
   stays unmanaged (`managed_pool_bytes`).  The policy is enforced by the
   ASSERT at the end of SECTIONS rather than remembered. */
POOL_SIZE = 768M;

/* The room the pool must leave below its window's ceiling: the image sits
   before the pool, so this is how far the image may grow before the pool's
   own end would leave the window.  More than the image is large today
   (measured ~72 MiB), which is why it is 128M and not 64M. */
POOL_MARGIN = 128M;

/* Where the RAM window the runtime tables identity-map ends — the nearer of
   the two bounds that matter, the other being the top of the machine's RAM.
   Kept in step with `KERNEL_RAM_BASE + KERNEL_RAM_LENGTH` in
   `src/arch/riscv64/mmu/mod.rs`; the linker script cannot read a Rust
   constant, so the ASSERT below is what makes the two disagree loudly
   instead of silently. */
RAM_WINDOW_END = 0xC0000000;

/* The demo slots' span: eight 2 MiB regions a user payload is loaded into,
   reserved the same way and placed before the pool so they lie at the front
   of the machine's RAM with the rest of the kernel. */
DEMO_SLOTS_SIZE = 16M;

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
    /* Where the loaded content ends: everything before this is the kernel the
       loader places and this boot clears, everything after is reserved
       address space (below).  The boot's memory check asks about this range
       rather than the whole image, because a machine is not required to have
       RAM under memory the kernel reserves and never loads. */
    . = ALIGN(16);
    __image_end = .;

    /* The demo slots and the frame pool are reserved **address space**, not
       sections: the location counter advances over them and no input section
       fills them, so no loadable segment covers the span.  That matters
       twice.  A loader zeroes a segment's `p_memsz`, so a 512 MiB pool inside
       one made QEMU refuse the machine ("No enough memory to place DTB after
       kernel/initrd") and made every boot pay a half-gigabyte clear; and the
       boot's own clear loop would run past the end of RAM on a small machine,
       which is a fault before the console exists.  The frame pool is
       therefore memory the allocator zeroes a frame at a time, and the demo
       slots are memory a payload load zeroes; the boot clears neither.  See
       `src/memory/frame.rs` and `docs/rfcs/0020-what-the-memory-map-may-refuse-on.md`. */
    . = ALIGN(2M);
    __demo_slots_start = .;
    . += DEMO_SLOTS_SIZE;
    __demo_slots_end = .;
    . = ALIGN(4K);
    __pool_start = .;
    . += POOL_SIZE;
    __pool_end = .;
    . = ALIGN(16);
    __bss_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }

    /* The pool's policy, as a build-time fact: it stays inside the window the
       runtime tables identity-map and leaves POOL_MARGIN below its ceiling.
       A pool that grew past this would be frames the kernel cannot map. */
    ASSERT(__pool_end + POOL_MARGIN <= RAM_WINDOW_END,
        "the frame pool must leave the RAM window's margin free; lower POOL_SIZE")
}
