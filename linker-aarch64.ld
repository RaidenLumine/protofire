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

/* The frame pool's span, in bytes.  It is reserved address space, not storage:
   nothing is loaded there and the boot never clears it — the allocator zeroes
   a frame when it hands one out, which is the guarantee that is actually
   needed.  It used to be a 512 MiB array in `.bss` that the boot cleared, and
   a machine whose RAM ended inside the image lost the console before it
   existed; see `src/memory/frame.rs`.

   The size is derived from the window, not picked: the pool is a reservation
   inside the RAM window the runtime tables identity-map, so its ceiling is
   `KERNEL_TEXT_END` (1 GiB of window from `KERNEL_TEXT_BASE`,
   `src/arch/aarch64/mmu/mod.rs`), and the policy below takes the largest
   256 MiB multiple that leaves `POOL_MARGIN` free — 768 MiB here, where the
   window ends at 0x8000_0000 and the pool starts at 0x4560_0000.  What the
   span buys is frames: on a machine with more RAM than the span the excess
   stays unmanaged (`managed_pool_bytes`).  The policy is enforced by the
   ASSERT at the end of SECTIONS rather than remembered. */
POOL_SIZE = 768M;

/* The room the pool must leave below its window's ceiling: the image sits
   before the pool, so this is how far the image may grow before the pool's
   own end would leave the window.  More than the image is large today
   (measured ~73 MiB), which is why it is 128M and not 64M. */
POOL_MARGIN = 128M;

/* Where the RAM window the runtime tables identity-map ends — the nearer of
   the two bounds that matter, the other being the top of the machine's RAM.
   Kept in step with `KERNEL_TEXT_END` in `src/arch/aarch64/mmu/mod.rs`; the
   linker script cannot read a Rust constant, so the ASSERT below is what
   makes the two disagree loudly instead of silently. */
RAM_WINDOW_END = 0x80000000;

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
    /* Where the loaded content ends: everything before this is the kernel the
       loader places and this boot clears, everything after is reserved
       address space (below).  The boot's memory check asks about this range
       rather than the whole image, because a machine is not required to have
       RAM under memory the kernel reserves and never loads. */
    . = ALIGN(16);
    __image_end = .;

    /* The demo slots and the frame pool are reserved **address space**, not
       sections: the location counter advances over them and no input section
       fills them, so no loadable segment covers the span.  A loader zeroes a
       segment's `p_memsz`, and a 512 MiB pool inside one made every boot pay
       a half-gigabyte clear — and made the boot's own clear loop run past the
       end of RAM on a small machine, a fault before the console exists.  The
       frame pool is memory the allocator zeroes a frame at a time and the
       demo slots are memory a payload load zeroes; the boot clears neither.
       See `src/memory/frame.rs` and
       `docs/rfcs/0020-what-the-memory-map-may-refuse-on.md`. */
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
