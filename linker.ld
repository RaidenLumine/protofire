/* File: linker.ld */
/* Purpose: Linker script for the x86_64 bare-metal kernel image. */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

KERNEL_LOAD_ADDRESS = 0x200000;

/* The frame pool's span, in bytes.  It is reserved address space, not
   storage: nothing is loaded there and no clear loop walks it — the
   allocator zeroes a frame when it hands one out.  See
   `src/memory/frame.rs`.

   The size is derived from the window, not picked, and on this machine the
   window is the *shorter* one: the pool is a reservation inside the kernel's
   own memory, which the runtime tables identity-map, and what bounds it is
   not the end of a RAM window but the kernel's stack window — `X86_STACK_WINDOW_BASE`
   (0x3000_0000, `src/arch/x86_64/paging/runtime.rs`) sits above the image and
   below everything else.  The policy takes the largest 256 MiB multiple that
   leaves `POOL_MARGIN` free below that bound: 512 MiB, with the pool ending
   at 0x2480_0000-ish and the margin before 0x3000_0000.  A 768 MiB pool would
   run into the stack window.  What the span buys is frames: on a machine with
   more RAM than the span the excess stays unmanaged
   (`managed_pool_bytes`).  The policy is enforced by the ASSERT at the end of
   SECTIONS rather than remembered. */
POOL_SIZE = 512M;

/* The room the pool must leave below the stack window: the image sits before
   the pool, so this is how far the image may grow before the pool's own end
   would reach the window.  More than the image is large today (measured
   ~73 MiB), which is why it is 128M and not 64M. */
POOL_MARGIN = 128M;

/* The kernel's stack window's base — the bound the pool must stay below,
   which on this machine is nearer than any window's end.  Kept in step with
   `X86_STACK_WINDOW_BASE` in `src/arch/x86_64/paging/runtime.rs`; the linker
   script cannot read a Rust constant, so the ASSERT below is what makes the
   two disagree loudly instead of silently. */
STACK_WINDOW_BASE = 0x30000000;

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
    /* Where the loaded content ends: everything before this is the kernel the
       loader places and this boot clears, everything after is reserved
       address space (below).  The boot's memory check asks about this range
       rather than the whole image, because a machine is not required to have
       RAM under memory the kernel reserves and never loads. */
    __image_end = .;

    /* The frame pool is reserved **address space**, not a section: the
       location counter advances over it and no input section fills it, so no
       loadable segment covers the span.  A loader zeroes a segment's
       `p_memsz`, and a 512 MiB pool inside one made every boot pay a
       half-gigabyte clear — and made an ELF with more `p_memsz` than the
       machine has RAM fail to load at all.  The pool is memory the allocator
       zeroes a frame at a time, so it is the allocator's, not the loader's.
       See `src/memory/frame.rs` and
       `docs/rfcs/0020-what-the-memory-map-may-refuse-on.md`. */
    . = ALIGN(4K);
    __pool_start = .;
    . += POOL_SIZE;
    __pool_end = .;
    __bss_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }

    /* The pool's policy, as a build-time fact: it stays inside the kernel's
       own memory — below the stack window — and leaves POOL_MARGIN free for
       the image to grow into.  A pool that grew past this would collide with
       the stacks. */
    ASSERT(__pool_end + POOL_MARGIN <= STACK_WINDOW_BASE,
        "the frame pool must leave the stack window's margin free; lower POOL_SIZE")
}
