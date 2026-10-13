# RFC 0022: Adopt the machine's memory as frames

- **Status:** Draft
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-13
- **Supersedes:** none

## Summary

RFC 0019 decided that a frame is an address in the kernel's **own** memory, and
named "adopting the machine's regions as frames" as a change of its own.  This
is that change, and its first finding is that the change is not what the
sentence suggests.  A frame's address is not merely *stored* in the kernel's
memory; it is the **same number** as the physical address, and the whole tree
depends on that: `phys_addr_of` answers DMA with it, `allocate_frames` hands
out a pointer that every caller (a kernel stack, a pipe buffer, a user page)
writes through directly, and `ensure_identity_mapped_range` exists to keep the
mapping for that pointer alive.  So "frames from the machine's regions" is a
change to an **invariant that spans the tree**, and this document's job is to
say which invariant, what it costs, and what has to be measured before it is
worth doing.  It does *not* decide to do it; it decides what doing it means.
Half the measurement is in: one binary boots a 1 GiB machine and a 16 GiB
machine to the same boot-work line, counter for counter, because the extra
15 GiB is never touched — so today's pool costs a big machine nothing and
gives it nothing.  The other half, what a direct map costs once the memory is
used, needs the change to exist and is named below rather than assumed.

## Motivation

`ROADMAP.md`'s "A real machine" list puts the memory the machine reports third,
and the reason is real: a machine's map has holes and RAM above 4 GiB, and this
kernel's pool is a few hundred megabytes of the kernel's own image — 768 MiB on
the device-tree machines, 512 MiB on the PC.  A machine with 16 GiB manages
one number whether it needs it or not: on the PC the boot says `machine
reports 16383 MiB in 10 region(s); the kernel's pool is 512 MiB` and on each
device-tree machine `machine reports 16384 MiB in 1 region(s); the kernel's
pool is 768 MiB` (measured at 16 GiB; the PC's E820-shaped table has ten
entries and calls the top of RAM reserved, which is why its number is 16383
rather than 16384).  (Those two numbers are what the linker's pool policy
arrived at —
`POOL_SIZE` per script, with an `ASSERT` against the window it lives in; see
RFC 0020's "The pool's size per target" for how.)

Two other measurements narrow what the work is:

- The pool's address **does not move when the machine's RAM grows.**  One
  binary on `q35` at 1, 2, 8 and 16 GiB reads `the pool is [0x489b000,
  0x2489b000)` in all four boots; the device-tree machines are the same shape
  (`[0x45800000, 0x75800000)` on aarch64, `[0x85600000, 0xb5600000)` on
  riscv64, at 16 GiB).  So the pool is not "the low part of the machine's
  RAM" — it is a fixed address the linker chose, and the gap between what the
  machine offers and what the kernel takes is the *whole* gap, not an
  alignment tail.
- The frames a machine would add are far away, and there are more of them
  than "16 GiB minus a little".  A 16 GiB `q35` machine's own table (read
  through the PVH block's `memmap`: 10 entries) calls two ranges available —
  `[0, 0x7ffdf000)`, just under 2 GiB, and
  `[0x1_0000_0000, 0x4_8000_0000)`, which is 14 GiB, every byte of it above
  the window a 32-bit device can name (RFC 0020's DMA-width question, which
  the measurement before this one answered for the *current* pool: nothing
  this kernel hands a device is above 4 GiB, precisely because the pool is
  where it is).  The 2 GiB range holds the kernel and its pool; the 14 GiB
  range holds nothing this kernel can use.

## Current state

The parts a change has to fit into, by file, and the reason each one is
load-bearing:

- `src/memory/frame.rs` — `pool_range()` (`__pool_start`/`__pool_end`),
  `FrameAllocator::init`/`set_node_range` (a `base` plus frame counts),
  `allocate`/`deallocate` (they answer and take `*mut u8`), and
  `zero_frame_range`, which calls `ensure_identity_mapped_range` before it
  writes — the allocator is what guarantees a frame is *writable at its
  address*, not merely free.
- `src/memory/arch.rs` — `KERNEL_IDENTITY_MEMORY_END` (where the kernel's own
  memory is), `managed_pool_bytes` (how much of the pool's span is real, which
  is how the allocator is sized today), `kernel_image_range`,
  `pool_is_addressable_by_a_device` and its refusal,
  `report_machine_memory` and the checks it makes.
- `src/arch/mmu.rs` — `phys_addr_of`: `Some(address)` for a kernel address that
  is its own physical address, `None` otherwise, and **every caller treats
  `None` as a refusal**.  Three implementations, one per machine, each naming
  the window its runtime tables identity-map.
- The consumers of a raw frame, `grep`-counted (27 `allocate_frames` call
  sites): `kernel/process/thread/kernel_stack.rs` (kernel stacks),
  `kernel/shm.rs`, `kernel/oom.rs`, the block layer's bounce buffers
  (`DmaBuffer`), and `memory/manager/` itself — `pfault.rs` (demand paging and
  copy-on-write), `swap.rs`, and the user-page install paths.  The filesystem
  layer does not allocate frames directly; it goes through the block cache and
  its own buffers.
- The machines' windows: aarch64 `KERNEL_TEXT_BASE..KERNEL_TEXT_END`
  (0x4000_0000–0x8000_0000), riscv64 `KERNEL_RAM_BASE..+KERNEL_RAM_LENGTH`
  (0x8000_0000–0xC000_0000), x86_64 the first gigabyte of static tables
  (`STATIC_KERNEL_TABLES_END`) inside a four-gigabyte bootstrap map.

## Design

**1. A frame's address stops being an identity, and becomes a mapping.**  The
change is: the allocator manages *physical* frames, and a frame the kernel
uses is reachable through a **direct map** the kernel maintains for it.  In
the terms the tree already has, `phys_addr_of(frame_address)` becomes a real
translation (a window base plus an offset) rather than an identity, and
`ensure_identity_mapped_range` becomes "map the frame into the kernel's direct
window", which is the same call with a different body.  The devices this tree
drives are unaffected — they are handed `phys_addr_of`'s answer either way.

**2. One direct window per machine, sized from the machine's answer.**  The
window is virtual address space the kernel owns; a frame at physical `p` is
reachable at `window_base + (p - ram_base)`, and `phys_addr_of` inverts that.
Its size is the machine's usable RAM, which is why this change cannot be made
without the machine's answer being *the* input (which RFC 0019's still-owed
read already wired for sizing, and which a machine with holes makes a list of
ranges rather than a length).

**3. The kernel's own memory stays where it is.**  The image, heap, pool and
stack window keep their addresses: a kernel that must first be mapped to run
is a bootstrap problem this change does not need.  What changes is which
memory the *allocator* hands out: the machine's regions, minus the kernel's
own image, minus what the firmware reserves, minus the holes.

**4. Refusals keep their shape.**  A machine whose RAM does not contain the
kernel already refuses (`the kernel's image is in no region the machine
describes`, and a pool past the machine's memory refuses with its range); the
new work adds one: a region the allocator cannot map into the window is a
region it does not adopt, and the boot says how much it left.

## Alternatives

- **Grow the pool and stop there.**  Taken as far as it goes, and it is not
  an answer to *this* question: the span is derived per machine now (768 MiB
  on the device-tree machines, 512 MiB on the PC, each with a link-time
  `ASSERT` against the window it lives in), which buys more frames from the
  same fixed span — and a machine's regions still go unmanaged.  It was the
  cheap step to take first because it needs no invariant to move, and what
  remains is the change that does: the frames already allocated are still
  the only ones a big machine will ever see.
- **Keep the identity and require RAM below 4 GiB.**  That is what the tree
  does today, and it is coherent: the pool is low, devices are 64-bit,
  `phys_addr_of` is trivial.  Rejected as a *permanent* position because a
  machine with 16 GiB would use 768 MiB of it forever (512 MiB on the PC),
  and because a real board's RAM is not arranged to suit the kernel.
- **Adopt only the regions below the DMA bound.**  On the measured 16 GiB
  `q35` that is its `[0, 0x7ffdf000)` range and nothing above 4 GiB: about
  2 GiB instead of 512 MiB, and every frame a 32-bit device could reach.  It
  needs the mapping invariant for exactly the same reason, so it is the same
  change with a smaller window — worth taking as a first step if the full
  window is too much code at once, and worth saying out loud that it leaves
  the other 14 GiB unmanaged.
- **Frames as indices rather than addresses.**  A frame is a `u32` index into
  a table, and a caller translates.  Rejected: it moves the work to every
  caller (there are 27 call sites of `allocate_frames` today, `grep`-counted)
  and it makes the DMA path
  a special case, when DMA *already* wants a physical address and a pointer
  wants a mapped one — the two-way split above says which is which.

## Drawbacks

- It is the tree's largest invariant move: `allocate_frames`'s answer stops
  being a physical address, so every place that writes through a frame with
  the pointer it was handed is re-examined, and the ones that pass a frame's
  address to a device or a page table are the ones that must now ask
  `phys_addr_of` (they already do, which is the one thing that makes this
  tractable).
- The direct map costs page tables for the machine's whole RAM — the thing the
  fixed pool avoids by being small.  A 16 GiB machine maps as 8192 two-megabyte
  entries, which is 16 page directories (64 KiB) at that granularity, or 32 MiB
  of leaves at 4 KiB.  The kernel already maps its own memory with 2 MiB pages,
  so the cheap number is the one to expect.
- The window has to be *found*: on aarch64 and riscv64 the RAM window is a
  constant (1 GiB each), so a 16 GiB machine needs a window the linker does
  not currently reserve.  Where it goes is a layout decision this document
  does not make.
- Nothing here is required for the project's stated near-term gates; the
  measurement that would justify it is not taken (below).

## Compatibility and migration

No ABI or on-disk change: a program sees the same addresses, because user
mappings are built from `phys_addr_of`'s answer today and would be from the
translation then.  What changes for a *contributor* is the meaning of a
`*mut u8` from the frame allocator, and that is the part to write down in
`docs/kernel/memory.md` in the same change rather than after it.  A machine
with no map (a PVH boot before the block's table, a hand-off with nothing)
keeps today's behaviour: the pool, because there is no answer to build a
window from.

## How this is proven

**This document does not yet have an implementation, so this section is its
checklist rather than its evidence.**  In the order they would have to hold:

- **The translation, as a unit test.**  A range list with a hole (the
  measured `q35` 16 GiB shape: `[0, 0x7ffdf000)` available, then
  `[0x7ffdf000, 0x80000000)` reserved, then `[0x1_0000_0000, 0x4_8000_0000)`
  available) mapped into a window, then `phys_addr_of` for both map
  directions, and a frame in the hole refused.
- **The allocator, on a region list.**  `FrameAllocator` sized from regions:
  a hole is skipped, a frame from the high region is handed out and written,
  and the boot reports how much it adopted.
- **The DMA path.**  `DmaBuffer::allocate` on a frame above 4 GiB, then a
  device programmed with `phys_addr_of`'s answer — NVMe's `set_prp1` or
  virtio's descriptor — reading it back.  The harness exists:
  `make check-x8664-nvme`, `make check-aarch64-nvme` and
  `make check-riscv64-nvme` boot a SimpleFs image on an NVMe namespace
  (`scripts/check-nvme-disk.sh`), and the virtio block and net drivers have
  runtime checks of their own.
- **The measurement that is owed**: how much *practical* memory the change
  buys, and what the direct map costs.  The first half is taken and it is
  blunt.  One `perf_baseline` binary on `q35` at 1 GiB and at 16 GiB prints
  the same boot-work line, counter for counter — `frames=23`,
  `frame-zero-bytes=610304`, `pt-maps=1064`, `pt-lookups=1067`,
  `fs-reads=1447`, `blk-reads=201`, `irqs` 527 vs 526, `heap-bytes` 26691072
  vs 26689424 (the last two differ only by scheduling jitter).  So the extra
  15 GiB costs this kernel **nothing at all today** — and buys it nothing
  either: not one frame, not one page table, not one worked byte.  That is
  the number the change is against: 512 MiB used of 16 GiB, at zero cost,
  because the memory is never touched.  What is still owed is the other
  side — what the direct map costs *when* the memory is used (the table
  pages and the entries to build them, countable with the same
  `perf_baseline` line) — and that cannot be measured without the change.

## Unresolved questions

- **Where the direct window goes**, per machine.  aarch64's and riscv64's RAM
  windows are one gigabyte and their kernels already sit inside; a bigger
  machine needs a window outside the current constants, and the choice
  interacts with the stack window and the device windows.
- **What a 32-bit device does with a high frame** (RFC 0020's DMA-width
  question): a bounce buffer, a low-only allocator fallback, or a refusal at
  allocation time.  This document says the split is per device and does not
  choose.
- **Whether the kernel's own memory should also move into the machine's
  regions** (so the image is one more adopted range) or stay a fixed
  reservation.  The Design above keeps it fixed; a board port might not.
- **What a machine doing hotplug would mean** for an allocator whose regions
  are fixed at boot.  Nothing in this tree supports hotplug memory today.
