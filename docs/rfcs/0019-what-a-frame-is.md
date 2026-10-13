# RFC 0019: Make a frame an address in the kernel's own memory

- **Status:** Superseded
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-11
- **Supersedes:** none
- **Superseded by:** [0020](0020-what-the-memory-map-may-refuse-on.md) (its placement check asked a question a correct memory map can never answer; everything else it decided stands)

## Summary

A frame is an address inside the kernel's own image, and the machine's memory
map is asked by nothing.  This decides both halves as they are — the pool
stays the kernel's memory, because the identity map is what makes a device
address equal to a pointer — and makes the machine's answer **used**: the
boot verifies that the image (and so the pool) lies in RAM the firmware calls
usable, refuses when the map says otherwise, and prints what the machine has
beside what the kernel has, instead of one number wearing both names.
Adopting the machine's regions as frames is named here and is its own RFC.

## Motivation

`ROADMAP.md`'s near-term list puts the memory a machine reports third, and the
reason is that a real machine's map has *holes* in it and RAM above 4 GiB.
The state being decided is worse than "the pool is fixed": the machine is
never asked at all.

- `multiboot2_memory_map` (`src/arch/boot.rs`) sums the usable entries of a
  Multiboot2 map, and **nothing calls it**.
- The device-tree parser fills `PlatformInfo::memory_base`/`memory_size` from
  a `/memory` node (`src/arch/fdt/parse.rs`), and **nothing reads those two
  fields** into `DETECTED_PHYSICAL_MEMORY`.
- `store_detected_memory` (`src/memory/arch.rs`) therefore has no caller, the
  atomic it writes is never written, and `detected_memory` always answers
  `None` — so `detect_memory` always answers `frame::physical_pool_size()`.
  The `#[allow(dead_code)]` on the store is justified in its own comment by
  "the binary crate's call sites", and there are none.
- The boot line, `src/memory/manager/init.rs`, prints that pool as
  `{} MiB physical` — the *kernel's* memory wearing the machine's name.  A
  machine with 8 GiB and a machine with 1 GiB print the same line.
- `docs/kernel/memory.md`'s "What the machine says" states that the
  architecture records the platform's answer into that atomic.  It does not,
  and the document is describing a call that is missing rather than code that
  exists.

And the gap is not only cosmetic.  The pool is a static array inside the
image, the image is where the loader put it, and **nothing checks that the
loader put it in RAM the firmware says is usable**.  A loader that places the
kernel over an ACPI-reclaim region, a hole belonging to a device, or memory a
mechanism withheld produces a kernel whose own memory is not memory — with
the pool, which every subsystem allocates from, as the corruption surface.
That is the failure a real machine can cause that no emulator here does.

## Current state

- `src/memory/frame.rs`: `PHYSICAL_POOL` and `PHYSICAL_POOL_SIZE` — a static
  array inside the image — and `FrameAllocator`, whose `base` is the array's
  own address and whose frames are addresses inside it.  `init(total_size)`
  clamps the platform's answer to the array
  (`total_size.min(PHYSICAL_POOL_SIZE)`), so the clamp is real and the
  platform's answer is only ever able to shrink the pool.
- `src/memory/arch.rs`: `DETECTED_PHYSICAL_MEMORY` and the store/read pair.
- `src/memory/manager/init.rs`: `MemoryManager::init` inits node 0 with
  `detect_memory()`, then the heap, and prints the line above.
- `src/arch/boot.rs`: `multiboot2_memory_map`, the sum of `type == 1` entries.
- `src/arch/fdt.rs`/`src/arch/fdt/parse.rs`: the device tree's memory window.
- `src/arch/mmu.rs`: `phys_addr_of` is the machine's answer to "is this
  address its own physical address" — a window test per architecture
  (x86_64 below `BOOTSTRAP_IDENTITY_MAP_END`, AArch64's kernel text window,
  RISC-V's RAM window) — and `DmaBuffer::allocate`
  (`src/memory/dma.rs`) refuses when it answers `None`.
- `src/kernel/topology.rs`: `set_node_range` splits the *pool* between nodes.
- `docs/kernel/memory.md` "Frames": the allocator manages the array, not the
  machine's RAM, and "a board port is where that changes".

## Design

**1. A frame is an address in the kernel's own memory, and that stays.**  The
pool is not a placeholder for a physical allocator; it is the decision.  What
it buys is that *the kernel's own address of a frame is the address a device
must be given*, which is why `phys_addr_of` is a window test rather than a
page-table walk, why a DMA buffer needs no bounce copy, and why "how much
memory does this kernel have" is a constant instead of a boot-time variable.
A frame allocator over the machine's regions would need the opposite of all
three: a mapping for every frame the kernel touches, a frame-to-kernel-address
table, and reserved-region bookkeeping — a change of shape, not of size.

**2. The machine's map is asked, and used to verify — the one new job.**  The
parsers are wired to `store_detected_memory` (the Multiboot2 sum on x86_64,
the device tree's `/memory` window on the other two), and the boot checks one
thing with the answer: **the kernel's own image lies inside an entry the map
calls usable**.  The image's range is the linker's own symbols, and the pool
is inside the image, so the check covers both.

The three answers are:

| The map | Answer |
| --- | --- |
| the image is inside a usable entry | the boot continues |
| the image is outside every usable entry | the boot **refuses**, naming both ranges |
| there is no map | the boot says so and continues |

The last row is deliberate: a protocol that describes nothing (a bare ELF, or
a hand-off with no map tag) is not a machine whose memory is unusable, and
refusing there would refuse the emulators and fixtures this tree boots every
day.  It is printed rather than silent, because a machine that says nothing
about its memory is worth seeing in a log.

**3. The identity window is checked too.**  A pool outside the window
`phys_addr_of` answers for is a kernel that can allocate and cannot DMA, and
the boot knows both ranges, so it checks them and refuses with the same
loudness.  Today that failure appears as the first device driver's
`DmaBuffer::allocate` answering `None`.

**4. The boot says which memory is whose.**  The line becomes "the machine
reports X, the kernel's pool is Y" — because those are two facts and the
current one conflates them.  The pool's size is the number a kernel
subsystem's failure is about; the machine's is what the next board port
would have to work with.

**5. What is not decided here.**  Adopting the machine's regions as frames —
the shape it would take (a frame table over the usable entries, those regions
mapped into the kernel window, the image reserved out of them) and what it
costs — is named in the unresolved questions as its own RFC, and the argument
for doing it would be a *measurement*: something that needs more than the pool
has.  RAM above 4 GiB, the width of a device's DMA address, an IOMMU, and the
pool's size as a per-target constant are the same kind of question and are
listed with it.

## Alternatives

- **Adopt the firmware's usable regions now.**  Rejected for this change: it
  is a new allocator shape (non-contiguous regions, a reserved image, a
  mapping of each region into the kernel window) and the thing that would
  justify it — a workload that needs the memory — does not exist yet.  Named
  in the unresolved questions rather than half-built.
- **Keep the map unused**, which is what the tree does by accident.  Rejected:
  two parsers, an atomic, a `dead_code` excuse and a document all claim the
  machine is asked, and the check a real machine's first boot genuinely wants
  (is our image in *usable* RAM?) is the one this buys.
- **Grow `PHYSICAL_POOL_SIZE`.**  Rejected as the fix for a machine with more
  RAM: the pool is a `.bss` array the loader must place and zero, and on
  x86_64 the identity window that makes `phys_addr_of` one line ends at
  1 GiB, so the constant cannot grow far without the second decision above.
- **Size the pool from the machine**, which is what the clamp *looks* like it
  does.  Rejected as the decision: the pool is a compile-time array, so the
  machine's answer can only ever shrink it — and that makes the kernel's own
  memory a boot-time variable whose value nothing measures.
- **Refuse when there is no map.**  Rejected above: it would refuse the
  emulated boots this tree runs every day, and "not described" is not
  "not usable".

## Drawbacks

- A machine with 8 GiB still gives the kernel 512 MiB, and the RFC says so
  rather than fixing it.  The next board port is where that becomes a
  problem worth its own document.
- A new way for a boot to refuse: a loader that places the image outside the
  firmware's usable map now stops with a message instead of corrupting its
  way through a boot.  That is the intent, and it is a behaviour change.
- Two numbers in the boot line, one more check, and one more thing a port has
  to keep true.

## Compatibility and migration

No ABI change, no on-disk change and nothing to migrate.  A boot whose
loader describes its memory the way the firmware did will print one more
number; a boot that was previously running outside the map now refuses, which
is a machine that was already broken.

## How this is proven

**What landed with this RFC.**  The machine is asked, and its answer has a job:
`multiboot2_usable_regions_at` walks a Multiboot2 map into `(base, length)`
entries with the hand-off address as a parameter (so a test drives it over a
block it built), the device tree's `/memory` window is answered by
`PlatformInfo` through `platform::described_memory_window`, and
`memory::record_machine_memory` records the total in the atomic that had no
writer.  `report_machine_memory` prints the machine's number and the pool's,
checks the pool against the window `phys_addr_of` answers for, and — on a
machine — checks the kernel's own image against the map, refusing with both
ranges when the loader put it somewhere the firmware withheld.  The manager's
own line prints the pool and only the pool, because the number that wore both
names is what this removes.

- **The parser, over a map built for it**: an mmap tag with an available entry
  and a reserved one, the reserved one not counted, and a truncated block
  answering `None` rather than reading past what the header claims.
- **The check, in its three shapes**: a range inside a region the machine
  called usable, one byte past it, and an empty range — with no regions at all
  as the fourth answer.
- **A boot of each machine**: x86_64's report runs **before** the memory
  manager — its walk needs no allocation — and a device-tree machine's runs
  after the platform is described, which is after the manager, because that
  parse allocates.  The aarch64 smoke prints `machine reports 1024 MiB in 1
  region(s); the kernel's pool is 512 MiB` and `the kernel's image
  [0x40080000, 0x646612d0) is in usable RAM`, which is the placement check
  answering on a device tree rather than a fixture.
- **The no-map answer**: a hand-off that describes nothing still prints `the
  machine described no memory map; the kernel's pool is 512 MiB` — the third
  row of the table above, working.  When this document was written the
  emulated `-kernel` boots were its examples, because the PVH block was read
  for nothing but its magic.  It carries an E820-shaped memory table of its
  own (`hvm_start_info.memmap_paddr`), and that table is what the PC's direct
  boots report from now ([RFC
  0020](0020-what-the-memory-map-may-refuse-on.md) carries that change).  What
  answers "no map" today is a loader that hands over neither a tag block nor a
  table.
- **The boot that has a loader map**, which arrived with the bootable image:
  `make check-x8664-iso` boots the kernel from a GRUB ISO, and what it requires
  is this RFC's own line — `machine reports 1023 MiB in 2 region(s); the
  kernel's pool is 512 MiB`, then `the kernel's image [0x200000, 0x24893838)
  is in usable RAM` — which no emulated boot could give *at the time*, because
  QEMU's own hand-off's block was read as tags and never as a memory table.
  Asking a real loader for the kernel found two
  things first: the ELF had to lose the relocation sections `--emit-relocs`
  keeps for KASLR, because GRUB refuses them, and the loader's info block had
  never been recorded on x86_64 at all, so the tag walk (the map *and* ACPI's
  RSDP) had always read address 0.
- **Landed later**: the device-tree machines' answer reaching the manager's
  *sizing* rather than its report, through a read of the blob that allocates
  nothing.  `fdt::memory_window` is that read — a pointer walk over the
  structure block for the `/memory` node's `reg` — and every machine is now
  asked before the memory manager is built; the full parse still runs later
  for the rest of the tree.

## Unresolved questions

- **Adopting the machine's regions**, which is the shape a board port would
  want: a frame table over the usable entries, a mapping of those regions
  into the kernel's window, the image reserved out of them, and what happens
  to the pool's `.bss` when it becomes the bootstrap rather than the store.
- **RAM above 4 GiB, and the width of a device's address**: a frame above the
  first 4 GiB is memory a 32-bit DMA engine cannot reach, which is a
  bounce-buffer decision or an IOMMU one, and neither exists here.
- **The pool's size per target**: one constant for three machines is a
  default rather than a fact, and the embedded target's answer would be a
  different number.  Answered by measurement since: the size is derived per
  machine in the linker scripts, each with an `ASSERT` against the window it
  lives in (RFC 0020's "The pool's size per target").
- **What "refuse to boot" means**: decided by
  `docs/fmts/unsafe-and-safety.md` §9 — a terminal halt with a message, on
  the panic path, in the boot path only (RFC 0020's carried-forward copy of
  this question has the fuller answer).
