# RFC 0019: Make a frame an address in the kernel's own memory

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-11
- **Supersedes:** none

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

- **The parsers, on a map built for them**: the Multiboot2 tag walk and the
  device tree's `/memory` window driven over constructed inputs, so the
  "ask the machine" half is a unit test rather than a claim about a boot.
  Where a parser reads a hand-off address from a global, the test drives the
  address-taking function and the global is a wrapper around it.
- **The check, on the three answers**: a map that contains the image (boots),
  a map that excludes it (refuses, with both ranges in the message), and no
  map (continues, and says so) — each a function's answer rather than a
  boot's behaviour.
- **The window check**: a pool range that ends outside `phys_addr_of`'s
  window refuses, and the real one does not.
- **The boot line**: the smoke boots' logs name both the machine's number and
  the pool's, which is what makes the number a reader sees attributable.

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
  different number.
- **What "refuse to boot" means**: the tree's panic policy is
  `docs/fmts/unsafe-and-safety.md`'s, and whether this is a halt with a
  message or a panic is a detail that document decides rather than this one.
