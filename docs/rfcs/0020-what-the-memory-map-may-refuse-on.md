# RFC 0020: What the memory map may refuse on

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-11
- **Supersedes:** 0019

## Summary

This supersedes RFC 0019's **placement check**; everything else that document
decided stands, and its §5 is restated below so a reader of one has the whole
decision.  RFC 0019 had the boot refuse when the kernel's image was not inside
RAM the loader's memory map called **usable**.  A real UEFI boot showed that the
question is unanswerable and the refusal therefore wrong: a loader reserves
exactly the memory it loads the image into, so a *correct* map never calls the
image's own range usable.  This decides what the check may ask instead — whether
the map **describes** where the image is, and whether what it says there is
defective — and what it may only report: the holes inside the image, which are
a loader's own reservations.

## Motivation

The check was written from a fixture's point of view and passed on the maps the
emulated boots give, which are coarse enough to cover the payload in one entry.
Under OVMF the map is granular — seven entries on the boot that found this — and
the image, 570 MiB of it because the frame pool is 512 MiB of `.bss`, spans
several of them:

```
[mem   ] FATAL: the kernel's image [0x200000, 0x24895168) is in no region the machine calls usable
[mem   ]   the machine offered [0x100000, 0x800000)
[mem   ]   the machine offered [0x808000, 0x80b000)
[mem   ]   the machine offered [0x80c000, 0x814000)
[mem   ]   the machine offered [0x900000, 0x3ed3f000)
```

Two things are true of that boot, and only the second is a defect.  The image
**does** span a gap (0x814000–0x900000) the map does not describe, and the
reason is the loader: it put the image there and reserved the memory for it.
And the image is not inside any entry the map calls available, which is what a
map is *supposed* to say about memory that is not free — the payload is not
free memory, it is the thing running.

So the refusal fires on every correct boot of that shape, which is the opposite
of what a gate is for.  The lesson is the one this tree keeps learning: a check
written against the maps a fixture produces is a check that has never met a
machine.

## Current state

- `src/memory/arch.rs`: `record_machine_memory`, `range_is_in_usable_memory`
  (a range walked piecewise across regions, because a granular map cannot
  contain it in one), `report_machine_memory`, and the two checks it makes
  before the memory manager is built.
- `src/arch/boot.rs`: `multiboot2_usable_regions_at` collects entries whose
  **type is 1** — available — and drops the type with them, so the check cannot
  tell "reserved by the loader" from "defective" ([RFC
  0019](0019-what-a-frame-is.md)'s walk, as it landed).
- `src/arch/platform.rs`: `described_memory_regions`, which answers the same
  shape for a device tree's single `/memory` window.
- The image's range is the linker's own symbols
  (`memory::arch::kernel_image_range`), and it is 570 MiB because
  `frame::PHYSICAL_POOL` lives in `.bss`.

## Design

**1. The regions keep their types.**  `multiboot2_usable_regions_at` becomes
`multiboot2_memory_regions_at`, answering `(base, length, type)` for **every**
entry the map has, because the type is the map's own word about what the memory
is and the check needs it.  The device-tree machines answer one region of type
1: a device tree describes the RAM it describes, and that is the whole of what
it says.

**2. What the boot asks.**  Two questions, and the refusals that follow:

- **Where is the image?**  The image's first and last byte must land inside
  entries the map *describes* — any type except 5, defective.  A map that is
  silent about the address the loader just loaded the kernel at is a map this
  kernel cannot trust about anything else, and that is the refusal that stays:
  `the kernel's image is in no region the machine describes`.
- **Is any of it defective?**  Every piece of the image's range that lands in an
  entry of type 5 is a piece of memory the firmware has already declared broken,
  and the boot refuses: `the kernel's image overlaps defective memory`.

**3. What the boot only reports.**  Holes inside the image's range — addresses
the map describes with no entry — and regions it calls reserved: printed, with
their ranges, and then the boot continues.  They are the loader's own
reservations, which is what the memory the kernel runs from looks like from
outside; refusing on them refuses every correct boot.

**4. Why this is still a check.**  The thing it exists to catch is a loader that
put the kernel somewhere the firmware's own tables do not describe at all — an
MMIO hole, memory the firmware withheld — and that is the case the first
question refuses on.  The check is weaker than it was written to be, and the
reason is worth as much as the check: **the map cannot answer the stronger
question, because the answer to it is always "no".**

**5. What carries over from RFC 0019.**  Everything else: a frame is an address
in the kernel's own memory; the pool is the machine's memory as far as this
kernel is concerned; the machine is asked, and its answer is recorded, printed
and checked against — never allocated from; every machine asks before the memory
manager is built — x86_64's map is a walk over the loader's block, and a device
tree's `/memory` window is a walk over the blob, and neither allocates — and the
boot line names the machine's number and the pool's separately.  A device
tree's full parse still runs later, for the rest of what the tree describes.

## Alternatives

- **Refuse whenever the image is not in available memory** (what the code did).
  Rejected: it refuses every map that is honest about the loader's own
  reservation, which is every UEFI boot.
- **Report everything and refuse nothing.**  Rejected: a map that does not
  describe the address the kernel is running from is a real failure — the
  firmware and the loader disagree, or the kernel is in a window that is not
  RAM — and no later symptom would say so as clearly.
- **Ask only about the image's first page.**  Rejected: a kernel whose `.bss`
  runs into a defective region is broken in a way the first page cannot see,
  and that is what question 2 is for.
- **Shrink the image so the question gets easier** (the pool is 512 MiB of
  `.bss`).  Not this RFC: the pool's size is RFC 0019's decision and a board
  port's question; what this one fixes is asking a question the map can answer.
- **Keep the check and let it refuse only when a gate runs it.**  Rejected: a
  refusal that only some configurations reach is a machine that boots or does
  not depending on where it was built.

## Drawbacks

- The check is weaker, and the weakening is deliberate: it no longer refuses
  "the image is in memory the map calls reserved", because the loader reserves
  it on purpose.
- One more field in the region type, one more shape for the device-tree
  machines to answer, and one more line of a boot log.

## Compatibility and migration

No ABI change, no on-disk change.  A boot that used to refuse now continues,
which is the point; a boot whose loader describes nothing about the image's
address still refuses, and that boot was already broken.

## How this is proven

- **The types survive the walk**: the Multiboot2 parser's test asserts the
  region list for a map with an available entry, a reserved one and a defective
  one — the three kinds the two questions turn on.
- **The questions, on the map that found this**: the OVMF map of the boot below,
  as a fixture — an image the map describes but does not call available (the boot
  continues), the same image with its first byte outside every entry (refused),
  and a range overlapping a defective entry (refused).
- **The boot that has a map at all**: `make check-x8664-iso` boots the image
  through BIOS *and* through OVMF, requiring the loader's hand-off, the
  machine's own map, the image described in it, no refusal, and the shell.  The
  UEFI half is the map this RFC exists for: a granular one, whose payload the
  map calls **reserved**, which is what the refused boot taught.

**What that pass found, and fixed.**  Two defects, both of which only a second
firmware could have shown:

- The kernel **wrote a page its own plan had made read-only**.  The free-PCID
  bitmap was an all-zero array of `u64` — immutable data, so the compiler placed
  it in `.rodata` — and the PCID path wrote it through a pointer cast to
  `&AtomicU64`.  It is an array of `AtomicU64` now: writable storage, with no
  cast and no `unsafe` between the storage and its use.
- Underneath it, a **hang**.  The bitmap search skipped the bits it must not
  hand out (PCID 0 belongs to the kernel) while its compare-exchange still
  expected the *masked* word, so it could never succeed: a spin with interrupts
  off.  The timer tick stopped with it, the console's serial bridge lives in the
  tick, and typed input stopped reaching the shell — which is what made
  `make check-x8664-runtime` red.  The compare-exchange expects the value that is
  in memory now, the search's own half is a pure function with a test, and that
  gate runs in CI.

**Four explanations the search refuted**, each by measurement rather than
argument: the pool moving, the bitmap overlapping the pool, a stale KASLR
relocation list, and `.bss` being handed over non-zero.  They are worth not
repeating, and this paragraph is where they are named rather than the design.

**What landed after it.**  RFC 0019's still-owed read — the device-tree
machines' answer reaching the manager's *sizing* — is `fdt::memory_window`: a
pointer walk over the blob's structure block for the first `/memory` node's
first `reg`, inheriting `#address-cells`/`#size-cells` from the root, with no
allocation and no `PlatformInfo`.  The boot entry calls
`report_machine_memory` for all three machines before `Kernel::new`, so the
manager is sized from the machine's answer and the report is printed before
the manager's own line; a device tree's full parse keeps its place for
everything else the tree describes.  The aarch64 and riscv64 runtime checks
assert the order (`[mem   ] machine reports …` before `Memory manager
initialized`), and the manager's line names the pool's size rather than the
machine's number that sized it.

**What landed from the questions below.**  The UART half of the tick's device
polling is a real interrupt now: the IOAPIC routes IRQ 4 to `COM1_VECTOR`,
`ioapic_setup_isa_irqs` arms the 16550's received-data interrupt once that
route exists, and the handler drains the FIFO through
`drivers::serial::handle_rx_interrupt` — the same drain-and-bridge path the
tick used to call, now with input no longer depending on the tick running at
all.  `make check-x8664-runtime` types at the shell and asserts the handler's
own one-time line, so the path is a gate rather than a code path.  xHCI and
virtio-input still poll from the tick, and so do the device-tree machines'
UARTs, which is what the question below now covers.

## Unresolved questions

- **Adopting the machine's regions as frames** (RFC 0019's question, carried
  forward here): a frame table over the usable entries, those regions mapped
  into the kernel's window, and the image reserved out of them.  The argument
  for it would be a measurement.
- **RAM above 4 GiB, and the width of a device's address**: a frame above the
  first 4 GiB is memory a 32-bit DMA engine cannot reach, which is a
  bounce-buffer decision or an IOMMU one, and neither exists here.
- **The pool's size per target, and where it sits**: one constant for three
  machines is a default rather than a fact, and the array is *movable* — one
  small static shifted it twice during this RFC's own work.  Pinning an address
  that a frame allocator measures everything from is a change that should argue
  for itself.
- **What "refuse to boot" means**: the tree's panic policy is
  `docs/fmts/unsafe-and-safety.md`'s, and whether this is a halt with a message
  or a panic is that document's to say.
- **The device polling that lives in the timer tick**: xHCI and virtio-input
  still poll from the tick handler, and so do the device-tree machines' UARTs,
  so a spin there takes their input with it.  x86_64's UART half landed (see
  above); the other machines' interrupt paths and the two USB/input polls are
  the part still named rather than half-built.
