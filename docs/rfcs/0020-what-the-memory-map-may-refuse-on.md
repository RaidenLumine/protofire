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
  (`memory::arch::kernel_image_range`).  When this document was written it was
  570 MiB because `frame::PHYSICAL_POOL` was a 512 MiB array in `.bss`; the
  pool is a reservation after `__image_end` now, so the range the check asks
  about is the loaded content (see "The pool's size per target" below for what
  the measurement found and changed).

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
initialized`).

The pool's own placement followed from the measurement above: it is reserved
address space now, outside the boot's clear and outside every loadable
segment, and `managed_pool_bytes` is the walk that turns the machine's
regions into the length the allocator is sized with.  The manager's line
therefore names the **managed** span — on every machine measured before the
small-RAM work those numbers were the same, and a boot where they differ
prints both, so the line and the machine's report cannot disagree without
saying so.

**The PC's direct boot answers a map at last.**  The PC's direct hand-off was
the last one with no answer: its block was read for its magic and nothing
else, so a direct `-kernel` boot reported "no memory map" and
`managed_pool_bytes` fell back to the pool's whole span — a machine smaller
than the span would manage memory that is not there.  Xen's `hvm_start_info`
carries one from version 1:
`memmap_paddr`/`memmap_entries`, an E820-shaped table of 24-byte entries whose
types are E820's, which `arch::boot::pvh_memory_regions` walks after checking
the block's magic (a hand-off that is not one answers nothing, which is the
rule every other reader of these blocks follows).  QEMU `q35` writes nine
entries; the RSS is what is bounded rather than trusted — a table longer than
the walk will read, or one that runs past the bootstrap map, is refused whole.
The `check-x8664-runtime` 512 MiB segment asserts both halves now: the machine
reports its number *and* the boot says which part of the pool's span it has.
Every boot of every machine answers a map today — a tag block, that table, or
a device tree's `/memory` — and what still answers "described nothing" is a
hand-off with none of the three.

**What landed from the questions below.**  The UART half of the tick's device
polling is a real interrupt now, on every machine whose controller can carry
one: the handler drains the FIFO through
`drivers::serial::handle_rx_interrupt` — the same drain-and-bridge path the
tick used to call — and each machine routes and arms its own line once the
interrupt controller is up (`arch::interrupt_controller::init`): the IOAPIC's
IRQ 4 to `COM1_VECTOR` on x86_64, the GIC's SPI 33 for the PL011 on aarch64,
the PLIC's source 10 for the 16550 on riscv64, and on an AIA machine the same
source through the supervisor APLIC domain, which composes the MSI that
carries identity 10 into the IMSIC.  All four runtime checks
type at the shell and assert the handler's own one-time line, so each path is
a gate rather than a code path.  xHCI and virtio-input still poll from the
tick, which is what the question below now covers.

A refused claim no longer costs input silently either.  The device-tree
machines set `rx_is_interrupt_driven` from what the claim and the controller
write actually did, so a console UART that could not be armed keeps the tick's
poll — and the claim that loses its identity is *reported*, not discarded into
a `let _ =`.  That is what the GICv3 segment of `make check-aarch64-runtime`
found the moment it was typed at: the registry indexed every window by
`identity - base`, so the LPI 8193 an ITS had registered and the wired SPI 33
the console claimed were the same slot, the UART's claim was refused in
silence, and a byte typed at the console ran the block driver's handler.  Each
base has a window of its own now (`src/arch/irq_handlers.rs`), the aarch64
segment types at the shell and asserts the UART's own line, and the second
controller's delivery is a gate rather than an assumption.

Wiring the two device-tree machines found two defects in the aarch64 GICv2
path that nothing had reached before, because the timer was its only interrupt
and the timer's tick is read from the counter's own status rather than from a
claim: `GICD_ITARGETSR` was at the wrong offset (0x1800 for 0x800, so the
first SPI routing aborted), and the CPU interface was not acknowledging Group
1 (`GICC_CTLR.AckCtl`), which hides every Group 1 interrupt from a Secure
`GICC_IAR` read with 1022.  Both are fixed where they were found, and the
device-tree machines' input now arrives by interrupt.

## Unresolved questions

- **Adopting the machine's regions as frames** (RFC 0019's question, carried
  forward here): a frame table over the usable entries, those regions mapped
  into the kernel's window, and the image reserved out of them.  The argument
  for it would be a measurement.
- **RAM above 4 GiB, and the width of a device's address**: measured, and
  latent rather than live.  **No frame the allocator can hand out is above
  the first 4 GiB**, and the reason is structural: the pool is the kernel's
  own reserved span, placed by the linker right after the image, and the
  runtime tables identity-map the kernel's own windows — so the pool's
  address does not move when the machine's RAM grows.  Measured with **one
  binary** on `q35` at 1 GiB, 2 GiB, 8 GiB and 16 GiB: `the pool is
  [0x489b000, 0x2489b000)` in all four boots.  (Across *builds* the address
  drifts by the image's size — the 2 GiB boot two commits earlier read
  `0x4898000` — which is the linker moving `__pool_end`, not the machine; a
  reader comparing two logs should expect that.)  The device-tree machines
  are the same shape: at 16 GiB the pool is `[0x45800000, 0x65800000)` on
  aarch64's `virt` and `[0x85600000, 0xa5600000)` on riscv64's, each right
  after its image.  Every one of those ends below the 4 GiB a 32-bit engine
  can name, so there is nothing to bounce today, and no code should pretend
  otherwise.
  The question becomes live with the *first* item above, and only with it:
  frames taken from the machine's regions can land anywhere the machine put
  RAM, and that is the change that has to decide what a high frame costs.  A
  board whose loader puts the *kernel* above the window its runtime tables
  identity-map hits a different bound first, and this machine names it: the
  static x86_64 tables cover the first gigabyte
  (`STATIC_KERNEL_TABLES_END`), the device-tree machines map their 1 GiB RAM
  windows, and `pool_is_addressable_by_a_device` refuses a boot whose pool
  does not fit, with the range in the message.
  When the frame-table change lands, the width to honour is **per device**,
  not one bound for all of them: every device this tree drives writes a
  64-bit address — NVMe PRP entries (`set_prp1`, and the pair `run_prp`
  builds as `u64`), virtio's descriptor layout (`drivers/virtio.rs`),
  xHCI's TRBs (`Trb::link` takes a `u64` in `xhci_protocol.rs`, and the
  runtime registers go through `reg_write64_lo_hi`), HDA's CORB/RIRB/BDL
  base registers (written as low and high halves — `HDA_CORBLBASE` beside
  `HDA_CORBUBASE`, `HDA_SDBDPL` beside `HDA_SDBDPU`) — so a 32-bit-only
  device would be the trigger, and the
  allocator would need a per-request reachability the way it has a per-node
  one.  What the first measurement of a bigger machine *did* find is one
  layer below this question: the PC could not boot on RAM above 1 GiB at all.
  The firmware moves its ACPI tables above the first gigabyte once there is
  more RAM (measured on `q35`: the RSDT is at 0x3ffe2351 with 1 GiB,
  0x7ffe2351 with 2 GiB), the boot parses RSDT → MADT → SRAT/SLIT before the
  runtime page tables exist, and the bootstrap identity map covered exactly
  1 GiB — so the first table entry faulted before the console had said
  anything else.  Every gate booted 1 GiB, so no check had ever met the
  shape.  The bootstrap map is four gigabytes now
  (`BOOTSTRAP_IDENTITY_MAP_LENGTH`) and `check-x8664-runtime` boots 2 GiB as
  a segment of its own.
- **The pool's size per target, and where it sits**: answered by measurement.
  The pool was a 512 MiB array in `.bss` that the boot cleared, and the clear
  is what a small machine died of: asked for a smaller RAM than the image
  spanned, the aarch64 check's own kernel printed **nothing at all** at 528
  MiB and booted at 640 — the fault was the clear's first store past RAM,
  before the console existed.  Worse, the pool inside a loadable segment made
  a smaller machine fail *earlier* on riscv64, where the loader refused the
  ELF outright (`No enough memory to place DTB after kernel/initrd`, because
  five hundred megabytes of the image were a segment's `p_memsz`).  The pool
  is reserved address space now, placed by each linker script after the
  initialised data and outside every loadable segment, and what the allocator
  manages inside it is the machine's answer
  (`memory::arch::managed_pool_bytes`); the boot prints both when they differ,
  and 512 MiB boots a shell on all three machines where it used to die.  The
  span is still one constant for three machines — a board port's decision —
  and a hand-off that describes nothing at all still manages the whole span,
  which is the boot the report names rather than a silent one.
- **What "refuse to boot" means**: the tree's panic policy is
  `docs/fmts/unsafe-and-safety.md`'s, and whether this is a halt with a message
  or a panic is that document's to say.  The small-RAM work gave it a second
  subject: a pool that starts past everything the machine describes is a boot
  with no frames at all, and it refuses at `[mem   ]` with its answer rather
  than faulting somewhere unrelated.
- **The device polling that lives in the timer tick**: answered by
  [RFC 0021](0021-what-the-timer-tick-still-polls.md).  Both remaining polls
  stay, for different reasons — xHCI's tick drain because the ring's lock
  means an interrupt that acknowledges cannot always drain, so the tick is
  what drains what it left, and `virtio-input`'s because the MMIO transport
  has no identity to claim — and that document names what would reopen each.
