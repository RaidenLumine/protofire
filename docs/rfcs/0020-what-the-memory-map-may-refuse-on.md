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
  (which now walks a range piecewise across regions, because a granular map
  cannot contain it in one), `report_machine_memory`, and the two checks it
  makes before the memory manager is built.
- `src/arch/boot.rs`: `multiboot2_usable_regions_at` collects entries whose
  **type is 1** — available — and drops the type with them, so the check cannot
  tell "reserved by the loader" from "defective".
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
and checked against — never allocated from; x86_64 asks before the memory
manager is built, the device-tree machines after their parse; and the boot line
names the machine's number and the pool's separately.

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
  one — the three that decide the two questions.
- **The questions, on the map that found this**: the seven-entry OVMF map of
  the boot above, as a fixture — the image described but not available (the boot
  continues), the same image with its first byte outside every entry (refused),
  and a range overlapping a defective entry (refused).
- **The boot**: `make check-x8664-iso` boots a loader's map on the BIOS path,
  and the UEFI boot this RFC exists for was run by hand — with OVMF, the same
  ISO, and the map that used to refuse it:
  `machine reports 1017 MiB in 20 region(s)` followed by `the kernel's image
  [0x200000, 0x24894058) is described: 0 KiB in no entry, 0 KiB reserved`, no
  refusal, and the boot continuing into its drivers.  What that boot does not
  give is the *framebuffer* tag the ISO work is after: on UEFI this GRUB passes
  none at all, and on BIOS it passes an EGA text one, so the framebuffer a
  loader hands over is still unwitnessed.

## Unresolved questions

- **A UEFI pass for the ISO check, and the two things it found**: the pass was
  written, run, and *not* kept, because it does not pass — and what it found is
  worth more than the pass.  The first was a write into read-only memory, and
  it is fixed:

  ```
  [FATAL] page fault addr=0x00000000004ed388 access=write reason=protection-violation
          prepared_perms=r-- plan=kernel-rodata
          rip=0x000000000046d596
  ```

  and both addresses named the same thing: the instruction was
  `core::sync::atomic::atomic_or`, the address was
  `protofire::arch::x86_64::paging::pcid::PCID_BITMAP_STORE`.  That static was an
  all-zero array of `u64`, which is immutable data — so the compiler placed it in
  `.rodata`, where `nm` marked it `r` — and the PCID path wrote it through a
  pointer cast to `&AtomicU64`.  It is an array of `AtomicU64` now: read-write
  storage (`.bss`), with no cast and no `unsafe` between the storage and its
  use.  The UEFI boot gets past the point it faulted at, further than it had
  ever gone, and the BIOS boot is unchanged.
- **The fix that did not work, measured**: the static became an array of
  `AtomicU64` — read-write storage, no cast, no `unsafe` — and the UEFI boot got
  past the fault, further than it had ever gone.  But **both firmwares then
  stalled** after `[init  ] init path from cmdline: /system/init.elf`, where the
  BIOS boot of the same image reached the shell in under a minute.  Two rounds
  of measurement narrowed it, and each one refuted a story that had looked
  obvious:

  | Build | pool | the bitmap | boot |
  | --- | --- | --- | --- |
  | as it is | `[0x484e000, 0x2484e000)` | `.rodata` | reaches the shell |
  | the fix | `[0x484e000, 0x2484e000)` | `.bss`, `0x24891350` (outside the pool) | stalls after the init path |
  | the fix, with the KASLR list regenerated | same | same | still stalls |

  So the pool does not move, the bitmap is inside nothing, and the KASLR
  relocation list — a build artifact this tree *ignores* in git and writes with
  `make gen-kaslr-relocs`, a target no build runs — is not the cause either:
  regenerating it and booting the **unchanged** kernel reaches the shell.  What
  is left is the static's *own* address: `0x24891350` is in the region after
  the frame pool, and the one thing that is special about that region is that
  the kernel's page plan has to have named it.  The next probe is the plan's
  own report for that page in the two builds (`active paging check` prints the
  class and permissions of the pages it is asked about), because a write that
  neither faults nor does what the code means is what a page mapped for
  something else looks like.
- **What the pass waits on**: for the boot to reach
  `[user  ] loaded /apps/packages/shell/bin/shell.elf` on both firmwares again
  with whatever fixes the placement, at which point the pass lands with the
  assertions it was written for.- **What the pass waits on**: for the boot to reach
  `[user  ] loaded /apps/packages/shell/bin/shell.elf` on both firmwares again
  with whatever fixes the placement, at which point the pass lands with the
  assertions it was written for.
- **The pool as `.bss`** — the reason the image is 570 MiB and spans regions at
  all — is RFC 0019's decision to keep and a board port's to revisit.
