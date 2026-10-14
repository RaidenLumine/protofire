# RFC 0026: Install the system pair, not one slot

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-14
- **Supersedes:** none

## Summary

An install writes the system zone as the **pair** it is read as: both slots,
A committed older and B newer with the same vocabulary the demo disk uses, so
a boot of an installed disk takes B and withdrawing B's marker hands the
machine back to A.  The three zones become four partitions — the pair, apps,
data — and the change is what makes rollback exist on a machine from its
first boot rather than only after a first update.

## Motivation

[docs/status.md](../status.md)'s installation row recorded the gap in its own
words: "the boot takes whichever system slot the install wrote, which on a
fresh disk is the only one".  The consequence is not cosmetic.
`install_system_build` (`src/fs/system_image.rs`) writes a newer volume into
"the slot that is not active" and answers `NotFound` from its
`slots.iter().find(|slot| slot.slot != active.slot)` lookup when no other
slot exists — so on a disk the installer wrote, an update has nowhere to
land and a rollback has nothing to go back to.  The pair is the design the
boot already implements: `system_slots` discovers two, `select_system_slot`
takes the highest committed generation, and `withdraw_active_build` gives the
machine back to the other.  The install was the one writer that did not
produce the shape the reader expects.

## Current state

- **`src/fs/install.rs`.**  `place_zones` wants three extents — one
  `System`, one `Apps`, one `Data` — and each zone's image comes from
  `demo::build_zone_image`, which for `System` is slot A's build
  (`DEMO_SYSTEM_SLOT_A_GENERATION`, generation 1).  A zone the table already
  carries keeps its extent; every other entry is an obstacle.
- **`src/fs/demo/mod.rs`.**  `build_zone_image` builds A's system image;
  `build_demo_disk_image_with_table` builds the demo disk's second slot from
  `content::system_zone_image(DEMO_SYSTEM_SLOT_B_GENERATION)` (generation 2).
  The generations live in `src/fs/layout.rs` as
  `DEMO_SYSTEM_SLOT_A_GENERATION`/`DEMO_SYSTEM_SLOT_B_GENERATION`.
- **`src/fs/system_image.rs`.**  The pair's semantics: a slot is committed
  when its volume carries `/etc/build`; a boot takes the highest committed
  generation; `install_system_build` needs an inactive slot;
  `withdraw_active_build` removes only the marker.
- **`src/fs/partition.rs`.**  A GPT answers the pair as "the first two
  entries of the system type, in array order" (MBR answers slots 0 and 3);
  `write_gpt_preserving` gives each entry the first unclaimed slot with its
  type GUID, else the first free slot, scanning from index 0.
- **`scripts/check-x8664-install.sh`.**  The gate: `sgdisk`-made disk with a
  stranger, `--yes` install, table read back, boot to a typed answer,
  reinstall reuses every extent; the blank-disk section boots a fresh GPT.
  It counts three placed/reused entries and asserts no system-slot line.

## Design

**1. Four partitions, three zones.**  `place_zones` wants, in this order:
System (build 1), System (build 2), Apps, Data.  The pair precedes the other
zones so a writer that scans for free slots from index 0 places A before B by
construction on a fresh disk.  Sizes are unchanged (`DEMO_DISK_SYSTEM_BLOCKS`
each), so an installed disk grows by one 128 KiB extent.

**2. The pair keeps extents by position, not by GUID alone.**  A disk may
carry zero, one or two entries of the system type:

| Existing system entries | A | B |
| --- | --- | --- |
| none | free space | free space |
| one (an install from before this change) | keeps it | free space — the reinstall **adds** the missing slot |
| two | keeps the first | keeps the second |

An entry is "first/second" in the table's own order, which is what the boot's
`system_partitions` reads.  A zone entry smaller than the volume needs is
still `NoSpace`, and a third system-type entry is an obstacle like any
stranger's.

**3. The generations are the demo disk's vocabulary.**  A commits
`DEMO_SYSTEM_SLOT_A_GENERATION` (1) and B commits
`DEMO_SYSTEM_SLOT_B_GENERATION` (2): B is newer, so a boot of a fresh install
takes B, and withdrawing B's marker boots A.  Reusing the constants rather
than writing two new numbers keeps one vocabulary for "which slot is newer",
and the install's volumes are built by the same
`content::system_zone_image(generation)` the demo disk's are.

**4. A reinstall lays down the system it ships.**  Both slots are rewritten
to the shipped generations.  This is deliberate and worth stating: a machine
whose slots carry later updates (B = 5) reinstalled from an older medium
goes *backwards* to B = 2, because an install means "run the system this
installer carries" rather than "keep the newer of two".  The update path is
`install_system_build`'s and is unaffected.

**5. The report says what was written, by build.**  `InstalledZone` gains
`build: Option<u64>` — `Some` for the pair's two entries, `None` for the
other zones — and the plan and report print it ("build 1"/"build 2").  The
boot's slot letters (`system: slot b active (build 2)`) are the **table's**
array order and are not claimed by the report; selection is by generation, so
even a layout where a kept system entry sits above a free slot — the pair's
letters then swapped relative to build order — boots and rolls back
correctly.  The gate asserts the normal case (both entries placed fresh,
letters and builds agreeing), and the unresolved questions keep the corner.

**6. What does not change.**  The plan-equals-install contract, the
confirmation, the blank-disk predicate, `write_gpt_preserving`'s copy-back of
stranger entries, and the volume image itself: A's volume is byte-identical
to what the old install wrote, and B's is the demo disk's second slot.

## Alternatives

- **Keep writing one slot.**  Rejected: it is the gap this RFC exists for —
  an update refuses (`NotFound`) and a rollback has no other slot.
- **Write B's volume but leave it uncommitted.**  Rejected: the slot would be
  dormant until something committed it, so a fresh disk would boot A and
  exercise none of the pair's machinery — the reasoning the demo disk already
  uses ("B committed as the newer build, so every runtime check boots the
  pair's selection") applies to an installed disk for the same reason.
- **Preserve a higher generation found on the disk.**  Rejected: it makes a
  reinstall neither idempotent nor predictable — the installer would have to
  decide which of two systems is "the" system, and the answer a machine's
  operator wants from an install is the one on the medium.
- **A `--rollback`/`update` command on the host tool, now.**  Not taken: the
  library calls exist and are tested; a command is an interface of its own
  and is left to the change that needs it (unresolved questions).
- **Ordering the pair by promised letters rather than by placement.**  Not
  taken: `write_gpt_preserving`'s search is "type GUID, else first free",
  which places both fresh entries in ascending slots; forcing order for the
  exotic kept-above-free layout would mean threading slot preferences through
  the writer to make a log letter prettier, while generation selection — the
  thing rollback rests on — is already order-independent.

## Drawbacks

- The install builds and writes a second system volume: one more image build
  and 256 more blocks on the installed disk, and the plan prints four lines.
- A reinstall clobbers an updated pair (design §4), which is a behaviour
  a person could reasonably expect the other way; it is written down here
  and in the module comment so it is a decision rather than a surprise.
- The census row for Disk installation grows a clause.

## Compatibility and migration

No format change: the pair, the marker, the selection and the table's pair
rule all exist.  A disk installed before this change carries one system entry
and keeps booting it; a reinstall adds the second slot and the generations
(the missing-slot row of design §2).  The report's new field is additive; the
gate's counts move from three to four.

## How this is proven

- **Unit tests in `src/fs/install.rs`**: an install on a machine's disk
  writes **both** system volumes — read back through `system_slots`, two
  committed slots whose generations are 1 and 2, and `select_system_slot`
  takes B — and `withdraw_active_build` hands the selection back to A
  (rollback, on the installed bytes).  The reinstall row of the table: an
  old single-slot disk gains the missing B slot on reinstall, and the second
  install reuses all four extents.  The plan-equals-install test covers the
  pair because the plan carries the same structs.
- **`scripts/check-x8664-install.sh`**: the `sgdisk` disk's install is four
  entries ("placed" count 4, then 4 "reused" on the reinstall), the plan and
  the report name both builds, and the boot of the installed disk must print
  `system: slot b active (build 2)` — the line that says the pair was
  written, committed, and selected.  The blank-disk section reads the fresh
  table back as four partitions and boots to the same line.
- **The gate's judgement was measured** — three negative runs, each failing
  on the check that exists for it: with one system slot wanted, `expected
  the four extents to be placed, saw 3 placed`; with B committing the older
  generation, `the install did not place the newer system slot (build 2)`;
  and with the written marker one generation off the plan, `missing log
  line: [fs    ] system: slot b active (build 2)`.

## Unresolved questions

- **Update and rollback have no host command.**  `install_system_build` and
  `withdraw_active_build` are library calls of `src/fs/system_image.rs`;
  a machine can only be updated by a program inside it (and nothing calls
  them there yet) or by a new host command.  Which shape a release channel
  wants is its own decision.
- **The letters-versus-builds corner**: a kept system entry above a free slot
  gives an installed pair whose table order is (build 2, build 1), so the
  boot's letters swap relative to build order.  Selection and rollback are
  by generation and unaffected; a reader of the log could still be misled,
  and the fix — if it is worth one — is in the writer's slot preference.
- **A third system-type entry** on a machine's disk is an obstacle, not an
  error: nothing says whether such a disk should be refused or repaired.
