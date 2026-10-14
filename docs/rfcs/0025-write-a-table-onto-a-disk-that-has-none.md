# RFC 0025: Write a table onto a disk that has none

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-14
- **Supersedes:** none

## Summary

The install path refuses a disk that carries no partition table, and
[docs/status.md](../status.md) records that as deliberate: "a disk with no
table is refused rather than partitioned".  This decides how that refusal
becomes a **decision the caller can make**: a second entry point —
`install --new-table` — that writes a fresh GPT, but only onto a disk that
carries no partition information *at all*, and refuses everything else
exactly as before.  The default stays the refusal; the flag, not the disk's
looks, is the consent.

## Motivation

A machine's disk that was never partitioned is the one disk an installer
cannot help under the current rule: `install_zones_into_disk_image` demands a
verified GPT and answers `NotFound` otherwise, and the module's own comment
says why — "writing a table onto a disk someone else partitioned is a
decision this module does not make".  That is the right default.  It is the
wrong *only* answer, because the decision has a case where it is easy: a disk
whose bytes are not a table — no partitions, no signatures, nothing a reader
would believe — is a disk with nothing to preserve, and refusing to ever
partition it means the installation path can only ever run on disks some
other tool got to first.

The roadmap lists the remaining installation work as "a user interface and a
confirmation (the disk-side operation is the module), and creating a table on
a disk that has none, which is a partitioning decision this kernel
deliberately does not make" ([ROADMAP.md](../../ROADMAP.md)).  This RFC is
the second of those, and it keeps the first in mind: a confirmation is a
caller saying yes, and "which caller said yes to *this*" is part of the
interface being decided here.

## Current state

- **`src/fs/install.rs`.**  `install_zones_into_disk_image(disk)` reads the
  table (`read_gpt_layout_from_bytes`), answers `NotFound` when there is
  none, plans in the span the table states (`place_zones` +
  `find_gap`), writes each zone volume over a zeroed extent, and rewrites the
  table with `write_gpt_preserving`.  Its module comment states the line this
  RFC moves: "What it deliberately does not do: create a table that is not
  there".
- **`src/fs/partition.rs`.**  Two writers live here already.
  `write_gpt_partitions` is the **fresh** writer the demo builder uses: it
  writes the protective MBR, both header copies and the entry array, with
  `GptGeometry::fresh` for the span.  `write_gpt_preserving` is the
  installer's: it requires a *verified* table to preserve and copies every
  entry it does not claim back byte for byte.  The readers
  (`read_gpt_from_bytes`, `read_gpt_layout_from_bytes`) verify the
  signature, the header's CRC-32 and the array's, and answer `None` for
  anything that does not hold — a damaged header is "no table" to them.
- **`src/main.rs`.**  `install <disk>` reads the disk whole, installs in
  memory, and writes the file back only on success — which is what makes a
  failed install leave the disk byte-identical.
- **`scripts/check-x8664-install.sh`.**  The gate: an `sgdisk`-made disk
  with a stranger's partition, the install, a table read-back with `sgdisk`,
  a boot to a typed answer, and a second install that reuses every extent.
- **RFC 0018** decided the read side and the two writers' invariants; its
  "What is not decided here" said writing was its own change, which has
  since landed.  A disk that is a **hybrid** — MBR entries that also name a
  GPT — remains unread, and the unresolved questions there still hold.

## Design

**1. "No table" is a predicate, not an impression.**  The disk must answer
all three of these before a fresh table is allowed:

| Question | Answered by | A "yes" means |
| --- | --- | --- |
| A verified GPT? | `read_gpt_layout_from_bytes` | a table is there — refuse |
| MBR entries, protective included? | `mbr_has_partitions` | something partitioned the disk — refuse |
| A GPT signature, checksum or not? | `gpt_signature_present` | a **damaged** table — refuse |

`mbr_has_partitions` is the same criterion the device-side MBR reader uses —
an entry whose boot flag or type byte is non-zero — so a protective MBR
(`0xEE`) counts, and a sector with the signature and four empty entries does
not.  `gpt_signature_present` deliberately stops at the signature: bytes
that *declare* a GPT are a table, and a table that failed its checksum is a
**repair** decision — RFC 0018 names the backup header as the place a
repair would look — not this install's to overwrite.  It looks at **both**
header places: a disk whose primary end is destroyed but whose backup is
whole still declares a GPT, and the backup is the one copy a repair could
use, so a fresh table there would be the writer destroying the survivor.
Every one of these "yes" answers and the flagless call itself produce the
same `NotFound` the path has always answered; the predicate narrows what
the flag reaches, it does not add a new refusal.

**2. Two entry points, one core.**  `install_zones_into_blank_disk_image` is
the flagged route and `install_zones_into_disk_image` keeps its meaning
exactly.  Both call one private `install_zones(disk, may_create)`; the
parameter is the whole difference.  `InstallReport` gains `created_table`,
so a caller can say which happened, and the CLI prints "(a fresh GPT was
written)" — a report a caller cannot act on is not a report.

**3. The plan and the table agree by construction.**  `write_gpt_partitions`
previously computed the fresh span inline; the fresh numbering now lives
once, in `fresh_gpt_layout(total_blocks)`, which the writer uses through
`GptGeometry::fresh` and the installer plans inside.  The entries the fresh
writer receives are the placement itself — zone order, slots 0..2 — because
there is no other entry to preserve.  A placement that fit the layout cannot
be an entry the header beside it calls impossible.

**4. Order and atomicity are kept.**  Placement is planned and each extent
is sized **before** the table is written (`NoSpace` refuses first, with the
disk untouched); the fresh table is written last, in the same step the
preserving writer would have run.  On the CLI the disk is still an in-memory
image written back only on success, so "writes nothing on refusal" is a
property of the whole operation rather than of each step.

**5. What stays refused, and why.**  A disk with MBR entries of any type; a
disk whose GPT is present but unverified; a disk whose only structure is a
protective MBR (which is what a hybrid disk's or a damaged GPT's first
sector looks like).  All of them carry bytes somebody wrote with intent, and
"erase or repair this" is not a permission an install flag can grant — the
first would need a different flag with a different argument, the second
belongs to whatever grows a repair path.

## Alternatives

- **Always write a table when the disk has none.**  Rejected: the refusal
  `docs/status.md` records is the feature.  A tool that partitions a disk
  by inspection is a tool that partitions the wrong disk once, and the flag
  costs one word.
- **An interactive confirmation instead of a flag.**  Not taken *yet*: that
  is the sibling item on the roadmap, and it belongs to the caller's
  interface (a host CLI today, an installer screen tomorrow), not to the
  disk-side operation.  The flag is the same consent written down, and the
  confirmation will call the function this RFC names.
- **Overwrite a GPT that failed its checksum.**  Rejected: a damaged table
  may be a whole backup array away from repair (RFC 0018), and the bytes
  still describe somebody's partitions.  `NotFound` for a damaged table is
  information, and a repair path can act on it later.
- **Create an MBR instead of a GPT.**  Rejected: a zone on a GPT is
  identified by its **type GUID**, an identity the disk carries; on an MBR
  it is a slot number, which is this tree's private convention for its own
  disks (RFC 0018's argument).  An installed machine's disk is a GPT.
- **Reuse `write_gpt_preserving` for the fresh case.**  Rejected: it
  requires a verified GPT to preserve — that requirement *is* the
  preserving contract — and a fresh disk has nothing to preserve.  The two
  writers state different invariants and stay two.
- **A `--force` that covers every refusal** (blank, damaged, entries).
  Rejected: one word cannot mean both "this disk has nothing to keep" and
  "destroy what is there".  If the second is ever wanted it gets its own
  name and its own argument, and this RFC does not invent it.

## Drawbacks

- The install command's surface grows a flag, and `InstallReport` a field;
  both are small but they are interface.
- A fresh table makes `install` a partitioning tool for exactly one input
  class.  The predicate is the fence: three questions, all answered by
  readers and checks that already existed and are already tested.
- A disk that carries a **filesystem without a partition table** (a raw
  `mkfs` on the whole device) is not caught by the predicate: its LBA 0 may
  hold a boot sector with the format's signature and no MBR entries, which
  reads as "no partition information" and would be overwritten by the
  protective MBR.  The flag is the consent for that shape too — the caller
  asked for a partitioned disk — but it is worth saying out loud, and the
  unresolved questions keep it.
- `docs/status.md`'s installation row grows a clause, and the gate's runtime
  grows one more boot.

## Compatibility and migration

Nothing on-disk changes for the existing routes: the flagless install's
inputs and outputs are byte-identical, because the predicate's additions only
*refuse* — the accepted set of disks is a subset of what was accepted
before.  The CLI's argument shape gains an optional leading flag; no existing
invocation changes meaning.  The fresh numbering moved from an inline
expression in `write_gpt_partitions` into `fresh_gpt_layout`, which is a
refactor of one function with the same bytes out — held by the demo builder
and its tests.

## How this is proven

- **Unit tests in `src/fs/install.rs`**: a blank disk gets a fresh table the
  reader verifies, with the zones where the report says and their volumes'
  bytes at the extents; a **second install** through the flagless route
  reuses every extent, so the fresh table became the disk's own; a disk with
  a real MBR entry, one with a protective MBR alone, one whose GPT header
  fails its CRC, and one whose primary end is destroyed while the **backup**
  header survives are each refused with the disk byte-identical; and a blank
  disk too small for the zones refuses **before the table**, with the disk
  byte-identical too.
- **`scripts/check-x8664-install.sh`**, a new section: a blank `dd` disk is
  offered to the flagless install first and must be refused; `--new-table`
  then installs, `sgdisk` reads the fresh table back and sees exactly three
  partitions, and the disk **boots** — the kernel mounts the zones it wrote
  over a table it wrote from nothing and a program comes off `/apps` to a
  typed answer.  The negative run of this section was measured: with the
  predicate bypassed the gate fails on "a disk with no table was installed
  onto without --new-table".
- **The existing sections stay green**: the `sgdisk` disk with the
  stranger's partition, the preserved entry, the boot, and the extent-reusing
  reinstall are unaffected — the change only adds a route.

## Unresolved questions

- **The raw-filesystem disk**: a whole-device `mkfs` with no table is
  indistinguishable from blank to table readers.  A check for filesystem
  signatures (or a requirement that LBA 0 be all zeros) would catch it, at
  the cost of a maintenance list; the flag currently carries the consent.
- **Repairing a damaged GPT**: a table whose primary header fails but whose
  backup is whole is readable by the format's rules.  RFC 0018 left that
  open; this RFC refuses such a disk rather than deciding it.
- **The naming of the zones' entries**: the fresh writer writes no
  partition names (the demo builder never needed any), so an installed disk
  shows unnamed partitions to other tools.  A name is a UTF-16 string with
  an encoding to get right; when something prints it, that is the change.
- **Windows-visible attributes**: the entry attribute bits are read and
  preserved, never set.  An installer for a machine with another OS on it
  might want to say "do not mount this"; nothing needs it yet.
