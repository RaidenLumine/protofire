# RFC 0027: Never mount a fixed offset over a table

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-15
- **Supersedes:** none

## Summary

A boot that finds a partition table on its boot disk and no zone in it stops
there: it mounts the in-memory demo volumes (on a build that has them) and says
which disk was refused, rather than falling back to the fixed zone offsets.
The fixed offsets keep their one remaining user — a disk that carries no
partition information at all — because that is the only disk for which they
are a description of anything.

## Motivation

The fallback is older than the table reader and was written when the only
disks this tree booted were images `mkimage` had made at those exact offsets.
Since then a machine's disk has become a first-class case — RFC 0018 reads a
GPT, `install` writes one, and `make check-x8664-install` boots it — and the
fallback's justification ("the layout this kernel's own builder wrote") no
longer covers the disks a boot actually meets.  A boot whose boot disk is a
laptop's own disk now goes: table read, no zone GUID found, **fixed offsets**,
which on that disk are inside the first partition the vendor put there.

Measured on the tree as it stands, with a 64 MiB NVMe disk attached to the ISO
boot:

- a **GPT** disk with one Linux-type partition at LBA 2048 and the demo
  image's bytes written underneath it prints
  `[fs    ] mounted fixed-zone SimpleFs volumes from ATA boot disk` — the
  volume mounted at LBA 2048 is the *vendor's partition*, read and writable
  as `/apps` and `/data`;
- an **MBR** disk with a table of Linux-type entries at the demo slots prints
  `system: slot b active (build 2)` and
  `mounted MBR-partitioned SimpleFs volumes from ATA boot disk` — the MBR path
  identifies a zone by slot and never compares the type byte, so a stranger's
  table is believed whenever the bytes at those offsets happen to parse.

The second is RFC 0018's deliberate choice ("safe *there* because the disk is
this kernel's own") and is not this document's to change; the first is a gap:
[ROADMAP.md](../../ROADMAP.md) already states the intended behaviour — "a
**machine's own disk** answers no zones and the boot says so rather than
mounting a stranger's partition at the wrong offset" — and the code does not
do it.  What makes that a data-safety failure and not a cosmetic one is the
write side: `/apps` and `/data` are writable mounts, so a boot on such a disk
is a boot that can overwrite whatever really lives at the fixed offsets.

## Current state

- **`src/fs/filesystem/layout.rs`.**  `install_boot_disk_layout` asks
  `boot_disk_zone_devices_from_partitions`; on `Ok(None)` — no table, a table
  without the zones, or a table whose system slot is missing — it calls
  `boot_disk_zone_devices_from_fixed_layout`, which slices the disk at
  `StorageZone::disk_range()` and installs those volumes.  The function's own
  comment calls this "the legacy fixed zone layout for older disk images",
  which is the claim this RFC tests and rejects.
- **`src/fs/layout.rs`.**  `DEMO_DISK_*_START_BLOCK` and `disk_range()` are the
  offsets; `build_demo_disk_image` uses the same numbers to *write* the demo
  disk's partitions, which is why they are a layout rather than a guess — but
  only for that disk.
- **`src/fs/filesystem/init.rs`.**  `FixedZoneFallback` and
  `BootDiskFixedZoneFallback` exist to report the route.
- **`src/fs/partition.rs`.**  `read_partitions` answers `None` for: no table,
  a protective MBR whose GPT does not verify, and a table that carries no
  entries.  Those answers are the discriminators this design needs, and they
  are already distinguished from "a table this kernel can read".
- **Disks the tree boots today.**  `mkimage` (MBR and GPT) writes its zones as
  partitions, so every demo, USB and install gate boots through the partition
  path; nothing in `scripts/` boots a table-less disk.

## Design

**1. The fallback is for a disk with no partition information, and nothing
else.**  The words are already this tree's: `install --new-table` gives a
fresh table only to a disk that carries *no partition information* — no
verified GPT, no MBR entries, no GPT signature, the predicate
`mbr_has_partitions`/`gpt_signature_present` state — and refuses every other
disk.  The boot now asks the same question of the disk it was handed, and only
a disk that answers "nothing there" is read at the fixed offsets:

```
table read, zones found      -> the partition path (unchanged)
table read, zones missing    -> refuse; do not fall back
nothing at all               -> the fixed offsets
```

"Nothing at all" is asked of the disk, not inferred from `read_partitions`
answering `None`: that answer also covers a **protective MBR whose GPT does
not verify** and a **damaged header**, both of which are a disk that declares
a table — the repair case, not the blank one.  So the new predicate reads LBA
0, LBA 1 and the last block, exactly where the two ends of a GPT live.

**2. A refusal is a first-class outcome, not a failure.**  A boot disk whose
table does not name this kernel's zones reports
`BootDiskLayoutSource::Foreign` and `StorageInitReport::BootDiskForeign`, and
the boot prints one line naming what it saw; on a build with the demo disk,
`init_with_boot_disk` then mounts the in-memory volumes — the outcome every
boot without a usable disk has — so the kernel stays usable and the log says
which of the two ran.

**3. What "names a zone" means does not change.**  The partition path still
requires **every** zone — the system pair, apps, data — because a partial
table is a disk this kernel should not mount half of; that requirement is
what makes `Foreign` reachable today and is kept deliberately.  RFC 0018's
type-GUID rule for GPT and slot rule for MBR are untouched.

**4. The fixed offsets keep one caller.**  `disk_range()` and the
`FixedZoneFallback` report stay, reached only by a disk with no partition
information: the disk a machine has that was never partitioned, where the
demo builder's offsets still describe where an image's bytes are.
`--new-table`'s install route is the writer for that same disk, so reader and
writer keep agreeing — in the same words.

**5. The security ordering rule this makes explicit.**  A boot's own disk is
only believed when it says, in a vocabulary this kernel reads, "this is one of
yours" — a type GUID, or nothing at all.  A table that says something else is
a statement this kernel accepts as "not mine".

## Alternatives

- **Compare the MBR type byte too.**  Rejected for this change, not in
  principle: it is what RFC 0018 did for GPT and did not do for MBR, and
  doing it now would refuse every disk `mkimage` made before the type bytes
  were written (which they are — but the demo path is not the only MBR
  producer a user may have).  It belongs in a change that can migrate those
  disks; this one stops the unrecoverable half (mounting offsets nothing
  declared).
- **Refuse the disk and fail the boot.**  Rejected: every other
  storage-init failure keeps the kernel usable with the demo volumes, and a
  bring-up machine with a stranger's disk is exactly when a shell that works
  is worth most.
- **Fall back only when the table is empty.**  Rejected as too narrow: it
  keeps the measured hazard for any table that has entries and not this
  kernel's, which is every machine bought with Windows on it.
- **Drop the fixed fallback entirely.**  Rejected: it removes the only reader
  for a table-less disk built before the partition paths existed, with no
  evidence any such disk is gone, and the install's `--new-table` route
  explicitly creates disks that have a table only after it ran.

## Drawbacks

- A machine whose disk carries a table and whose zones were written at the
  fixed offsets *without* partitions stops booting those zones.  Nothing in
  the tree produces such a disk (`mkimage` has always written the table), and
  the boot says which disk it refused, so the failure is attributable rather
  than silent.
- One more report variant and one more log line, and `docs/status.md`'s
  installation row grows a clause.
- The MBR type-byte hazard stays for the false-positive case: a stranger's MBR
  disk whose entries happen to sit at the zones' slots with type bytes this
  kernel does not read still mounts.  This RFC narrows the hazard; it does
  not close it (see Unresolved).

## Compatibility and migration

No format changes and nothing to migrate: a disk that boots today through the
partition path boots identically, and the demo disk takes the same route it
always has.  The only behaviour that changes is a boot whose boot disk has a
table that names no zone — which today mounts the wrong bytes, and after this
mounts the in-memory demo volumes and prints why.

## How this is proven

- **`src/fs/filesystem/tests.rs`** — a host test builds a disk with a
  verified GPT that carries a stranger's entry and the demo image's bytes
  *behind it at the fixed offsets*, runs `init_with_boot_disk`, and asserts
  the fixed-zone route was **not** taken and the demo volumes are what
  mounted; the mirror test (no table, same bytes) asserts the fixed offsets
  still work.  The first fails on the current code, which is the evidence the
  change is load-bearing.
- **`scripts/check-x8664-install.sh`** — one more section: a GPT disk made by
  `sgdisk` carrying only a stranger's partition is booted, and the gate
  requires the refusal line and *not* `mounted fixed-zone`; it then unwraps
  the disk (the same disk with the table zeroed) and requires that the same
  image now takes the fixed offsets, so one gate holds both halves.
- **`make check-x8664-usb-disk` / `check-x8664-runtime` / `check-nvme-disk`**
  keep passing unchanged: every disk they attach carries a table.

## Unresolved questions

- **The MBR type byte.**  Should an MBR boot disk's zones be found by type as
  a GPT disk's are?  Doing it means deciding what happens to disks written
  before the type bytes were set, which is a migration question this RFC does
  not answer.
- **A table with *some* zones.**  Today a table that names apps and data but
  not the system pair is refused whole.  Whether a boot should mount the zones
  it can name is a product question — a half-mounted machine may be worse than
  a demo one — and nothing needs it yet.
- **The GPT backup header.**  A disk whose primary is destroyed but whose
  backup is whole still reads as `None` here (RFC 0018's unresolved question);
  this RFC makes that answer safer (no fixed fallback over it) without making
  it smarter.
