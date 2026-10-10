# RFC 0018: Read a disk whose table is GPT

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-10
- **Supersedes:** none

## Summary

The kernel reads one partition table — MBR, the one `mkimage` writes for its own
demo disk — and a machine's own disk is **GPT**, so today the boot either finds
nothing or finds a lie (below).  This decides the read side: a protective MBR
leads to the GPT header the table names, both of its checksums are verified,
and a partition is a **zone** only when its type GUID is that zone's, which is
the difference between reading a foreign table and trusting one.  What it does
not decide is writing: the release path keeps writing MBR, and installing onto
a GPT disk is its own change.

## Motivation

`ROADMAP.md`'s near-term list of what stands between this kernel and a real
machine puts the disk second, and the reason is that a machine's
installer-partitioned disk is a GPT.  What the kernel does with one today is
worth stating exactly, because it is not "nothing":

- `read_mbr_partitions` (`src/fs/partition.rs`) accepts any boot sector with the
  `0x55AA` signature, and a protective MBR carries an entry of type `0xEE`
  covering LBA 1 to the end of the disk.  That entry is returned as a
  partition, because the parser asks only whether the type byte is non-zero.
- `system_slots` (`src/fs/system_image.rs`) reads slots 0 and 3, so the
  protective entry becomes **slot A**: the boot builds a slice of the disk
  from LBA 1, reads it for a build marker, finds none, and prints
  `system: slot a active` — it has a system volume whose bytes are a
  stranger's disk.
- `boot_disk_zone_devices_from_mbr` (`src/fs/filesystem/layout.rs`) then finds
  no partition in the slots `StorageZone::Apps` and `StorageZone::Data` name —
  a protective MBR has one entry and they are not it — and refuses the whole
  table (`Ok(None)`), so what runs is the fixed-zone fallback.

So a GPT disk is not invisible: half of it is believed.  The boot announces a
system slot it does not have, then falls back to a layout the disk does not
have either, and the partitions the machine really has are never mentioned.  A
parser that answers "there is no zone here" — once, for the whole table — is
the improvement, and reading the table is how it answers.

## Current state

- `src/fs/partition.rs`: `MbrPartitionEntry` (bootable, type byte, start,
  count), `read_mbr_partitions`, `write_mbr_partitions`, and the tests that
  build a boot sector by hand and round-trip it.
- `src/fs/layout.rs`: `StorageZone` and its MBR vocabulary — the type bytes
  `DEMO_MBR_SYSTEM_PARTITION_TYPE`/`_APPS_`/`_DATA_` with
  `StorageZone::mbr_partition_type()`, and `partition_slot()`, the index the
  zone lives at.
- `src/fs/filesystem/layout.rs`: `install_boot_disk_layout` prefers the
  partition table and falls back to the fixed zone layout, and
  `boot_disk_zone_devices_from_mbr` refuses the whole table when one expected
  zone is missing (`Ok(None)`, so the fallback is what runs).
- `src/fs/system_image.rs`: the A/B system pair at slots 0 and 3, chosen by
  index, with the build marker deciding between them.
- `src/kernel/crypto.rs`: `crc32`, the standard reflected CRC-32 — which is the
  checksum both GPT checksums are.
- `src/main.rs`: the host `mkimage` command, which writes the demo disk's MBR
  table; `scripts/check-x8664-usb-disk.sh` boots that image over USB and
  requires the boot's own line saying it mounted MBR-partitioned volumes.

## Design

**1. The table is detected, not assumed.**  LBA 0 with the `0x55AA` signature
whose first entry is type `0xEE` starting at LBA 1 is a **protective** MBR: the
table is at the LBAs the GPT header names, and the header is looked for where
the format puts the primary copy, LBA 1.

The three answers are:

| LBA 0 | GPT header | Answer |
| --- | --- | --- |
| no `0x55AA` | — | no table |
| signature, no `0xEE` first | — | the MBR table (unchanged) |
| protective | `EFI PART`, checksums hold | the GPT table |
| protective | anything else | **no table** |

That last row is the decision worth arguing.  The protective entry is not a
description of a partition — it is a promise that the real table is in the
GPT — so a disk whose GPT cannot be read is a disk whose partitions this
kernel does not know, and it is *not* the disk's single `0xEE` partition.
Answering with the MBR view there is how the boot ends up mounting the wrong
thing, and the fallback that runs instead is honest about knowing nothing.

**2. Both checksums are verified.**  The header's CRC-32 covers the header up
to its own declared `header_size`, with the CRC field taken as zero; the entry
array's covers `num_partition_entries * sizeof_partition_entry` bytes.  The
format gives them for exactly this, so a table that fails either is a table the
kernel does not read partitions out of — the same answer as a header that is
not there, and for the same reason: a partition handed out of a corrupt table
is a volume mounted at the wrong offset.

**3. What is read is bounded by what the code can hold.**  The entry size must
be at least the format's 128 bytes; the count is bounded by a constant in
`src/fs/partition.rs` (the format's usual 128 entries is well inside it), so no
disk's own header can make the boot read megabytes of entries.  An entry whose
type GUID is all zero is unused.

**4. A zone is identified by its type, not by its index.**  This is the second
decision worth arguing.  The MBR path identifies a zone by the slot its
`partition_slot()` names and does not even compare the type byte, which is
safe *there* because the disk is this kernel's own: `mkimage` wrote it, and
the index is the convention that wrote it.  A GPT is the shape a **foreign**
machine's disk has, and the indices of a stranger's disk are a stranger's
choices — index 1 is an EFI system partition on almost every machine sold.  So
a GPT partition is a zone only when its type GUID is the zone's own:
`StorageZone::gpt_type_guid()`, a GUID table of this kernel's own invention
standing where `mbr_partition_type()` stands today.

The consequence is deliberate: a real machine's disk, which carries no such
GUID, gives no zones, the boot falls back exactly as it does for a disk with no
table, and it says so.  What makes a GPT disk bootable by this kernel is a
tool that writes those GUIDs — the same host tool that writes the MBR table
today — not an inference from position.

**5. One view for both tables.**  `read_partitions` answers a
`PartitionTable`, which is either the MBR's four entries or the GPT's array,
and answers a partition — start, count, and a `kind` that is the MBR type byte
or the GPT type GUID — by slot.  The mount path, the zone loop and the system
pair ask that view rather than the table-specific readers, so the *layout*
decisions (which zone is where, what a missing zone does) stay in one place
and the two tables differ only in the file that parses them.

**6. What is not decided here.**  Writing a GPT, the backup header at the end
of the disk and restoring from it, the entry's name (a UTF-16LE string nothing
in this tree has a reader for), and the attributes word: each is named in the
unresolved questions rather than half-built.  The release path keeps writing
MBR, and a disk that has both tables is read as the GPT says.

## Alternatives

- **Read the GPT and treat its entries as slots**, the way MBR's are.  Rejected
  above: index identity on a foreign disk is how an EFI system partition
  becomes `/apps`.
- **Accept a protective MBR as a one-partition table.**  Rejected: the
  partition it describes is the disk, and mounting it is the failure this RFC
  exists to remove.  It also cannot be distinguished from a hybrid disk's real
  MBR entries, which are a third shape this RFC does not read.
- **Skip the CRC-32 checks.**  Rejected: the check is one pass over the header
  and the array — the array is usually 16 KiB — and the alternative is handing
  out offsets from bytes nobody has vouched for.  A boot that reads a corrupt
  table mounts a volume at the wrong place, which is the one failure a
  filesystem cannot report.
- **Carry the partition name.**  Not taken: nothing reads it, and a name is a
  string with an encoding and a length that would have to be validated.  When
  something wants to print a machine's partition names, that is the change.
- **Write GPT as well, now.**  Not taken: the write side is where the backup
  header and the ordering (entries, then header, then the protective MBR) are
  argued, and nothing needs it until an installation target is a real disk.
- **A GUID for `/system` that matches a distribution's installer layout.**
  Rejected: these volumes are this kernel's own filesystem and no installer
  knows them; borrowing a familiar GUID would claim a meaning the type does
  not have.

## Drawbacks

- One more format in the tree, with two checksums and a bounded array read: a
  GPT disk costs a 512-byte read, a header read, and a pass over the entries
  where an MBR disk costs one sector.
- A GPT disk that is *not* this kernel's own now yields no zones at all, where
  before it yielded a wrong one.  That is the point, and it is also a behaviour
  change worth saying out loud: a boot on a stranger's disk goes from a failed
  mount of the whole disk to the fixed-zone fallback.
- `docs/status.md`'s census of the layout grows a row or a clause, and
  `docs/kernel/fs.md`'s mount-time section has one more table in it.

## Compatibility and migration

No on-disk change and nothing to migrate: an MBR disk is read exactly as
before, byte for byte, and the new path is entered only by a disk whose LBA 0
says the table is somewhere else.  The demo disk `mkimage` writes keeps its MBR
until the change that gives it a GPT, and both are read as what they are.

## How this is proven

- **A table built by hand, read back**: a GPT image built byte for byte in the
  test — protective MBR, header, entries — with its checksums computed, and the
  entries it declares coming back with their LBAs and type GUIDs; the same for
  an MBR disk, whose answers may not move.
- **Each refusal, on its own image**: a protective MBR with no GPT header, one
  whose header signature is wrong, one whose header CRC-32 is wrong, one whose
  entry-array CRC-32 is wrong, one whose entry size is smaller than the
  format's, and one whose entry count is past the constant — each answering "no
  table" rather than a partition.
- **A disk that is the machine's**: a GPT built by the host's own tool
  (`sgdisk`) carrying none of this kernel's zone GUIDs, over the same block
  device the gates use, answering no zones — and the boot falling back exactly
  as it does today for a disk with no table.
**What landed with this RFC.**  The two tables, the uniform view, and the boot
path that goes through it: `read_partitions` answers either table,
`PartitionTable::zone_partitions` answers by type GUID on a GPT and by slot on
an MBR, `system_slots` takes the pair from whichever table the disk carries,
and the boot's own line names the table it mounted from.  The tests are the
hand-built image with its checksums, the two system volumes found by type in
the array's order, a foreign type GUID (an EFI system partition's) answering no
zone, each way a GPT can be unreadable answering "no table", the MBR answers
the change may not move, and the parsers' fuzz harness, which now drives
`read_partitions` rather than the MBR reader alone — the comment in it had said
"an MBR or GPT" since before there was a GPT to read.

- **The last item, still owed**: the **end to end**, which wants a host tool
  that writes a GPT with these GUIDs — `mkimage` writes an MBR today — and a
  second pass of `scripts/check-x8664-usb-disk.sh` that boots it, requires the
  boot's own line naming the GPT, and loads a program out of `/apps` on it.
  Its input is the same zone table in the other format, so it is the writer
  that is missing rather than the kernel half.

## Unresolved questions

- **Writing a GPT**: the backup header at the last LBA, the entries-before-
  header order, and what an in-place update of one partition does to the
  alternate copy.  The release path is what would want it.
- **The backup header as a fallback**: a disk whose primary header is damaged
  but whose backup is whole is readable by the format's rules.  Whether a boot
  should look there is a decision about how much damage to keep booting
  through.
- **A hybrid MBR**, whose MBR entries are real *and* name a GPT: reading it as
  both is how a disk ends up mounted twice.
- **The partition name and attributes**: nothing reads either yet.
- **Which GUIDs**: this RFC invents a type GUID per zone, and a real
  installation medium would want them written down somewhere a tool can read
  them from — the same question `mkimage` answers today by being in this tree.
