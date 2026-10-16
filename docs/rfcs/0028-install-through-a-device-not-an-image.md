# RFC 0028: Install through a device, not through an image

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-15
- **Supersedes:** none

## Summary

The install path stops reading the whole disk into memory: it asks a
`BlockDevice` for the blocks a GPT lives in — LBA 0, LBA 1, the entry array
and the disk's last block — and writes zone content and table back as
blocks.  The byte-slice entry points stay, because `mkimage` and the tests
build images; the bootable install is the device one.

## Motivation

`install_zones_onto_disk` (`src/main.rs`) starts with `fs::read(path)` and
ends with `fs::write(path)`, and every operation in between — the plan, the
placement, the table rewrite — runs over that `Vec<u8>`.  A 64 MiB demo
image is fine; a machine's own disk is not.  Measured on this tree: a 64 GiB
disk with a GPT and one stranger's partition fails with `OutOfMemory` on a
15 GiB machine before a single zone is placed.  A laptop's disk is 512 GiB
to 2 TiB, so the install path as it stands cannot install onto the machine
it exists for, and the README's recipe (`cp /dev/sdX disk.img` … `dd
if=disk.img of=/dev/sdX`) requires having the whole disk free somewhere
else, which a machine being installed does not.

Everything an install touches is block-granular: the protective MBR, the
primary header, the entry array (16 KiB for a 128-entry table), its backup
and the backup header.  Zone images are the demo sizes — hundreds of KiB.
Nothing about the operation needs the disk.

## Current state

- **`src/fs/partition.rs`.**  Readers `read_gpt_from_bytes` /
  `read_gpt_layout_from_bytes` and writers `write_gpt_partitions` /
  `write_gpt_preserving` all take `&[u8]` / `&mut [u8]`.  Their shared
  verification (`gpt_header_info`, `parse_gpt_entries`, `crc32`) is already
  separate from the byte access.
- **`src/fs/install.rs`.**  `place_zones` is pure over
  `(GptLayout, &[GptPartitionEntry])`; `read_or_create` and `install_zones`
  slice a `&mut [u8]`; `plan_zones_into_disk_image` reads only.
- **`src/kernel/block.rs`.**  `BlockDevice` has `read_blocks`/`write_blocks`
  in whole blocks, a `block_count`, and drivers already implement it
  (NVMe, AHCI, USB MSD, virtio-blk).  The kernel's own boot mounts volumes
  through it.
- **`src/main.rs`.**  The host binary has no `BlockDevice` over a file.

## Design

**0. A zone extent is written in pieces.**  A zone the table already carries
keeps the *table's* extent — the install does not shrink a partition someone
else declared — so a reused entry can be far larger than the demo sizes, and
the zeroed tail after the image must not be built in one buffer.  The image
goes down in one block-aligned write and the rest of the extent is zeroed in
`ZERO_CHUNK_BLOCKS`-sized writes, so the install's memory does not grow with a
partition it did not place.  This is a defect the first cut shipped — it held
the whole extent — and the gate observes the write sizes through a recording
`BlockIo`, because the byte result looks the same either way.

**1. A block-level I/O trait, next to the format.**  `fs::partition` gains
`BlockIo`: `block_count`, `read_blocks`, `write_blocks` — the same shape
`BlockDevice` has, minus queues, tickets and capability questions.  Two
implementations: `&mut [u8]` (an image in memory, block-aligned) and
`DeviceIo<'_>` (delegating to a `&dyn BlockDevice`).  The GPT readers and
writers become generic over it once; the byte-slice functions stay as thin
wrappers, so `mkimage`, the demo builder and every existing test are
unchanged.

**2. The install path takes a device.**  `install_zones_into_disk` /
`install_zones_into_blank_disk` / `plan_zones_into_disk` take
`&dyn BlockDevice`; the algorithm is the same placement and the same
preserving write, expressed in blocks.  The byte-slice functions stay for
callers that already hold an image, implemented by wrapping the slice.

**3. Buffer bounds become checks.**  The device reader cannot rely on the
slice to bound a table: `read_gpt_io` refuses an entry array larger than
`GPT_ENTRIES_MAX_BYTES` (64 KiB), which the slice path enforced by
construction.

**4. The host gets a file-backed device.**  `main.rs` implements
`BlockDevice` over a `std::fs::File` (seek + read/write under a lock,
`block_count` from the file's length), and `install` runs the plan over it,
asks, then writes.  A block device node (`/dev/sdX`) is such a file on
Linux, so the same code installs onto a stick or a laptop's disk.

**5. Nothing about the confirmation changes.**  The plan still reads only;
nothing is written before the typed `yes`, so `no`, no answer and end of
input still leave the disk byte-identical — now a fact about the device
path too, and the gate that `cmp`s the disk still holds it.

## Alternatives

- **Memory-map or seek the image.**  Rejected: a memory map is still a
  whole-disk view and needs an address space the boot does not have; seeking
  is what the device implementation does, minus the trait that the kernel
  side already speaks.
- **Keep the image path and `dd` in chunks.**  Rejected: it moves the same
  work into the recipe, where it is not gated and not the install's contract.
- **Install from inside the kernel (a booted installer).**  Not taken: the
  kernel mounts its zones read-only and has no program that partitions; the
  host tool with a real device is the smaller change that unblocks the
  machine.

## Drawbacks

- Two spellings of one algorithm (device and slice) unless the slice
  wrappers delegate — they do, so the spellings are one function each.
- A corrupted disk's table is now read block by block; a device error
  mid-read is reported rather than being an in-memory parse failure, which
  is more honest but a new error path to attribute.
- The README's recipe changes: `cargo run -- install /dev/sdX` (or a copy)
  instead of copying the whole disk first.

## Compatibility and migration

No on-disk change: the bytes written are the same bytes.  Evidence: a host
test installs onto the same disk through both paths and requires the two
images to be byte-identical, and the gate boots the device-path result.

## How this is proven

- **`src/fs/install.rs` tests** — device-side install equals byte-side
  install, byte for byte, on the shipped `machine_disk` fixture; a
  table-less device takes the fresh-table route, matching the slice path.
  Two more cover the reused extent: an entry larger than the demo sizes is
  kept and zeroed past its image, and a recording `BlockIo` requires every
  write to stay within the chunk bound — the second fails if the install
  builds an extent whole, which the byte comparison cannot show.
- **`scripts/check-x8664-install.sh`** — the existing `cargo run --
  install` sections now run over the file-backed device; one section adds a
  **64 GiB sparse** disk whose install must complete while the file's
  allocated blocks stay small (`du`), which is the property the change
  exists for.
- **Kernel-side readers** — no kernel change; the boot already reads its
  table through `BlockDevice`.

## Unresolved questions

- **Should the kernel expose its own installer** (a program that performs
  this over its own disks)?  Not now: the host tool is what a person runs
  from the ISO's shell today; an in-kernel installer is a later change with
  its own safety argument.
- **Writing boot code to the disk's ESP.**  Out of scope: the install adds
  zones; making a machine boot them without a USB stick is firmware work
  (`grub-install`-shaped) this RFC does not decide.
