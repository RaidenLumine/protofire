# RFC 0011: Make ISO 9660 file data writable

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-07
- **Supersedes:** none

## Summary

The roadmap's next filesystem item is that "the read-only drivers — NTFS,
BtrFS, SquashFS, ISO 9660, EROFS — move toward read-write".  This decides
which of them moves first and what the first stage is: **ISO 9660**, and its
**file data path**.  An ISO 9660 file is one raw, contiguous extent whose
length lives in its directory record, so replacing bytes *inside that length*
changes no metadata at all — no directory record, no path table, no volume
space size.  Growing, truncating, creating and removing all rewrite metadata
and are later stages; this is the one every later stage stands on.

## Motivation

The five candidates are not equally ready, and the differences are not
stylistic:

- **SquashFS and EROFS store file data compressed.**  An in-place overwrite is
  impossible without recompressing, and the new compressed size is not the old
  one — so the data path is a metadata change by construction.
- **BtrFS checksums every data block** in the csum tree.  Overwriting a block
  in place makes its checksum wrong, so a data write is a tree update, not a
  data write.
- **NTFS is the real prize** — a mutable disk filesystem with a journal, and
  the tree already has its raw cluster-write helpers
  (`src/fs/ntfs/fs.rs`) — but it needs MFT record allocation, `$Bitmap`, index
  insertion and the journal semantics that make its writes meaningful, and its
  tests today are parser-level (`src/fs/ntfs/tests.rs` parses reparse points,
  EA entries and filename attributes) with no image to mount.  It should get
  its own RFC, and it needs a harness before it can be verified.
- **ISO 9660 has neither compression nor checksums**, its files are
  contiguous extents, and its tests already build a complete image by hand
  (`src/fs/iso9660/tests.rs`), so a write can be checked end to end the day it
  lands.

That combination — the smallest metadata surface and the only ready harness —
is why it goes first.

## Current state

- **The reader.**  `Iso9660Volume` (`src/fs/iso9660/mod.rs`) parses the PVD,
  walks directory records and hands out `Iso9660VNode`s that carry
  `extent_location`, `extent_size` and the device.  A file is read with
  `fs::read_extent`, which maps a byte offset into the extent and calls
  `read_exact` — a byte-granular read built out of whole-block device reads.
- **Everything mutating refuses.**  `write`, `set_len` and the volume's
  `create_file`/`create_dir`/`remove_path`/`rename` return
  `PermissionDenied`, and the module documents itself as read-only.
- **There is no cache.**  Reads go straight to the device, so a write that
  reaches the device is what the next read sees.
- **The image.**  The test image carries `HELLO.TXT;1` (21 bytes) at sector 30
  and `NOTES.TXT;1` in a subdirectory at sector 31, in 2048-byte sectors.

## Design

**`write_extent`: the mirror of `read_extent`, clamped to the recorded
length.**  It maps the offset into the extent exactly as the read does, and
the number of bytes it will take is `extent_size - offset`.  A write past the
end is therefore a **short write** — the VFS contract's own answer — and not
an error: growing a file means rewriting the record that says how long it is,
which is stage 2.

**`write_exact`: whole-block device writes, with a read-modify-write for the
sectors the caller only partly covers.**  The device writes blocks, so the
sectors a range touches are classified first: one the range covers entirely is
written without being read, and one it partly covers is read, patched and
written back.  This is the whole of the data path — no journal, no cache, and
nothing else on the volume is touched.

**`Iso9660VNode::write`** is that call, for files.  Every other mutating
operation keeps refusing, and a read-only *device* still refuses because the
device does: a volume mounted from a read-only slice of the boot disk — which
is how `/system` is mounted — rejects the device write, not the filesystem.

**What the first stage deliberately does not do.**  `set_len`, `create_file`,
`create_dir` and `remove_path` are stages 2 and 3:

- **Stage 2, truncate and extend within the allocated sectors,** needs the
  *position* of the directory record that describes the file, which the reader
  deliberately discards today (it keeps the parsed record, not where it came
  from).  The node has to remember it, and the record's both-endian length —
  and the Rock Ridge `PX` size entry, when present — has to be rewritten in
  place.
- **Stage 3, create and remove,** needs free-sector allocation, a new or
  blanked directory record, and the path tables and volume-space size updated
  to match.  That is the part with a layout decision in it.

## Alternatives

- **NTFS first.**  The prize, and the largest step: allocation, a bitmap, an
  index and a journal, with no mount-level test to prove any of it.  Rejected
  as the *first* step, not as the goal.
- **BtrFS first.**  The data path is a csum-tree update; the smallest honest
  version is the same size as the whole ISO 9660 stage.
- **SquashFS or EROFS first.**  The data path does not exist in isolation:
  a write is a recompression and a relocation.
- **The metadata stages first on ISO 9660.**  They are the stages that need an
  allocation policy and a layout decision, and they would land with nothing
  under them: a `create_file` that produces a file nobody can write is not a
  step forward.
- **A builder instead of in-place writes** — regenerate an ISO from a tree, as
  `mkisofs` does.  Useful, and a different feature: it does not make a mounted
  volume writable, which is what "moves toward read-write" means for the other
  four filesystems on the list.

## Drawbacks

- **A torn data write damages the file.**  ISO 9660 has no journal and no data
  checksum, so a write that stops half way leaves the file half new — exactly
  what a raw data write means on any filesystem without a journal, and this
  stage claims no atomicity it does not have.  `docs/status.md` has to say so
  in its own words rather than letting "writable" imply "safe to interrupt".
- **A partial writable surface is a surface people will misread.**  A file can
  be overwritten but not grown, and the volume still refuses to create
  anything.  The module's own documentation and the status table are where
  that stops being a surprise.
- **Stage 2's change to the node is not obvious from stage 1.**  The record's
  position is the piece the reader throws away, and the reader was written
  that way for a good reason (nothing needed it).  Whoever does stage 2 has to
  thread it back through the lookup path.

## Compatibility and migration

No format changes: the bytes written are exactly the bytes the reader already
reads, and no existing image gains or loses anything.  A volume mounted from a
read-only device is unaffected, because the refusal is the device's.

## How this is proven

The module's tests are these filesystems' harness — `docs/status.md` records
that the read-only drivers are exercised by tests rather than by a boot, and
ISO 9660's tests already build a full image:

- **An overwrite inside the file is what the reader reads back afterwards**,
  and the *device's* sector carries the new bytes — so the write reached the
  medium rather than a copy.
- **The rest of the partly-covered sector is unchanged**, which is the
  read-modify-write path and the one way this stage can corrupt data it was
  not asked to touch.
- **A write past the end is a short write**, not an error and not an
  extension.
- **A read-only device refuses**, so the slice that makes `/system` read-only
  still does.

## Unresolved questions

- **Where does the directory record live?**  Stage 2 needs it; the lookup path
  currently returns a parsed record with no position.  Whether the node
  carries `(extent, offset)` or the volume re-walks the path is a design
  choice for that stage.
- **Does ISO 9660 want a cache?**  It has none today and a write is visible at
  once because of it; adding one later means the write path has to go through
  it too.
- **Is NTFS's harness the demo disk or a fixture image?**  Whichever it is, it
  is a prerequisite for NTFS's own RFC, and it is what that RFC should decide
  first.

## What landed

Stage 1, and only stage 1.

- `src/fs/iso9660/fs.rs` gained `write_extent`, the mirror of `read_extent`:
  the byte offset maps into the extent the same way, and the number of bytes it
  will take is `extent_size - offset`, so a write past the end is a short
  write rather than an error or an extension.
- `write_exact` is the whole-block device write underneath it: a sector the
  range covers in full is written without being read, and one it partly covers
  is read, patched and written back.  On a 21-byte file in a 2048-byte sector
  that is the only path there is, which is why the tests check the sector's
  padding survives.
- `Iso9660VNode::write` is that call for files.  `set_len`, `create_file`,
  `create_dir`, `remove_path` and `rename` still refuse, and a read-only device
  still refuses — the test for that mounts the image on a read-only
  `MemoryBlockDevice`, which is what `/system`'s slice is.
- Five tests: the overwrite reads back and is on the medium; a write that
  straddles two file sectors changes no byte outside its range; a write past
  the end is short and does not change the recorded length; a read-only device
  refuses; a directory refuses.

The module's own documentation said "read-only (all mutating operations return
`PermissionDenied`)" and now says which one does not.
