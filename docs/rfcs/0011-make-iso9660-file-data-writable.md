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

- **Where does the directory record live?**  *Decided when stage 2 landed*:
  the node carries it.  `DirRecord` gained `source_offset` — the offset the
  parser found the record at, inside the buffer it walked — and `resolve`
  turns that into an offset on the volume, because the volume is what knows
  where the extent it read came from.  The node keeps that number for its
  life and a resize writes there; the alternative, re-walking the path on
  every `set_len`, would read a directory extent to change eight bytes.
- **Does ISO 9660 want a cache?**  It has none today and a write is visible at
  once because of it; adding one later means the write path has to go through
  it too.
- **A Joliet image has two directory trees.**  The mount reads the Joliet tree
  when the image has one, so a resize rewrites the record it looked the file up
  in — and the *primary* tree's record for the same file keeps the old length.
  The data is one extent and both trees point at it, so nothing is lost; what
  is stale is one tree's idea of how long the file is, for a reader that
  prefers the primary tree.  Updating both means mapping a Joliet record to its
  primary counterpart, which is name work rather than record work, and it is
  the first thing a stage-2 follow-up should do.
- **Is NTFS's harness the demo disk or a fixture image?**  Whichever it is, it
  is a prerequisite for NTFS's own RFC, and it is what that RFC should decide
  first.

## What landed

Stages 1, 2 and 3a.

- **Stage 1 — the data path.**
- `src/fs/iso9660/fs.rs` gained `write_extent`, the mirror of `read_extent`:
  the byte offset maps into the extent the same way, and the number of bytes it
  will take is `extent_size - offset`, so a write past the end is a short
  write rather than an error or an extension.
- `write_exact` is the whole-block device write underneath it: a sector the
  range covers in full is written without being read, and one it partly covers
  is read, patched and written back.  On a 21-byte file in a 2048-byte sector
  that is the only path there is, which is why the tests check the sector's
  padding survives.
- `Iso9660VNode::write` is that call for files.  `create_file`, `create_dir`,
  `remove_path` and `rename` still refuse, and a read-only device
  still refuses — the test for that mounts the image on a read-only
  `MemoryBlockDevice`, which is what `/system`'s slice is.
- Five tests: the overwrite reads back and is on the medium; a write that
  straddles two file sectors changes no byte outside its range; a write past
  the end is short and does not change the recorded length; a read-only device
  refuses; a directory refuses.

**Stage 2 — the length, which is one field.**

- `DirRecord` carries `source_offset` and `resolve` turns it into an offset on
  the volume, so `Iso9660VNode` knows where its own record sits (the open
  question above, decided).
- `Iso9660VNode::set_len` rewrites the record's data-length field — both
  endiannesses, because the format stores it twice — and then answers with the
  new length, which the node keeps in an atomic because the VFS hands out
  `&self`.
- The rule is the format's own: a length up to the end of the block the file
  already has is free, and one that would reach into a second block is refused
  with `NoSpace`, because there is no allocation map to give it one.  Every
  extent begins on a block boundary, so that block's tail belongs to no other
  extent — which is what makes the grow safe rather than merely unchecked.
- Four more tests: a truncation reads back short, a *second mount* sees the new
  length (so it is on the medium), both halves of the field carry it, and a
  shrink can be grown back because the bytes were never erased; a grow fills
  the block's tail with the medium's own bytes and stops there; a directory
  refuses; a read-only device refuses.

The module's own documentation said "read-only (all mutating operations return
`PermissionDenied`)" and now says which operations do not.

**Stage 3a — space, from an append-only allocator.**

- `fs::allocate_blocks` hands out blocks beginning where the volume's declared
  size ends, and moves the one metadata field that says how far the volume
  goes — the PVD's volume-space size, stored twice.  It never hands out a block
  the image already wrote, which is what makes it correct **without a
  free-space scan**: the property is a consequence of the design rather than
  something it has to check.
- `set_len` past the block a file has therefore has two ways to grow, and
  `Iso9660VNode` picks by where the file is: the blocks that follow it, if it
  is the last extent the volume holds (grow in place — the volume moves over
  them, no copy); otherwise it **moves** to the end of the volume, data first
  and the record after, so a crash before the record leaves the old file whole.
- `write` past the end grows first, so a caller can write a file the way it
  writes any other; when the growth is refused the write is **short**, which is
  the answer this call has always given for a byte it could not take.
- The two fields move together: `rewrite_record_placement` writes the extent
  location and the length in one 16-byte write, because they are adjacent and
  each is stored twice.
- Four more tests: a file with a neighbour moves and the neighbour is
  untouched; the last file extends where it is, with its record's location
  field unchanged and the volume grown by exactly the block it took; a length
  beyond the medium is `NoSpace`; and on a medium that is exactly the volume's
  size, a write that cannot grow is short.

**What that leaves.**  Stage 3b is creating and removing, which is the same
allocator plus the directory work the RFC's stage 3 named: appending a record
and growing a directory's extent, or rewriting one without a record.  And the
allocator's cost is stated where it lives: a removal reclaims nothing, and a
file that has something after it pays a copy to grow.  A free-space scan over
every extent is what would fix both, and it is the next step.

**Stage 3b — the directory, which is where a record lives.**

- `resolve_child` splits a path into the parent directory and the child's
  name, and `resolve` now answers the *parent's* record offset — including the
  root's, which is a field of the PVD rather than a record in some directory.
  That is the second half of the position question stage 2 answered for files.
- `fs::place_extent` is stage 3a's growth, extracted: give an extent the blocks
  a size needs, in place if it is the volume's last, by moving otherwise.
  `set_len` and the directory append are both it, so a file and a directory
  grow the same way.
- `fs::append_record` puts a record at the end of a directory's extent.  A
  record may not straddle a block boundary, so one that does not fit starts the
  next block — and the bytes it skips are left alone, which a reader reads as
  "no more records in this block" (`read_directory` already did).
- `create_file` writes an empty file's record: its extent starts where the
  volume's space ends and its length is zero, so a create costs the record and
  nothing else, and the first write gives it blocks.
- `remove_path` shifts the records after the target down over it and zeroes
  what is left, then shortens the directory's record.  The bytes are shifted
  rather than re-serialised because a record carries whatever its writer put in
  the System Use area, and this driver does not parse all of it.
- A **name** an ISO identifier has no room for is refused: no Rock Ridge name
  entry is written yet, so a caller that asks for `hello.txt` gets
  `HELLO.TXT;1` — which this driver reads back as `hello.txt`, because its
  lookup is case-insensitive — and a caller that asks for `a name with spaces`
  is told no.
- Nine tests: a created file is empty and findable, on a second mount too; it
  can be written and read back; the directory is longer by exactly the record's
  43 bytes; a directory that fills its block takes another and every created
  name is still found; a create of an existing name is `AlreadyExists`; a name
  with a space is `InvalidArgument`; a removal takes the record out and the
  neighbour and a second mount agree; a directory is `Unsupported`; and a
  read-only device refuses both.

**What that leaves.**  Stage 3c is directories — creating one needs a new
extent *and* an entry in both path tables, in their order, and removing one
needs the same in reverse — and a Rock Ridge name entry, which is what would
let a created name be anything a caller likes.

**Stage 3c — directories, which means the path tables.**

- `Iso9660Volume::path_table_entries` walks the tree level by level and builds
  the table the standard asks for: by level, then by the parent's number, then
  by identifier.  A level-order walk gives the first two for free, because a
  parent is always numbered before its children; each directory's children are
  sorted by identifier, which is the part a walk does not give.
- The tables are **rebuilt, not edited**: a directory's number *is* its
  position, so inserting one renumbers everything after it, and rebuilding the
  list is the same work with fewer ways to be wrong.  Both are written — one
  per byte order — and the descriptor's four fields (size, both locations, and
  the optional copies when the image has them) are rewritten to match.  A table
  that no longer fits the blocks it holds moves to the end of the volume like
  any other extent.
- `create_dir` writes the two records an empty directory is — "." at its own
  extent and ".." at its parent's — appends the parent's record for it, and
  rebuilds the tables **last**, so a crash in between leaves a directory the
  tree has and the table does not (which a walk still finds) rather than an
  entry for a directory that is not there.
- `remove_path` takes a directory out only when it is empty — its extent is
  exactly its own two records — because a child's record would otherwise point
  at a parent nothing names, and rebuilds the tables after it.
- **A bug the first test found**: the descriptor stores one path table's
  location big-endian and the other's little-endian, and reading the
  big-endian one as an integer gives a number that addresses nothing.  The
  tests caught it as a write past the device's end; `field_le`/`field_be` are
  now what reads those fields.
- Five tests, and the important one is a **checker**: the reader never consults
  a path table (it walks records), so nothing in the driver would notice a
  table that was wrong.  The tests parse both tables back off the medium and
  require the properties a reader depends on — the two agree, the root is
  first and its own parent, a number is its position, a parent is numbered
  before its child, every directory appears exactly once at the extent its
  record names, and siblings are in identifier order.  Plus: a created
  directory is empty, findable and named in the tables, on a second mount too;
  it holds files; removing an empty one takes it out of the tree and the
  tables; a directory that holds something is `Busy`; a read-only device
  refuses.

**What that leaves.**  `rename`, which is a removal and a create that the
caller sees as one, and the Rock Ridge name entry that would let a created
name be anything at all.

**Stage 3d — renaming and moving.**

- `rename` is a removal and a create the caller sees as one: the record leaves
  its directory and an identical one — the same extent, the same length —
  joins the destination's under the new name.  Both halves already existed;
  what is new is that they are one operation.
- The destination is resolved **again after the removal**, because when both
  names are in the same directory the removal shortened it and the append has
  to see the length that leaves.  That is the kind of ordering a single
  operation makes easy to get wrong, so it is written where it happens.
- A directory that moves rewrites its own ".." record, found by its identifier
  (`0x01`) rather than by assuming how long the "." record before it is — a
  foreign image's first record need not be the length this driver would write.
  A directory whose parent did not change skips that, and a **file** rename
  skips the path tables entirely, because the tables name directories.
- A directory cannot move inside itself: the records the move would rewrite are
  the ones it is made of.  The check is on the paths, before anything is
  written.
- Seven tests: a renamed file keeps its contents and a second mount agrees; a
  move into a subdirectory takes the record with it; a renamed directory is
  found under its new identifier and the tables no longer name the old one;
  a *moved* directory's ".." points at the directory it moved into (read off
  the medium, because the driver never resolves `..`); a move into itself is
  `InvalidArgument`; a rename onto an existing name is `AlreadyExists`; a
  read-only device refuses.

**What that leaves.**  The Rock Ridge name entry, which would let a created or
renamed name be anything at all, and the free-space scan that would let a
removal reclaim what it freed.
