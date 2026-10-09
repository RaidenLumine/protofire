# RFC 0012: Decide the harness an NTFS write is proven on

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-08
- **Supersedes:** none

## Summary

NTFS is the next filesystem the roadmap moves toward read-write and the
largest of them, and the roadmap says its RFC has to decide its **harness**
before its writes.  This decides both that harness and the first stage under
it: a **fixture volume built in the tree**, in the shapes a real volume has,
checked by its own invariants and kept honest against a volume `mkntfs`
makes — and, as the first stage, the **read** path through it, because the
probe below shows the driver answering a question about a real volume with a
different record than it was asked for, and there is nothing in the tree that
would notice.

## Motivation

[docs/status.md](../status.md) records the gap in NTFS's own row: "MFT
parsing, attribute resolution; `write` overwrites inside existing runs",
with "no create, rename or remove (`NotImplemented`); no file extension, and
compressed and encrypted streams are not covered".  The roadmap, in the same
breath, says why this RFC comes before any of that work: "its RFC has to
decide its harness before its writes".

That is not a formality, and the reason is measurable.  A volume `mkntfs`
makes has 1024-byte MFT records and 4096-byte clusters, and this driver
computes the record size from the boot sector's exponent as
`(1 << |exp|) / cluster_size`, with a floor of one cluster — so it decides the
records are 4096 bytes.  Asked for records 0, 3 and 5 of that volume it
answered with records **0, 12 and 0**, the last of which is not in use: the
root directory this driver works with is, on a real volume, some other
record.  Every one of those reads *succeeded*, because the magic is still
`FILE` — the MFT is a run of records the format wrote, and four times the
right stride still lands inside it.

Nothing in the tree can notice that today.  `src/fs/ntfs/tests.rs` says it in
its own header: the end-to-end suite went with the API the driver was
refactored away from, and what is left tests parsers — reparse points, `$EA`,
filename selection, `$STANDARD_INFORMATION`, index entries — none of which
has ever seen a volume.

## Current state

- **`src/fs/ntfs/mod.rs`.**  `NtfsFs::new` reads the boot sector;
  `NtfsInfo::new` derives the cluster, record and index sizes from it.
  `read_mft_record` addresses a record as
  `mft_lcn * cluster_size + record_number * mft_record_size` — a stride from
  the MFT's first cluster, with no runlist in between.  `lookup` ignores the
  path it is given and answers the root; `read_dir` answers one dummy entry;
  `create_file`, `create_dir`, `remove_path` and `rename` are
  `NotImplemented`.  `NtfsVnode::write` writes data through the runlist
  (`fs::write_clusters`, the only call in the module that reaches the device
  with a write) and then calls `update_mft_record(&mut record, …)` — on the
  record the vnode holds in a `SpinLock`, which is a buffer, not the volume.
  `set_len` changes that same in-memory record's `$DATA` size.  The vnode has
  a `readdir` helper that walks the record's `$INDEX_ROOT`, but it is not a
  trait method and nothing calls it.
- **`src/fs/ntfs/fs.rs`.**  `BootSector::parse`; attribute parsing; runlist
  decoding; `parse_index_entries`; `apply_usa_fixup`; `write_clusters`.
- **`src/fs/ntfs/types.rs`.**  The structures the above use.  `$Bitmap`,
  `$UpCase`, `$Volume` and `$LogFile` are not named anywhere in the module.
- **`src/fs/ntfs/tests.rs`.**  Parser-level tests, as above.
- **What a real volume is**, measured on a 16 MiB image `mkntfs -F -Q` made:
  8 × 512-byte sectors per cluster (4096 bytes), the record-size exponent
  `-10` (1024 bytes), a 4096-byte index buffer, `$MFT` at LCN 4, `$MFTMirr`
  at 2047, the USA at offset 48 with three entries — and `$MFT`'s own `$DATA`
  as **one run of seven clusters**, which is what a volume looks like at the
  moment it is made.

## Design

### The harness

A **fixture volume built by the driver's own tests**, the shape
`src/fs/iso9660/tests.rs` already has, with the differences NTFS forces:

- **The record size is what the exponent says**, which for a volume whose
  records are smaller than a cluster is a *fraction* of one — 1024 bytes in a
  4096-byte cluster is the default shape and is what the probe above got
  wrong.  The fixture builds both that shape and a whole-cluster one, because
  the arithmetic differs and only one of them is common.
- **A contiguous `$MFT`**, with the records the fixture's reads touch:
  `$MFT` itself (0) carrying its own `$DATA` runlist, the root (5) with its
  `$I30` index root, `$Bitmap` (6) for the stage that allocates, `$Volume`
  (3) for the dirty flag — and the rest formatted but not in use, which is
  what a real MFT's free records look like.
- **Every record with its update sequence array**, at offset 48 of a
  1024-byte record and wherever the header says otherwise: a fixture without
  one would test a volume no NTFS writer produces.
- **Files that exercise the two shapes of `$DATA`**: one resident in the
  record, one non-resident with a runlist of *two* runs (a runlist of one is
  the case that cannot expose an offset-decoding bug, because the delta is
  the address).
- **A `$Bitmap` and an `$I30` root** whose contents the fixture's own checks
  can compare against the runlists and the records.

### What the fixture is checked against

ISO 9660's tests parse both path tables back and check the properties a
reader depends on, because its reader never consults one.  NTFS needs the
same discipline for different reasons, and the checks are the ones the
writes must preserve:

- every record's USA is the one its own header says, and the last two bytes
  of each sector are the sequence number;
- `bytes_in_use` and the attribute end marker agree with the attributes the
  record holds;
- the `$INDEX_ROOT`'s entries name records whose `$FILE_NAME` has the same
  parent and the same name;
- the `$Bitmap`'s bits are set for every cluster the runlists name, and clear
  for the clusters the fixture left free — the check that a stage which
  allocates has to keep true;
- `$MFT`'s own `$DATA` covers the records the volume has.

### Keeping it honest against a real volume

A fixture written by the same head that writes the driver shares its
misunderstandings.  So a **script**, not a test, makes a volume with `mkntfs`
and compares shapes: the boot sector's fields, the record size the exponent
implies, the MFT's own runlist, the USA's place.  The probe in this RFC's
Motivation is what that comparison found; it is also how the ISO 9660 work
found what a real Rock Ridge root record is (`xorriso`, and a released
distribution image).  The script is run when the format is in question, and
never from `make verify`: the gates do not depend on a host tool.

### The stages

0. **Read a file end to end.**  `lookup` resolves a path through the index
   instead of answering the root, `read_dir` lists it, `read` follows the
   runlist — and the record size comes out of the boot sector as the format
   says (`1 << |exp|` bytes, and clusters per record as that divided by the
   cluster size, which may be zero) with the MFT's own runlist followed
   rather than assumed.  Proven by reading the fixture end to end, and by the
   probe above answering the record it was asked for.
1. **A write that lands.**  The record's changes are written back: the USA
   applied before the write, `bytes_in_use` and the attribute end marker
   set, and the volume's dirty flag raised while it is in flight.  Proven by
   a **second mount** of the same device reading the new bytes *and the new
   length* — which today never leaves memory.
2. **Growing a file.**  `$Bitmap` is read (as a file, with its own runs),
   clusters are claimed, the `$DATA` runlist is rewritten by the mapping
   pairs' own rules, and the record's allocated size follows.  When the
   attribute no longer fits its record, the `$MFT` itself has to grow, which
   is the same problem one level up — the reason this is a stage and not a
   paragraph.
3. **Creating and removing.**  A record out of the MFT's free space, the
   index insertion and removal, `$Bitmap` again, `$MFTMirr` when the records
   it mirrors change, and the sequence number that makes a removed record's
   number unusable — and the **MFT's own growth**, which is what a volume with
   no free record left needs.
4. **The attribute list.**  A record with no room for its attributes gets an
   **extension record** of its own, named by an `$ATTRIBUTE_LIST` — read
   first, so that a volume taken apart by another writer reads here, and then
   written, which is what lets a record that is *full* grow.
5. **The index allocation.**  A directory whose entries do not fit any
   record's index root keeps them in an **`$INDEX_ALLOCATION` block**, with the
   bitmap that says which of the blocks are in use, and the root's node keeps
   only the pointer to the first one.
6. **Renaming.**  A name lives twice — in the parent's index and in the
   record's own `$FILE_NAME` — so a rename moves both, in the order that leaves
   every window a mount can read; a record's number does not change, which is
   what lets a directory be renamed with everything inside it untouched.
7. **A value that outgrows its record.**  A resident `$DATA` grows into its
   record's own room and, when it has none left, **converts** to one whose
   value is where runs say — which is what a file created empty needs before
   it can take content.
8. **An index that is a tree.**  A directory whose entries outgrow one block
   keeps them in several, with the keys that separate them in the node above —
   read first, so a directory of many names reads here, then **routed**, which
   is a change reaching the block its key belongs in, and then *split*, which is
   a block that is full.

### The journal, decided once

This driver writes **no `$LogFile`**.  A volume carries a dirty flag, and the
driver raises it for the window in which it is changing metadata and clears
it when it is done: that is what tells Windows and `chkdsk` that the volume
needs checking rather than replaying, and it is the one thing about NTFS's
crash story this driver can state honestly.  Nothing here journals, and the
Drawbacks section says what that costs.

## Alternatives

- **A captured image in the tree.**  A volume made by `mkntfs` and committed
  would be the most real thing to test against — and unreadable: a reader
  cannot tell which byte of a blob the fixture was built to test, the diff
  cannot show what changed when the format question changes, and the tests
  would then depend on one writer's choices about allocator layout.  Rejected
  as the fixture; kept as the script that checks the fixture.
- **A generator tool in the test path.**  `tools/` could make the volume the
  way ISO 9660's tests make theirs in Rust — but the gates would then need
  `mkntfs` on the machine, and every test in this tree is self-contained by
  design.
- **Writes first.**  ISO 9660's first stage was a write, and it landed with
  tests.  It could do that because a foreign image was not needed to prove
  it: a file's data is one extent and the write either lands there or does
  not.  NTFS's write lands in a record that this driver currently cannot even
  *find*, and a length that changes in a buffer is not visible to anything
  short of a second mount.
- **A stride, not a runlist.**  The record addressing could be fixed by the
  exponent alone, and left as a stride from the MFT's first cluster.  That
  is correct for a volume that was just made — the probe measures exactly
  such a volume, and `$MFT` is one run of seven clusters there — and wrong
  for every volume that has grown, which is every volume in use.  The
  runlist is one attribute read away.

## Drawbacks

- **A fixture shares its author's misunderstandings.**  The script that
  compares it against a real volume is the mitigation, and it is a manual
  step, not a gate.
- **The first stage is a read, and the feature is a write.**  The road to
  write support for NTFS now has a stage that adds no capability.  What it
  adds is the ability to tell a write landed, which is what every later stage
  is measured by.
- **No journal.**  A volume this driver writes to has no log of the change.
  A machine that mounts it afterwards can only be told, by the dirty flag,
  that it should check rather than replay; a torn metadata write is a
  half-written record, and the fixture's invariants are what say which.
- **`$UpCase` costs the fixture a file.**  NTFS compares names through a
  folding table the volume carries, and stage 3a reads it, so the fixture had
  to grow a 128 KiB table of its own: a fixture without one would exercise the
  driver's fallback — compare the bytes as they are stored — and never the
  format's order, which is what decides where a new name goes.

## Compatibility and migration

The harness changes nothing on disk.  The record-size correction changes what
a *read* means on every volume whose records are a fraction of a cluster —
which is the default shape — from "a different record" to "the record asked
for"; a volume that is currently misread is one this driver cannot be said to
have read at all, so this is a fix rather than a migration.  A volume written
by a later stage stays a volume this driver and a real NTFS can read, which is
what stage 1's record serialisation is for.

## How this is proven

- The fixture's own invariants, listed above, checked by the tests that read
  the volume back — the same shape as ISO 9660's table checks, and for the
  same reason: the code under test is the code that just wrote.
- A **second mount** after every write in stages 1 to 3: a fresh `NtfsFs` on
  the same device, asked the same questions.
- A **volume this driver did not build**: `make check-ntfs-image` makes one
  with `mkntfs`, injects a file with `ntfscp` — a name and bytes the driver
  never wrote — and runs
  `a_volume_mkntfs_wrote_is_read_and_written_back` over it.  The driver reads
  the host's file, creates one of its own, and the script then hands the volume
  it left to `ntfs-3g`'s own reader: `ntfsls` lists both names, `ntfscat`
  reads both files back, and `ntfsfix -n` walks the metadata.  This is the
  harness's answer to the fixture being the driver's own work — the format
  facts the fixture encodes are held against a foreign implementation, on a
  volume neither side built.  It needs the ntfs-3g tools rather than QEMU, so
  it runs in the static tier; what it does **not** prove is the boot path,
  which would need the zone dispatch to know the type.
- The real-volume script for the format facts it is worth asking about, and
  the probe in the Motivation as the case stage 0 has to make stop being
  true: a record number answers with the record that has that number.

## Unresolved questions

- **A torn write is not detected, and it is not silent.**  A 4096-byte index
  block reaches the device as eight sector writes, so a machine that stops
  between two of them leaves half the block new and half of it old.  The
  format's answer is the **update sequence**: every sector ends with a copy of
  the number the array holds, so a block whose sectors disagree is one a reader
  can refuse.  Neither half of that is built — `pack_usa`
  (`src/fs/ntfs/fs.rs`) copies the number and never changes it, and
  `apply_usa_fixup` in the same file writes the array's bytes back into the
  sector ends **without comparing them first**.  It was measured by stopping
  the driver's device after each of its own writes: after the sixteenth write
  of a fill that splits a block, the tree's block holds an entry whose name
  stops at byte 512 — `many-001-pppppp`, then zeros for the two hundred bytes
  the entry claims — and a walk lists that as a name.  A **third** half is the
  same problem: several writers insert the *packed* buffer into `mft_cache`, so
  a record whose attribute spans a sector end is held in the cache with two
  bytes of sequence where its payload should be.  What the fix has to be is
  one change and not three: the sequence changes on every write, a read
  refuses a buffer whose sectors disagree with it, and the cache holds the
  buffer the way the record's own bytes read rather than the way the volume
  stores them.

- **Where does the dirty flag live, and what does Windows need from it?**  A
  volume's `$Volume` carries volume information with a dirty bit, and this
  driver does not read `$Volume` at all.  Stage 1 has to settle which field
  it is, when it goes up, and when it comes down — and whether a volume left
  clean needs anything written into `$LogFile` for a replay to be a no-op.
- **Is case folding a stage of its own?**  *Stage 3a answered this.*  Reading
  `$UpCase` is one attribute in a system record, and using it is a rule in
  every name comparison — and it turned out to be load-bearing for a *write*
  and not only for a lookup, because where a new name goes in an index is
  decided by the same table.  The fixture carries a table of its own for it.
- **The index allocation.**  A directory whose entries do not fit its index
  root keeps them in a `$INDEX_ALLOCATION` the root points at, with an index
  bitmap.  *The measurement behind stage 0 settled part of this*: a directory
  with children has that shape and nothing else — the volume `mkntfs` makes
  holds even one file's entry in the allocation, with the index root reduced
  to a node that points at it — so walking a directory the way a real volume
  stores one is stage 0's work, not a later stage's.  *Stages 3a and 3b built
  the insertion*: a node is rewritten as a run with the new entry where its
  name sorts, and an index *root* — which is a value inside a record — grows
  into the record's own free space when a name does not fit.  What is still
  open is the other answer to a name that does not fit: a record with no room
  gets an allocation block of its own, and with it the index bitmap's bits.
  *Stage 4b* makes such a record's *room* by moving another attribute into an
  extension record, which is enough while the record has one to spare — and
  *stage 5* answers the other half: a directory whose entries do not fit the
  record the root moved to keeps them in a block, with the index bitmap's
  bits, and the root reduced to the node that points at it.
- **Compressed, encrypted and sparse `$DATA`.**  `docs/status.md` records
  that they are not covered.  Writing one is a different problem from writing
  a plain runlist — compression units, EFS metadata, and runs that name no
  cluster — and this RFC does not decide them.
  *[RFC 0013](0013-refuse-the-ntfs-streams-this-driver-cannot-read.md)
  decides them*: a compressed or encrypted stream is refused rather than
  misread, and a sparse one reads and fills as a hole should.

## What landed

**Stage 0, first half — the fixture, and the record addressing.**

- `src/fs/ntfs/tests.rs` builds a **fixture volume** in the two shapes the
  arithmetic differs between: records that are a fraction of a cluster (1024
  bytes in 4096, which is what `mkntfs` makes) and records that are whole
  clusters.  It carries the MFT in **two runs with a gap between them**, an
  update sequence array in every record and index block, a resident file, a
  file in two runs, a subdirectory whose entries are in its index root, a root
  whose entries are in an index *allocation*, a `$Bitmap`, spare records that
  are formatted but not in use, and a check of its own invariants — the
  sequence at every sector's end, the end marker, and the bitmap against the
  layout it just made.
- Three format facts the fixture found by disagreeing with the reader, all of
  them now written the way the format says:
  - **A negative exponent is bytes, not clusters.**  `size_from_exponent`
    (`src/fs/ntfs/types.rs`) is what `NtfsInfo` reads the record and index
    sizes through, so the default shape's records are 1024 bytes and not
    "one cluster" of 4096 — which is what asked for record 5 and got record 0.
  - **A resident attribute's value is where its own header says**, and
    `$INDEX_ROOT` is a *named* attribute, so its value begins after the name.
  - **A runlist's offset is from the attribute, not from the buffer it sits
    in** — which for the first attribute of a record is the same number, and
    for every later one is not.
  - And the update sequence array is unpacked with the *volume's* sector size,
    from the boot sector, rather than the device's.
- `read_mft_record` follows the MFT's own `$DATA` run list: record 0 is the
  one the boot sector names, and reading record 0 is what says where the rest
  of them are.  A stride from the first cluster is right only for a volume
  whose MFT never grew, and the fixture's second run is the shape that says
  so.
- The load-bearing tests: every record of both shapes answers with the number
  it was asked for; and where a stride from the first cluster would have
  looked, it lands on **another** record — with the same `FILE` magic, which
  is why nothing had complained.

**Stage 0, second half — the index, and reading a file end to end.**

- `parse_index_node` (`src/fs/ntfs/fs.rs`) reads a node where the format puts
  it: an index *root*'s value carries its node after the root header, and an
  allocation block after `INDX`, the block's own update sequence array and its
  virtual cluster number.  Two shape facts the fixture settled:
  - **an entry's name begins sixteen bytes into it**, and the field beside the
    entry's length is that name's *length* and not an offset to it — the two
    are the same number only while a name is sixteen bytes long, which is how
    a reader can be wrong about every other one;
  - **an allocation block's node starts its entries forty bytes in**, because
    the block's update sequence array sits in front of them — a node that
    starts them at sixteen is *overwritten* by the array, which is what the
    reader saw as a node with no entries at all.
  - **a child pointer's virtual cluster number is the entry's *last* eight
    bytes**, and the reference field a name entry keeps its record in is left
    zero — found when a writer needed to produce one, and measured on a
    volume `mkntfs` makes.  The fixture and the reader had agreed on the
    reference field, which a real volume leaves zero, so a walk descended by
    an address that was only right while the child was the volume's first
    block.
- `NtfsFs::directory_entries` walks a directory's index the way a real volume
  stores it: from the record's `$INDEX_ROOT`, down the child pointer its last
  entry carries, into the `$INDEX_ALLOCATION` block at that virtual cluster
  number — following the block's own runs and unpacking its update sequence
  array with the volume's sector size — skipping the directory's own "."
  entry and keeping one name per record, the preferred namespace's.
- `resolve`, `lookup` and `read_dir` are that walk: a path is resolved from the
  root down, the root's record being the standard's fifth; a name is matched
  byte for byte, which is what the driver can do without the `$UpCase` table;
  and a node now carries the name its parent's index gave it.
- A **resident** `$DATA` is served from the record the node holds rather than
  from a run list — it has none — which is where a small file's bytes live.

**Stage 0 is done.**  A file reads end to end through a path: five tests over
the fixture, from the root's listing (whose entries are in an allocation) and
the subdirectory's (whose entries are in its index root) to a two-run file
whose second run is the part a reader that stopped early would miss.  What
comes next is stage 1: a write that lands — the record written back, and a
second mount as the proof.

**Stage 1 — a write that lands.**

- A change is written as the **field it is**, in the place it lives, rather
  than by rebuilding the record: the `$DATA`'s value length for a resident
  file, its data and initialized sizes for one with runs.  `parse_attributes`
  now reports each attribute's own offset, so the field's address is the
  record's position on the volume plus that offset plus the header's — and the
  record's position comes from its number mapped through the MFT's runs, which
  is what [`byte_offset_in_runs`] answers.
- A field write is a **read-modify-write of the block around it**
  (`write_device_bytes`), because the device writes blocks and the bytes around
  a field are not this write's to lose.  An in-place field write needs no
  sequence-array handling at all: the array's territory is the end of each
  sector, and a field does not reach it.  A stage that *relocates* an attribute
  is the one that will have to unpack and repack the array.
- A length is bounded by what the file already has — a resident value may
  shrink, and a file with runs may be as long as those runs add up to — and
  anything past that is `NoSpace`, with allocation as the next stage.  A write
  past the end grows first and is a **short write** when it cannot, which is
  the contract's own answer.  A write that would land in a *sparse* run is
  refused rather than reported as bytes it did not store.
- The volume's `$VOLUME_INFORMATION` flags carry the **dirty** bit, and this
  driver keeps it set while it is changing the volume and clears it in
  `sync()`: a change that stops half way leaves the flag up, which is what
  tells a checker to look rather than trust, and the one honest thing a driver
  with no `$LogFile` can say.
- `update_mft_record`, the in-memory re-serialiser, is gone: it built
  attribute headers from scratch with zeroed names, flags and run lengths, and
  nothing ever wrote its output to the volume.  Two of the bugs it hid came
  out with it — the write path's run walk treated a run's *absolute* cluster
  address as if it were a file offset, and `write_device_bytes` underflowed on
  a write smaller than the offset inside its block.
- Five tests, every one of them proved by a **second mount** of the same
  bytes: an overwrite that a fresh mount reads back; a shorter length that a
  fresh mount agrees with; a file shortened to two of its three clusters'
  length and grown back, the second run's bytes still there; a length past the
  runs refused, with a write into that space a short write; and the volume's
  dirty flag going up with the first change and down again at `sync`.  And one
  that pins where a field write does *not* go: the sequence is still at every
  sector's end of the record on the volume afterwards, which is what a reader
  unpacks and what a record-relocating stage will have to put back itself.

**What comes next is stage 2:** growing a file past what it already has —
`$Bitmap` read as a file, clusters claimed, the run list rewritten by the
mapping pairs' rules, and the MFT's own growth when a record's attribute no
longer fits.

**Stage 2a — claiming clusters, and the run list that names them.**

- The **`$Bitmap` is read as a file** — the sixth record's `$DATA`, with its
  own runs — and the clusters the volume says are free are the run of clear
  bits a growth takes.  The bits are set *before* the cluster is handed out,
  so a crash after the answer leaves a cluster claimed and unused, which is
  the harmless direction to be wrong in.
- The run list is **rewritten by the mapping pairs' own rules** — each run's
  length and its signed delta from the one before it, which is a spelling
  `encode_runs` answers and `parse_data_runs` reads back — and the attribute's
  data size, initialized size, allocated size and last VCN follow.  The list
  has to fit the room the attribute already has; an attribute that has
  outgrown it is *relocated*, and that is stage 2b.
- The clusters a file has just taken **read as zeros**: they have never held
  its bytes, and writing them makes them the file's.
- The **node's own copy of the record** is updated with the new run list as
  well as the volume's: a stale list there answered a read with the length the
  file *had*, which is what the first version of this stage did.
- Three tests: a growth that claims a cluster, reads zeros there, writes them
  and is read back by a **second mount**, with the bitmap's count of set bits
  one higher than the fixture's own; a growth the volume has no *run* for
  refused with `NoSpace`; and a write that would need it a short write — zero
  bytes when it starts past the end of a file that cannot grow.

**What stage 2b is:** an attribute whose run list no longer fits its room has
to move inside the record — which is where the update sequence array stops
being something a partial write can ignore.

**Stage 2b — the attribute that has outgrown its room.**

- A run list that no longer fits the room its attribute has means the
  attribute **moves**: it is written last, and every attribute that followed it
  shifts up by the difference.  The record therefore changes from end to end,
  so it is written in **one** piece — the shift crosses sector ends — with the
  update sequence array **packed again**.  `pack_usa` is that direction, and it
  is not the same task as `apply_usa_fixup`: a reader unpacks the record it
  read, and a writer that rewrote it has to put the sequence back.
- `bytes_in_use` and the attribute end marker follow the new layout, and the
  record's copy in the mount's **cache** is replaced with it: a stale cache
  would serve the record as it was before the move.
- **Stage 2's last case, decided rather than built.**  A record that is *full*
  is not a record that is short of records: the MFT growing gives records, and
  what a run list that no longer fits needs is **room**.  The format's answer
  is an `$ATTRIBUTE_LIST` — attributes that live in a record of their own,
  named by the one that owns them — and that is a feature with its own shape:
  a new attribute type, a record's attributes split across two places, and
  every reader of a record taught to follow it.  It is a stage, not this one's
  last line.
- So the refusal stands, and it is now **verified**: the fixture carries a file
  whose record is full to within its end marker, and one more run is
  `NoSpace` — with nothing moved, and a second mount agreeing.  *(Stage 4b
  turns that growth into the one the format gives a record with no room: the
  run list stays where a writer can patch it, and another attribute moves into
  a record of its own.)*
- The MFT's own growth, then, is what *creating* a record needs, which is stage
  3's business and not a full run list's.
- One test: the fixture's *tight* file has a `$DATA` with two runs, no room to
  spare, and a `$EA_INFORMATION` after it.  Growing it by a cluster makes the
  attribute move, and a second mount reads the longer file, the moved run list
  (three clusters in three runs), the attribute that followed it — still eight
  bytes — and the sequence at every sector's end of the record as the volume
  holds it.

**Stage 3a — creating and removing a file.**

- A path's *last* segment is the name and the rest is the directory it is in,
  so a creation is two changes: a **record** out of the MFT's free space, and
  the name in the parent's **index**.  The record goes down first and the name
  second, and a removal is the reverse — a name nothing names a record for is
  the worse half of either crash, so the order is the one that leaves a leak
  rather than a dangling name.
- The record is the first the volume says is free past the sixteen it keeps
  for itself, and **`$MFT`'s own `$BITMAP`** is the volume's word on it: the
  bit is raised *before* the record is written and lowered *after* it is given
  back, so a crash between the two leaves a record the volume calls used that
  nothing names.  A record a volume has never written is all zeros and free
  too — which is what the records past `mkntfs`'s own look like — and its
  sequence then starts at one, where a record that had one gets the next.  The
  bitmap is a **file with its own runs**, which is the shape a real volume
  keeps, and the fixture carries that shape rather than a value inside the
  record.
- The new record is written **whole**: its name, the timestamps a volume with
  no clock leaves zero, an empty and therefore *resident* `$DATA`, its update
  sequence array packed, and the next attribute instance the attributes it
  holds imply.
- **An index node is rewritten as a run** (`write_index_entries`): the entries
  it had, the new one in the place its name sorts to, and the node's own
  terminator last, with the node's own length fields following.  A node with no
  room refuses (`NoSpace`) rather than writing past what it owns — the format's
  answer to a full node is to split it, which is not built — and that refusal
  is verified on the fixture's subdirectory, whose entries are in its *index
  root* and leave no room at all.
- **The collation is the volume's, so `$UpCase` is read**: the tenth record's
  `$DATA` — 128 KiB of code units — folded into every comparison.  A name is
  matched the way a real NTFS matches one (`/RESIDENT.TXT` finds
  `resident.txt`), which is the question this RFC opened, and it is also what
  decides where a new name goes: `a.txt` sorts before `B.txt` because the table
  folds both.
- A removal takes the name out of the index, gives the file's clusters back to
  the `$Bitmap`, and moves the record's **sequence** on with its in-use bit
  down — which is what makes the number that named it stop matching.
- **What is not built.**  An index node is never split, so no block is added
  and the index bitmap is untouched; the MFT is never grown, so a new record
  comes from the records the volume already has *— stage 3c adds that —*; a
  directory cannot be created or removed *— stage 3b adds that —*; and a file
  created empty is resident, so writing content into it needs the
  resident-to-non-resident conversion.  `$MFTMirr` is *not* written, and does
  not need to be: it mirrors the volume's first four records, which this stage
  never touches.
- Seven tests, every write proved by a **second mount**: a created file that
  the fresh mount finds, reads as empty and lists, with `$MFT`'s `$BITMAP`
  naming its record; `$UpCase` folding in a lookup; a new name placed by the
  folded order; a name that is already there refused (`AlreadyExists`); a
  creation the index has no room for refused with nothing left behind; a
  removal the fresh mount agrees with, in the name, the clusters and both
  words on the record; and a directory refused *— which stage 3b makes a
  `Busy` for a directory that still holds something.*

**Stage 3b — directories, and an index root that grows.**

- A **directory is created and removed the same way a file is**: a record out
  of the MFT's free space with its name in the parent's index.  What differs
  is one attribute — an empty `$INDEX_ROOT` in the place of `$DATA` — and the
  flags and the link count that say a record is a directory.
- An empty index root is the shape the reference writer makes: the
  `$FILE_NAME` index's own header (the attribute it indexes, the collation
  rule, the size of a block, and the clusters in one), and then a node with
  nothing but its terminator.  **A directory's entries are its children**:
  the "." and ".." a listing shows are the reader's own, and the `.` that
  `mkntfs` writes into the root it makes is why a reader skips one rather than
  expecting it.  `directory_entries` now skips both, whichever a volume keeps.
- **A name added to a small directory makes its index root longer.**  That
  value is a resident attribute inside the record, and a record's free space
  is what it may grow into: the value's bytes extend, everything after the
  attribute — the end marker included — shifts up, `bytes_in_use` follows, and
  the record goes back whole with its update sequence array packed.  This is
  what the measured reference does: a directory with one child has a
  `$INDEX_ROOT` value of 136 bytes over the 48 it started with, its node's
  index length and allocated size both 120.
- A record that has *no* room refuses (`NoSpace`), and that is the other
  answer this RFC left open: the format gives such a directory an
  `$INDEX_ALLOCATION` block of its own.  The fixture carries a directory whose
  record is full to within its end marker, so the refusal is verified rather
  than implemented — and a name a *failed* creation claimed has given its
  `$MFT` bit back.  *(Stage 4b makes such a record grow instead: the attribute
  that could not grow stays, and another one moves out of the way.)*
- A removal refuses a directory that still holds something (`Busy`, as ISO
  9660 does): its children's names are in *its* index, and a walk that reached
  it would find entries whose parent the volume no longer has.  An empty one
  goes the way a file does — and every non-resident attribute's runs go back
  to the `$Bitmap`, not only `$DATA`'s, because a directory keeps its entries,
  and the bitmap of the blocks they are in, in files of their own.
- Five tests: a created directory a second mount finds, empty, with the
  volume's own record of what is in use naming it; a file created *in* it,
  which is where the index root grows; a name added to a directory that has
  one already, with both listed by the fresh mount; a name a full record has
  no room for refused, with the claimed record given back; and a directory
  that still holds something refused (`Busy`).

**Stage 3c — the MFT grows.**

- Stage 2b said it: the MFT growing is what *creating* a record needs, and a
  volume whose records are all spoken for is the case.  The MFT is a file
  whose content is its records, so growing it is growing a file: clusters come
  from the volume's `$Bitmap`, the run list in `$MFT`'s **own** record gains a
  run — or its last one gets longer, when the clusters continue it — and the
  allocated, data and initialized sizes follow with the last VCN.
- The step is a **cluster's worth of records** (a record's worth where a
  cluster holds only part of one), so one growth answers the one record that
  asked for it.  The measured reference grows the same way: a real `$MFT`'s
  `$DATA` is 70656 bytes of data — 69 records — over 77824 bytes of
  allocation, 19 clusters, with the initialized size equal to the data size.
- **The records the growth made are written as zeros.**  A record a volume has
  never written is all zeros, and that is what the search for a free one
  reads; a cluster that held a file's data would otherwise be a record with
  the wrong `FILE` magic in it.
- `$MFT`'s own `$BITMAP` grows with it, because a record past the bitmap's last
  byte is a record nothing could say was in use.  That bitmap is a *file*
  too — the fields are a non-resident attribute's, the value it uses at +48
  and the space it has at +40 — which is the one thing a first version of this
  got wrong: it wrote the resident attribute's length field at +16, which is
  where a non-resident attribute keeps its **first VCN**.  The test that
  caught it creates a second name after the growth, which is the first thing
  that reads the record past the one the growth was asked for.
- A volume with no free *cluster*, a `$MFT` whose `$DATA` run list has no room
  for another run, and a resident `$MFT` are all refused (`NoSpace`,
  `NotImplemented`) rather than half-grown — the run list's case is the
  relocation the attribute list is for, which is the next stage.  A run list
  that does not fit is refused *after* the clusters are claimed, so the
  clusters are given straight back.
- The fixture builds a second shape: **every record in use**, with the records
  a volume would keep formatted but free named like any other, because a
  record in use is a record some directory names.  `$MFT`'s `$DATA` gains room
  for one more run, which is where a growth appends.
- Three tests: a creation on a full volume that grows the MFT, names the first
  record the growth made, passes to a **second mount** that reads the longer
  MFT, and leaves one cluster of the volume claimed — with a second name
  landing right after the first, no second growth; a creation on a volume with
  free records that does *not* grow it; and a record the growth made that a
  removal frees, and that the next creation takes back on the same mount.

**Stage 4a — reading through an `$ATTRIBUTE_LIST`.**

- The format's answer to a record with no room is an `$ATTRIBUTE_LIST`: a list
  of the record's attributes, each with the record that holds it.  Stage 2b
  named it and refused it; this is the reader half — and the half a *read*
  needs, because a volume another writer took apart is one this driver could
  not read at all before it.
- The entry is 26 bytes and padded to eight: the attribute's type, its
  instance number and its name, the lowest virtual cluster number this part
  covers, and the reference of the record that holds it.  The list does **not**
  name itself — measured on a real volume, where putting a directory's
  `$INDEX_ROOT` in an extension record was what made one — so the attributes a
  record holds in *its own bytes* are kept as well where the list leaves them
  out.
- A non-resident attribute can be **split** by virtual cluster number: the
  parts live in different records, and `attributes_of` puts them back together
  in the order their entries give them.  The entry's *instance* number is what
  pairs a part with the attribute it belongs to, and the *sequence* number in
  its reference is what says the record is the one the list was written about.
- A list is usually a value in the record that carries it, and can be a file of
  its own — which is what the measured volume writes.  Both are read.
- The read path answers with the merged attributes: `lookup`, `read`, a
  directory's index, both bitmaps, the folding table and a record's `$DATA`
  length.  The **writers refuse** (`NotImplemented`) a record whose attributes
  are listed, because patching a field where it lies is only right when the
  attribute is all there.  The removal is the exception that proves the rule:
  it walks the merged view so every cluster goes back, and gives the
  **extension records themselves** back too — a leak nothing else would have
  caught.
- The fixture carries both shapes: one file whose `$DATA` is **split** across
  its own record and an extension (the fragmented shape), and one whose `$DATA`
  has **moved** into an extension whole (the measured shape, its list a file of
  its own).  Neither extension is named by any directory, and the fixture's own
  invariants check that every entry names an attribute the record it points at
  really holds, and that the record it points at names the one that listed it.
- Four tests: the split file reads whole — both parts, and a read that starts
  inside the second — and a second mount reads a rewrite that landed in *both*
  parts; the moved file reads whole, with its extension record in use and
  unnamed; a listed file is refused a length change and still takes an
  overwrite; and a removal gives the extension record and the list's own
  cluster back.

**Stage 4b — writing one: an attribute that moves.**

- A record with no room now answers with the list, instead of refusing: **an
  attribute moves into an extension record**, and the `$ATTRIBUTE_LIST` the
  record it left carries names every attribute of that record and which record
  holds it.  This is the mechanism stage 2b named and refused, and the one the
  measured volume had already used.
- **Which attribute moves**: the largest one that is *not* the one that has to
  grow, so the attribute a writer is about to patch stays where it is.  A
  record full because of its `$DATA`'s run list therefore makes room with
  something else — the fixture's file is full because of a filler attribute,
  and the filler is what leaves.
- The record it goes to is **claimed out of the MFT's free space** like any
  other, growing the MFT when it has to, and its own header carries the base
  reference: in use, no name of its own, and no link to count — which is the
  shape the measured extension record (record 74, holding a directory's
  `$INDEX_ROOT`) had.  The bytes that move are the attribute's *as they lay*,
  so a writer's own flags and padding survive the move.
- The list joins the record **where its own type sorts** — between
  `$STANDARD_INFORMATION` and `$FILE_NAME`, which is where the measured volume
  keeps it — and `bytes_in_use` and the next attribute instance follow it.  The
  record goes back whole, its update sequence array packed again.
- The reader's view is what the writer walks: the merged attributes are what
  `set_len` finds its `$DATA` in and what the removal walks to give clusters
  and extension records back, which stage 4a had already pinned.
- **What is refused.**  A `$DATA` **split** across records is grown only where a
  writer can name one record's bytes, so the split fixture file is still refused
  a length change — while a file whose `$DATA` has *moved whole* into an
  extension record grows there.  *(Stage 4c makes the list itself grow, and
  lets the attribute that needs the room be the one that moves.)*
- Three tests: a file whose record is full grows, its third cluster reading as
  zeros and a second mount agreeing — with the run list in the room the move
  made, the base record carrying a list, the moved attribute in a record whose
  own header points back, the volume one record further into its MFT, and a
  *second* growth landing in the same record; a directory whose record is full
  takes a name the same way; and a file whose `$DATA` already lives in an
  extension record grows *there*.

**Stage 4c — the list grows, and the attribute that needs the room moves.**

- **The attribute that asked for the room goes first.**  Stage 4b made room
  with *another* attribute and kept the growing one where a writer could patch
  it; that is the smaller change, and it is not what the measured volume did:
  ntfs-3g moved the attribute that had to grow — a directory's `$INDEX_ROOT` —
  into record 74.  Now the caller names the attribute that needs the room, it
  moves first, and the caller finds it by the record its list entry names.  An
  index root that moves is written *there*: `index_leaf` answers with the
  record that holds the attribute, and `write_index_leaf` patches that record,
  so a directory whose root has left its record still lists and still takes
  names.
- **The move is a *set*, chosen to fit the list.**  When the attribute's own
  bytes are not enough to hold the list where it was, the largest others go
  with it, biggest first, until what is left of the record fits.  That is what
  makes a record full of several attributes work rather than refuse.
- **A list that is already there grows.**  Its entries name every attribute of
  the file and the record that holds each, so an attribute that moves again
  only changes *its* entry's holder — the list's own length does not change,
  whether the list is a value in the record or a file of its own (whose value
  is written through its runs).
- **What is still refused**, and not carried by the fixture: a record that is
  *itself* an extension (`NotImplemented`) — the file's list is in the base
  record, and extending it from an extension is a step of its own — and a
  record where even moving everything the list names leaves no room for the
  list (`NoSpace`).
- The two stage-4b tests are now *extensions* of it: the file whose record is
  full moves its `$DATA` — the attribute that had to grow — and the filler that
  makes room for the list into one extension record, both entries naming it;
  and the directory whose record is full already *carries* a list, so the name
  that arrives moves the index root out of it and grows it there.  Both keep
  what stage 4b proved: the second mount, the length, the listing, and a writer
  that can still change the file afterwards.

**Stage 5 — the entries leave for a block.**

- The answer a directory needs when a *name* does not fit anywhere: its entries
  leave the index root's value for an **`$INDEX_ALLOCATION` block**; the two
  attributes that describe the allocation — the runs, and the bitmap of the
  blocks, both named `$I30` — go into a record of their own, whose base
  reference names the directory and which the base's `$ATTRIBUTE_LIST` names in
  turn, exactly the way stage 4 leaves things; and the root's node keeps only
  the pointer to the block.
- **When** it happens: the root has already left the base record — stage 4c
  moved it, or the name would not have fitted — and the record it moved *to* is
  full of entries in its turn.  The entries then have nowhere to grow, which is
  what the block is for; a base whose record still has something to spare makes
  room by the route stage 4c built.
- **The block** is `INDX`, its own update sequence array, the virtual cluster
  number it holds, and a node twenty-four bytes in whose entries begin forty
  bytes into *the node* — the array sits in front of them — with the node's
  allocated size what the block has past its header.  A real volume's block is
  the same shape: measured on one `mkntfs` made, the node's entries offset is
  40 and its allocated size the block less 24.
- **The root**, reduced: its node's entries become the one pointer entry, whose
  virtual cluster number is the entry's **last** eight bytes and whose reference
  field is left zero — the fact the pointer fix added to stage 0's list of what
  the fixture had wrong.  Measured, the root's value is then 56 bytes: its node's
  entries offset 16, its index length and allocated size 40, its flags 1.
- **The writes are ordered by what a crash leaves**, and every window is one a
  mount reads: the record that carries the two attributes and the block itself
  first — a record in use that nothing names, and a block nothing points at, are
  leaks, the harmless direction — the base's list second, because the root still
  holds its entries as a value and a listing reads them where they were, and the
  root's node **last**, which is the write that turns the index into a tree.
- **What is refused**: a block smaller than a cluster, which no virtual cluster
  number can address (`NotImplemented`); a set of entries that does not fit one
  block (`NoSpace`, the format's answer to a full block being a split, which is
  not built); a base whose `$ATTRIBUTE_LIST` is a file of its own
  (`NotImplemented`, growing one is a step of its own); and a base that cannot
  hold the two new list entries even after making room (`NoSpace`).
- Two tests: a directory whose record is full runs names in until the root has
  moved into a record of its own and filled *that*, and the entries then leave
  for a block — a second mount lists every name and finds each by its path, the
  shape is checked attribute by attribute (where the root, the allocation and
  the bitmap live, the one bit the index bitmap sets, the two list entries), and
  the crash window above is **replayed**: the two records are rewound to the
  bytes they held the moment before the root's last write, and a mount lists the
  names the root's value still holds.  And a small directory whose root begins in
  its own record fills it the same way, one name at a time.

**Stage 6 — a name that moves.**

- A name lives in **two places**: the parent's index, which is what a walk
  reads, and the record's own `$FILE_NAME`, which is where the record knows the
  name and the parent it has.  A rename moves both, and `rename` is the two
  index changes plus the record's own value rewritten where it lies
  (`replace_value`: a value that has grown shifts what follows it, so the record
  goes back whole with its update sequence array packed again).
- **The order is what a crash leaves.**  The new index entry goes in first, the
  record's own name follows it, and the old entry leaves last: a window then
  holds two names for one record — which a walk reads — rather than a record no
  directory names.  The one order that cannot hold to that is a change of
  *spelling*: two names that fold together are one key in the index, so the old
  spelling has to leave before the new one arrives, and that window is the one
  that can leave a file nothing names.
- **A record does not move and its number does not change**, so renaming a
  directory touches nothing inside it: its children name it by the reference in
  their own `$FILE_NAME` — the only link from a child to its parent, which is
  also what makes *moving a directory into itself* a refusal (`is_inside` walks
  those references upward, bounded).
- A name that does not fit the record's own room makes room the way any growth
  does — stage 4c's move, its largest attribute that is not the name going into
  a record of its own — and the test that proves it is `full.bin`, whose record
  is exactly full.
- **What is refused**: the root, which has no name in a directory to change; a
  name another record already has (`AlreadyExists`); a name to be put in a
  record that is not a directory, or a move into itself or into something below
  it (`InvalidArgument`); and a record whose `$FILE_NAME` is *split* across
  records (`NotImplemented`).
- Seven tests: a file renamed where it is, with the new name found by a second
  mount, the old one gone, the bytes the same, and the record's own name and
  parent checked; a file moved into another directory, with the record naming
  the directory it moved to; a directory renamed with its child still found by
  path; a name that is taken refused with nothing moved; a change of spelling,
  where the listing and the record carry the spelling the caller asked for; the
  three refusals, including a directory moved into itself; and a name too long
  for its record, which makes room and leaves a list behind.

**Stage 7 — a value that outgrows its record.**

- A resident `$DATA` **grows into its record's own room**: the value's bytes
  extend by the growth, which shifts everything after the attribute and is
  written the way any resident value is (`replace_value`, the record whole with
  its update sequence array packed again).  A file created empty therefore
  takes a small write exactly where it is, still resident.
- A growth the record has **no room** for is the conversion: clusters are
  claimed for the whole length, and the attribute — which keeps its instance
  number — becomes one whose value is where the runs say, with the allocated,
  data and initialized sizes after it.  The bytes the record held are written
  into the first cluster and the rest read as zeros, which is what the growth
  means.  A record without the room for the *longer header* makes room the way
  any record does: stage 4c's move, its largest attribute that is not the data
  going into a record of its own, and the conversion is tried again.
- The conversion is not reversible here: a file that shrinks keeps the runs it
  had, and a value that would fit a record again stays where it is.  The
  reverse conversion is what a *reclaiming* stage would need, and it is not
  built.
- **The volume's own state is shared.**  A vnode is handed a clone of the
  filesystem, and a cache and an `NtfsInfo` that each clone kept to itself were
  two views of one volume: a write through a vnode left the mount that made it
  answering with the record it *had*.  The record cache and the volume's state
  are `Arc`s now, so every handle to a mount is a handle to the same two locks
  — the same invariant the earlier stages had to keep by hand, made structural.
  The test that found it is the one above: a growth *on one mount*, read back
  *on the same mount*.
- Two tests: a file made empty takes a small write and the value is still in
  its record; and a file that outgrows its record converts — a second mount
  reads the bytes back, the attribute has runs, the cluster it took is the
  volume's no more, and the file then grows again the way a file with runs does.

**Stage 8 — reading a directory whose index is a tree.**

- A directory whose entries outgrow one block keeps them in several, and the
  shape was **measured** on a volume `mkntfs` made with eighty names in one
  directory: the root's node holds an entry per child but the last, and that
  entry carries a **key** *and* the child — the key's record in the first eight
  bytes, the child's virtual cluster number right-aligned in the *last* eight,
  with the padding a key of any length leaves between them — and the last entry
  has no key at all.
- The child holds the keys **less than** the entry's key, so the entry's key is
  that child's successor, and it is a real name: the measured tree's
  `name-018.txt` lives in the root's node and in **no** block, because a split
  *promotes* it.  A walk therefore takes each child first and the entry's own
  key after it — which is the order the names sort in — and `walk_index` is
  that walk.  `directory_entries` is it, so a listing of a tree holds the
  promoted keys like any other name and `lookup` finds a name whichever node
  holds it.
- **The writer half is not built.**  A node that points at more than one child
  refuses (`NotImplemented`) — routing an insertion by key and splitting a full
  block are the stage after reading one — so a tree directory is read and not
  changed, and the refusal is what keeps an insertion from landing in the wrong
  block.
- The fixture carries the shape: a directory whose index is two blocks with one
  promoted key between them, and the key's own record.
- Two tests: the listing is the tree's order (`alpha.txt`, the promoted
  `middle.txt`, `omega.txt`), and every name is found by its path and answers
  with the record it names; and a tree directory refuses a creation, a removal
  and a rename, with nothing it holds moved.
- What is left is the writer: routing by key, splitting a full block, and the
  index bitmap's own growth when the blocks outnumber its bits.

**Stage 9 — routing a change to the block its key names.**

- A tree's keys are what decide where a name goes: an internal node's entry
  carries a key and the child it points at, that child keeps the keys **less
  than** the key, and the last entry has no key and takes the largest ones.  So
  a change reaches the block that holds the name by taking the first key
  *greater* than it, and the last (keyless) child when no key is — which is what
  `index_leaf` now does, with the name it is asked about.
- A name that is a key **is** the node above the blocks — that is what a split
  promotes — so a change that finds it there answers for itself: an insertion
  says it is already there (`AlreadyExists`), and a removal refuses
  (`NotImplemented`), because taking a promoted key out is the tree *deletion*
  this stage does not have: the entry carries the child whose keys are less than
  it, and dropping it would leave that child unreachable.
- An insertion therefore lands in the right block while that block has room, and
  a **block that is full still refuses** (`NoSpace`): splitting it, promoting
  its middle key into the node above and giving the new block a bit in the index
  bitmap is the stage after this one.  A removal of a name a *leaf* holds works
  the same way it did for one block — the leaf is routed to, and the entry
  leaves it.
- Two tests: a name below the promoted key and a name above it are both created,
  a leaf's name is removed, and a second mount lists them in the tree's order
  with the promoted key still in the middle of it and finds each by its path;
  and the promoted key itself refuses a removal, with nothing the directory
  holds moved.

**Stage 10 — a full block splits.**

- A block with no room for a name is what the format **splits**: half its
  entries move to a block of their own, the entry *between* the halves becomes
  a key of the node above — the entry the walk came through keeps the keys
  greater than it — and the index bitmap gains a bit for the new block.
- The new block's virtual cluster number is the **allocation's next**, which is
  the number its own size names: `$INDEX_ALLOCATION`'s data size divided by the
  block size, times the clusters a block is.  The leaf's own number plus one is
  that only while the leaf is the *last* block, and a tree's blocks are reached
  in key order, which need not be number order — a split beside a middle block
  would have written over the block that already lived at the next number.
- The node above is written from a **fresh read of its record**, not from the
  copy the walk started with, because growing the allocation can *move* the
  root: the run list that outgrows the room its attribute has moves that
  attribute to the end of the record, and the root's node goes with it.  A node
  written back at the offset the walk once measured would put the record back
  the way it was — undoing the growth and the bitmap bit with it, which is what
  the test caught before this was fixed: the allocation grew, and the write
  that followed put the old bytes back.
- The writes keep stage 9's order, one every window a mount reads survives:
  the allocation and the bitmap first (a block nothing points at is a leak),
  the new block next (still unreachable, and its half of the entries is in the
  old block *too*, so a listing shows each name once), the node above after
  that (whose key is what makes the new block reachable), and the old block
  last, with the half that stayed in it.
- One test: a tree directory whose block fills by a handful of names — the
  names are long, because an entry is mostly its name and the fixture's own MFT
  has only so many free records to create with — splits once, and a second
  mount finds one more block, its bit in the index bitmap, every name in the
  tree's order, and each name by its path.
- What is left of the tree is its **deletion**: taking a promoted key out would
  leave the child whose keys are less than it unreachable, and merging two
  half-empty blocks back is the same stage.  The index bitmap's own *growth*,
  for a set of blocks that outnumbers its bits, is not built either — a split
  needs the bit it sets to already have room.

**Stage 11 — the index bitmap grows.**

- The index bitmap names eight blocks per byte, so the block a split makes can
  need a byte the bitmap does **not** have.  A bitmap that is short grows to
  what the bit needs — the value longer where it lives, and the record that
  holds it making room the way any record with no room does — rather than the
  bit being dropped and the block left unnamed.
- One place moves a bit now (`set_index_block_bit`), and both directions go
  through it: raising one for a block a split made, and lowering one for a
  block a deletion gives back.  A byte the bitmap does not have names no block,
  so lowering past the end of the value is nothing to do rather than an error.
- The fixture's tree directory carries an allocation with room for **eight**
  blocks and an index bitmap of **one** byte, with two of the blocks holding
  the tree: the shape a directory reaches when earlier deletions left blocks
  behind, and the one where the next split's bit is past the last byte.
- The split test is what proves it: the block the split makes is the
  allocation's ninth, the bitmap's value is two bytes afterwards, and the bit
  in the second byte is set.  Before this stage that split was `NotImplemented`,
  which is what the bit running off the end of the value used to mean.
- A bitmap that is a **file** of its own would be grown by a step of its own —
  its size and its run list moving together — and still refuses
  (`NotImplemented`).

**Stage 12 — a name comes back out of the tree.**

- A name a **block** holds comes out of the block, and the block it leaves may
  be one the tree no longer has to keep: what that block and the one next to it
  hold is **merged** back into one when it fits, the key that separated the pair
  moving *down* between the two halves, and the block that lost its names is
  given back — its bit in the index bitmap lowered.  A pair that still needs two
  blocks is left as it is, which is an answer (`Ok(())`) rather than a refusal,
  and it is what a removal that left a block *nearly* full hits.
- A name the node **above** the blocks holds is a key a split promoted, and it
  is the case that used to refuse (`NotImplemented`).  A key's entry carries the
  child whose keys are *less* than it, so the entry cannot simply go: what takes
  its place is the key's **predecessor**, the largest name that child holds,
  which keeps the child where it is and leaves the name that is going nowhere at
  all.  The predecessor is then taken out of its block, which is the removal a
  block's name takes — and that block may itself be merged back.  A key whose
  child holds **nothing** is the case where the entry goes as it is, the block
  it pointed at being given back with it.
- The node above is written **first** in that walk.  Written with the
  predecessor's key in it, the removed name is gone and the predecessor appears
  twice — in the node and still in the block — which a walk reads as one name,
  because both copies name the same record.  The other order would leave the
  name in neither.  The merge's own order is the same idea: the merged block
  first (its names reachable twice, counted once), the node above next (after
  which the block that lost its names is not reachable at all), and its bit
  last, which is what gives the block back.
- The clusters of a block that goes back stay part of the allocation, a free
  block inside it.  Taking the tail of an allocation back is a step of its own,
  and the block a split takes is the allocation's *next* rather than the first
  free bit it holds, so a freed block is not reused yet either.
- Three tests: a promoted key is removed and its predecessor takes the key's
  place while the emptied block merges back; a block whose last name comes out
  moves the key that separated it down into the block before it and gives its
  bit back; and the two halves of a split that are still too full to be one keep
  their shape, with neither block's bit given back.
- What is left of the tree is **reusing** a block a deletion gave back, the
  allocation's own shrink, and a tree deeper than one level of blocks under the
  root, which `index_leaf` refuses.

**Stage 13 — a block a deletion gives back is taken again.**

- A split no longer always grows the allocation.  The block it needs is the
  first the index bitmap says is **free** — a block a merge gave back — and only
  when the bitmap names none is it the allocation's *next*, which is the one
  that grows the allocation.  A directory whose index only ever grew would keep
  the volume's clusters claimed for blocks that nothing is stored in.
- A byte the bitmap does not have names no block, and a block nothing names is
  free, which is the same rule that lowering a bit follows.
- A block the bitmap says is **in use** but that the node above does not point
  at is left alone.  That is the shape this driver's own split leaves between
  its two writes (the bitmap first, the node above last), and telling a leaked
  block from a live one is a walk of the whole tree — a repair, not a write.
- The fixture's tree directory carries that shape: its one-byte bitmap names
  eight blocks and its node points at two of them.  A split therefore has
  nothing free to take and appends, which is what keeps stage 11's growth proven
  end to end; and a merge that gives a block back leaves the next split
  something to take, which is what proves this stage.
- The allocation is **not** shrunk when its tail runs out of blocks.  A kept
  block costs nothing to use again, and a shrink that the next split undoes is
  worse than a block left over; taking the tail of an allocation back is a step
  of its own.
- One test: a block that a merge gave back is the block the next split takes,
  with the allocation's size unchanged, the bit set again, and a second mount
  listing every name the directory holds.
- What is left of the tree is a tree **deeper** than one level of blocks under
  the root — which `index_leaf` refuses — and an index bitmap that is a file of
  its own.

**Stage 14 — the index bitmap is a file too.**

- A directory's index bitmap is a value in its record until it outgrows one;
  where it is a **file**, its bits are read and written where its runs say.
  Stage 11's two functions — the search for a block a split can take again and
  the bit that block needs — go through one reader and one writer now, so the
  shape of the bitmap is not something either of them has to know about.
- A bit past the value's last byte **grows** it: the value's data size moves,
  the bytes between the old length and the new are written as zeros (a
  bitmap's unwritten bytes are blocks nothing is in), and the clusters behind
  it are the runs' own where they are there and are claimed where they are
  not — the same growth `write_grown_data` does for any other file.
- The fixture carries the shape: a directory whose index bitmap is one byte in
  a cluster of its own, with its index root pointing at one block.  Filling
  that block splits it, and both the search for a free block and the bit the
  new block sets go through the runs; a second mount lists every name.
- One test runs that end to end, and a direct one behind it: a bit past the
  value grows the bitmap's bytes where its runs say, and the allocation's own
  blocks do not move.
- What is left of the tree is a tree **deeper** than one level of blocks under
  the root, which `index_leaf` still refuses.

**Stage 15 — a tree deeper than one level of blocks.**

- The shape stage 8 reads and stage 9 could not write — a root whose node
  points at a block that points at blocks — is a shape a **change** reaches
  now.  The walk that finds the leaf keeps the nodes it went through, from the
  index root down, instead of only the last one, and the name it is looking
  for is located on the way: a name a node holds as a *key* comes back with the
  node and the entry that carries it, which is what a removal needs and what
  the old walk threw away by answering "not a leaf".
- Two things fell out of that and are the reason the change is worth its size.
  A **merge** now takes the node above the block from the walk rather than
  reading the directory's own record, so a block two levels down merges with
  its neighbour through the *block* that holds the key between them, and a
  removal in a deep tree collapses the two leaves into one.  And the node a
  key is in is written from a **fresh** read of that node, which is the same
  staleness stage 10 found in a split: a merge starting from the copy the walk
  made put back the key the swing had just replaced, and a test caught it.
- What is left is the **split** of a leaf whose node above is a block: a split
  promotes its middle key into the node above, and when that node is a block
  the promotion may fill it in turn.  That is a stage of its own, and until it
  is built a leaf two levels down that fills answers `NotImplemented` — before
  it writes anything, since the refusal comes first.
- The fixture carries the shape: a directory whose index root points at an
  internal block, that block holds the key between two blocks of names, and
  the bitmap says all three are in use.
- Two tests: names are created in the block each one's key belongs in, a name
  is removed, the two leaves merge through the block above them, the block
  that went gives its bit back, and a second mount lists every name in the
  tree's order; and a leaf that fills two levels down refuses the split it
  would need, with every name taken before it still there.

**Stage 16 — a value that comes back into its record.**

- Stage 7 made a resident value take runs when it outgrows its record, and
  said the conversion did not run the other way: a file that shrank kept the
  runs it had, so a file written long and cut short held clusters nothing used.
  It runs both ways now.  A value that shrinks **small enough for the record
  to hold it** becomes resident again — the run list it no longer needs is
  room the value takes — and the clusters come back to the volume.
- The order is the difference between a leak and a volume that reads another
  file's bytes.  The record goes first and the clusters second: the write drops
  the run list, which leaves clusters nothing names if it stops in between,
  while freeing them first would leave an attribute naming clusters the volume
  has handed out again.  A value the record cannot hold stays where it is
  (`NoSpace`), an attribute an `$ATTRIBUTE_LIST` split across records is no one
  record's to rewrite (`NotImplemented`), and a **sparse** stream keeps its
  runs — its holes are not something a record can say.
- What lies past a value's **initialized size** was never written and reads as
  zeros, and a record that holds the value has no way to say that: those bytes
  are made explicit in the conversion rather than left as whatever the
  clusters happened to hold.  That is why `ParsedAttr` carries the initialized
  size now.
- One test: a file written past its record takes clusters, is cut to four
  bytes, and the attribute is resident again with the volume's `$Bitmap`
  showing the cluster back; a second mount reads the four bytes it kept and
  writes into the record the value is in.
