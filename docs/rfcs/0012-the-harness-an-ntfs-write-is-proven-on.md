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
   number unusable.

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
- The real-volume script for the format facts it is worth asking about, and
  the probe in the Motivation as the case stage 0 has to make stop being
  true: a record number answers with the record that has that number.

## Unresolved questions

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
  A name that arrives at such a record is refused until then.
- **Compressed, encrypted and sparse `$DATA`.**  `docs/status.md` records
  that they are not covered.  Writing one is a different problem from writing
  a plain runlist — compression units, EFS metadata, and runs that name no
  cluster — and this RFC does not decide them.

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
  `NoSpace` — with nothing moved, and a second mount agreeing.
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
  comes from the records the volume already has; a directory cannot be created
  or removed *— stage 3b adds that —*; and a file created empty is resident, so
  writing content into it needs the resident-to-non-resident conversion.
  `$MFTMirr` is *not* written, and does not need to be: it mirrors the
  volume's first four records, which this stage never touches.
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
  `$MFT` bit back.
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
