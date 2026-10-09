# RFC 0013: Refuse the NTFS streams this driver cannot read

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-09
- **Supersedes:** none

## Summary

This driver reads a **compressed** or **encrypted** `$DATA` as if it were a
plain runlist, which returns bytes that are not the file's — a read that
succeeds and is wrong, the one failure the kernel's own contract cannot
report.  This decides that a stream whose attribute flags say it is
compressed or encrypted is **refused** (`NotImplemented`) rather than
misread; that a **sparse** run reads as zeros and a write into one
**allocates** the clusters it lands in; and that EFS is left to an RFC that
decides this kernel's security model, not to this one.

## Motivation

[docs/status.md](../status.md) records the gap in NTFS's own row —
"compressed, sparse and encrypted streams are not covered and a write into a
sparse run is refused" — and
[RFC 0012](0012-the-harness-an-ntfs-write-is-proven-on.md) left it open on
purpose: "writing one is a different problem from writing a plain runlist".

The gap is worse than a missing feature, and that is measurable.  `mkntfs -C`
makes a volume whose files are compressed, `ntfscp` puts 26,400 bytes of text
in one, and this driver answers:

```
size 26400, first bytes: "a\x00\0the quic\0k brown \0fox jump\xe2s over ..."
```

That is the LZNT1 bitstream: `parse_attributes` carries no attribute flags at
all, so the reader cannot tell a compressed stream from a plain one, and the
compression unit's first cluster is returned as the file's bytes.  A caller
has no way to find out, and neither does a reviewer: the read succeeded.

An encrypted `$DATA` is the same shape of problem with a worse answer, and a
sparse one is the *opposite* shape: its reads are already right — a run that
names no cluster reads as zeros — and only its writes are refused.

## Current state

- `src/fs/ntfs/types.rs`: `ParsedAttr` carries an attribute's type, instance,
  name, holder, offsets and lengths — and **no flags**.  `DataRun.lcn` is the
  absolute cluster number of a run, or `-1` for a run that names none.
- `src/fs/ntfs/fs.rs`: `read_from_runs` fills a sparse run with zeros, so a
  hole already reads the way the format says it should.  `write_to_runs`
  refuses a write that lands in one rather than reporting bytes it did not
  store, and `encode_runs`/`parse_data_runs` carry the sparse bit both ways.
- `src/fs/ntfs/mod.rs`: nothing reads an attribute's flags.  The reader asks
  for a `$DATA` by type and name and takes its runs, whatever the stream is.
- `src/fs/ntfs/tests.rs` carries no sparse and no compressed stream.  The new
  `make check-ntfs-image` mounts a volume `mkntfs` made, which is where the
  bitstream above was found; `mkntfs -C` is what makes one compressed, and
  `ntfscat` on the same image is a decompressing reference to judge against.
- [docs/status.md](../status.md)'s NTFS row records the gap; RFC 0012's
  unresolved questions name it as undecided.

## Design

**1. An attribute's flags are parsed and carried.**  `ParsedAttr` gains
`flags`, from the two bytes at offset 12 of the attribute header, so that
every caller that has an attribute can ask what its stream *is* before it
reads it.  Cost: one field, and the parse that already walks those bytes.

**2. A stream this driver cannot read is refused, not misread.**  A `$DATA`
whose flags carry `COMPRESSED` (0x0001) or `ENCRYPTED` (0x4000) answers
`NotImplemented` for a **read** and a **write**, and the refusal names the
flag.  The file is still *listed* — its name and sizes are in its parent's
index, and a walk of a volume is not a read of every stream in it — so what
fails is the bytes, at the operation that asks for them.

Refusing rather than making the best of it is the whole decision: the
compressed layout's runs name clusters that hold an LZNT1 bitstream, so a
reader that ignores the flag returns something file-shaped and false, and the
caller cannot tell.  `NotImplemented` is attributable; a wrong byte is not.

**3. Sparse: a hole reads as zeros, and a write into one allocates.**  The
zero-fill is already the behaviour and becomes the decided one, with a test
that pins it.  A write that lands in a run with no `lcn` **claims the
clusters it needs and fills the hole**: `$Bitmap` gains the clusters, the
runlist gains real runs inside the hole, and the write is short (`NoSpace`)
only when the volume has no free cluster.  The attribute keeps its
`SPARSE` flag and every other hole: what happens is the same thing Windows
does with a write into a hole, which is that the region written becomes
allocated and the file stays sparse.

Nothing in the tree *makes* a hole: there is no trim, no
`FSCTL_SET_ZERO_DATA` and no way to ask for a range to be deallocated, so a
file this driver wrote is dense.  That half is the unresolved question below,
and it is why this RFC decides the *fill* and not the *make*.

**4. EFS is out of scope until a security model exists.**  An encrypted
stream's key material is not the volume's: `$EFS` names the certificates, the
private key is the *user's*, and this kernel has not decided who may read
whose data.  So the refusal above is not a placeholder for an obvious next
stage — it is the decision, and an RFC that decides the security model is
what would change it.

**5. The stages.**

- **Stage 1 — refuse what is not read.**  `ParsedAttr.flags`, the check on the
  read and write paths, the fixture's two streams, and the tests below.
  Nothing else changes: every file the driver reads today it still reads.
- **Stage 2 — fill a hole.**  The write path allocates into a sparse run, the
  fixture gains a file with a hole between two real runs, and the extension
  is proved by a second mount and by the volume's `$Bitmap`.
- **Unbuilt, and named as such**: LZNT1 decompression (a reader for a
  compressed stream), compression on write, making a hole, EFS, and the
  compression of a *directory's* index — which is a different stream under
  the same flag and is not covered by either stage.

## Alternatives

- **Return the bitstream and document it.**  Rejected: a read that succeeds
  and is wrong is the one failure a filesystem cannot report to its caller,
  and RFC 0012 exists because a reader that answered with the wrong record
  went unnoticed for months.
- **Refuse the whole volume at mount.**  Rejected: one compressed file does
  not make a directory unreadable, and the census the driver keeps is per
  file.  A volume is a tree of names; a stream is bytes someone asks for.
- **Decompress LZNT1 now.**  Rejected for *this* RFC, not forever: LZNT1 is a
  bitstream with a window and a unit size, which is an argument of its own
  with its own measurement (`ntfscat` on a `mkntfs -C` volume is the
  reference).  The refusal is what makes landing it later safe: no build of
  this driver has ever answered a compressed read with something wrong.
- **Convert a compressed file to uncompressed when it is written.**  Rejected:
  it is a real NTFS behaviour, but silently changing a layout the user chose
  is a surprise, and it needs the same spare space a rewrite does.  A
  refusal is the honest half of it for now.
- **Decrypt EFS with a volume key.**  Rejected: there is no such key.  EFS's
  keys are per user, held outside the volume, and no boot has a user yet.
- **Leave a sparse write refused** (today's behaviour).  Rejected: a hole is
  the one of the three that is already readable, and refusing the write
  leaves a file that can be read and not filled, for no reason the format
  gives.

## Drawbacks

- A compressed file cannot be read at all until the LZNT1 stage lands, where
  today it can be read *wrongly*.  That is the point, and it is still a
  capability the tree does not have.
- Two more branches on the read and write paths, and one more field in a
  parsed attribute — the price of never misreading a stream.
- A sparse write that allocates can fail with `NoSpace` where the caller
  might have hoped for a hole; there is no answer that both keeps the hole
  and stores the bytes.
- The census grows by one distinction per file: readable, or refused and
  named.  A reader of `docs/status.md` has one more thing to hold in mind.

## Compatibility and migration

Nothing on disk changes and no format moves: this is about what the driver
does with flags it already reads past.  The behaviour change is from *wrong
bytes* to `NotImplemented`, and a caller cannot have depended on the wrong
bytes — they were not the file's.  No fixture carries a compressed, encrypted
or sparse stream yet, so no test changes for stage 1.

The status row moves in the change that lands each stage, and
`make check-ntfs-image` is unaffected: a volume `mkntfs` makes carries no
compressed file unless `-C` is passed, and no sparse one at all.

## How this is proven

- **Stage 1, as it landed**: `scripts/check-ntfs-image.sh` makes a second
  volume with `mkntfs -C`, injects a compressible file with `ntfscp`, and
  requires that the tool made it compressed (`ntfsinfo` must report the
  compressed attribute flag, so that a file that came out *plain* fails the
  check instead of proving nothing), and
  `a_compressed_stream_on_a_real_volume_is_refused` mounts it, requires the
  file to still be listed and to have its length, and requires
  `NotImplemented` from both a read and a write of its bytes.  The volume and
  the file are the host's, so this is the same fact as the probe above, on a
  volume the driver did not build.
- **The encrypted half is gated too, now.**  No tool on this host can make an
  EFS file, so the fixture carries the shape: `ENCRYPTED_FILE` holds a `$DATA`
  whose flags say it is encrypted — what its runs hold is ciphertext — and
  `an_encrypted_stream_is_refused_and_a_plain_one_beside_it_is_not` requires
  the name to be listed, the length to be answered from the record, the read
  and the write to be `NotImplemented`, and a **plain** file beside it to read
  its runs, which is what keeps the refusal from being a blanket one.
- Stage 2 (filling a hole) is not built: a write that lands in a sparse run is
  still refused, and the census row says so rather than claiming the fill.  A
  later stage's decompressor will be judged against `ntfscat` on a
  `mkntfs -C` volume, which is where the refusal's other half is proven today.

## Alternatives

- **Return the bitstream and document it.**  Rejected: a read that succeeds
  and is wrong is the one failure a filesystem cannot report to its caller,
  and RFC 0012 exists because a reader that answered with the wrong record
  went unnoticed for months.
- **Refuse the whole volume at mount.**  Rejected: one compressed file does
  not make a directory unreadable, and the census the driver keeps is per
  file.  A volume is a tree of names; a stream is bytes someone asks for.
- **Decompress LZNT1 now.**  Rejected for *this* RFC, not forever: LZNT1 is a
  bitstream with a window and a unit size, which is an argument of its own
  with its own measurement (`ntfscat` on a `mkntfs -C` volume is the
  reference).  The refusal is what makes landing it later safe: no build of
  this driver has ever answered a compressed read with something wrong.
- **Convert a compressed file to uncompressed when it is written.**  Rejected:
  it is a real NTFS behaviour, but silently changing a layout the user chose
  is a surprise, and it needs the same spare space a rewrite does.  A
  refusal is the honest half of it for now.
- **Decrypt EFS with a volume key.**  Rejected: there is no such key.  EFS's
  keys are per user, held outside the volume, and no boot has a user yet.
- **Leave a sparse write refused** (today's behaviour).  Rejected: a hole is
  the one of the three that is already readable, and refusing the write
  leaves a file that can be read and not filled, for no reason the format
  gives.

## Drawbacks

- A compressed file cannot be read at all until the LZNT1 stage lands, where
  today it can be read *wrongly*.  That is the point, and it is still a
  capability the tree does not have.
- Two more branches on the read and write paths, and one more field in a
  parsed attribute — the price of never misreading a stream.
- A sparse write that allocates can fail with `NoSpace` where the caller
  might have hoped for a hole; there is no answer that both keeps the hole
  and stores the bytes.
- The census grows by one distinction per file: readable, or refused and
  named.  A reader of `docs/status.md` has one more thing to hold in mind.

## Compatibility and migration

Nothing on disk changes and no format moves: this is about what the driver
does with flags it already reads past.  The behaviour change is from *wrong
bytes* to `NotImplemented`, and a caller cannot have depended on the wrong
bytes — they were not the file's.  No fixture carries a compressed, encrypted
or sparse stream yet, so no test changes for stage 1.

The status row moves in the change that lands each stage, and
`make check-ntfs-image` is unaffected: a volume `mkntfs` makes carries no
compressed file unless `-C` is passed, and no sparse one at all.

## How this is proven

- **Stage 1, as it landed**: `scripts/check-ntfs-image.sh` makes a second
  volume with `mkntfs -C`, injects a compressible file with `ntfscp`, and
  requires that the tool made it compressed (`ntfsinfo` must report the
  compressed attribute flag, so that a file that came out *plain* fails the
  check instead of proving nothing), and
  `a_compressed_stream_on_a_real_volume_is_refused` mounts it, requires the
  file to still be listed and to have its length, and requires
  `NotImplemented` from both a read and a write of its bytes.  The volume and
  the file are the host's, so this is the same fact as the probe above, on a
  volume the driver did not build.
- **Still owed**: the fixture carries no stream with these flags, so the
  **encrypted** refusal — the same code path, decided by the same check — is
  implemented and not yet exercised by a gate.  No tool here can make an EFS
  file (only Windows can), so the fixture is where it has to be proven:
  a record whose `$DATA` carries the encrypted flag, read and written, with
  the file still listed, beside a record whose flags are plain and which still
  reads its runs.  `ntfscat` on a `mkntfs -C` volume is what a later stage's
  decompressor will be judged against.
- **Stage 2**: the fixture's sparse file (a hole between two real runs), the
  test `a_hole_reads_as_zeros_and_a_write_into_it_allocates`, a second mount
  reading the bytes back, and `$Bitmap` showing the clusters the write
  claimed.

## Unresolved questions

- **How does a hole get made?**  Nothing here trims, punches or deallocates a
  range, so a file this driver writes is dense.  Whether this kernel grows a
  `fallocate`-shaped call, and what it does to a file's dense runs, is a
  syscall-visible decision and an RFC of its own.
- **Is a compressed *directory* the same problem?**  NTFS compresses an index
  the same way it compresses a stream, and the flag lives in the same place;
  `$INDEX_ROOT` and `$INDEX_ALLOCATION` are a different reader, and this RFC
  does not decide whether they refuse the same way or grow the same reader.
- **What is a write to a compressed file worth?**  Refusing is honest today.
  Whether the answer should be "convert to uncompressed", "compress the unit
  again", or a `NotImplemented` that never moves, is a decision for the RFC
  that brings LZNT1 to this tree.
- **EFS, if it is ever taken on**: it needs a security model before it needs a
  cipher, and neither is in this tree.
