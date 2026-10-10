# RFC 0015: Compress an NTFS stream on write

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-10
- **Supersedes:** none

## Summary

A file whose `$DATA` carries the **compressed** flag can be read and not
written: the write path refuses one, because its runs hold an LZNT1 stream and
writing bytes into a stream means producing that stream again.  This decides
that the driver **compresses**: a write to a compressed file rewrites the units
from the one the write touches to the end of the stream, with an encoder of
this tree's own, and the file stays compressed.  It does not decide *making* a
file compressed — that flag is the volume's policy, and a call that sets it is
an interface this RFC does not open.

## Motivation

[RFC 0014](0014-read-the-ntfs-streams-lznt1-compressed.md) makes a compressed
stream readable, and [RFC 0013](0013-refuse-the-ntfs-streams-this-driver-cannot-read.md)
refused the write to stop answering with wrong bytes.  A file that can be read
and not written is a second-class file, and the census says so today
([docs/status.md](../status.md), the NTFS row: compressed and encrypted streams
are refused rather than misread).  The encoder's failure direction is the safe
one — one that finds fewer matches writes a **bigger** file, never a wrong one
— and the reader it can be held against is on the host: `mkntfs -C` plus
`ntfscp` make a compressed file, and `ntfscat` reads one back.

## Current state

- `src/fs/ntfs/mod.rs`: `refuse_a_stream_this_driver_cannot_read` is the first
  thing the read **and** write paths do; `write_grown_data` is what writes a
  run list and its sizes; `grow_data` is what the length and the allocation go
  through; `free_clusters` is what gives clusters back.
- `src/fs/ntfs/fs.rs`: `read_from_runs`/`write_to_runs` are the run-list
  readers and writers; `encode_runs`/`parse_data_runs` carry the list itself.
- `scripts/check-ntfs-image.sh`: makes a `mkntfs -C` volume, injects a
  compressible file with `ntfscp`, requires `ntfsinfo` to report the compressed
  flag, and hands the volume to `ntfs-3g`'s reader afterwards.

## Design

**1. What is rewritten, and what is not.**  A compressed stream is a packed
sequence of units, so a unit's compressed length is not its uncompressed
length: inserting bytes into a unit shifts every byte after it.  The units
**before** the write keep their bytes and their positions; the units from the
one the write touches **to the end of the stream** are decoded and encoded
again, one unit at a time, so the work is bounded by the file's tail and the
driver holds one unit of 4096 bytes at a time and never the whole file.  A
sequential write is therefore cheap and a random write near the start of a
large file is not; that cost is a *measurement* this design asks for rather
than a claim it makes.

**2. The encoder.**  One unit at a time: the split of a 16-bit pair at
`12 - index` bits, the distance table the index is found in (0x10, 0x20 …
0x1000), and a greedy matcher over the unit's own earlier bytes — a
three-byte hash into a chain of positions, the longest match within the
current distance window, written with the smallest offset field that carries
it.  This is Linux's `fs/ntfs3/lznt.c` "standard" level (`longest_match_std`
and the `s_max_len`/`s_max_off` tables); its "best" level
(`longest_match_best`) is **not** taken, and is named below as unbuilt.  What
is taken from the reference is its *shape*; the code is this tree's, and the
reason that is safe is §5.

**3. A unit that does not pay is written literally.**  The format has a
second unit shape: header `0x3FFF` (bit 15 clear) and exactly 4096 bytes of
literal data, which is what the reference's own encoder writes when squeezing a
unit made it no smaller.  The encoder emits that shape whenever the compressed
form would not be shorter, so a write can never leave a stream larger than the
plain bytes plus two bytes a unit — and a **wholly zero** input is what the
reference answers with *nothing at all* (its `compress_lznt` returns 0 for an
input that was all zeros), which is the shape RFC 0014 already reads as zeros;
the writer keeps it, and a file written to zeros loses its clusters entirely.

**4. The stream's clusters.**  The suffix's new length is not the old one, so
the allocation moves with it: clusters are claimed for the bytes the new
suffix needs and the ones the old suffix held are given back
(`free_clusters`), and the run list goes back through the same writer
`grow_data` uses, so a list that no longer fits the record is relocated or the
record makes room — **settled before any cluster is freed**, because what is
given back cannot be taken again in the same operation.  Bytes go down first
and the record names them second, which is the order the hole-filling write
already uses; freed clusters go last, after the record has stopped naming them,
which is the order the shrink path already uses.

**5. Why a wrong encoder cannot answer with wrong bytes.**  A compressor's
bugs are of two kinds and both are caught by construction.  A matcher that
misses a match writes a bigger stream; a bitstream that does not decode is
caught by the driver's own reader (RFC 0014's decoder, which refuses a stream
that does not add up) *before* the record names it — and by a foreign reader
afterwards.  What the encoder produces goes through the same `write_grown_data`
the rest of the driver uses, so the extra safety argument is only about the
bytes, not about the record.

**6. What stays as it is.**  The **encrypted** refusal is untouched.  Setting
the compressed flag on a file that does not have it — Windows' per-file or
per-folder "compress" — is a policy and a call of its own, and this RFC does
not open it; a compressed **index** is written by the same encoder but is a
different caller and is not covered here.

## Alternatives

- **Keep refusing writes to a compressed file.**  Rejected: it is the state
  RFC 0013 left, and it makes a readable file unwritable for no reason the
  format gives.
- **Convert a compressed file to uncompressed when it is written.**  Rejected
  by RFC 0013 for the same reason it is rejected here: silently changing a
  layout the user chose is a surprise, and it loses the space the file was
  compressed for.
- **Decode the whole file, splice, encode the whole file.**  Rejected: it
  needs a buffer the size of the file, which a kernel cannot spend on a write.
  Rewriting the suffix holds one unit.
- **Pad every unit to a fixed stride so a write stays in place.**  Rejected:
  it is not the format — another reader would not know the padding is not
  stream — and it spends the space compression was for.
- **Port the reference's encoder wholesale.**  Not taken for the same reason
  RFC 0014 did not port its decoder: what is worth borrowing is the shape, and
  the tree's own comments are where the format's facts are kept.  The safe
  failure direction above is what makes writing it here defensible.
- **Take the "best" level now.**  Rejected for now: it is a search over more
  candidates for a few percent, and the measurement that would justify it is
  the same one §1 asks for.

## Drawbacks

- A write pays for the file's tail.  A sequential writer is unaffected; a
  random writer into a compressed file pays for everything after it, which is
  a cost the format imposes rather than this design.
- The run list grows when the stream's shape changes, so a write to a
  compressed file on a fragmented stream can need `make_room` or refuse with
  `NoSpace`; nothing is freed before that is settled, so a refusal spends
  nothing.
- Compression is now two implementations in one tree (a reader and a writer)
  held to each other and to `ntfscat`, where before there was a refusal.

## Compatibility and migration

Nothing on disk changes and no format moves: the flag, the units and the
header are the format's.  The behaviour change is from `NotImplemented` to the
file's own bytes for a compressed file that is written, and the writer emits
only shapes another reader already accepts.

## How this is proven

- **A unit's round trip, in the fixture**: units a matcher can squeeze (a
  repeated run), one it cannot (a unit of noise, which must come out literal),
  one of zeros, and a stream whose length is not a whole number of units —
  encoded and decoded back byte for byte, with the encoder's output length
  asserted against the shapes it is allowed to emit (never more than the plain
  bytes plus two a unit).
- **The host's own reader as the judge**: `scripts/check-ntfs-image.sh`
  already makes a `mkntfs -C` volume with a compressed file the host can read;
  the stage has the **driver write into that file** and then `ntfscat` read it
  back, required to equal the bytes the driver meant to write.  This is the
  fact no fixture can carry: an encoder this tree did not write, judged by a
  reader this tree did not write.
- **The tail's shape**: a write into the middle of a multi-unit stream, with
  the units before it required to be byte-identical afterwards and a second
  mount required to read the whole file back.
- **The zeros**: a compressed file written to zeros with the no-cluster shape
  read back as zeros, and the volume's `$Bitmap` showing its clusters given
  back.

## Unresolved questions

- **What does a random write into a compressed file cost?**  The suffix
  rewrite is bounded by the tail; whether that is worth a unit cache, a
  "compress from here" strategy, or nothing at all is a measurement, and
  `make check-perf-baseline` is where a number would come from.
- **How does a file *become* compressed?**  This RFC keeps a compressed file
  compressed; setting the flag is a policy the volume's own tools carry
  (Windows' per-file or per-folder setting), and a call that does it is an
  interface decision of its own — RFC 0013's "what is a write to a compressed
  file worth?" is answered here for the write, not for the setting.
- **The "best" level**: a search over more candidates for a few percent, and
  the same measurement as the first question would justify it.
- **A compressed index, written**: the same encoder behind a different caller;
  RFC 0013 asked whether an index refuses like a stream or grows the same
  reader, and this RFC answers only for `$DATA`.
