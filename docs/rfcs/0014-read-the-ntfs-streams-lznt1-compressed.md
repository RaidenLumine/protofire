# RFC 0014: Read the NTFS streams LZNT1 compressed

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-10
- **Supersedes:** none

## Summary

A `$DATA` whose flags say **compressed** is refused today — its runs hold an
LZNT1 bitstream, and reading them as a plain runlist answers with something
file-shaped and false, so [RFC 0013](0013-refuse-the-ntfs-streams-this-driver-cannot-read.md)
decided the operation is `NotImplemented` rather than wrong.  This decides the
other half of that: the driver **decompresses** the stream, one compression
unit at a time, and answers with the bytes the file has.  A stream this decoder
cannot account for stays refused (`InvalidArgument`); a **write** to a
compressed file stays refused; a compressed **index** is not covered.

## Motivation

The census says it plainly: compressed and encrypted streams are *refused
rather than misread*, and the refusal is the whole of what exists — a file
`mkntfs -C` compressed cannot be read at all
([docs/status.md](../status.md), the NTFS row).  RFC 0013 called LZNT1 "an
argument of its own with its own measurement" and left it to this document;
what it bought is that no build of this driver has ever answered a compressed
read with bytes that are not the file's, which is the ground this reader stands
on.  The reference is on the host and in the tree's own tests: `mkntfs -C` plus
`ntfscp` make a compressed file that `ntfscat` reads back, and
`make check-ntfs-image` already builds that volume and requires the file to be
compressed (`ntfsinfo`) and the driver to refuse it.

## Current state

- `src/fs/ntfs/mod.rs`: `refuse_a_stream_this_driver_cannot_read` is the check
  the read and write paths both begin with; `NtfsVnode::read` follows the data
  runs through `fs::read_from_runs`.
- `src/fs/ntfs/fs.rs`: `read_from_runs` is what walks the runs and fills a
  sparse run with zeros; `parse_data_runs`/`encode_runs` carry the run list.
- `src/fs/ntfs/types.rs`: `ATTR_FLAG_COMPRESSED` (0x0001) and
  `ATTR_FLAG_SPARSE` (0x8000) are parsed already.
- `src/fs/ntfs/tests.rs`: the fixture carries an `ENCRYPTED_FILE` (the
  refusal's gate) and no compressed stream; the compressed fact is carried by
  the real volume `scripts/check-ntfs-image.sh` makes.

## Design

**1. The stream, as the format writes it.**  A volume compresses a
**compression unit** at a time — sixteen clusters by the standard's own
maximum, and the exponent is a byte of the `$DATA` attribute itself — and inside
one of those the bytes are a sequence of 4096-byte LZNT1 **chunks**.  What a
squeezed compression unit did not need of its clusters is left a **sparse run**,
so a unit's bytes are at the unit's own place in the stream and the units are
not contiguous; a unit whose squeezed bytes were no smaller is stored **as it
is**, which the run list says: its real clusters cover it whole.  Each chunk is
a 16-bit little-endian header followed by its payload:

| Field | Meaning |
| --- | --- |
| bits 11..0 | the payload's length **less one** |
| bit 15 | 1: the payload is a compressed unit; 0: it is 4096 bytes of literal data |
| bits 14..12 | `0b011`, the shape the reference's encoder writes |

so a unit's bytes are `3 + (header & 0x0FFF)` long, header included, and one
that does not fit what the runs hold is a stream that does not add up.  A
compressed payload is a byte of eight **flags**, most significant bit first,
each of which says whether the next item is a literal byte or a **pair**; a
pair is a 16-bit little-endian value whose high and low halves split at
`12 - index` bits, where `index` is how far the unit's output has already
grown (the thresholds are 0x10, 0x20, 0x40 … 0x1000): the high half is
`distance - 1` and the low half is `length - 3`, and the item copies `length`
bytes from `distance` bytes further back **inside the same unit**.  A pair
whose distance reaches before the unit's start, or a length that runs past the
unit's end, is a stream that does not add up.  The reference is Linux's
`fs/ntfs3/lznt.c` (`decompress_chunk` and the `s_max_off` table it indexes
with), whose only differences are choices of error numbers.

**2. What a read does.**  Chunks are independent — nothing is carried across a
chunk boundary — and units are too, so a read needs exactly the compression unit
its range touches: which unit that is, is a **count** (`offset / unit bytes`),
because a unit's bytes are at the unit's own place, and inside it the chunks
follow each other, so the walk steps over their headers, `2 + (header &
0x0FFF)` bytes at a time, until it reaches the chunk that holds the offset.  A
unit stored as it is has no headers to walk at all: it is read outright.  A read
of `n` bytes therefore decodes at most one compression unit's worth of chunks
plus the bytes it was asked for, and nothing is kept between reads: a
measurement of what a boot's reads cost is what would argue for a cache, and
this document does not have that measurement.

**3. What the bytes are.**  The attribute's `data_size` is the length the
file has, and the units are read until it is answered; the last unit's output
is cut to it.  A file **with no clusters at all** and a length — which is what
the reference's own encoder leaves behind for an input that was entirely
zeros (`compress_lznt` answers 0 for it) — reads as zeros, because that is
what its units decompress to.  A stream that ends (a zero header, or the
payload the runs hold running out) while the length still wants bytes that are
not zeros is `InvalidArgument`: a read that succeeds and is wrong is the one
failure this driver does not have.

**4. What does not move.**  The refusal for **encrypted** streams
(`NotImplemented`) is untouched.  A **write** to a compressed file is
`NotImplemented` as it is today: this RFC is about reading a stream the volume
squeezed, and RFC 0013's question about what a write to one should be stays
open.  A compressed **index** (`$INDEX_ROOT`/`$INDEX_ALLOCATION` under the same
flag) is a different reader and is not covered: it stays refused.

**5. Where the code goes.**  A decompressor beside the driver, in a module of
its own — the unit loop, the flag loop, the distance table — with
`read_from_runs`' caller
choosing it when the attribute's flags say compressed, and the walk of the
unit headers next to it; the write path's `refuse_a_stream_this_driver_cannot_read`
keeps saying `NotImplemented` and the read path stops calling it for the
compressed flag only.

## Alternatives

- **Keep refusing.**  Rejected: the stream is readable, the format documents
  it, the reference implementation is on this host, and the census names the
  gap.  RFC 0013 refused it to stop answering with the wrong bytes, not
  because the bytes are hard to get.
- **Decompress the whole stream at mount, or on the first read, and keep it.**
  Rejected for now: it costs a buffer the size of the file and the work for a
  file nobody may read; the per-read walk is bounded and the measurement that
  would argue for a cache has not been taken.
- **Cache the last decompressed unit.**  Tempting and rejected for the same
  reason: a sequential read already decompresses each unit once, and this
  document would rather land the reader with no state and measure than land
  state it cannot justify.
- **Read the units out of order by their headers' offsets.**  Rejected as
  impossible: a unit's length is only known from its header, so the headers
  before it have to be walked whatever else happens.
- **Refuse a stream that does not add up with `NotImplemented`.**  Rejected:
  `NotImplemented` is "this driver does not do that", and a broken stream is
  the *volume's* word, not this driver's; `InvalidArgument` is what a caller
  can act on.
- **Decompress through a port of ntfs-3g's or the kernel's code.**  Not taken:
  the algorithm is a table and two loops, and the tree's own comments carry
  the format's facts; what is worth borrowing from the reference is its
  *shape*, which the design above names.

## Drawbacks

- A read of a compressed file costs a walk over unit headers it does not read.
  For a sequential read that is two bytes per unit, which is noise; for a
  random read near the end of a large file it is the whole header walk, and a
  cache is what a measurement would have to justify.
- One more reader to keep true, and the first one in this driver whose failure
  mode is "a bitstream that does not decode" rather than "a structure that does
  not fit".
- The write path stays asymmetric with the read path: a file can be read and
  not written, and the census has to say so.

## Compatibility and migration

Nothing on disk changes and no format moves: this is what the driver does with
a flag it already reads.  The behaviour change is from `NotImplemented` to the
file's own bytes for every compressed stream that decodes, which cannot break a
caller that had nothing to depend on but a refusal.

## How this is proven

- **A unit's own decode, in the fixture**: a record whose `$DATA` carries the
  compressed flag and a hand-built stream — at least two units, one holding a
  literal-only payload and one holding a pair — read back byte for byte
  against what the fixture encoded, including a read that starts and ends
  inside a unit.
- **A stream that does not add up**: a second fixture stream whose pair reaches
  before its unit's start, read and refused with `InvalidArgument`, with the
  file still listed and its length still answered from the record.
- **A volume `mkntfs -C` made, and the host's own file as the answer to it**:
  `scripts/check-ntfs-image.sh` already injects a compressible file and
  requires `ntfsinfo` to say the attribute is compressed; the stage extends it
  to keep the file it injected, and the test reads the driver's bytes back and
  requires them to equal that file.  This is the fact the fixture cannot
  carry: an encoder written by someone else, on a volume neither side built.
- **The refusal that stays**: `a_compressed_stream_on_a_real_volume_is_refused`
  becomes "is read", and the encrypted stream's refusal keeps its own gate, so
  the two flags are still told apart.

## Unresolved questions

- **What is a write to a compressed file worth?**  Refusing is honest today.
  Whether the answer should be "convert to uncompressed", "compress the unit
  again", or a `NotImplemented` that never moves, is a decision for the RFC
  that takes it on — RFC 0013 left it there and this document does not move it.
- **Is a compressed *directory* the same problem?**  NTFS compresses an index
  the same way, under the same flag; `$INDEX_ROOT`/`$INDEX_ALLOCATION` are a
  different reader with a different failure mode (a name that does not decode
  is a directory that does not list), and this RFC decides only the stream.
- **Does a boot's read want a unit cache?**  The walk is bounded and the
  decompression is per unit; a boot's workload is what would say whether the
  walk is worth removing, and `make check-perf-baseline` is where a number
  would come from.
- **What does the format say about a stream that ends early?**  A wholly-zero
  file is stored with no clusters at all, which this design answers with zeros;
  whether a *partial* stream that ends before its length is legal (padding
  beyond the last unit) is a fact a volume made by another writer would settle.
