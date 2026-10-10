# RFC 0016: Punch a hole in an NTFS file

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-10
- **Supersedes:** none

## Summary

RFC 0013 filled a hole an NTFS write reached, and left the obvious gap: this
driver can *write into* a hole and has no way to **make** one.  This decides
the interface that makes them: a `fallocate`-shaped call with
`FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`, a new `VNode` operation a
filesystem implements or does not, and the NTFS implementation — the range's
whole clusters become a sparse run and go back to the volume, and the bytes
inside the clusters the range only partly covers are written as the zeros the
hole reads as.

## Motivation

A hole is the one shape this driver can read (RFC 0013), fill (RFC 0013's
stage 2) and not make, and the census says so
([docs/status.md](../status.md), the NTFS row: a sparse stream is read and
written into, and nothing there trims or punches).  What a hole is *for* is
space: a caller that knows a range of a file is meaningless can have the
volume's clusters back and the bytes still read as zeros, and that is a
decision no lower layer can make on its behalf.  It is also the syscall-shaped
half of "sparse files": the format has run lists that name no cluster, and
nothing in this kernel can produce one.

## Current state

- `src/syscall/table.rs`: the syscall table and `PUBLIC_SYSCALL_COUNT`, whose
  numbers at and above 121 the ABI's own document leaves **experimental**
  ([docs/fmts/syscall-abi.md](../fmts/syscall-abi.md), which is also the
  checklist a new call has to walk).
- `src/fs/vfs/vnode.rs`: the operations a `VNode` may have, with `set_len` as
  the shape an optional one takes — a default that answers `NotImplemented`,
  and an implementation where a filesystem can do it.
- `src/fs/ntfs/mod.rs`: `free_clusters` gives a file's clusters back;
  `fill_the_holes` is the write-side inverse of what this RFC adds, and is
  where the shape of that inverse lives.
- `src/fs/ntfs/fs.rs`: `encode_runs`/`parse_data_runs` carry the run list,
  sparse run included.

## Design

**1. The call.**  `fallocate(fd, mode, offset, length)`, POSIX's order and
Linux's flags:

| Flag | Value | Meaning |
| --- | --- | --- |
| `FALLOC_FL_KEEP_SIZE` | 0x01 | the file's length does not change |
| `FALLOC_FL_PUNCH_HOLE` | 0x02 | the range reads as zeros and its clusters go back |

The two together are the only mode this RFC defines, and Linux requires them
together for a punch as well: the range becomes zeros and the length stays, so
a caller cannot lose bytes it did not ask to lose.  A mode with any other bit
set is `NotImplemented`; a range past the end of the file is not a punch at
all (there is nothing there to make zeros of) and is `InvalidArgument`; a
descriptor that is not a file is `InvalidArgument`.  The call's number comes
from the experimental space at or above 121, which is where a new call is
allowed to land without an ABI version bump.

**2. The `VNode` operation.**  `punch_hole(&self, offset: u64, length: u64)`,
defaulting to `NotImplemented` the way `set_len` does, so every filesystem
that does not care says so in one place and a caller can tell "not for this
filesystem" from "not with these arguments".  It is a range operation rather
than a flag on `set_len`, because `set_len` has one end and this has two.

**3. The NTFS implementation, which is an inverse.**  The range is walked over
the run list in whole clusters.  A cluster **wholly inside** the range becomes
a sparse run: its data goes back to the volume with `free_clusters` and the
run list says a hole was there.  A cluster the range only **partly** covers
cannot go back — the bytes beside the range are the file's — so those bytes are
written as zeros and the cluster stays.  The result is the shape
`fill_the_holes` already produces in reverse: a run split into the piece
outside the range, a sparse run, and the piece after it.

**4. The order, which is stage 19's lesson.**  A punch **adds runs** to the
list, so the list it will have is built and its room settled *before* a single
cluster is freed: a record that cannot hold the longer list makes room first,
and a punch that cannot be worked out refuses with `NoSpace` having freed
nothing — a freed cluster cannot be taken again in the same operation, and a
refusal that spends the volume's space is worse than one that does not.  The
record is written after the zeros and before the frees, so a machine that stops
in between leaves clusters nothing names rather than a file whose bytes are not
its own.

**5. What does not move.**  The length and `initialized_size` are untouched
(`KEEP_SIZE` is the point): the range reads as zeros because its runs are
**sparse**, which is the fact RFC 0013's reader already answers, not because
anything was un-initialized.  `lseek`'s `SEEK_HOLE`/`SEEK_DATA` — a *query*
about where the holes are — is not part of this: a caller that wants to ask is
a second call and a second decision.  Making a *new* file sparse, or a whole
file at once, is the same operation on a range that covers it.

## Alternatives

- **Leave it unbuilt.**  Rejected: a hole that can be filled and not made is a
  capability with no way to use it, and the census names the gap.
- **A flag on a truncate-shaped call.**  Rejected: truncation has one end and
  a punch has two, and a call whose argument is a *range* should say so in its
  arguments rather than in a bit.
- **Only whole-cluster ranges, refusing the rest.**  Rejected: a caller
  computes a range from the bytes it cares about, not from this
  filesystem's cluster size; the driver zeroes the partial ends instead, which
  is what the format leaves it able to do.
- **`lseek(SEEK_HOLE)`/`SEEK_DATA` instead.**  Rejected as a *substitute*:
  those report holes, they do not make them.  It is named above as a decision
  this RFC does not take.
- **A new operation that also allocates (`FALLOC_FL_ALLOCATE`).**  Not taken:
  allocating ahead of a write is a different promise (the bytes are not the
  file's yet), and nothing in this tree asks for it.
- **Free the clusters first and fix the run list after.**  Rejected: a run
  list that cannot hold the hole leaves clusters that are already the
  volume's, which is a file that reads back someone else's data.

## Drawbacks

- A punch can need `make_room`, and a punch on a fragmented file can refuse
  with `NoSpace` having done nothing; the caller is told rather than served a
  half-punch.
- A partially-covered cluster is written to in full, which is a write on a
  path the caller may have thought was metadata-only.
- One more optional `VNode` operation, one more syscall number in the
  experimental space, and one more thing the census has to keep true.

## Compatibility and migration

No on-disk change and no ABI bump: a sparse run is a run list another reader
already understands, and the call's number is taken from the range the ABI's
own document leaves experimental.  The behaviour change is a range that used to
answer `NotImplemented` from a call that did not exist before, which cannot
break a caller.

## How this is proven

**The `VNode` half and the NTFS half, as they landed.**  `punch_hole` is an
optional operation on `VNode` — its default refuses the way `set_len`'s does
(`PermissionDenied`, not `NotImplemented`: the error the tree already uses for
an operation a node does not have) — and the NTFS driver implements it: the
whole clusters inside the range become a sparse run and go back, the clusters
the range only partly covers are written as zeros, the run list is built and its
room settled before a cluster is freed, and the stream is marked sparse with the
flag the format keeps for exactly that.  A compressed or encrypted `$DATA`, and
a directory, refuse with their own answers, and a resident value refuses too
(`NotImplemented`: a hole in a value that lives in the record is a shape of its
own).

- **The fixture's file, punched**: a range inside a file's runs read back as
  zeros, the volume's `$Bitmap` showing exactly the clusters the punch gave
  back, the file's length unchanged, and a second mount reading the same
  bytes.
- **The partial cluster**: a range whose ends fall inside a cluster, with the
  bytes for the file before and after it required to survive and the range
  between them required to read as zeros.
- **The refusals**: a punch whose range reaches past the end
  (`InvalidArgument`), an unsupported mode (`NotImplemented`), a directory
  (`InvalidArgument`), and a punch on a file that cannot hold the longer run
  list (`NoSpace`, with the volume's `$Bitmap` unchanged — the gate for §4's
  order).
- **The syscall, as it landed**: `fallocate` is number **193** — the first free
  slot above the experimental range, with `SYSCALL_COUNT` and the ABI's minor
  version (4) moved with it — and its only mode is
  `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`: both bits, or the answer is
  `NotImplemented` rather than a bad argument.  It reaches a file through the
  descriptor, the way `set_len` does (`kernel::io::punch_hole`, `OpenFile`,
  `FileHandle`, `VNode`), its pointer spec is the empty one (four integers), and
  its tests are the mode refusals, the reserved-argument refusal, and a
  descriptor with no file behind it.  What is still owed is the **end-to-end**
  test: no gate punches a range through the interface and reads zeros back
  through it, because the volume the punchable filesystem lives on is the
  fixture's and the interface's own gate would have to mount it.
- **A punch whose run list cannot be held, as it landed**: the fixture carries
  `/sub/full-long.bin` — one run of three clusters, in a record with no room —
  so a punch of the middle cluster is a hole with a real cluster on either side
  of it, three runs where there was one.  The test fills the volume first, by
  writing files until neither a cluster nor a record is left (the last growth of
  the MFT leaves records behind, so those are taken too), and then requires
  `NoSpace` with the volume's `$Bitmap` unchanged.  The order §4 argues about is
  what makes that the answer: the list is built and its room asked for before
  anything is freed, and the refusal spends nothing.
  Getting there found a defect **below** the punch, in `encode_runs`: a run
  list's offset is a signed field, and a *positive* distance of 128 or more was
  written without the byte that says it is positive — so a reader that
  sign-extends read the run as a *negative* one, which the driver's own reader
  answers as a sparse run.  The fixture's own file is what made it visible (its
  run is at cluster 129), and the gate is
  `a_positive_delta_that_looks_negative_round_trips`: an encoder and a decoder
  held to each other across the sign bit.

## Unresolved questions

- **`SEEK_HOLE`/`SEEK_DATA`**: a caller that wants to *ask* where a file's
  holes are wants a query, and whether this kernel grows one is its own
  decision.
- **`FALLOC_FL_ALLOCATE` / `ZERO_RANGE`**: allocating ahead of a write and
  zeroing a range without giving its clusters back are the two neighbours of
  this call; neither is decided here.
- **A punch across an allocation the driver would have to shrink**: a file
  punched at its *end* leaves clusters past the length; whether the allocation
  follows the length down is the same question the shrink path already answers
  for data, and a punch that only makes holes does not have to answer it.
