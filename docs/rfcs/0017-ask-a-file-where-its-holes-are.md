# RFC 0017: Ask a file where its holes are

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-10
- **Supersedes:** none

## Summary

RFC 0016 made holes and nothing can ask where they are.  This decides the
query: `lseek` grows two `whence` values — `SEEK_DATA` and `SEEK_HOLE`, the
numbers Linux uses, 3 and 4 — answered from the only map that knows, the run
list, through a new optional operation on `VNode`.  A stream whose answers this
driver cannot stand behind refuses rather than guesses, and the refusals are
the same set RFC 0016's punch refuses.

## Motivation

A hole is worth making only if a caller can find it again.  The programs that
punch and skip are the same programs that ask: a copy that preserves sparseness
asks where the data is so it can skip the rest, an archiver asks the same
question, and both are written against POSIX's two `whence` values rather than
against a kernel-specific call.  Today this tree can make a hole, read it and
fill it, and no program on it can *find* one: RFC 0016 named the query as a
decision of its own and did not take it.

There is a second reason, which is the census.  `docs/status.md`'s NTFS row
records a sparse stream being read and written into; a capability that no
interface reaches is a capability nothing can use, which is the defect this
tree keeps finding in itself in the other direction — code that is written,
wired and never executed.

## Current state

- `src/syscall/table.rs`: `Seek = 9` and its handler `io_fd::seek`, which takes
  a descriptor, a signed offset and a `whence`, checks that the other three
  arguments are zero, and reaches `kernel::io::seek`.
- `src/fs/mod.rs`: `SEEK_SET`, `SEEK_CUR` and `SEEK_END` are `0`, `1` and `2`.
- `src/fs/handle.rs`: `FileHandle::seek(offset, whence)` computes a base from
  the `whence`, adds the offset, refuses a negative result and **sets the
  cursor**; a `whence` it does not know is `InvalidArgument`.
- `src/fs/vfs/vnode.rs`: the shape an optional operation takes — `punch_hole`
  and `set_len` default to a refusal, `set_nonblocking` to a no-op, because a
  node that never blocks has nothing to record.
- `src/fs/ntfs/types.rs`: `DataRun { lcn, cluster_count }`, where `lcn` is `-1`
  for a sparse run, and `ParsedAttr`, whose `data_size` is the file's length,
  and whose `initialized_size` is how much of the value was ever **written** —
  for a resident value, all of it.
- `src/fs/ntfs/fs.rs`: `read_from_runs` is the reader: it walks the run list,
  answers a sparse run with zeros, and is what a hole *is* to this driver.
- `src/fs/ntfs/mod.rs`: `punch_hole` (a whole cluster inside the range becomes
  a sparse run and goes back to the volume) and `convert_to_resident`, which
  reads `min(length, initialized_size)` bytes with the reason in its comment:
  what lies past the initialized size was never written, and the format says
  it reads as zeros.
- `src/abi/fs.rs` and `src/user/shared/abi/fs.rs`: the same file twice, held in
  step by `check-abi-mirror`, which is where a value a *program* has to pass
  belongs.
- `docs/fmts/syscall-abi.md`: `0..=120` is frozen and additive *optional*
  behaviour is the only change permitted there; §4 says a new flag bit moves
  `SYSCALL_ABI_VERSION_MINOR`, which is `4` and pinned by a test.

## Design

**1. The call.**  `lseek(fd, offset, SEEK_DATA | SEEK_HOLE)`:

| `whence` | Value | Answer |
| --- | --- | --- |
| `SEEK_SET` / `SEEK_CUR` / `SEEK_END` | 0 / 1 / 2 | unchanged |
| `SEEK_DATA` | 3 | the first byte at or after `offset` that is data |
| `SEEK_HOLE` | 4 | the first byte at or after `offset` that is a hole |

The numbers are Linux's, for the same reason `fallocate`'s flags are: a call
whose shape already exists should not invent a new spelling of it.  `offset` is
**absolute** for both, the way it is for `SEEK_SET` — the question is about a
place in the file, not about a distance from the cursor — so the handler hands
the value through rather than adding it to a base.

**2. What the answers are, and what they are not.**

- A **hole** is a range whose bytes read as zeros and whose storage the
  filesystem does not hold: a sparse run, and the region the file declares but
  was never written to (past `initialized_size`).  The second half is the
  convention every Unix filesystem already follows for a preallocated extent,
  and it is the format's own rule rather than a choice: those bytes read as
  zeros.
- `SEEK_DATA` at or past the last byte of data is **`NotFound`**, which is
  POSIX's `ENXIO`: the caller asked for something there is not.
- `SEEK_HOLE` at a file's end is the end, because the end of a file is a hole.
- An `offset` **past the end** of the file is `InvalidArgument` — there is no
  file there to ask about — and a negative offset is too.
- A success **sets the cursor** to the answer, which is what `lseek` is for; a
  refusal leaves it where it was.
- The granularity is the run list's: a range a punch could only partly cover
  is still allocated, so it reads as zeros and is still **data**.  A caller
  that wants it back as a hole wants a punch, not an answer.

**3. The `VNode` operation.**  One method, because one walk answers both
questions:

```rust
fn next_extent(&self, offset: u64, kind: ExtentKind) -> Result<Option<u64>>;
```

`ExtentKind::Data` and `ExtentKind::Hole`; `None` is "there is none", the
answer `NotFound` is made from.  Its **default is an implementation, not a
refusal**: every node in this tree that reports a size has bytes from zero to
that size and no holes, so the default answers `offset` for data inside the
file and the end for a hole — which is exact.  A backend whose bytes include
holes overrides it; a backend that cannot say where its holes are refuses with
`NotImplemented`, which is a different claim from "there are none".

**4. The NTFS answer.**  The map is the run list, walked the way
`read_from_runs` walks it: cluster by cluster in file order, a real run is
data, a sparse run is a hole, and the file's **data** ends at
`initialized_size` — past it there is a hole until `data_size`.  What the runs
do not cover is a hole as well, since there is nothing there to read.  A
resident value is all data, and its `initialized_size` is its size, so it needs
no special case.

**5. What refuses, and why it is the same set as the punch.**  A **compressed**
stream is `NotImplemented`: its runs are in compression **units** (RFC 0014),
so the byte arithmetic a hole question needs is the unit walk's, and a hole
inside a unit is the unit's own business.  An **encrypted** stream is
`NotImplemented` for RFC 0013's reason: the driver has no bytes for it, so it
has no map of them either.  A **directory** is `InvalidArgument`.

**6. The ABI.**  The `whence` values move into the shared ABI record
(`src/abi/fs.rs` and the user-facing copy, which the mirror gate holds
identical), because a value a program has to pass is part of the interface;
`src/fs/mod.rs` re-exports them so the kernel keeps one definition rather than
two.  `SYSCALL_ABI_VERSION_MINOR` moves `4` to `5`: the refusal set and the
accepted values of an existing call changed, which is the table's own row for
a new flag bit.  Syscall number `9` is in the **frozen** range, where additive
optional behaviour is the only change permitted and is what this is: a program
that never passes 3 or 4 sees exactly what it saw before.

## Alternatives

- **A new syscall** (`file_extents(fd, offset, kind)`).  Rejected: the shape
  already exists in every program's headers, and a second spelling of "ask this
  file a question about an offset" is a second thing to keep true.
- **A `fiemap`-shaped whole-map call.**  Rejected as the first form: a list has
  to be sized, allocated, copied out and versioned, which is a pointer spec and
  an allocator decision, where the single-offset answer is a loop in the caller
  and no new shape at all.  A caller that wants the whole map is named in the
  unresolved questions rather than pre-paid for.
- **Report the allocated run list only**, without the `initialized_size` rule.
  Rejected: it would answer "data" for bytes the format itself says read as
  zeros, and the caller's purpose is to skip exactly those.
- **Answer for a compressed stream from its runs.**  Rejected: the runs are in
  units, so the arithmetic would be a second implementation of the unit walk,
  and the RFC that put a unit walk there (0014) put it there for a read.
- **Make the default a refusal**, the way `set_len`'s is.  Rejected: every node
  this tree has except the ones that override it *does* have an answer, and a
  default that refuses would make every caller handle an error that means
  nothing for a node with no holes.  The refusals that matter are the ones a
  backend makes deliberately (compressed, encrypted), not the ones the trait
  makes for it.
- **`SEEK_HOLE` only.**  Rejected: the two questions are one walk, and a caller
  that has one and not the other cannot copy a sparse file.

## Drawbacks

- The answer is only as good as the run list: a punch inside one cluster leaves
  the cluster allocated, so the range reads as zeros and is reported as data.
  The caller gets the truth about the *storage*, which is what the two values
  are about, but not "where the zeros are".
- Every caller that walks a file with the pair inherits this filesystem's
  granularity.  That is POSIX's shape, not this tree's invention.
- One more optional `VNode` operation, one more pair of ABI constants, and one
  more thing `docs/status.md` has to keep true.

## Compatibility and migration

No on-disk change and no new syscall number.  The frozen range's rule is
satisfied by construction — nothing a program passes today means anything
different — and the minor version is what records that the accepted values
grew.  A program built before this change that passes `3` or `4` by accident
got `InvalidArgument` and still does not get an answer it did not ask for: the
values it passes now mean the POSIX thing, which is why these numbers and not
others.

## How this is proven

- **The handle, on a node with no holes** (the trait's default, which is what
  every static node and every SimpleFS file takes): data inside the file is
  its own offset, a hole is the end, data at the end is `NotFound`, a hole at
  the end is the end, and an offset past the end is `InvalidArgument`.
- **The fixture's punched file**, whose hole RFC 0016's own gate made: the
  answers are held against the punch that made it — where the punch began is
  where the hole begins, and the bytes the hole covers read as zeros through
  `read`, so the answers and the bytes are two descriptions of one thing rather
  than two claims.
- **A file with no hole at all** (a fixture file written end to end):
  `SEEK_HOLE` answers its length from every offset inside it, and `SEEK_DATA`
  answers the offset it was given.
- **The refusals**: a compressed stream (`NotImplemented` — the fixture's own,
  and the volume `mkntfs -C` made), an encrypted `$DATA` (`NotImplemented`), a
  directory (`InvalidArgument`), an offset past the end (`InvalidArgument`),
  and a `whence` this kernel does not define (`InvalidArgument`, which is what
  it already does).
- **The syscall, as it landed**: the `whence` values and the mirror, the
  number `9` in the frozen range with its golden row unchanged, and the minor
  version and its pinned test moving together.

## Unresolved questions

- **Where a compressed stream's holes are.**  Its runs are in compression
  units, so the question is the unit walk's (RFC 0014).  Until that walk
  answers one, this refuses — which is the safe direction: a caller that is
  refused copies zeros as data and is right, and a caller told a wrong hole
  skips bytes that are the file's.
- **The whole-map form.**  Whether this kernel should also answer "every extent
  of this file at once" is a `fiemap`-shaped decision, and no caller here has
  asked for it yet.
- **`FALLOC_FL_ALLOCATE` and `FALLOC_FL_ZERO_RANGE`**, RFC 0016's two
  neighbours of the punch, are still each their own decision.  A zero-range
  would make a hole the run list does not show, which is the one shape this
  RFC's answer cannot see.
- **A file that *becomes* sparse by a truncation that gives clusters back**:
  the driver's shrink path decides whether the allocation follows the length
  down, and that decision would show up here as a hole.
