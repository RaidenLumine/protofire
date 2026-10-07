# RFC 0008: Keep a sequential miss in one request

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-07
- **Supersedes:** none

## Summary

[RFC 0007](0007-hold-a-second-request-on-a-device.md) decided the queued
device interface and named, as its first caller, "a read-ahead that submits
the next run before polling the current one".  The interface landed with a
boot probe instead, and this RFC decides that the read-ahead should **not**
follow it: the block cache keeps the caller's block and its lookahead in
**one** request on every device.  Splitting them so the demanded block can
come back first would put back the commands the coalescing was measured to
remove, and would buy the caller no earlier block — a device's price for 512
bytes and for 2560 contiguous bytes is the same fixed cost, and in a
sequential scan there is no window for the second request to hide in.

## Motivation

RFC 0007's Design section is the only place in the tree that names a caller
for the queued interface, and it is the reason the interface was judged
buildable at all: an interface no caller uses cannot be verified.  The caller
that landed is a probe in `src/kernel/workload.rs`, which is honest — it says
that is what it is — but a probe is not a reason.  The read-ahead was
supposed to be, and before writing it this RFC asks whether it pays.

## Current state

- **The read path.**  `BlockCache::read_cached` (`src/fs/block_cache.rs`)
  serves a hit from the pool.  On a miss it decides whether the read is
  sequential and, if it is, counts `lookahead` blocks after the demand —
  stopping at the first block that is already cached — and reads
  `lookahead + 1` blocks in **one** `read_blocks` call into a stack scratch
  buffer, inserting all of them.
- **The parameters.**  `PREFETCH_RUN_BLOCKS` is 4, and SimpleFS opens its
  cache with `BlockCache::with_read_ahead(device, 4)`
  (`src/fs/simplefs/superblock.rs`), so one sequential miss is a five-block
  request.
- **The measurement that turns this.**  The same file records what coalescing
  bought, measured on the demo boot: with the prefetch coalesced into one
  request the boot issues **208** device reads instead of **327** with
  read-ahead off — 36 % fewer commands for 0.9 % more traffic — and depth 8
  gives 189 reads.
- **The explicit form has no caller.**  `BlockCache::prefetch` is read-ahead
  as its own call, and nothing in the tree calls it; its only callers are the
  cache's own tests.
- **The interface exists.**  `BlockDevice::queue_depth`, `submit_read` and
  `poll_read` are in the tree and gated ([RFC 0007](0007-hold-a-second-request-on-a-device.md));
  the NVMe driver answers a depth of two.

## Design

**The decision: the demand and its lookahead stay in one request.**  Nothing
in the read path changes.

**Why the split cannot pay.**  Reading `[lba, lba+4]` and reading `[lba, lba]`
then `[lba+1, lba+4]` move the same 2560 bytes.  They differ in three things,
and the split loses all three:

- **Commands.**  One versus two.  The coalescing above is exactly the
  difference between 208 and 327 commands in a boot, and a split takes
  roughly one command per sequential miss back.
- **The caller's wait.**  The same, or worse.  A device's cost for a 512-byte
  request and for a 2560-byte request that is contiguous with it is the same
  order — fixed command cost dominates on a queueing device, the seek
  dominates on a rotating one — so the two-command form waits for one command
  and then for another, while the one-command form waits once.
- **The overlap.**  None.  A queue is worth having because a second request is
  in flight while the first is waited on, and in a sequential scan the next
  access arrives immediately: the lookahead would be polled again before it
  had had time to finish.  There is nothing for the overlap to hide behind.

**And the cache is the wrong shape for the borrow.**  A queued read borrows
the caller's buffer until its ticket is polled, which is the `unsafe`
contract [`BlockDevice::submit_read`](../../src/kernel/block.rs) states.  The
probe satisfies it by construction — both of its buffers are locals and it
polls them before they die.  The cache cannot: its buffers are its own, and a
persistent one would be cache-owned memory the cache frees when the volume
goes away, so a device that never completes would be writing into freed
memory.  Closing that would take a drain in `Drop` plus a rule for a device
that never answers — machinery for a read the caller cannot use any sooner.

## Alternatives

- **Split only when the device queues.**  Leaves the four depth-one baselines
  byte-identical and changes the disk one — and still pays the extra command
  for no earlier block.
- **Submit the lookahead queued and never wait for it.**  This is the split
  with the wait moved to the next access, which in a sequential scan is the
  next instruction.
- **Make `prefetch` the caller.**  It is the call that means "I do not need
  this yet", and it has no caller: the read path folds its lookahead in
  precisely because a second request was worse.  Giving it one means
  inventing a reader that can be ahead of its own demand, which is the thing
  this RFC finds does not exist here.
- **Leave RFC 0007's caller unbuilt and say nothing.**  That is the state
  today, but as a default rather than a decision.  Deciding it out loud says
  where the next caller has to be looked for: a path whose requests really
  are independent of each other.

## Drawbacks

- **The queued interface's only caller stays a probe.**  Its justification
  moves to whatever earns it a real one, and until then the interface is
  verified as a *mechanism* and unexercised as a *benefit*, which
  `docs/status.md` and `ROADMAP.md` say in their own words.
- **This is a decision about today's parameters.**  A device whose fixed
  command cost is negligible beside its transfer time, or a lookahead of tens
  of blocks rather than four, would change it.  Whoever revisits it should
  read the numbers above rather than the shape of the code.

## Compatibility and migration

None.  No format, no ABI, no interface: the read path keeps the shape it has,
and no baseline moves.

## How this is proven

- **The command count is pinned by a test.**  The cache's own
  `CountingDevice` (`src/fs/block_cache.rs`) counts device reads, and
  `sequential_read_triggers_read_ahead` now asserts that a sequential miss
  costs **one** read for the demand and its lookahead.  A split fails it, in
  the smallest place the change could be made.
- **The boot counters are the same claim at boot scale.**  `blk-reads` in
  `scripts/perf-baseline.txt` and `scripts/perf-baseline-disk.txt` was
  recorded with the coalesced shape; a split raises it for the same bytes and
  the baselines refuse the change.

## Unresolved questions

- **Is the write path the caller?**  A flush of independent dirty blocks has
  no ordering constraint *between* them, and its data goes *into* the device,
  so a driver can copy the block into its own slot at submit and nothing of
  the caller's has to stay alive — the safe shape this RFC says the read path
  lacks.  That is a decision of its own, and the next one to make.
- **Does anything else read independently?**  A mount reads a superblock, an
  inode table and a dirent table that do not depend on each other; whether
  overlapping those pays is unmeasured, and it is a boot-once cost rather
  than a steady-state one.
