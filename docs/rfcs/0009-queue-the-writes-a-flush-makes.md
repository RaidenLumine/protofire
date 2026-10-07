# RFC 0009: Queue the writes a flush makes

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-07
- **Supersedes:** none

## Summary

[RFC 0007](0007-hold-a-second-request-on-a-device.md) decided the queued
device interface and covered **reads** only; this decides the write half, and
with it the interface's first production caller.  Two things are different
from the read half.  A write's data goes *into* the device, so the driver
copies it out of the caller before the submit returns and **no caller buffer
has to outlive the ticket** — the `unsafe` borrow `submit_read` needs is not
needed here at all, which is exactly why
[RFC 0008](0008-keep-a-sequential-miss-in-one-request.md) left this as the
next decision.  And the write path already has a place where the requests are
independent: a flush of dirty blocks.  The cache's three flush calls become
one mechanism — take the dirty set under the lock, submit up to what the
device can hold, **release the lock**, poll to completion, and clear a
block's dirty flag only if the block was not rewritten while its write was in
flight.

## Motivation

The roadmap and `docs/status.md` both record the same gap: the queued
interface is verified as a mechanism and has no production caller, and the
read path cannot be one (RFC 0008).  The write path can, and it is worth more
than a caller:

- **The blocks a flush writes are independent.**  Distinct LBAs, no order
  between them, and all of them must be durable before the flush returns.
  That is the shape a queue is for, and it is the one shape the read path
  never has.
- **The flush holds the cache's lock across every device write.**
  `BlockCache::flush`, `flush_aged` and `flush_range`
  (`src/fs/block_cache.rs`) all loop over the entries under `entries` and call
  the synchronous `write_blocks` once per dirty block.  A flush is therefore N
  serialized round trips **and** a reader-visible lock hold for the whole of
  them, on a device that could be taking all N at once.
- **The write already copies.**  The synchronous NVMe path copies the
  caller's block into its own bounce buffer before submitting
  (`src/drivers/nvme.rs`), so the "the device owns the bytes" property the
  write half needs is not new work — it is the shape the write path has had
  all along.

## Current state

- **The trait.**  `src/kernel/block.rs` has `queue_depth`, `submit_read` and
  `poll_read` (RFC 0007), with `read_blocks` and `write_blocks` as the
  waiting calls.  `CountingDevice` counts `write_ops`/`write_bytes` per
  *call* and keeps one in-flight guard per call.
- **The counter.**  `DeviceIo::in_flight_high_water` counts reads and writes
  together, and it is **2** on the disk baseline today — moved by the
  workload's read probe (`src/kernel/workload.rs`), not by any write.
- **The cache.**  `CacheEntry { lba, data, generation, dirty, dirty_since }`
  (`src/fs/block_cache.rs`).  `write_through` persists a metadata block at
  once; `write_back` marks data dirty and defers.  The three flush calls write
  every selected dirty block under the lock and clear its flag after the
  device says yes.  `generation` is already bumped whenever an entry's
  contents change (`insert`, `bump_generation_and_update`).
- **The flush callers.**  `SimpleFsVolume::sync` (`src/fs/simplefs/vfs.rs`)
  calls `cache.flush()` and then the device's `flush`; `SimpleFs`'s `Drop`
  calls it again.  The maintenance thread runs the aged path —
  `src/kernel/maintenance.rs` calls `fs::sync_global_caches_aged` every
  `WRITE_BACK_AGE_TICKS` — but the VFS default answers `0` and **only fat32
  implements `flush_aged`** (`src/fs/fat32/fs.rs`), so the main filesystem's
  dirty data reaches the device only through an explicit sync, pressure, or
  eviction.
- **The driver.**  `NvmeController::write_blocks` takes the shared `io_buf`
  and calls `io_submit_and_wait`, which holds the I/O state across the wait.
  One write at a time, and one buffer for all of them.

## Design

**The interface: a write submit that is safe, and a poll that is shared.**
`BlockDevice` gains

- `submit_write(&self, lba: u64, data: &[u8]) -> Result<Ticket>`, **not**
  `unsafe`: the device copies `data` before the call returns, so nothing of
  the caller's has to stay alive, and a caller that drops its buffer the
  instant the submit returns is correct.
- `poll(ticket) -> RequestState`, one poll for both directions, because the
  ticket already names the request and its direction.

`ReadTicket`/`ReadState`/`poll_read` are renamed to `Ticket`/`RequestState`/
`poll` rather than duplicated.  Both submits default to doing the work in
place and answering a done ticket, so a device that does not queue is
unchanged, and a device that refuses (`Busy` when its slots are full) is
refused rather than blocked.

**The mechanism: one helper for all three flush calls.**  A fresh
generation is the marker of "this content is being written":

1. Take `entries`.  While fewer than `device.queue_depth()` writes are
   outstanding and a selected dirty entry remains, assign it a fresh
   generation, submit it (`submit_write`, which copies), and remember
   `(ticket, lba, generation)`.
2. **Drop the lock** and poll one outstanding ticket to completion.
3. Take `entries` again and clear the dirty flag **only** if the entry's
   generation is still the one that was submitted.  A block rewritten while
   its write was in flight keeps its flag and is written again by the next
   flush — which is what "the cache copy is newer than the device" means.
4. Repeat until no selected dirty entry remains.

`flush`, `flush_aged` and `flush_range` become one predicate each over the
same helper, so the three cannot drift.

**The first caller is the aged write-back, and wiring it is part of this.**
The maintenance thread already runs it every `WRITE_BACK_AGE_TICKS`
(`src/kernel/maintenance.rs`), it is the flush with the least ordering to
respect and the most blocks at once, and it is the one whose whole purpose is
to write data nobody is waiting on.  `SimpleFsVolume` gains the
`flush_aged` implementation the VFS default has been answering `0` for, so
the main filesystem stops being the one that never write-backs in the
background.  That is a **durability behaviour change** and it is part of the
decision, not a side effect: dirty data now reaches the device without an
explicit sync.

**The counter: split it by direction.**  `blk-in-flight-high-water` becomes
`blk-read-high-water` and `blk-write-high-water`.  One number that two
different changes can move attributes neither, and the question anyone asks
of it is which direction is queued.  The five recorded baselines are
re-recorded in the change that moves them.

## Alternatives

- **Batch a flush into one multi-block request.**  The dirty blocks are not
  contiguous — a cache's dirty set is wherever the caller wrote — so this is a
  scatter/gather request: a PRP list, which the driver does not have, and a
  bigger change than the queue for no more benefit than the queue gives.
- **Keep the lock and submit-then-poll inside it.**  That is today's code with
  the tickets added: the submits serialize on the lock, so nothing overlaps
  and the reader-visible hold stays.
- **Return before the data is durable.**  A flush is a durability call; it
  answers when the device has the bytes.  Making it asynchronous to its caller
  is a different interface with a different name.
- **Order the writes by LBA.**  There is no order to keep — the LBAs are
  distinct and each device's own per-LBA ordering is what applies — and
  sorting would only decide which of two independent requests goes first.
- **Leave the interface to the read probe.**  Then it keeps no caller that
  does work anybody wanted, and a flush keeps blocking every reader of the
  volume for as long as the device takes.

## Drawbacks

- **A dirty flag can now be cleared late.**  A block rewritten between submit
  and completion stays dirty and is written again by the next flush.  That is
  the correct answer — the newer content is in the cache and the device holds
  the older one — but it is a case the single-lock flush could not reach, and
  the generation rule is the thing that has to be right.
- **The lock is released while writes are in flight.**  A reader can now see a
  block whose write has not completed; the cache's copy is the authoritative
  one, so the read is correct, but it is a behaviour change to state rather
  than to discover.
- **SimpleFS write-backs in the background.**  Background write-back is what a
  write-back cache is for, and it is a change in when data reaches the device,
  which `docs/status.md` has to say in its own words.
- **The counter split moves five baselines**, and each is re-recorded by the
  change that moves it.

## Compatibility and migration

Nothing on disk, on the wire or in the syscall ABI changes.  The trait's new
method is defaulted, so every existing device is unchanged; the rename is
mechanical and lands with the code that uses it; and `write_blocks` keeps its
signature, so every caller compiles.  The one behaviour that moves is when
SimpleFS's dirty data reaches the device, and it moves in the change that
wires it.

## How this is proven

- **A boot runs the queued write path, and a test shows it holding two.**  A
  waiting write is now a queued write polled at once, so every `write_blocks`
  in every boot executes the mechanism, and `blk-read-high-water` and
  `blk-write-high-water` are recorded on all five baselines.  What a boot
  cannot show *before its sample* is the **overlap**, and this was measured
  rather than assumed: the boot-work line is printed at
  `PERF_BASELINE_TICK` (500), the only flush a boot performs unaided is the
  aged write-back, and a block is only eligible once it is
  `WRITE_BACK_AGE_TICKS` (600) old — so the disk baseline records
  `blk-write-high-water=1` at tick 522 with 338 writes already behind it, and
  the background write-back is invisible to that line on every flavour.  The
  overlap is therefore gated where it can be reached: the cache's own test
  (`src/fs/block_cache.rs`) flushes four dirty blocks to a depth-two device
  and requires two writes to be outstanding at once, and requires a depth-one
  device to hold exactly one.
- **The dirty-flag rule is gated where it lives.**  A test rewrites a block
  between the submit and the completion and requires the flag to still be set
  afterwards, which is the only way to see the generation rule work.
- **The existing flush tests stay green**, which is what says the three calls
  still write what they wrote before.

## Unresolved questions

- **Does the pressure path share it?**  `flush_if_under_pressure` calls
  `flush`, so it inherits the mechanism; whether the *threshold* is still the
  right one once a flush is cheap is a tuning question with no counter yet.
- **Does the commit path ever want it?**  A commit's metadata writes are
  ordered by the commit protocol and are one block each, so they stay
  synchronous.  If a filesystem ever writes two *independent* metadata blocks
  per commit, this is where the argument for overlapping them goes.
- **Is the aged interval still right?**  `WRITE_BACK_AGE_TICKS` was chosen when
  the flush was synchronous and serialized; a cheaper flush may want a
  different one, and the disk baseline is where that would show.  This RFC
  does not move it.

## What landed

The mechanism, the caller and the counter split are in the tree.

- `BlockDevice` carries `submit_write` beside `submit_read`, with one `poll`
  for both, and the ticket types are named for the request rather than for the
  read (`Ticket`, `RequestState`).  Both submits default to completing in
  place, so a device that does not queue is the device it was; `submit_write`
  is **safe**, which is the half of the interface a caller can hand a borrowed
  block to.
- `src/drivers/nvme.rs` has one slot table for both directions.  A write fills
  its slot at submit and nothing is copied back at completion; a read fills
  its slot's *destination* instead.  `write_blocks` is that pair polled at
  once, so the driver has one write path as it has one read path, and the
  shared bounce buffer the synchronous write path used is gone — the disk
  baseline lost the frame it occupied.
- `BlockCache::flush_selected` is the one place deferred data is written back,
  and `flush`, `flush_aged` and `flush_range` are one predicate each over it.
  The dirty set is submitted under the lock and the lock is dropped while the
  writes are in flight; a block's flag is cleared only if the entry still
  carries the generation that was submitted.
- **A rule the Design implied but did not state**: a block is written at most
  **once per flush**.  Without it the flush would pick up a block rewritten
  mid-flight and chase a busy writer without end.  It was found while writing
  the test for the rewrite case, which is what that test is for.
- `SimpleFsVolume::flush_aged` exists, so the maintenance thread's aged
  write-back covers the main filesystem and not only fat32.  That is the
  durability change this RFC decided on, and it lands here.
- The counter split is in `DeviceIo` and the boot-work line: `blk-read-high-water`
  and `blk-write-high-water` replace `blk-in-flight-high-water`, and all five
  recorded baselines were re-recorded — 52 rows each.
- **What the sample cannot see.**  Every baseline records
  `blk-write-high-water=1`, and that is not a defect in the change: the
  boot-work line is taken at tick 500 and the background write-back cannot
  fire before a block is 600 ticks old, so the durability path's device work
  is invisible to the line on every flavour.  Reading the overlap therefore
  needs the test above rather than the gate, and anything that wants the
  write-back *counted* has to move the sample or the threshold deliberately.
