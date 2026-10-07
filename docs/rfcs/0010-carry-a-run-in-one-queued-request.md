# RFC 0010: Carry a run in one queued request

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-07
- **Supersedes:** none

## Summary

[RFC 0007](0007-hold-a-second-request-on-a-device.md)'s queued read carries
**one block**: `submit_read(lba, buffer)` refuses anything longer, so a caller
with a multi-block request has nowhere to put it.  That is why the mount can
only overlap its two superblock mirrors and not the inode and dirent tables it
reads next ([RFC 0008](0008-keep-a-sequential-miss-in-one-request.md) recorded
that), and it is also why the block cache's lookahead — one request for the
demand and four blocks after it, argued for in `src/fs/block_cache.rs` as
"strictly better than two" — reaches the NVMe driver as **five** commands,
because the driver serves `read_blocks` one block at a time.  This decides
that a queued request carries a **run**: the trait's contract becomes "a whole
number of blocks", the driver issues one command for a run it can hold, and it
**refuses** a run larger than that rather than splitting it silently.

## Motivation

Two callers already ask for runs, and neither is served:

- **The mount.**  Its table reads are measured on the demo disk at 1–10 blocks
  (448–4864 bytes: an inode table of 14–77 inodes at 32 bytes, a dirent table
  of 13–76 entries at 64).  The superblock pair overlaps today because each
  mirror is one block; the tables cannot, for no reason except the interface's
  width.
- **The cache.**  A sequential miss reads the caller's block and its lookahead
  in one request *on purpose*, and the driver turns that one request into one
  command per block.  The cache's argument is about a device that charges per
  request; the driver was quietly charging per block.

The measurement that makes this concrete is the command count, and it is not
visible to any counter the tree prints today — which is itself part of the
decision below.

## Current state

- **The trait.**  `src/kernel/block.rs` documents `submit_read` as "a
  one-block read", and `submit_write` likewise; both default to the waiting
  call, so a device that does not queue already accepts any size.
- **The driver.**  `NvmeController::submit_read` and `submit_write`
  (`src/drivers/nvme.rs`) return `InvalidArgument` unless
  `buffer.len() == block_size()`, and each slot owns one 4 KiB bounce buffer
  (`IoSlot::bounce`).  `read_blocks` and `write_blocks` loop one block at a
  time through that pair.
- **The mapping.**  `DmaBuffer` (`src/memory/dma.rs`) is allocated as
  *physically contiguous* frames and is page-aligned, so a buffer's pages are
  `phys_addr() + i * 4096` and PRP entries for them need no list.
- **The callers.**  The mount (`src/fs/simplefs/format_io.rs`) reads its
  tables with one `read_blocks` each; the cache
  (`src/fs/block_cache.rs`) reads at most `1 + PREFETCH_RUN_BLOCKS` = 5 blocks
  in one call.

## Design

**The contract: a request names a whole number of blocks.**  `submit_read`
and `submit_write` take `buffer.len()` that is a multiple of
`block_size()`, and both submit and poll name one request however many blocks
it covers.  A queued driver **may refuse** a request it cannot hold, with
`InvalidArgument`, and a caller must be prepared for that — the contract says
so, because a driver that silently split a refused run would hide the fact
that the caller's request was too big for it.  The waiting calls
(`read_blocks`, `write_blocks`) accept any size and split it into runs the
driver can take.

**The driver: one command per run, out of two pages it owns.**  Each NVMe slot
gets a run buffer of **two frames** (8192 bytes, 16 blocks) instead of one,
and the command is built from the buffer's pages:

- `NLB` = blocks − 1 (NVMe counts zero-based);
- `PRP1` = the run buffer's address;
- `PRP2` = the run buffer's second page, and only when the run is longer than
  one page — the frames are physically contiguous, so the second page is
  `phys_addr() + 4096` and no PRP list is needed for any run this buffer can
  hold.

A run longer than 16 blocks is refused; the waiting calls chunk their request,
so a 100-block read is seven commands instead of one hundred.

**The mount takes it up.**  `load_runtime_state_from_superblock` submits the
inode table and the dirent table before polling either — the overlap RFC 0008
left open — and falls back to the waiting calls, chunked by the caller, when a
device refuses the run.

**The command reduction is gated, not asserted.**  The tree's rule is that a
claim no gate exercises is implemented rather than verified, and the existing
counters measure the *layer above* the driver: `blk-reads` counts the calls
the filesystem made, not the commands the device got, so it cannot see this
change at all.  `DeviceIo` therefore gains **`commands`**: the requests a
driver put on its own device queue, counted by the driver where it submits
them, and printed as `blk-commands` beside the rows that count the layers
above.  A regression that went back to one command per block fails that row.

## Alternatives

- **One ticket over N one-block commands.**  The driver queues the run's
  blocks itself and completes the ticket when the last lands.  It needs a
  completion count per ticket and still pays N commands, so it is more state
  for the same work.
- **DMA straight into the caller's buffer.**  No bounce, no copy, no size
  limit — and it needs a physical address for a buffer the caller owns.
  `phys_addr_of` answers for the machine's identity-mapped window only
  (`src/arch/mmu.rs`), and a caller's buffer may be on the kernel heap, which
  is a static whose placement the linker decides.  Passing an address the
  machine cannot translate is silent corruption rather than a failed read, so
  this is rejected for a saving of one copy.
- **A PRP list, so a run is unbounded.**  It is what a bigger run buffer would
  need, and it buys nothing yet: every run this tree reads is under 16 blocks
  (measured above), the waiting calls chunk anything larger, and a list adds a
  second DMA buffer per slot and a second way to describe a transfer.
- **Caller-driven per-block pipelining.**  No interface change at all: the
  mount could submit one block at a time and poll in a loop.  It changes what
  `blk-reads` counts — one request becomes N — which is a change to the
  measurement rather than to the machine, and it pays N commands where the
  device could take one.

## Drawbacks

- **Two frames per slot instead of one.**  The disk baseline's `frames` and
  `frame-zero-bytes` move by the eight kilobytes that costs, and the row is
  recorded rather than hidden.
- **A refusal path every caller must handle.**  A run over 16 blocks is the
  caller's to chunk or to fall back on; the mount does the latter, and the
  contract states it so the next caller does not assume otherwise.
- **`blk-commands` is a driver-level number on a machine-level line.**  It is
  zero on a machine whose driver does not count (the in-memory volumes), which
  is honest and slightly odd: the row means "commands a driver queued", and a
  device with no driver behind it has none.

## Compatibility and migration

No format, no ABI, no syscall changes.  The trait's contract widens, so every
existing caller keeps working; a driver that queues must decide what run size
it can hold, and the one in the tree answers 16 blocks.  The five recorded
baselines are re-recorded for the new rows and the frames.

## How this is proven

- **The NVMe gates mount real filesystems through the run path.**
  `make check-x8664-nvme`, `check-aarch64-nvme` and `check-riscv64-nvme` read
  every table the mount needs — a wrong `NLB` or a wrong second PRP page
  hands the mount different bytes than it asked for, so the volume does not
  mount rather than mounting wrongly.
- **The PRP choice is a unit test.**  The encoding is a function of the run
  length, and the test pins the three cases: one page (no PRP2), exactly two
  pages, and a refusal past the buffer.
- **`blk-commands` is the gate for the claim.**  The disk baseline records how
  many commands the run support needed; a change that went back to one command
  per block raises it and fails.
- **The mount overlaps.**  `blk-read-high-water` is 2 with the mirror pair and
  stays 2 with the tables added, and the four depth-one baselines are
  unchanged because their device completes each submit in place.

## Unresolved questions

- **How big should the run buffer be?**  16 blocks covers every run this tree
  reads and costs two frames per slot; the number is a memory-per-command
  trade rather than a property of the interface, and `blk-commands` is where a
  different answer would show.
- **Should `blk-commands` move to the block layer?**  Then every driver would
  report the same way and the row would mean the same thing on every machine.
  It is the driver that knows how many commands it queued, so it is the driver
  that counts them today.

## What landed

- `BlockDevice::submit_read` and `submit_write` document and accept a run —
  `buffer.len()` blocks — and say that a driver may refuse one it cannot hold.
  `read_blocks` and `write_blocks` split any longer request into runs, so no
  caller has to know the driver's width.
- `src/drivers/nvme.rs` holds two frames per slot (8192 bytes, 16 blocks) and
  builds one command per run: `NLB` from the block count, `PRP1` the buffer's
  base and `PRP2` its second page when the run is more than one page.
  `nvme_protocol::run_prp` is the choice, and its three cases are unit tests —
  one page, exactly two, and a run the buffer can hold exactly.
- The command count is gated: `DeviceIo::commands` and
  `count_device_command()` put the driver's own queue submissions on the
  boot-work line as `blk-commands`, and the driver calls it in `io_submit`.
  The disk baseline records **497** for 503 caller requests, which is what
  using runs looks like — the average request here is more than one block, so
  one command per block would roughly double the row.
- `load_runtime_state_from_superblock` submits the inode table and the dirent
  table before polling either, and falls back to the waiting calls (draining
  whatever was accepted first) when a device refuses one of the runs.
- **What it cost**: one more frame per slot, which is the disk baseline's
  `frame-zero-bytes` +8192 and nothing else.  `frames` counts allocations, and
  the allocations did not change.
