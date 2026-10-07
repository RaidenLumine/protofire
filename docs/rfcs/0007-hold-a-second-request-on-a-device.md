# RFC 0007: Hold a second request on a device

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-07
- **Supersedes:** none

## Summary

This kernel's block interface is synchronous: `BlockDevice::read_blocks`
returns when the data is in the caller's buffer, and every driver in the tree
implements it by writing the request and spinning on the device until it
completes.  That is a fine shape for a caller that has nothing else to do, and
it is the only shape the tree has — nothing anywhere issues a second request
while the first is outstanding, so `blk-in-flight-high-water` is **1** on
every boot every gate records.  This RFC decides the shape a device takes when
that stops being true: a **submit/poll pair** beside the waiting call, defaulted
so a device that cannot hold a second request keeps today's behaviour, and
landed as one change with the first caller that can be ahead of a device and
the gate that measures it.  The interface is not built on its own, because an
interface no caller uses cannot be verified, and this tree does not ship
unverified mechanisms.

## Motivation

[docs/status.md](../status.md) records the gap in the boot-work section, and
the roadmap repeats it: the counters say what a boot asks a device for, and
`blk-in-flight-high-water` in [`src/kernel/block.rs`](../../src/kernel/block.rs)
is the number that would show a device holding more than one request — but it
is 1 in all five recorded baselines (`scripts/perf-baseline*.txt`, tolerance
0), on the in-memory volumes, on the NVMe namespace, on four CPUs and under
the NUMA topology.  Read-ahead already asks for a run in one request rather
than one block at a time, so the filesystem is not the bottleneck; the shape
of the interface is.  A reader that issues a synchronous call cannot be ahead
of the device it is reading from, and a second thread issuing the same call
would only be serialized behind the first: the overlap has to be a queue at
the device.

The question this RFC answers is not "is overlapping I/O good" — it is — but
**what the interface is, and what would show it works**.  The roadmap's
current position is that the interface is deliberately not built because a
high-water mark of one makes it unverifiable.  That position is right about
the verification and wrong about the ceiling: the same number that would show
a queue helps is the number that proves it does nothing.

## Current state

- **The trait.**  `src/kernel/block.rs` declares `BlockDevice` with
  `read_blocks(&self, lba, buffer)` and `write_blocks(&self, lba, data)`, both
  of which complete before they return.  `flush` and `device_health` are
  already defaulted methods, so the trait has precedent for growing a method
  that a device need not implement.
- **The counter.**  `counting_device` wraps every device that enters the
  filesystem's device map in `CountingDevice`, whose `read_blocks` and
  `write_blocks` take an `io_counters::InFlight` guard for the duration of
  the call and `fetch_max` the high-water mark.  Because the call is
  synchronous, the guard is held for exactly one request at a time.
  `src/kernel/perf_baseline.rs` prints the mark as `blk-in-flight-high-water`
  and the recorded baselines compare it with tolerance 0.
- **The drivers.**  `src/drivers/nvme.rs` owns one I/O submission queue and
  one completion queue, and `NvmeIoState` behind a `Mutex` carries the tail,
  the head, the phase bit and the command id.  `io_submit_and_wait` holds
  that mutex from the doorbell write until the completion is reaped, and
  every data transfer goes through one shared bounce buffer
  (`io_buf: Mutex<DmaBuffer>`), so a second request cannot even be *written*
  while the first is outstanding.  The virtio-blk driver has the same shape
  over a virtqueue.
- **The callers.**  `src/fs/block_cache.rs` reads a block at a time and waits
  for each; the filesystem's read-ahead issues a run in one call and waits for
  it; [`src/kernel/workload.rs`](../../src/kernel/workload.rs) writes eight
  files and reads them back synchronously.  No path in the tree asks for two
  requests at once, which is exactly what the high-water mark of 1 says.
- **The network device is the same shape.**
  `NetworkDevice::send`/`receive` in `src/network/link/device.rs` are
  synchronous, and the stack polls; the loopback device's own comment points
  at `blk-in-flight-high-water` as the reason nothing is queued there either.

## Design

**The interface is a submit/poll pair, defaulted to today's behaviour.**
`BlockDevice` gains two methods beside the waiting calls:

- a **depth**, the most requests the device can hold at once, defaulting to
  one;
- a **submit**, which hands the device a request — an LBA, a buffer and a
  length — and returns a ticket, or completes it in place when the device's
  depth is one;
- a **poll**, which asks whether a ticket has completed and, when it has,
  answers with the request's own result.

`read_blocks` and `write_blocks` stay, and become convenience wrappers that
submit and poll until the ticket answers.  A device that implements nothing
new behaves exactly as it does today: the default submit performs the
existing call and returns an already-complete ticket, so the default methods
are a synchronisation point rather than a queue.

**The buffer's lifetime is the caller's contract.**  A queued request holds a
pointer into memory the caller owns, and the interface is `unsafe` for the
same reason `DmaBuffer` and the MSI-X claims are: the caller promises the
buffer stays live and does not move until the ticket is polled to completion.
The alternative — copying into a driver-owned ring — is what the single
bounce buffer does today, and it is what makes the current driver unable to
hold two requests; a queue that keeps that copy would spend the DMA twice.

**The counter moves with the request, not the call.**  `CountingDevice` must
hold the `InFlight` guard from submit until the ticket's completion, which
means the guard lives in the ticket's entry in the wrapper rather than on the
stack of the call.  That is the change that makes
`blk-in-flight-high-water` mean "requests a device is holding" rather than
"calls that have not returned", and it is why the counter is the gate: the
number already exists and already prints.

**The first caller is a read-ahead that is ahead of its own wait.**  The
filesystem's read-ahead already computes the run it wants; with a queued
device it submits the *next* run before polling the current one, so the
device has two requests in flight for the duration of the overlap.  The
caller asks the device for its depth and pipelines only as deep as it answers,
which keeps the one-request in-memory volume on exactly today's path.

**Drivers split submit from complete.**  `NvmeController::io_submit_and_wait`
becomes an `io_submit` that writes the slot, advances the tail, rings the
doorbell and releases the lock — carrying the command id in the ticket — and
an `io_complete` that reaps the completion queue and matches the id.  The
completion queue is a ring: entries arrive in submission order and are
matched by the command id the driver put in the submission entry, so a
completion for a later request does not have to be withheld behind an earlier
one.  The shared bounce buffer is what forces the driver to own one buffer
per outstanding request, which is the depth it advertises.

## Alternatives

- **`async fn` and futures.**  The obvious modern shape, and the wrong one
  here: a future needs an executor and a waker, and the block layer sits
  below the scheduler by construction (`block` names `sync` and nothing
  above it — see `scripts/layering-baseline.txt`).  Putting a runtime under
  the filesystem to avoid writing a ticket would be a larger change than the
  interface it replaces, and it would make the wait path the runtime's
  problem instead of the caller's.
- **A completion callback per request.**  It inverts control: the caller
  hands the driver a function to run, and the driver has to decide when it is
  safe to call it.  The kernel's driver completion paths all run from an
  event drain rather than an interrupt (this is the stack's polling
  decision), so a callback would be called from the same poll the caller is
  already doing, with the callback's reentrancy added on top.
- **A device-owned queue the block layer polls.**  This is the network
  stack's shape, and it is the same interface with a global table in front of
  it.  The device has no maintenance thread of its own, so the poll would
  still be driven by whichever caller is waiting, and the table would only
  add a place for a request to be forgotten.  The ticket is that poll made
  explicit.
- **Make `read_blocks` itself non-blocking.**  Every caller and every device
  changes at once, including the in-memory volumes whose "device" completes
  in place; the waiting form is what the filesystem, the cache and the
  workload actually want, and removing it would make each of them write the
  poll loop.
- **Raise the depth without splitting submit from complete.**  A driver
  cannot hold two requests while its only entry point spins, so this is the
  same change with the counter still at 1 — the interface would be
  unverifiable in exactly the way the roadmap objects to.
- **Do nothing until a caller needs it.**  Today's position, and it is the
  one this RFC replaces only because the RFC names the caller: without a
  caller the interface cannot be tested, and *with* the read-ahead caller it
  can.  If that caller is dropped, this RFC's implementation goes with it.

## Drawbacks

- **The interface is `unsafe` where the old one was not.**  A queued request
  borrows the caller's memory across a window the compiler cannot see.  That
  is a real cost in a tree whose rule is that `unsafe` carries its argument
  at the block; the argument here is that the copy it replaces is the thing
  that caps the queue at one.
- **The counter wrapper grows state.**  `CountingDevice` becomes a wrapper
  that owns a ticket table rather than a pair of guards, and a leaked ticket
  would leave the in-flight count up.  The guard that drops with the ticket
  is what keeps that honest, the same way the stack guard keeps the current
  one honest on an error return.
- **The NVMe driver has to be correct without a lock across the wait.**  Two
  submitters must be able to write different slots and ring the doorbell
  without losing an update, and the completion reaper must match by command
  id rather than by "the next entry".  The current driver is simple *because*
  it holds the lock; that simplicity is what is being spent.
- **A device whose depth is one pays for the shape.**  It keeps the default
  methods, so it pays nothing at run time, but the trait it implements now
  describes a queue it does not have.

## Compatibility and migration

Nothing on disk, on the wire or in the syscall ABI changes: the interface is
between the filesystem and the block layer inside one boot.  The new methods
are defaulted, so every existing device keeps working without being touched,
and `read_blocks`/`write_blocks` keep their signatures, so every caller
compiles unchanged.  The one thing that moves is the recorded baselines: the
NVMe flavour's `blk-in-flight-high-water` goes from 1 to 2 when the caller
lands, and the other four stay at 1 because their volumes have depth one.
Because the counter is deterministic, the tolerance stays 0 — which is what
makes the number a gate rather than a report.

## How this is proven

- **The count is the gate.**  `make check-perf-baseline-disk` boots the
  workload on the NVMe namespace, and the recorded row for
  `blk-in-flight-high-water` moves from 1 to 2 when a caller pipelines;
  the in-memory, SMP, NUMA and loopback baselines stay at 1, so the change
  cannot pass by making *every* device report a queue.
- **The waiting path is unchanged.**  `make test-lib` and
  `make check-x8664-runtime` exercise `read_blocks` through the filesystem,
  the cache and the workload; a device whose depth is one must be on exactly
  the path it is on today, and the in-memory baselines' other rows are what
  say so.
- **The device is real.**  `make check-x8664-nvme` and
  `make check-aarch64-nvme` mount a filesystem from a namespace, so the
  submit/complete split is exercised against a device that queues rather than
  against the in-memory volumes.
- **The claim is named.**  The gate's passing line reports the mark, so a
  reader can re-run the boot and read the same number, which is this tree's
  rule for saying a mechanism ran rather than was merely written.

## Unresolved questions

- **Does the write path need the same shape?**  A commit writes a run and
  waits for it to be durable before the next; overlapping writes is a
  different argument (ordering and durability, not throughput), and this RFC
  deliberately covers reads only.
- **Should the network device get the same ticket?**  The stack is polled,
  so a queued send is the same shape; nothing on the network path is ahead of
  its own wait today, and `nw-polls` would be where a change showed.
- **How deep should the read-ahead pipeline?**  The device advertises a
  depth; how much of it the filesystem should use is a tuning question the
  workload's counters answer, not a property of the interface.
- **Is the ticket table the right place for the counter?**  It is where the
  guard has to live for the number to mean the right thing; whether it should
  enumerate requests for anything else (a timeout, a cancel) is left open.

## What landed

The interface and its first caller are in the tree; the read-ahead caller the
Design section names is not.

- `BlockDevice` carries `queue_depth`, `submit_read` and `poll_read`, all
  defaulted, so a device that does not queue is the device it was: its submit
  completes the read in place and answers `ReadTicket::DONE`, and its poll
  always answers `Done`.  `BlockSliceDevice` passes the three through, because
  a slice of a device that queues is a device that queues.
- `CountingDevice` holds each queued read's in-flight guard in a ticket table
  instead of on the call's stack, which is what makes
  `blk-in-flight-high-water` mean "requests a device is holding" rather than
  "calls that have not returned".
- `src/drivers/nvme.rs` answers a depth of two and splits its submission from
  its completion reaping.  It matches a completion to its request by the
  command identifier — so a queued read and a synchronous one can be
  outstanding together, which "the next completion to arrive" would have got
  wrong — and each slot owns its own bounce buffer, which is what the single
  shared buffer had made impossible.  `read_blocks` is now the waiting form of
  that pair — the same submit, polled at once — so there is one read path in
  the driver and the queued one is exercised by every read the filesystem
  does, not only by the probe.
- **The caller that landed is not the read-ahead this RFC names**, and that is
  deliberate.  The block cache's lookahead rides in the *same request* as the
  block the caller asked for, and `src/fs/block_cache.rs` argues why ("one
  request that serves the caller and warms four blocks is strictly better than
  two").  Overlapping that read means splitting a request the filesystem
  decided to keep whole, which is its own decision and its own change.  What
  landed instead is the boot probe in `src/kernel/workload.rs`: when the data
  zone's device advertises a depth of two, it submits two one-block reads
  before polling either, then waits for both.  It is deliberately the smallest
  caller that makes the mechanism run rather than a workload that benefits
  from it — the benefit is a question for real hardware, which is not what
  this tree's gates boot.
- `make check-perf-baseline-disk` records `blk-in-flight-high-water` at **2**,
  and the in-memory, SMP, NUMA and loopback baselines stay at **1**, which is
  what says the change did not make *every* device report a queue.  The same
  boot prints
  `[perf  ] queued read: depth=2 submitted=2 in-flight-high-water=2` — the
  probe naming its own evidence.  What the boot pays for the mechanism is two
  4 KiB frames of DMA memory, one bounce buffer per slot, and the recorded
  `frames` and `frame-zero-bytes` moved by exactly that.
