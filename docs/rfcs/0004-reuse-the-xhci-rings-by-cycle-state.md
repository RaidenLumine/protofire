# RFC 0004: Reuse the xHCI rings by cycle state

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-06
- **Supersedes:** none

## Summary

Every ring this kernel gives the xHCI controller — the command ring, a slot's
control, interrupt and bulk transfer rings, and the event ring the controller
writes back — holds one lap of work and then stops.  This RFC gives all of
them the cycle-state discipline the specification describes, so a ring can be
reused: a producer ring carries a Link TRB with its Toggle Cycle bit set and
flips its producer cycle state on the wrap, the event ring is consumed against
the segment size the ERST already states and has no Link TRB at all, and a
transfer completion is matched to the TRB the event names rather than to
"the next event for this slot".

## Motivation

[docs/status.md](../status.md) records the gap in two rows: xHCI's "event
ring's *reuse* is unfinished, and a device kept busy for more than one lap of
it stops completing transfers"; and the USB mass-storage row, "a disk cannot
be *mounted* over USB".  A boot reproduces it: with the demo image the host
`mkimage` writes attached over `usb-storage`, the boot reaches

    [fs    ] failed to mount SimpleFs volumes from ATA boot disk: invalid argument

and falls back to the in-memory volumes, while the *same image* over
`virtio-blk` reaches `mounted MBR-partitioned SimpleFs volumes from ATA boot
disk`.  That is what makes the difference the driver's and not the image's:
the mount is a longer read than the single-sector probe the gate already
does, and it is long enough to wrap the rings.

Two things are wrong, and they are the same thing in two places: the driver
never decided what a ring's cycle bit means across a wrap, so both the rings
it produces and the ring it consumes are single-lap by accident.

**The producer rings.**  `src/drivers/xhci.rs` writes every TRB of the
command, control, interrupt and bulk rings with cycle 1, and their Link TRBs
have no Toggle Cycle bit (the comment at `control_transfer` says so as if it
were a design: "the Link TRB carries no TC bit, so QEMU's cycle state never
toggles and every TRB keeps cycle 1").  Nothing in a written slot changes
when the controller consumes it, so after the producer wraps, a slot the
producer has not rewritten still holds the previous lap's TRB with cycle 1 —
and the consumer, whose cycle state is also still 1, reads it as work.  The
command ring is worse than single-lap: `post_cmd_trb` *does* flip `cmd_pcs`
at the wrap while its Link TRB has no Toggle Cycle bit, so after the first
lap the driver writes TRBs the controller will not see.

**The event ring.**  The driver consumes at most 63 of its 64 entries — it
wraps its dequeue at `RING_SEGMENT_TRBS - 1` and leaves a Link TRB in slot
63 — while the ERST it programmed says the segment is `RING_SEGMENT_TRBS`
entries long, and the controller wraps its producer at the segment size.  The
consumer therefore flips its cycle state one event before the controller
flips the producer's, and the ERDP it writes back names a slot one ahead of
the controller's write position.  The semantics are not in doubt and are not
this driver's to choose: the controller's side is
`er_ep_idx`/`er_pcs` against `er_size` from the ERST, and the event ring has
no Link TRB in it.  A consumer that is one event out of step then reports
"no event" forever: the controller treats the slot it is about to write as
the consumer's, drops the event, and never moves, which is the shape of the
failure recorded in `docs/status.md` (a consumer parked at entry 0 of the
ring, waiting for a lap the controller did not write).

**And the completion.**  Even with the rings in step, a completion is
currently identified by "the next transfer event for this slot"
(`poll_transfer_event` takes `expected_slot` and nothing else).  A transfer
event names the TRB that produced it in its parameter field, and a driver
that ignores that field cannot tell its own completion from a stale one; the
observed "CSW of 13 zero bytes" is such a misidentification.  This is the
same class of defect as the rings: an identity that is available and unused.

## Current state

- **Where the rings are described.**  `src/drivers/xhci_protocol.rs` defines
  `Trb`, `Trb::link(addr, cycle)` (which sets no Toggle Cycle bit),
  `TRB_CYCLE_BIT`, `RING_SEGMENT_TRBS = 64`, and `ErstEntry::new(base, count)`.
- **Where they are made.**  `XhciController::init_rings` programs the command
  ring (CRCR, RCS = 1), the event ring (ERST with one segment of
  `RING_SEGMENT_TRBS` entries, ERDP with DCS = 1), the DCBAAP and CONFIG.
  `alloc_slot_resources`, `configure_hid_endpoint` and
  `configure_bulk_endpoint` each allocate a transfer ring and write its Link
  TRB with cycle 1 and no Toggle Cycle bit; `build_address_device_input` and
  `configure_bulk_endpoint` point the endpoint's dequeue at the ring with
  DCS = 1.
- **Where they are produced.**  `post_cmd_trb`, `control_transfer`,
  `submit_bulk_trb` and `arm_hid_read` write TRBs with `TRB_CYCLE_BIT`
  hard-coded and advance a position that wraps at `RING_SEGMENT_TRBS - 1`.
  Only `post_cmd_trb` keeps a cycle state, and it flips it.
- **Where they are consumed.**  `await_cmd_completion`, `poll_transfer_event`
  and `poll_events` read at `evt_dequeue`, compare `cycle_bit()` against
  `evt_ccs`, advance and wrap at `RING_SEGMENT_TRBS - 1`, and write ERDP with
  bit 3 set only when `evt_ccs` is true.
- **What is already right.**  `DmaBuffer::allocate` zeroes its frames, so an
  unwritten slot reads as cycle 0 — which is what a first-lap consumer needs
  to stop at.  The submission paths are serial: each posts its TD and waits
  for its own completion before returning, so at most one TD per ring is in
  flight.

## Design

**A producer ring keeps a cycle state and flips it at the Link TRB.**  A
ring is `RING_SEGMENT_TRBS` entries; slots `0..=n-2` carry TRBs, slot `n-1`
is a Link TRB whose parameter points back at the segment's base and whose
Toggle Cycle bit is set.  Software keeps `(index, pcs)`.  Before writing a
TD it makes room for the whole TD; if the TD would cross the Link TRB it
rewrites the Link TRB with the cycle state of the lap that is ending and
flips `pcs`.  This is the discipline in the specification's "Cycle State"
section, and it is what makes a slot readable as "this lap" versus "the
lap before": a slot the producer has not rewritten this lap holds the
previous lap's cycle and stops the consumer, while with a fixed cycle bit
every previously written slot looks like work.

**A TD never straddles the Link TRB.**  With a toggling cycle state the TRBs
before and after the link carry different cycle bits, so a chain that
crossed it would be cut in half; the reservation above therefore wraps
*before* the first TRB of a TD that would not fit.  The largest TD here is
the three TRBs of a control transfer, against 63 usable slots.

**The event ring is 64 usable entries and has no Link TRB.**  The ERST
already says the segment is `RING_SEGMENT_TRBS` entries; that is also where
the controller wraps and flips its producer cycle state, so the consumer
wraps at the same count and flips its own state to match.  The Link TRB the
driver used to write into the event ring is deleted: the entry it sat in is a
segment slot, and a controller that writes an event there would otherwise
overwrite it.  After each consumed event the driver writes ERDP to the new
dequeue with EHB set (bit 3 is write-1-to-clear), which both acknowledges and
tells the controller where the consumer is — and the controller's
event-ring-full decision is made against exactly that value, so a dequeue one
entry out of step is what turns into a dropped-event deadlock.

**The consumer reads the cycle bit before the rest of the entry.**  A TRB is
published in address order — parameter, then status, then the control word the
cycle bit lives in — so a control word that already reads as the expected
cycle is a promise that the other two words are in place, and the rest is read
only after that promise.  Reading the whole `Trb` in one go does not give that
promise: it is not one access (the compiler emits two), and the controller can
publish an event between them, which is exactly what happened — a completion
whose parameter read as zero with a cycle bit that matched, so the transfer
that had completed came back as a timeout.  The control word is re-read after
the other two, and a slot rewritten underneath the read is refused rather than
half-accepted.

**A completion is matched by the TRB the event names.**  `poll_transfer_event`
takes the endpoint's DCI and the physical address of the TRB carrying
Interrupt On Completion, and accepts an event only when it names that
endpoint and that address; the parameter field is the TRB address the
controller reports for a Transfer Event.  A transfer event for another slot
is still delivered to its HID consumer, and an event for the awaited slot and
endpoint that names a different TRB is a desynchronisation the caller should
see as a failure rather than as its own completion.

**Reuse is safe because a ring holds one TD in flight.**  Every submit path
here waits for its completion before the next, so the producer can never lap
its consumer, and the largest TD (three TRBs) is far inside a 63-slot lap.
This is a property of the callers, not of the rings, and the RFC states it
as one: a future path that pipelines submissions has to add a room check
before it can be correct.

## Alternatives

- **Leave the rings single-lap and make the boot avoid a wrap** — larger
  caches, smaller transfers, or a mount that reads fewer blocks.  Rejected:
  it does not remove the defect, it hides it below the size of the demo, and
  a user with a real disk reaches it on the first directory listing.
- **Keep the fixed cycle bit and re-zero a slot as it is consumed.**  A
  consumer cannot zero its own ring in this design (the controller has no
  store into it) and a producer cannot tell a consumed slot from an
  unconsumed one, so there is nothing to key the rewrite on.
- **Keep the fixed cycle bit and insert a No-Op/Zero-Length pad at the Link
  TRB.**  A fixed cycle state still cannot distinguish "written this lap"
  from "written last lap" once the ring has wrapped once, so the pad does not
  fix the reuse that motivates the change.
- **One Link TRB per lap with only one lap ever used (size the ring to the
  work).**  Rejected for the same reason as the first option, and because the
  work is a function of the filesystem the user mounts.
- **Consume the event ring by 63 entries and program the ERST with 63.**  The
  driver's off-by-one would then match.  Rejected: it encodes a private
  convention into a structure whose length the controller reads, and the Link
  TRB would still be a slot the controller writes events into.
- **Match completions by slot only.**  Rejected: the defect it produces is
  silent and misattributes a completion to a transfer that did not complete,
  which is exactly the failure the mass-storage row records.

## Drawbacks

- **Every submit path grows a cycle state and a reservation.**  The position
  is now `(index, cycle state)` rather than a counter modulo the ring size,
  and the three-TRB control transfer has to reserve before it writes.
- **The Link TRB is rewritten, not static.**  A reader of the ring can no
  longer assume slot `n-1` never changes; the rewrite is what carries the
  cycle state into the next lap, and it happens on the producer's thread.
- **The event ring's consumer must be exact.**  There is no slack in the
  count: 64 is both the segment size and the wrap, and being one out is a
  dropped-event deadlock rather than a slowdown (which is the failure this
  RFC fixes, so the property is a cost the design accepts knowingly).
- **Matching by TRB address can time out where matching by slot "succeeded"
  wrongly.**  That is the intended direction, but it means a future desync
  surfaces as a timeout instead of a plausible-looking completion.

## Compatibility and migration

Nothing on disk, on the wire or in the ABI changes; this is one driver's
private ring convention, and only x86_64 builds the module.  The image the
host `mkimage` writes is not re-read differently: what changes is whether the
controller can complete the reads.  The `docs/status.md` rows for xHCI and
USB MSD are updated here, and the caveat that a disk cannot be mounted is
removed rather than reworded.  There is no half-applied state to lose
interrupts in: the rings are programmed once, before the controller is
started, and a machine that never reaches the driver keeps its existing
behaviour.

## How this is proven

- `make check-x8664-usb-disk` (`scripts/check-x8664-usb-disk.sh`) is the one
  that exercises the reuse: it builds the kernel, has the host write a real
  SimpleFs image with `cargo run -- mkimage`, hashes it, boots with that image
  as the only disk behind `usb-storage`, and asserts (a) the mass-storage
  device answers INQUIRY and is chosen as the boot disk, (b) the boot reaches
  `mounted MBR-partitioned SimpleFs volumes from ATA boot disk` and not
  `failed to mount SimpleFs volumes from ATA boot disk`, (c) a program is
  loaded from `/apps` on that volume, (d) the shell *writes* a marker into the
  volume through `open`/`write` and `cat` reads it back, and (e) the host finds
  those bytes in the image afterwards — a write the gate drove, through the
  filesystem API, rather than one the boot makes on its own.  The single-sector
  read in `make check-x8664-runtime` stays as the short-transfer control, and
  `scripts/verify.sh` runs the new gate beside it.
- The reproduction rate, measured the way the working rules ask: with the old
  driver the disk-only boot failed to mount every time it was run, and the
  same image over `virtio-blk` reached the mount line.  With the cycle change
  alone it still failed (6 of 6 runs), which is how the torn read above was
  found; with both, 10 of 10 consecutive boots mounted the volume and 10 of 10
  left the image changed on the host.
- `make check-x8664-runtime` remains green: the keyboard's interrupt path,
  the single-block read and the whole boot are unchanged in their assertions,
  and they run over the same rings this RFC rewrites.
- The control for "is it the driver" is the boot of the *same* image over
  `virtio-blk`, which reaches the mount line; the new gate's failure before
  this change is the assertion the change has to move.
- `make clippy`, `make clippy-targets`, `make check-unsafe-comments` and the
  host tests in `src/drivers/xhci_protocol.rs` cover the new TRB helper and
  the Link TRB's encoding.

## Unresolved questions

- **Should the event ring be larger than one segment?**  One 64-entry segment
  is what the ERST programs today and what this RFC keeps; the consumer can
  walk multiple segments later without changing the cycle rule, only the
  wrap position.
- **Should the producer rings be checked for room rather than assumed
  serial?**  The serialisation invariant is stated, not enforced.  A check
  needs the controller's dequeue (read back from the endpoint context), which
  no path here needs yet.
