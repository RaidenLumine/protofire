# RFC 0006: End a producer ring's lap where its work ends

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-06
- **Supersedes:** 0004

## Summary

[RFC 0004](0004-reuse-the-xhci-rings-by-cycle-state.md) gave this kernel's
xHCI producer rings a cycle state, and pinned their Link TRB to the segment's
last slot.  A lap that wrapped past the slots the last TD did not fill then
left those slots holding the *previous* lap's cycle state — and a consumer
stops at the first TRB whose cycle state it does not own, so it stopped
*before* the link, never learned to wrap, and never saw another TRB.  This
RFC ends each lap where its work ends: the Link TRB goes in the slot the next
TD would have started in, so the consumer can always reach it.  Everything
else RFC 0004 decided — the cycle state, the Toggle Cycle bit, the event
ring's 64 usable entries with no link in them, reading the cycle bit before
the rest of an event, matching a completion by the TRB it names — is kept.

## Motivation

RFC 0004's design says the link "is rewritten … with the cycle state of the
lap that is ending" and that a TD never straddles it, both of which the code
does.  What it did not say is where a lap *is* when a TD does not fit: the
code wrapped at the segment's last slot regardless, so a lap could be
discontinuous with the TRBs it wrote.

The defect is only visible once a ring is used long enough for the gap to
land in front of the link, which is why the gates that exercise rings —
a disk mount over USB, a keyboard's reports — never saw it: their laps are
either one TRB long (bulk and interrupt rings, where a lap fills the slot
before the link by construction) or few enough that no control ring wraps
with a hole.  The hub work that prompted this RFC does twenty-odd control
transfers on one EP0 ring at boot, and the twentieth wraps with two slots
left over.  QEMU's trace of that ring shows the consumer reading the empty
slot, stopping, and never fetching the TRBs the driver had written past the
link: the driver waits for a completion event that can never come, while the
device never sees the request at all.

## Current state

- **The position.**  `src/drivers/xhci.rs` keeps a producer ring's position
  as `RingPos { index, pcs }`; `RING_USABLE_TRBS` is
  `RING_SEGMENT_TRBS - 1`, so slots `0..=62` are data and slot 63 is where
  the link was pinned.
- **The reservation.**  `RingPos::reserve` ended a lap only when
  `index + trbs > RING_USABLE_TRBS`, so a TD that did not fit produced a lap
  ending *at the segment's end* while the last TRB written was earlier than
  that, leaving `index..62` holding the previous lap's TRBs.
- **The link.**  `RingPos::write_link` wrote the link at
  `RING_USABLE_TRBS`, with the cycle state of the lap that was ending; the
  consumer follows a link whose cycle state matches its own and flips when
  the link's toggle bit is set.
- **The event ring.**  It is a different half of the same struct:
  `advance_event_ring` wraps at `RING_SEGMENT_TRBS` and the event ring has no
  link, which RFC 0004 settled and nothing here changes.

## Design

**A lap ends where its work ends.**  `RingPos::reserve` calls `end_lap` when
the next TD would not fit before the segment's end, and `end_lap` writes a
Link TRB *at the current position* — the slot the TD would have started in —
carrying the current lap's cycle state, with Toggle Cycle set, pointing back
at the segment's base; then it flips `pcs` and sets `index = 0`.  There is
no slot between the last TRB written and the link, so there is nothing for
the consumer to stop on: it consumes the lap, follows the link, flips its own
cycle state, and reads the next lap from the base.

**The first lap still ends at the segment's end.**  A ring that has never
wrapped has written its TRBs from slot 0, so the only slot a lap can reach
without being *told* where to end is the last one; `TransferRing::allocate`
still writes that link, now with the first lap's own cycle state so a
consumer that reaches it may follow it.  Once a lap wraps, the link moves to
wherever that lap ended, and the ring's last slot becomes an ordinary one.

**The link is rewritten, not static.**  A link is now a slot a later lap may
use for data: the producer overwrites it when its own lap reaches that
offset.  This is the same rule RFC 0004's "the Link TRB is rewritten, not
static" drawback states, applied to a slot that is not fixed.

## Alternatives

- **Keep the link pinned at the segment's end and pad the gap with No-Op
  TRBs.**  This works — the consumer walks the padding and reaches the link —
  but every pad TRB is a TD the controller completes, so it costs a transfer
  event and an event-ring entry per pad, and it makes the ring's contents a
  function of how the TDs happened to line up.
- **Expand the ring instead, as Linux does.**  Linux keeps a free slot
  between enqueue and dequeue and grows the ring when a TD would fill a
  segment.  That is the right design for a ring whose size is a policy; here
  the segment is one 4 KiB frame the driver allocates once, and expansion
  would mean a segment list, a larger structure, and a set-dequeue command
  this driver has no other reason to need.
- **Keep a free slot like Linux, without expanding.**  This does not remove
  the defect, it moves it: the gap is where the last TD did not fit, and
  reserving one more slot only means the *next* wrap has a different hole.
- **Size the TDs so a lap always fills the segment.**  A control transfer's
  TD size is a property of the request, not of the driver's convenience;
  making the ring's correctness depend on the caller's arithmetic is what the
  ring is for.
- **Reset the ring (and the endpoint) when it would wrap.**  Correct, but it
  throws away the queue and the endpoint's dequeue state for every lap, which
  is the thing the rings exist to avoid.

## Drawbacks

- **The link is no longer at a fixed offset.**  A reader of the ring — a
  debugger, a future path that wants to walk it — can no longer assume slot
  63 is the link; `end_lap`'s comment is where the rule is written down.
- **A lap can be one TRB shorter than the segment.**  The link occupies a
  slot in the lap it ends, exactly as it did when it was pinned, so the
  usable slots per lap are unchanged; the difference is only *which* slot.
- **The wrap is now silent when it is wrong.**  A consumer that stops before
  a link produces no error, only a timeout: the failure mode this RFC fixes
  is not detectable from the driver's side, which is why the gate that covers
  it drives the device from outside.

## Compatibility and migration

Nothing on disk, on the wire or in the ABI changes: this is one driver's
private ring convention, and only x86_64 builds the module.  There is no
half-applied state — the rings are programmed once, before the controller is
started — and a ring written under the old rule differs from a ring written
under the new one only in where the link sits, which the driver rewrites on
the first wrap.

## How this is proven

- `make check-x8664-usb-hotplug` (`scripts/check-x8664-usb-hotplug.sh`) is
  the gate that reaches the case: its hub does more than a lap's worth of
  control transfers before the ring wraps with slots to spare, and the whole
  scenario fails against the pre-fix tree — the same gate, copied onto it,
  reports that the guest never enumerated the device at all.
- `make check-x8664-runtime` and `make check-x8664-usb-disk` stay green:
  they exercise the same rings through the keyboard's interrupt endpoint, the
  mass-storage bulk rings and the command ring, and `check-x8664-usb-disk`
  wraps the bulk and event rings several times.
- The host tests in `src/drivers/xhci_protocol.rs` cover the `Trb` encoding
  the link is built from; the position logic itself is in the module only
  x86_64 compiles, which is why the evidence for it is a boot and not a unit
  test.

## Unresolved questions

- **Should the producer rings be checked for room rather than assumed
  serial?**  Both halves are settled in code now.  The driver *keeps* the rule
  instead of relying on it: the work an event asks for (a hub's status-change
  report, a root port's change) is run from the event-ring drain rather than
  under a transfer's wait, because that work is itself requests, and a second
  TD on a ring whose first is outstanding is how a completion comes back for
  nobody.  And a submit asks its ring's `RingRoom` — the TRBs submitted and
  not yet completed, the only honest measure, since the controller writes its
  dequeue back into an endpoint's context only when the endpoint stops or
  faults — refusing with `Busy` when the ring cannot hold the TD.  Nothing
  here pipelines, so nothing here is refused; a caller that does pipeline has
  the check it needs before it can be correct.
- **Should a hole be detected rather than avoided?**  A consumer that stops
  early is invisible to the driver; a debug build could read the controller's
  dequeue back and say so, which no path needs yet.
