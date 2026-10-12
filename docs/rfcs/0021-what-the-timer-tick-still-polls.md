# RFC 0021: What the timer tick still polls

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-13
- **Supersedes:** none

## Summary

Two device polls are left in the timer tick — xHCI's event-ring drain and
`virtio-input`'s event-queue poll — and [RFC
0020](0020-what-the-memory-map-may-refuse-on.md)'s open question named them
without deciding them.  This decides: **both stay**, for reasons that are
different, and the tree says what each one is for.  xHCI's tick drain is the
*fallback the ring's own lock requires* — the interrupt acknowledges and
cannot wait, so the tick is what drains the ring a busy transfer left — and
`virtio-input`'s poll is the *MMIO transport's shape*: it has no identity to
claim, and every gate's boot attaches no such device.  Neither is a stop-gap
waiting to be removed; each is named with what would have to change for that
to be true.

## Motivation

The round that gave the console UART a real interrupt path on every machine
(RFC 0020's landed work, and the APLIC driver that finished it) exists because
input riding the timer tick is input a tick stall takes with it.  That
argument does not land everywhere it sounds like it should, and RFC 0020's
question — "the device polling that lives in the timer tick" — is where the
difference has to be written down rather than left implied.  Two polls
remain:

- `src/kernel/process/scheduler/timer.rs` calls `xhci_poll()` and
  `virtio_input::poll_hardware()` on every tick.
- `docs/status.md`'s xHCI row and `docs/kernel/drivers.md` call the xHCI one
  "the fallback"; nothing says what it is a fallback *for*, so a reader
  cannot tell a load-bearing edge from a leftover.
- `docs/status.md`'s VirtIO (block) row already carries the sentence the
  input poll needs — the virtio-mmio transport has no vectors of its own —
  and the Makefile says the input drivers "stay cold" because no run target
  attaches a device.

## Current state

**xHCI.** The controller claims an MSI-X vector; its handler
(`src/drivers/xhci.rs`, `xhci_msi_handler`) does two things in a deliberate
order: it **acknowledges** the interrupter — the controller raises one
message per 0→1 transition of the interrupter's pending bit, so a message
left pending silences every one after it — and then **drains** the event ring
with `try_lock`, because an interrupt must not wait on the rings' owner: a
transfer in flight holds the controller's lock, and that transfer is often
exactly what the interrupt is completing.  When `try_lock` fails the ring is
left undrained, with its message already acknowledged, and no later message
is raised for it.  The full drain (`poll_events`) ends by running
`service_pending`, which is where a hub's status report and a root port's
change are answered — those answers are themselves transfers, so they can
only run where no transfer is outstanding.

The tick's `xhci_poll` takes the blocking lock and drains; the claim is made
at probe time and the device's table is programmed later
(`arch::platform::program_device_msix`), so at boot and on a machine whose
claim was never armed the handler never runs at all.  The lock is a `Mutex`
(a spin mutex that does not park waiters), so a tick that meets a transfer in
flight spins briefly rather than sleeping.

**virtio-input.** `src/drivers/virtio_input/mmio.rs` drives the device over
the virtio-mmio transport, whose module comment says the timer-tick poll is
what drains completed key events.  The transport (`src/drivers/virtio.rs`)
reads no interrupt-status register and claims no line, because the MMIO
transport carries no MSI-X table: there is no *identity* a claim could own —
the same fact `docs/status.md` records for the block driver ("the virtio-mmio
transport has no vectors of its own, so only the PCIe path claims an identity
per queue").  Every gate boots without an input device attached (the
Makefile's run targets say so), so on every measured machine the poll finds
an empty queue.

**What the two share.** No gate forces either poll's interesting case: for
xHCI, no test makes a report arrive while a transfer holds the rings; for
virtio-input, no test attaches the device at all.

## Design

**1. xHCI keeps its tick drain, and the reason is the lock, not caution.**
The handler's `try_lock` is not a shortcut — it is the only shape an
interrupt can have over a lock a transfer holds, and its price is that the
events it did not take are not re-offered (the message was acknowledged, and
the controller raises a message per *transition*).  Something must drain that
ring later, and the tick is that something.  Concretely the tick drain is
load-bearing in three cases:

- **a report under a transfer's wait**: a hub's status report or a root
  port's change that arrives while a transfer holds the rings is dispatched
  by the transfer's own event loop into `pending`, but `service_pending` runs
  only from a drain — and the drain the interrupt attempted did not happen.
  The next tick answers it.  This is the hotplug path
  (`make check-x8664-usb-hotplug`) surviving a busy machine.
- **a machine whose claim was never armed**: no table, no vector, no handler;
  the tick is the only drainer, and the NIC-sized case of "a device that has
  to signal and cannot" is exactly what the MSI-X work removes one device at
  a time.
- **the boot window**: the controller is started at probe time and its table
  is programmed later, so events can be posted while no message exists to
  raise — and arming the table does not re-offer a message for a pending bit
  that is already set.  The tick drains the ring; nothing else would.

So the documents stop calling it a fallback and name what it catches, and
RFC 0020's question — which called it one of "the two USB/input polls" — is
answered by this document rather than left open.

**2. virtio-input's MMIO poll stays, and is named as the transport's shape.**
A completion with no identity has nothing the handler registry could own, so
"give it an interrupt" is not a wiring change but a design one: either the
MMIO transport learns its device-tree line (`InterruptStatus`/`InterruptACK`,
a claim per slot — the shape the console UART's line just got) or the device
moves to the PCIe transport, where per-entry claims already exist
([RFC 0005](0005-claim-the-msix-entries-a-driver-names.md)).  Neither is
taken *now*: the device is attached by no gate and no documented machine, so
the work would serve a cold path, which is the trade this tree refuses
elsewhere ("a claim no gate exercises is *implemented*, not *verified*").
What changes now is the record: `docs/kernel/drivers.md` says next to the
driver that the poll is the transport's shape, `docs/status.md`'s keyboard
row carries the same fact, and this document names the trigger that reopens
it — the first machine or gate that attaches a virtio keyboard.

## Alternatives

- **Remove the tick drain and make the ring's owner drain on release.**
  Rejected: the lock's release point cannot know the handler missed (nothing
  was recorded), so this needs a missed-drain flag *and* a drain inside every
  transfer path — a larger surface for the same property, and one whose
  failure mode is the silent kind (a report nobody drains).  Under TCG the
  lock-held delivery is the common case, not an edge, so the new paths would
  be the hot ones.
- **Make the tick drain conditional on a "the handler missed" flag.**
  Closer to right, and worth doing if a measurement ever shows the per-tick
  lock take: the flag alone is not sufficient (the boot window posts events
  with no message to miss, and arming does not re-raise), so it needs a
  drain at arming as well.  Not taken here because it changes a path this
  tree cannot yet force with a gate; named under Unresolved questions.
- **Drain from the interrupt by making the ring lock-free** (split consumer
  state so the handler owns the consumer index).  Rejected: the ring's
  consumer state is the controller's, RFC 0006's lap design is built on one
  owner, and a second consumer is a rewrite of both to serve a case the tick
  already covers.
- **Remove the virtio-input poll and poll only on demand** (from the read
  path, the way `SerialDevice::try_read_byte` polls the FIFO).  Rejected: the
  console polls because a reader is waiting; a keyboard has no waiter — its
  reports must be injected whether or not anyone reads — so the timer is the
  only period there is.

## Drawbacks

- The tick still takes the controller's lock every tick on a machine with a
  USB controller; with the flag idea above that could be conditional, and the
  argument for paying it now is that the flag cannot yet be trusted with the
  boot window.
- The virtio-input poll stays a path that no boot runs.  That is the honest
  cost of keeping an interface whose device is cold: deleting it would make
  the device undrivable, and pretending it is verified would be worse.
- The RFC settles two questions with no code change.  Its only mechanical
  product is prose — this document, the comments beside the two polls in
  `src/kernel/process/scheduler/timer.rs`, and the rows and passages that
  describe them — which is exactly what a decision with no implementation
  looks like, and the next reader gets the argument instead of re-deriving
  it.

## Compatibility and migration

None.  No ABI, no on-disk format, no interface moves.  The documents that
describe the two polls change; the code does not.

## How this is proven

- **The drain half**: `make check-x8664-usb-hotplug` and
  `make check-x8664-runtime` both run the drain — the hub's watch and the
  keyboard's reports are served from it — so the mechanism the tick backs up
  is gated on those machines.
- **The contention sequence** (a report arriving while a transfer holds the
  rings) is *not* forced by any gate today.  That is named below rather than
  papered over: what is asserted is the drain path, not the tick's necessity.
- **The virtio-input half**: nothing, and the document says so; the poll's
  only gate would be a boot with the device attached, which no machine has.

## Unresolved questions

- **A gate for the contention sequence**: a probe that takes the rings (or a
  transfer held open) while a hub report is posted, then asserts the report
  is answered by the *tick* rather than the interrupt.  Until it exists, the
  fallback's necessity is argued, not measured.
- **The conditional drain**: if the per-tick lock take ever shows up in a
  measurement (`make check-perf-baseline`'s counters are the place it would),
  the flag-plus-arming-drain version is the change to make, with the boot
  window's drain at arming as the part that cannot be left out.
- **The MMIO transport's line**: giving it `InterruptStatus`/`InterruptACK`
  and a claim per slot would serve every virtio-mmio device, not just input —
  a second PCIe-class transport decision, triggered by the first machine
  that needs a mmio device's completion not to wait for the tick.
