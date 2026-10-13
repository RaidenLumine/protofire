# RFC 0024: What the HDA controller signals with

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-14
- **Supersedes:** none

## Summary

The queued work item was "HDA claims its RIRB interrupt, the way NVMe just
did".  The measurement says it cannot take that shape: QEMU's HDA controller
offers **classic MSI and no MSI-X table**, so a claim — which is defined as
one identity per named *table entry* (RFC 0005, RFC 0023) — has nothing to
name.  This document decides instead: **HDA keeps its polling path**, and
records why, what would change it, and what the first obstacle after
"no table" would be, so the next person does not have to re-measure any of
it.

## Motivation

The tree has one class left whose driver polls its completion ring when a
modern device would signal: the Intel HDA controller
(`src/drivers/hda.rs`).  [docs/status.md](../status.md) records the gap
("the driver polls and claims no interrupt, so a device that has to signal
is still a gap"), and `ROADMAP.md`'s AArch64 PCIe note named it beside NVMe
as the class that had never exercised the ITS through a driver that must be
woken.  NVMe's completion queue claims an entry now, so the question stands
for HDA alone, and the answer has to be written down: a reader of either
document would otherwise keep expecting a claim that the hardware cannot
carry.

## Current state

- **The controller has no MSI-X table.**  QEMU's `intel-hda` calls
  `msi_init` (classic MSI, one vector, 64-bit address capable) and never
  `msix_init`; the file has no occurrence of `msix` at all (measured against
  `hw/audio/intel-hda.c`, QEMU 10.2.1 — the version the gates boot).  The
  same shape is what a real controller often is: classic MSI is the common
  capability on HDA functions, MSI-X rarer.
- **The claim path cannot express it.**  `arch::platform::pci_claim_msix`
  and the three backends program a *table*: entries selected by the driver,
  every other entry written masked.  A function with no table has no entries
  to select and no mask to depend on.
- **The driver already asks the controller to signal.**  `src/drivers/hda.rs`
  sets `RIRBCTL_RINTCTL` (raise an interrupt when the response write pointer
  advances) and clears `RIRBSTS` W1C flags while it polls; nothing in the
  tree composes a message for that line, so the interrupt the controller
  raises has no destination.  The two waits that a wakeup would shorten are
  `send_verb`'s poll of `RIRBWP` and `write_pcm`'s poll of the stream's link
  position, both bounded spins on DMA state the driver reads itself.
- **The waits run under the controller's lock.**  `device_write` holds
  `HDA_CONTROLLER` (a spin mutex; its critical section masks interrupts) and
  calls `write_pcm` on the controller inside it.  The block driver's park —
  the only shape in the tree that waits on a claimed interrupt — releases its
  queue lock on every iteration for exactly this reason
  (`src/drivers/virtio.rs`, `poll_completion`).

## Design

**HDA stays on its polling path.**  Nothing in the driver changes in this
change: no claim is taken (there is nothing to claim), no wait becomes a
park.  The gap is reclassified: it is not "HDA has not claimed yet" but
"**HDA cannot claim on the controllers this tree boots**, because its
controller has no MSI-X table, and its waits are shaped for polling".  Both
HDA gates continue to prove what the driver is for — the tone reaching the
host's WAV backend — on the path that runs.

**The mechanism that would change it is named.**  Two routes exist, in the
order they become live:

1. **A controller with an MSI-X table.**  Then the standard claim works
   unchanged — one entry named, the RIRB handler registered, the waits
   parking through the same `DeviceInterrupts` shape every other driver
   uses.  No new mechanism: this is the trigger that reopens the question
   with the least work, and it is a property of hardware, not of this tree.
2. **Composed classic MSI.**  A function that offers only classic MSI needs
   a second composition path per machine — message address/data written
   into the capability (LAPIC `0xFEE0_0000` base on x86_64; the GICv3 ITS's
   translater or the IMSIC's MSI page address on the device-tree machines),
   one identity claimed, the enable deferred until the receiver is up.
   This is the route a real HDA-only machine would need, and it is a
   mechanism of its own rather than a use of the claim path.

**The wakeup is not free even with a table.**  Before either route lands,
the wait shape has to change: a park inside `device_write`'s critical
section would spin forever with interrupts masked, so the waits would have
to drop the controller lock per iteration, exactly as the block driver
releases its queue lock before parking.  That is a change to how the audio
node's writer serialises, and it should be argued on a latency need from a
real workload — a BDL ring large enough that `write_pcm`'s bounded spin is
the wrong shape — rather than for an interrupt's own sake.

## Alternatives

- **Compose classic MSI now.**  Rejected for this change: it is new
  composition code on two machines (x86_64 and AArch64; riscv64 does not
  compile the HDA driver) for a device whose *correctness* never depends on
  the interrupt — both gates' evidence is the WAV's bytes, and both waits
  are bounded spins on state the driver reads directly.  The cost is a
  second interrupt mechanism in the tree against a latency improvement
  nothing measures yet.
- **Claim anyway and log the refusal.**  Rejected: a boot line that can
  never differ ("no MSI-X table") is a constant, not a measurement, and
  taking a claim to prove it fails would register handlers no device can
  ever deliver to.  The measurement lives here, with its source named.
- **Route the PCI interrupt line (INTx) instead.**  Rejected: a third
  mechanism (IOAPIC pin routing read from the PCI line register, or a GIC
  SPI claim on AArch64) with the same "no workload needs it yet" cost and
  worse behaviour on a shared line — the whole reason MSI exists.
- **Leave the documents as they were.**  Rejected: both `docs/status.md`
  and `ROADMAP.md` promised a claim that this RFC shows the hardware cannot
  carry; the record is the change.

## Drawbacks

- The latency of a full BDL ring's wait stays bounded-spin.  The counters
  that would show it are already in the driver (`position_spins`, reset on
  every successful copy), and the trigger is a caller that makes them
  visible.
- One class's completion path stays different in kind from every other
  driver's.  That difference is now a decision with a reason rather than a
  gap waiting for the same treatment as NVMe.

## Compatibility and migration

Nothing changes: no code moves in this RFC, no interface, no ABI.
`src/drivers/hda.rs` keeps polling; the two HDA gates keep passing on the
same conditions; a machine whose controller does have an MSI-X table would
take route 1 above when its driver half is written (the claim call sites
already handle a function with a table).

## How this is proven

- The claim's shape is what it is because of RFC 0005 and RFC 0023; this
  RFC cites their definitions rather than restating them.
- The hardware fact is re-checkable: `grep -c msix hw/audio/intel-hda.c` is
  0 against the QEMU version the gates boot, and the `msi_init` call is the
  controller's only interrupt capability.
- The driver's current path is what the gates prove: `make check-x8664-hda`
  and `make check-aarch64-hda` play a tone and measure it in the host's WAV
  file.  A claim that cannot deliver would add nothing to that evidence,
  which is why none is taken.

## Unresolved questions

- **Does any real HDA function this tree would run on offer an MSI-X
  table?**  If one does, route 1 is a driver change plus a gate on that
  machine, with no design work.  The RFC expects that to be the first
  reopening, and names it so it is recognized as one.
