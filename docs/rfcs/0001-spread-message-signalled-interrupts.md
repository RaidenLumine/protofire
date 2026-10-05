# RFC 0001: Deliver message-signalled interrupts on more than one CPU

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-05
- **Supersedes:** none

## Summary

Every message-signalled interrupt this kernel accepts is delivered to CPU 0.
On AArch64 that CPU is a constant in the ITS, and on RISC-V it is a literal
zero at the site that arms a device's MSI-X claim.  This RFC gives the kernel
one LPI collection and one pending table per CPU on AArch64, moves the choice
of destination to the moment a driver claims a device, and does the same on
RISC-V by threading a CPU through an arm path that already takes one.

## Motivation

A device's interrupts landing on one core does not break anything this tree
tests — the demo is quiet enough that a single CPU serves every queue — but
it is the reason the SMP work stops paying off exactly where the load is: a
NIC with several queues serialises all of them onto the core that also runs
the scheduler tick, while the cores that could take half the completions
never see one.

[current-status.md](../kernel-introduction/current-status.md) records both
halves of this as weaknesses — one LPI collection on AArch64, and MSI-X
claimed per device rather than per queue — and [ROADMAP.md](../../ROADMAP.md)
lists spreading the collections as what is left of the AArch64 PCIe path.

## Current state

The kernel owns the destination on both device-tree machines, and only one of
them has an interface for saying so:

- **AArch64.** A message becomes an LPI through the ITS: the device writes a
  device id and an event id, the ITS maps that pair to an LPI number and a
  *collection*, and the collection names a redistributor.  The mapping lives
  in kernel memory, so the kernel can change it without touching the device.
  `src/arch/aarch64/its.rs` programs exactly one collection and points it at
  the boot CPU's redistributor through `gicv3::rd_base_for_cpu`.  LPIs
  themselves are enabled by `src/arch/aarch64/gicv3.rs`, which allocates one
  configuration table shared by every redistributor plus a single pending
  table, and then points the *calling* core's redistributor at them.  The boot
  CPU is the only caller, and the code says that is on purpose.
- **RISC-V.** The message names a hart's IMSIC file, and the message is
  composed when the kernel writes the device's MSI-X table
  (`src/arch/riscv64/aia_imsic.rs`).  That path already takes the target CPU
  as a parameter; what it is passed is a literal zero, in `MsixClaim::arm`
  inside `src/arch/riscv64/pci.rs`.
- **x86_64.** Out of scope here, with a reason rather than by omission: a
  message-signalled interrupt's destination is part of the message, the
  message lives in the device's own table, and `src/arch/x86_64/msi.rs` is
  where this kernel composes one.  Placement there belongs to whatever
  programs that table, and changing it afterwards is a different change.
- **The existing balancer cannot cover this.**
  `src/kernel/irq_balance.rs` moves the interrupts whose destination is a
  controller-side routing entry — an IOAPIC redirection register, a GIC SPI's
  affinity, a PLIC context enable — and has `pin_irq` for the ones it cannot
  move.  A message-signalled interrupt has no such entry: its destination was
  chosen when the message was written, which is exactly the choice this RFC is
  about.

## Design

Three parts, in the order they have to happen.

1. **Per-CPU LPI state on AArch64.**  `src/arch/aarch64/gicv3.rs` keeps a
   pending table per CPU instead of one for the boot CPU; the configuration
   table stays shared, because the architecture says every redistributor reads
   the same one.  Enabling LPIs for a core moves into the per-CPU bring-up
   that already runs on every core and already finds and wakes that core's
   redistributor (`init_gicc` in `src/arch/aarch64/mod.rs`).  A core whose
   redistributor is missing, or whose pending table cannot be allocated, is
   simply never handed a collection.
2. **One collection per CPU.**  The ITS programming loop maps collection `c`
   to CPU `c`'s redistributor, and `claim_msix` stops using the constant: it
   asks a chooser for a CPU and maps that device's identities to that CPU's
   collection.
3. **A chooser with two answers.**  At claim time the chooser answers with a
   CPU: round-robin over the CPUs that can receive (the default), or the CPU
   the driver named when it has an opinion — the per-queue case, where a NIC
   wants queue `q` on a specific core.  The chooser is the single place this
   policy lives, and it is a pure function of the CPU count, the online set,
   and the request, so its tests need no machine.

RISC-V uses the same chooser: `MsixClaim::arm` passes its answer where the
literal zero is today.  Nothing else in that path changes — the table is
already written and read back entry by entry, and the read-back simply names
the CPU the chooser chose.

## Alternatives

- **Leave it, and record "MSIs go to CPU 0" as a design decision.**  This is
  defensible while the demo is the only load: one collection is less state,
  fewer commands, and no new failure mode.  It loses because the cost is the
  whole point of the SMP work — cores that cannot take the machine's busiest
  interrupt — and because the work is bounded: the per-CPU state is small and
  the chooser is a few lines.
- **One ITS per CPU.**  A collection is a name in a translation table, and the
  machine provides one ITS.  Giving each CPU its own would need the machine to
  offer one, which QEMU's does not.
- **Let the existing balancer migrate live interrupts.**  Attractive on
  AArch64, because the mapping is kernel memory and the ITS can re-point an
  event at another collection without the device being involved.  Deferred
  rather than rejected — see the open questions — because re-pointing a live
  interrupt needs a protocol with the driver, and the static version is worth
  landing first.
- **Spread per queue now.**  The right end state, and the reason the chooser
  takes a request at all, but it depends on claiming MSI-X identities per
  queue, which is a driver-facing gap in a different layer.  The placement
  landed able to answer it, and the driver half landed with it (see the
  implementation note), because the two together are what makes the spread
  observable.

## Drawbacks

- More boot-time state: one pending table per CPU, allocated before that CPU
  can be named in a collection, and a new way for a boot to come up with LPIs
  enabled on some cores and not others.
- More ITS commands at bring-up (one `MAPC` per CPU) and a collection table
  that has to stay valid for the machine's life, because collections are not
  freed.
- "Why is this queue on this CPU" gains an answer that lives in the chooser
  rather than in a constant: better, but one more thing to know when
  debugging an interrupt.

## Compatibility and migration

No ABI, on-disk, or on-wire change: the same LPIs are delivered, to a
different redistributor.  A single-CPU machine is unaffected, because the
chooser has one answer.  A boot that cannot allocate a CPU's pending table
keeps today's behaviour for that CPU — no collection — and the boot log has to
say so, in the shape the existing "no LPI tables" line already has.

## How this is proven

- The chooser is a pure function, so the host-side tests live next to it: one
  CPU, several CPUs, and a wrap.
- The hardware path is proven by the AArch64 boot with a NIC: the GICv3 second
  boot inside `scripts/check-aarch64-runtime.sh` runs two CPUs and a
  `virtio-net-pci`, and it asserts that each CPU enabled LPIs for itself, that
  the device's four entries were placed on `[0, 1, 0, 1]`, and — the property
  the whole design is for — that the RX and TX queues were *served by different
  CPUs*.  Which CPU served a queue is the console's own `[cpuN]` prefix, so the
  driver does not reach into per-CPU state to duplicate it.
- RISC-V is checked the same way where its tables are programmed: the
  placement line and a per-queue interrupt are asserted by
  `scripts/check-riscv64-pci-runtime.sh`, on the IMSIC machine
  (`-machine virt,aia=aplic-imsic`).

## Implementation note

`src/arch/aarch64/gicv3.rs` keeps one pending table per CPU and enables LPIs
for a core as it comes up; `src/arch/aarch64/its.rs` maps one collection per
CPU and places a device's entries over the CPUs that can receive.  RISC-V
names the hart in each MSI-X entry itself (`src/arch/riscv64/aia_imsic.rs`),
which is the same decision taken where that machine's table lives.  Both call
the policy in `src/arch/irq_placement.rs` (host-tested, next to the shared
`irq_handlers` registry).  x86_64 stayed out of scope as the design says.

Two things moved with it.  Device tables are now programmed after the APs are
up (`src/kernel/mod.rs`), because an entry naming a core whose pending table is
not installed yet would have its interrupt dropped rather than queued — before
that point the only CPU that can receive one is the boot CPU.  And the driver
half landed too: the registry registers one handler per identity
(`crate::arch::irq_handlers::claim_each`), a claim takes the entry each queue
named for itself, and virtio-net parks each queue's completion on that queue's
own interrupt rather than on the device's.

## Unresolved questions

- Round-robin, least-loaded, or driver-named by default?  This RFC starts
  with round-robin and a request hint, and expects the answer to change once
  there is load to measure.
- Should the AArch64 mapping ever be re-pointed at run time (an `MAPTI` and
  the `SYNC` that follows it), which would let the existing balancer move an
  LPI?  If so, what protocol does a driver owe — mask, drain, then move — and
  who owns the in-flight message?
- Per-queue identities landed with the placement rather than after it, so a
  driver now asks for them by naming a vector; what is still open is whether
  every queue of every future device should get its own CPU, or whether a
  device should be able to ask for a narrower spread.
- What happens to a CPU that comes up after a claim already picked it?  The
  chooser reads the online set at claim time, so a late CPU is only ever
  skipped, never preferred; a rebalancing story would have to revisit that.
