# Interrupts

How a device or a core gets the kernel's attention, and what happens between
the trap and the handler.  Each machine has its own controller and its own way
of naming an interrupt; what is shared is the part after that — one registry of
handlers, one set of counters, one balancer — in `src/arch/irq_handlers.rs`,
`src/kernel/irq_stats.rs`, `src/kernel/irq_balance.rs` and
`src/arch/irq_placement.rs`.

## From the trap to the handler

The per-architecture trap entry (`src/arch/<machine>/trap.S`, or the IDT on
x86_64) saves the interrupted context and calls the controller's dispatch.
Every controller implements the same three answers
(`src/arch/interrupt_controller.rs`): initialise the hardware, end an interrupt
(`end_of_interrupt` — an EOI, a GICC write, a claim-and-complete on RISC-V),
and enable or prioritise a source.

Delivered identities are then looked up in one registry.  Its reason for
existing is the message-signalled machines: RISC-V's IMSIC names an identity in
the message's data word and AArch64's ITS translates one into an LPI, so both
deliver *numbers* rather than wires, and both need the same three things — a
window of identities a device may own, one handler per identity, and a lookup
that runs the handler for the number that arrived.  `claim` and `claim_each`
allocate a run of identities (the second taking one handler per identity, which
is what a multi-queue device wants), and `dispatch` runs the handler, taking it
out of the table first so a handler that registers another identity cannot
deadlock on the registry's own lock.  An identity nobody claimed is
distinguished from a spurious interrupt by the caller, and both are counted.

## The controllers

### x86_64

The local APIC and the IOAPIC, mapped at their MMIO window in
`src/arch/x86_64/apic.rs`, with the IDT and the vector space in
`interrupts.rs`.  The IOAPIC's redirection table is where a wired interrupt's
destination lives, so that is the lever the load balancer pulls.  Message
interrupts are composed in `src/arch/x86_64/msi.rs` — the address carries the
destination LAPIC id and the data word the vector — and a device's table is
programmed there too: a driver claims vectors from a window of the IDT
(`MSIX_VECTOR_BASE`..`MSIX_VECTOR_LAST`, each with its own stub), the claim is
held until the local APIC is up, and arming it writes the function's table,
enables MSI-X and clears its function mask.  A delivered vector *is* the
identity: `interrupts.rs` looks it up in the same
[handler registry](../../src/arch/irq_handlers.rs) the ITS and the IMSIC answer
through, so a completion reaches the queue that claimed it.  The design is
[RFC 0003](../rfcs/0003-program-the-msix-table-on-x86_64.md).

### AArch64

GICv2 or GICv3, chosen by reading the distributor's identification registers
(`GICD_PIDR2`) rather than by configuration, in `src/arch/aarch64/mod.rs` and
`src/arch/aarch64/gicv3.rs`.  The two differ in where per-CPU state lives: in
GICv2 the CPU interface is a frame and the SGI/PPI bank is in the distributor,
while in GICv3 the interface is the `ICC_*` system registers and each PE has
its own redistributor carrying its SGI/PPI bank.  SGIs are sent by affinity.

Message interrupts go further: the GICv3 **ITS** (`src/arch/aarch64/its.rs`)
translates a device's device-id/event-id into an LPI and a *collection*, and a
collection names a redistributor.  This kernel maps one collection and one LPI
pending table per CPU — the configuration table is shared, because the
architecture has every redistributor read one — and places a device's entries
over the CPUs that can receive
([see below](#where-an-interrupt-is-placed)), so a multi-queue device's queues
are completed by different cores.

### RISC-V 64

The PLIC, with one S-mode context per hart (`src/arch/riscv64/mod.rs`): a
context enable is the per-hart lever, so that is what the balancer uses.  The
**AIA IMSIC** (`src/arch/riscv64/aia_imsic.rs`) is the other machine's
controller: each hart has an MSI-write page and a file whose `stopei` register
answers with the identity on top and claims it in the same read.  The default
machine has no IMSIC, so the PLIC is the external controller there and the IMSIC
only appears on a machine that describes it.

## Message-signalled interrupts

A device that signals by writing a message needs three things, and this tree
names all three: a controller that receives it (`arch::interrupt_controller`),
a table on the device that says where to write, and a driver that owns the
identities the table delivers.  The driver claims at probe time — a claim is a
table entry, not a hardware access — and the platform programs the table later,
once the controller is up (`arch::platform::program_device_msix`), reading each
entry back so that a table nobody wrote shows up then rather than as a missing
interrupt later.

Programming happens after the secondary CPUs are up, because that is also when
the placement is decided: an entry naming a core whose LPI pending table is not
installed yet would have its message dropped rather than queued.

A claim is sized by what the driver names, not by what the table has: the
driver passes `(table entry, handler)` pairs, and the claim takes one identity
per pair and **writes every other entry of the table masked**, so a device
cannot deliver an identity nobody registered for.  That is why an xHCI
controller with sixteen interrupters takes one identity rather than sixteen —
[RFC 0005](../rfcs/0005-claim-the-msix-entries-a-driver-names.md) is the
decision, and it is the successor to RFC 0003's per-entry claim.

What is claimed today: the PCIe `virtio-net` driver (one identity per queue),
`virtio-blk` (one, for its one queue), and xHCI (one, for its one interrupter),
on the machines that have the controller to carry them.  Everything else —
NVMe, HDA, any second PCIe driver — is reached through its architecture's own
enumeration and does not claim identities through this path.

## Where an interrupt is placed

`src/arch/irq_placement.rs` is the policy, and it is one line because the
interesting part is what it must not do: hand every entry of a device to the
boot CPU.  Entries are placed round-robin over the CPUs that can receive one,
which is what puts a device's queues on different cores; "least loaded" was the
alternative and loses because placement happens at claim time, before there is
any load to read.

Each architecture turns that choice into hardware its own way: AArch64 maps a
collection per CPU and points an entry at a collection, while RISC-V writes the
target hart's IMSIC identity into each entry of the device's table.  Both ask
the same question first — *can this CPU receive one?* — and skip a core whose
pending table or IMSIC file is not ready, so a placement never names a reader
that is not there.

## NMI

`src/kernel/nmi.rs` is a registry and a dispatch path for the interrupts that
cannot be masked, with a handler that may claim the event or leave the default.
Which machines have a source is the architecture's answer: x86_64 has the NMI
vector, AArch64 has SError and FIQ, and RISC-V has no architectural source at
all — its S-mode dispatch entry stays dormant, which is why "no NMI source" is a
scope statement rather than a gap in a table.

## Balancing

`src/kernel/irq_balance.rs` migrates the busiest *migratable* interrupt away
from an overloaded CPU, on a period driven by the scheduler tick.  Whether an
interrupt is migratable is a property of its controller: an IOAPIC redirection
entry, a GIC SPI's affinity and a PLIC context enable are all controller-side
routing, and the balancer can rewrite any of them.  A message-signalled
interrupt has no such entry — its destination was chosen when the message or the
translation was written — so `pin_irq` is how a driver says "not this one", and
a device's own spread is the placement's doing rather than the balancer's.

## What is counted

`src/kernel/irq_stats.rs` keeps per-CPU, per-vector counts plus totals for
IPIs, NMIs and spurious interrupts.  The counters are the source of two things:
the load balancer's input, and `SystemInfo`
selector `SYSTEM_INFO_IRQ_PROFILER` (`src/abi/diagnostic.rs`), which is how a
program can ask which CPU has been taking the machine's interrupts.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/arch/interrupt_controller.rs` | The trait every controller implements |
| `src/arch/irq_handlers.rs` | The identity registry: claim, claim-each, dispatch |
| `src/arch/irq_placement.rs` | Which CPU a claimed entry is delivered to |
| `src/arch/x86_64/apic.rs`, `interrupts.rs`, `ioapic.rs`, `msi.rs` | LAPIC, IDT and vectors, IOAPIC routing, message composition |
| `src/arch/aarch64/gicv3.rs`, `its.rs` | GICv2/GICv3, LPIs, and the ITS translation |
| `src/arch/riscv64/mod.rs`, `aia_imsic.rs` | PLIC per-hart contexts, IMSIC files |
| `src/arch/platform.rs` | `pci_claim_msix`, `program_device_msix`, the arming order |
| `src/kernel/nmi.rs` | The unmaskable path and its handlers |
| `src/kernel/irq_balance.rs` | Migrating the interrupts a controller can re-route |
| `src/kernel/irq_stats.rs` | The counters, per CPU and per vector |

## See also

- [boot.md](boot.md) — when the controllers come up and when tables are programmed
- [RFC 0001](../rfcs/0001-spread-message-signalled-interrupts.md) — the design
  behind the placement policy
