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
is what a multi-queue device wants), and `dispatch` runs the handler, cloned
out of the table so a handler that registers another identity cannot deadlock on
the registry's own lock.  An identity nobody claimed is
distinguished from a spurious interrupt by the caller, and both are counted.

Each *base* gets a window of its own, with its own slots.  That is not
tidiness: a slot is `identity - base`, so two bases answer to the same slot
number by arithmetic — an LPI 8193 (AArch64's `LPI_BASE`, 8192) and the console
UART's wired SPI 33 (`SPI_HANDLER_BASE`, 32) are both slot 1.  While one table
served every base, the first claim to arrive took the slot and the second was
refused; on a GICv3 boot the ITS registered the block device's LPIs before the
console's SPI was claimed, the UART's claim failed into a discarded result, and
a delivered 33 ran the *block driver's* handler — a typed byte announced as
`[virtio-blk] queue MSI (irq 33)`.  Each base now opens a window at its first
claim, and a claim that finds no window is refused rather than sharing one.

A wire can be an identity too.  AArch64's console UART claims its SPI in the
registry (`SPI_HANDLER_BASE`, `src/arch/aarch64/mod.rs`) and the trap path runs
it there, so a wired interrupt and a translated message take the same lookup;
RISC-V's PLIC sources are dispatched the same way (`PLIC_HANDLER_BASE`,
`src/arch/riscv64/mod.rs`).  On an AIA machine the wire arrives as a message in
the first place: the APLIC composes it, and the IMSIC's claim dispatches it
like any other identity.

What the console UART's arm actually achieved is the machine's answer, not an
assumption: the device-tree machines set a flag once their claim succeeded (the
controller writes follow it, in the same function), and the timer tick polls a
UART whose flag is clear.  A refused claim therefore costs an interrupt rather
than typing — the failure mode the collision above produced, which is why the
poll is wired to the outcome.

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
The CPU interface acknowledges Group 1 (`GICC_CTLR.AckCtl`): the kernel drives
every interrupt as Group 1, and a machine without the security extensions
presents the interface as Secure, where a clear bit hides every Group 1
interrupt from `GICC_IAR` and nothing is ever claimed.

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

An AIA machine has no PLIC at all, and its wire interrupts do not stop being
wires: they are carried by an **APLIC** domain (`src/arch/riscv64/aplic.rs`),
which watches a source's line and, in MSI mode, delivers it to an IMSIC file as
the message a PCIe device's MSI-X table would write.  QEMU `virt` describes
two domains — a machine-level one that holds the wires and delegates each
source to a child (`riscv,children`), and the supervisor-level child that
turns a delegated source into a message — and only the child is the kernel's
to program; `PlatformInfo::aplic_base` is the node the parser settles on (the
one *without* children).  What is measured on QEMU 10.2.1's bundled OpenSBI is
the split the driver assumes: firmware has already delegated the sources and
pointed the child's messages at the supervisor IMSIC (`SMSICFGADDR`), while
every source in the child is inactive, so arming one is exactly the gap the
count.  The identity a source's message carries is the source number itself,
which is what keeps a PLIC machine and an AIA machine answering through the
same registry window.

An AIA machine is also why the balancer's answer is the controller's:
`irq_balance::is_routable` refuses every source there, because the
destination of a message is decided where the message is *composed* — the
APLIC's own target register, whose firmware-written address fields name no
hart — and because the address a PLIC's enable bits sit at is, on that
machine, the machine-level APLIC's register block (the kernel programs the
supervisor domain at 0xd000_0000; the PLIC fallback address sits in the
machine-level window at 0xc000_0000).

A machine can have an APLIC and **no IMSIC behind it**
(`-machine virt,aia=aplic`): there is no PLIC to catch the wires either, and
the domain delivers through a different half of the specification — it
raises the receiving hart's supervisor external interrupt, and the hart
claims the source by *reading* its own window's `claimi` register.
`aplic::is_direct_mode()` is the discriminator (an APLIC node and no IMSIC),
`arm_source_direct`/`claim_direct` are the path, and a direct-mode controller
replaces the PLIC's so no PLIC-shaped write reaches a window no device
answers (falling back used to fault the boot at `0xc201000`, measured).

Two details are the whole of the difference and both were measured on the
machine rather than read off the specification:

* **The claim register is not an identity.**  `claimi` answers with the
  domain's `topi` word — source number in bits 31:16, priority in bits 7:0 —
  and the first version of the driver passed that word to the handler
  registry, which looked for a handler for `0x000a0001`, found none, and
  left the source re-pended forever: the claim loop outranked the timer tick
  and starved it.  Decoding the number is what makes the delivery work, and
  the trap dispatches by it the same way the PLIC and IMSIC paths do.
* **Nothing else claims or completes.**  Reading the register is the claim,
  and a level-high source whose input is still asserted is re-pended by the
  domain, so the handler's drain is what lowers the line — there is no
  `IDC` completion write in the path.

`make check-riscv64-aplic-direct-runtime` types at the machine's shell and
asserts the RX-interrupt landmark, which is the same evidence the other
machines' console paths are held to: arming alone is not delivery.

The mode's `iprio` is the order the domain arbitrates pending sources in —
"smaller priority numbers convey higher priority", a threshold of P holds
back P and higher, and zero is not a value the field takes — so the driver
carries a small policy rather than a number: the console takes the scale's
most urgent value and a device's wire sits below it, the threshold is zero
(every armed source passes), and the relations are `const` assertions in
`aplic.rs` so an edit that flips the scale fails the build.

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
`virtio-blk` (one, for its one queue), xHCI (one, for its one interrupter), and
NVMe (one, for its completion queue — the entry the controller's own admin
completions share, because a queue's vector is fixed by the `Create I/O
Completion Queue` command that runs before any table can be programmed), on
the machines that have the controller to carry them.  A driver whose claim the
machine refuses or never programs — a GICv2 with no ITS, a PLIC machine with
no IMSIC — polls instead, and says so at probe time.  What still polls on
every boot is HDA, whose controller has no MSI-X at all (QEMU's `intel-hda`
offers classic MSI, which this tree does not compose) and which asks the
platform for a register window and claims nothing
([RFC 0024](../rfcs/0024-what-the-hda-controller-signals-with.md) is the
decision and names what would change it).

One subtlety a device that *consults* the capability introduces: the claim
enables MSI-X **with the function mask set** (the same order Linux arrives at
through `pci_alloc_irq_vectors`), so a device that reads Message Control while
it is being configured — NVMe's `Create I/O Completion Queue` decides whether
that queue will interrupt from it — sees the capability as on, while nothing
can be delivered because the mask holds every entry back and the table is
still the all-masked one it reset to.  Arming is the step that programs the
table and clears the mask, and only that step makes the device able to
signal.

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
a device's own spread is the placement's doing rather than the balancer's.  An
AIA machine answers "not migratable" for every source
(`irq_balance::is_routable`), because none of its wire interrupts arrives
through routing the balancer could rewrite, and because the addresses a PLIC's
enable bits sit at name the machine's **machine-level** APLIC — firmware's
domain, whose registers do not mean what a PLIC's do.

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
| `src/arch/riscv64/mod.rs`, `aia_imsic.rs`, `aplic.rs` | PLIC per-hart contexts, IMSIC files, the APLIC domain that turns a wire into a message |
| `src/arch/platform.rs` | `pci_claim_msix`, `program_device_msix`, the arming order |
| `src/kernel/nmi.rs` | The unmaskable path and its handlers |
| `src/kernel/irq_balance.rs` | Migrating the interrupts a controller can re-route |
| `src/kernel/irq_stats.rs` | The counters, per CPU and per vector |

## See also

- [boot.md](boot.md) — when the controllers come up and when tables are programmed
- [RFC 0001](../rfcs/0001-spread-message-signalled-interrupts.md) — the design
  behind the placement policy
