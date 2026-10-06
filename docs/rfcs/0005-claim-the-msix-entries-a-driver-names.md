# RFC 0005: Claim the MSI-X entries a driver names

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-06
- **Supersedes:** 0003

## Summary

A claim on a device's MSI-X table is sized by the table, not by the driver: it
allocates one interrupt identity per *entry the table has* and gives every
unnamed entry a device-wide handler.  An xHCI controller with sixteen
interrupters therefore takes sixteen of the window's thirty-two vectors to
signal on one.  This RFC sizes the claim by what the driver names: one
identity per named entry, and every other entry written **masked**, so the
device cannot deliver an identity nobody owns — which is what the fallback
handler was for.

## Motivation

[RFC 0003](0003-program-the-msix-table-on-x86_64.md) chose the per-entry claim
for a reason that is still right — "an identity the device can signal and
nobody owns is counted as spurious, which is a worse answer than a wakeup that
turns out to be for another queue" — but it answered it by owning *more* than
it needed.  The cost is in two places:

- **The window is finite and first-fit.**  `MSIX_VECTOR_BASE..=MSIX_VECTOR_LAST`
  is 32 vectors, and xHCI's table has sixteen entries, so one controller takes
  half of it and a third PCIe device can be refused a claim it should have had.
  `docs/status.md` records the shape: "a claim takes one identity per entry".
- **Every unnamed entry has an owner that can do nothing with the message.**  A
  virtio device's config-change entry and xHCI's other fifteen interrupters are
  programmed to wake a handler whose only answer is to re-read the ring, which
  is exactly the "wakeup that turns out to be for another queue" the fallback
  was meant to absorb — and the device was told to deliver it.

And the design that replaces it is smaller, not larger: an MSI-X entry whose
Vector Control mask bit is set cannot deliver a message at all, so the way to
guarantee that no identity is delivered without an owner is to leave the entry
masked rather than to give it a handler.

## Current state

- **The window.**  `src/arch/x86_64/msi.rs` defines `MSIX_VECTOR_BASE` (0x60)
  through `MSIX_VECTOR_LAST` (0x7F); `msix_handlers_for` in
  `src/arch/platform.rs` builds a handler list of the table's size, naming the
  driver's handlers and filling every other entry with the fallback.
- **The claims.**  `src/arch/x86_64/msi.rs`, `src/arch/aarch64/its.rs` and
  `src/arch/riscv64/pci.rs` each validate `named` against the table size, call
  `irq_handlers::claim_each` with a handler list of the table's size, and
  program *every* entry of the table when the machine can receive.
- **The drivers.**  `src/drivers/virtio_net.rs` names entries 0 and 1 and
  passes a device-wide fallback; `src/drivers/virtio.rs` names entry 0 and
  passes one; `src/drivers/xhci.rs` names entry 0 and passes one.
- **The self-test.**  `src/arch/riscv64/pci.rs`'s `probe_unclaimed_msix` claims
  an undriven device's table with an empty `named` list and a probe handler as
  the fallback, to exercise the programming path once on a machine whose only
  device a driver already owns.

## Design

**A claim is one identity per named entry, and `named` is the whole request.**
`msix_handlers_for(count, named, fallback)` becomes
`msix_named_handlers(count, named)`: it validates that every named entry is
inside the table and that no entry is named twice, and answers the handlers in
the order the ids are allocated.  The claim calls `claim_each` with exactly
`named.len()` handlers, and records the table entry each identity belongs to
(`entries: Vec<u16>`, allocation order).  A caller that names nothing is a
caller asking for nothing, which is not a claim.

**Everything unnamed is written masked.**  Arming writes all `count` entries,
the named ones composed with their identity and the rest as
`MsixTableEntry::masked()`, then unmasks only the named ones and enables MSI-X.
Writing the unnamed entries is what makes the claim safe on a device whose
table was left in an unknown state: an entry this claim does not own ends the
arm step unable to deliver, rather than depending on what a previous user left
there.

**The fallback parameter goes away.**  It has no entry to be the handler for.
A message the driver's own handler cannot attribute is still absorbed by the
driver's re-read loop, which is where that already happens today; what changes
is that the device is no longer told to send one.

**The identity a driver gets is still opaque.**  A driver names table entries —
the transport's own numbering — and the claim decides which vectors carry
them; nothing in this change tells a driver which vector it owns, and
`first_irq()` keeps answering the first identity it allocated, for logs.

**The RISC-V self-test names entry 0.**  `probe_unclaimed_msix` exists to run
the programming path on a machine where every driven device is already
claimed, and with no fallback to register it names the first entry of an
undriven table with the probe handler.  That is a claim like any other: one
identity, one entry, the rest masked.

## Alternatives

- **Keep per-entry claims and grow the window.**  The cost is not only
  vectors: each device's unnamed entries are still programmed and unmasked, so
  the messages they can raise exist whether or not the window has room for
  them.  It also scales with the widest table rather than with the work.
- **Keep the fallback handler and mask the entries anyway.**  A masked entry
  cannot deliver, so the handler is unreachable code that the registry still
  has to reserve a vector for — the cost this RFC removes, kept for the
  appearance of safety.
- **Let a driver pass its own `count`.**  Rejected: the table's size is read
  from the capability and the driver's need is read from `named`; a driver
  that could name a size could claim vectors it never uses, which is the
  defect, one layer down.
- **Reject a claim when the driver names entries out of order, rather than
  allocating in the order named.**  The allocation order is the driver's to
  choose; what has to be refused is an entry outside the table or one named
  twice, and the first-fit allocator already gives consecutive ids for a
  run.

## Drawbacks

- **A driver that forgets to name an entry it needs loses that interrupt.**
  Under per-entry claims such an entry was programmed with the device-wide
  handler and would at least wake something; now it is masked and silent.  The
  answer is that a driver that does not name an entry has not said it uses it
  — and the device's own transport decides which entries carry what, so the
  driver's numbering is the one place this can be got right.
- **The log lines change, and the gates that assert them change with them.**
  The number of identities a device takes goes *down*, which is the point, but
  a reader who remembers the NIC taking `irq 8196-8199` will see it take
  `irq 8194-8195`, and the block function beside it go from three identities to
  one.
- **The table is now written in two shapes** — composed for named entries,
  masked for the rest — so the programming path has one more case than it had.

## Compatibility and migration

Nothing on disk, on the wire or in the ABI changes.  The drivers' own
interfaces are unchanged: they still name `(entry, handler)` pairs and still
ask the platform for a claim; the parameter they no longer pass is one only
they supplied.  A device-tree machine with no ITS or no IMSIC still refuses
the claim and leaves the driver on its polling path, and the polling path is
unchanged.  The change is not half-applicable in a way that loses an interrupt:
an entry is either named and owned, or written masked.

## How this is proven

- `make check-x8664-runtime` asserts the NIC's claim and its table
  (`[msix  ] MSI-X on 00:02.0 delivers vectors ...`) and that a queue's own
  message arrived; with this change the NIC takes two identities and xHCI
  takes one, so the log's vector numbers move and the assertions move with
  them.
- `make check-aarch64-runtime` asserts the LPIs each device takes
  (`[its   ] MSI-X ...: irq ...-... placed on cpu [...]`) — the same numbers
  RFC 0003 sized by the table — and is where the change shows as *fewer* LPIs
  per device rather than as a device that stopped working.
- `make check-riscv64-pci-runtime` asserts the IMSIC's per-device claim, the
  table's programming and the receive-side walk, including the self-test that
  names entry 0 of an undriven table.
- The host tests in `src/arch/x86_64/msi.rs` cover the window and the entry
  composition; the masked entry's shape is one of them.

## Unresolved questions

- **Should the window stay 32 vectors?**  With per-entry claims the same
  window holds more devices, which is the reason to keep it fixed for now;
  sizing it from the tables the machine actually has is a later change.
- **Should a claim report which identities it took, rather than only the
  first?**  `first_irq()` is enough for the logs and the drivers; a driver
  that wanted one vector per queue pinned to a CPU would want the list, and
  nothing here forbids returning it later.
