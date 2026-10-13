# RFC 0023: Enable MSI-X when the claim is taken

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-14
- **Supersedes:** 0005

## Summary

RFC 0005 fixed what a claim *takes* — one interrupt identity per MSI-X table
entry the driver names, and every unnamed entry written masked — and its
closing step was where the function first saw MSI-X enabled: at arm time,
when the table is programmed.  This replaces that step, and only that step:
the claim writes the enable bit, and the function is kept *unable to
deliver* until arming by holding the Function Mask up in between.  The
reason is a device that consults the capability while it is being configured
rather than when a message is raised: NVMe's `Create I/O Completion Queue`
fixes its completion queue's interrupt behaviour from Message Control at
command time, and it ran before arm time — so the claim that this RFC's
sibling work makes for the NVMe completion queue could not have worked
without it.  Everything else RFC 0005 decided stands: the entries taken, the
entries masked, and the identity registry are as they were.

## Motivation

A claim is taken at probe time and armed later, once the interrupt controller
is up (`arch::platform::program_device_msix`).  In between, `src/arch/x86_64/msi.rs`,
`src/arch/aarch64/its.rs` and `src/arch/riscv64/pci.rs` left Message Control
as they found it: MSI-X disabled, everything masked.  Arming then did three
things in one step — write the table, unmask the named entries, and write
`MSIX_ENABLE`.

That order reads as the conservative one: nothing changes about the function
until the machine can receive.  The cost is paid by a device that *reads*
Message Control before arming, and QEMU's NVMe model is such a device.
`nvme_create_cq` validates the vector (`!msix_enabled(pci) && vector` is
`NVME_INVALID_IRQ_VECTOR`) and marks it in use (`msix_vector_use(pci,
vector)`, only when `msix_enabled(pci) && irq_enabled`), and `msix_notify`
returns early for a vector that was never marked:

```
if (!dev->msix_entry_used[vector]) {
    return;
}
```

So a completion queue created while MSI-X is disabled gets an interrupt that
QEMU will never deliver, however the table is programmed afterwards.  The
queue's vector is a field of `Create I/O Completion Queue`, which runs during
controller bring-up — before the interrupt controller exists and therefore
before any arming — and a queue's vector cannot be changed without deleting
and recreating it.  There is no later moment at which the driver could ask
for the interrupt.  The NVMe driver's claim (docs/status.md's NVMe row) is
the caller this RFC exists for; the same gate sits in every QEMU device that
uses `msix_vector_use`, which includes xHCI's interrupter mapping.

## Current state

- Each architecture's claim entry (`claim_msix`) validates the capability,
  takes the identities, maps the table, and returns a claim whose `arm()`
  writes the table and then `(message_control | MSIX_ENABLE) &
  !MSIX_FUNCTION_MASK`.
- `MsixClaimInner` records `message_control` as it was found, for that last
  step to compose from.
- Drivers claim at probe time and arm later: `virtio_net` and the block
  driver claim before their queues are enabled, xHCI after enumeration, and
  the platform holds the claims in a per-architecture `PENDING` list.
- A second claim on a function is refused with `AlreadyExists` when the
  capability reads enabled — which, before this change, meant "armed",
  leaving a window in which two probes could claim one function and the
  second'd overwrite the first's table.

## Design

**A claim takes the capability as enabled with the function mask set.**  The
claim step writes Message Control to `claimed_control(found)` — Enable set,
Function Mask set, everything else preserved — through the same
configuration-space write arming uses.  From the moment the claim exists:

- the function reads MSI-X as enabled, which is what a device consulting
  Message Control while it configures itself needs to see;
- **nothing can be delivered**: the Function Mask withholds every table
  entry regardless of the entry's own mask bit, and the table itself is
  still the all-masked state it reset to (the claim wrote no entry yet);
- a second claim is refused for the whole claim lifetime, because the
  capability reads enabled from the first claim onward — which closes the
  double-claim window above.

**Arming clears the mask, and only the mask.**  `arm()` writes the table
entries, unmasks the named ones, then writes `armed_control(found)` — Enable
set, Function Mask clear.  The enable bit written at claim time is what that
word keeps; the ordering *within* arming (table written, read back, named
entries unmasked, function mask last) is unchanged from RFC 0005, so a
message that arrives during arming is held by the mask and re-raised by
QEMU's mask-clear path (`msix_handle_mask_update` re-notifies a pending
entry), not lost.

**The two words are shared, not per-architecture.**  `claimed_control` and
`armed_control` live in `src/arch/pci/mod.rs` next to `MSIX_ENABLE` and
`MSIX_FUNCTION_MASK`, because the order has to hold on every machine that
programs an MSI-X table and the three backends are three places to get it
wrong.  The x86_64 claim's table-width check moves to
`claim_window_fits(named.len())` in the same step: RFC 0005 made the claim
the driver's requirement, so a table wider than the vector window (NVMe's has
65 entries against 32 vectors) must not refuse a claim that names one entry.

**A refused claim leaves the function as it found it.**  Each backend reads
the capability and performs every fallible step before the configuration
write, so a claim that answers `NotImplemented`, `AlreadyExists`,
`NoSpace` or `InvalidArgument` has written nothing and the caller polls as
before.

## Alternatives

- **Program the table and enable MSI-X at claim time, and skip arming.**
  Rejected: the interrupt controller is not up at claim time, so the
  destination the table would name does not exist yet — the entry could name
  the wrong CPU (AP bring-up moves the set of receivers) and the delivery
  would be dropped, not queued.
- **Let the NVMe driver create its completion queue late.**  Rejected: the
  queue pair is part of controller bring-up; a driver that deferred queue
  creation until after `program_device_msix` would have to re-order the whole
  boot, and the same pattern would be pushed onto every future driver whose
  device fixes queue state at configuration time.
- **Special-case MSI-X-less receivers: keep the enable at arm and make the
  NVMe claim ask for the capability early by another route.**  There is no
  other route — Message Control is the only bit that answers the question —
  and the special case would leave the three backends disagreeing about what
  a claim means.
- **Enable at claim time but without the function mask.**  Rejected: between
  claim and arm the table is all-masked, so delivery is already impossible —
  but the mask is the one bit that makes this true *by construction* rather
  than as an inference about the table's state, and the two bits read
  differently to a device that consults the capability.  Keeping the mask up
  until arming is also what Linux's `pci_alloc_irq_vectors` /
  `request_irq` pair does, which is the prior art this decision follows.

## Drawbacks

- A claimed-but-unarmed function reads as MSI-X-capable to anything else that
  looks at it.  On this tree the only other reader is a second claim, which
  should be refused anyway.
- The invariant "unarmed means harmless" now rests on the Function Mask
  rather than on the enable bit, so a backend that forgets the mask in its
  claim word would enable delivery with a table it does not control.  The
  two `const fn`s in one module are the mitigation, and the unit test pins
  their composition.
- Devices that treat "MSI-X enabled but masked" as an error state would be
  surprised; none is known, and the specification's own reset state is
  enabled-with-everything-masked on many devices (QEMU's `msix_init` starts
  with all entries masked and only the enable bit writable).

## Compatibility and migration

No wire or ABI change.  The claim and arm halves are internal to
`src/arch/`; a driver that claims and never arms leaves the function
enabled-but-masked, which delivers nothing, and a machine that never claims
touches no capability bit.  Drivers already written against RFC 0005 need no
change: they claim, they arm, and the end state is the same words as before,
one write earlier.

## How this is proven

- The unit tests in `src/arch/x86_64/msi.rs` pin the two words:
  `msix_claim_control_words_enable_without_delivering` and
  `msix_window_bounds_named_entries_not_the_table` (named entries, not the
  table's width, as the bound).
- The NVMe gate, which would not pass otherwise: on a boot where the claim
  is taken before `Create I/O Completion Queue`, `make check-x8664-nvme`,
  `check-aarch64-nvme` and `check-riscv64-nvme` require the completion MSI
  to reach the driver's handler ("[nvme  ] completion MSI (irq ..."), each
  on a machine whose controller can carry it, while the same machines'
  claim-refusing configurations (a GICv2 with no ITS, a PLIC with no IMSIC)
  still mount with the driver polling.
- The gates that were claiming before this change still are:
  `make check-x8664-runtime` (virtio-net, xHCI),
  `check-aarch64-runtime` (virtio-net, virtio-blk on GICv3),
  `check-riscv64-pci-runtime` and the NVMe/AIA gates assert claimed
  delivery on the machines whose controllers carry it, and the refusal
  segments assert the machines whose controllers cannot.

## Unresolved questions

- **Should a claim be *visibly* pending to anything but its owner?**  Today
  nothing distinguishes "claimed, not armed" from "armed" except the
  Function Mask read back with the capability.  If a driver ever has to ask,
  the answer is a bitmask of claimed entries in the claim object, not a
  fourth piece of hardware state.
