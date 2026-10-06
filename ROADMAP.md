# Protofire Roadmap

This roadmap describes where the Protofire kernel is headed. It is maintained
by the project maintainers and updated as work lands. Milestones are indicative,
not commitments — priorities can shift with contributors' interest.

The authoritative picture of what exists today is
[docs/status.md](docs/status.md).

---

## Guiding Principles

1. **ABI stability first.** The syscall ABI is the compatibility boundary.
   Stable slots (0–120) are frozen; numbering is append-only, never renumbered.
2. **Correctness over features.** Crash-safety, fault-injection tests, and
   transactional recovery come before adding more surface area.
3. **Architecture parity.** Where the hardware permits, features should land on
   all three targets (x86_64, AArch64, RISC-V 64) — not just one.
4. **Verifiable progress.** Every milestone ends in tests, docs, and a green
   `make verify-p3`.

---

## Near Term (next 3–6 months)

- **RISC-V 64 → full target support.** The user ABI, interactive demo shell, and
  demo payload are verified on RISC-V 64 under QEMU, and so is the AIA IMSIC —
  the kernel boots on `aia=aplic-imsic` and walks its own MSI path there.  The
  PCIe window is walked too, now that the device-tree parser settles it at the
  end of the node instead of when it reads `reg`, the kernel's own resource
  pass gives a device's BARs addresses, a `virtio-net-pci` is driven through
  the modern transport (that is the NIC the runtime check boots with), and an
  MSI-X table is programmed through the IMSIC, read back, its identities
  allocated by the controller and claimed by the driver that owns the device
  before it is allowed to signal, and the NIC's queues are routed to them — so
  the device signals on its own and a completion waits on that interrupt
  (checking the ring first, spinning last).  Remaining gaps: MSI-X is claimed
  per queue now, with each entry placed on a hart in turn; the NVMe driver is
  the same one the PC compiles (it asks the platform for a window), so it
  drives this machine's bus too — but it cannot bring its queues up here,
  because `arch::mmu::phys_addr_of` answers nothing on riscv64 and a DMA
  buffer cannot be allocated.  That translation is the blocker; what follows
  it is a driver for any other PCIe device, and broader device-tree driver
  coverage.
- **AArch64 PCIe.** The ECAM window is found, its buses enumerated, its BARs
  assigned, and its `virtio-net-pci` driven — the same code as riscv64 with a
  different way of reaching a BAR.  Its devices signal by MSI too now: the
  GICv3, the LPIs and the ITS that translates a device's message into one are
  all there, one collection and one pending table per CPU, and a device's
  entries are placed over those CPUs in turn — so the NIC's queues are
  completed by different cores.  A second PCIe driver claims through the ITS
  too: `virtio-blk` on the same bus has its own DeviceID, its own LPI range and
  its own completion path that waits on it, which is what makes the placement a
  property of the machine rather than of one driver.  A third device class is
  driven now as well: NVMe, whose driver asks the platform for a window and
  whose queues and DMA are machine-neutral, so `make check-aarch64-nvme` mounts
  a real filesystem from a namespace on this bus.  What is left is another
  class still — the HDA controller, and anything that has to claim an
  interrupt of its own.
  [RFC 0001](docs/rfcs/0001-spread-message-signalled-interrupts.md) is the
  design the placement follows.
- **USB host (xHCI) completion.** The driver is present; close the remaining
  feature gaps so USB storage and HID work end-to-end.
- **HDA audio to userspace.** Expose the Intel HD Audio engine (currently CORB/
  RIRB + codec discovery) as a usable userspace stream interface.

## Mid Term (6–18 months)

- **Write support for more filesystems.** The read-only drivers — NTFS,
  BtrFS, SquashFS, ISO 9660, EROFS — move toward read-write, matching ext4 /
  F2FS / XFS / exFAT / FAT32.
- **Real-hardware bring-up.** Validate on bare-metal x86_64 boards and AArch64
  SoCs, not just QEMU; harden the device-tree probe path accordingly.  The
  assumptions a port has to remove — a fixed memory pool, `virt`-shaped
  fallbacks, fixed device windows, and the entry contract — are listed in
  [boot.md](docs/kernel/boot.md#platform-assumptions).
- **Stabilise the syscall ABI.** Graduate Experimental syscalls into Stable as
  they mature, moving the frozen boundary up; the append-only rule already
  reserves everything above the current highest slot.
- **Userspace VIRGL 3D demo.** Ship a demo renderer driving the virtio-gpu VIRGL
  interface (#181–189) to scanout.
- **Fuzzing & robustness.** Add cargo-fuzz-style targets for the ELF loader,
  filesystem image parsers, network packet parsers, and the LUKS2 header;
  extend the existing SimpleFs crash matrix.
- **Performance validation.** The work a boot does is counted and gated today:
  `make check-perf-baseline` compares the counters a boot reports against a
  recorded baseline, so a change that does more work fails without anyone
  measuring seconds.  What remains is measurement under load — SMP
  load-balancing on multi-core hosts, NUMA-node stress tests, and network
  throughput benchmarks.

## Long Term (1–3 years)

- **Broader POSIX surface.** Grow the file-oriented userspace ABI toward a
  practical UNIX subset; evolve the shell and runtime (`src/user/shared/`).
- **Userspace ecosystem.** An init/service manager and a lightweight package
  story for the demo disk.
- **Formal-verification seeds.** Property-based testing (proptest) and model
  checking for the TLSF allocator, the scheduler invariants, and the FS
  undo-log — the subsystems where a subtle bug hurts most.
- **Security hardening pass.** Default-deny MAC policies, audit tooling, and a
  full attack-surface review.
- **Reproducible releases.** The artifacts are reproducible and gated
  (`make check-reproducible-build`), and one can be signed with a fresh
  one-time key (`cargo run -- sign-release …`, checked with `verify-signature`).
  `make release` builds the four artifacts, names them for shipping, signs each
  with its own one-time key, verifies every signature, and writes the checksum
  manifest, and [CONTRIBUTING.md](CONTRIBUTING.md) carries the order around it
  — the gate, the tag, the upload, and the rebuild a user can check a signature
  against.  What remains is the release itself: tagged 1.x versions and the
  first published key records.
- **Governance.** Design documents for large changes live under
  [`docs/rfcs/`](docs/rfcs/README.md), with a lifecycle that ends in a record
  of what was decided and why; [MAINTAINERS.md](MAINTAINERS.md) names who
  accepts one.  What remains is growing the maintainer team beyond one person.

---

## How to Help

Pick a milestone, open an issue to claim it, and read
[CONTRIBUTING.md](CONTRIBUTING.md). Known gaps in the code are tracked in
[docs/status.md](docs/status.md); anything labelled `good first issue` is a
good starting point.
