# Protofire Roadmap

This roadmap describes where the Protofire kernel is headed. It is maintained
by the project maintainers and updated as work lands. Milestones are indicative,
not commitments — priorities can shift with contributors' interest.

The authoritative picture of what exists today is
[docs/kernel-introduction/current-status.md](docs/kernel-introduction/current-status.md).

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
  per device rather than per queue, a driver for any other PCIe device, and
  broader device-tree driver coverage.
- **AArch64 PCIe.** The ECAM window is found, its buses enumerated, its BARs
  assigned, and its `virtio-net-pci` driven — the same code as riscv64 with a
  different way of reaching a BAR.  The GICv3 the machine's devices signal
  through is implemented too, so what is left is the MSI side: on this machine
  that means a GICv3 ITS and the LPIs it delivers.
- **USB host (xHCI) completion.** The driver is present; close the remaining
  feature gaps so USB storage and HID work end-to-end.
- **HDA audio to userspace.** Expose the Intel HD Audio engine (currently CORB/
  RIRB + codec discovery) as a usable userspace stream interface.

## Mid Term (6–18 months)

- **Write support for more filesystems.** The read-only drivers — NTFS,
  BtrFS, SquashFS, ISO 9660, EROFS — move toward read-write, matching ext4 /
  F2FS / XFS / exFAT / FAT32.
- **Real-hardware bring-up.** Validate on bare-metal x86_64 boards and AArch64
  SoCs, not just QEMU; harden the device-tree probe path accordingly.
- **Stabilise the syscall ABI.** Graduate Experimental syscalls into Stable as
  they mature, moving the frozen boundary up; the append-only rule already
  reserves everything above the current highest slot.
- **Userspace VIRGL 3D demo.** Ship a demo renderer driving the virtio-gpu VIRGL
  interface (#181–189) to scanout.
- **Fuzzing & robustness.** Add cargo-fuzz-style targets for the ELF loader,
  filesystem image parsers, network packet parsers, and the LUKS2 header;
  extend the existing SimpleFs crash matrix.
- **Performance validation.** SMP load-balancing under multi-core hosts,
  NUMA-node stress tests, and network throughput benchmarks.

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
- **Reproducible releases.** Tagged 1.x releases with reproducible ISOs/disk
  images and signed artifacts for all three architectures.
- **Governance.** Grow the maintainer team, adopt RFC-style design docs for
  large features, and formalise the review process in [MAINTAINERS.md](MAINTAINERS.md).

---

## How to Help

Pick a milestone, open an issue to claim it, and read
[CONTRIBUTING.md](CONTRIBUTING.md). Known gaps in the code are tracked in
[docs/kernel-introduction/current-status.md](docs/kernel-introduction/current-status.md); anything labelled
`good first issue` is a good starting point.
