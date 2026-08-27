# Protofire Roadmap

[English](./ROADMAP.md) | [简体中文](./ROADMAP.zh-CN.md)

This roadmap describes where the Protofire kernel is headed. It is maintained
by the project maintainers and updated as work lands. Milestones are indicative,
not commitments — priorities can shift with contributors' interest.

The authoritative picture of what exists today is
[docs/en/current-status.md](docs/en/current-status.md).

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
  demo payload are verified on RISC-V 64 under QEMU. Remaining gaps: MSI/MSI-X
  (RISC-V AIA), full PCIe ECAM probing, and broader device-tree driver coverage.
- **AArch64 PCIe.** Move beyond basic probing to full ECAM support, matching
  x86_64.
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
- **Stabilise the syscall ABI.** Graduate Experimental syscalls (121–189) into
  Stable as they mature; reserve room beyond slot 190 with the append-only rule.
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
[docs/en/current-status.md](docs/en/current-status.md); anything labelled
`good first issue` is a good starting point.
