# Maintainers

[English](./MAINTAINERS.md) | [简体中文](./MAINTAINERS.zh-CN.md)

This file lists the maintainers of the Protofire kernel, their scope, and how
the project is governed.

## Core Maintainers

Have final responsibility for the overall architecture, releases, and major decisions.

*   **Raiden Lumine** (<2557597107@qq.com>) - Project founder and lead architect. Owns: overall architecture, ABI stability, release management, code review.

## Module Maintainers

Each module owner is responsible for the quality and evolution of their
subsystem. Currently every module is held by the core maintainer; seats are
open for nomination via the [Becoming a Maintainer](#becoming-a-maintainer)
process.

### Boot & Init

*   **File paths**: `src/arch/`, `src/kernel/smp/`, `src/kernel/percpu.rs`
*   Raiden Lumine (<2557597107@qq.com>) - Owns: boot assembly, `_start` entry, multicore bring-up, early memory init.

### Memory Management

*   **File paths**: `src/kernel/memory/`, `src/arch/*/paging` and `src/arch/*/mmu`
*   Raiden Lumine (<2557597107@qq.com>) - Owns: page tables, TLSF heap allocator, physical/virtual memory, NUMA.

### Process & Scheduler

*   **File paths**: `src/kernel/process/`, `src/kernel/percpu.rs`, `src/arch/*/trap*`
*   Raiden Lumine (<2557597107@qq.com>) - Owns: process control blocks, scheduling, context switch, trap handling.

### File System

*   **File paths**: `src/kernel/fs/`
*   Raiden Lumine (<2557597107@qq.com>) - Owns: the VFS layer, SimpleFs, external filesystems (FAT32, Ext4, XFS, ...), block device interfaces.

### Device Drivers

*   **File paths**: `src/kernel/drivers/`, `src/arch/*/`
*   Raiden Lumine (<2557597107@qq.com>) - Owns: UART, keyboard, display, storage (AHCI/NVMe/VirtIO) and other driver frameworks.

### Networking

*   **File paths**: `src/kernel/network/`
*   Raiden Lumine (<2557597107@qq.com>) - Owns: the network protocol stack, NIC drivers.

### Syscall ABI & Shared User Runtime

*   **File paths**: `src/abi/`, `src/kernel/syscall/`, `src/user/shared/`
*   Raiden Lumine (<2557597107@qq.com>) - Owns: the syscall ABI (append-only numbering), kernel dispatch and user wrappers, the shared shell runtime.

## Documentation & Community

*   **File paths**: `docs/`, `README.md`, `README.en.md`
*   Raiden Lumine (<2557597107@qq.com>) - Owns: technical documentation, the `docs/` directory, bilingual (en/zh-CN) translations, community operations.

## Responsibilities

Maintainers are expected to:

- Review and merge pull requests; triage issues.
- Enforce the [Code of Conduct](CODE_OF_CONDUCT.md).
- Own the **syscall ABI**: append-only numbering, stability classification, and
  version bumps.
- Keep `make verify-p3` green and gate releases on it.
- Maintain [ROADMAP.md](ROADMAP.md) and keep
  [docs/current-status](docs/) in sync with reality.
- Handle security reports per [SECURITY.md](SECURITY.md).

## Review Policy

- Protofire is currently a **single-maintainer** project: pull requests are
  reviewed and merged by lumine.
- Substantial changes must pass the full verification gate (`make verify-p3`)
  or the equivalent CI run before merge.
- One logical change per PR; the review checklist is in the
  [PR template](.github/PULL_REQUEST_TEMPLATE/pull_request_template.md).

## Becoming a Maintainer

- Consistent, high-quality contributions over time in one or more areas.
- Demonstrated expertise in a subsystem and agreement with the project's
  guiding principles (see [ROADMAP.md](ROADMAP.md)).
- Nomination by an existing maintainer, agreed to by the current maintainer(s).

## Contact

- Email: **123@456.com**
- Public discussion: GitHub issues and pull requests (English or Simplified
  Chinese).
- Security: see [SECURITY.md](SECURITY.md) — do **not** post vulnerability
  details publicly.
