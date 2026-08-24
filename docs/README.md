# Kernel Documentation

The kernel is a bare-metal, `no_std` monolithic kernel prototype written in Rust, targeting x86_64, AArch64, and RISC-V 64.

Documentation is organised across two directories:

| Directory | Purpose | Audience |
|-----------|---------|----------|
| [`en/`](en/) | English subsystem overviews with merged detailed reference | Anyone learning about or contributing to the kernel |
| [`zh-CN/`](zh-CN/) | 简体中文翻译 — 子系统概览 | 中文读者 |

- **`en/`** — High-level descriptions and detailed technical reference for each subsystem:
  boot flow, memory management, process/thread model, filesystem, network stack, syscall
  ABI, and the shared user runtime (`src/user/shared/`).
  Each document covers both _what_ the kernel does and _how_ the code is structured.
- **`zh-CN/`** — Simplified Chinese translations of the `en/` documentation.

---

## Document Index

### English Documentation ([`en/`](en/))

| Document | Description |
|----------|-------------|
| [Architecture Overview](en/README.md) | High-level architecture, subsystem dependency graph, memory layout, build system, ABI stability |
| [Boot Flow](en/boot.md) | Firmware handoff → kernel entry → init → idle loop; arch-specific entries, PS/2 probe, filesystem init |
| [Current Status](en/current-status.md) | Subsystem evaluations, scores, known gaps, milestones |
| [Filesystem](en/filesystem.md) | VFS layer, SimpleFs, external filesystem drivers; driver internals, file I/O, directory ops |
| [Memory Management](en/memory.md) | Frame allocation, TLSF heap, page tables, CoW, demand paging; frame allocator internals, swap |
| [Network Stack](en/network.md) | Dual-backend TCP/IP, TLS 1.3, protocol support; TCP/IP layering, connection model, poll readiness |
| [Process & Thread Model](en/process.md) | Scheduler, threads, process groups, signals, IPC; scheduler internals, thread lifecycle, signal delivery |
| [Shared user runtime](en/shared-user-runtime.md) | Shared ABI library, syscall wrappers, user-space runtime (module `src/user/shared/` inside the kernel crate) |
| [Syscall ABI](en/syscall.md) | Dispatch mechanism, numbering, user-memory validation; SyscallNumber enum, dispatch table, registry |

### Simplified Chinese Documentation ([`zh-CN/`](zh-CN/))

| Document | 描述 |
|----------|------|
| [架构总览](zh-CN/README.md) | 高级架构、子系统依赖图、内存布局、构建系统、ABI 稳定性 |
| [启动流程](zh-CN/boot.md) | Firmware 交接 → 内核入口 → init → 空闲循环 |
| [当前状态](zh-CN/current-status.md) | 子系统评估、评分、已知缺口、里程碑 |
| [文件系统](zh-CN/filesystem.md) | VFS 层、SimpleFs、外部文件系统驱动 |
| [内存管理](zh-CN/memory.md) | 帧分配、TLSF 堆、页表、写时复制、按需分页 |
| [网络协议栈](zh-CN/network.md) | 双后端 TCP/IP、TLS 1.3、协议支持 |
| [进程与线程模型](zh-CN/process.md) | 调度器、线程、进程组、信号、IPC |
| [共享用户运行时](zh-CN/shared-user-runtime.md) | 共享 ABI 库、系统调用包装、用户空间运行时（`src/user/shared/` 模块，位于内核 crate 内） |
| [系统调用 ABI](zh-CN/syscall.md) | 分发机制、编号、用户内存验证 |

---

## Related Documents

Collaboration and governance documents live at the repository root:

| Document | 说明 |
|----------|------|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | 贡献指南 — build/test, code style, syscall ABI rules / 贡献指南 |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 (English + 简体中文) |
| [SECURITY.md](../SECURITY.md) | 安全漏洞报告政策 / Security policy |
| [ROADMAP.md](../ROADMAP.md) | 项目路线图 / Project roadmap |
| [MAINTAINERS.md](../MAINTAINERS.md) | 维护者列表 / Maintainer list |
| [NOTICE](../NOTICE) | 版权与归属声明 / Copyright notice |

---

> **Codebase:** ~215,000 lines of Rust across 600+ files  
> **Targets:** x86_64 (full), AArch64 (full), RISC-V 64 (partial)  
> **Last updated:** 2026-08-20
