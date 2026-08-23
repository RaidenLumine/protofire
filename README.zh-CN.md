# 源火内核

[English](./README.md) | [简体中文](./README.zh-CN.md)

这是一个用 Rust 编写的裸机 `#![no_std]` 宏内核，支持 x86_64、AArch64 和 RISC-V 64 架构。它提供了面向文件的用户态 ABI，具备抢占式多线程、原生 TCP/IP 协议栈、事务性内存文件系统（SimpleFs）、NUMA 感知调度、virtio-gpu 加速显示、MSI/MSI-X 中断支持和每线程栈金丝雀保护，以及内核和用户态程序共享的 `src/user/shared/` 库。

## 构建与测试

### 前置要求

- Rust 稳定版工具链，并已安装 `x86_64-unknown-none`、`aarch64-unknown-none` 和 `riscv64gc-unknown-none-elf` 目标
- QEMU（用于 `make run`、`make run-aarch64` 和 `make run-riscv64`）

### 快速开始

```bash
# 主机端类型检查（所有目标）
make check

# 主机端单元测试 + 集成测试（需要启用 demo-disk 特性）
make test

# 快速测试子集
make test-fast          # 路径、I/O、系统调用、用户集成回归测试
make test-concurrency   # 调度器、输入、条件变量并发回归测试
make test-storage       # 文件系统、恢复、故障注入回归测试

# 多级验证门禁
make verify             # 默认 P3 门禁（fmt + clippy + test + cross-check）
make verify-p0          # 最快：fmt + clippy
make verify-p1          # p0 + 主机端单元测试 + 目标检查
make verify-p2          # p1 + 集成测试
make verify-p3          # p2 + 全交叉目标构建

# 裸机构建
make build
make build-aarch64
make build-riscv64

# 在 QEMU 中运行
make run
make run-aarch64
make run-riscv64

# Clippy（所有目标，关键 lint 将警告视为错误）
make clippy
```

## 目录结构
```text
├── src/
│   ├── abi/               # 共享 ABI 记录（系统调用编码、进程/文件/网络数据格式）
│   ├── arch/              # 架构后端（x86_64、AArch64、RISC-V）
│   ├── kernel/            # 内核核心（VFS、驱动程序、网络、进程、内存、系统调用、同步）
│   ├── user/              # 用户态支持（ELF 加载器、程序管理、shell 分发、演示负载）
│   │   ├── demo/          # 演示 ELF 工件构建器（elf_builder）
│   │   └── shared/        # 共享 shell/用户运行时逻辑（ABI 类型、系统调用包装器、内置命令）
│   └── util/              # 工具辅助函数（调试、格式化、加密辅助）
├── tests/                 # 主机端集成测试（fs、io、memory、net、process、simplefs、sync、syscall）
├── docs/                  # 架构和子系统文档
├── Makefile               # 构建、测试、检查、clippy、验证门禁
├── Cargo.toml
├── build.rs               # 链接脚本选择
├── linker.ld              # x86_64 链接脚本
├── linker-aarch64.ld      # AArch64 链接脚本
└── linker-riscv64.ld      # RISC-V 链接脚本
```

## 特性标志

| 特性 | 用途 |
|-|-|
| `demo-disk` | 内存演示文件系统卷、演示内核工作线程、演示用户程序 |
| `fs_profiler` | 文件系统操作性能分析计数器 |
| `net_profiler` | 网络数据包 / 吞吐量性能分析计数器 |
| `alloc_profiler` | 内核堆分配性能分析计数器 |
| `fault_profiler` | 页错误性能分析计数器 |
| `educational_networking` | 网络栈详细调试日志 |

## 架构支持
|目标 | 启动协议 | 状态 |
|-|-|-|
|x86_64-unknown-none | Multiboot2（GRUB）/ QEMU PVH	完整 |
|aarch64-unknown-none | QEMU 直接 `-kernel` | 完整 |
|riscv64gc-unknown-none-elf | QEMU 直接 `-kernel` | 部分 |

## 文档

请参阅 `docs/` 目录获取完整的设计文档、API 手册和移植指南。

## 参与贡献

欢迎任何形式的贡献——代码、文档、测试、Issue 报告或设计讨论。问题与 PR 可以使用中文或英文。相关文件：

- [CONTRIBUTING.md](CONTRIBUTING.md) — 贡献指南（构建、测试、代码风格、系统调用 ABI 规则）
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — 行为准则
- [SECURITY.md](SECURITY.md) — 安全漏洞报告政策
- [ROADMAP.md](ROADMAP.md) — 项目路线图
- [MAINTAINERS.md](MAINTAINERS.md) — 维护者列表
- [NOTICE](NOTICE) — 版权与归属声明

## 许可证

[Apache-2.0](LICENSE)