# 维护者

[English](./MAINTAINERS.md) | [简体中文](./MAINTAINERS.zh-CN.md)

本文件列出源火内核（Protofire）的维护者、职责范围与项目治理方式。

## 核心维护者 (Core Maintainers)

对项目整体架构、发布和重大决策负有最终责任。

*   **Raiden Lumine** (<2557597107@qq.com>) - 项目创始人，架构总设计。负责：总体架构、ABI 稳定性、发布管理、代码审查。

## 模块维护者 (Module Maintainers)

各模块负责人对该子系统的代码质量与演进负责。目前各模块由核心维护者兼任，
欢迎通过[成为维护者](#成为维护者)流程提名认领。

### 内核启动与初始化 (Boot & Init)

*   **文件路径**: `src/arch/`, `src/kernel/smp/`, `src/kernel/percpu.rs`
*   Raiden Lumine (<2557597107@qq.com>) - 负责：启动汇编、`_start` 入口、多核启动、早期内存初始化。

### 内存管理 (Memory Management)

*   **文件路径**: `src/kernel/memory/`, `src/arch/*/paging`、`src/arch/*/mmu`
*   Raiden Lumine (<2557597107@qq.com>) - 负责：页表、TLSF 堆分配器、物理/虚拟内存管理、NUMA。

### 进程与调度 (Process & Scheduler)

*   **文件路径**: `src/kernel/process/`, `src/kernel/percpu.rs`, `src/arch/*/trap*`
*   Raiden Lumine (<2557597107@qq.comm>) - 负责：进程控制块、调度算法、上下文切换、trap 处理。

### 文件系统 (File System)

*   **文件路径**: `src/kernel/fs/`
*   Raiden Lumine (<2557597107@qq.com>) - 负责：VFS 层、SimpleFs、外部文件系统（FAT32、Ext4、XFS 等）、块设备接口。

### 设备驱动 (Device Drivers)

*   **文件路径**: `src/kernel/drivers/`, `src/arch/*/`
*   Raiden Lumine (<2557597107@qq.com>) - 负责：串口、键盘、显示、存储（AHCI/NVMe/VirtIO）等驱动框架与实现。

### 网络协议栈 (Networking)

*   **文件路径**: `src/kernel/network/`
*   Raiden Lumine (<2557597107@qq.com>) - 负责：网络协议栈、网卡驱动。

### 系统调用 ABI 与共享用户运行时 (Syscall ABI & Shared User Runtime)

*   **文件路径**: `src/abi/`, `src/kernel/syscall/`, `src/user/shared/`
*   Raiden Lumine (<2557597107@qq.com>) - 负责：系统调用 ABI（编号只增不删）、内核分发与用户包装器、共享 shell 运行时。

## 文档与社区 (Documentation & Community)

*   **文件路径**: `docs/`, `README.md`, `README.en.md`
*   Raiden Lumine (<2557597107@qq.com>) - 负责：技术文档维护、`docs/` 目录、中英双语翻译、社区运营。

## 职责

维护者应当：

- 审查并合并 pull request；分诊 Issue。
- 执行[行为准则](CODE_OF_CONDUCT.zh-CN.md)。
- 负责**系统调用 ABI**：只增不删的编号、稳定性分类与版本号递增。
- 保持 `make verify-p3` 通过，并以它为发布门禁。
- 维护 [ROADMAP.md](ROADMAP.zh-CN.md)，让 [docs/current-status](docs/) 与实际情况同步。
- 按 [SECURITY.md](SECURITY.zh-CN.md) 处理安全报告。

## 评审政策

- Protofire 目前是**单一维护者**项目：pull request 由 lumine 审查与合并。
- 重大改动合并前必须通过完整验证门禁（`make verify-p3`）或等价的 CI。
- 每个 PR 只做一件逻辑变更；评审清单见
  [PR 模板](.github/PULL_REQUEST_TEMPLATE/pull_request_template.md)。

## 成为维护者

- 在某个或多个领域持续提供高质量贡献。
- 表现出对某个子系统的专业能力，并认同项目指导原则（见 [ROADMAP.md](ROADMAP.zh-CN.md)）。
- 由现有维护者提名，并经当前维护者一致同意。

## 联系方式

- 邮件：**2557597107@qq.com**
- 公开讨论：GitHub Issue 与 pull request（英文或简体中文）。
- 安全事项：见 [SECURITY.md](SECURITY.zh-CN.md)——请**不要**公开张贴漏洞细节。
