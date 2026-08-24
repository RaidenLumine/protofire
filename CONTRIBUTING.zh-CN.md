# 内核贡献指南

[English](./CONTRIBUTING.md) | [简体中文](./CONTRIBUTING.zh-CN.md)

感谢你对 **源火内核（Protofire）** 的关注与贡献。这是一个用 Rust 编写的裸机
`#![no_std]` 宏内核，支持 x86_64、AArch64 与 RISC-V 64 三种架构。我们欢迎一切形式的
贡献：代码、文档、测试、Issue、缺陷修复、基准测试与设计讨论。

参与本项目即表示你同意遵守[行为准则](CODE_OF_CONDUCT.md)。

---

## 快速参考

| 任务 | 命令 |
|------|------|
| 主机端类型检查（全部目标） | `make check` |
| 快速测试子集（路径、I/O、系统调用、用户集成） | `make test-fast` |
| 主机端完整单元 + 集成测试 | `make test` |
| 完整验证门禁（fmt + clippy + 测试 + 交叉构建） | `make verify` / `make verify-p3` |
| 裸机构建 | `make build` / `make build-aarch64` / `make build-riscv64` |
| QEMU 中运行 | `make run` / `make run-aarch64` / `make run-riscv64` |
| Clippy（关键 lint 视为错误） | `make clippy` |

完整的构建/测试矩阵见 [README.md](README.md)。

---

## 目录

1. [开发环境](#开发环境)
2. [从哪开始](#从哪开始)
3. [沟通与讨论](#沟通与讨论)
4. [代码风格与约定](#代码风格与约定)
5. [验证门禁](#验证门禁)
6. [新增或修改系统调用](#新增或修改系统调用)
7. [文档](#文档)
8. [提交变更](#提交变更)
9. [提交信息规范](#提交信息规范)
10. [PR 评审流程](#pr-评审流程)
11. [贡献者认可](#贡献者认可)

---

## 开发环境

### 先决条件

- **Rust 工具链：** 仓库通过 [`rust-toolchain.toml`](rust-toolchain.toml) 固定了精确的
  channel、组件与目标，文件会自动安装三个 `*-none` 目标：
  - `x86_64-unknown-none`
  - `aarch64-unknown-none`
  - `riscv64gc-unknown-none-elf`
- **QEMU** — `make run` / `make run-aarch64` / `make run-riscv64` 与交互式演示 shell 需要。
- 需要 `rustfmt` 与 `clippy`（均已在工具链文件中声明）。

### 首次构建：

```bash
make check          # 快速主机端类型检查
make verify-p3      # 完整门禁：fmt + clippy + 测试 + 交叉目标构建
make run            # QEMU 启动 x86_64（含约 40 条内置命令的演示 shell）
```

---

## 从哪开始

- 先读 [docs](docs/)
  [`docs/zh-CN/README.md`](docs/zh-CN/README.md)（架构总览）、
  [`docs/zh-CN/syscall.md`](docs/zh-CN/syscall.md)（ABI）与
  [`docs/zh-CN/current-status.md`](docs/zh-CN/current-status.md)（子系统状态）。
- 通常带 `good first issue` 标签的任务最适合入门；若暂无，`current-status.md` 中的
  「已知缺口」也是很好的切入点。
- 不确定改动归属时，先开 Issue 问清楚再动手，可以避免返工。

内核 crate 布局：

| 路径 | 用途 |
|------|------|
| `src/abi/` | 共享 ABI 记录（系统调用编码、进程/文件/网络数据格式） |
| `src/arch/` | 架构后端（`x86_64/`、`aarch64/`、`riscv64/`） |
| `src/kernel/` | 内核核心（VFS、驱动、网络、进程、内存、系统调用、同步） |
| `src/user/` | 用户态支持：`demo/`（ELF 构建器）与 `shared/`（shell + ABI 运行时） |
| `src/user/shared/` | **系统调用 ABI 的唯一事实来源** |
| `src/util/` | 工具辅助函数 |
| `tests/` | 主机端集成测试（fs、io、memory、net、process、simplefs、sync、syscall） |
| `docs/` | 中英双语文档（`en/` 与 `zh-CN/`） |

---

## 沟通与讨论

- **GitHub Issues**：用于 bug 报告、功能请求、设计讨论。
- **实时交流**：若需要快速问答和协作，可通过邮箱联系：<2557597107@qq.com>。

---

## 代码风格与约定

代码库约 21.5 万行 Rust、600+ 个文件，一致性很重要。

- **格式化：** 运行 `cargo fmt`，门禁把格式视为必检项。
- **文件头：** 每个 `.rs` 文件第 1 行为 `//! <相对路径>`，第 2 行为留空的 `//!`，
  第 3 行起才是实际内容。由 `make verify` 中的 `check_source_headers` 强制
  （见 `scripts/verify.sh`）。
- **Lint：** 运行 `make clippy`（全部目标），关键 lint 视为错误。
- **`no_std`：** 内核代码为 `#![no_std]` 且 `panic = "abort"`。中断/原子路径中
  除内核堆外不得使用 `std` 或动态分配。
- **`unsafe` 纪律：** 保持 `unsafe` 最小化、局部化并加以说明——每个 `unsafe` 块
  都需要 `// SAFETY:` 注释解释其维持的不变量。用户内存必须先验证再访问（绝不做
  投机性拷贝）。
- **错误处理：** 使用 `Result`/`Option`；核心路径避免 `panic!`，优先使用内核既有的
  错误类型而非 `expect`。
- **命名与惯例：** 与周围代码保持一致——同样的注释密度、命名习惯与结构，
  跟着相邻代码的风格走。
- **特性门控：** 可选子系统放在 Cargo 特性后面（见 [README.md](README.md) 特性表）。
- **测试：** 新模块带单元测试；用户可见行为在 `tests/` 下补充集成测试。

---

## 验证门禁

Makefile 提供了多级验证门禁，任何 PR 合并前至少要通过完整门禁：

| 门禁 | 内容 |
|------|------|
| `make verify-p0` | fmt-check + 主机/x86_64 检查 + aarch64 检查 + x86_64/aarch64 构建 + 源文件头覆盖 |
| `make verify-p1` | p0 + 主机单元测试（`test-lib`、并发、快速回归） |
| `make verify-p2` | p1 + 存储/恢复/故障注入回归（`test-storage`） |
| `make verify-p3` | p2 + clippy（全部目标）+ 可选 AArch64 运行时 smoke |

CI 在每次 push 与 PR 上运行 `make check`、`make verify-p0` 与 `make clippy`
（见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)）。

涉及内核行为的改动，还应在受影响架构的 QEMU 中启动 demo-disk shell 验证运行时行为：

```bash
cargo build --features demo-disk          # x86_64
cargo build --features demo-disk --target aarch64-unknown-none
cargo build --features demo-disk --target riscv64gc-unknown-none-elf
```

---

## 新增或修改系统调用

系统调用 ABI 是本内核的兼容性边界，请严格遵守以下规则：

1. **编号只存在于一个地方：** `src/user/shared/abi/syscall.rs`。内核的 `SyscallNumber`
   枚举与所有用户态包装器都编译自同一清单——编号不会漂移。
2. **只增不改。** 绝不重编号、绝不复用已释放的槽位、绝不插入到中间。
3. **稳定性分类：** 槽位 `0–120` 为**稳定**（冻结）。新系统调用先分配到**实验性**
   区间 `121–189`，成熟后再晋升。
4. **版本管理：** 增量改动递增 `SYSCALL_ABI_VERSION_MINOR`，破坏性改动递增
   `SYSCALL_ABI_VERSION_MAJOR`。
5. **注册处理器**：在分发表中注册，并在合适的 `src/kernel/syscall/` 分类下新增
   处理器模块。
6. **验证用户指针**：通过中心 `SYSCALL_POINTER_SPECS` 表校验，绝不无验证地解引用
   用户地址。
7. **添加类型化包装器**：在 `src/user/shared/syscall.rs` 中。
8. **更新文档：** `docs/en/syscall.md` 与 `docs/zh-CN/syscall.md`。
9. **添加测试：** 处理器单元测试；用户可见行为补充 `tests/syscall/` 集成覆盖。

---

## 文档

- 文档为双语：`docs/en/`（英文）与 `docs/zh-CN/`（简体中文）。改动子系统时，
  **两个目录**对应的文档以及 `docs/<lang>/current-status.md` 都要同步更新。
- 保持索引 [`docs/README.md`](docs/README.md) 同步。
- 代码注释请使用英文。

---

## 提交变更

1. **Fork 并建分支。** 从 `main` 建主题分支（如 `fix/ata-timeouts`）。
2. **一个 PR 只做一件事。** 保持 diff 小而可审。
3. **提交信息：** 遵循下方的[提交信息规范](#提交信息规范)——本地由
   `make install-hooks` 与 CI 强制执行。
4. **发起 pull request**，按[PR 模板](.github/PULL_REQUEST_TEMPLATE/pull_request_template.md)
   填写并完成清单。
5. **保持 CI 通过。** 确保 `make check`、`make verify-p0`、`make clippy` 通过
   （行为类改动本地跑完整 `make verify-p3`）。
6. **语言：** Issue 与 PR 可以使用**中文或英文**。

---

## 提交信息规范

Protofire 遵循 Linus Torvalds 在 Linux 内核上贯彻的精神：提交信息是写给未来读者的
一封信，而不是对 diff 的收据。两条准则——保持简短，讲 *为什么* 而不讲 *是什么*
（diff 已经展示了是什么）。

**主题行（第一行）：**

- 祈使句，句首大写：`Fix ATA timeouts on cold boot`，而不是 `fixed`。
- 不超过 72 个字符。
- 结尾不加句号。
- 鼓励 `<类型>:` 前缀（`fix:`、`feat:`、`docs:`、`refactor:`、`chore:`、`test:`）；
  也使用 `Protofire 0.1.x:` 这类版本标记。
- git 自动生成的 `Merge ...` 与 `Revert "..."` 行豁免。

**正文（空一行，然后分段）：**

- 解释**为什么**需要这个改动，以及（如相关）考虑过哪些替代方案。不要复述 diff。
- 一个逻辑一个提交；正文超过几行时，考虑拆分提交。
- 相关时引用 Issue/PR（`Fixes #123`）。

**署名（Attribution trailers）：**

署名分三层，对象各自固定，类别之间永不交叉：

| Trailer | 对象 | 说明 |
|---------|------|------|
| `Signed-off-by:` | 第一位开发者 | **每个提交必写。** DCO 认证：本人创作或经手该改动，并依项目许可证提交。仅限人类——AI 工具绝不能签。`git commit -s` 自动添加。 |
| `Co-authored-by:` | 协作自然人 | 每位人类合著者一条，`Name <email>`。GitHub 在提交列表渲染。 |
| `Co-developed-by:` | 协作自然人 | Linux 式共同开发；每位合著者同时加上自己的 `Signed-off-by:`。 |
| `Assisted-by:` | AI 工具 | `AGENT:MODEL [TOOLS]`——工具没有邮箱，不用邮箱格式。遵循 Linux 内核 coding-assistants 政策，如 `Assisted-by: Claude:claude-3-opus coccinelle sparse`。 |

每个 trailer 的使用对象是固定的：`Co-developed-by:` 指向人，`Assisted-by:` 指向工具，
**两者不能互换**。既不能用 `Assisted-by:` 给人署名，也不能用 `Co-developed-by:` /
`Co-authored-by:` 给工具署名。

一个 AI 辅助提交的完整示例：

    Fix ATA timeouts on cold boot

    Explain why, not what.

    Signed-off-by: Ada Kernelson <ada@example.com>
    Co-authored-by: Bob Lin <bob@example.com>
    Assisted-by: Claude:claude-sonnet-4.5 coccinelle

trailer 行豁免正文 72 字符换行限制，保持单行即可。

**强制执行：** `scripts/hooks/commit-msg` 会在每次 `git commit` 时校验主题、正文与
必填的 `Signed-off-by:` trailer（`make install-hooks` 一次性安装），并在 CI 中对每个
pull request 再次校验。若提交被拒绝，阅读报错信息并 `git commit --amend`——检查快速且精确。

---

## PR 评审流程

1. **自动检查**：CI 会自动运行 `make verify-p0` 和 `make clippy`，必须全部通过。
2. **人工评审**：至少需要 **一名模块维护者** 的批准（见 [MAINTAINERS.md](MAINTAINERS.md)）。
3. **评审时间**：维护者会在 **1 周内** 给出初审意见；若超时，可在 PR 中 @ 核心维护者提醒。
4. **修改与更新**：根据评审意见修改后，用 `git commit --amend` 或新增 fixup commit 均可，最终合并时会 squash。
5. **合并**：由核心维护者或模块维护者合并到 `main` 分支。

---

## 贡献者认可

- 我们珍视每一位贡献者的付出。所有代码贡献者会被列入项目根目录的 [AUTHORS](AUTHORS) 文件。
- 向本项目贡献代码，即表示同意被列入 [AUTHORS](AUTHORS) 文件。该列表会定期从 `git log --format='%aN <%aE>' | sort -u` 生成。
- 贡献不仅限于代码——文档、测试、设计讨论、Bug 报告同样被认可。