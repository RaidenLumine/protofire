# 路线图

[English](./ROADMAP.md) | [简体中文](./ROADMAP.zh-CN.md)

本路线图描述源火内核（Protofire）的前进方向，由项目维护者维护并随工作落地而更新。
里程碑是方向性的而非承诺——优先级会随贡献者的兴趣而变化。

当前状态的权威描述见 [docs/zh-CN/current-status.md](docs/zh-CN/current-status.md)。

---

## 指导原则

1. **ABI 稳定优先。** 系统调用 ABI 是兼容性边界。稳定槽位（0–120）冻结；编号只增不改。
2. **正确性优先于功能。** 崩溃安全、故障注入测试与事务性恢复先于新增功能面。
3. **架构对齐。** 只要硬件允许，功能应同时落地到全部三个目标
   （x86_64、AArch64、RISC-V 64），而非只做某一个。
4. **可验证的进展。** 每个里程碑都以测试、文档和绿色的 `make verify-p3` 收尾。

---

## 近期（未来 3–6 个月）

- **RISC-V 64 → 完整目标支持。** 用户 ABI、交互式演示 shell 与演示负载已在 QEMU
  下的 RISC-V 64 上验证。剩余缺口：MSI/MSI-X（RISC-V AIA）、完整的 PCIe ECAM
  探测、以及更广的设备树驱动覆盖。
- **AArch64 PCIe。** 从基础探测迈向完整 ECAM 支持，对齐 x86_64。
- **USB 主机（xHCI）完善。** 驱动已存在；补齐剩余功能缺口，使 USB 存储与 HID
  端到端可用。
- **HDA 音频面向用户空间。** 把 Intel HD Audio 引擎（当前为 CORB/RIRB + codec
  发现）暴露为可用的用户空间流接口。

## 中期（6–18 个月）

- **更多文件系统的写支持。** 只读驱动——FAT32、NTFS、BtrFS、SquashFS、ISO 9660、
  EROFS——向读写迈进，对齐 ext4 / F2FS / XFS / exFAT。
- **真实硬件上电验证。** 在裸机 x86_64 主板与 AArch64 SoC 上验证，而非仅 QEMU；
  相应加固设备树探测路径。
- **稳定系统调用 ABI。** 随着实验性系统调用（121–189）成熟晋升为稳定；在
  只增不删规则下为槽位 190 以上预留空间。
- **用户空间 VIRGL 3D 演示。** 交付一个驱动 virtio-gpu VIRGL 接口（#181–189）
  到扫描输出的演示渲染器。
- **模糊测试与健壮性。** 为 ELF 加载器、文件系统镜像解析器、网络包解析器与
  LUKS2 头增加 cargo-fuzz 式目标；扩展现有 SimpleFs 崩溃矩阵。
- **性能验证。** 多核宿主下的 SMP 负载均衡、NUMA 节点压力测试与网络吞吐基准。

## 长期（1–3 年）

- **更广的 POSIX 表面。** 把面向文件的用户空间 ABI 增长为实用的 UNIX 子集；
  演进 shell 与运行时（`src/user/shared/`）。
- **用户空间生态。** 为演示盘提供 init/服务管理器与轻量包管理方案。
- **形式化验证种子。** 为 TLSF 分配器、调度器不变量与文件系统 undo-log——这些最怕
  微妙 bug 的子系统——引入基于性质的测试（proptest）与模型检查。
- **安全加固专项。** 默认拒绝的 MAC 策略、审计工具与完整的攻击面审查。
- **可复现发布。** 带标记的 1.x 发布，为三种架构产出可复现的 ISO/磁盘镜像与签名工件。
- **治理。** 扩充维护者团队，为大型特性采用 RFC 式设计文档，并在
  [MAINTAINERS.md](MAINTAINERS.zh-CN.md) 中固化评审流程。

---

## 如何参与

挑一个里程碑，开 Issue 认领，并阅读 [CONTRIBUTING.md](CONTRIBUTING.zh-CN.md)。
代码中的已知缺口在 [docs/zh-CN/current-status.md](docs/zh-CN/current-status.md)
中跟踪；任何带 `good first issue` 标签的任务都是很好的起点。
