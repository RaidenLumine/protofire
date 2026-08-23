# 内核架构

## 设计理念

这是一个从头编写的业余操作系统内核，使用 Rust 语言，目标架构为 x86_64、AArch64 和 RISC-V 64。它完全在 `no_std` 环境（无 libc，无标准库）下运行于裸机之上。该内核是**宏内核**——所有核心子系统（内存管理、文件系统、调度器、驱动程序、网络栈、系统调用分发）都在一个单一的特权地址空间中运行，不存在微内核 IPC 边界。

关键设计目标：
- **尽可能利用 Rust 的安全性**：内核仅在 MMIO、内联汇编和指针级上下文切换机制中使用 `unsafe`。页表遍历、文件系统操作和网络协议解析均为安全的 Rust 代码。
- **单一地址空间 ELF 加载器**：ring-3（用户）程序是自包含的 ELF 文件，加载到每个进程各自的页表中。无需动态链接，无共享库——每个程序都是独立的二进制文件。
- **协作式线程调度**：调度器对内核和用户线程执行简单的轮转调度。调度器核心中没有抢占定时器；线程通过 `yield_current()` 或阻塞 I/O 显式让出 CPU。定时器中断递增一个滴答计数器，并通过 `on_timer_tick_with_preemption` 驱动调度器时间片分配。
- **面向文件的 ABI**：系统调用接口基于类似 POSIX 的操作（open、read、write、close、ioctl、mmap、fork、exec、wait）建模，具有一个平坦的 100 槽位分发表。
- **最小化平台假设**：启动信息通过 Multiboot2（x86_64）或扁平设备树 FDT 指针（AArch64、RISC-V）接收。PCI/ACPI 表的遍历在早期内存初始化之后进行。

该内核在 `src/` 目录树中跨越 **460+ 个源文件**，约 **210,000+ 行 Rust 代码**。

---

## 启动流程

```
                 x86_64                              AArch64 / RISC-V
       ┌─────────────────────┐          ┌──────────────────────────┐
       │  GRUB / 引导加载程序 │          │  QEMU virt / 固件       │
       │  Multiboot2 头部    │          │  DTB 指针在 x0/a0 寄存器│
       └────────┬────────────┘          └───────────┬──────────────┘
                │                                    │
                ▼                                    ▼
       ┌─────────────────────┐          ┌──────────────────────────┐
       │ arch/x86_64/boot.asm│          │ arch/aarch64/boot.S      │
       │ 32 位入口点，       │          │ 或 arch/riscv64/boot.S   │
       │ 切换到长模式        │          │ 设置栈，跳转到           │
       │ 调用 kernel_entry() │          │ kernel_entry_*()         │
       └────────┬────────────┘          └───────────┬──────────────┘
                │                                    │
                ▼                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │ main.rs: kernel_entry*() -> boot_kernel(BootInfo)      │
       │   - 保存交接地址以供后续 SMP/ACPI 使用                  │
       │   - 打印启动横幅                                        │
       │   - 解析 FDT（aarch64/riscv64）或存储 multiboot 信息    │
       │   - 构造 Kernel::new()                                  │
       │   - 调用 Kernel::init()                                 │
       └────────────────────────┬───────────────────────────────┘
                                │
                                ▼
       ┌────────────────────────────────────────────────────────┐
       │ Kernel::init()  (src/kernel/mod.rs)                    │
       │                                                        │
       │   1. memory::init()           TLSF 堆分配器            │
       │   2. prepare_arch_paging()    切换到内核页表            │
       │   3. init_numa()              NUMA 拓扑检测            │
       │   4. console::init_global()                            │
       │   5. drivers::init()          探测 VirtIO（块设备，    │
       │                               网络设备，输入，GPU）    │
       │   6. fs::init_with_boot_disk()  构建/挂载启动 VFS      │
       │   7. maybe_init_swap()        磁盘交换检测             │
       │   8. PCI/PCIe 枚举            (x86_64 + AArch64)       │
       │   7. 网络栈初始化             DHCP 地址获取            │
       │   8. 卷恢复                   检查并修复挂载点         │
       │   9. user::init_user_database()                        │
       │  10. arch::interrupt_controller::init()                │
       │  11. arch::timer::init()                               │
       │  12. 每 CPU 数据 + SMP AP 启动  (x86_64)              │
       │  13. syscall::Table::init()    填充分发表              │
       │  14. spawn_init_program()     加载 /system/init.elf    │
       │  15. spawn_system_programs()  (demo-disk 特性)         │
       │  16. scheduler.start_idle_process()                    │
       └────────────────────────┬───────────────────────────────┘
                                │
                                ▼
       ┌────────────────────────────────────────────────────────┐
       │ Kernel::run()  (永不返回)                              │
       │   loop {                                               │
       │     scheduler.process_deferred_dying()                 │
       │     arch::interrupts::disable()                        │
       │     scheduler.schedule()                               │
       │     arch::instructions::idle()                         │
       │   }                                                    │
       └────────────────────────────────────────────────────────┘
```

各架构的 `kernel_entry` 函数如下：

- **x86_64**：`src/main.rs` 中的 `kernel_entry(multiboot_magic, multiboot_info)`，由 `src/arch/x86_64/boot.asm` 调用。通过 `arch::boot::from_x86_64_multiboot2()` 解析。
- **AArch64**：`src/main.rs` 中的 `kernel_entry_aarch64(device_tree_blob)`，由 `src/arch/aarch64/boot.S` 调用。通过 `arch::boot::from_aarch64_qemu_direct()` 解析。
- **RISC-V**：`src/main.rs` 中的 `kernel_entry_riscv64(device_tree_blob)`，由 `src/arch/riscv64/boot.S` 调用。通过 `arch::boot::from_riscv64_qemu_direct()` 解析。

在 AArch64 和 RISC-V 上，串行控制器在启动横幅之前初始化；在 x86_64 上，UART 在 `X86_64::init_early()` 内部设置。

---

## 子系统依赖图

```
kernel::Kernel
    ├── memory::MemoryManager        (TLSF 堆，帧分配器，页表)
    │     └── memory::paging         (架构无关的页表接口)
    ├── process::Scheduler           (协作式轮转调度，线程生命周期)
    │     ├── process::Thread        (每线程上下文，状态机)
    │     ├── process::Process       (地址空间，文件描述符表，安全令牌)
    │     └── process::Context       (架构寄存器保存区)
    ├── fs::FileSystem               (VFS + SimpleFS)
    │     └── fs::simplefs           (磁盘布局，两阶段提交)
    ├── drivers::DriverManager       (VirtIO 块/网络/输入/GPU，PCI 探测)
    │     └── device                 (控制台，键盘，null，zero，串行)
    ├── syscall::Table               (100 槽位分发表)
    │     ├── syscall::process_launch
    │     ├── syscall::process_management
    │     ├── syscall::fs
    │     ├── syscall::net
    │     └── syscall::ipc
    ├── network                      (TCP/UDP/DHCP/DNS，原始套接字)
    ├── shm                          (共享内存区域)
    ├── topology                     (NUMA 拓扑，每节点分配器)
    ├── smp                          (SMP AP 发现与启动，x86_64)
    ├── percpu                       (每 CPU 调度器/APIC 数据，numa_node_id)
    ├── sync                         (Mutex，SpinLock，Condvar)
    ├── crypto                       (签名密钥验证)
    └── user                         (用户数据库，程序加载器)

arch                                 (按目标架构分发的抽象层)
    ├── boot                         (BootInfo，multiboot/FDT 解析)
    ├── mmu                          (页表准备/激活/检查)
    ├── trap                         (异常向量设置)
    ├── interrupt_controller         (APIC，GICv2，PLIC)
    ├── timer                        (PIT/HPET，通用定时器，SBI 定时器)
    ├── syscall_trap                 (系统调用入口内联汇编)
    └── {x86_64, aarch64, riscv64}   (各架构：串行，上下文切换，分页)
```

`src/kernel/mod.rs` 中的 `Kernel` 结构体持有顶层子系统：

```rust
pub struct Kernel {
    memory: MemoryManager,
    scheduler: Scheduler,
    fs: Mutex<FileSystem>,
    drivers: DriverManager,
    syscall_table: syscall::Table,
    initialized: bool,
}
```

每个子系统在初始化后被安装到全局槽位中（例如 `memory::install_global_unchecked`、`syscall::install_global_unchecked`、`fs::install_global_unchecked`），以便中断处理程序和工作线程无需借用 `Kernel` 对象即可访问它们。

---

## 内存布局

### 物理内存

物理内存通过 Multiboot2 内存映射（x86_64）或 FDT 的 `/memory` 节点（AArch64、RISC-V）发现。帧分配器（`memory::frame`）使用位图分配器管理 4 KiB 页帧，并有一个独立的 TLSF 堆用于内核自身的分配。

### 虚拟内存布局（x86_64 示例）

```
0x0000_0000_0000_0000  ┌──────────────────────┐
                       │  用户空间（PML4       │  用户 ELF 段，
                       │  表项 0..255）        │  栈，守护页
                       │                       │
                       │  [用户栈]             │
                       │  [守护页]             │
                       │  [ELF 段]             │
0x0000_8000_0000_0000  ├──────────────────────┤
                       │  （空洞 / 规范        │
                       │   地址断点）           │
0xFFFF_8000_0000_0000  ├──────────────────────┤
                       │  内核空间（PML4       │  内核映像，
                       │  表项 256..511）      │  堆，页表
                       │                       │
                       │  [内核文本/数据段]    │
                       │  [TLSF 堆]            │
                       │  [页表页]             │
                       │  [帧分配器位图]       │
0xFFFF_FFFF_FFFF_FFFF  └──────────────────────┘
```

在 AArch64 和 RISC-V 上，分区遵循相同原则，但使用各架构特定的虚拟地址位宽（48 位或 39 位）。

### 内核栈与守护页

每个内核线程都有一个由物理帧支持的专用栈区域。每个栈下方是一个未映射的守护页，可在栈溢出时触发页错误。守护页在线程创建期间（`process/thread.rs`）分配并映射，详见[内核栈守护页](../en/memory.md#kernel-stack-guard-page)概述。这适用于内核线程和用户线程的内核栈。

### 堆

内核堆使用在 `memory/heap/` 中实现的 **TLSF（两级分离适配）** 分配器。它在 `Kernel::init()` 早期由 `MemoryManager::init()` 初始化，该函数从帧分配器中划分出一块区域并播种 TLSF 池。此后，`extern crate alloc` 提供 `Box`、`Vec`、`Arc`、`String` 等类型。

选择 TLSF 是因为它提供 O(1) 的分配/释放操作，且碎片化程度有限——这对于一个不能依赖用户空间 malloc 的内核来说至关重要。

---

## 构建系统

### Makefile 目标

顶层 `Makefile` 提供：

| 目标 | 描述 |
|--------|-------------|
| `build` | 构建 x86_64 内核 ELF（`x86_64-unknown-none`） |
| `build-aarch64` | 构建 AArch64 内核 ELF（`aarch64-unknown-none`） |
| `build-riscv64` | 构建 RISC-V 内核 ELF（`riscv64gc-unknown-none-elf`） |
| `run` | 在 QEMU q35 上启动 x86_64（无磁盘，串行控制台） |
| `run-aarch64` | 在 QEMU virt 上启动 AArch64 |
| `run-riscv64` | 在 QEMU virt 上启动 RISC-V |
| `check` | 宿主机 + 裸机类型检查 |
| `check-aarch64` / `check-riscv64` | 交叉目标类型检查 |
| `test` | 宿主机端单元测试 + 集成测试（使用 `demo-disk`） |
| `verify-p{0,1,2,3}` | CI 验证门禁（范围递增） |
| `fmt` / `fmt-check` | Rust 格式化 |
| `clippy` | 代码检查 |

QEMU 调用会传递一个 VirtIO 网络设备用于网络栈测试，并使用 `-serial stdio` 进行控制台输出。

### 特性标志

定义在 `Cargo.toml` 中：

| 特性 | 用途 |
|---------|---------|
| `demo-disk` | 启用内存中的演示 SimpleFS 卷、演示工作线程和演示用户程序 |
| `fs_profiler` | 文件系统 I/O 性能分析计数器 |
| `net_profiler` | 网络栈性能分析计数器 |
| `alloc_profiler` | 堆分配器性能分析计数器 |
| `fault_profiler` | 页错误性能分析计数器 |
| `educational_networking` | 在网络代码中启用教学文档 |

默认特性集为空。大多数集成测试使用 `--features demo-disk` 来填充启动文件系统。

### 链接脚本与 `build.rs`

`build.rs` 脚本（仓库根目录下的 `build.rs`）根据架构选择对应的链接脚本：

| 目标 | 链接脚本 |
|--------|---------------|
| `x86_64-unknown-none` | `linker.ld` |
| `aarch64-unknown-none` | `linker-aarch64.ld` |
| `riscv64gc-unknown-none-elf` | `linker-riscv64.ld` |

演示系统卷通过内核的 `src/kernel/fs/demo.rs` 构建；启动链路沿用 `/apps/current → /apps/catalog → /apps/packages` 布局，由 `crate::user::program::launch_reference` 负责解析。

Ring-3 ELF 负载的构建器（`elf_builder`）已并入内核的 `src/user/demo/`；演示卷所需的占位 ELF 以内联常量形式提供在 `src/kernel/fs/demo.rs` 中。

### CI 验证门禁

`scripts/verify.sh` 脚本按层级执行检查：

- **P0**：格式检查 + 宿主机/x86_64/AArch64 构建检查 + 头文件覆盖率
- **P1**：P0 加上快速并发/路径/I-O/ABI 回归测试
- **P2**（默认）：P1 加上存储/恢复/错误矩阵回归测试
- **P3**：P2 加上 clippy 和可选的 AArch64 运行时冒烟测试（`make check-aarch64-runtime`）

---

## ABI 稳定性策略

- **系统调用号是稳定的**。100 槽位分发表（`src/kernel/syscall/table.rs` 中的 `syscall::Table`）为操作分配了固定的编号（open、read、write、close、ioctl、mmap、fork、exec、wait 等）。新增系统调用必须使用之前未分配的槽位。
- **`src/user/shared/` 是 ABI 边界**。该模块定义了 ABI 记录类型（`FileStat`、`DirectoryEntryRecord`、`IoVec` 等）和系统调用包装函数，位于内核 crate 内。对其公开类型的修改需要协调所有使用方。
- 内核版本号为 `2026.7.1`（日历版本号）。不同主版本之间不提供稳定性保证；ring-3 ELF 随演示盘分发，并与内核一起重新构建。

---

## 关键架构决策

### 宏内核与协作式线程调度

整个内核在单个特权级（ring 0 / EL1 / S-mode）和单个虚拟地址空间中运行。没有独立的"内核服务器"进程。驱动程序、文件系统、网络栈和系统调用分发器都链接到同一个二进制文件中，彼此直接调用。

线程调度默认是**协作式**的：`schedule()` 在主循环、阻塞 I/O 路径以及 `yield_current()` 中显式调用。定时器中断处理程序（`on_timer_tick_with_preemption`）可以将当前线程标记为可抢占，但实际的上下文切换仍然发生在主循环的 `schedule()` 调用中。这种设计避免了调度器中的重入问题，并使上下文切换路径具有确定性。

### Ring-3 程序作为自包含 ELF

用户程序（`/system/init.elf`、shell、演示负载）是存储在启动文件系统上的独立 ELF 二进制文件。内核的程序加载器（`src/user/program/`）解析 ELF 头部，将段映射到用户地址空间，设置带有守护页的栈，并通过 `iretq` / `eret` / `sret` 指令返回到用户模式。没有动态链接器。

### 通过 `src/arch/` 实现架构抽象

`src/arch/mod.rs` 模块定义了 `Arch` 特质（`init_early`、`halt`、`reboot`），并使用条件编译委托到：

- `src/arch/x86_64/` -- GDT、IDT、分页（4 级）、APIC/IOAPIC、端口 I/O、MSI、UART 16550
- `src/arch/aarch64/` -- 陷阱向量（trap.S）、MMU（4 级）、GICv2、PL011 UART、FDT 解析、PCIe ECAM
- `src/arch/riscv64/` -- 陷阱向量（trap.S）、MMU（Sv39）、PLIC、NS16550A UART、SBI/Sstc 定时器、FDT 解析

`mmu` 和 `interrupt_controller` 外观模块重新导出各架构的实现：

```rust
// src/arch/mmu.rs
#[cfg(target_arch = "x86_64")]
pub use super::x86_64::paging::*;
#[cfg(target_arch = "aarch64")]
pub use super::aarch64::mmu::*;
```

这使得 `src/kernel/` 中的代码可以调用 `arch::mmu::prepare_runtime_kernel_page_tables()`，而无需关心目标架构。

### 卷恢复

每次启动时，内核在每个已挂载的卷上（排除合成根卷）运行 `recover_volumes()`。它调用 `fs.check_and_repair_volume()`，该函数运行 SimpleFS 一致性检查器：检查孤立数据块、中断的两阶段提交、校验和失败以及暂存目录孤儿。`VolumeRecoverySummary` 存储在全局位置，可在运行时通过 `SystemHealth` 系统调用查询。

### SMP 支持

目前仅支持 **x86_64**（AArch64 和 RISC-V 计划中）。BSP 在早期启动期间通过 ACPI MADT 发现 AP（在页表切换之前，身份映射仍然有效时），为 AP 跳板保存启动 CR3，然后在每 CPU 数据初始化后启动 AP。每个 CPU 都有自己的调度器实例，记录在每 CPU 调度器表中。详见 `src/kernel/smp/` 和 `src/arch/x86_64/ap_trampoline.asm`。

### NUMA 支持

内核支持最多 8 个节点（`MAX_NODES = 8`）的 NUMA 拓扑。
发现由 `init_numa()` 在启动早期执行（页表准备之后，设备驱动程序之前）。
拓扑子系统（`src/kernel/topology.rs`）将发现的 CPU 核心和内存范围分类到
NUMA 节点中。Per-CPU 数据包括一个 `numa_node_id: u8` 字段，用于
CPU 到节点亲和性查找。帧分配器维护一个包含 8 个每节点分配器的数组，
调度器的工作窃取算法优先选择同一 NUMA 节点上的受害者 CPU。
当未检测到 NUMA 硬件时（常见情况），默认的单节点拓扑将所有 CPU
映射到节点 0。

---

## 相关文档

### 子系统概述（`docs/en/`）

| 文档 | 描述 |
|----------|-------------|
| [`docs/en/README.md`](../en/README.md) | 架构概述、子系统依赖图、内存布局、构建系统 |
| [`docs/en/boot.md`](../en/boot.md) | 启动流程、Kernel::init() 分步说明、SMP |
| [`docs/en/memory.md`](../en/memory.md) | 物理/虚拟内存管理、TLSF 堆、页表 |
| [`docs/en/process.md`](../en/process.md) | 进程模型、线程状态、调度器、安全令牌 |
| [`docs/en/filesystem.md`](../en/filesystem.md) | VFS 层、SimpleFS 磁盘格式、两阶段提交 |
| [`docs/en/network.md`](../en/network.md) | 网络栈、DHCP、TCP/UDP、DNS |
| [`docs/en/syscall.md`](../en/syscall.md) | 系统调用分发表、ABI 目录 |
| [`docs/en/shared-user-runtime.md`](../en/shared-user-runtime.md) | 共享 ABI 类型和系统调用包装函数（`src/user/shared/` 模块） |

### 内核开发者参考（`docs/kernel/`）

| 文档 | 描述 |
|----------|-------------|
| [`docs/kernel/boot.md`](../kernel/boot.md) | 各架构入口、PS/2 探测、文件系统初始化、文件映射 |
| [`docs/kernel/memory.md`](../kernel/memory.md) | 帧分配器内部实现、TLSF 布局、页表操作、交换 |
| [`docs/kernel/process.md`](../kernel/process.md) | 调度器核心类型、线程生命周期、进程组、信号 |
| [`docs/kernel/filesystem.md`](../kernel/filesystem.md) | VFS 特质方法、文件系统驱动表、文件 I/O 内部实现 |
| [`docs/kernel/network.md`](../kernel/network.md) | **分层架构、协议文件、套接字选项、轮询就绪** |
| [`docs/kernel/syscall.md`](../kernel/syscall.md) | `SyscallNumber` 枚举、`SYSCALL_REGISTRY`、指针规范 |
| [`docs/en/shared-user-runtime.md`](../en/shared-user-runtime.md) | 系统调用包装约定、分发内部实现、模块映射 |
