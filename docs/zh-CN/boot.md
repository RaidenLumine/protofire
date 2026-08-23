# 内核启动流程

本文档描述了内核从固件/引导加载程序交接开始，经过冷启动序列直至进入空闲循环的完整过程，涵盖所有三个支持的架构（x86_64、AArch64、RISC-V 64）以及 `src/kernel/mod.rs` 中与架构无关的初始化。

---

## 1. 入口向量（各架构汇编代码）

Rust 入口点永远不会被直接调用——每个架构都有各自的汇编存根（stub），由引导加载程序/固件跳转至该处。

### 1.1 x86_64 -- `src/arch/x86_64/boot.asm`

```
GRUB / PVH ──> _start (32-bit) ──> setup_page_tables ──> enable_long_mode ──> long_mode_start ──> kernel_entry()
```

1. **Multiboot2 头部**位于 `.multiboot_header`（魔数 `0xE85250D6`，架构 0，校验和）。同时包含一个 **Xen ELF note**（类型 18 = `XEN_ELFNOTE_PHYS32_ENTRY`），用于通过 PVH 协议使用 QEMU `-kernel` 直接引导。
2. `_start`（32 位）：将 EAX（魔数）和 EBX（信息）保存到 BSS 段中的 `multiboot_magic` / `multiboot_info`，设置一个 64 KiB 的引导栈（`boot_stack`）。
3. `setup_page_tables`：构建四级页表层次结构：
   - `boot_pml4` 指向 `boot_pdpt`
   - `boot_pdpt` 指向 `boot_pd`
   - `boot_pd` 使用 2 MiB 大页（PS=1，RW+Present）对前 1 GiB 进行恒等映射
4. `enable_long_mode`：加载 `boot_pml4` → CR3，设置 PAE（CR4.PAE=5），启用 **LME**（IA32_EFER.LME=8）和 **NXE**（IA32_EFER.NXE=11），然后设置 PG（CR0.PG=31）。
5. `long_mode_start`（64 位）：使用 64 位 GDT（代码段偏移 0x08，数据段偏移 0x10）重载段寄存器，加载 64 位栈指针，然后调用 `kernel_entry(multiboot_magic, multiboot_info)`。

### 1.2 AArch64 -- `src/arch/aarch64/boot.S`

```
QEMU virt ──> _start (EL1) ──> BSS clear ──> kernel_entry_aarch64(dtb)
```

1. 读取 `MPIDR_EL1` 并提取低 8 位（CPU 亲和性）。
2. **非零号 CPU 在 `wfe` 循环中自旋**（spin-table 模式）。只有 CPU 0（BSP）继续执行。
3. BSP：将 SP 设置为 `__boot_stack_top`，清除 BSS（`__bss_start` .. `__bss_end`），然后调用 `kernel_entry_aarch64(device_tree_blob)`。
4. DTB 地址通过 x0 传入（QEMU 约定）并原样传递。

### 1.3 RISC-V 64 -- `src/arch/riscv64/boot.S`

```
OpenSBI ──> _start (S-mode) ──> BSS clear ──> kernel_entry_riscv64(dtb)
```

1. 进入 **S-mode**（监管者模式），OpenSBI 已过滤掉次级 hart——只有 hart 0 到达 `_start`。
2. 将 FDT 指针（来自 OpenSBI 约定的 a1）保存到被调用者保存的寄存器 `s0`。
3. 将 SP 设置为 `__boot_stack_top`，清除 BSS，将 FDT 指针传入 a0，然后调用 `kernel_entry_riscv64(device_tree_blob)`。

---

## 2. 引导信息交接 -- `src/arch/boot.rs`

每个汇编入口点调用一个 Rust 函数，将引导加载程序参数封装到 `BootInfo` 结构体中：

```rust
pub struct BootInfo {
    architecture: &'static str,
    protocol:     BootProtocol,   // Multiboot2 | QemuDirect | Unknown
    loader_magic: u32,
    handoff_address: usize,
}
```

| 入口点 | 构造函数 | 协议 |
|---|---|---|
| `kernel_entry` | `from_x86_64_multiboot2(magic, info)` | `Multiboot2` |
| `kernel_entry_aarch64` | `from_aarch64_qemu_direct(dtb)` | `QemuDirect` |
| `kernel_entry_riscv64` | `from_riscv64_qemu_direct(dtb)` | `QemuDirect` |

交接地址通过 `store_handoff_address()` 保存，供启动后期的使用者（SMP AP 唤醒、ACPI 表访问）使用。

---

## 3. 架构无关的引导 -- `src/main.rs`

所有三个入口点汇聚到同一个 `boot_kernel()` 函数：

```
boot_kernel(BootInfo)
  ├── store_handoff_address()
  ├── util::debug::init()
  ├── arch::serial::init()           # aarch64 / riscv64 专属
  ├── print_banner()
  ├── FDT 解析 (aarch64 / riscv64)   # arch::fdt::parse_fdt()
  ├── RTC 初始化 (aarch64 / riscv64)
  ├── Kernel::new()
  ├── Kernel::init()
  └── Kernel::run()                  # 永不返回
```

### 3.1 FDT 解析（aarch64 / riscv64）

在没有 Multiboot2 协议的架构上，交接地址处的扁平设备树（FDT）由 `arch::fdt::parse_fdt()` 解析。得到的 `PlatformInfo` 存储了以下设备的发现地址：

- UART（串口控制台）
- 中断控制器（GIC）
- 定时器
- VirtIO MMIO 传输层
- RTC（AArch64 上为 PL031，RISC-V 上为 Goldfish）

如果 x0 中的 DTB 地址为零（AArch64 QEMU 边界情况），则会在前 512 MiB 范围内以 2 MiB 间隔进行 RAM 扫描，搜索 FDT 魔数（`0xd00dfeed`）作为回退方案。

### 3.2 架构早期初始化

`boot_kernel()` 返回后，每个架构调用 `Arch::init_early()`：

- **x86_64**：串口初始化，GDT/IDT 设置，异常处理程序。
- **AArch64**：`enable_fp_simd()`（设置 CPACR_EL1.FPEN 以允许 EL0/EL1 访问），陷阱向量表初始化，串口初始化。
- **RISC-V 64**：串口初始化，陷阱处理程序初始化。

---

## 4. 内核初始化 -- `src/kernel/mod.rs`

`Kernel::init()` 运行完整的子系统初始化流水线：

```
Kernel::init()
  ├── self.memory.init()                          # MMU + 堆引导
  ├── memory::install_global_unchecked()
  ├── SMP AP 发现 (x86_64)                        # ACPI MADT -> LAPIC ID
  ├── prepare_arch_paging()                       # 运行时内核页表
  ├── init_numa()                                 # NUMA 拓扑检测
  ├── console::init_global()                      # 打印基础设施
  ├── self.drivers.init()                         # 设备发现（包括 virtio-gpu）
  ├── self.fs.lock().init_with_boot_disk()        # 根文件系统挂载
  ├── maybe_init_swap()                           # 探测块设备上的交换签名
  ├── PCI 枚举 (x86_64)                           # pci::pci_enumerate_buses()
  ├── 网络栈初始化                                 # DHCP / IPv4
  ├── 卷恢复                                       # check_and_repair_volume()
  ├── user::init_user_database()
  ├── arch::interrupt_controller::init()          # PIC / GIC 初始化
  ├── arch::timer::init()                         # 定时器中断
  ├── 每 CPU 数据初始化 (x86_64)                   # percpu::init_bsp()
  ├── SMP AP 唤醒 (x86_64)                         # smp::bring_up_aps()
  ├── self.syscall_table.init()                   # 系统调用分发表
  ├── spawn_init_program()                        # /system/init.elf
  ├── spawn_system_programs()                     # /system/rc.d/*.toml
  └── self.scheduler.start_idle_process()
```

### 4.1 MMU 初始化与堆

`self.memory.init()` 初始化 `MemoryManager`，其功能如下：

1. 从 Multiboot2 内存映射（x86_64）或 FDT `/memory` 节点（AArch64 / RISC-V）检测物理 RAM 总量。
2. 在可用的物理页帧上初始化帧分配器。
3. 在内核虚拟地址范围内分配内核堆。

### 4.2 运行时页表

`prepare_arch_paging()`（通过 cfg 按架构调用）构建并激活一组新的内核页表，依次调用 `arch::mmu::prepare_runtime_kernel_page_tables()` 和 `arch::mmu::activate_prepared_runtime_kernel_page_tables()`。

在 x86_64 上，切换前会保存引导 CR3，以便 AP 跳板（trampoline）在唤醒期间使用恒等映射的引导页表。激活后，自我检查（`active_runtime_kernel_page_table_check`）验证 RIP、RSP 和堆均以预期的权限被映射。

### 4.3 SMP AP 发现与唤醒（x86_64）

**发现**（`src/kernel/smp/discovery.rs`）：解析 ACPI MADT 表（通过 Multiboot2 RSDP 标签）以枚举 LAPIC ID。BSP 记录自身的 LAPIC ID，发现的 AP ID 存储为"早期 AP"。

**唤醒**（`src/kernel/smp/bringup.rs`）：

```
bring_up_aps(aps)
  ├── 复制跳板代码 (ap_trampoline_start..ap_trampoline_end) 到 0x8000
  └── 对每个 AP：
        ├── 分配 PerCpuData + TSS
        ├── 在 0x9000 写入跳板数据页：
        │     boot_cr3 | stack_top | entry_point | cpu_id | lapic_id
        │     percpu_base | ap_started_flag | runtime_cr3
        ├── 通过 LAPIC ICR 发送 INIT-SIPI-SIPI
        └── 等待 ap_started_flag
```

AP 跳板代码（`src/arch/x86_64/ap_trampoline.asm`）将 AP 从 16 位实模式经过保护模式转换到 64 位长模式，切换到运行时 CR3，然后跳转到 `ap_entry()`，该函数将 GS 基址设置为每 CPU 数据，配置本地 APIC，并进入空闲循环。

### 4.4 每 CPU 数据

`struct PerCpuData`（`src/kernel/percpu.rs`，64 字节缓存行对齐）：

| 偏移 | 字段 | 描述 |
|---|---|---|
| 0 | `cpu_id: u32` | 逻辑 CPU ID |
| 4 | `lapic_id: u8` | 本地 APIC ID |
| 8 | `scheduler: *mut Scheduler` | CPU 调度器指针（GS 快速路径） |
| 16 | `tss: *mut u8` | 任务状态段指针 |
| 24 | `tlb_generation_seen: u64` | TLB 失效代次 |
| 32 | `context_switches: u64` | 饱和计数器 |

在 x86_64 上，每 CPU 数据通过 GS 段基址（IA32_GS_BASE MSR，`0xC0000101`）访问。`scheduler` 字段使用 `mov reg, gs:[8]` 加载——偏移量在编译时检查。

在 AArch64 上，`TPIDR_EL1` 承担相同的作用。

---

## 5. 初始程序的生成

### 5.1 命令行解析

`arch::boot::multiboot2_command_line()` 遍历 Multiboot2 信息标签以提取内核命令行。`init_path_from_command_line()` 在空白分隔的令牌中扫描 `init=<path>`。

在 aarch64 / riscv64 上没有 Multiboot2 命令行，因此始终使用默认路径。

### 5.2 默认 Init 路径

```rust
const DEFAULT_INIT_PATH: &str = "/system/init.elf";
```

### 5.3 `spawn_init_program()`（`src/kernel/mod.rs:547`）

```
spawn_init_program(init_path)
  ├── fs.lock()
  ├── program::load_from_filesystem(&fs, "/", init_path)
  │     └── 解析 ELF，将段加载到新的地址空间
  ├── program::launch_loaded_program_with_security_token(
  │       &scheduler, loaded, SecurityToken::guest(), start_suspended=false)
  └── 成功时记录 PID，失败时记录错误
```

`SecurityToken::guest()` 分配最低特权级别，将 init 进程限制为来宾范围内的操作。init 程序永远不会以挂起状态启动。

如果 ELF 缺失（无引导磁盘或未安装发行版），内核会打印诊断信息并继续运行——系统仅以内核工作线程和空闲进程运行。

### 5.4 `spawn_system_programs()`（`src/kernel/mod.rs:415`）

服务定义从 `/system/rc.d/` 中的 TOML 文件通过 `service::load_services_from_fs()` 加载。

每个 `ServiceDefinition` 都有一个 `kind`：

- `ServiceKind::KernelThread`——通过解析 `WORKER_REGISTRY` 表中的入口名称启动的内核工作线程。
- `ServiceKind::UserProgram`——从某个路径加载的 ELF 二进制文件，作为用户进程生成。

当没有 rc.d 文件时（例如演示磁盘配置），嵌入式回退方案通过 `spawn_embedded_default_services()` 生成演示内核工作者（`kworker-a`、`kworker-b`、`demo_syscall_fs_worker`）和用户程序（shell、I/O 演示、故障演示）。

---

## 6. 主循环

所有初始化完成后，`Kernel::run()` 进入调度器循环：

```rust
loop {
    self.scheduler.process_deferred_dying();
    arch::interrupts::disable();
    self.scheduler.schedule();
    arch::instructions::idle();
}
```

在进入此循环之前，空闲进程已启动。调度器选择下一个可运行的线程并切换上下文到该线程。当没有线程就绪时，CPU 通过架构特定的 `idle()` 函数在启用中断的情况下执行空闲指令（`hlt` / `wfi`）。

---

## 7. 构建目标与 ISO 创建

### 7.1 内核构建

| Make 目标 | 三元组 | ELF 输出 |
|---|---|---|
| `make build` | `x86_64-unknown-none` | `target/x86_64-unknown-none/debug|release/protofire` |
| `make build-aarch64` | `aarch64-unknown-none` | `target/aarch64-unknown-none/debug|release/protofire` |
| `make build-riscv64` | `riscv64gc-unknown-none-elf` | `target/riscv64gc-unknown-none-elf/debug|release/protofire` |

### 7.2 QEMU 直接引导

`make run` / `make run-aarch64` / `make run-riscv64` 目标通过 QEMU 的 `-kernel` 标志直接传递 ELF 文件。无需引导加载程序映像。

- x86_64 使用 `-machine q35`，搭配 `virtio-net-pci`。
- AArch64 使用 `-machine virt`，搭配 `virtio-net-device`。
- RISC-V 64 使用 `-machine virt`，搭配 `virtio-net-device`。

### 7.3 GRUB ISO（发行版级别）

ISO 创建是一个发行版级别目标。内核通过 `grub-mkrescue`（需要 `xorriso`）打包成 GRUB 可引导 ISO。GRUB 配置通过 Multiboot2 命令行传递 `init=/system/init.elf`。ISO 引导流程如下：

```
UEFI/BIOS ──> GRUB ──> Multiboot2 ──> _start ──> kernel_entry() ──> boot_kernel()
```

### 7.4 工具链检查

`make doctor`（通过 `scripts/doctor.sh`）验证除 Rust 工具链外，`grub-mkrescue` 和 `xorriso` 是否存在。

---

## 启动序列图（x86_64）

```
Firmware
   │
   ▼
GRUB (Multiboot2)       or      QEMU -kernel (PVH ELF note)
   │                                  │
   └──────────┬───────────────────────┘
              │
              ▼
       _start (32-bit)
              │
              ├── 保存 multiboot_magic / multiboot_info
              ├── setup_page_tables   (PML4 → PDPT → PD: 1 GiB 恒等映射)
              ├── enable_long_mode    (PAE | LME | NXE | PG)
              │
              ▼
       long_mode_start (64-bit)
              │
              ├── 重载 GDT，设置 SS=0x10
              ├── 加载 64 位 RSP
              │
              ▼
       kernel_entry(magic, info)
              │
              ▼
       boot_kernel(BootInfo)
              │
              ├── arch::boot::store_handoff_address()
              ├── util::debug::init()
              ├── print_banner()
              │
              ▼
       Kernel::new() → Kernel::init()
              │
              ├── memory::init()                  # 帧分配器 + 堆
              ├── prepare_arch_paging()            # 运行时页表
              ├── console::init_global()
              ├── drivers::init() + fs::init()
              ├── PCI 枚举
              ├── interrupt_controller::init()
              ├── timer::init()
              ├── percpu::init_bsp()               # GS 基址 → PerCpuData
              ├── smp::bring_up_aps()              # INIT-SIPI-SIPI
              ├── syscall_table::init()
              ├── spawn_init_program("/system/init.elf")
              ├── spawn_system_programs()          # rc.d/*.toml
              │
              ▼
       Kernel::run()  ──>  schedule() ──> idle()
```

## 关键源文件

| 文件 | 角色 |
|---|---|
| `src/main.rs` | 架构无关的入口点（`boot_kernel`） |
| `src/arch/boot.rs` | `BootInfo`、`BootProtocol`、命令行解析 |
| `src/arch/x86_64/boot.asm` | x86_64 Multiboot2 + 长模式入口 |
| `src/arch/aarch64/boot.S` | AArch64 spin-table EL1 入口 |
| `src/arch/riscv64/boot.S` | RISC-V S-mode 入口（通过 OpenSBI） |
| `src/arch/x86_64/ap_trampoline.asm` | AP 16→32→64 位跳板代码 |
| `src/kernel/mod.rs` | `Kernel::init()` 流水线、`maybe_init_swap()` |
| `src/kernel/topology.rs` | NUMA 拓扑检测 |
| `src/kernel/memory/swap.rs` | `SWAP_MAGIC`、`probe_device()` 启动时交换检测 |
| `src/kernel/smp/` | AP 发现、唤醒、TLB 刷除 |
| `src/kernel/percpu.rs` | `PerCpuData` 布局（`cpu_id`、`lapic_id`、`numa_node_id` 等） |
| `src/kernel/service.rs` | 从 rc.d 加载服务定义 |
| `src/kernel/smp/bringup.rs` | AP 跳板数据页布局、入口 |
| `Makefile` | 构建/运行/检查目标 |

---

## 参见

- [子系统概述](../en/boot.md) — 启动流程的高层描述
- [文档索引](../README.md) — 完整的文档树
