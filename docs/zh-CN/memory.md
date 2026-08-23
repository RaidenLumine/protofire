# 内存子系统架构

## 概述

内存子系统管理物理帧、虚拟地址空间、内核堆分配和页表操作。它按以下层次（自底向上）组织在 `src/kernel/memory/` 下：

1. **物理内存检测与帧分配** — 发现可用 RAM 并分配 4 KiB 帧。
2. **虚拟内存/分页** — 基于 `MappingKind` 分类和 `PagePermissions` 的每进程软件页表。
3. **内核堆** — 基于 TLSF 的 `GlobalAlloc`，用于动态内核分配。
4. **MemoryManager** — 中央协调器，将上述组件整合在一起并提供对外可见的 API。

```
  ┌─────────────────────────────────────────────┐
  │            MemoryManager                    │
  │  (manager/mod.rs, manager/init.rs,          │
  │   manager/mapping.rs, manager/pfault.rs,    │
  │   manager/swap.rs)                          │
  ├───────────┬──────────┬──────────────────────┤
  │ Frame     │ PageTable│ HeapAllocator        │
  │ Allocator │ (paging) │ (heap/tlsf+allocator)│
  │ (frame.rs)│          │                      │
  ├───────────┴──────────┴──────────────────────┤
  │         arch.rs (平台分派)                    │
  └─────────────────────────────────────────────┘
```

---

## 1. 物理内存检测

在引导早期，架构特定的二进制 crate 解析引导加载程序的内存映射，并将总物理 RAM 记录在一个全局原子变量中：

```rust
// src/kernel/memory/arch.rs
static DETECTED_PHYSICAL_MEMORY: AtomicU64 = AtomicU64::new(0);
```

- `store_detected_memory(size: usize)`（第 23 行） — 在**引导早期**、`MemoryManager::init()` 之前**调用一次**。使用 `Release` 顺序存储该值。
- `detected_memory() -> Option<usize>`（第 31 行） — 使用 `Acquire` 顺序读取；如果未执行检测（即原子变量仍为零）则返回 `None`。
- `detect_memory() -> usize`（第 123 行） — 内部回退机制：如果原子变量非零则返回该值，否则调用方获取 `frame::physical_pool_size()`（32 MiB）。

引导加载程序来源：
- **x86_64** — Multiboot2 内存映射（`mb2_tag_mmap`）。
- **AArch64 / RISC-V** — FDT `/memory` 节点的 `reg` 属性。

---

## 2. 帧分配器

定义在 `src/kernel/memory/frame.rs` 中。

```rust
pub struct FrameAllocator {
    base: usize,                    // 后端池起始地址
    total_frames: usize,            // 池大小 / FRAME_SIZE
    next_frame: usize,              // bump 分配水位线
    free_ranges: BTreeMap<usize, usize>, // 起始帧 -> 数量，O(log n)
    pub profiler: AllocProfiler,
}
```

### 后端存储

一个静态的 32 MiB 池（`PHYSICAL_POOL`）是默认的后端存储。`init(total_size)` 方法将调用方检测到的大小限制在此池范围内，并向取整到整帧。在实际硬件上，帧分配器会管理真实的物理帧；静态池用于原型开发和宿主机端测试。

### NUMA 感知帧分配

帧分配器子系统支持最多 8 个节点（`MAX_NODES = 8`）的 NUMA 拓扑。
`MemoryManager` 持有一个每节点帧分配器数组（`frame_allocators: [FrameAllocator; MAX_NODES]`）
而不是单个分配器。关键操作：

- **`set_node_range(node_id, base, size)`** — 将物理内存范围注册为属于特定
  NUMA 节点。调用者（拓扑子系统）在 NUMA 发现期间调用此函数，按节点划分物理帧。
- **`allocate_frame_on_node(node_id, count)`** — 从指定节点的分配器分配。
  如果节点特定分配器耗尽，则回退到默认分配器（节点 0）。
- **`allocate_frames(count)`** — 从节点 0（默认/回退分配器）分配，
  保持与非 NUMA 代码路径的向后兼容性。

拓扑子系统（`src/kernel/topology.rs`）提供：
- `NumaNode` — 具有 ID、CPU 数量和内存范围的节点。
- `Topology` — 持有节点表和 CPU 到节点亲和性映射的全局拓扑单例。
- `NUMA_NODE_NONE` — 未关联 CPU 的标记值（0xFF）。
- `global()` — 返回 `Option<&'static Topology>`；当未检测到 NUMA 硬件时返回 `None`
  （单节点回退）。
- `node_for_cpu(cpu_id)` — 返回给定 CPU 的 NUMA 节点 ID。

调度器在 `try_steal_work()` 中使用 NUMA 信息：选择用于工作窃取的受害者 CPU 时，
同一 NUMA 节点的受害者获得双倍分数，使调度器倾向于从共享同一内存节点的 CPU 窃取。

### 分配策略

`allocate(count)`（第 66 行）使用**混合方法**：

1. **从空闲区间中重用** — 在 `free_ranges` 上进行首次适应搜索（通过 `BTreeMap` 迭代按地址升序）。如果找到大小足够的空洞，则从中分割并返回。
2. **bump 尾部** — 如果没有合适的可重用空洞，则推进 bump 指针（`next_frame`）。
3. 所有返回的帧通过 `write_bytes` **清零**。

`deallocate(ptr, count)`（第 98 行）将释放的区间插入 `free_ranges`，并**向前和向后合并相邻区间**。如果释放的区间触及 bump 尾部，则尾部会被提前回退，以便未来的分配重用回收的区域。

### 公开 API

通过 `MemoryManager` 提供：

```rust
// src/kernel/memory/manager/init.rs
pub fn allocate_frames(&mut self, count: usize) -> Option<*mut u8>
pub fn deallocate_frames(&mut self, ptr: *mut u8, count: usize) -> bool
```

---

## 3. 虚拟内存与分页

定义在 `src/kernel/memory/paging.rs` 中。

### 页表模型

```rust
pub struct PageTable {
    mappings: Vec<Mapping>,  // 软件页表条目
    initialized: bool,
    pub profiler: AllocProfiler,
}
```

每个 `Mapping` 存储虚拟地址、物理地址、长度、权限、类型，以及一个供时钟页面回收算法使用的 `accessed` 标志。

关键操作：

| 方法 | 用途 |
|--------|---------|
| `map_region(va, len, perms)` | 在 `va` 处匿名映射 `len` 字节 |
| `map_region_with_kind(va, len, perms, kind)` | 同上，带显式 `MappingKind` |
| `map_to(va, pa, len, perms)` | 恒等映射或设备映射（VA != PA） |
| `map_to_with_kind(va, pa, len, perms, kind)` | 完全控制映射 |
| `unmap(va, len)` | 移除映射，保留前缀/后缀片段 |
| `lookup(va)` | 转换 VA -> (PA, PagePermissions) |
| `lookup_mapping(va)` | 同上，额外返回 `MappingKind` |

映射在虚拟地址空间中**不得重叠** — `overlaps()` 检查（第 383 行）拒绝冲突的范围。`unmap` 通过将现有映射拆分为前缀和后缀片段来处理部分重叠。

### MappingKind

```rust
// src/kernel/memory/paging.rs，第 12 行
pub enum MappingKind {
    KernelHeap,   // 内核堆区域
    Anonymous,    // 普通匿名内存
    Identity,     // 恒等映射（VA == PA），用于引导阶段
    DeviceMemory, // MMIO / 设备内存
    DemandPaged,  // 首次访问时惰性分配
    Cow,          // 写时复制（fork 优化）
    Shared,       // 共享内存（多进程）
}
```

### PagePermissions

一个 3 位位域（第 47 行）：

```rust
pub struct PagePermissions(u8);
pub const READ:   Self = Self(0b001);
pub const WRITE:  Self = Self(0b010);
pub const EXECUTE:Self = Self(0b100);
```

定义了便捷常量 `READ_WRITE`、`READ_EXECUTE` 和 `READ_WRITE_EXECUTE`，以及 `contains()` 和 `as_rwx()` 访问器。

### 页面大小

```rust
pub const PAGE_SIZE: usize = 4096;  // paging.rs，第 9 行
```

---

## 4. 内存管理器

位于 `src/kernel/memory/manager/mod.rs`，`MemoryManager` 是中央协调器：

```rust
pub struct MemoryManager {
    pub(crate) frame_allocators: [FrameAllocator; MAX_NODES], // 每 NUMA 节点分配器
    pub(crate) heap_allocator: HeapAllocator,
    pub(crate) page_table: PageTable,
    pub(crate) fault_profiler: FaultProfiler,
    pub(crate) kernel_heap_start: usize,
    pub(crate) kernel_heap_end: usize,
    pub(crate) initialized: bool,
    pub(crate) page_content: Vec<(usize, Vec<u8>)>,   // DemandPaged 回填
    pub(crate) frame_refcounts: BTreeMap<usize, usize>, // CoW 引用计数
    pub(crate) reclaim_hand: usize,                    // 时钟游标
    pub(crate) swap_area: Option<SwapArea>,
    pub(crate) swap_map: BTreeMap<usize, u64>,         // VA -> 交换槽
}
```

### 初始化

`MemoryManager::init()`（在 `manager/init.rs` 中，第 28 行）：

1. 调用 `detect_memory()` 确定总物理 RAM。
2. 使用该大小初始化 `FrameAllocator`。
3. 初始化 `PageTable`。
4. 调用 `init_kernel_heap()`，其中调用 `HeapAllocator::init()`（在首次分配时触发 TLSF 引导）。
5. 调用 `map_kernel_heap_bootstrap()` 将内核堆范围注册为 `MappingKind::KernelHeap` 映射。

来自引导路径的调用顺序如下：

```
binary crate boot
  → store_detected_memory(size)
  → MemoryManager::new()
  → MemoryManager::init()
  → install_global_unchecked(&manager)
```

### 全局单例

```rust
// src/kernel/memory/global.rs
pub(crate) static GLOBAL_MEMORY_MANAGER: AtomicPtr<MemoryManager> = ...;
```

通过以下方式访问：
- `global() -> Option<&'static MemoryManager>` — 不可变引用。
- `global_mut() -> Option<MemoryManagerGuard>` — 通过指数退避自旋锁（`MEMORY_MANAGER_LOCK`）实现的可变引用，用于 SMP 安全。
- `install_global_unchecked(memory)` — 调用一次以安装单例。

### 映射操作（manager/mapping.rs）

将页表操作与硬件关联：

| `MemoryManager` 方法 | 委托给 | 同时调用 |
|------------------------|-------------|------------|
| `map_region` | `page_table.map_region_with_kind` | — |
| `map_region_with_kind` | `page_table.map_region_with_kind` | — |
| `map_to` | `page_table.map_to_with_kind` | — |
| `map_to_with_kind` | `page_table.map_to_with_kind` | `shootdown_range()` |
| `unmap` | `page_table.unmap` | `shootdown_range()` |
| `translate` | `page_table.lookup` | — |

任何映射更改后，`shootdown_range()`（来自 `arch.rs`）会向所有在线 CPU 广播 TLB 无效化 IPI。

### 用户页面注册

```rust
// manager/mapping.rs
pub fn register_user_pages(
    &mut self,
    pages: &[(usize, usize, PagePermissions, MappingKind)],
) -> usize

pub fn register_shared_page(
    &mut self,
    virtual_address: usize,
    physical_address: usize,
    permissions: PagePermissions,
) -> Result<()>

pub fn unregister_user_page_range(
    &mut self,
    start: usize,
    len: usize,
) -> usize
```

`register_user_pages`（第 156 行）遍历 `(va, pa, perms, kind)` 元组切片，跳过与内核映射（`KernelHeap`、`Identity`、`DeviceMemory`）冲突的条目。相同 VA 上的现有用户映射会被静默替换（先解除映射）。

`unregister_user_page_range`（第 210 行）移除用户映射（`Anonymous`、`DemandPaged`、`Cow`、`Shared`），递减 CoW 帧引用计数，并释放任何关联的交换槽。

### 诊断探针

`page_fault_insight(va)`（第 91 行）组装了一个分层诊断快照：

- 当前运行时转换（来自 `PageTable::lookup_mapping`）。
- 引导阶段转换（x86_64 恒等映射，通过 `arch::bootstrap_translation`）。
- 预准备转换（运行时内核表，仅 x86_64）。
- 计划的内核区域分类。
- `va` 是否落在内核堆范围内。

---

## 5. 内核堆

内核堆是一个 **TLSF（两级分离适配）** 分配器，定义在 `src/kernel/memory/heap/` 中。

```
heap/
  mod.rs        — 模块结构，重导出
  allocator.rs  — KernelGlobalAllocator、GlobalAlloc 实现、自旋锁保护
  tlsf.rs       — TLSF 常量、块头部、空闲链表、位图、合并
  wrapper.rs    — #[global_allocator] 接线、heap_model()、HeapAllocator API
  global.rs     — [备用文件] 内容与 allocator.rs+wrapper.rs 相同
```

### TLSF 参数

```
KERNEL_HEAP_SIZE  = 16 MiB
HEAP_BLOCK_ALIGNMENT = 16 字节
HEADER_SIZE       = 16 字节（size + prev_phys_block）
MIN_FREE_BLOCK    = 32 字节
FL_MIN = 5, FL_MAX = 24  →  FL_COUNT = 20
SL_COUNT = 32
FREE_LISTS_COUNT  = 20 * 32 = 640
```

### 分配器状态

```rust
// heap/tlsf.rs，第 59 行
pub(crate) struct AllocatorState {
    pub start: usize,          // 堆基地址
    pub end: usize,            // 堆结束地址
    pub available: usize,      // 空闲字节数
    pub initialized: bool,
    pub fl_bitmap: u32,        // 每个一级类别一个位
    pub sl_bitmaps: [u32; FL_COUNT],  // 每个二级子类别一个位
    pub free_lists: [usize; FREE_LISTS_COUNT],  // 640 个链表头
}
```

### 分配算法

`allocate_locked`（heap/allocator.rs，第 118 行）：

1. 根据请求的 `Layout` 计算 `min_block_size`（大小 + 对齐填充 + 头部）。
2. 通过 `find_suitable_block` 使用 TLSF 位图搜索合适大小类别的空闲块 — 期望 O(1)。
3. 分割块：创建前缀空闲块（如果对齐间隙 ≥ `MIN_FREE_BLOCK`）、后缀空闲块（如果剩余空间 ≥ `MIN_FREE_BLOCK`），并将分配的块标记为已用。
4. 更新 `prev_phys` 链以供合并。

如果选中的块在对齐后空间过紧，则将其重新插入并尝试下一个大小类别（这避免了因同一位图条目反复找到相同块而导致的无限循环）。

### 释放与合并

`deallocate_locked`（第 281 行）：

1. 验证指针：必须非空、在 `[start, end)` 范围内、且标记为已用。
2. 将块标记为空闲。
3. 调用 `coalesce()` 与物理相邻的空闲块合并（使用 `prev_phys_block` 字段和下一个块的头部）。
4. 将合并后的块插入到适当的空闲链表中。

### GlobalAlloc 接线

```rust
// heap/wrapper.rs（或 heap/global.rs）
#[global_allocator]
#[cfg(target_os = "none")]
static GLOBAL_ALLOCATOR: KernelGlobalAllocator = KernelGlobalAllocator::new();
```

这将 TLSF 分配器注册为 Rust 的全局分配器。在非裸机目标上（`#[cfg(not(target_os = "none"))]`），使用标准的 `System` 分配器。

```rust
pub(crate) fn heap_model() -> &'static KernelGlobalAllocator { ... }
```

`HeapAllocator`（`wrapper.rs` 第 21 行）提供公开 API：

```rust
pub struct HeapAllocator;
impl HeapAllocator {
    pub fn init(&self);        // 首次使用时惰性初始化
    pub fn bounds(&self) -> (usize, usize);
    pub fn remaining(&self) -> usize;
}
```

### 自旋锁

`KernelGlobalAllocator::acquire_lock()` 使用**指数退避测试-并-测试-并-设置（test-and-test-and-set）自旋锁**，在持锁期间**禁用中断**。禁用中断是为了防止重入死锁：定时器中断可能抢占持有堆锁的线程，调度另一个线程尝试分配，然后在同一 CPU 上死锁。保护锁在释放时恢复之前的中断状态。

---

## 6. 架构分派

`src/kernel/memory/arch.rs` 提供围绕平台 MMU 原语的轻量包装。

### TLB 关闭

```rust
pub(crate) fn shootdown_range(virtual_address: usize, length: usize)  // 第 42 行
```

将范围对齐到页边界，并对每个页面调用 `smp::tlb_shootdown(va)`。在 SMP 目标上，这发送一个 IPI 并等待确认。

### 用户页面安装

```rust
pub(crate) fn install_user_page_arch(va, pa, permissions) -> bool  // 第 60 行
pub(crate) fn unmap_user_page_arch(va) -> bool                     // 第 99 行
```

这些分派到 `crate::arch::mmu::install_user_page` / `unmap_page`，具体取决于目标架构（x86_64、AArch64、RISC-V），或在宿主机目标上返回 `false`。

### 转换诊断（x86_64）

- `bootstrap_translation(va)` — 通过早期恒等映射进行转换。
- `prepared_page_tables_active()` — 检查运行时内核页表是否已激活。
- `prepared_translation(va, heap_bounds)` — 通过运行时内核页表进行转换。
- `planned_kernel_region(va, heap_bounds)` — 根据预期的页面布局方案对地址进行分类。

---

## 7. 地址空间布局

### 内核地址空间

内核堆占据一个连续区域（`KERNEL_HEAP_SIZE` = 16 MiB），在软件页表中注册为 `MappingKind::KernelHeap`。堆通过 `GlobalAlloc` trait 支持所有 `alloc`/`dealloc` 调用。

内核栈（在 `src/kernel/stack.rs` 中描述，不在内存模块本身中）是由帧支持的多个区域，栈下方有一个未映射的守护页，用于捕获栈下溢。每个线程拥有其专用的内核栈。

### 用户地址空间

进程地址空间通过每进程的 `PageTable` 管理。用户页面通过 `register_user_pages()` 安装，该函数接受 `(va, pa, perms, kind)` 元组数组。支持的用户空间 `MappingKind` 值包括：

| 类型 | 用途 |
|------|---------|
| `Anonymous` | 普通堆/栈/数据映射 |
| `DemandPaged` | 惰性分配；首次访问触发缺页，分配一个清零帧 |
| `Cow` | 写时复制（fork）；共享只读，直到写错误触发私有副本 |
| `Shared` | 跨进程共享内存；帧由共享内存段注册表管理 |

共享内存页通过 `register_shared_page()` 注册，该函数始终使用 `MappingKind::Shared`。使用 `unregister_user_page_range` 解除映射范围会自动递减 CoW 帧引用计数并释放任何关联的交换槽。

---

## 8. 页面回收与交换

软件页表为每个映射跟踪一个 `accessed` 位，由**时钟算法**用于页面回收（时钟指针为 `reclaim_hand`）。当物理内存压力大时，回收扫描器遍历映射，清除 `accessed` 位，并回收最近未使用的页面。

回收的页面可以：
- **内存中**存储在 `page_content`（内容存储）中，用于按需分页回填 — 保留原始代码/数据，以便后续缺页可以重新填充页面。
- 通过 `SwapArea` **写入交换设备** — VA 到槽位的映射保存在 `swap_map`（`BTreeMap<usize, u64>`）中。

### 交换区域（`src/kernel/memory/swap.rs`）

`SwapArea` 结构体包装一个 `Arc<dyn BlockDevice>` 并管理连续块范围中的页面槽位：

```rust
pub struct SwapArea {
    device: Arc<dyn BlockDevice>,
    start_lba: u64,
    total_pages: u64,
    free_slots: Vec<u64>,
}
```

每个页面槽位跨越 8 × 512 字节块（4096 字节，匹配 `PAGE_SIZE`）。
槽位从 LIFO 空闲列表中分配，该列表在每次启动时重建——交换数据仅对当前启动会话有效。

### 启动时交换检测

在启动时，`maybe_init_swap()`（从文件系统初始化后的 `Kernel::init()` 调用）
扫描注册的块设备以查找有效的交换签名：

```rust
pub const SWAP_MAGIC: [u8; 8] = *b"ADASWAP\x00";

pub fn probe_device(device: &dyn BlockDevice) -> Option<(u64, u64)> {
    let mut header = [0u8; 512];
    device.read_blocks(0, &mut header).ok()?;
    if header[..8] != SWAP_MAGIC {
        return None;
    }
    let page_count = u64::from_le_bytes(header[8..16].try_into().ok()?);
    if page_count == 0 { return None; }
    Some((0, page_count))
}
```

如果找到具有 `ADASWAP` 魔数签名的设备，则使用设备、起始 LBA (0) 和页面计数
调用 `init_swap()`。如果未发现交换设备，内核回退到内存中的 `page_content`
存储（现有行为）。

---

## 关键源文件位置

| 组件 | 文件 |
|-----------|------|
| 内存检测 | `src/kernel/memory/arch.rs`（第 12-34、123-130 行） |
| 帧分配器 | `src/kernel/memory/frame.rs` |
| NUMA 感知分配器 | `src/kernel/memory/frame.rs`（`MAX_NODES`，`set_node_range()`） |
| NUMA 拓扑 | `src/kernel/topology.rs` |
| 页表/分页 | `src/kernel/memory/paging.rs` |
| `MemoryManager` 结构体 | `src/kernel/memory/manager/mod.rs` |
| `MemoryManager::init` | `src/kernel/memory/manager/init.rs` |
| 映射操作 | `src/kernel/memory/manager/mapping.rs` |
| 全局单例 | `src/kernel/memory/global.rs` |
| TLSF 分配器 | `src/kernel/memory/heap/tlsf.rs` |
| `KernelGlobalAllocator` | `src/kernel/memory/heap/allocator.rs` |
| `#[global_allocator]` 接线 | `src/kernel/memory/heap/wrapper.rs` |
| 架构 MMU 分派 | `src/kernel/memory/arch.rs` |
| 缺页处理 | `src/kernel/memory/manager/pfault.rs` |
| 交换/页面回收 | `src/kernel/memory/manager/swap.rs`、`src/kernel/memory/swap.rs` |
| 交换启动探测 | `src/kernel/memory/swap.rs`（`SWAP_MAGIC`，`probe_device()`） |
| 交换启动集成 | `src/kernel/mod.rs`（`maybe_init_swap()`） |
| 分配器性能分析 | `src/kernel/memory/alloc_profiler.rs` |

---

## 参见

- [子系统概述](../en/memory.md) — 高层级内存管理描述
- [文档索引](../README.md) — 完整文档树
