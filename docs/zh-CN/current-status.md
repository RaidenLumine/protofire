# 当前状态

> **最后更新：** 2026-08-24 **代码库：** 600+ 个 Rust 文件，约 215,000 行 Rust 代码 **目标架构：** x86_64（完整），AArch64（完整），RISC-V 64（部分）

---

## 子系统评估

### 1. 设备驱动程序 — ★★★★☆ (87%)

| 驱动程序 | 代码行数 | 类型 | 状态 |
|--------|-------|------|--------|
| AHCI (SATA) | 1,100+ | 块设备 | 完整读写（DMA，轮询） |
| ATA (PIO) | 3,554 | 块设备 | 完整读写 |
| VirtIO (块设备) | 1,200+ | 块设备 | 完整读写 |
| VirtIO (网络) | 1,500+ | 网络 | 完整 RX/TX |
| VirtIO (GPU) | 1,200+ | 显示 | 完整 2D 模式设置（x86_64 PCI + AArch64/RISC-V 设备树 MMIO），VIRGL 3D 用户空间接口（#181-189） |
| NVMe | 500+ | 块设备 | 完整读写，MSI-X 中断 |
| xHCI | 1,657 | USB 主机 | 驱动程序存在 |
| USB HID | 329 | HID (键盘) | 驱动程序存在 |
| 串行 (UART 16550) | 2,000+ | 文本 I/O | 全双工 |
| PS/2 键盘 | 841 | 输入 | 完整 |
| 帧缓冲 | 273 | 显示 | 线性帧缓冲 |
| 帧缓冲控制台 | 692 | 显示 | 文本渲染 |
| HDA (Intel HD Audio) | 450+ | 音频 | CORB/RIRB，编解码器发现，流描述符 |
| PCIe ECAM | 架构特定 | 总线 | x86_64：完整；AArch64：基本探测 |

**优势：** 驱动覆盖存储、网络、显示、音频与输入，其中大部分已在 QEMU 下验证。

- **存储**：AHCI (SATA)、ATA PIO、VirtIO 与 NVMe 四种独立块后端；NVMe 通过 MSI-X 中断驱动完成。
- **网络**：VirtIO 网络驱动达到生产质量（支持多队列、中断驱动）。
- **显示**：VirtIO GPU 在 VirtIO MMIO 传输上提供加速 2D 模式设置，直接集成帧缓冲控制台（无需独立的 bochs-display 设备）；**VIRGL 3D 用户空间接口**（syscall #181-189）把 virtio-gpu 的 VIRGL 协议暴露给用户空间渲染器——上下文创建/销毁、3D 资源（内核 DMA 后端）、主机传输、命令提交与扫描输出，真实 3D 渲染由宿主机 virglrenderer 执行。
- **设备树驱动的驱动探测**：在 AArch64/RISC-V 上按 compatible 字符串把 FDT 节点绑定到驱动，virtio-gpu/block/net 均按 DT 节点 `reg` 探测，GPU 由此在 AArch64/RISC-V 上可用。
- **MSI/MSI-X**：能力解析与向量编程可供所有驱动使用（NVMe、VirtIO PCI）。
- **音频**：Intel HDA 驱动提供控制器初始化、CORB/RIRB 引擎、编解码器发现与流描述符配置。
- **热插拔**：通过 DeviceManager 生命周期框架监控 PCIe 插槽状态与 xHCI 端口变化。

**缺点：**

- **USB 未闭环**：xHCI 与 USB HID 仅"驱动程序存在"，USB 存储/键盘尚未端到端可用。
- **HDA 未到用户空间**：音频仅有控制器级接口，尚无可用的用户空间音频流。
- **AArch64 PCIe 仅基本探测**：PCI 设备（NVMe、virtio-pci）在 AArch64/RISC-V 上依赖设备树 MMIO。
- **仅在 QEMU 下验证**：尚无裸机硬件上的真实设备验证。

---

### 2. I/O 子系统 — ★★★★☆ (82%)

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| 文件描述符表 | 300+ | 完整（每进程 fd 表，dup，dup2，F_DUPFD，close-on-exec） |
| 管道 | 650+ | 完整（VFS 中的匿名管道，fcntl 动态缓冲区，O_NONBLOCK） |
| 块缓存 | 1,200+ | LRU（128 项），直写/回写，预取，脏块老化 + 后台写回 |
| 句柄表 | 300+ | 通用句柄/对象框架 |
| 控制台 I/O | 783 | 全局控制台设备，Ctrl-C 处理 |

**优势：** 完整的文件描述符与管道语义，辅以运行时管道与块缓存管理。

- **fd 语义**：跨 spawn 继承、close-on-exec、dup。
- **管道**：基于 VFS，与常规文件共用读写路径。
- **fcntl (#179)**：F_DUPFD / F_GETFD / F_SETFD / F_GETFL / F_SETFL，以及 **F_GETPIPE_SZ / F_SETPIPE_SZ**——管道缓冲区可运行时调整（按页取整、上限 1 MiB、数据保留）；每端独立的 O_NONBLOCK 让空读/满写立即返回 EAGAIN 而非阻塞。
- **持久块缓存**：为每个脏块记录脏化时刻，超过 6 秒（600 滴答）的脏块每 3 秒后台自动写回；**sync (#180)** 提供按需全量落盘（POSIX sync(2)），无需显式 fsync 即可持久化。

**缺点：**

- **块缓存容量小**：LRU 仅 128 项，大块工作负载下命中率有限。
- **I/O 路径仅在模拟下验证**：尚无真实磁盘/SSD 上的延迟与吞吐测试。

---

### 3. 虚拟文件系统 — ★★★★★ (91%)

VFS 是最大的子系统，**62,700+ 行代码，分布在 118 个文件中**。

#### 3.1 原生文件系统

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| SimpleFs 核心 (V2/V3) | 6,557 | 完整读写，校验和（CRC32C） |
| TmpFs | 833 | 内存中，完整读写 |
| DevFs | 327 | 设备节点列表 |
| ProcFs | 828 | 进程信息，运行时状态 |
| Unicode 层 | 4,579 | Unicode 15.1 NFC/NFD，大小写折叠，GB18030，OEM 代码页 |

#### 3.2 外部文件系统驱动程序

| 驱动程序 | 代码行数 | 模式 | 特性 |
|--------|-------|------|----------|
| ext4 | 3,626 | **读写** | 日志（撤销重放，v3 校验和标签），区段树，目录索引 |
| F2FS | 3,594 | **读写** | 检查点（SIT 持久化），孤立恢复，原子 CP+SB 写入 |
| XFS v5 | 3,829 | **带日志重放的读写** | B+树，CRC32C，v5 超级块，日志重放（缓冲/inode/dquot 项） |
| exFAT | 3,089 | 读写 | VFAT 扩展 |
| BtrFS | 2,899 | 只读 | B树遍历 |
| FAT32 | 2,794 | 读写 | LFN，OEM 代码页，FSInfo 记账 |
| NTFS 3.1 | 2,684 | 只读 | MFT 解析，属性解析 |
| SquashFS 4.0 | 1,446 | 只读 | 5 种压缩算法 |
| ISO 9660 | 1,475 | 只读 | Joliet，Rock Ridge |
| EROFS v1 | 1,219 | 只读 | 紧凑的 inode 格式 |

#### 3.3 VFS 层

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| VFS 核心（挂载，路径解析，操作） | 1,947 | 完整 |
| 卷恢复 | 1,163 | 事务撤销日志，崩溃恢复能力，崩溃矩阵测试 |
| 故障注入矩阵 | 1,245 | 全面的单故障 + 双故障/多轮崩溃测试 |
| 扩展属性（xattr）表 | 315 | SimpleFs V4 持久存储 + tmpfs 内存存储 |
| 透明文件压缩 | 132+ | 每文件 LZSS/raw chunk 压缩（复用内存压缩编解码器） |
| 跨文件去重 | 207+ | 内容哈希共享 extent，挂载时重建引用计数 |
| 块设备后端抽象 | ~2,500 | ATA、VirtIO、NVMe 后端 |

**优势：** 11 个文件系统驱动（含 4 个可写）、崩溃安全的原生 FS 与静态加密。

- **多文件系统**：ext4、F2FS、XFS 支持从真实磁盘进行完整日志重放；另有 exFAT 与 FAT32（读写）以及 btrfs/NTFS/SquashFS/ISO 9660/EROFS（只读）。
- **Unicode 15.1**：完整的 NF C/D 规范化与 GB18030 编解码器。
- **崩溃安全**：SimpleFs 使用撤销日志事务与两阶段提交。
- **静态数据加密**：EncryptedBlockDevice 提供 AES-256 XTS 磁盘加密，兼容 LUKS2、PBKDF2 密钥派生，可透明置于任何文件系统之下。

**缺点：**

- **只读驱动多**：btrfs、NTFS、SquashFS、ISO 9660、EROFS 均为只读，写支持是路线图中期目标。
- **日志重放仅在模拟磁盘验证**：真实损坏磁盘的边角情形覆盖面有限。

**SimpleFs V4 数据缩减格式**（继承 V3 的持久安全描述符 + `pending_commit` 两阶段提交）：

- **扩展属性**：按 inode 持久化在活动/影子 xattr 表槽中，与 inode/dirent 表在同一两阶段提交中刷新；SimpleFs 与 tmpfs 均支持 `setxattr`/`getxattr`/`listxattr`/`removexattr` 语义（syscall #151-154）。
- **透明每文件压缩**：每个 4 KiB chunk 编码为 zero/RLE/LZSS（不可压缩时回退原始数据），`size` 保留逻辑长度，读取时只解压相交的 chunk；通过 `SetFileFlags`（#155）切换。
- **跨文件去重**：内容相同的文件合并为单个共享 extent，引用计数在挂载时从磁盘 `DEDUPED` 标记重建，覆盖写/删除经 copy-on-write 解共享；两者都通过 `GetFileFlags`（#156）暴露给用户空间。

#### 3.4 静态数据加密

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| AES-256 + AES-XTS | 500+ | 加密引擎（kernel/crypto.rs） |
| PBKDF2 密钥派生 | 100+ | 磁盘加密的密钥拉伸 |
| EncryptedBlockDevice | 200+ | 块设备加密包装器（fs/crypt_device.rs） |
| LUKS2 头部解析器 | 300+ | LUKS2 磁盘格式解析（fs/luks2.rs） |

---

### 4. CPU 调度器 — ★★★★★ (90%)

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| 调度器核心 | 1,200+ | 带优先级的抢占式轮转调度 |
| 线程生命周期 | 1,500+ | 生成、退出、终止、分离 |
| 上下文切换 | 600+ | x86_64、AArch64、RISC-V（每架构汇编） |
| 进程/线程类型 | 800+ | 状态、优先级、凭证 |
| 进程组 | 400+ | 作业控制，前台/后台 |
| SMP 发现 | 300+ | x86_64：ACPI MADT AP 启动；RISC-V：FDT CPU 节点 |
| 定时器滴答 | 200+ | 调度器时间片管理 |
| 唤醒器 | 150+ | 线程唤醒通知 |
| 调度器统计 | 200+ | 负载平均（1秒采样，300项环形缓冲），每线程 CPU 滴答，空闲跟踪，ProcFs 集成 |
| 优先级提升 | 100+ | 饥饿保护：空闲 50 滴答后 Normal → High，8 滴答后降级 |
| 工作窃取 | 80+ | 跨 CPU 负载均衡，NUMA 感知受害者选择 |
| 栈金丝雀 | 60+ | 每线程随机金丝雀，上下文切换时全局保护更新 |
| 电源管理 | 400+ | CPU 频率缩放（x86_64 MSR P-state 驱动；aarch64/riscv64 DT OPP 范围发现 + 目标跟踪），5 种 governor，调度器 tick 集成，DTS 温度读取 |

**优势：** 抢占式多线程调度，含 NUMA 感知负载均衡与运行时栈保护。

- **调度策略**：`SchedDefault`（轮转）、`SchedFifo`（运行至完成）、`SchedRoundRobin`（显式 RR）；支持 `START_SUSPENDED` 标志与优先级提升的饥饿保护。
- **工作窃取**：跨 CPU 负载均衡，NUMA 感知受害者选择（同节点窃取得分翻倍）。
- **内核栈保护**：所有架构上的内核栈保护页，`dying_thread` 模式防止上下文切换时 Arc 泄漏。
- **每线程栈金丝雀**：创建时写入随机 64 位金丝雀，上下文切换回到调度器前验证。
- **CPU 频率缩放**：x86_64 经 IA32_PERF_CTL/PERF_STATUS MSR（CPUID leaf 0x16 + PLATFORM_INFO 检测，AMD 只读回退），1 Hz governor 驱动（performance/powersave/ondemand/schedutil/userspace），温度经 IA32_PACKAGE_THERM_STATUS 读取；aarch64/riscv64 从设备树 OPP 表（`operating-points-v2` phandle / legacy `operating-points` 元组）发现频率范围。

**缺点：**

- **ARM/RISC-V 频率缩放未落地**：aarch64/riscv64 仅在软件中记录目标频率，真实频率切换依赖尚未接入的平台 clock/firmware 接口（SCMI、common-clock、SBI CPPC）。
- **负载均衡缺少真实负载验证**：SMP 多核与 NUMA 场景主要在 QEMU 下测试。

---

### 5. 内存管理 — ★★★★★ (93%)

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| 物理帧分配器 | 800+ | 512 MiB 池（通过 Multiboot2/FDT 动态检测），Bump + BTreeMap 空闲跟踪 |
| NUMA 帧分配器 | 120+ | 8 个每节点分配器（MAX_NODES），`set_node_range()`，回退到节点 0 |
| TLSF 堆分配器 | 1,200+ | 16 MiB，640 个空闲列表，O(1) 分配/释放 |
| 页表管理 | 1,500+ | 每架构表，恒等映射，用户地址空间，2 MiB + 1 GiB 大页支持 |
| 写时复制 | 400+ | 引用计数帧，故障触发复制 |
| 按需分页 | 500+ | 内容存储 + 换出（磁盘支持） |
| 交换区域 | 350+ | 块设备支持的页面槽位，LIFO 空闲列表，基于魔数的启动时检测 |
| 压缩页缓存 | 200+ | zswap 式回收页压缩（zero/RLE/LZSS 编码），16 MiB 预算，超限回退原始内容存储 |
| 内存整理 | 250+ | 物理池碎片整理：迁移可移动用户帧，合并空闲区段 |
| ASID 分配器 | 250+ | AArch64 位图 + CAS，RISC-V 位图 + CAS（65536 个 ASID） |
| 用户地址空间 | 600+ | Brk 堆，ELF 加载，保护页 |
| 内核栈保护 | 100+ | 每个内核栈下方的未映射页 |

**优势：** 覆盖现代虚拟内存特性，含 NUMA、磁盘交换、压缩与碎片整理。

- **TLSF 分配器**：有界 2^32 堆，O(1) 分配/释放，640 个空闲列表。
- **虚拟内存**：写时复制 fork、带换出的按需分页、2 MiB / 1 GiB 大页自动选择、所有线程内核栈保护页；mlock/munlock (#131-132) 与 madvise (#133)。
- **NUMA**：最多 8 个每节点帧分配器、CPU-节点映射（`numa_node_id`）与自动拓扑发现（x86_64 ACPI SRAT/SLIT；AArch64/RISC-V FDT numa-node-id/distance-map）；无 NUMA 时回退单节点拓扑。
- **磁盘交换**：启动时经 `ADASWAP` 魔数自动激活。
- **内存压缩与整理**：zswap 式 zero/RLE/LZSS 压缩（16 MiB 预算）与物理池碎片整理；经 `CompactMemory` 系统调用（#150）暴露。

**缺点：**

- **容量上限固定**：内核 TLSF 堆固定为 16 MiB、物理池默认 512 MiB，大工作负载下受限。
- **x86_64 无 ASID/PCID 级 TLB 标记**：上下文切换依赖 TLB 失效。
- **换出/压缩仅在模拟下验证**：真实内存压力场景未覆盖。

---

### 6. 中断与异常处理 — ★★★★★ (93%)

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| x86_64 IDT + 异常 | 500+ | 完整：#PF, #GP, #UD, #DF, 定时器, IPI |
| x86_64 APIC + IOAPIC | 211 | 完整：SMP IPI，定时器，I/O 路由 |
| AArch64 异常向量 | 839 | EL1 同步/IRQ/FIQ/SError，EL0 同步 |
| AArch64 GIC | 471 (在 arch 模块中) | 从 FDT 检测 GICv2/v3，中断路由 |
| RISC-V 陷阱处理程序 | 550 | U 模式 ecall，定时器，外部中断 |
| RISC-V PLIC | 440 (在 arch 模块中) | 从 FDT 初始化 PLIC |
| 通用中断抽象 | 137 | `InterruptController` trait |
| 线程异常处理 | 401 | 页错误恢复，信号传递 |
| PAN/SMAP 模拟 | 500+ | AArch64 PSTATE.PAN，x86_64 SMAP，RISC-V SUM |
| MSI/MSI-X 编程 | 350+ | 向量分配器，MSI/MSI-X 表条目编程（x86_64，AArch64 GIC ITS） |
| NMI 处理 | 130+ | x86_64 向量 2 专用路径，AArch64 SError/FIQ 专用路径，处理器注册表 |
| 中断负载均衡 (SMP) | 250+ | IOAPIC 重定向重定位，GIC SPI 亲和性，PLIC 每上下文使能 |
| 中断统计接口 | 200+ | 每 CPU/每向量计数器，NMI/IPI 总数，负载均衡状态（SystemInfo #9） |

**优势：** 三架构异常处理完整，含 PAN/SMAP 模拟、MSI/MSI-X、NMI 与中断负载均衡。

- **异常处理**：三架构完整；x86_64 双故障处理；AArch64 异常向量正确分类同步异常/IRQ/FIQ/SError；PAN/SMAP 已正确实现（`asm nomem` 修复已部署）。
- **MSI/MSI-X**：x86_64 向量分配器 + 表编程；AArch64 经 GICv3 ITS（命令队列、设备/集合表、中断转换、LPI 配置）；NVMe 与 VirtIO PCI 现代传输使用 MSI-X 完成。
- **NMI**：x86_64 向量 2 与 AArch64 SError/FIQ 专用最小路径 + 三架构处理器注册表。
- **软中断/底半部**：32 个向量、AtomicU32 待处理掩码、集成到调度器循环与三架构陷阱分发。
- **中断负载均衡 (SMP)**：每 2 秒把最忙 CPU 上最热的可迁移 IRQ 迁往最闲 CPU（x86_64 IOAPIC 重定向 / AArch64 GIC SPI 亲和性 / RISC-V PLIC 每上下文使能）。
- **中断统计**：`SystemInfo` 类型 9 暴露每 CPU/每向量 IRQ、IPI/NMI 计数与负载均衡状态。

**缺点：**

- **RISC-V 无 MSI/MSI-X**：AIA 尚未接入，中断仍走 PLIC。
- **RISC-V 无架构级 NMI 源**：S 模式下分发入口保持休眠（需 M 模式或 `smnmi` 路径）。
- **GIC/PLIC 仅在模拟下验证**：无真实硬件上的路由与延迟测试。

---

### 7. 网络栈 — ★★★★★ (89%)

网络栈是第二大子系统，**40,809 行代码，分布在 81 个文件中**，加上 **TLS 1.3（3,224 行，4 个文件）**，并带有 ring3 用户空间 API（#121）。

#### 7.1 协议支持

| 层 | 协议 | 状态 |
|-------|-----------|--------|
| **链路层** | 以太网，ARP，设备抽象 | 完整 |
| **网络层** | IPv4，IPv6，ICMP，ICMPv6，IGMP，MLD，NAT，IP 选项 | 完整 |
| **传输层** | TCP（拥塞控制，ECN），UDP，SCTP（四次握手，CRC32C），DCCP（RFC 4340，CCID 2，完整 syscall API） | 完整 |
| **应用层** | DHCP，DNS（缓存，解析），mDNS，NTP，PPP | 完整 |
| **安全** | TLS 1.3（握手，记录，证书），IPsec（ESP + AH，SAD/SPD，传输/隧道模式） | 完整（内核端） |
| **VPN** | WireGuard（Noise_IKpsk2 握手，ChaCha20-Poly1305 传输，密钥管理） | 完整 |
| **多播路由** | MFC/VIF 转发引擎（RPF + TTL 门控），IGMPv2/MLDv1 路由器模式，MRT 管理 API | 完整 |
| **原始** | 原始套接字，原始包 | 完整 |
| **教育¹** | CSMA/CD，CSMA/CA，STP，IPv4 选项，移动 IP，RSVP，PIM-DM（洪泛-剪枝） | 特性门控 |

¹ 由 `feature = "educational_networking"` 控制。

#### 7.2 TCP 实现

| 组件 | 状态 |
|-----------|--------|
| 段处理 | 完整（分段，重组，重传） |
| 连接表 | 完整（哈希表，状态机） |
| 拥塞控制 | 已实现 |
| ECN（显式拥塞通知） | 已实现 |
| 定时器管理 | 完整（RTO，延迟 ACK，保活） |
| 窗口缩放 | 已包含 |

#### 7.3 网络系统调用

定义了 40 个网络系统调用；其中 35 个具有共享用户库（`src/user/shared/`）包装器。

**优势：** 完整的原生（非 lwIP）TCP/IP 栈，含传输层扩展与内核态安全协议。

- **协议覆盖**：链路层（以太网、ARP）、网络层（IPv4/IPv6/ICMP/IGMP/MLD/NAT）、传输层（TCP 拥塞控制 + ECN、UDP、SCTP、DCCP）、应用层（DHCP、DNS 缓存、mDNS、NTP、PPP）。
- **IPsec**：ESP + AH，AES-GCM/ChaCha20-Poly1305 AEAD 与 HMAC-SHA256，传输/隧道双模式，SAD/SPD 经专用 syscall 管理。
- **多播路由**：MFC/VIF 转发引擎（RPF + TTL 门控）、IGMPv2/MLDv1 路由器模式、MRT 管理 API，`educational_networking` 下附带 PIM-DM 洪泛-剪枝控制面。
- **IPv6 加固**：路径 MTU 发现（RFC 8201，含 TX 分片）、原子分片（RFC 6946）、扩展头链顺序与长度限制（RFC 8200 §4.1）、路由头类型 0 拒绝（RFC 5095）、重叠分片丢弃（RFC 5722）。
- **TLS 1.3**：作为内核模块实现，不常见，可能对安全引导有用。

**缺点：**

- **40 个网络 syscall 中仅 35 个有共享库包装器**。
- **内核态 TLS 未形成可信体系**：证书与信任锚管理仍很初级。
- **教育类协议特性门控**：CSMA/CD、STP、移动 IP、RSVP、PIM-DM 等仅在 `educational_networking` 下编译。
- **性能未基准**：吞吐与并发基准（多核、负载均衡）尚待建立。

---

### 8. IPC / 同步 — ★★★★★ (92%)

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| 管道 | 543 | 基于 VFS，匿名，阻塞读/写 |
| 信号 | 600+ | 43 个槽位（0-42），11 个 RT 信号（32-42），u64 掩码，安装/入队/等待 |
| 信号掩码 | 150+ | 每进程阻塞信号跟踪，u64 位域 |
| 异步信号分发 | 200+ | 用户栈上的信号帧，架构特定跳板，sigreturn；x86_64，AArch64，RISC-V |
| SA_SIGINFO 支持 | 80+ | siginfo_t 传递（si_signo, si_code, si_pid, si_uid, si_addr, si_value） |
| SA_RESTART 支持 | 100+ | 信号返回时自动重启系统调用，每线程 RestartBlock |
| sigsuspend (#135) | 60+ | 原子掩码交换 + 线程挂起直到信号到达 |
| POSIX 定时器 (#137-140) | 300+ | timer_create/settime/gettime/delete，每进程定时器管理，到期时信号传递 |
| eventfd (#107) | 130+ | 计数器/信号量模式，EFD_NONBLOCK/EFD_CLOEXEC，poll/epoll 集成，写溢出 EAGAIN |
| 事件 | 100+ | 事件标志同步 |
| 条件变量 | 200+ | 阻塞等待/唤醒 |
| 互斥锁 | 150+ | 阻塞互斥锁 |
| 信号量 | 100+ | 计数信号量 |
| 自旋锁 | 100+ | IRQ 安全自旋锁 |
| Shell 管道 | 200+ | 带进程组的命令管道 |

**优势：** 完整的同步原语与信号机制，含 POSIX 信号交互模型。

- **同步原语**：互斥锁、信号量、条件变量、事件、IRQ 安全自旋锁完整；eventfd (#107) 提供 Linux 风格计数/信号量语义（EFD_SEMAPHORE/EFD_NONBLOCK/EFD_CLOEXEC，写溢出 EAGAIN）并集成 `poll`/`epoll`/`io_uring` 就绪探测。
- **信号**：43 个槽位（0-42）、11 个 RT 信号（32-42）携带 `siginfo_t`；SA_SIGINFO 提供每架构 `ucontext_t`；SA_RESTART 自动回退被中断指令指针并重入分发器；sigsuspend (#135) 原子替换掩码并挂起；POSIX 定时器 (#137-140) 到期经调度器滴答传递信号。
- **异步信号分发**：三架构用户栈信号帧 + 架构特定跳板 + sigreturn。
- **Shell 管道**：`cmd1 | cmd2` 带进程组。

**缺点：**

- **IPC 形态有限**：主要依赖管道、信号、eventfd/mq，无标准化的共享内存 IPC API（shm 尚为特定 syscall）。
- **压力场景未基准**：锁竞争、信号洪峰等并发压力测试尚缺。

---

### 9. 安全与访问控制 — ★★★★★ (92%)

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| Biba 完整性模型 | 200+ | 系统 > 高 > 中 > 低 |
| **MAC 类型强制** | 400+ | SELinux 式 TE 引擎：主体/对象安全类型、allow 规则策略、中心 VFS 钩子 + Process/Network 类检查、exec 域转换、管理 syscall（#175-178） |
| 区域感知 DAC | 300+ | 系统 (/system)，数据 (/data)，用户 (/home) 区域 |
| 安全描述符 | 200+ | 每对象安全标签 |
| 用户/组数据库 | 300+ | `/data/etc/passwd`，`/data/etc/shadow`（持久化、原子写、0600） |
| 进程安全令牌 | 165 | 每线程凭证（含 MAC 主体类型） |
| 访问辅助函数 | 150+ | VFS 操作上的权限检查 |
| SHA-256 完整性 | 100+ | 启动载荷哈希验证（manifest_sha256 / entry_sha256） |
| PAN/SMAP | 500+ | 内核-用户内存隔离 |
| 栈金丝雀 | 60+ | 每线程随机金丝雀，上下文切换时栈验证 |
| 审计子系统 | 300+ | 审计事件类型（Syscall、FileOp、Process、Network、Auth、**MacDenial**），环形缓冲区（8192 条目），系统调用入口/出口钩子，AuditSetEnable (#143) 和 AuditReadLog (#144) 系统调用 |

**优势：** 业余内核中罕见的正式多级安全策略与强制访问控制。

- **Biba 完整性模型**：系统 > 高 > 中 > 低的正式信息流策略。
- **MAC 类型强制引擎**（SELinux/AppArmor 等价物）：主体（进程）与对象（文件）各带安全类型，allow 规则策略在中心 VFS 检查点强制执行，Process 类覆盖 ptrace/信号、Network 类覆盖网络能力，exec 时域转换，管理 syscall（#175-178），拒绝时发 `MacDenial` 审计记录。
- **区域感知 DAC**：系统 (/system)、数据 (/data)、用户 (/home) 分区。
- **凭证持久化**：`/data/etc/passwd` 与 `/data/etc/shadow` 原子写回（临时文件 + rename），shadow 保持 0600。
- **代码完整性**：SHA-256（启动清单与载荷）；seccomp (#129) 进程沙箱；PAN/SMAP 防止内核推测性访问用户内存。
- **栈金丝雀**：每线程随机 64 位金丝雀，上下文切换回调度器前经 `check_stack_canary()` 验证。
- **审计子系统**：分类事件类型（Syscall、FileOp、Process、Network、Auth、MacDenial）+ 环形缓冲区 + AuditSetEnable (#143)/AuditReadLog (#144)。

**缺点：**

- **默认放行**：未加载 MAC 策略时默认允许，deny-by-default 需显式配置策略。
- **审计日志仅在内存**：8192 项环形缓冲区不落盘，重启即丢失。
- **安装应用信任边界基于路径**：`/apps/packages` 下的已安装应用仅凭路径包含关系与 SHA-256 完整性校验获得信任，无程序签名验证。

---

### 10. 系统调用接口 — ★★★★★ (93%)

| 组件 | 代码行数 | 状态 |
|-----------|-------|--------|
| 系统调用表 | 1,300+ | 190 个槽位（0-189），全部已注册处理程序 |
| 调度引擎 | 500+ | 具有操作返回的上下文感知调度 |
| 用户内存验证 | 400+ | `validate_user_mapping()` + `copy_user_bytes()` |
| 共享包装器（`src/user/shared/syscall.rs`） | 2,000+ | 90+ 个类型化包装器，7 个原始入口点 |
| ABI 类型 | 500+ | 线路格式记录，系统调用编码 |
| 按类别分类的处理程序文件 | 14 个文件 | fs, network, process, diagnostic, tls, filter, io_uring, ptrace 等 |
| 系统调用分析 | 200+ | 每系统调用计数器（可选特性） |

**系统调用处理程序类别：**

| 类别 | 处理程序 | 文件 |
|----------|----------|-------|
| 进程/线程生命周期 | 15+ | `launch_metadata.rs`，`runtime.rs` |
| 进程控制 | 1 | `misc/prctl.rs` |
| 文件/路径操作 | 15+ | `fs_path_ops.rs` |
| I/O（读/写） | 8+ | `io_fd.rs` |
| 网络 | 22 | `network.rs` |
| IPC & 同步 | 12+ | `futex.rs`, `event_fd.rs`, `signal_fd.rs`, `timer_fd.rs`, `mq.rs`, `epoll.rs` |
| 内存管理 | 10+ | `memory/map.rs`, `memory/brk.rs`, `memory/shm_handlers.rs` |
| 文件系统（挂载/FUSE） | 10+ | `fs_path_ops.rs`, `fs/fuse_mount.rs` |
| TLS 加密连接 | 1 | `tls_handler.rs` |
| 包过滤器/防火墙 | 4 | `filter_handler.rs` |
| io_uring 异步 I/O | 2 | `io_uring_handler.rs` |
| ptrace 进程跟踪 | 1 | `ptrace.rs` (syscall) + `process/ptrace.rs` (core) |
| seccomp | 1 | `seccomp_handler.rs` |
| 信号控制 | 4 | `signal.rs`, `signal_mask.rs`, `sigsuspend.rs`, `restart_syscall.rs` |
| 异常控制 | 6 | `exception_control.rs` |
| POSIX 定时器 (#137-140) | 4 | `timer.rs`（timer_create/settime/gettime/delete） |
| 审计 (#143-144) | 2 | `audit.rs`（AuditSetEnable，AuditReadLog） |
| 扩展属性 + 文件标志 (#151-156) | 6 | `fs/xattr.rs`（setxattr/getxattr/listxattr/removexattr/set_file_flags/get_file_flags） |
| 诊断 | 10+ | `diagnostic.rs` |
| ABI 信息 | 4+ | `abi_info.rs` |
| 杂项 | 5+ | `misc.rs` |

**优势：** 稳定的 ABI、集中的单一事实来源与完善的用户内存验证。

- **按类别组织**：处理程序文件按类别清晰分离（fs、network、process、tls、filter、io_uring、ptrace 等 14 个文件）；槽位有良好文档记录并含扩展空间（最多 256 个）。
- **单一真实来源**：`src/user/shared/` 提供 ABI 的单一事实来源，内核与用户空间针对相同常量编译；`UserSyscall` 类型允许内核内部调用者（如演示工作线程）走同一路径。
- **用户内存验证**：每次访问前验证（无推测性 copyin），经集中 `SYSCALL_POINTER_SPECS` 表预验证。
- **信号与定时器**：sigsuspend (#135) 与 restart_syscall (#136) 完善 POSIX 信号交互模型（SA_RESTART 回退指令指针并重入分发器）；POSIX 定时器 (#137-140)。
- **管理类 syscall**：审计 (#143-144)、CPU 频率缩放 (#145-149)、扩展属性与文件标志 (#151-156)、fcntl (#179)、sync (#180)。
- **VIRGL 3D 接口 (#181-189)**：gpu_ctx_create/destroy、gpu_res_create_3d/unref（内核 DMA 后端）、gpu_transfer_to_host_3d/from_host_3d、gpu_submit_3d、gpu_set_scanout、gpu_device_info。
- **ABI 已稳定且版本化**：全部编号收敛到唯一规范清单 `src/user/shared/abi/syscall.rs`；`SYSCALL_ABI_VERSION_MAJOR/MINOR` 经 `RuntimeAbiInfo` 运行期上报；编号只追加；Stable (0-120) 冻结、Experimental (121-189) 分类，编译期/运行期测试锁定编号并断言注册表稠密覆盖。

**缺点：**

- **121-189 仍是 Experimental**：69 个槽位未冻结，跨主版本不保证稳定。
- **无外部工具链与符合性测试**：ABI 只在内核 crate 内部自洽，尚无独立工具链或 POSIX 一致性套件。

---

## 横切关注点

### 架构支持

| 特性 | x86_64 | AArch64 | RISC-V 64 |
|---------|--------|---------|-----------|
| 引导协议 | Multiboot2 / QEMU PVH | QEMU 直接 `-kernel` | QEMU 直接 `-kernel` |
| 中断控制器 | APIC + IOAPIC | GICv2/v3 | PLIC |
| 定时器 | APIC 定时器 | 通用定时器 | CLINT 定时器 |
| SMP | 完整（MADT + AP 启动） | 完整（spin-table + GIC SGI） | 完整（SBI HSM + FDT CPU 节点） |
| 上下文切换 | 完整 | 完整 | 完整 |
| PAN/SMAP | SMAP (stac/clac) | PSTATE.PAN (set/clear) | SUM (sstatus) |
| MSI/MSI-X | 完整（向量分配器 + 表编程） | 完整（GIC ITS，LPI） | — |
| PCIe | 完整 ECAM | 基本探测 | 基本探测 |
| ASID 分配器 | — | 完整（位图 + CAS） | 完整（位图 + CAS，65536 个 ASID） |
| FDT 解析 | — | 完整 | 完整 |
| RTC | — | 完整（来自 FDT） | 完整 |
| 串行 | 完整（UART 16550） | 完整（UART 16550） | UART 16550（SBI 回退） |
| NUMA 发现 | 完整（ACPI SRAT/SLIT） | 完整（FDT numa-node-id，distance-map） | 完整（FDT numa-node-id，distance-map） |
| CPU 频率缩放 | 完整（MSR P-state） | 完整（DT OPP） | 完整（DT OPP） |
| 代码大小 | 10,824 行 | 6,663 行 | 3,500+ 行 |

### 共享用户运行时（`src/user/shared/`）

| 模块 | 代码行数 | 用途 |
|--------|-------|---------|
| `syscall.rs` | 2,000+ | 55+ 个类型化系统调用包装器 |
| `dispatch.rs` | 1,500+ | ~40 个 Shell 内置命令（cat, ls, cp, mv, grep 等） |
| `commands/` | 2,000+ | 子命令实现 |
| `app/` | 400+ | 应用程序管理 |
| `version.rs` | 50+ | 自然版本号字符串比较 |
| `net.rs` | 519 | HTTP 客户端，获取辅助函数 |
| `signal.rs` | 150+ | 信号处理 API（u64 掩码，sigsuspend，SA_SIGINFO） |
| `crypto.rs` | 150+ | 加密辅助函数 |
| `passwd.rs` | 100+ | 密码文件解析 |
| `jobs.rs` | 100+ | 作业控制逻辑 |
| `abi/` | 500+ | ABI 类型定义 |
| `runtime.rs` | 550+ | 架构系统调用包装器，brk 分配器，参数 |

**总计：** 22 个模块，约 14,000 行，已并入内核 crate。

### 测试

| 类别 | 数量 | 覆盖率 |
|----------|--------|----------|
| 单元测试（模块内） | ~100+ | 因模块而异 |
| 集成测试文件 | 17 | 8,536 行 |
| 故障注入测试 | 1,245 行 | SimpleFs 单故障矩阵 |
| 恢复测试 | 1,163 行 | 崩溃 + 重放场景 |
| 并发测试 | 700+ 行 | 调度器、条件变量、控制台、键盘 |
| virtio-gpu 布局测试 | 10+ | 结构体大小/布局 + 命令 wire 格式（mock 设备）验证 |
| CI 工作流 | ✅ | GitHub Actions：fmt、check、build、clippy |
| 验证门 | P0–P3 | 多层：fmt → test → cross-build → clippy |

**2026-08-20 更新：** `demo-disk` 特性已在 QEMU 下的全部三个目标上端到端验证——交互式
shell（约 40 条内置命令）、演示负载（app-id/image/cwd/argv0/resume-1/resume-2，退出码
42），0 FATAL。RISC-V 64 用户 ABI 与演示 shell 已确认可用。主机端测试：**3,056 通过 /
0 失败**。

### 构建与开发

- **构建系统：** Cargo + Makefile（按架构验证目标）
- **布局：** 共享用户运行时与演示负载位于内核 crate 内，分别为 `src/user/shared/` 和 `src/user/demo/`
- **可选特性：** `demo-disk`，`fs_profiler`，`net_profiler`，`alloc_profiler`，`fault_profiler`，`educational_networking`
- **发布配置文件：** `panic = "abort"`，`opt-level = "s"`，`lto = true`，`codegen-units = 1`

---

## 缺点 / 已知缺口 (Weaknesses & Known Gaps)

- **模拟环境验证为主**：除 x86_64 外，AArch64/RISC-V 均在 QEMU 下验证；尚无裸机硬件 bring-up（见路线图中期"真实硬件启动"）。
- **RISC-V 64 仍为部分支持**：无 MSI/MSI-X（AIA）、PCIe 仅基本探测、无架构级 NMI 源。
- **用户态生态薄弱**：演示盘上的 ring3 程序（shell、demo-launcher、init.elf）为内联的 `exit(0)` 占位 ELF 桩，尚无真实应用与工具链。
- **单一维护者**：bus factor = 1，所有模块由一名维护者兼任。
- **实验性 syscall 未冻结**：槽位 121-189 分类为 Experimental。
- **无模糊测试**：ELF 加载器、文件系统镜像解析、网络包解析、LUKS2 头部尚无 fuzz 目标。
- **无可复现发布**：尚无带可复现 ISO/磁盘镜像与签名产物的标记版本。

---

## 此内核的独特之处

1. **11 个文件系统驱动程序** — FAT32、exFAT、ext4、F2FS、btrfs、XFS、NTFS、ISO 9660、EROFS、SquashFS + 原生 SimpleFs
2. **原生 TCP/IP 栈** 带有 TLS 1.3、SCTP 和 WireGuard VPN — 不是 lwIP/uIP 的移植；具有完整 TCP 拥塞控制、DNS 缓存、DHCP 的自定义实现
3. **三个架构目标** — x86_64、AArch64、RISC-V 64 — 所有三个架构上都具备 PAN/SMAP
4. **Biba 完整性模型** — 业余内核中的正式多级安全策略很罕见
5. **Unicode 15.1 NFC/NFD 规范化** + GB18030 编解码器 — 全面的国际化
6. **TLSF 堆分配器** — O(1) 有界时间分配/释放，640 个空闲列表
7. **`src/user/shared/`** — 共享 ABI 库，内核和用户空间都针对其编译，消除了 ABI 漂移
8. **抢占式多线程**，所有架构上都有保护页
9. **NUMA 感知帧分配、调度和 SRAT/FDT 发现** — 每节点帧分配器与 CPU 到节点映射，NUMA 感知工作窃取，以及通过 ACPI SRAT/SLIT（x86_64）和 FDT numa-node-id（AArch64、RISC-V）的自动拓扑发现
10. **virtio-gpu 加速显示与 VIRGL 3D 协议基础设施** — 提供 2D 模式设置和 VIRGL 3D 协议支持的 VirtIO GPU 驱动程序，作为 bochs-display 的替代方案
11. **MSI/MSI-X 和 GIC ITS 中断支持** — x86_64 上 NVMe 和 VirtIO PCI 驱动程序的向量分配和表编程，以及在 AArch64 上具有 LPI 配置的 GICv3 ITS 控制器
12. **每线程栈金丝雀** — 上下文切换时的软件实现金丝雀验证，用于运行时缓冲区溢出检测
13. **静态数据加密** — AES-256 XTS 模式，PBKDF2 密钥派生，LUKS2 头部解析，透明的 EncryptedBlockDevice 包装器
14. **ext4/XFS/F2FS 日志重放** — 真实磁盘日志恢复：撤销块、缓冲/inode/dquot 项、孤立恢复、SIT 持久化
15. **审计子系统** — 具有分类事件类型、环形缓冲区（8192 条目）和专用审计系统调用（#143-144）的系统调用审计
16. **SCTP 协议** — 完整的传输层实现，具有四次握手和 CRC32C 验证
17. **热插拔支持** — 通过 DeviceManager 生命周期进行 PCIe 插槽状态监控和 xHCI 端口状态变化轮询
18. **POSIX 定时器 (#137-140)** — timer_create/timer_settime/timer_gettime/timer_delete，具有每进程定时器管理和信号传递
19. **HDA 音频控制器驱动程序** — Intel HD Audio，具有 CORB/RIRB 引擎、编解码器发现和流描述符
20. **WireGuard VPN** — Noise_IKpsk2 握手状态机，ChaCha20-Poly1305 传输加密，会话密钥管理
21. **CPU 频率缩放与电源管理** — x86_64 MSR P-state 驱动（CPUID leaf 0x16 + PLATFORM_INFO 检测，HWP 处理，DTS 温度）+ aarch64/riscv64 DT OPP 范围发现与目标跟踪（`operating-points-v2` / legacy `operating-points`），5 种 governor，调度器 tick 集成，cpufreq 系统调用（#145-149）
22. **内存压缩与碎片整理** — zswap 式压缩页缓存（zero/RLE/LZSS 编码，16 MiB 预算）集成到回收路径，加上物理池整理：迁移可移动用户帧合并碎片化空闲区段；`CompactMemory` 系统调用（#150）
23. **NMI 处理 + SMP 中断负载均衡 + 中断统计** — x86_64 向量 2 / AArch64 SError-FIQ 专用 NMI 路径与处理器注册表；每 2 秒从最忙 CPU 迁移最热可迁移 IRQ（IOAPIC 重定向 / GIC SPI 亲和性 / PLIC 每上下文使能）；`SystemInfo` 类型 9 暴露每 CPU/每向量 IRQ、IPI、NMI 计数与负载均衡状态
24. **SimpleFs V4 数据缩减与扩展属性** — 原生文件系统上的持久 xattr 表（`setxattr`/`getxattr`/`listxattr`/`removexattr`，syscall #151-154）、每文件透明压缩（分块 LZSS/raw 编码，读取时按需解压）和跨文件内容去重（共享 extent + 挂载时重建引用计数 + copy-on-write 解共享）；通过 `set_file_flags`/`get_file_flags`（#155-156）切换与查询，全部在 V4 的 `pending_commit` 两阶段提交中崩溃安全
25. **DCCP 传输协议（RFC 4340）** — 连接导向的数据报传输：Request/Response/Ack 握手、9 状态机、48 位扩展序列号、选项与特征协商、CCID 2 拥塞控制（cwnd/ssthresh + Ack Vector）、服务码；完整 syscall API（bind/listen/connect/accept/send/recv/close，#157-163）
26. **IPsec（ESP + AH）** — RFC 4303/4302 数据平面变换：ESP 用 AES-GCM（RFC 4106）与 ChaCha20-Poly1305（RFC 7634）AEAD，AH 用 HMAC-SHA256-128（RFC 4868），传输/隧道双模式、IPv4/IPv6、64 位反重放窗口；手动 SAD/SPD 管理（syscall #164-168），隧道解封装有深度防护
27. **多播路由** — MFC/VIF 转发引擎（RPF + TTL 门控 + 计数器）、IGMPv2/MLDv1 路由器模式（成员跟踪、一般查询、超时）、MRT 管理 syscall（#169-174，仿 Linux mroute）；`educational_networking` 下的 PIM-DM 洪泛-剪枝控制面
28. **IPv6 边缘情况加固** — 路径 MTU 发现（RFC 8201，Packet Too Big → 每目的 PMTU 缓存 + TX 分片）、原子分片（RFC 6946）、扩展头链顺序与 7 头上限（RFC 8200 §4.1）、路由头类型 0 拒绝（RFC 5095）、重叠分片丢弃（RFC 5722）、RA MTU 选项

29. **MAC 类型强制引擎（SELinux/AppArmor 等价物）** — 超出 Biba 的强制访问控制：主体（进程）与对象（文件）安全类型、allow 规则策略（首匹配 + deny-by-default）、中心 VFS 钩子覆盖所有文件操作、Process 类（ptrace/信号）与 Network 类检查、exec 域转换（采纳二进制类型）、管理 syscall（#175-178）、拒绝时发出 MacDenial 审计记录
30. **凭证系统持久化** — `/data/etc/passwd` 与 `/data/etc/shadow` 原子写回（临时文件 + rename，崩溃不损坏）、shadow 每次保存后恢复 0600、删除用户时同步清理 shadow 条目
31. **fcntl 描述符控制 (#179)** — 完整的 POSIX fcntl 子集：F_DUPFD / F_GETFD / F_SETFD / F_GETFL / F_SETFL（O_NONBLOCK 逐端生效），加上 F_GETPIPE_SZ / F_SETPIPE_SZ 运行时调整管道缓冲区（按页取整、上限 1 MiB、数据保留），打破"管道大小固定"
32. **持久块缓存** — 每个脏块记录脏化时钟，调度器每滴答推进；超过 6 秒（600 滴答）的脏块每 3 秒由后台自动写回设备，`sync`（#180）提供按需全量落盘，使回写缓存无需显式 fsync 即可持久化
33. **设备树驱动的驱动程序探测** — 在 AArch64/RISC-V 上按 `compatible` 字符串把 FDT 节点绑定到驱动：`collect_dt_nodes` 建立节点表（compatible/reg/interrupts/phandle/status），`Driver::compatible_strings()/probe_dt()` 在 `DriverManager::probe_dt_devices` 中完成绑定；virtio-gpu/block/net 均按 DT 节点 `reg` 探测（GPU 由此在 AArch64/RISC-V 上可用），取代硬编码地址区间扫描
34. **VIRGL 3D 用户空间接口 (#181-189)** — 把 virtio-gpu 的 VIRGL 协议暴露给用户空间渲染器：上下文、3D 资源（内核 DMA 后端）、主机传输、命令提交、扫描输出与能力报告；真实 3D 渲染由宿主机 virglrenderer 执行，内核提供渲染器驱动的传输层（配有 mock 设备 wire 格式测试）
