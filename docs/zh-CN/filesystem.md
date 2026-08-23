# 文件系统架构

## 概述

文件系统层（`src/kernel/fs/`）提供了一个虚拟文件系统（VFS），用于挂载卷、解析路径，并向用户空间暴露统一的文件/目录/设备 I/O 接口。它支持多种磁盘格式（SimpleFs、ext4、FAT32、NTFS、btrfs、XFS、F2FS、EROFS、squashfs、iso9660）和内存伪文件系统（tmpfs、procfs、devfs）。主要的本地格式是 **SimpleFs**，一种为嵌入式用途设计的自定义轻量级文件系统。

---

## VFS 架构

### FileSystem 外观

顶层 `FileSystem` 结构体（`src/kernel/fs/mod.rs`）是一个单例，管理以下内容：

| 字段 | 用途 |
|---|---|
| `root: Arc<dyn VNode>` | 虚拟根节点（`/`） |
| `filesystems: BTreeMap<String, Arc<dyn VfsTrait>>` | 已注册的文件系统后端 |
| `block_devices: BTreeMap<String, Arc<dyn BlockDevice>>` | 已知块设备 |
| `mounted_fs: BTreeMap<String, MountPoint>` | 活动挂载点 |
| `current_working_dir: Mutex<String>` | 每会话 CWD |
| `next_handle: Mutex<u64>` | 单调文件句柄计数器 |
| `rootfs_type: String` | `"simplefs"` 或 `"ext4"` |

它存储在全局 `AtomicPtr<Mutex<FileSystem>>` 中，并通过 `global()` / `install_global()` 访问。初始化发生在 `filesystem/init.rs` 中的 `init_with_boot_disk()`，其过程为：

1. 解析引导块设备的 MBR 分区，或回退到固定区域偏移量。
2. 为每个区域（System/Apps/Data）打开 SimpleFs（或 ext4）卷。
3. 将它们注册为已挂载的文件系统。
4. 如果没有真实的引导磁盘，则回退到内存中的演示卷。

### 文件系统 trait

定义在 `src/kernel/fs/vfs/filesystem.rs` 中 —— 方法包括 `lookup()`、`stat()`、`read_dir()`、`rename()`、`create_file()`、`create_dir()`、`create_symlink()`、`create_device()`、`hard_link()`、`remove_path()`、`check_and_repair()`、`fs_profiler_snapshot()`、`list_xattrs()`、`update_security_descriptor()`。`StaticFileSystem` 提供了基于编译时条目的只读树 —— 用于 procfs、devfs 和类似的伪文件系统。

### VNode trait

定义在 `src/kernel/fs/vfs/vnode.rs` 中 —— 方法包括 `name()`、`kind()`（File | Directory | Device | Symlink）、`size()`、`metadata()`、`read()`、`write()`、`set_len()`、`readlink()`、`sync()`、`sync_data()`、`list_xattrs()`。所有文件系统对象都实现此 trait。

### 路径解析

路径规范化位于 `src/kernel/fs/path.rs`（`normalize_path`）。它生成绝对规范路径，不含 `.`/`..`/冗余斜杠，拒绝驱动器前缀（`C:`）和嵌入的控制字符。外观的 `normalize_path`（位于 `query.rs` 中）将其与当前工作目录封装在一起。

`filesystem/path_helpers.rs` 模块提供了挂载系统内部使用的工具函数：`matches_mount`、`direct_mount_child_name`、`join_normalized_child`、`parent_normalized_path`、`is_valid_child_name`。

### 挂载系统

挂载点记录在 `FileSystem::mounted_fs`（`BTreeMap<String, MountPoint>`）中，其中每个 `MountPoint`（`src/kernel/fs/filesystem/types.rs`）包含 `fs: Arc<dyn VfsTrait>`、`fs_name`、`device` 和 `flags`（`MOUNT_READ_ONLY=1`、`MOUNT_EXECUTABLE=2`、`MOUNT_USER_DATA=4` 的位掩码，定义于 `layout.rs`）。`mount()` 规范化目标路径，按名称查找文件系统，并插入挂载点。`unmount()` 将其移除。

内置的虚拟挂载点如下：

| 挂载路径 | 设备 | 后端 |
|---|---|---|
| `/system` | `/dev/protofire-system` | SimpleFs（只读） |
| `/apps` | `/dev/protofire-apps` | SimpleFs（可执行） |
| `/data` | `/dev/protofire-data` | SimpleFs（用户数据） |
| `/tmp` | `/dev/protofire-temp` | SimpleFs（可写临时空间） |
| `/proc` | — | StaticFileSystem |
| `/dev` | — | StaticFileSystem（设备节点） |
| `/system/dev` | — | 虚拟设备 FS |
| `/system/logs` | — | 内核日志 FS |

---

## SimpleFs —— 磁盘格式

源代码：`src/kernel/fs/simplefs/`。SimpleFs 是一个自定义的嵌入式文件系统，采用固定块布局、双超级块设计以及基于撤销日志的事务机制。

### 格式版本

- **V2**：32 字节 inode、64 字节目录项，数据校验和位于字节 28。
- **V3**（`V3PersistentSecurityDescriptors`）：重用字节 24..31 作为 `owner_uid`/`owner_gid` —— 持久安全描述符取代了 V2 校验和字段。支持待处理提交两阶段协议以实现崩溃安全。

### 超级块

每个 SimpleFs 卷有两个超级块副本（块 0 和块 1），定义在 `constants.rs` 中：

```
块 0：主超级块
  [0..8)    魔数："ADAFS1\0\0"
  [24..28)  活动 inode 表块
  [28..32)  活动目录项表块
  [32..36)  数据块起始
  [36..40)  影子 inode 表块
  [40..44)  影子目录项表块
  [44..48)  Inode 表块数
  [48..52)  目录项表块数
  [52..56)  代际编号
  [56..64)  校验和
  [64..96)  卷标签（32 字节）
  [96..100) 待处理提交标记（V3+）
块 1：次超级块（相同布局）
```

解析通过 `SimpleFs::open()` 在 `superblock.rs` 中进行。活动/影子表对实现了原子元数据更新。

### 区域布局（layout.rs）

磁盘被划分为多个区域，每个区域是一个 SimpleFs 卷：

```
+--------+--------+--------+--------+--------+
| MBR    | System |  Apps  |  Data  | Temp   |
| 扇区   |  (256) | (1536) | (2048) | (128)  |
+--------+--------+--------+--------+--------+
0        2048     2304     3840     5888     6016  块
```

`StorageZone` 枚举将每个区域映射到其根路径、文件系统名称、设备路径、挂载标志和 MBR 分区类型：

| 区域 | 根路径 | MBR 类型 | 标志 | 大小写敏感 |
|---|---|---|---|---|
| System | `/system` | 0xa1 | 只读 | 是 |
| Apps | `/apps` | 0xa2 | 可执行 | 是 |
| Data | `/data` | 0xa3 | 用户数据 | 否 |

### Inode 和目录项

32 字节 `OnDiskInode`（`types.rs`）：`kind`、`deleted`、`entry_start`（目录的目录项表起始）、`entry_count`、`data_block`、`block_count`、`size`、`persistent_security`（V3）、`data_checksum`（V2）。

64 字节 `OnDiskDirEntry`（`types.rs`）：`inode_index`、`kind`、`name`（56 字节内嵌）。

### ImageEntry

镜像构建器使用 `ImageEntry`（`src/kernel/fs/simplefs/mod.rs`）：`{ path: &str, data: &[u8] }`，用于 `SimpleFs::build_image()` 和 `build_image_with_headroom()`。

---

## 块层

### BLOCK_SIZE

`src/kernel/fs/block.rs` 定义了 `BLOCK_SIZE = 512`。所有块 I/O 以该值的倍数为单位进行操作。

### BlockDevice trait

`src/kernel/fs/block.rs` —— 关键方法：`name()`、`block_size()`（默认 512）、`block_count()`、`is_read_only()`、`read_blocks(lba, buffer)`、`write_blocks(lba, data)`、`flush()`、`device_health()`（返回 `Healthy` | `Degraded` | `Failed`）。

两个具体实现：

- **`MemoryBlockDevice`**（`block.rs`）：内存中的 `Vec<u8>` 存储，自动填充到块边界。用于演示磁盘和测试。
- **`BlockSliceDevice`**（`block.rs`）：父设备的子范围 —— 在偏移 `start_block` 处委托读写操作。用于分区切片。

### BlockCache

`src/kernel/fs/block_cache.rs` 提供了一个 128 槽位的 LRU 缓存，具有以下功能：

- **写透（元数据）**：`write_through()` 持久化到设备并更新缓存。
- **写回（文件数据）**：`write_back()` 标记脏数据；`flush()` 写入设备。
- **预读**：可选顺序预取（可配置深度），用于文件读取。
- **干净优先驱逐**：驱逐策略始终优先选择干净条目；如果所有条目都是脏的，则 LRU 脏条目在驱逐前被刷新。

统计数据通过 `CacheStats`（命中、未命中、驱逐、脏写回、预取）进行跟踪。

SimpleFs 通过 `cached_read_blocks()` 和 `write_blocks_cached()`（元数据写入，立即持久化到设备并填充干净缓存）以及 `write_blocks_cached_wb()`（延迟数据写入）来使用该缓存。

---

## 分区表解析

`src/kernel/fs/partition.rs` 通过 `read_mbr_partitions()` 实现标准 MBR 解析，该函数读取块 0，验证 0x55AA 签名，解析偏移量 446 处的四个分区条目（每个 `MbrPartitionEntry`：`bootable`、`partition_type`、`start_block`、`block_count`），检查重叠，并返回 `Option<MbrPartitionTable>`。LBA 字段为 32 位（最大 ~2 TiB）。分区类型 0xa1/0xa2/0xa3 标识 protofire 区域。`write_mbr_partitions()` 序列化到扇区缓冲区。

---

## 事务 / 恢复

源代码：`src/kernel/fs/simplefs/transaction.rs`。

### 撤销日志事务

所有 SimpleFs 元数据变更都在撤销日志事务内执行。流程如下：

1. `SimpleFsState::begin_undo()` 快照脏标志。
2. 对于每个变更，保存当前值（`save_inode_for_undo`、`save_dirent_for_undo`、`save_free_extents_for_undo` 等）。
3. `rollback_undo()` 以后进先出的顺序恢复所有保存的值 —— 这对于移动数组的插入/删除操作至关重要。
4. `commit_undo()` 在成功时丢弃日志。

### TransactionContext

`TransactionContext` 提供了批量元数据变更的方法（`create_dir`、`create_dir_with_security`、`remove_path`、`update_security_descriptor`），这些方法都在锁定的内存状态上操作，并原子地刷新。

### 两阶段提交（V3）

V3 超级块包含一个 `pending_commit` 字段（偏移量 96）。在元数据刷新之前：

1. 将 `pending_commit` 设置为磁盘上的目标代际编号。
2. 将元数据表（inode + 目录项）写入影子块。
3. 翻转超级块，使活动/影子表互换。
4. 清除 `pending_commit`。

挂载时，非零的 `pending_commit` 表示提交中断 —— 由 `check_and_repair()` 检测，该函数清除过时的标记并通过 `RuntimeHealthSnapshot` 验证表的一致性。

### VolumeCheckReport

由 `check_and_repair()` 返回（`src/kernel/fs/vfs/types.rs`）：跟踪 `issues_detected`、`repairs_applied`、`orphan_data_blocks`、`checksum_failures`、`staging_orphans_cleaned`、`orphan_blocks_cleaned` 和 `interrupted_commits`。

---

## 文件系统操作

所有操作都通过 `FileSystem` 外观进行调度，该外观规范化路径、解析挂载点并委托给后端。

### open / create_file

`src/kernel/fs/filesystem/open.rs`。`create_file_normalized_with_security_token()` 实现了三种处置方式：

| 常量 | 值 | 行为 |
|---|---|---|
| `OPEN_EXISTING` | 0 | 打开现有文件；不存在则报错 |
| `CREATE_NEW` | 1 | 创建新文件；已存在则报错 |
| `OPEN_ALWAYS` | 2 | 打开现有文件或创建新文件 |

返回一个 `FileHandle`，包含位置、安全描述符、挂载标志和共享模式。

### FileHandle

`src/kernel/fs/handle.rs`。将 `Arc<dyn VNode>` 与游标位置和安全上下文封装在一起：

- `read()` / `write()`：委托给当前位置的 `VNode`，并前进游标。
- `seek()`：支持 `SEEK_SET`（0）、`SEEK_CUR`（1）、`SEEK_END`（2）。
- `set_len()`：截断或扩展；钳制游标。
- `sync()` / `sync_data()`：刷新到稳定存储。

### read / write / replace

`src/kernel/fs/filesystem/io.rs`。外观的 `read()` 和 `write()` 转发到 `FileHandle::read`/`write`。`replace_file_contents_normalized_with_security_token()` 以 `OPEN_ALWAYS` 方式打开文件、截断、写入并验证字节数。

### stat / read_dir / query

`src/kernel/fs/filesystem/query.rs`：

- `stat_normalized_path()`：将后端元数据与挂载级别的安全信息和叠加层合并。
- `read_dir()`：将后端的目录项与跨挂载子项合并。
- `mount_points()` / `block_devices()`：枚举活动挂载点和已知块设备。
- `fs_profiler_snapshot()`：聚合所有卷的操作计数器。

### mkdir / rm

`src/kernel/fs/filesystem/dir.rs`：

- `create_dir()` / `create_dir_from()`：规范化路径，委托给后端。
- `remove_path()` / `remove_path_from()`：规范化路径，委托给后端。
- `remove_normalized_path_if_exists_with_security_token()`：忽略 `NotFound` 错误。

### rename

`src/kernel/fs/filesystem/rename.rs`：

- `rename_path()` / `rename_path_from()`：规范化两个路径，解析到同一挂载点，授权，并调用后端的 `FileSystem::rename()`。

---

## 管道支持

`src/kernel/fs/pipe.rs` 实现了匿名管道，作为一对共享环形缓冲区的 `VNode`。

**关键类型：**

| 类型 | 角色 |
|---|---|
| `PipeRing` | 固定容量环形字节缓冲区（默认 16 KiB） |
| `PipeChannel` | 共享状态：`Mutex<PipeRing>` + 读/写 `Condvar` |
| `PipeReadEnd` | 支持 `read()` 的 `VNode`；在 `write()` 时返回 `PermissionDenied` |
| `PipeWriteEnd` | 支持 `write()` 的 `VNode`；在 `read()` 时返回 `PermissionDenied` |

**阻塞语义：**

- 读入者在缓冲区为空时阻塞在 `read_wait` 上；写入者在插入数据后唤醒读入者。
- 写入者在缓冲区已满时阻塞在 `write_wait` 上；读入者在消耗数据后唤醒写入者。
- 丢弃 `PipeWriteEnd` 会设置 `write_closed`，唤醒读入者，并且 `read()` 返回 0（EOF）。
- 丢弃 `PipeReadEnd` 会设置 `read_closed`，唤醒写入者，并且 `write()` 返回 `DeviceError`。

通过 `pipe_channel()`（16 KiB 默认）或 `pipe_channel_with_capacity(n)` 创建。

---

## FUSE（设计 / 推迟实现）

`src/kernel/fs/fuse/mod.rs` 包含 minimal FUSE 框架的设计文档和公开类型存根。实现子模块（尚未构建）：

- `protocol.rs`：线路格式（`FuseHeader` + TLV 载荷）
- `connection.rs`：`FuseConnection` —— 每挂载点管道对 + 顺序调度
- `filesystem.rs`：`FuseFileSystem` —— 通过管道转发实现 `FileSystem` trait
- `vnode.rs`：`FuseVNode` —— 远程 inode 号的轻量级封装
- `error.rs`：`FuseError` 到内核 `Error` 的映射

**协议**：24 字节头部（`seq: u64`、`opcode: u32`、`ino: u64`、`payload_len: u32`），后跟特定操作码的载荷。操作码包括 LOOKUP、STAT、READ、WRITE、READDIR、CREATE、REMOVE、CREATE_DIR、RENAME、SET_LEN、FLUSH、ERROR。顺序调度（阶段 1）避免了线程复杂性。

---

## 关键文件参考

| 文件 | 用途 |
|---|---|
| `src/kernel/fs/mod.rs` | 顶层外观、重导出、全局单例 |
| `src/kernel/fs/vfs/filesystem.rs` | `FileSystem` trait、`StaticFileSystem` |
| `src/kernel/fs/vfs/vnode.rs` | `VNode` trait、`StaticVNode` |
| `src/kernel/fs/vfs/types.rs` | `NodeKind`、`Metadata`、`SecurityDescriptor`、`DirectoryEntry`、`VolumeCheckReport` |
| `src/kernel/fs/filesystem/{init,mount,open,io,dir,rename}.rs` | VFS 操作（初始化、挂载、打开、读写、mkdir/rm、重命名） |
| `src/kernel/fs/filesystem/{path_helpers,resolve,overlay}.rs` | 路径解析、挂载点解析、跨挂载目录叠加 |
| `src/kernel/fs/filesystem/{security,security_helpers}.rs` | 访问控制和安全描述符授权 |
| `src/kernel/fs/filesystem/types.rs` | `MountPoint`、`MountInfo`、`StorageInitReport` |
| `src/kernel/fs/filesystem/profiler.rs` | `FsProfiler` —— 操作计数器 |
| `src/kernel/fs/path.rs` | `normalize_path()` —— 规范路径规范化 |
| `src/kernel/fs/block.rs` | `BlockDevice` trait、`MemoryBlockDevice`、`BlockSliceDevice`、`BLOCK_SIZE` |
| `src/kernel/fs/block_cache.rs` | `BlockCache` —— 128 槽位 LRU 缓存，支持写透/写回 |
| `src/kernel/fs/partition.rs` | MBR 分区表解析/写入 |
| `src/kernel/fs/layout.rs` | `StorageZone` 枚举、挂载标志、区域块范围 |
| `src/kernel/fs/handle.rs` | `FileHandle` —— 打开的文件描述符 |
| `src/kernel/fs/pipe.rs` | 匿名管道（`pipe_channel()`、`PipeReadEnd`、`PipeWriteEnd`） |
| `src/kernel/fs/simplefs/mod.rs` | `SimpleFs`、`SimpleFsState`、`UndoLog`、`ImageEntry` |
| `src/kernel/fs/simplefs/{superblock,types,constants}.rs` | 磁盘格式：超级块、`OnDiskInode`、`OnDiskDirEntry`、几何布局 |
| `src/kernel/fs/simplefs/transaction.rs` | 撤销日志事务、`TransactionContext` |
| `src/kernel/fs/simplefs/image_staging.rs` | `SimpleFs::build_image()`、`build_image_with_headroom()` |
| `src/kernel/fs/simplefs/{vfs,file_io,dir_ops,inode_dirent}.rs` | SimpleFs VFS trait 实现、数据 I/O、目录项操作、磁盘序列化 |
| `src/kernel/fs/fuse/mod.rs` | FUSE 设计文档、协议类型（`FuseOpcode`、`FuseHeader`） |
| `src/kernel/fs/demo.rs` | 遗留演示磁盘构建器（区域镜像、MBR 布局） |
| `src/kernel/fs/test_support.rs` | `build_test_zone_image()`、`build_minimal_test_zone_image()` |

---

## 参见

- [子系统概述](../en/filesystem.md) —— 高层 VFS 和 SimpleFs 描述
- [文档索引](../README.md) —— 完整文档树
