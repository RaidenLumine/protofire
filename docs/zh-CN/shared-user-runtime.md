# 共享用户运行时 — `src/user/shared/`

## 目的

`src/user/shared/` 是一个 `#![no_std]` 兼容的模块，定义了 **内核与用户空间程序之间的 ABI 边界**：

- **在内核中** — 内建 shell 使用该模块进行命令分发、分词和 shell 逻辑。
- **在 ring3 二进制文件中** — 独立运行时（本仓库未构建）可以链接内核 crate 并启用 `runtime` 特性，以获取系统调用桥接、`BrkAllocator` 和信号处理。

该模块位于内核 crate 内的 `src/user/shared/` 目录。

### 关键设计约束

所有模块仅依赖 `alloc`（`core` + `alloc` crate 对）。没有 `std`，没有平台相关的 libc。这使得同一份代码可以编译进内核映像，并在启用 `runtime` 特性时编译进独立的 ring3 ELF 二进制文件。

---

## 模块映射

来源：`src/user/shared/mod.rs`

该模块导出以下公开子模块：

| 模块 | 文件 | 职责 |
|---|---|---|
| `abi` | `abi/mod.rs` | `#[repr(C)]` 的 ABI 记录类型，在内核/用户空间边界共享 |
| `commands` | `commands/mod.rs` | 约 45 个 shell 内建命令的实现 |
| `control_flow` | `control_flow.rs` | `if`/`for`/`while` 的解析和执行 |
| `crypto` | `crypto.rs` | 加密原语（哈希、随机数） |
| `dispatch` | `dispatch.rs` | 命令名到函数的调度表 |
| `expand` | `expand.rs` | 环境变量展开（`$VAR`、`${VAR}`） |
| `glob` | `glob.rs` | 通配符模式匹配（`*`、`?`、`[...]` 字符类） |
| `history` | `history.rs` | 命令历史：添加、展开、公共前缀搜索 |
| `jobs` | `jobs.rs` | 后台任务跟踪 |
| `version` | `version.rs` | 自然版本号字符串比较（`compare_natural_version_strings`） |
| `net` | `net.rs` | HTTP/1.1 客户端（URL 解析、GET 获取）、TCP 服务器框架 |
| `passwd` | `passwd.rs` | 极简的 `/data/etc/passwd` 文件解析器 |
| `path_util` | `path_util.rs` | `resolve_path()` 和 `normalize_path_segments()` |
| `pipeline` | `pipeline.rs` | `&&` / `||` 条件链接、管道拆分、重定向解析 |
| `runtime` | `runtime.rs` | 架构相关的系统调用桥接、`BrkAllocator`、参数解析、panic 处理 |
| `signal` | `signal.rs` | 协作式信号处理：等待、发送、屏蔽 (u64)、sigsuspend、分发循环 |
| `syscall` | `syscall.rs` | `SYS_*` 常量（约 80 个系统调用号）+ `sys_*()` 类型化封装（约 50 个函数） |
| `tokenizer` | `tokenizer.rs` | Shell 单词分词器（引号、转义、空白符） |
| `types` | `types.rs` | `CmdResult` — 所有 shell 命令的结构化返回类型 |

---

## 系统调用封装 (`syscall.rs`)

文件：`src/user/shared/syscall.rs`

该模块提供两层抽象：

### 第一层 — 原始入口点

七个 `extern "Rust"` 函数（`__shell_syscall0` 到 `__shell_syscall6`），由运行环境实现：

```rust
extern "Rust" {
    fn __shell_syscall3(number: usize, a0: usize, a1: usize, a2: usize) -> isize;
    // ... 0 参数到 6 参数的变体
}
```

- **在内核中**：声明由 `src/user/program/shell/syscall_bridge.rs` 满足，连接到 `UserSyscall` + `syscall::dispatch()`。
- **在 ring3 二进制文件中**：`runtime` 模块提供 `#[no_mangle]` 的实现（通过 `runtime` 特性），发出 `int 0x80`（x86_64）或 `svc #0`（AArch64）指令。
- **在宿主机测试中**：相同的 `#[no_mangle]` 内核桥接满足 extern 声明 — 无需单独的测试桩。

`decode()` 辅助函数转换原始的 `isize` 返回值：负数表示错误，非负数为成功值。

### 第二层 — 类型化封装函数

每个封装函数遵循以下模式：

```rust
pub fn sys_open(path: &str, flags: usize) -> Result<usize, isize>
```

函数对字符串参数接受 `&str`，返回 `Result<usize, isize>` 或 `Result<(), isize>`。调用者模式始终是将 `path.as_ptr() as usize, path.len()` 作为两个独立的参数传递。

### 系统调用号常量

定义了多个 `SYS_*` 常量，涵盖以下类别：

| 类别 | 示例 |
|---|---|
| **文件 I/O** | `SYS_OPEN` (2)、`SYS_READ` (5)、`SYS_WRITE` (6)、`SYS_CLOSE` (7)、`SYS_STAT` (27)、`SYS_READ_DIR` (28)、`SYS_SET_LENGTH` (20) |
| **文件系统** | `SYS_CURRENT_DIR` (14)、`SYS_CREATE_DIR` (19)、`SYS_REMOVE_PATH` (21)、`SYS_RENAME` (29) |
| **进程** | `SYS_SPAWN_PROCESS` (25)、`SYS_EXIT` (3)、`SYS_WAIT_PROCESS` (24)、`SYS_GETPID` (81)、`SYS_GETPPID` (82) |
| **网络** | `SYS_NETWORK_STATUS` (37)、`SYS_CONNECT_TCP` (38)、`SYS_LISTEN_TCP` (56)、`SYS_ACCEPT_TCP` (57)、`SYS_BIND_UDP` (58)、`SYS_SENDTO_UDP` (59)、`SYS_RECVFROM_UDP` (60)、`SYS_RESOLVE_HOSTNAME` (93)、`SYS_CREATE_RAW_SOCKET` (76) |
| **内存** | `SYS_BRK` (92)、`SYS_SHMGET` (100)、`SYS_SHMAT` (101)、`SYS_SHMDT` (102)、`SYS_SHMCTL` (103) |
| **安全** | `SYS_ACCESS_QUERY` (42)、`SYS_PERMISSION_METADATA` (45)、`SYS_SET_SECURITY_DESCRIPTOR` (88)、`SYS_ADD_USER` (89)、`SYS_REMOVE_USER` (90)、`SYS_SET_USER_PASSWORD` (91) |
| **信号** | `SYS_SEND_SIGNAL` (40)、`SYS_WAIT_SIGNAL` (41)、`SYS_SET_SIGNAL_MASK` (94)、`SYS_SET_SIGNAL_HANDLER` (104)、`SYS_SIGSUSPEND` (135)、`SYS_RESTART_SYSCALL` (136) |
| **诊断** | `SYS_LIST_PROCESSES` (50)、`SYS_LIST_THREADS` (51)、`SYS_KERNEL_LOG` (52)、`SYS_SYSTEM_INFO` (53)、`SYS_LIST_MOUNTS` (86)、`SYS_LIST_BLOCK_DEVICES` (87)、`SYS_REPAIR_VOLUME` (95) |
| **Unix 域套接字** | `SYS_BIND_LOCAL` (97)、`SYS_CONNECT_LOCAL` (98)、`SYS_ACCEPT_LOCAL` (99) |

特殊用途的辅助函数包括：返回 `VolumeRepairReport` 结构体的 `sys_repair_volume()`、带有 `PollFd` 结构体的 `sys_poll()`，以及 `fn(sys_exit(code: usize) -> !`（永不返回）的 `sys_exit()`。

### 网络状态标志

```rust
pub const NETWORK_STATUS_FLAG_AVAILABLE: u32 = 1 << 0;
pub const NETWORK_STATUS_FLAG_TCP_CONNECT: u32 = 1 << 2;
pub const NETWORK_STATUS_FLAG_STREAM_IO: u32 = 1 << 3;
pub const NETWORK_STATUS_FLAG_TCP_LISTEN: u32 = 1 << 6;
pub const NETWORK_STATUS_FLAG_IPV6: u32 = 1 << 8;
// ... 以及其他标志
```

函数 `network_supports_tcp_stream_transport()` 检查基于 TCP 的 HTTP 下载所需的最小能力集。

---

## ABI 类型 (`abi/`)

文件：`src/user/shared/abi/mod.rs`

五个子模块，全部为 `#[repr(C)]` — 布局必须在不同内核版本之间保持二进制稳定：

### `abi/fs.rs` — 文件系统 ABI

| 类型 | 大小 | 用途 |
|---|---|---|
| `FileStat` | 16 字节 | `kind`（0=未知、1=目录、2=文件、3=设备、4=符号链接）+ `size` |
| `AccessQueryRecord` | 8 字节 | `required_access`、`granted_mode_bits`、`flags` |
| `PermissionMetadataRecord` | 12 字节 | `owner_uid`、`owner_gid`、`mode`、`reserved` |
| `DirectoryEntryRecord` | 32 字节 | `read_dir` 的头信息：`kind`、`size`、`name_offset`、`name_len` |
| `MountInfoRecord` | 356 字节 | `path[256]`、`fs_name[32]`、`device[64]`、`flags` |
| `BlockDeviceInfoRecord` | 88 字节 | `name[64]`、`block_size`、`block_count`、`read_only` |

常量：`FILE_KIND_DIRECTORY`、`FILE_KIND_FILE`、`FILE_KIND_DEVICE`、`AT_FDCWD`、`OPEN_FLAG_READ`、`OPEN_FLAG_WRITE`、`OPEN_FLAG_CREATE` 以及访问位标志。

### `abi/process.rs` — 进程 ABI

| 类型 | 大小 | 用途 |
|---|---|---|
| `ProcessTerminationRecord` | 40 字节 | `kind`（exit/exception/none）、`status`、`vector`、`error_code`、`fault_address` |
| `ProcessSignalRecord` | 24 字节 | `signal`、`sender_pid`、`payload` |
| `ProcessSpawnOptions` | 56 字节 | 启动选项：`flags`、`argv`、`argc`、`env`、`envc`、`working_dir` |
| `ProcessSpawnStringRef` | 16 字节 | `ptr`、`len` — spawn 选项中的字符串描述符 |

Spawn 标志：`PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS`、`PROCESS_SPAWN_FLAG_INHERIT_STDIO`、`PROCESS_SPAWN_FLAG_INHERIT_FDS`、`PROCESS_SPAWN_FLAG_START_SUSPENDED` 等。

### `abi/io.rs` — I/O ABI

打开标志：`OPEN_FLAG_READ` (1)、`OPEN_FLAG_WRITE` (2)、`OPEN_FLAG_CREATE` (4) 及其组合。

### `abi/shm.rs` — 共享内存 ABI

`ShmInfo` 结构体和 IPC 常量：`IPC_PRIVATE`、`IPC_CREAT`、`IPC_EXCL`、`IPC_RMID`、`IPC_STAT`、`IPC_SET`、`SHM_RDONLY`。

### `abi/diagnostic.rs` — 诊断 ABI

用于系统内省的记录类型：
- `ProcessInfoRecord` — `pid`、`ppid`、`name[64]`、`state`、`thread_count`、`priority`、`cpu_ticks`
- `ThreadInfoRecord` — `tid`、`priority`、`cpu_ticks`、`state`
- `SystemInfoRecord` — 调度器计数器（运行时间、分发、抢占等）
- `AllocProfilerRecord` — 堆和帧分配器计数器
- `FaultProfilerRecord` — 缺页异常、异常和终止计数器
- `FsProfilerRecord` / `NetProfilerRecord` / `PerCpuRecord` — 各子系统的统计信息
- `BootReportRecord` — 启动时间、物理内存、子系统初始化状态
- `SystemHealthRecord` — 聚合的健康计数器
- `FaultRecordAbi` — 供 ring3 使用的异常详情

状态常量：`PROCESS_STATE_READY`、`PROCESS_STATE_RUNNING`、`PROCESS_STATE_WAITING`、`THREAD_STATE_*`、`THREAD_PRIORITY_*`。系统信息选择器：`SYSTEM_INFO_SCHEDULER` (0) 到 `SYSTEM_INFO_PER_CPU` (8)。

---

## 运行时 (`runtime.rs`)

文件：`src/user/shared/runtime.rs`

该模块提供了独立 ring3 二进制文件所需的裸机运行时，受 `feature = "runtime"` 特性门控制。在内核构建中该特性关闭（内核在 `syscall_bridge.rs` 中提供自己的 `#[no_mangle]` 桥接）。

### 架构相关的系统调用 (`runtime::arch`)

两种实现，由 `#[cfg(target_arch)]` 选择：

```
x86_64:
  inlateout("rax") number => status
  in("rdi") arg0, in("rsi") arg1, in("rdx") arg2
  in("rcx") arg3, in("r8") arg4, in("r9") arg5
  int 0x80

AArch64:
  in("x8") number
  inlateout("x0") arg0 => status
  in("x1") arg1 ... in("x5") arg5
  svc #0
```

每个架构模块提供：`syscall_raw()`、`exit()`、`write()`、`read()`、`current_dir()`、`arg_count()`、`arg_value()`、`brk()`。

### 系统调用桥接 (`__shell_syscall0`..`__shell_syscall6`)

`#[no_mangle] extern "Rust"` 函数，实现了 `syscall.rs` 中声明的符号。这些函数在 `runtime.rs` 中只编译一次，而不是在每个 ring3 二进制文件中重复。`decode_for_bridge()` 辅助函数将内核的 `Error` 枚举编码映射为负的 `isize` 值：

| 内核错误 | `isize` |
|---|---|
| `InvalidArgument` | -1 |
| `NotFound` | -2 |
| `AlreadyExists` | -3 |
| `PermissionDenied` | -4 |
| `OutOfMemory` | -5 |
| `DeviceError` | -6 |
| `Busy` | -7 |
| `TimedOut` | -8 |
| `Unsupported` | -9 |
| `NotImplemented` | -10 |
| `InternalError` | -11 |
| `InvalidCredential` | -12 |

### BrkAllocator

一个简单的 bump 分配器，由 `brk` 系统调用支持：

```rust
pub struct BrkAllocator {
    current: AtomicUsize,
}

unsafe impl GlobalAlloc for BrkAllocator { ... }
```

- 首次分配查询当前程序断点（默认为 0x40_2000）。
- 后续分配将断点向上推进。
- `dealloc()` 为空操作 — 内存从不归还给内核。

### 参数解析

`read_argv()` 通过 `SYS_ARG_COUNT` / `SYS_ARG_VALUE` 系统调用读取进程参数，返回 `Vec<String>`。`read_cwd()` 读取当前工作目录，返回 `String`。

### Panic 处理辅助函数

`write_panic(prefix, info)` 将格式化的 panic 消息写入标准输出，并调用 `arch::exit(2)`。每个 ring3 二进制文件的 `#[panic_handler]` 都委托给此函数。

---

## Shell 分发 (`dispatch.rs`)

文件：`src/user/shared/dispatch.rs`

两个入口点：

```rust
pub fn dispatch_single_command(cmd_line: &str, ...) -> CmdResult
pub fn dispatch_tokens(tokens: &[String], ...) -> CmdResult
```

`dispatch_single_command` 首先对输入行进行分词，然后调用 `dispatch_tokens`。`dispatch_tokens` 接受已预分词的 argv，供自行执行别名/通配符展开的调用者使用。

调度表将命令名称与 `commands/` 中的 `cmd_*` 函数匹配。未知命令返回退出码 127。

状态通过参数显式传递（无全局变量），使得分发在 ring0（内核 `Mutex` 静态变量）和 ring3（局部变量）中工作方式完全相同：

```rust
pub fn dispatch_single_command(
    cmd_line: &str,
    cwd: &mut String,
    stdin: Option<&str>,
    home_dir: Option<&str>,
    env_vars: &mut Vec<(String, String)>,
    aliases: &mut Vec<(String, String)>,
    history: &[String],
    positional_params: &mut Vec<String>,
    source_depth: &mut u32,
    read_line_fn: impl FnMut() -> Option<String>,
    exec_fn: impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult
```

`SOURCE_MAX_DEPTH` (16) 防止 `source` 命令的无限递归。

### 命令实现 (`commands/`)

文件：`src/user/shared/commands/mod.rs`

约 45 个内建命令，按子模块组织：

**`commands/fs.rs`** — 文件系统命令：`cmd_pwd`、`cmd_cd`、`cmd_ls`、`cmd_cat`、`cmd_mkdir`、`cmd_rm`、`cmd_touch`、`cmd_cp`、`cmd_mv`、`cmd_chmod`、`cmd_du`、`cmd_df`。

**`commands/text.rs`** — 文本处理：`cmd_grep`、`cmd_find`、`cmd_head`、`cmd_tail`、`cmd_wc`、`cmd_sort`、`cmd_uniq`、`cmd_diff`、`cmd_edit`、`cmd_hexdump`。

**`commands/system.rs`** — 系统命令：`cmd_help`、`cmd_echo`、`cmd_clear`、`cmd_sleep`、`cmd_sysinfo`、`cmd_top`、`cmd_dmesg`、`cmd_uname`、`cmd_uptime`、`cmd_test`。

**`commands/process.rs`** — 进程命令：`cmd_ps`、`cmd_kill`、`cmd_true`、`cmd_false`。

**`commands/state.rs`** — Shell 状态：`cmd_export`、`cmd_alias`、`cmd_history`、`cmd_read`、`cmd_shift`、`cmd_source`。

**`commands/perf.rs`** — `cmd_perf`。

所有命令返回 `CmdResult`（定义在 `types.rs` 中）：

```rust
pub struct CmdResult {
    pub exit_code: i32,
    pub output: String,
}
```

---

## 包管理

包管理不属于内核职责。Linux 内核本身不包含包管理器（apt/dnf/pacman 全在用户态），
内核只提供从路径加载程序的 exec 原语。因此 protofire 的包管理器（安装/卸载/升级/回滚、
远程仓库、事务日志、文件关联、签名密钥、appctl/app-center）已从内核 crate 中移除。
内核保留的启动链路为 `/apps/current → /apps/catalog → /apps/packages → ELF`，
实现位于 `crate::user::program::launch_reference`。

---

## 信号处理 (`signal.rs`)

文件：`src/user/shared/signal.rs`

### 协作式信号模型

内核以 **协作** 方式传递信号：进程必须显式调用 `wait_signal()` 才能接收下一个待处理信号。不存在异步抢占。

### 信号掩码

信号掩码现在是一个 **64 位** 位域（`u64`），支持最多 64 个信号槽位。
内核当前使用槽位 0-42，包括 11 个实时信号（SIGRTMIN=32 到 SIGRTMAX=42）。

核心 API：

| 函数 | 描述 |
|---|---|
| `wait_signal(timeout_ticks)` | `Option<ProcessSignalRecord>` — 最多阻塞 `WAIT_FOREVER` 个 tick，或传入 `0` 进行轮询 |
| `wait_signal_forever()` | 无限阻塞，返回下一个信号记录 |
| `poll_signal()` | 非阻塞检查待处理信号 |
| `send_signal(pid, signal, payload)` | `Result<(), isize>` — 发送信号 |
| `sigsuspend(mask)` | `Result<(), isize>` — 原子设置掩码并挂起（系统调用 #135） |
| `set_signal_mask(mask)` / `signal_mask()` | 获取/设置 **64 位** 信号掩码 |
| `block_signal(signal)` / `unblock_signal(signal)` | 便捷的掩码辅助函数 |
| `signal_dispatch_loop(handlers)` | `!` — 无限循环，分发到注册的处理函数 |

重新导出的信号常量：`SIGHUP` (1)、`SIGINT` (2)、`SIGQUIT` (3)、`SIGKILL` (9)、`SIGTERM` (15)、`SIGCHLD` (17)、`SIGCONT` (18)、`SIGSTOP` (19)、`SIGTSTP` (20)。此外，还提供 `SIGRTMIN` (32) 和 `SIGRTMAX` (42) 常量用于实时信号范围操作。定义 `SA_SIGINFO` 和 `SA_RESTART` 标志常量，用于 `SetSignalHandler` 系统调用的 `sa_flags` 参数。

`sigsuspend()` 包装器调用 `SYS_SIGSUSPEND` 系统调用 (135)，它以原子方式替换信号掩码并挂起调用线程直到信号到达，然后恢复原始掩码。

使用模式：

```rust
loop {
    let sig = signal::wait_signal_forever();
    match sig.signal {
        SIGTERM | SIGINT => syscall::sys_exit(0),
        SIGCHLD => { /* 回收子进程 */ }
        _ => {}
    }
}
```

---

## 网络 (`net.rs`)

文件：`src/user/shared/net.rs`

### HTTP 客户端

`fetch_http_url_bytes(url)` 和 `fetch_http_url_text(url)` 提供 HTTP/1.1 GET 功能：
1. 通过 `parse_http_url()` 解析 URL（支持 `http://` 和 `https://` — HTTPS 在获取时被拒绝）
2. 检查 `sys_network_status()` 的能力
3. 通过 `sys_connect_tcp()` 建立连接
4. 发送 `GET` 请求
5. 读取响应（处理 `Content-Length` 和分块传输编码）
6. 关闭连接

限制：仅 HTTP（无 TLS）、不跟踪重定向、无持久连接、无自定义头部。

### HTTP 服务器

`HttpServer` 提供单线程的监听器：

```rust
let mut server = HttpServer::new(8080)?;
server.route("/api/v1/status", HttpMethod::GET, status_handler);
server.set_server_data("/var/www");
server.serve()?; // 永不返回
```

路由处理函数是 `fn(&HttpRequest, Option<&str>) -> HttpResponse` 函数指针（无闭包，以兼容 `no_std`）。

### URL 支持

`fetch_url_bytes()` 处理 `http://` 和 `file://` 两种 scheme。`file://` 路径通过系统调用读取本地文件，并支持百分比解码。

---

## 关键约定

1. **仅 `no_std` + `alloc`** — 无 libc 依赖。所有模块同时编译进内核映像和独立的 ELF 二进制文件。

2. **`Result` 错误类型为 `String`** — 底层系统调用封装返回 `Result<_, isize>`（原始内核 errno），但命令实现和公开 API 将 errno 值转换为人类可读的 `String` 消息。

3. **字符串参数使用 `&str`** — 在尽可能的情况下，类型化封装函数接受 `&str` 而非 `(ptr, len)` 元组，内部通过 `.as_ptr() as usize, path.len()` 进行转换。

4. **ABI 边界使用 `#[repr(C)]`** — 每个跨越内核/用户空间边界的结构体都使用 `#[repr(C)]` 并带有显式字段顺序。偏移量在编译时通过 `offset_of!()` 进行检查。

5. **`extern "Rust"` 桥接** — 系统调用模块声明了每个环境都要实现的 `extern "Rust"` 函数。这避免了 `extern "C"` ABI 开销，同时保持实现可互换。

6. **特性门控运行时** — `runtime` 特性控制是否编译独立裸机系统调用桥接、分配器和 panic 处理函数。内核构建将其关闭：内核的 `syscall_bridge.rs` 提供 `__shell_syscallN` 实现，宿主机端测试也针对同一桥接解析。

7. **显式状态传递** — 分发函数将所有状态作为可变引用（`cwd`、`env_vars`、`aliases` 等）传递，而不是使用全局变量或线程局部存储，使其既可用于 ring0（内核静态变量）也可用于 ring3（栈变量）。

8. **错误到退出码的映射** — 内核的 `Error` 枚举在系统调用边界被编码为负的 `isize` 值（-1 = InvalidArgument 到 -12 = InvalidCredential），命令实现通过 `CmdResult` 将其映射为 POSIX 风格的退出码。

---

## 参见

- [系统调用 ABI 参考](../en/syscall.md) — SyscallNumber 枚举、调度表、指针规范
- [文档索引](../README.md) — 完整文档树
