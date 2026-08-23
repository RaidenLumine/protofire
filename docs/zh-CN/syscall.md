# 系统调用 ABI

内核提供基于寄存器的系统调用接口。本文档涵盖 ABI 契约、编号方案、分发流水线、指针验证、错误编码以及共享用户桥接层（`src/user/shared/`）。

## ABI 契约

参数和返回值通过通用寄存器传递。具体的寄存器映射与架构相关，定义在 `src/abi/syscall.rs` 中（以 `crate::kernel::syscall::abi` 重新导出）。

### 参数传递

| 参数         | 寄存器                              |
|-------------|-------------------------------------|
| 系统调用号   | `%rax` (x86_64) / `x8` (aarch64)   |
| arg[0]      | `%rdi` (x86_64) / `x0` (aarch64)   |
| arg[1]      | `%rsi` / `x1`                       |
| arg[2]      | `%rdx` / `x2`                       |
| arg[3]      | `%r10` / `x3`                       |
| arg[4]      | `%r8`  / `x4`                       |
| arg[5]      | `%r9`  / `x5`                       |

所有六个参数槽位被打包进内核的 `SyscallContext` 结构体：

```rust
// src/kernel/syscall/table.rs
pub struct SyscallContext {
    pub number: usize,
    pub args: [usize; syscall_abi::ARG_COUNT],  // 始终为 6
    pub caller_pid: Option<u32>,
}
```

常量 `syscall_abi::ARG_COUNT` 的值为 `6`。未使用的尾部参数槽位必须为零 —— 辅助函数 `validate_zeroed_args()` 通过扫描 `args[start..]` 并在发现非零条目时返回 `Error::InvalidArgument` 来强制执行此要求。

### 返回值

成功时，处理程序将 `usize` 类型的结果值存储在 `SyscallDispatch::value` 中。架构陷阱桩将该值放入指定的返回寄存器（`%rax` / `x0`）。

错误编码为接近 `usize::MAX` 的大无符号值。共享的 `decode()` 函数将这些值转换为 `isize`，以便基于符号进行区分：

```rust
// src/user/shared/syscall.rs
fn decode(status: isize) -> Result<usize, isize> {
    if status < 0 {
        Err(status)        // 负的 errno
    } else {
        Ok(status as usize)
    }
}
```

内部的 `Error` 枚举提供 `Error::as_str()` 用于诊断消息，并在 ABI 边界处映射为负 errno 约定。

## 系统调用编号

每个公开系统调用在 `src/kernel/syscall/table.rs` 的 `SyscallNumber` 枚举中都有一个固定的编号。编号按顺序分配，其中预留了 Dup2 (69) 和 GetTimeOfDay (70) 的空隙。

```rust
#[repr(usize)]
pub enum SyscallNumber {
    Yield                  = 0,
    WriteDebug             = 1,
    Open                   = 2,
    Exit                   = 3,
    ReadConsole            = 4,
    Read                   = 5,
    Write                  = 6,
    Close                  = 7,
    Dup                    = 8,
    Seek                   = 9,
    ArgCount               = 10,
    // ...
    Dup2                   = 69,
    GetTimeOfDay           = 70,
    // ...
    ShmCtl                 = 103,
}
```

### 当前分配情况 (0-150, 151 个系统调用)

| 范围    | 类别                         |
|--------|------------------------------|
| 0-9    | 核心 I/O（yield, open, read, write, close, dup, seek） |
| 10-18  | 启动元数据（args, env, app info, cwd） |
| 19-21  | 文件系统修改（mkdir, setlen, remove） |
| 22-23  | 异常处理                     |
| 24-26  | 进程生命周期（wait, spawn, exec） |
| 27-36  | 文件系统查询（stat, readdir, rename, *-at 变体） |
| 37-38  | TCP 网络                     |
| 39     | ABI 信息                     |
| 40-41  | 信号发送/等待                |
| 42-47  | 访问控制与权限元数据         |
| 48     | 文件描述符标志               |
| 49-53  | 诊断（sleep, list, kernel log, system info） |
| 54-55  | 同步（fsync, fdatasync）     |
| 56-60  | TCP listen/accept, UDP       |
| 61     | 进程故障                     |
| 62-63  | Fork, ReclaimPages           |
| 64     | 管道                         |
| 65-66  | Mount, Umount                |
| 67-68  | Mmap, Munmap                 |
| 69     | Dup2                         |
| 70-72  | 时间, 主机名                 |
| 73-74  | 套接字名称/对端名称          |
| 75     | GetRandom                    |
| 76-80  | 原始套接字 + sockopt         |
| 81-84  | 身份（pid, ppid, uid, gid）  |
| 85     | SetCurrentDir                |
| 86-87  | 挂载/块设备列表              |
| 88     | SetSecurityDescriptor        |
| 89-91  | 用户管理                     |
| 92     | Brk                          |
| 93     | ResolveHostname              |
| 94     | SetSignalMask                |
| 95     | RepairVolume                 |
| 96     | Poll                         |
| 97-99  | Unix 域套接字                |
| 100-103| SystV 共享内存               |
| 104    | SetSignalHandler             |
| 105    | FUSE 挂载                    |
| 106    | Futex                        |
| 107-109| eventfd, signalfd, timerfd   |
| 110-111| sched_setaffinity, sched_getaffinity |
| 112-117| POSIX 消息队列               |
| 118-120| epoll (create, ctl, wait)    |
| 121-125| （预留用于扩展）             |
| 126-127| io_uring (setup, submit_and_wait) |
| 128    | ptrace                        |
| 129    | seccomp                       |
| 130    | prctl                         |
| 131-132| mlock, munlock                |
| 133    | madvise                       |
| 134    | sigreturn                     |
| 135    | sigsuspend                    |
| 136    | restart_syscall               |
| 137-140| POSIX 定时器（timer_create/settime/gettime/delete） |
| 141-142| （预留：WireGuard）           |
| 143-144| 审计（audit_set_enable, audit_read_log） |
| 145-149| CPU 频率缩放（cpufreq_get/set/get_range/set_governor/get_temp） |
| 150    | 内存碎片整理（compact_memory） |

### PUBLIC_SYSCALL_COUNT

```rust
// src/kernel/syscall/table.rs
pub(crate) const PUBLIC_SYSCALL_COUNT: u32 = SyscallNumber::CompactMemory as u32 + 1;
```

该常量由枚举中最大的判别式值（`CompactMemory = 150`）推导得出。它在测试中用于验证分发表中的每个槽位都已填充：

```rust
#[test]
fn table_init_registers_every_public_syscall_slot() {
    let mut table = Table::new();
    table.init();
    for number in 0..PUBLIC_SYSCALL_COUNT as usize {
        assert!(table.entries[number].is_some(),
                "syscall slot {number} should be registered");
    }
}
```

## 分发机制

### 表结构

分发表是一个固定大小为 256 个槽位的数组（`MAX_SYSCALLS = 256`）：

```rust
pub struct Table {
    entries: [Option<SyscallHandler>; MAX_SYSCALLS],
}
```

处理程序的签名如下：

```rust
pub type SyscallHandler = fn(&mut SyscallContext) -> Result<SyscallDispatch>;
```

### 注册表

静态的 `SYSCALL_REGISTRY` 切片将 `usize` 编号映射到处理函数：

```rust
const SYSCALL_REGISTRY: &[(usize, SyscallHandler)] = &[
    (SyscallNumber::Yield as usize, misc::yield_now),
    (SyscallNumber::WriteDebug as usize, misc::write_debug),
    (SyscallNumber::Open as usize, fs_path_ops::open),
    // ...
];
```

`Table::init()` 遍历注册表并为每个条目调用 `register()`。

### 分发流程

```
用户陷阱 (int 0x80 / svc #0)
       |
       v
陷阱桩：解包寄存器 → SyscallContext
       |
       v
validate_syscall_pointers(number, args)   ← 来自 SYSCALL_POINTER_SPECS 的预验证
       |
       v
table.dispatch_with_action(context)
       |
       v
查找 entries[number] → handler(context)
       |
       v
handler 返回 Result<SyscallDispatch>
       |
       v
陷阱桩：应用 SyscallAction (yield, exit, exec, return-from-exception)
           然后将 SyscallDispatch::value 写入返回寄存器
```

### SyscallDispatch

处理程序的返回值同时携带结果值和副作用标志：

```rust
pub struct SyscallDispatch {
    pub value: usize,
    pub action: SyscallAction,
}

pub enum SyscallAction {
    None,
    Yield,
    Exit { status: usize },
    ReturnFromException { frame_pointer: usize },
    ExecProcess,
}
```

构造器提供了便捷的简写形式：

- `SyscallDispatch::complete(value)` -- 正常返回，无副作用。
- `SyscallDispatch::yield_now()` -- 设置返回值后让出当前线程。
- `SyscallDispatch::exit(status)` -- 终止当前进程。
- `SyscallDispatch::return_from_exception(fp)` -- 恢复执行到已保存的异常帧。
- `SyscallDispatch::exec_process()` -- 触发 exec 重定向。

### 全局表安装

模块 `src/kernel/syscall/mod.rs` 管理一个单一的原子全局表：

```rust
static GLOBAL_TABLE: AtomicPtr<Table> = AtomicPtr::new(ptr::null_mut());

pub fn install_global(table: &'static Table) { /* ... */ }
pub fn global() -> Option<&'static Table> { /* ... */ }
pub fn dispatch(context: &mut SyscallContext) -> Result<usize> { /* ... */ }
pub fn dispatch_with_action(context: &mut SyscallContext) -> Result<SyscallDispatch> { /* ... */ }
```

`Table` 的 `Drop` 实现会在该表是已安装的表时原子地清除全局指针，防止释放后使用。

## 指针验证

### 纵深防御

每个接受用户空间指针的系统调用都经过两层验证：

1. **预验证**（在处理程序运行之前）—— 基于 `src/kernel/syscall/memory/user.rs` 中的静态 `SYSCALL_POINTER_SPECS` 表。
2. **处理程序级验证** —— 处理程序本身使用同一模块中的辅助函数验证指针。

### SyscallPointerSpec

```rust
struct SyscallPointerSpec {
    arg_index: usize,             // 哪个 ABI 槽位 (0-5) 存放指针
    direction: PointerDirection,  // In, Out 或 InOut
    size_arg_index: Option<usize>, // 哪个 ABI 槽位携带字节长度
    fixed_size: Option<usize>,     // 固定大小结构体的确切大小
}
```

静态的 `SYSCALL_POINTER_SPECS` 表恰好有 `PUBLIC_SYSCALL_COUNT` 个条目。每个系统调用编号映射到一个规格切片；空切片表示无需预验证。测试强制执行此要求：

```rust
#[test]
fn pointer_spec_table_covers_every_syscall() {
    assert_eq!(SYSCALL_POINTER_SPECS.len(), PUBLIC_SYSCALL_COUNT as usize);
}
```

系统调用 6 (Write) 的条目示例：

```rust
// arg1 = 数据指针 (输入), arg2 = 长度
&[SyscallPointerSpec::input(1, Some(2), None)],
```

### 验证函数

```rust
pub(crate) fn validate_syscall_pointers(number: usize, args: &[usize; 6]) -> Result<()>
```

该函数读取规格，解析字节长度（来自 `fixed_size` 或 `size_arg_index` 参数），然后调用：

- `validate_current_process_user_input_buffer` -- 用于 `PointerDirection::In`
- `validate_current_process_user_output_buffer` -- 用于 `PointerDirection::Out`

两者都检查空指针、内核半区地址范围和规范地址空洞边界（`USER_ADDRESS_MAX = 0x0000_7FFF_FFFF_FFFF`）。在裸机 x86_64/aarch64 上，它们还通过 `validate_user_mapping()` 遍历页表，以验证该范围已映射且具有所需的权限（输入为 READ，输出为 WRITE）。

### SMAP/PAN 处理

在具有 SMAP 的 x86_64（或等效的 aarch64 PAN）上，用户内存访问需要设置 EFLAGS.AC。该模块将每次解引用包装在 `with_user_access_guard()` 中：

```rust
fn with_user_access_guard<T>(f: impl FnOnce() -> T) -> T {
    // 在裸机上：stac → f() → clac
    // 在主机测试中：无操作
}
```

基于闭包的辅助函数（`with_optional_input_slice`、`with_optional_output_slice`）在进入 SMAP 守卫之前验证指针范围，以便页表遍历错误（内核内部操作）不会在 AC 置位的情况下运行。

## 共享包装器（`src/user/shared/syscall.rs`）

系统调用桥接现位于内核 crate 内的 `src/user/shared/syscall.rs`。它是用户空间 ABI 的唯一事实来源：常量、原始入口点和类型化包装器。

### 常量

每个公开系统调用都有一个 `SYS_*` 常量，从 `src/user/shared/abi/syscall` 重新导出（与内核的 `SyscallNumber` 枚举共享规范定义）：

```rust
pub const SYS_OPEN: usize = 2;
pub const SYS_EXIT: usize = 3;
pub const SYS_READ: usize = 5;
// ... (总共 96 个常量，与 SyscallNumber 对应)
```

### 原始入口点

在 `src/user/shared/syscall.rs` 中声明并由每个环境实现的七个 `extern "Rust"` 函数（每个参数个数一个，0-6）：

```rust
extern "Rust" {
    fn __shell_syscall0(number: usize) -> isize;
    fn __shell_syscall1(number: usize, a0: usize) -> isize;
    // ... 直到 __shell_syscall6
}
```

在内核中，这些解析到 `src/user/program/shell/syscall_bridge.rs`，它包装 `UserSyscall + syscall::dispatch()`。独立的 ring3 运行时可以通过启用 `runtime` 特性（`src/user/shared/runtime.rs`）将它们连接到 `int 0x80` / `svc #0`。extern 声明是无条件的，因此主机端单元测试针对相同的 `#[no_mangle]` 桥接解析 —— 无需单独的测试桩。

### 类型化包装器

更高级的 `sys_*()` 函数提供安全的类型化接口：

```rust
pub fn sys_open(path: &str, flags: usize) -> Result<usize, isize>;
pub fn sys_read(fd: usize, buf: &mut [u8], timeout_ticks: u64) -> Result<usize, isize>;
pub fn sys_write(fd: usize, data: &[u8]) -> Result<usize, isize>;
pub fn sys_close(fd: usize) -> Result<(), isize>;
pub fn sys_exit(code: usize) -> !;
// ... 总共 40+ 个包装器
```

每个包装器对原始的 `isize` 返回值调用 `decode()`，将其转换为 `Result<usize, isize>`。

## 添加新的系统调用

完整的工作流程涉及四个位置：

1. **内核枚举变体** 在 `src/kernel/syscall/table.rs` 中
   ```rust
   pub enum SyscallNumber {
       // ...
       MyNewSyscall = 104,
   }
   ```

2. **处理程序函数** 在适当的处理程序模块中（例如 `src/kernel/syscall/fs/metadata.rs`），签名如下：
   ```rust
   pub(super) fn my_handler(ctx: &mut SyscallContext) -> Result<SyscallDispatch>;
   ```
   然后在 `SYSCALL_REGISTRY` 中注册：
   ```rust
   (SyscallNumber::MyNewSyscall as usize, my_module::my_handler),
   ```

3. **指针规格** 在 `src/kernel/syscall/memory/user.rs` 的 `SYSCALL_POINTER_SPECS` 中。该表必须恰好有 `PUBLIC_SYSCALL_COUNT` 个条目 —— 在末尾添加一个新条目（如果没有指针参数则为空 `&[]`）。

4. **共享常量 + 包装器** 在 `src/user/shared/syscall.rs` 中
   ```rust
   pub const SYS_MY_NEW_SYSCALL: usize = 104;
   pub fn sys_my_new_syscall(...) -> Result<usize, isize> { ... }
   ```

5. **PUBLIC_SYSCALL_COUNT** 从枚举判别式自动更新，只要最大编号的变体是新增的那个。

## 模块布局

| 文件 | 作用 |
|------|------|
| `src/kernel/syscall/mod.rs` | 全局表安装, `dispatch()`, `dispatch_with_action()` |
| `src/kernel/syscall/table.rs` | `SyscallNumber`, `Table`, `SyscallContext`, `SyscallDispatch`, `SYSCALL_REGISTRY` |
| `src/kernel/syscall/memory/user.rs` | `SYSCALL_POINTER_SPECS`, `validate_syscall_pointers()`, 用户内存访问辅助函数 |
| `src/user/shared/syscall.rs` | `SYS_*` 常量, `__shell_syscallN` 入口点, `sys_*()` 包装器 |
| `src/user/program/shell/syscall_bridge.rs` | 内核端 `#[no_mangle]` 的 `__shell_syscallN` 实现 |

---

## 参见

- [子系统概述](../en/syscall.md) — 高级系统调用 ABI 描述
- [共享用户运行时参考](../en/shared-user-runtime.md) — 系统调用包装器约定，双环境分发
- [文档索引](../README.md) — 完整文档树
