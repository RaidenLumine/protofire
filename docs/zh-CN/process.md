# 进程与线程模型

本文档描述内核的进程与线程架构。
源文件位于 `src/kernel/process/` 目录下，架构相关的上下文切换代码
位于 `src/arch/{x86_64,aarch64,riscv64}/context.rs`。

---

## 进程 / 线程关系

一个 `Process`（`src/kernel/process/process/mod.rs`）拥有零个或多个线程、
一个句柄表、一个文件描述符表、一个地址空间、信号状态以及
安全凭据。一个 `Thread`（`src/kernel/process/thread/mod.rs`）是
可调度的执行单元，并且始终从属于且仅从属于一个进程。

```
  ┌───────────────┐       1:N       ┌────────────────┐
  │   Process     │ ──────────────> │    Thread      │
  │               │                 │                │
  │  pid: u32     │                 │  tid: u32      │
  │  handle_table │                 │  process: Arc  │
  │  fd_table     │                 │  context: Cell │
  │  security_tok │                 │  priority      │
  │  addr_space   │                 │  state         │
  │  signal_state │                 │  kernel_stack  │
  └───────────────┘                 └────────────────┘
```

- 调度器操作的对象是 `Thread`，而非 `Process`。
- 同一进程中的所有线程共享其地址空间、文件描述符和
  信号处理函数。
- 当最后一个活跃线程终止时，进程终止。

---

## 进程状态与生命周期

`ProcessState` 枚举（`src/kernel/process/process/types.rs`）包含五种状态：

```
  New ──> Ready ──> Running ──> Terminated
               \──> Waiting ──> Ready
```

- **New**：进程已构造但尚未分派。用于
  `PROCESS_SPAWN_FLAG_START_SUSPENDED`——线程存储在
  `suspended_thread` 中，直到父进程调用 `resume_suspended_process`。
- **Ready**：至少有一个线程可运行。调度器将选择
  优先级最高的线程。
- **Running**：当前正在某个 CPU 上执行的一个线程。
- **Waiting**：所有线程均已阻塞（睡眠、等待信号、I/O）。
- **Terminated**：进程已终止，资源被释放。父进程通过
  `Scheduler::reap_process()` 收割该进程。退出原因通过
  `TerminationReason::Exit { status }` 或 `TerminationReason::Exception(...)` 记录。

### 生命周期钩子（`src/kernel/process/process/lifecycle.rs`）

```rust
fn complete_termination(&self, reason: Option<TerminationReason>)
```

此函数：
1. 将状态设置为 `Terminated` 并记录原因。
2. 调用 `release_termination_resources()`，该函数清除句柄表、fd 表、
   信号处理函数、子进程列表，并将用户地址空间移入
   `deferred_user_address_space_drop`。
3. 触发 `termination_event` 以唤醒等待者。
4. 如果在裸机环境下运行，调度器向父进程发送 `SIGCHLD`
   （`src/kernel/process/scheduler/terminate.rs`）。

收割（`Scheduler::reap_process()`，位于 `src/kernel/process/scheduler/process.rs`）
会释放延迟的地址空间，将进程从其父进程的子进程列表中移除，
回收 PID，并返回终止记录。

---

## 线程状态

`ThreadState` 枚举（`src/kernel/process/thread/types.rs`）：

- **Ready**：在调度器就绪队列中，等待 CPU。
- **Running**：当前正在执行。
- **Waiting**：在 `WaitQueue`、`Event` 或定时器上阻塞。
- **Stopped**：由 `SIGSTOP`/`SIGTSTP` 挂起。
- **Terminated**：执行完毕。

---

## 栈金丝雀

每个线程携带一个每线程随机栈金丝雀用于运行时缓冲区溢出检测。金丝雀是一个在
线程创建期间通过 `random::random_u64()` 生成的 64 位随机值，存储在 `Thread`
结构体的 `canary` 字段（`AtomicU64`）中。

### 初始化（`src/kernel/process/thread/lifecycle.rs`）

在 `new_inner()` 中，内核栈分配之后：
1. 生成一个随机的 64 位金丝雀值。
2. 通过 `core::ptr::write_unaligned()` 将金丝雀写入内核栈底部。
3. `Thread::canary` 字段设置为相同的值。

### 验证（`check_stack_canary()`）

`Thread::check_stack_canary()` 方法从内核栈底部读取金丝雀值并与存储的
`Thread::canary` 比较。如果不同，则输出栈损坏诊断信息并 panic。

### 上下文切换更新

在 `schedule_bare_metal()`（`src/kernel/process/scheduler/dispatch.rs`）中：
1. **抢占后** — 在刚让出 CPU 回到调度器的线程上调用 `check_stack_canary()`
   （在 `process_deferred_dying()` 之后）。
2. **分派前** — 读取下一个线程的 `canary` 值并存入全局 `__stack_chk_guard`
   （`src/lib.rs` 中的 `AtomicUsize`），然后再调用 `arch::switch_context()`。

### 全局保护符号

```rust
// src/lib.rs
#[no_mangle]
pub static __stack_chk_guard: AtomicUsize = AtomicUsize::new(0);

#[no_mangle]
pub extern "C" fn __rustc_stack_protector() -> *mut usize {
    &__stack_chk_guard as *const AtomicUsize as *mut usize
}
```

`__rustc_stack_protector()` 函数提供编译器插入的金丝雀引用点。
在每次上下文切换时，`__stack_chk_guard` 更新为新线程的金丝雀值。
因为每个 CPU 一次最多运行一个线程，所以单个全局保护足够。

---

## 调度器

`Scheduler` 结构体（`src/kernel/process/scheduler/mod.rs`）是核心
调度引擎。每个 CPU（SMP）对应一个调度器；每个调度器
维护自己的就绪队列和当前线程槽位。

### 就绪队列

定义了四个优先级级别（`types.rs` 中的 `ThreadPriority`）：

| 级别     | 值   | 描述             |
|----------|------|------------------|
| Idle     | 0    | 仅空闲线程       |
| Normal   | 1    | 默认用户线程     |
| High     | 2    | 优先级提升的线程 |
| Realtime | 3    | 实时线程         |

线程按优先级从高到低分派，在同一优先级级别内
采用轮转调度（`SchedFifo` 策略的线程在被抢占时回到队首）。

### 调度策略

支持两种策略（`ThreadSchedPolicy`）：

- `SchedDefault`：优先级内轮转。时间片到期时被抢占
  （`TIME_SLICE_TICKS = 2` 个定时器滴答）。
- `SchedFifo`：运行至完成——时间片到期时不会被抢占。

### 优先级提升（`src/kernel/process/scheduler/timer.rs`）

一种防饥饿机制：等待时间超过 `BOOST_THRESHOLD_TICKS`（50 个滴答）的
Normal 优先级线程被提升至 High 优先级，持续
`BOOST_DURATION_TICKS`（8 个滴答），然后降级回原优先级。

### 抢占

- **基于定时器的抢占**：`src/kernel/process/scheduler/api.rs` 中的
  `on_timer_tick_with_preemption()` 由定时器中断调用。
  每 `TIME_SLICE_TICKS` 个滴答，当前线程被抢占并通过
  `preempt_current_thread_from_interrupt()` 重新入队。
- **自愿让出**：`yield_current()` -> `yield_current_thread()`，位于
  `src/kernel/process/scheduler/dispatch.rs`。
- **睡眠**：`sleep_current(ticks)` 将当前线程以唤醒截止时间阻塞在
  等待队列上。

### 上下文切换（`src/kernel/process/scheduler/dispatch.rs`）

核心循环是 `schedule_bare_metal()`：

```
loop {
    // 将即将终止的线程移至延迟释放槽位
    if 无需重新调度 且 当前线程存在 -> 返回
    next = take_next_dispatchable_thread(&ready_queues)
    if 没有下一个 -> 恢复内核地址空间并返回
    prepare_thread_address_space(&next)
    next.restore_context()
    self.current = Some(next)
    arch::switch_context(dispatch_context, next.context_ptr())
    // 当线程陷入内核或被抢占时，返回到此处
}
```

`arch::switch_context()` 函数按架构定义：

- **x86_64**（`src/arch/x86_64/context.rs`）：内联汇编将 RSP、RBP、RBX、
  R12-R15、RFLAGS 和 XMM0-XMM15 保存到 `Context` 结构体中。
  跳转到下一个线程保存的指令指针。
- **AArch64**（`src/arch/aarch64/context.rs`）：保存 X19-X30、SP、DAIF 和
  Q8-Q15。加载下一个线程的上下文并分支跳转。
- **RISC-V 64**（`src/arch/riscv64/context.rs`）：相同约定，架构
  特定的寄存器集合。

`Context` 结构体（`src/kernel/process/context.rs`）包含：
`instruction_pointer`、`stack_pointer`、`flags`、16 个通用寄存器
以及 SIMD 寄存器（x86_64 为 16 个，AArch64/RISC-V 为 8 个）。

用户态入口使用 `arch::enter_user_mode_with_context()`，该函数构建
`iretq` 帧（x86_64）或编程 `ELR_EL1`/`SPSR_EL1`（AArch64）并执行
`eret`。

### APC / 每 CPU 调度器

在 SMP 系统上，每个 CPU 拥有自己的 `Scheduler` 实例。线程在
创建时通过轮转分配 `cpu_affinity`
（`src/kernel/process/scheduler/spawn.rs` 中的 `register_spawned_thread()`）。
当更高优先级的线程被创建时，会向远程 CPU 发送重新调度 IPI。

---

## 创建 API（`src/kernel/process/scheduler/spawn.rs`）

调度器提供类型化的创建入口点：

| 函数 | 描述 |
|----------|-------------|
| `spawn_kernel_named(name, entry_fn)` | 内核态线程，ring 0 |
| `spawn_user_named(name, start_descriptor)` | 用户态线程，ring 3 |
| `try_spawn_user_named_with_security_token(...)` | 带显式安全令牌的用户线程 |

所有创建路径：
1. 通过 `allocate_pid()` 分配 PID（重用已释放的 PID，在 u32 最大值处回绕）。
2. 创建处于 `Ready`（或 `start_suspended` 时为 `New`）状态的 `Process`。
3. 通过 `Thread::new()` 或 `Thread::try_new_user()` 创建 `Thread`。
4. 调用 `register_spawned_thread()`，该函数分配 CPU 亲和性并将
   线程入队到目标 CPU 的就绪队列。
5. 可选地向目标 CPU 发送重新调度 IPI。

### Init 程序

第一个用户态进程（PID 1）使用
`spawn_from_launch_reference()` 创建，该函数解析引导镜像清单，
构造 `LaunchContext`（目录 ID、清单路径、镜像路径、版本、
工作目录、参数、环境），并通过
`ProcessUserAddressSpace::from_prepared_process()` 设置用户地址空间。

### Fork（`src/kernel/process/process/fork.rs`）

`Process::fork()` 创建一个具有写时复制地址空间的子进程。
子进程继承文件描述符（重新打开为独立的句柄）、启动上下文、
CWD 和主目录。只有单线程进程可以进行 fork。

---

## 安全模型（`src/kernel/process/process/security.rs`）

每个进程携带一个 `SecurityToken`：

```rust
pub struct SecurityToken {
    pub user_id: UserId,
    pub primary_group_id: GroupId,
    pub integrity: IntegrityLevel,
    elevated: bool,
    pub recovery: bool,
    pub supplementary_group_ids: &'static [GroupId],
    authenticated: bool,
}
```

### 完整性级别

| 级别   | 值   | 用途                 |
|--------|------|----------------------|
| System | 0    | 仅内核线程           |
| High   | 1    | 根/管理员进程        |
| Medium | 2    | Guest / 普通用户     |
| Low    | 3    | 沙箱进程             |

一个完整性级别若其数值 <= 另一级别，则称其**支配**另一级别。

### 关键查询

- `may_bypass_discretionary_permissions()`：系统令牌始终可绕过；
  用户令牌需要超级用户/管理员模式且通过基于密码的
  认证（`is_authenticated()`）。
- `may_manage_system_tree()`：需要管理员模式（提升的或系统级别）。
- `is_admin_mode()`：如果 `elevated` 为真或 `integrity == System`，则为真。
- `may_bypass_read_only_mounts()`：仅恢复模式。
- `belongs_to_group()`：检查主组 ID + 补充组 ID。

### 认证流程

- `SecurityToken::system()`：内核内部使用，始终具有特权，无认证标志。
- `SecurityToken::root()`：High 完整性、提升的，默认未经认证。
- `SecurityToken::guest()`：Medium 完整性，非特权。
- `with_authentication()`：在基于密码的登录后调用；用于用户态管理员令牌的
  `may_bypass_discretionary_permissions()` 门控。

---

## 信号投递（`src/kernel/process/process/lifecycle.rs`）

信号子系统提供类似 POSIX 的信号语义，具有 43 个信号槽位（0-42），
包括 11 个实时信号（32-42）。信号掩码是一个 64 位位域，异步传递支持
所有三个架构上的 SA_SIGINFO 和 SA_RESTART 标志。

### 架构

```
            ┌──────────────────────────────────┐
            │ Process                           │
            │  signal_handlers: [Option;43]     │
            │  signal_sa_flags: [u32; 43]       │
            │  signal_mask: u64 bitfield         │
            │  signal_queue: WaitQueue           │
            └──────────────────────────────────┘
                        │
            ┌───────────┴───────────┐
            │ Thread                │
            │  restart_block:       │
            │   RestartBlock        │
            └───────────────────────┘
```

### 实时信号（RT）

实时信号（SIGRTMIN = 32 到 SIGRTMAX = 42）提供 11 个具有类似 POSIX
传递语义的排队信号槽位。每个 RT 信号携带一个 `SignalInfo`
（兼容 siginfo_t）负载，包含 `si_signo`、`si_code`、`sender_pid`、
`sender_uid`、`si_value` 和 `si_addr`。RT 信号是单独排队的——
与标准信号不同，同一 RT 信号的多个实例可以同时待处理。
`PROCESS_SIGNAL_MAX` 常量现在为 42（从 31 增加）。

### 处理函数安装

信号处理函数数组大小为 43 个槽位（索引 0-42）。每个槽位的
`signal_sa_flags` 字段存储来自 `sigaction` 的 `sa_flags`，
支持 SA_SIGINFO 和 SA_RESTART 标志：

- **SA_SIGINFO**：设置后，异步信号传递将 `SignalInfo` 结构体
  与信号帧一起写入用户栈。处理函数接收 `si_signo`、`si_code`、
  `si_pid`、`si_uid`、`si_value` 和 `si_addr`，填充有发送进程
  的身份和信号负载值。
- **SA_RESTART**：设置后，信号传递用被中断的系统调用上下文
  标记被中断线程的 `RestartBlock`。在 sigreturn 时，架构特定的
  陷阱分发回退指令指针以重试系统调用（x86_64 `int 0x80` 上 2 字节，
  AArch64 `svc #0` 上 4 字节，RISC-V `ecall` 上 4 字节）。
  调用 `restart_syscall` 系统调用 (#136) 重新执行被中断的操作。

### RestartBlock（`src/kernel/process/thread/types.rs`）

```rust
pub struct RestartBlock {
    /// 是否有待处理的重启。
    pub pending: bool,
    /// 被中断且应重启的系统调用号。
    pub syscall_number: usize,
    /// 用于重新调用的保存参数。
    pub args: [usize; 6],
}
```

每个线程在其 `Thread` 结构体中存储一个 `RestartBlock`
（在 `src/kernel/process/thread/mod.rs` 中）。当带有 SA_RESTART 的
信号处理函数返回时，架构陷阱分发检查此块并回退指令指针以触发
被中断系统调用的重新执行。

### 入队（`enqueue_signal(sender_pid, signal, payload)`）

1. 首先检查 POSIX 信号（SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGKILL,
   SIGSTOP 等）：
   - SIGKILL 和 SIGSTOP 始终立即触发默认操作。
   - 其他 POSIX 信号：如果未安装处理函数且信号未被阻塞，
     则应用默认操作（SIGHUP/SIGINT/SIGQUIT/SIGTERM 终止；
     SIGSTOP/SIGTSTP 停止；SIGCONT 继续）。
2. 如果信号有处理函数或被阻塞，则将其入队到
   `PendingProcessSignalState`（容量 64）中。
3. 如果有线程正在等待，则将其出队并唤醒。

### 等待（`wait_for_signal()`、`wait_for_signal_timeout(ticks)`）

调用线程在进程的 `signal_queue` WaitQueue 上阻塞，直到
信号到达或超时到期。`ThreadWaitOutcome` 被设置为
`Completed`（已收到信号）或 `TimedOut`。

### sigsuspend（`src/kernel/syscall/process/sigsuspend.rs`）

`sigsuspend` 系统调用 (#135) 提供 POSIX `sigsuspend()` 语义：
原子地将进程信号掩码替换为调用方提供的掩码，然后挂起调用线程
直到信号到达。返回时，恢复原始信号掩码。u64 信号掩码作为单个
寄存器参数传递。实现：
1. 保存当前信号掩码。
2. 将进程掩码替换为调用方的掩码。
3. 在信号 WaitQueue 上挂起当前线程。
4. 唤醒时（信号到达），恢复原始掩码并返回。

### 处理函数（`src/kernel/process/process/constants.rs`）

```rust
pub type SignalHandler = fn(i32);
```

进程通过 `Process::install_signal_handler()`（位于
`src/kernel/process/process/fork.rs`）安装处理函数。共 43 个槽位，
按信号编号索引。信号掩码通过 `block_signal()`、`unblock_signal()` 和
`set_signal_mask()` 操作，全部使用 u64 位域。

### 默认操作（`apply_default_signal_action()`）

| 信号     | 操作                           |
|----------|----------------------------------|
| SIGHUP   | 终止                             |
| SIGINT   | 终止                             |
| SIGQUIT  | 终止                             |
| SIGTERM  | 终止                             |
| SIGKILL  | 终止（始终，不可阻塞）            |
| SIGSTOP  | 停止线程执行                     |
| SIGTSTP  | 停止线程执行                     |
| SIGCONT  | 恢复线程执行                     |
| SIGCHLD  | 忽略（默认）                     |

---

## 作业控制（`src/kernel/process/scheduler/process.rs`）

作业控制在调度器级别实现：

- `stop_process(pid)`：扫描所有每 CPU 调度器，将线程从
  就绪/等待队列中移除，并将其状态设置为 `Stopped`。
- `continue_process(pid)`：扫描所有调度器并恢复已停止的线程。
- `SIGSTOP`/`SIGCONT`/`SIGTSTP` 通过 `send_signal()` 触发这些路径。

---

## 句柄表（`src/kernel/process/process/types.rs`）

每个进程维护一个 `BTreeMap<Handle, HandleEntry>`（句柄表）和
一个 `BTreeMap<FileDescriptor, Handle>`（fd 表）。标准 fd（0=stdin，
1=stdout，2=stderr）存储在单独的 `standard_handles` 数组中。

### KernelObject 枚举

```rust
pub enum KernelObject {
    File(OpenFile),
    Directory(String),
    Device(String),
    Network(TcpConnection),
    TcpListener(TcpListener),
    UdpSocket(UdpSocket),
    RawSocket(RawSocketHandle),
    LocalSocket(Arc<LocalSocket>),
    TlsConnection(Arc<TlsWrappedConnection>),
    Process(ProcessId),
    Thread(ThreadId),
}
```

### HandleEntry

```rust
pub struct HandleEntry {
    pub object: KernelObject,
    pub rights: u32,          // HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE
}
```

### 句柄操作（`src/kernel/process/process/handle_entry.rs`）

- `read_stream(buffer, timeout)`：根据 `KernelObject` 变体分派到
  `Device::read`、`TcpConnection::read`、`OpenFile::read` 等。
- `write_stream(buffer)`：类似地分派写操作。
- `is_readable()` / `is_writable()`：返回就绪状态而不阻塞。
  File 和 Device 始终报告可读/可写；网络对象委托给
  底层的连接或套接字。
- `public_file_stat_record()`：为类 stat 查询生成 `fs_abi::FileStat`。
- `reopen_handle_in(process)` / `reopen_descriptor_in(process)`：将
  句柄复制到另一个进程的表中。

### FD 表操作（`src/kernel/process/process/handle_ops.rs`）

- `open_handle()` / `open_descriptor()`：插入一个新对象。
- `close_fd(fd)`：移除 fd 绑定，如果没有其他引用则释放句柄。
- `duplicate_fd(fd)` / `duplicate_fd_to(fd, newfd)`：POSIX dup/dup2 语义。
- `bind_standard_handle(fd, handle)`：设置 stdio 槽位（0/1/2）。
- `inherit_fds_from(source)`：从另一个进程复制非 CLOEXEC 的 fd
  （在创建时使用）。
- `close_cloexec_fds()`：关闭所有带有 `FD_CLOEXEC` 标志的 fd
  （在 exec 时使用）。
- `set_fd_flags(fd, set, clear)`：操作每个 fd 的标志，如 CLOEXEC。
- `redirect(from, to)`：标准 fd 之间的 Dup2 风格重定向。

---

## 进程生命周期钩子

### 退出时（`src/kernel/process/scheduler/terminate.rs`）

`finish_current_thread()`：

1. 将当前线程从调度器的当前槽位移除。
2. 调用 `terminate_sibling_threads()` 终止同一进程中处于就绪/等待
   队列的所有其他线程。
3. 终止当前线程，触发 `termination_event`。
4. 向父进程发送 `SIGCHLD`（仅裸机环境）。
5. 将线程移入 `dying_thread`，使其 `KernelStack` 和 `Arc`
   稍后在上下文切换到调度器自身栈后被释放。

### 父进程通知

当最后一个线程终止时，调用 `complete_termination()`。调度器
向父进程发送带有 `payload = child_pid` 的 `SIGCHLD`。父进程
随后可以调用 `Scheduler::reap_process()`，该函数：

1. 调用 `process.reap_termination_reason()` 消费一次性原因。
2. 将子进程从父进程的子进程列表中移除。
3. 在中断开启的情况下释放延迟的用户地址空间（页表）。
4. 回收 PID。

### SHM 清理（`src/kernel/process/process/lifecycle.rs`）

`Process` 在 `shm_attachments: Vec<ProcessShmAttachment>` 中跟踪
共享内存的附着关系。在 `release_termination_resources()` 期间，
`collect_shm_attachments()` 返回所有附着关系供 SHM 子系统
分离，然后 `clear_shm_attachments()` 将其移除。

### 重新父化

孤儿进程在原始父进程先于子进程终止时，通过 `set_parent_pid()`
重新父化到 PID 1。

---

## 参见

- [子系统概览](../en/process.md)——进程与线程模型的高级描述
- [文档索引](../README.md)——完整的文档树
