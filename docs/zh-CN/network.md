# 内核网络栈

## 分层架构

网络栈采用传统的 TCP/IP 分层模型组织，
实现在 `src/kernel/network/` 中：

```
 Application    TLS 1.3, DNS, DHCP, NTP, mDNS, HTTP (user space)
 Transport      TCP         UDP       Raw Sockets
 Internet       IPv4        IPv6      ARP      ICMP(v6)
 Link           Ethernet    PPP       Device (NIC trait)
```

| 层       | 模块路径                                  | 职责                                |
|----------|------------------------------------------|-------------------------------------|
| 链路层   | `link::device`, `link::ethernet`         | NIC trait、MAC 成帧                |
| 网际层   | `internet::ipv4`, `internet::ipv6`       | IP 包解析/发送、ARP、ICMP          |
| 传输层   | `tcp/`, `udp`, `raw`                     | TCP 状态机、UDP 数据报              |
| 应用层   | `dns/`, `dhcp`, `ntp`, `mdns`, `tls/`    | DNS 解析器、DHCP 客户端、TLS 1.3    |

全局解复用器位于 `stack::NetworkStack`（`src/kernel/network/stack/`），
它拥有 TCP 连接表、UDP 套接字表、原始套接字表、ARP
缓存、NDP 缓存和性能分析器。`NetworkStack::init_with_device(dev, ip)`
安装一个单例，`poll()` 将传入帧分派到正确的
协议处理程序。

## 双后端

内核支持两种网络后端，在编译时选择：

- **Native**（`target_os = "none"`，裸机）：内核自有的 TCP/IP 栈，
  在 `src/kernel/network/` 下约 58 个源文件中实现。
  提供完整的协议层，包括 TCP 拥塞控制
  （`tcp/congestion.rs`）、ECN（`tcp/ecn.rs`）、SACK 和窗口缩放。

- **HostRuntimeCompat**（宿主机构建，例如 `cargo test`）：将 TCP
  操作委托给 `std::net::{TcpStream, TcpListener}`。内核在两个
  后端上暴露相同的 API 类型（`TcpConnection`、`TcpListener`、`UdpSocket`）；
  条件编译（`#[cfg(target_os = "none")]` /
  `#[cfg(not(target_os = "none"))]`）将每个方法路由到相应的
  实现。

活动后端通过 `KernelTcpBackend::status()` 报告，该函数返回
一个带有能力标志的 `net_abi::NetworkStatus`（例如，
`NETWORK_STATUS_FLAG_TCP_CONNECT`、`NETWORK_STATUS_FLAG_STREAM_IO`）。用户
空间可以通过 `network_status()` 系统调用来检查此信息，以决定哪些
API 可用。

## TCP（`src/kernel/network/tcp/`）

TCP 实现（RFC 793）包含完整的 11 状态状态机：

### 连接状态

定义在 `tcp/types::TcpState` 中：

```
Closed → Listen → SynReceived → Established → CloseWait → LastAck → Closed
                       ↗                         ↘
                   SynSent                    FinWait1 → FinWait2
                                                         ↘
                                                    Closing → TimeWait → Closed
```

`TcpConnectionState`（`tcp/types.rs`）跟踪每个连接的状态：
- 发送端：`send_next`（SND.NXT）、`send_unacked`（SND.UNA）、`send_window`
- 接收端：`recv_next`（RCV.NXT）、`recv_buffer`（通过 `VecDeque<u8>` 实现的环形缓冲区）
- 重传：`RetransmitState`，带指数退避（`RTO_BASE_TICKS = 30`、
  `MAX_BACKOFF_MULTIPLIER = 3`、`MAX_RETRIES = 5`）
- 拥塞：`CongestionState`，含 cwnd、ssthresh、恢复
- ECN：`EcnState`，用于显式拥塞通知（RFC 3168）

### 套接字管理

`TcpConnectionTable`（`tcp/table.rs`）是一个哈希表，键为
`(local_port, remote_ip, remote_port)`。临时端口从
范围 `49152..=65535` 中分配。监听器存储在一个单独的
`TcpListenerState` 映射中，每个都有一个 `backlog`（最大待处理连接数）
和一个等待 `accept()` 的已建立子连接的 `VecDeque`。

### 关键操作

公共 API（`tcp/mod.rs` 重新导出）：

| 操作                | 函数 / 路径                              | 描述                                   |
|--------------------|------------------------------------------|----------------------------------------|
| `connect()`        | `tcp::connect(stack, ip, port)`          | 主动打开：SYN → SYN-ACK → ACK         |
| `listen()`         | `tcp::listen(&mut table, port, backlog)` | 在端口上被动打开                      |
| `accept_nonblocking()` | `tcp::accept_nonblocking(&mut table, port)` | 从监听器 backlog 中弹出         |
| `process_segment()`    | `tcp::process_segment(...)`         | 入站段解复用及状态机                 |
| `close()`              | `tcp::close(...)`                    | FIN 握手发起方                        |
| `retransmit_check()`   | `tcp::retransmit_check(...)`       | 超时触发的重传                        |

### 重传与窗口管理

重传定时器使用基 RTO 为 30 个 tick（100 Hz 下为 300 ms）。
每次超时后退避加倍，上限为 `MAX_BACKOFF_MULTIPLIER = 3`
（最大 RTO 为 240 个 tick）。经过 `MAX_RETRIES = 5` 次后，连接
转换为 `Closed`。

接收窗口通告为 `(MAX_RECV_BUFFER - recv_buffer.len()) >> 6`
（窗口缩放因子 `DEFAULT_WINDOW_SCALE = 6`）。当缓冲区满时，
窗口缩小为零，对对端施加背压。

TIME-WAIT 持续 `TIME_WAIT_TICKS = 6000`（100 Hz 下为 60 秒），之后
连接转换为 `Closed` 并从表中移除。

## UDP（`src/kernel/network/udp.rs`）

UDP 是无连接的。`UdpSocketTable`（`udp::UdpSocketTable`）是一个
`BTreeMap<u16, UdpSocket>`，以本地端口为键。每个 `UdpSocket` 有一个
接收队列（`VecDeque<(IpAddress, u16, Vec<u8>)>`）。

公共 API：

| 函数              | 描述                                            |
|-------------------|-------------------------------------------------|
| `bind(port)`      | 注册本地端口；若已被占用则返回 `AlreadyExists` |
| `unbind(port)`    | 释放端口绑定                                     |
| `deliver(src_ip, src_port, dst_port, data)` | 将传入数据报推入套接字队列     |
| `recv_from(port, buffer)` | 从队列弹出；若为空则返回 `TimedOut`（非阻塞）|
| `has_pending(port)` | 若套接字有排队的数据报则返回 `true`           |

`UdpSocket` 上的 `is_readable()` 方法（在 `mod.rs` 中定义）调用
`table.has_pending(self.port)`。`send_to()` 和 `send_to_v6()` 构建
完整的 IP 包（调用 `build_udp_ipv4_packet()` 或
`build_udp_ipv6_packet()`）并通过栈的 ARP/NDP
解析路径推送。

该实现有意在调用 `send_ipv4_packet()` 之前释放 UDP 表锁，
以避免与 ARP/NDP 解析路径死锁
（该路径可能 `poll()` 并需要锁定 UDP 表以进行传入数据报
投递）。

## 本地套接字（`src/kernel/network/local.rs`）

本地套接字提供同一台机器上进程之间的 Unix-domain 风格 IPC。
全局注册表 `LOCAL_SOCKETS: Mutex<BTreeMap<String, Arc<LocalSocket>>>`
将路径映射到已绑定的套接字。

| 操作                  | 函数                          | 行为                                                |
|-----------------------|-------------------------------|-----------------------------------------------------|
| `bind_local(path)`    | `local::bind_local()`         | 在给定路径注册 `LocalSocket`                        |
| `connect_local(path)` | `local::connect_local()`      | 创建内核管道对；将读端 VNode 推入套接字的 accept 队列；返回写端 VNode |
| `accept_local(socket)`| `local::accept_local()`       | 从 accept 队列弹出下一个待处理 `VNode`              |
| `unbind_local(path)`  | `local::unbind_local()`       | 从注册表中移除绑定                                  |

每个 `LocalSocket` 有一个 `pending: Mutex<VecDeque<Arc<dyn VNode>>>` 队列，
最大深度为 16（`LOCAL_SOCKET_BACKLOG`）。`is_readable()`
方法在待处理队列非空时返回 `true`。

`LocalSocket` 类型从 `mod.rs` 重新导出为 `pub use local::LocalSocket`，
并作为进程 fd 表中的 `KernelObject` 变体可用。

## TLS 1.3（`src/kernel/network/tls/`）

TLS 1.3 客户端实现分为三个子模块：

| 模块         | 路径                            | 内容                                              |
|-------------|---------------------------------|---------------------------------------------------|
| `record`    | `tls/record.rs`                 | TLS 记录层：使用 AES-128-GCM 或 ChaCha20-Poly1305 加解密 |
| `handshake` | `tls/handshake.rs`              | 握手消息解析、密钥调度、Finished 验证              |
| `certificate`| `tls/certificate.rs`           | X.509 证书解析和基本链验证                         |

### 架构

核心类型包括：

- **`TlsConnection`** — 客户端握手状态机。管理
  转录哈希（`TranscriptHash`）、X25519 ECDH 密钥交换以及
  握手和应用流量密钥的派生。握手状态
  建模为 `TlsHandshakeState`：
  `ClientHello → WaitServerHello → WaitEncryptedExtensions → WaitCertificate
   → WaitCertificateVerify → WaitFinished → Done`

- **`TlsWrappedConnection`** — 用应用流量密钥包装已建立的 `TcpConnection`。
  握手后，`write()` 使用客户端写密钥加密有效载荷，
  `read()` 使用服务器写密钥解密传入记录
  （握手期间在客户端派生）。每个实例的
  `read_buf` 处理不完整的 TLS 记录读取。

顶层 `tls_connect(host, port)` 函数执行完整序列：
TCP 连接、TLS 1.3 握手，然后返回一个可用于加密 I/O 的 `TlsWrappedConnection`。

```rust
// 使用示意
let tls = tls::tls_connect("example.com", 443)?;
tls.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?;
let mut buf = [0u8; 4096];
let n = tls.read(&mut buf, 500)?;
```

## DNS 解析（`src/kernel/network/dns/`）

子模块布局：

| 文件             | 内容                                          |
|------------------|-----------------------------------------------|
| `query.rs`       | DNS 查询构建器（A、AAAA、PTR、EDNS0）        |
| `parse.rs`       | 响应解析器（A、AAAA、PTR、名称解码）         |
| `cache.rs`       | 感知 TTL 的 DNS 响应缓存 + 静态主机表         |
| `resolve.rs`     | 解析编排                                      |

### 解析策略（`resolve::resolve_hostname`）

1. **静态主机表** — 检查 `cache::lookup_hosts(hostname)`。
2. **DNS 缓存** — 检查 `cache::cache_lookup(hostname, now)` 是否有
   先前解析且 TTL 尚未到期的条目。
3. **DNS 查询**（仅裸机）— 通过 UDP 向配置的
   名称服务器（`stack.dns_server()`，通常由 DHCP 设置）发送 A 记录查询。
   在自旋循环中轮询 `recv_from()`，超时 `DNS_QUERY_TIMEOUT_TICKS = 200`
   （2 秒），最多重试 `DNS_MAX_RETRIES = 2` 次。成功后结果
   被插入感知 TTL 的缓存。

`resolve_dual_stack()` 函数先尝试 AAAA（IPv6），然后回退
到 A（IPv4）。在宿主机构建中，DNS 解析由操作系统处理，
除非 hosts 表中有条目，否则 `resolve_hostname` 返回 `Error::NotFound`。

## 网络系统调用

网络 API 向用户空间暴露 22 个系统调用（编号 37--80），
在共享用户库（`src/user/shared/`）中有 17 个对应的包装器。
这些覆盖：

- `SYS_SOCKET` / `SYS_CLOSE_SOCKET` — 创建和销毁套接字句柄
- `SYS_BIND` — 绑定 UDP 端口或监听 TCP 端口
- `SYS_CONNECT` — TCP 主动打开
- `SYS_LISTEN` — TCP 被动打开
- `SYS_ACCEPT` — 接受待处理 TCP 连接
- `SYS_SENDTO` / `SYS_RECVFROM` — UDP 发送/接收数据报
- `SYS_SEND` / `SYS_RECV` — TCP 流读写
- `SYS_GETSOCKOPT` / `SYS_SETSOCKOPT` — 套接字选项获取/设置
- `SYS_GETHOSTNAME` / `SYS_SETHOSTNAME` — 内核主机名
- `SYS_NETWORK_STATUS` — 查询后端能力

## 套接字生命周期

所有套接字类型的通用生命周期：

```
create → bind → [listen → accept] → read/write → close
          ↗
       connect (TCP only, skip bind/listen/accept)
```

- **create**：`TcpConnection` / `TcpListener` / `UdpSocket` / `LocalSocket`
  由各自的构造函数实例化。
- **bind**：`bind_udp(port)` 在 `UdpSocketTable` 中注册；
  `listen_tcp(port, backlog)` 在 `TcpConnectionTable` 中注册。
- **connect**：`connect_tcp(host, port)` 解析（通过 DNS 或 hosts 表）
  并通过 `tcp::connect()` 执行三次握手。
- **listen/accept**：`listen_tcp()` 创建监听器条目；传入的 SYN
  段由 `process_segment()` 路由到监听器，监听器在
  `SynReceived` 状态下生成一个子 `TcpConnectionState`。当握手
  完成时，子连接被移入监听器的 backlog，然后
  `accept_nonblocking()`（从 `accept_tcp()` 调用）将其取出。
- **read/write**：TCP 在发送/接收缓冲区上使用 `TcpConnectionState::read()` 和 `write()`。
  UDP 使用 `UdpSocketTable::recv_from()` / `send_to()`。
- **close**：TCP `close()` 启动 FIN 握手；UDP `close()` 解绑
  端口；本地套接字 `unbind_local()` 从注册表中移除路径。

## 就绪检查

每种套接字类型暴露 `is_readable()` 和（对于 TCP/TLS）`is_writable()`
用于非阻塞 I/O 多路复用：

| 类型                    | `is_readable()`                                                  | `is_writable()`                                                 |
|-------------------------|------------------------------------------------------------------|-----------------------------------------------------------------|
| `TcpConnection`         | `state.available() > 0` 或状态为 `CloseWait/Closing`             | 状态为 `Established/CloseWait/FinWait1/FinWait2`               |
| `TcpListener`           | `listener_has_pending(&table, port)` — backlog 非空              | 无                                                              |
| `UdpSocket`             | `table.has_pending(port)` — 接收队列非空                         | 无（无连接 — 已绑定时始终可写）                                 |
| `LocalSocket`           | `!pending.lock().is_empty()` — accept 队列非空                   | 无                                                              |
| `TlsWrappedConnection`  | 解密后的读缓冲区非空，然后委托给 `TcpConnection::is_readable()`  | 委托给 `TcpConnection::is_writable()`                           |

这些检查被内核的 poll/select 模拟和用户空间事件循环使用，
以确定 I/O 操作何时不会阻塞。

---

## 参见

- [子系统概述](../en/network.md) — 网络栈高层描述
- [文档索引](../README.md) — 完整文档树
