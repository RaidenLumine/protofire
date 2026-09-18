# Kernel Network Stack

## Layered Architecture

The network stack is organised in the traditional TCP/IP layering model,
implemented in `src/kernel/network/`:

```
 Application    TLS 1.3, DNS, DHCP, NTP, mDNS, HTTP (user space)
 Transport      TCP         UDP       Raw Sockets
 Internet       IPv4        IPv6      ARP      ICMP(v6)
 Link           Ethernet    PPP       Device (NIC trait)
```

| Layer    | Module path                             | Responsibility                        |
|----------|-----------------------------------------|---------------------------------------|
| Link     | `link::device`, `link::ethernet`        | NIC trait, MAC framing                |
| Internet | `internet::ipv4`, `internet::ipv6`      | IP packet parse/send, ARP, ICMP       |
| Transport| `tcp/`, `udp`, `raw`                    | TCP state machine, UDP datagrams      |
| Application| `dns/`, `dhcp`, `ntp`, `mdns`, `tls/` | DNS resolver, DHCP client, TLS 1.3  |

The global demultiplexer lives in `stack::NetworkStack` (`src/kernel/network/stack/`),
which owns the TCP connection table, UDP socket table, raw socket table, ARP
cache, NDP cache, and profiler.  `NetworkStack::init_with_device(dev, ip)`
installs a singleton that `poll()` dispatches incoming frames to the correct
protocol handler.

## Dual Backend

The kernel supports two networking backends, selected at compile time:

- **Native** (`target_os = "none"`, bare-metal): the kernel's own TCP/IP stack
  implemented in approximately 58 source files under `src/kernel/network/`.
  Provides the full set of protocol layers including TCP congestion control
  (`tcp/congestion.rs`), ECN (`tcp/ecn.rs`), SACK, and window scaling.

- **HostRuntimeCompat** (host builds, e.g., `cargo test`): delegates TCP
  operations to `std::net::{TcpStream, TcpListener}`.  The kernel exposes the
  same API types (`TcpConnection`, `TcpListener`, `UdpSocket`) over both
  backends; conditional compilation (`#[cfg(target_os = "none")]` /
  `#[cfg(not(target_os = "none"))]`) routes each method to the appropriate
  implementation.

The active backend is reported via `KernelTcpBackend::status()`, which returns
a `net_abi::NetworkStatus` with capability flags (e.g.,
`NETWORK_STATUS_FLAG_TCP_CONNECT`, `NETWORK_STATUS_FLAG_STREAM_IO`).  User
space can inspect this through the `network_status()` syscall to decide which
API surface is available.

## TCP (`src/kernel/network/tcp/`)

The TCP implementation (RFC 793) includes a full 11-state state machine:

### Connection States

Defined in `tcp/types::TcpState`:

```
Closed → Listen → SynReceived → Established → CloseWait → LastAck → Closed
                       ↗                         ↘
                   SynSent                    FinWait1 → FinWait2
                                                         ↘
                                                    Closing → TimeWait → Closed
```

`TcpConnectionState` (`tcp/types.rs`) tracks per-connection state:
- Sender: `send_next` (SND.NXT), `send_unacked` (SND.UNA), `send_window`
- Receiver: `recv_next` (RCV.NXT), `recv_buffer` (ring buffer via `VecDeque<u8>`)
- Retransmit: `RetransmitState` with exponential backoff (`RTO_BASE_TICKS = 30`,
  `MAX_BACKOFF_MULTIPLIER = 3`, `MAX_RETRIES = 5`)
- Congestion: `CongestionState` with cwnd, ssthresh, recovery
- ECN: `EcnState` for Explicit Congestion Notification (RFC 3168)

### Socket Management

The `TcpConnectionTable` (`tcp/table.rs`) is a hash map keyed by
`(local_port, remote_ip, remote_port)`.  Ephemeral ports are allocated from
the range `49152..=65535`.  Listeners are stored in a separate
`TcpListenerState` map, each with a `backlog` (maximum pending connections)
and a `VecDeque` of established child connections awaiting `accept()`.

### Key operations

public API (`tcp/mod.rs` re-exports):

| Operation     | Function / path                             | Description                          |
|---------------|---------------------------------------------|--------------------------------------|
| `connect()`   | `tcp::connect(stack, ip, port)`             | Active open: SYN → SYN-ACK → ACK     |
| `listen()`    | `tcp::listen(&mut table, port, backlog)`    | Passive open on port                 |
| `accept_nonblocking()` | `tcp::accept_nonblocking(&mut table, port)` | Pop from listener backlog     |
| `process_segment()` | `tcp::process_segment(...)`            | Inbound segment demux & state machine |
| `close()`     | `tcp::close(...)`                           | FIN handshake initiator              |
| `retransmit_check()` | `tcp::retransmit_check(...)`          | Timeout-triggered retransmission    |

### Retransmission and Window Management

The retransmission timer uses a base RTO of 30 ticks (300 ms at 100 Hz).
On each timeout the backoff doubles, capped at `MAX_BACKOFF_MULTIPLIER = 3`
(for a maximum RTO of 240 ticks).  After `MAX_RETRIES = 5` the connection
transitions to `Closed`.

The receive window is advertised as `(MAX_RECV_BUFFER - recv_buffer.len()) >> 6`
(the window scale shift `DEFAULT_WINDOW_SCALE = 6`).  When the buffer is full
the window shrinks to zero, applying backpressure to the peer.

TIME-WAIT lasts `TIME_WAIT_TICKS = 6000` (60 seconds at 100 Hz), after which
the connection transitions to `Closed` and is removed from the table.

## UDP (`src/kernel/network/udp.rs`)

UDP is connectionless.  The `UdpSocketTable` (`udp::UdpSocketTable`) is a
`BTreeMap<u16, UdpSocket>` keyed by local port.  Each `UdpSocket` has a
receive queue (`VecDeque<(IpAddress, u16, Vec<u8>)>`).

Public API:

| Function      | Description                                     |
|---------------|-------------------------------------------------|
| `bind(port)`  | Register a local port; returns `AlreadyExists` if taken |
| `unbind(port)`| Release the port binding                        |
| `deliver(src_ip, src_port, dst_port, data)`| Push incoming datagram to socket queue |
| `recv_from(port, buffer)` | Pop from queue; returns `TimedOut` if empty (non-blocking) |
| `has_pending(port)` | Returns `true` if the socket has queued datagrams |

The `is_readable()` method on `UdpSocket` (defined in `mod.rs`) calls
`table.has_pending(self.port)`.  `send_to()` and `send_to_v6()` build
the full IP packet (calling `build_udp_ipv4_packet()` or
`build_udp_ipv6_packet()`) and push it through the stack's ARP/NDP
resolution path.

The implementation intentionally releases the UDP table lock before calling
`send_ipv4_packet()` to avoid deadlock with the ARP/NDP resolution path
(which may `poll()` and need to lock the UDP table for incoming datagram
delivery).

## Local Sockets (`src/kernel/network/local.rs`)

Local sockets provide Unix-domain-style IPC between processes on the same
machine.  The global registry `LOCAL_SOCKETS: Mutex<BTreeMap<String, Arc<LocalSocket>>>`
maps paths to bound sockets.

| Operation       | Function                     | Behavior                                        |
|-----------------|------------------------------|-------------------------------------------------|
| `bind_local(path)` | `local::bind_local()`    | Register `LocalSocket` at the given path        |
| `connect_local(path)` | `local::connect_local()` | Creates a kernel pipe pair; pushes the read-end VNode into the socket's accept queue; returns the write-end VNode |
| `accept_local(socket)` | `local::accept_local()` | Pops the next pending `VNode` from the accept queue |
| `unbind_local(path)` | `local::unbind_local()` | Removes the binding from the registry          |

Each `LocalSocket` has a `pending: Mutex<VecDeque<Arc<dyn VNode>>>` queue
with a maximum depth of 16 (`LOCAL_SOCKET_BACKLOG`).  The `is_readable()`
method returns `true` when the pending queue is non-empty.

The `LocalSocket` type is re-exported from `mod.rs` as `pub use local::LocalSocket`
and is available as a `KernelObject` variant in the process fd table.

## TLS 1.3 (`src/kernel/network/tls/`)

The TLS 1.3 client implementation is split into three sub-modules:

| Module      | Path                           | Content                                       |
|-------------|--------------------------------|-----------------------------------------------|
| `record`    | `tls/record.rs`                | TLS record layer: encrypt/decrypt using AES-128-GCM or ChaCha20-Poly1305 |
| `handshake` | `tls/handshake.rs`             | Handshake message parsing, key schedule, Finished verification |
| `certificate`| `tls/certificate.rs`          | X.509 certificate parsing and basic chain verification |

### Architecture

The central types are:

- **`TlsConnection`** — client-side handshake state machine.  Manages the
  transcript hash (`TranscriptHash`), X25519 ECDH key exchange, and
  derivation of handshake and application traffic keys.  Handshake states
  are modelled as `TlsHandshakeState`:
  `ClientHello → WaitServerHello → WaitEncryptedExtensions → WaitCertificate
   → WaitCertificateVerify → WaitFinished → Done`

- **`TlsWrappedConnection`** — wraps an established `TcpConnection` with
  application traffic keys.  After the handshake, `write()` encrypts payloads
  with the client write key and `read()` decrypts incoming records with the
  server write key (derived client-side during the handshake).  A per-instance
  `read_buf` handles partial TLS record reads.

The top-level `tls_connect(host, port)` function performs the full sequence:
TCP connect, TLS 1.3 handshake, then returns a `TlsWrappedConnection` ready
for encrypted I/O.

```rust
// Usage sketch
let tls = tls::tls_connect("example.com", 443)?;
tls.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?;
let mut buf = [0u8; 4096];
let n = tls.read(&mut buf, 500)?;
```

## DNS Resolution (`src/kernel/network/dns/`)

Sub-module layout:

| File             | Content                                      |
|------------------|----------------------------------------------|
| `query.rs`       | DNS query builders (A, AAAA, PTR, EDNS0)     |
| `parse.rs`       | Response parsers (A, AAAA, PTR, name decode) |
| `cache.rs`       | TTL-aware DNS response cache + static hosts table |
| `resolve.rs`     | Resolution orchestration                      |

### Resolution Strategy (`resolve::resolve_hostname`)

1. **Static hosts table** — check `cache::lookup_hosts(hostname)`.
2. **DNS cache** — check `cache::cache_lookup(hostname, now)` for a
   previously-resolved entry whose TTL has not expired.
3. **DNS query** (bare-metal only) — send an A-record query via UDP to the
   configured nameserver (`stack.dns_server()`, usually set by DHCP).
   Polls `recv_from()` in a spin loop with `DNS_QUERY_TIMEOUT_TICKS = 200`
   (2 seconds) and up to `DNS_MAX_RETRIES = 2`.  On success the result is
   inserted into the TTL-aware cache.

The `resolve_dual_stack()` function tries AAAA first (IPv6), then falls back
to A (IPv4).  On host builds, DNS resolution is handled by the OS, and
`resolve_hostname` returns `Error::NotFound` unless the hosts table has an
entry.

## Network Syscalls

The network API surface exposes 22 syscalls (numbered 37--80) to user space,
with 17 corresponding wrappers in the shared user library (`src/user/shared/`).
These cover:

- `SYS_SOCKET` / `SYS_CLOSE_SOCKET` — create and destroy socket handles
- `SYS_BIND` — bind UDP port or listen TCP port
- `SYS_CONNECT` — TCP active open
- `SYS_LISTEN` — TCP passive open
- `SYS_ACCEPT` — accept pending TCP connection
- `SYS_SENDTO` / `SYS_RECVFROM` — UDP send/receive datagram
- `SYS_SEND` / `SYS_RECV` — TCP stream read/write
- `SYS_GETSOCKOPT` / `SYS_SETSOCKOPT` — socket option get/set
- `SYS_GETHOSTNAME` / `SYS_SETHOSTNAME` — kernel hostname
- `SYS_NETWORK_STATUS` — query backend capabilities

## Socket Lifecycle

The generic lifecycle for all socket types:

```
create → bind → [listen → accept] → read/write → close
          ↗
       connect (TCP only, skip bind/listen/accept)
```

- **create**: `TcpConnection` / `TcpListener` / `UdpSocket` / `LocalSocket`
  are instantiated by their respective constructors.
- **bind**: `bind_udp(port)` registers in the `UdpSocketTable`;
  `listen_tcp(port, backlog)` registers in the `TcpConnectionTable`.
- **connect**: `connect_tcp(host, port)` resolves (via DNS or hosts table)
  and performs the three-way handshake through `tcp::connect()`.
- **listen/accept**: `listen_tcp()` creates a listener entry; incoming SYN
  segments are routed by `process_segment()` to the listener, which spawns
  a child `TcpConnectionState` in `SynReceived`.  When the handshake
  completes the child is moved to the listener's backlog, where
  `accept_nonblocking()` (called from `accept_tcp()`) retrieves it.
- **read/write**: TCP uses `TcpConnectionState::read()` and `write()` on the
  send/recv buffers.  UDP uses `UdpSocketTable::recv_from()` / `send_to()`.
- **close**: TCP `close()` initiates the FIN handshake; UDP `close()` unbinds
  the port; local socket `unbind_local()` removes the path from the registry.

## Readiness Checks

Each socket type exposes `is_readable()` and (for TCP/TLS) `is_writable()`
for non-blocking I/O multiplexing:

| Type            | `is_readable()`                                             | `is_writable()`                                          |
|-----------------|-------------------------------------------------------------|----------------------------------------------------------|
| `TcpConnection` | `state.available() > 0` or state in `CloseWait/Closing`      | State in `Established/CloseWait/FinWait1/FinWait2`       |
| `TcpListener`   | `listener_has_pending(&table, port)` — backlog non-empty    | N/A                                                      |
| `UdpSocket`     | `table.has_pending(port)` — receive queue non-empty         | N/A (connectionless — always writable if bound)          |
| `LocalSocket`   | `!pending.lock().is_empty()` — accept queue non-empty       | N/A                                                      |
| `TlsWrappedConnection`| Decrypted read buffer non-empty, then delegates to `TcpConnection::is_readable()` | Delegates to `TcpConnection::is_writable()` |

These checks are used by the kernel's poll/select emulation and by user-space
event loops to determine when I/O operations will not block.

---

## See Also

- [Subsystem overview](../en/network.md) — high-level network stack description
- [Documentation index](../README.md) — complete document tree
