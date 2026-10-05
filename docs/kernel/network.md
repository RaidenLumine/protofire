# Networking

`src/network/` is the kernel's own TCP/IP stack.  On a bare-metal build a boot
brings it up over the VirtIO NIC a driver probe found; on a host build the same
API is served by `std::net`, so the callers above the stack can be tested
without a device.  The thing the stack talks to is `NetworkDevice`
(`src/network/link/device.rs`), implemented by `src/drivers/virtio_net.rs`.

Two properties shape everything below: the stack is *polled*, not fed by a
receive interrupt, and its periodic work is split between a single atomic
clock in the tick handler and a pass that runs on the maintenance thread.

## The stack and how a boot gets one

`NetworkStack` (`src/network/stack/mod.rs`) owns the device, the addresses, the
tick counter and every per-protocol table: ARP, TCP, UDP, DCCP, the IPsec SPD
and SAD, NAT, IPv4 and IPv6 fragment reassembly, the routing table, IGMP/MLD
host state, raw sockets, the NTP client, the mDNS responder, PPP/PPPoE state
and the packet filter.  `init_with_device`
(`src/network/stack/global.rs`) builds it, publishes it behind an `AtomicPtr`,
and sends a gratuitous ARP so the segment learns our MAC.  `global()` is how
the rest of the kernel reaches it.

`Kernel::init` (`src/kernel/mod.rs`) calls `init_with_device` only when
`drivers.boot_net_device()` found a NIC, with `0.0.0.0` and the QEMU
user-mode defaults for DNS, gateway and mask.  It then runs
`dhcp::discover_and_request`, applies whichever of the lease's options came
back, falls back to the QEMU guest address when DHCP fails, and arms IPv6 with
`start_slaac`.  No NIC, no stack: `global()` stays `None` and the network
syscalls answer `Unsupported`.

### The two backends

`KernelTcpBackend` (`src/network/mod.rs`) names the choice.  A bare-metal build
gets `Native`, the stack described here.  A host build gets
`HostRuntimeCompat`, which delegates connect, listen, accept and stream I/O to
`std::net`; the tests drive the native stack directly by installing one.

The choice is visible to programs.  `NetworkCapabilities` is derived from a
`NetworkStatus` flag word (`src/abi/net.rs`), and `network_status()` returns
it: available, requires-host-runtime, TCP connect/listen, UDP datagram, stream
IO, read timeouts, zero-timeout-read-is-poll and IPv6.  A bare-metal build
reports the native backend as available only while a stack is installed, so a
machine with no NIC is distinguishable from one that has not been asked yet.

## Polling and the clock

`NetworkStack::poll` (`src/network/stack/dispatch.rs`) reads one frame from
the device, parses the Ethernet header and demuxes it; `Ok(false)` means the
device had nothing.

The NIC's interrupt does not deliver packets.  On the machines whose NIC
claims MSI-X, the interrupt is what ends a transmit or command *completion
wait* (`wait_for_queue_interrupt` in `src/drivers/virtio_net.rs`); received
frames are drained by whoever calls `poll()`.  The callers are the operations
that wait on the network itself: the loop in `tcp::connect`, the accept loop,
the DNS resolver, DHCP discovery, and the ARP and NDP resolution paths.  A
bare-metal stream read does not poll — `NativeTcpConnection::read` spins on
the receive buffer and the clock — so a read makes progress while some other
caller is polling, and times out if none is.  There is no receive thread and
no interrupt-driven dispatcher, which is a scope statement about the stack
rather than a plan.

The receive buffer is one static on bare metal; the code documents the
single-poller assumption and names SMP as what would replace it.  The protocol
tables are behind `Mutex`; the four addresses (local IPv4, DNS, gateway, mask)
are `SyncUnsafeCell` with a single-writer contract that the boot's DHCP write
relies on.

Time is split the same way.  `advance_clock` is a single atomic add and runs
from the scheduler tick (`src/kernel/process/scheduler/timer.rs`), which then
asks the maintenance thread for a pass; `run_maintenance` is that pass and
never runs in interrupt context, because parts of it transmit and a transmit
waits on the device.  It evicts expired ARP and DNS entries, runs TCP
retransmission and TIME-WAIT checks, drives SLAAC, expires fragment, NAT and
filter entries, polls NTP, ticks mDNS, IGMP/MLD and PIM, and renews the DHCP
lease when its timers say so.  The host build has no maintenance thread, so
`advance_tick` does both halves and the tests call it directly.

## The demux

### Link and internet

`ethernet::parse_frame` (`src/network/link/ethernet.rs`) yields the frame; the
EtherType decides what comes next.

- **ARP** goes to `arp::process_arp_packet`; the cache
  (`src/network/internet/arp.rs`) has a tick-based TTL, and outbound
  resolution is `resolve_mac`.
- **IPv4** is parsed, then dropped unless the destination is one of ours, a
  broadcast or a multicast (a foreign packet must not provoke a reply).  In
  order: fragment reassembly (`FragmentCache`), reverse NAT, the inbound
  packet filter, raw-socket copies, and then exactly one of ICMP, IGMP, PIM,
  UDP or TCP.
- **IPv6** gets the same treatment through the extension-header chain
  (hop-by-hop, destination options, routing), with the fragment header handled
  first; then ICMPv6/NDP, MLD, PIM, TCP or UDP.  PMTU state is kept per
  destination (`PmtuCache`), and the link MTU is learned from router
  advertisements.

ICMP errors are acted on: `react_to_icmp_error` removes a TCP connection that
is still in SYN-SENT, which is what makes `connect` fail fast instead of
running out its timeout.  A connection that is already established is left
alone — that is the RFC 1122 soft-error choice, and the code says so.  There
is no connected-UDP notion, so a UDP error is not recorded against a port.

### Transport

TCP and UDP are demultiplexed by port; both are dual-stack, keyed on
`IpAddress::V4`/`V6`.  Raw sockets receive a copy of every IP payload whose
protocol number they asked for, and there is one queue per raw socket.

## TCP

`TcpConnectionState` (`src/network/tcp/types.rs`) carries the state machine,
the send and receive sequence variables, a `VecDeque` receive buffer, the
`RetransmitState`, the congestion state, the ECN state and `SocketOptions`.
`TcpConnectionTable` (`src/network/tcp/table.rs`) is a `BTreeMap` keyed by
`(local_port, remote_ip, remote_port)`, with listeners in the same table
keyed by port, each holding a backlog of children waiting for `accept`.
Ephemeral ports are allocated from `EPHEMERAL_PORT_START` to
`EPHEMERAL_PORT_END` and reserved in a set so a listener and a connection
cannot collide.

The operations are `tcp::connect`, `tcp::listen`, `tcp::accept_nonblocking`,
`tcp::process_segment`, `tcp::close` and `tcp::retransmit_check`.  On the
wire, the receive window is the space left in `MAX_RECV_BUFFER` shifted by the
negotiated window-scale option, so a full buffer advertises zero and applies
backpressure.

Retransmission is `RTO_BASE_TICKS`, doubled per attempt up to
`MAX_BACKOFF_MULTIPLIER`, giving up after `MAX_RETRIES` and closing the
connection; a closed connection lingers for `TIME_WAIT_TICKS` before it is
removed.  Congestion control (`tcp/congestion.rs`) is Tahoe or Reno —
`CongestionAlgorithm` is an enum, not a plug-in registry — and ECN
(`tcp/ecn.rs`) negotiates and reacts to CE marks.

`SocketOptions` is set and read through `setsockopt`/`getsockopt`
(`tcp/table.rs`).  Two fields are worth naming for what they are not:
`keepalive` is stored and reported but no probe is ever sent from
`tick_maintenance`, and there is no delayed-ACK path — the status document
used to imply both.

## UDP

`UdpSocketTable` (`src/network/udp.rs`) is keyed by local port; each socket
has a queue of `(source, port, payload)`.  `bind` reserves a port,
`deliver` pushes a datagram, `recv_from` pops one, and `has_pending` is what
`is_readable` reports.  `send_to` builds the IP header
(`build_udp_ipv4_packet`/`build_udp_ipv6_packet`) and goes out through the
same ARP/NDP resolution as any other packet.  The send path releases the UDP
table lock before resolving, because resolution can poll and the poll path
takes the table.

## Local sockets

`src/network/local.rs` is the same-machine rendezvous, not IP.  A
`LocalSocket` is registered under a filesystem path in a global map;
`connect_local` allocates a kernel pipe pair, pushes the read end into the
socket's accept queue and returns the write end, so a connection is one
unidirectional pipe.  The queue is bounded by `LOCAL_SOCKET_BACKLOG`.
`LocalSocket` is a `KernelObject` variant, and the three syscalls are
`BindLocal`, `ConnectLocal` and `AcceptLocal`.

## Names and configuration

Several things run at once here, and they are separate mechanisms:

- **DHCP** (`src/network/dhcp.rs`) sends discovery on the client port and
  accepts offers and acknowledgements, parses the address, DNS, router, mask
  and lease-time options, and keeps the lease so `run_maintenance` can renew
  it at T1/T2.  A boot applies the result; a host build has no DHCP.
- **DNS** (`src/network/dns/`) tries the static hosts table
  (`lookup_hosts`), then the TTL-capped response cache, then an A query to
  the configured server on bare metal, with `DNS_QUERY_TIMEOUT_TICKS` and
  `DNS_MAX_RETRIES`.  `resolve_dual_stack` prefers AAAA, but the user-facing
  `resolve_hostname` returns an IPv4 address and the connect path uses it.
- **SLAAC** (`src/network/stack/slaac.rs`) is armed at boot and stepped by
  the tick: router solicitations, then the duplicate-address-detection window
  for the address an advertisement forms.
- **NTP** (`src/network/ntp.rs`) polls from the maintenance pass, resolving
  its server through DNS the first time; the current offset is kept in the
  client.
- **mDNS** (`src/network/mdns.rs`) is a responder for the host name, driven
  by the same pass.
- **IGMP and MLD** (`src/network/internet/igmp.rs`, `mld.rs`) keep host
  membership state and emit the reports the maintenance pass collects.

## TLS

`src/network/tls/` is a TLS 1.3 client: `record.rs` is the record layer
(AES-128-GCM or ChaCha20-Poly1305), `handshake.rs` parses the
ServerHello…Finished sequence, derives the key schedule and verifies the
Finished verify-data, and `certificate.rs` is a hand-rolled DER/X.509 parser
with chain verification.  `TlsConnection` is the handshake state machine and
`TlsWrappedConnection` is the post-handshake stream that encrypts writes and
decrypts reads.  `tls_connect` is the whole sequence, and the `TlsConnect`
syscall hands back a descriptor that does that transparently.

Trust anchors exist and are checked: `root_store::trusted_roots` is a small
built-in demo CA set, and `verify_chain` requires the chain to terminate at
one of them after checking validity, hostname and each signature.  What does
not exist is a way to change that set at runtime — no trust-store
configuration and no per-connection anchor.

## IPsec

The outbound path is wired: `send_ipv4_packet` and `send_ipv6_packet`
(`src/network/stack/send.rs`) call
`ipsec::transform::process_outbound_v4`/`_v6`, which consult the SPD and SAD
the `IpsecAddSp`/`IpsecAddSa` and their `Del` counterparts maintain.  The
inbound counterparts, `process_inbound_v4`/`_v6`, exist but no dispatch path
calls them, so a tunnel can be configured and will transform what this host
sends, while inbound ESP/AH is not unwrapped.

## What is in the tree but not on the wire

The tree carries more protocol code than a boot uses, and the difference is
worth naming because the old document read it as capability:

- **DCCP** has a connection table in the stack and seven syscalls that
  operate on it, but the receive path never dispatches to it.
- **SCTP** is a module with test coverage and nothing else: no syscall, no
  dispatch.
- **WireGuard** is declared as a module and referenced nowhere; no code
  constructs a device.
- **PPPoE/PPP** has a state machine and a maintenance hook behind
  `set_pppoe_enabled`, whose only caller is a test.  NAT is the same shape:
  the receive and send paths consult `NatTable`, but nothing outside the
  tests enables it.
- **PIM-DM** messages are parsed by the IPv4 and IPv6 dispatch arms and the
  `Mrt*` syscalls manage the MRT state, but the module's own header records
  that its flood/forward helpers have no live caller.
- **IPv4 options, Mobile IP and RSVP** are compiled only with
  `educational_networking` (or the test harness).

## The syscall surface

The network entry points are `SyscallNumber` variants in
`src/syscall/table.rs`, handled by `src/syscall/network.rs`,
`src/syscall/tls.rs`, `src/syscall/filter.rs`, `src/syscall/ipsec.rs` and
`src/syscall/mrt.rs`.  Named by what they do: `NetworkStatus`, `ConnectTcp`,
`ListenTcp`, `AcceptTcp`, `BindUdp`, `SendToUdp`, `RecvFromUdp`,
`GetSockName`/`GetPeerName`, `SetSockOpt`/`GetSockOpt`, `GetHostName`/
`SetHostName`, `ResolveHostname`, `CreateRawSocket`/`SendRawPacket`/
`RecvRawPacket`, `BindLocal`/`ConnectLocal`/`AcceptLocal`, `TlsConnect`, the
`Filter*` group, the `Dccp*` group, the `Ipsec*` group and the `Mrt*` group.
A TCP stream is read and written through the generic `Read` and `Write`.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/network/stack/` | `NetworkStack`: the singleton, its tables, demux, send and maintenance |
| `src/network/link/` | `NetworkDevice`, Ethernet framing |
| `src/network/internet/` | IPv4, IPv6, ARP, ICMP, ICMPv6/NDP, IGMP, MLD, fragments, NAT, PMTU |
| `src/network/tcp/` | The state machine, table, segments, congestion and ECN |
| `src/network/udp.rs`, `src/network/raw.rs` | Datagrams and raw IP sockets |
| `src/network/local.rs` | Path-named local sockets |
| `src/network/dhcp.rs`, `src/network/dns/`, `src/network/stack/slaac.rs`, `src/network/ntp.rs`, `src/network/mdns.rs` | Configuration and naming |
| `src/network/tls/` | TLS 1.3, the record layer and the certificate chain |
| `src/network/ipsec/`, `src/network/filter/` | ESP/AH transform, and the packet filter |
| `src/network/net_profiler.rs` | Packet and error counters behind the `net_profiler` feature |
| `src/syscall/network.rs` | The socket and DNS handlers |

## See also

- [drivers.md](drivers.md) — the VirtIO net driver and where its completions
  come from
- [interrupts.md](interrupts.md) — the MSI-X identities a NIC queue claims
