# Networking

`src/network/` is the kernel's own TCP/IP stack.  On a bare-metal build a boot
brings it up over the VirtIO NIC a driver probe found; on a host build the same
API is served by `std::net`, so the callers above the stack can be tested
without a device.  The thing the stack talks to is `NetworkDevice`
(`src/network/link/device.rs`), implemented by `src/drivers/virtio_net.rs`.

Two properties shape everything below: the stack is *polled*, not fed by a
receive interrupt, and its periodic work is split between a single atomic
clock in the tick handler and a pass that runs on the maintenance thread.
"Polled" describes the device — its receive interrupt delivers no packets —
not the waiters: a thread waiting for a datagram parks, and the deferred
receive thread is what polls while it does.

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
DHCP discovery, and the ARP and NDP resolution paths.

A TCP reader is not among them either, since RFC 0031: it parks on the
connection's own `WaitQueue` (`TcpConnectionState::reader` returns a
`TcpReadWait`), and `process_segment` wakes it after extending the receive
buffer.  A close wakes every reader through `ReaderNotifier`, a guard
`process_segment` takes on entry so that none of its dozen returns can leave a
reader parked on a connection that will never fill again.

The DNS resolver parks the same way on the UDP socket's wait queue
(`UdpSocketTable::readiness` returns a `DatagramWait`), and the socket's
`deliver` wakes it.  Something has to drive the device while either sleeps, so
`Kernel::init` spawns `kernel-net-rx`
(`kernel::maintenance::network_receive_entry`): a kernel thread that blocks on
the UDP table's receive event until a waiter announces itself, then sleeps one
tick at a time while `NetworkStack::has_receive_waiter` — which asks both
transports — keeps answering yes.  On each pass it calls `poll_available`,
which reads up to 32 frames before letting the scheduler have the CPU back.  The tick cannot do this job — it is interrupt
context, and `poll()` takes locks and can transmit — and the maintenance
thread cannot either, because its pass resolves the NTP server's name.

A waiter that wakes is woken because a datagram or a segment was queued, but
it does not trust that: another waiter can have taken it, and a deadline is
delivered as
a wake too, so the resolver drains the socket and checks the clock before it
decides.  That is the condition-variable discipline `docs/fmts/code-style.md`
expects, and it is the shape RFC 0029 records.

The receive buffer is one `Mutex<[u8; 2048]>` on the stack, not a static, and
the lock is what makes `poll()` safe for its several callers.  It covers the
device read and the copy of the frame out of the buffer; the demux runs on
that copy after the lock is released, because the demux can transmit and a
transmit that misses the ARP cache polls again on the same thread.  The copy
also keeps a nested `poll()` from overwriting the frame its caller is still
demuxing.  Every table the demux touches is behind its own `Mutex`, so two
pollers can demux concurrently.  The protocol tables are behind `Mutex`; the
four addresses (local IPv4, DNS, gateway, mask) are `SyncUnsafeCell` with a
single-writer contract that the boot's DHCP write relies on.

Time is split the same way.  `advance_clock` is a single atomic add and runs
from the scheduler tick (`src/kernel/process/scheduler/timer.rs`), which then
asks the maintenance thread for a pass; `run_maintenance` is that pass and
never runs in interrupt context, because parts of it transmit and a transmit
waits on the device.  It evicts expired ARP and DNS entries, runs TCP
retransmission and TIME-WAIT checks, drives SLAAC, expires fragment, NAT and
filter entries, polls NTP, ticks mDNS, IGMP/MLD and PIM, and renews the DHCP
lease when its timers say so.  The host build has no maintenance thread, so
`advance_tick` does both halves and the tests call it directly.

The pass is also the one place a *lookup's budget* had to be thought about.
NTP resolves its server's name there, and since RFC 0029 that resolution
parks; the pass gives it `DNS_BACKGROUND_TIMEOUT_TICKS` and no retries instead
of the syscall's six seconds, so a nameserver that never answers costs one
short wait rather than the whole periodic pass.  The address it obtains is
stored on the client, so only the first poll pays it.

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
has a queue of `(source, port, payload)` and a `WaitQueue<u64>` whose state is
that queue's length.  `bind` reserves a port, `deliver` pushes a datagram and
wakes one waiter under the wait queue's own lock — datagram first, wake
second — `recv_from` pops one and decrements the count, and `has_pending` is
what `is_readable` reports.  `send_to` builds the IP header
(`build_udp_ipv4_packet`/`build_udp_ipv6_packet`) and goes out through the
same ARP/NDP resolution as any other packet.  The send path releases the UDP
table lock before resolving, because resolution can transmit and the
transmit path takes the table.

`readiness(port)` hands out a `DatagramWait`, which names the socket's wait
queue through an `Arc` so it outlives an `unbind`.  A caller drains with
`recv_from` and then calls `wait(deadline)`; it never holds the table across
the wait, because `deliver` needs the same table.  `wait` does not report
*why* it returned — the queue and the clock are what a caller asks — but it
does return a `DatagramWaitOutcome`: `AlreadyQueued` when the datagram landed
before the thread could park, `Parked` when it really did, and `CannotPark`
when there is no scheduler or no current thread.  A loop must stop on
`CannotPark`, because the deadline it watches is that scheduler's clock; and
`Parked` is the one outcome a caller can count as evidence that it waited
rather than spun, which is what the DNS self-test's park count means.

`bind_ephemeral` hands out a free port from `61000..=65535` (see the naming
section below for why that range).  It is one lock and one decision, so two
callers cannot be given the same port.  `bind` remains for a caller that
names a port.

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
  the configured server on bare metal.  The wait is a park on the socket's
  `DatagramWait`, not a poll loop; `resolve_within` takes the per-attempt
  budget and retry count, and the two callers differ there because their
  contexts do — a syscall spends `DNS_QUERY_TIMEOUT_TICKS` (2 s) over
  `DNS_MAX_RETRIES` attempts, while the maintenance thread's NTP lookup
  spends `DNS_BACKGROUND_TIMEOUT_TICKS` (200 ms) and does not retry, so one
  unanswered name cannot stall every other job in its pass.
  A lookup allocates a source port from `61000..=65535` for its whole life
  and gives it back through a guard, and draws a random transaction id per
  lookup rather than reusing a constant — the id is what tells its answer
  from one meant for a previous lookup on the same port.  The range starts
  above NAT's (`32768..=60999`), so a port handed to a socket can never be
  one NAT translates another connection to; TCP and DCCP stay in the
  overlapping block because their port space is separate from UDP's.
  `resolve_dual_stack` prefers AAAA, but the user-facing `resolve_hostname`
  returns an IPv4 address and the connect path uses it.  A boot walks the
  whole path once in `selftest.rs`, because no machine a gate boots answers a
  query: one thread parks in the real loop and another delivers a synthetic A
  record, and the printed line carries the park count so a resolver that kept
  polling is visible.  `DNS_PARK_COUNT` is that evidence.
- **SLAAC** (`src/network/stack/slaac.rs`) is armed at boot and stepped by
  the tick: router solicitations, then the duplicate-address-detection window
  for the address an advertisement forms.
- **NTP** (`src/network/ntp.rs`) polls from the maintenance pass.  Its server
  name is resolved the first time, and that resolution parks — so the pass
  reads the cached address under the client's lock, resolves outside it, and
  writes the result back.  Resolving under that lock was the one place in the
  tree that held a lock across a resolution, and it is gone rather than
  commented around: `NtpClient` no longer has a method that resolves.
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
