# RFC 0031: Let a TCP reader wait instead of spin

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-20
- **Supersedes:** none

## Summary

`NativeTcpConnection::read` spins on the receive buffer and the tick counter.
Nothing wakes it, and nothing polls on its behalf: it makes progress only while
some *other* caller is driving the device.  This decides that a TCP connection
gets the same wait queue a UDP socket got in RFC 0029 — a reader parks on its
connection, the segment that fills the buffer wakes it — and that the deferred
receive thread counts a waiting reader as work to poll for.

## Motivation

`docs/status.md` has recorded this as a weakness for as long as the row has
existed: "a read depends on another caller driving the device".  RFC 0029
closed it for name resolution and left TCP alone, saying so explicitly, because
converting UDP was already a four-stage change.

The gap is not cosmetic.  A program that reads from a socket is usually the
process the machine exists to run at that moment, and on a quiet machine
nothing else calls `poll()`.  The read therefore burns a core for its whole
timeout — the same defect RFC 0029 removed from the resolver, in the place
where it is most likely to be seen.  `Makefile`'s own run targets boot a shell
that does exactly this.

The shape is also the one RFC 0029 already chose: a `WaitQueue` owned by the
thing that has data, woken by whatever delivers the data, with the deferred
receive thread polling only while somebody is parked.  Reusing it is not a new
mechanism, and a second design here would be a second way to wait in one stack.

## Current state

- `src/network/tcp/table.rs` — `NativeTcpConnection::read` loops: look up the
  connection, take its `Mutex`, call `state.read`, and if that returned nothing
  check the clock and loop.  There is no sleep and no yield.
- `src/network/tcp/types.rs` — `TcpConnectionState` owns `recv_buffer:
  VecDeque<u8>` and is reached through `Arc<Mutex<TcpConnectionState>>`.
- `src/network/tcp/ops.rs` — `process_segment` extends `recv_buffer` when data
  arrives in order (around line 564) and queues out-of-order segments for
  later.  This is the only place received bytes are added.
- `src/network/udp.rs` — `UdpSocket` owns a `WaitQueue<u64>`; `DatagramWait`
  hands out a handle naming it through an `Arc`; `DatagramWait::wait` returns
  `DatagramWaitOutcome` (`AlreadyQueued` / `Parked` / `CannotPark`).
- `src/kernel/maintenance.rs` — `kernel-net-rx` polls while
  `NetworkStack::has_receive_waiter()` is true, which today asks only the UDP
  table.

## Design

**The connection owns a `WaitQueue<usize>` whose state is the receive buffer's
length.**  Same shape as the UDP socket: `deliver`-equivalent pushes then
wakes, the reader drains then checks.  The count lets a waiter decide whether
to park without taking the connection's own lock, which matters because the
reader already holds it when it asks.

**`process_segment` wakes after extending the buffer.**  It holds the
connection's `Mutex` at that point; the wake is issued from inside that
critical section, after the bytes are in.  That ordering is the whole
correctness argument and it is the same one `UdpSocketTable::deliver` makes:
a waiter that observes a wake and finds the buffer empty can only be looking
at data another reader took.

**`NativeTcpConnection::read` becomes drain-then-park.**  It drains, and when
that yields nothing it takes a handle on the connection's wait queue and parks
until the next delivery or its deadline.  A wake is not trusted as "data is
here" — another reader may have taken it, and the deadline arrives as a wake
too — so the loop always re-drains and re-checks the clock.  This is exactly
RFC 0029's loop, and it should read as the same code doing the same thing.

**`has_receive_waiter` learns about TCP.**  The deferred receive thread's job
is to poll while *anybody* is parked, and "anybody" now includes a TCP reader.
Without this the reader would park and nothing would ever drive the device —
the failure mode RFC 0029's stage 3 exists to prevent, reappearing one
protocol over.

**A closed connection ends the wait.**  A reader parked on a connection whose
peer sends FIN or RST, or which is reaped, must not sleep until its deadline:
the close path signals the same wait queue.  `TcpConnectionTable::remove` and
the state transitions into `Closed` are the places to find.

**Landed:** `TcpConnectionState::readable`, `TcpReadWait`, `wake_reader` and
`ReaderNotifier` (`src/network/tcp/types.rs`), the wake in `process_segment`
(`src/network/tcp/ops.rs`), the drain-then-park loop in
`NativeTcpConnection::read` (`src/network/tcp/table.rs`), and the TCP half of
`NetworkStack::has_receive_waiter` (`src/network/stack/config.rs`).

## Alternatives

**Leave it spinning, and record it.**  It is what the tree does today and the
gate does not notice.  It loses because the defect is user-visible — a quiet
machine with one reader burns a core — and because `docs/status.md` already
calls it a weakness, so the document is asking for this change.

**Give the reader a periodic wake instead of a queue.**  Smaller: a timer
wakes the reader, it re-drains, goes back to sleep.  It loses because it
changes nothing about who drives the device — the reader still cannot receive
while it sleeps — so it would only replace a spin with a slower spin.  RFC
0029 rejected the same option for the resolver.

**Poll the device from the tick.**  The RFC 0029 answer applies unchanged: the
tick is interrupt context and `poll()` takes locks and can block.  The thread
is the poller.

**One wait queue for the whole TCP table.**  Fewer objects, one wake for any
data anywhere.  It loses because every reader would wake for every segment of
every connection: an N-way connection table with N readers becomes N wakes per
segment, and each of them re-drains and re-parks.  Per-connection is what the
data belongs to.

## Drawbacks

The wake is tick-granular for the same reason UDP's is: the poller runs every
tick while somebody waits.  A reader that would have been answered in
microseconds takes up to 10 ms.  That is the price of not burning a core, and
it is the same trade RFC 0029 already accepted for DNS.

A reader parked on a connection holds no lock, so the connection can close
under it.  That is why the close path has to signal the queue; a close that
signalled only the buffer's length would leave the reader sleeping with a
buffer it can never fill.

`read` with `timeout_ticks == 0` must stay a pure probe, and a probe must not
signal the receive thread — otherwise every non-blocking read on the machine
would cause a device poll.

## Compatibility and migration

No ABI change.  `SyscallNumber::ReadSocket` keeps its behaviour: a blocking
read returns the same bytes, a zero-timeout read still returns `Ok(0)`.

The host build is unaffected: `NativeTcpConnection::read` is bare-metal only
and the host backend delegates to `std::net`.

## How this is proven

**The reader parks and is woken.**  A host test drives the real `read` against
a connection with no data and a threaded scheduler, then extends the receive
buffer from the "sender" and asserts the reader returned the bytes.  The
current tree cannot pass it: `read` never sleeps, so the test's second thread
would never run.

**A probe does not park.**  A zero-timeout read on an empty connection returns
`Ok(0)` and leaves `waiting_count()` unchanged.

**A closed connection ends the wait.**  A reader parked on a connection that is
then removed returns rather than sleeping to its deadline.

**A waiting reader is work for the poller.**  `has_receive_waiter` answers true
while a TCP reader is parked, which is what makes the deferred receive thread
drive the device for it.  This is the assertion that would catch the
"registered but never polled" failure, which is the one this change could
plausibly introduce.

## Unresolved questions

**Two readers on one connection.**  The queue wakes one waiter, and both would
drain the same buffer.  POSIX does not promise otherwise for a single socket,
and nothing here adds a rule; whether this ABI should refuse a second
concurrent read is a decision of its own.

**A writer is never blocked, which is a different gap.**  This RFC's first
draft said a writer stopped by a full peer window still spins.  It does not
spin, because it is never stopped: `TcpConnectionState::write` appends to
`send_buffer` without a bound and answers with the whole length, so `write`
accepts everything and `write_all`'s retry loop always finishes in one pass.
Whatever does not fit the peer's window waits in the buffer instead.

So the unresolved question is not a wait queue but a bound, and the risk is
the opposite of a spin: a peer that stops reading while the writer keeps
writing grows `send_buffer` for as long as the program keeps asking.  Nothing
in this tree refuses, and no gate exercises it.  Deciding what a full send
buffer should do — refuse with `WouldBlock`, park until the window opens, or
keep growing until memory says no — is a socket-semantics decision like the
ephemeral-port one RFC 0030 took, and it is not this RFC's.
