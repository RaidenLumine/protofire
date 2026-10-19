# RFC 0029: Wait for a DNS answer instead of polling for one

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-19
- **Supersedes:** none

## Summary

Name resolution spins.  `src/network/dns/resolve.rs` sends the query and then,
for up to `DNS_QUERY_TIMEOUT_TICKS` (200 ticks, 2 s) per attempt and up to
three attempts, calls `NetworkStack::poll()`, tries `recv_from` on a bound
UDP port, and calls `scheduler::yield_current()` — six hundred iterations of
that in the worst case, all to discover whether one datagram arrived.

This decides that the resolver **sleeps on a wait queue the UDP socket owns**
and is woken when a datagram is delivered to it.  That requires two
prerequisites the tree does not have yet, and one of them is a defect on its
own: `poll()` documents an assumption that the kernel is single-threaded, and
it is not.  The decision is therefore staged, with each stage landing and
being gated on its own.

## Motivation

Three costs, in the order they matter.

**The spin is expensive.**  A resolution that is answered on time still
executes the loop until the answer lands; one that is never answered executes
all six hundred iterations, each doing a device `receive`.  The loop's only
yield point is `yield_current`, which does not sleep — it asks the scheduler
to look at the run queue and returns.  A machine with nothing else runnable
spins a core at full speed for two seconds per attempt.

**The dependency is wrong.**  The two `yield_current` calls are the whole of
the `network` -> `process` census edges that are not a shared constant (the
third was `RawSocketHandle`, which moved to `network`).  A network protocol
naming the scheduler in order to wait is the same shape
`docs/fmts/code-style.md` argues about for drivers: acceptable at the bottom
of a wait, but only because there is no other primitive — and here there is
one, in `kernel::process::wait`, which `serial` and `virtio_net` already use
for their own devices.

**The loop cannot be made safe as it stands.**  At the time this was written,
`NetworkStack::poll` carried this line:

```rust
// SAFETY: `poll()` is never called concurrently — the kernel is
// single-threaded in bare-metal builds.
```

and read into a single static `RX_BUFFER`.  The kernel schedules on up to
seventeen CPUs, and two processes resolving two names are two threads in this
loop at once.  The assumption was already false; the loop is what made it
look true, because a spinning caller was the only caller.  Any design that
lets something other than the waiter poll — which is every design below —
had to make `poll` safe first, and stage 1 does.

## Current state

- `src/network/dns/resolve.rs` — `resolve` and `resolve_v6` each own a copy of
  the loop.  Both filter answers by the configured nameserver, and `resolve`
  additionally by the 16-bit transaction id; a malformed answer is ignored and
  the loop continues.
- `src/network/udp.rs` — `UdpSocketTable::deliver` pushes onto the socket's
  `receive_queue: VecDeque` and returns.  `recv_from` pops or answers
  `Err(Error::TimedOut)`; there is no wait queue anywhere in `src/network/`.
- `src/network/stack/dispatch.rs` — `poll()` reads one frame from the device,
  parses it, and demuxes.  Since stage 1 landed, the device read and the copy
  out of `NetworkStack::rx_buffer` happen under that buffer's lock, and the
  demux runs on the copy afterwards; before that, the read used one static
  buffer whose comment claimed serialisation by single-threadedness.
- `src/kernel/process/wait/queue.rs` — `WaitQueue` with `block_current_if`,
  `block_current_until_if` and `plan_timed_wait`; `src/drivers/serial.rs` and
  `src/drivers/virtio_net.rs` use it for their own devices' input and
  completion.
- `src/network/stack/dispatch.rs` — `run_maintenance()` does **not** poll, and
  the timer tick only advances the clock and requests a maintenance pass.  So
  nothing in the tree drives the receive path except a caller that is itself
  in a poll loop: the resolver, `arp`, the TCP accept path, DHCP, and the
  shell's `network` command.

That last fact decides the shape of the design: if the resolver sleeps, the
receive path stops entirely unless something else polls.

## Design

Four stages.  Each is a separate change with its own gate; a stage that is
not implemented leaves the tree exactly as it is now.

### Stage 1 — `poll()` becomes safe for more than one caller

Either give the receive path a lock, or give each poller its own buffer.

The choice here is a **single receive lock** owned by the stack, with the
buffer inside it.  A per-caller buffer would move the race rather than end it:
`deliver` into the UDP table still has two writers, and the demux path mutates
the ARP, TCP and UDP tables.  One lock means one rule, and it is the rule the
stack already follows everywhere else.

**What the lock covers, and what it cannot.**  The decision above is about
ownership of the buffer, not about holding a lock for the length of the
receive path.  The first draft of this RFC said the lock would be held "across
one `receive` and the demux of its frame"; that is not implementable.  The
demux transmits on several paths (an ICMP echo reply, a TCP acknowledgement,
an ICMP port-unreachable), and a transmit resolves a neighbour that is not
cached by calling `poll()` again (`arp::resolve_mac`).  A lock held across the
demux is therefore taken recursively on one thread, and the release would
never run.  Taking it without masking interrupts does not rescue it either:
the neighbour resolution that recurses is a spin-wait on the stack's own
clock, so a demux that froze the tick would wait for a timeout that cannot
advance.

So the lock covers exactly what a second caller can tear: the device read and
the copy of the frame out of the shared buffer.  The demux then runs on the
copy, after the lock is released.  That is still sufficient for safety —
every table the demux touches (`arp_cache`, `tcp_table`, `udp_table`,
`fragment_cache`, `nat_table`, `filter_table`, the raw-socket map) is behind
its own `Mutex`, so concurrent demuxes serialise there rather than on the
receive buffer.  Two pollers may demux two frames in either order; the
protocols already accept reordering (TCP queues out-of-order segments, IP
reassembly buffers fragments), and nothing in the receive path requires that
two frames from the device reach the tables in the order the device produced
them.

The copy also closes a second, single-threaded hole that the old static
buffer had: a nested `poll()` during the demux read a new frame into the same
storage while the outer frame's bytes were still being used.  Owned bytes make
the recursion safe whether or not two CPUs are involved.

The lock is the stack's ordinary `Mutex`, so it masks interrupts for the
length of the device read and the copy.  Interrupt context must not call
`poll()` anyway: the demux can send, and a send that misses the neighbour
cache spin-waits on the stack's clock, which is not something a handler can
do.  A handler that needs the receive path leaves that work to the tick,
exactly as RFC 0021 already decides for xHCI.

**Landed:** `NetworkStack::rx_buffer` is a `Mutex<[u8; 2048]>`, and
`receive_frame` (`src/network/stack/dispatch.rs`) is the only reader of the
device.  The same code runs in the host and bare-metal builds, so the host
test exercises the path a boot runs rather than a stack-buffer substitute.

### Stage 2 — a UDP socket can be waited on

`UdpSocket` gains a `WaitQueue<()>`.  `deliver` pushes the datagram and then
notifies the queue — under the table lock it already holds, or after releasing
it, as long as the datagram is queued before the notification.  A waiter that
wakes, takes the table lock, and finds the queue empty has seen a spurious
wakeup and blocks again.

### Stage 3 — something other than the waiter drives the receive path

This is the part with a real choice, and it is the part this RFC is mostly
about.

The tick asks the network stack for a receive **only while someone is
waiting**.  A registration count — the shape the MSI-X claim already uses for
"is this armed" — is incremented when a waiter blocks and decremented when it
leaves; the tick's half is one atomic load and, when the count is non-zero,
one `poll()`.

That keeps an idle machine free of a per-tick `receive`, which is the reason
not to simply poll unconditionally: a 100 Hz receive on a machine with no
network traffic is work nobody asked for.

### Stage 4 — the resolver blocks instead of spinning

Both loops become: send, then `block_current_until_if(deadline, ...)` with the
same nameserver and transaction-id filter, rechecking the queue on every
wakeup, up to the existing retry count.  The deadline is the same 200 ticks;
the difference is that the thread is parked rather than yielding.

The ephemeral binding, the retry-on-timeout rebind, and the final unbind stay
as they are — they are not part of what is wrong.

## Alternatives

**Leave it as it is, and record the edge as debt.**  The loop works and the
tree has shipped with it.  It loses because the assumption in `poll`'s SAFETY
comment is false today, so the status quo is not merely slow — it is
unsound the first time two threads resolve at once — and because six hundred
device reads to learn one datagram landed is the kind of cost a boot gate
should not be paying on every name a service resolves.

**Poll the stack on every tick, unconditionally.**  Simplest possible
coupling and no registration count to get wrong.  It loses on an idle
machine: every tick would call `receive` on a device with nothing to say, and
the tick is the one path in the kernel that must stay short.

**Have the device's MSI-X handler call `poll()`.**  The most direct
completion-driven answer, and the handler already runs for each queue.  It
loses for now: `poll` demuxes through the whole protocol stack, which takes
locks and can allocate, and an interrupt must not wait on a thread holding
one.  It becomes the right answer when the demux path can be split into a
lock-free enqueue and a deferred pass — that is a larger change than this
one, and this RFC does not depend on it.

**A dedicated network thread that polls in a loop.**  It would own the
receive path and make the wakeup model obvious.  It loses because it costs a
thread and a scheduling policy for a machine whose network is idle almost all
of the time, while the tick already exists and is already where the tree puts
"work that must happen on a clock".

**Sleep between polls instead of yielding.**  A one-line change that removes
the CPU burn without changing the architecture.  It loses because it does not
remove the dependency (the sleep is `process`'s), and because the waiter
still cannot receive while it sleeps: the poll that would deliver the answer
is the one it is not making.  It is a plausible fallback if the staged design
stalls — say so in review rather than discovering it later.

## Drawbacks

The registration count is new shared state between the scheduler and the
network stack, and a count that goes wrong in either direction is a bug with
two faces: too high and the tick polls forever, too low and a waiter is never
woken.  The decrement has to happen on timeout and on cancellation, not only
on success.

The wakeup is tick-granular.  A resolution that would have been answered in
100 µs still takes up to one tick (10 ms) to observe it.  That is a latency
regression against a spinning loop, and it is the price of not burning a
core; the shell and the NTP client are the users, and neither is latency
critical.

A spurious wakeup now costs a lock round trip rather than a loop iteration.
The wait must therefore recheck the queue and re-block, which is the standard
shape but is code that does not exist today.

## Compatibility and migration

No format and no ABI change.  `SyscallNumber::ResolveHostname` keeps its
blocking semantics and its return value; a caller cannot tell the difference
except that the machine does less work while it waits.

The host build is unaffected: `resolve` and `resolve_v6` are
`#[cfg(target_os = "none")]`, and the host path returns `NotFound` from the
hosts table.

Stage 1 is worth landing even if stages 2–4 never do: it fixes a documented
assumption that the SMP bring-up made false.

## How this is proven

**Stage 1.**  A host test (`two_pollers_receive_every_frame_intact` in
`src/network/stack/tests.rs`) runs two threads calling `poll()` against a
device that pauses halfway through writing each frame.  The pause is what
makes the race reachable: a second caller that is allowed into `receive` lands
between the two halves of someone else's frame.  The test asserts three
things — the device never sees two receives in flight, every frame is read
exactly once, and every datagram's payload is uniform, which a frame assembled
from two receives cannot be.  With the buffer back on the stack (the test
build's old shape) the first assertion fails on this tree.

**Stage 2.**  A host test: bind a port, register a waiter, call `deliver`,
assert the waiter woke.  `src/network/stack/tests.rs` and the mock device are
the scaffolding.

**Stage 3 and 4.**  No device on any gate's machine sends a DNS answer, so —
the same reasoning RFC 0023's IMSIC self-test follows — the kernel walks the
path itself.  A `dns` self-test binds the ephemeral port, arms the waiter,
delivers a synthetic A-record through `deliver`, and asserts the waiter woke
and that the record parsed and was cached.  The boot prints one line saying
it ran, and `make check-x8664-runtime` asserts that line.

The spin itself needs its own evidence, because a design that quietly keeps
polling would still pass the functional test.  The resolver counts its poll
iterations and the self-test logs the count; the gate asserts it is bounded
by the tick budget rather than by the old six hundred, and a run that still
spins fails it.

## Unresolved questions

**One ephemeral port, several resolvers.**  `DNS_EPHEMERAL_PORT` is a single
constant (53000) shared by every caller, and `bind` answering `AlreadyExists`
is ignored so that a second resolver silently reuses the first one's socket.
Two processes resolving at once can therefore take each other's answers; the
transaction-id filter makes that rare rather than impossible, and a name that
resolves to the wrong address is worse than one that fails.  This RFC does
not fix it — an allocation scheme for source ports is a decision of its own —
but the wait-queue work makes the collision more likely to be *observed*, and
the fix should be written down before the spin is removed.

**Whether the tick is the right poller at all.**  Stage 3 assumes it is,
following RFC 0021.  If the network stack later gains a deferred demux that
can run from the device's interrupt, the registration count becomes
unnecessary and should be removed rather than kept as a second path.
