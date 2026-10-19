# RFC 0029: Wait for a DNS answer instead of polling for one

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-19
- **Supersedes:** none

## Summary

Name resolution used to spin: `src/network/dns/resolve.rs` sent the query and
then, for up to `DNS_QUERY_TIMEOUT_TICKS` (200 ticks, 2 s) per attempt and up
to three attempts, called `NetworkStack::poll()`, tried `recv_from` on a bound
UDP port, and called `scheduler::yield_current()` — six hundred iterations of
that in the worst case, all to discover whether one datagram arrived.

This decides that the resolver **sleeps on a wait queue the UDP socket owns**
and is woken when a datagram is delivered to it.  That required two
prerequisites the tree did not have, and one of them was a defect on its own:
`poll()` documented an assumption that the kernel is single-threaded, and it
is not.  The decision is therefore staged, with each stage landing and being
gated on its own.

All four stages have landed.  The one design change the draft did not foresee
is in stage 3: the poller is a kernel thread rather than the timer tick,
because the tick is interrupt context and `poll()` both takes a mutex and can
block.  Stage 3 below says why, and what it cost.

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

- `src/network/dns/resolve.rs` — each resolver used to own a copy of the spin
  loop.  Both filter answers by the configured nameserver, and the A path
  additionally by the 16-bit transaction id; a malformed answer is ignored and
  the loop continues.  They wait on the socket now.
- `src/network/udp.rs` — `UdpSocketTable::deliver` pushes onto the socket's
  `receive_queue: VecDeque`, wakes one waiter, and returns.  `recv_from` pops
  or answers `Err(Error::TimedOut)`.  A socket owns a `WaitQueue<u64>` whose
  state is the queue's length.
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
  the timer tick only advances the clock and requests a maintenance pass.  The
  receive path was therefore driven only by a caller that was itself in a poll
  loop: the resolver, `arp`, the TCP accept path, DHCP, and the shell's
  `network` command.

That last fact is what the design had to answer: if the resolver sleeps, the
receive path stops entirely unless something else polls.  That something is a
kernel thread now, and it polls only while a socket has a parked receiver.

## Design

Four stages.  Each was a separate change with its own gate; a stage that was
not implemented would have left the tree exactly as it was.

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

`UdpSocket` gains a `WaitQueue<u64>`.  Its state is the number of datagrams
queued — the same number as the length of `receive_queue` — so a waiter can
decide whether to park without taking the socket table's lock.  `deliver`
pushes the datagram and then increments the count and wakes one waiter, all
under the wait queue's own lock, so the datagram is queued before the
notification.  A waiter that wakes, takes the table lock, and finds the queue
empty has seen a spurious wakeup (or lost the datagram to another waiter) and
blocks again.

`recv_from` decrements the count as it pops, and `unbind` zeroes it before
waking every waiter: the datagrams left with the socket, and a waiter that
kept seeing a stale count would return to a socket that is no longer there.

The caller takes a `DatagramWait` handle under the table lock and waits on
that, not on the table.  It cannot hold the table across the wait — `deliver`
needs the same lock — and it must not need the table to learn whether its wait
succeeded: that question is answered by `recv_from` and by the clock, which is
the ordinary condition-variable discipline.  The handle holds the wait queue
through an `Arc`, so a waiter still parked when the socket unbinds keeps a live
queue to be woken on.

**Landed:** `UdpSocketTable::readiness` and `DatagramWait`
(`src/network/udp.rs`); `tests/net/udp_wait.rs` covers the delivery wake, the
deadline, the datagram that arrived before the wait, and the unbind wake.

### Stage 3 — something other than the waiter drives the receive path

This is the part with a real choice, and it is the part this RFC is mostly
about.

The requirement is only that something drives the device **while a socket has
a parked receiver**, and that an idle machine does not pay a device read per
tick.  The first draft said "the tick does it, gated on a registration
count".  That does not survive contact with the tree's own rules: the timer
tick runs in interrupt context, and §11 of `docs/fmts/code-style.md` forbids
an interrupt from taking a `Mutex` or blocking.  `poll()` takes the receive
buffer's mutex and the demux takes several more, and the demux can transmit —
a transmit that misses the ARP cache waits on the clock.  An interrupt that
did that would be the deadlock the section names.

So the poller is a **kernel thread** (`kernel-net-rx`,
`maintenance::network_receive_entry`), and the gating question is asked of the
socket table rather than of a counter someone has to maintain: `any_waiter()`,
which asks each bound socket's wait queue.  There is no count that a timeout
or a cancelled waiter can leave raised — a thread that is no longer waiting is
pruned out of the queue it would have been counted in.

The thread sleeps one tick while a receiver is parked and ten ticks while
none is, then asks again before it looks.  One tick is the wait's latency: the
answer is read on the first tick after it lands, which is why the RFC's
Drawbacks still apply.  Ten idle ticks is 100 ms at 100 Hz, well inside the
resolver's two-second budget, and it costs no device read.

A thread of its own, rather than a job on the existing maintenance thread, for
one specific reason: the maintenance pass resolves the NTP server's name, and
now that resolution can park.  A resolver parked on the maintenance thread
would be waiting for a receive only that thread could have made.

**Landed:** `NetworkStack::has_receive_waiter`, `NetworkStack::poll_available`,
and the thread itself, spawned beside the maintenance thread in
`Kernel::init`.  `poll_available` bounds one pass at 32 frames so a flooding
peer cannot hold the thread; the rest are the next pass's work.

### Stage 4 — the resolver blocks instead of spinning

Both loops become: send, drain what the socket holds, and — when nothing was
there — park on the socket's wait queue until the next delivery or the
deadline, then drain again.  The nameserver and transaction-id filter, the
retry-on-timeout rebind and the final unbind are unchanged; the deadline is
still 200 ticks per attempt.

Two details are load-bearing.

The wake is not taken as "the answer is here".  Another waiter on the same
port can take the datagram first, and a deadline arrives as a wake too, so the
loop always drains and checks the clock before it returns.  That is what makes
a spurious wakeup cost one lock round trip instead of a wrong answer.

Resolution can now park, so no caller may hold a lock across it.  The one
place that did was the maintenance pass's NTP step, which called
`server_ip()` — resolving inside — while holding the NTP client's lock.  It now
reads the cached address under the lock, resolves outside it, and writes the
result back.  The other callers (the syscall, the shell's `ping`, TCP connect,
the NTP timer) hold no lock at that point.

**Landed:** `await_a_record` and `await_aaaa_record`
(`src/network/dns/resolve.rs`); the boot's self-test covers the wake path and
`resolve_takes_an_answer_that_is_already_queued` covers the drain-first path
and the cache write.  `DNS_PARK_COUNT` counts parks, and the gate asserts it:
a resolver that quietly kept polling would still answer correctly and leave
the count at zero.

## Alternatives

**Leave it as it is, and record the edge as debt.**  The loop works and the
tree has shipped with it.  It loses because the assumption in `poll`'s SAFETY
comment is false today, so the status quo is not merely slow — it is
unsound the first time two threads resolve at once — and because six hundred
device reads to learn one datagram landed is the kind of cost a boot gate
should not be paying on every name a service resolves.

**Poll the stack on every tick, unconditionally.**  Simplest possible
coupling and no gating to get wrong.  It loses on an idle machine: every tick
would call `receive` on a device with nothing to say, and the tick is the one
path in the kernel that must stay short.  It is also not available as stated
— the tick is interrupt context and `poll()` blocks — which is why stage 3
uses a thread.

**Have the device's MSI-X handler call `poll()`.**  The most direct
completion-driven answer, and the handler already runs for each queue.  It
loses for now: `poll` demuxes through the whole protocol stack, which takes
locks and can allocate, and an interrupt must not wait on a thread holding
one.  It becomes the right answer when the demux path can be split into a
lock-free enqueue and a deferred pass — that is a larger change than this
one, and this RFC does not depend on it.

**A dedicated network thread that polls in a loop.**  It would own the
receive path and make the wakeup model obvious.  This is close to what stage 3
landed, and the difference is what makes it work: the thread does not poll in
a loop, it sleeps and asks whether anyone is waiting first, so an idle machine
costs a wakeup every ten ticks and no device read.  A thread that polled
unconditionally loses for the reason the tick does.

**Sleep between polls instead of yielding.**  A one-line change that removes
the CPU burn without changing the architecture.  It loses because it does not
remove the dependency (the sleep is `process`'s), and because the waiter
still cannot receive while it sleeps: the poll that would deliver the answer
is the one it is not making.  It is a plausible fallback if the staged design
stalls — say so in review rather than discovering it later.

## Drawbacks

The gating question moved from a registration count to the sockets' own wait
queues, which removes the count that could go wrong in either direction — too
high and the poller runs forever, too low and a waiter is never woken.  What
remains is the cost of asking: one lock and one `waiter_count()` per bound
socket, once per pass.  That is cheap at the number of sockets this stack has
(one, on the machines a gate boots), and it would need revisiting if the
table grew large.

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

The host build is unaffected in behaviour: `resolve_hostname` still returns
`NotFound` there, because a host resolves through its own stack.  `resolve`
and the wait loop are compiled on the host so the gate can run them against a
mock device; they are annotated dead there, with the reason beside them.

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

**Stage 2.**  `tests/net/udp_wait.rs` installs a scheduler and drives the
socket's wait queue directly: a parked waiter is woken by `deliver` and finds
the datagram; a deadline with no delivery leaves the queue empty and the wait
timed out; a datagram queued before the wait makes it return without parking;
and `unbind` wakes a parked waiter.  Those four are the cases stage 4's loop
depends on, and each one is a way the resolver could hang.

**Stage 3 and 4.**  No device on any gate's machine sends a DNS answer, so —
the same reasoning RFC 0023's IMSIC self-test follows — the kernel walks the
path itself (`src/network/dns/selftest.rs`).  Two threads: one binds a test
port and runs the resolver's real wait loop; the other sleeps five ticks and
then delivers a synthetic A record to that port, which is what the demux would
have done with a frame from a nameserver.  The waiter parses the record,
caches it, and prints one line with the number of parks it took.  The boot
asserts `parked 1 time(s)` and `cache holds it`, so a resolver that returned
the right address without parking, or one that parsed without caching, fails
the gate.

The spin itself needs evidence a functional test cannot give, because a design
that quietly kept polling would still return the right answer.  That is what
`DNS_PARK_COUNT` is for: it counts parks, not loop iterations, and a spin
leaves it at zero.  The self-test's `parked 1 time(s)` is that evidence.
`resolve_takes_an_answer_that_is_already_queued` is the other half — it
asserts the count *unchanged* when the datagram is already queued, so a
resolver that parked unconditionally would fail it.

**The receive thread.**  `the_receive_waiter_question_follows_the_socket` and
`one_drain_pass_reads_what_the_device_has` cover the thread's two decisions:
that nothing is polled when nobody is waiting, and that one pass drains what
the device has up to its bound.

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

It is now more visible than the draft expected: with two resolvers parked on
the same socket, `deliver` wakes one of them, and whether that one is the
waiter whose transaction id the datagram carries is up to the scheduler.  The
loser wakes, finds a datagram it must discard, and re-parks; the winner is
still parked and is woken by the *next* datagram.  That is wasteful rather
than wrong — the filter is still applied — but it means a collision now
costs an extra round trip instead of being invisible.  The port allocation is
therefore the next change to this path, not a follow-up that can wait for a
later one.

**Whether a thread is the right poller at all.**  Stage 3 landed with a
thread because the tick cannot do the work.  If the network stack later gains
a deferred demux that can run from the device's interrupt, the gating
question — who is waiting — and the thread both become unnecessary and should
be removed rather than kept as a second path.
