# RFC 0030: Give each DNS lookup its own source port

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-20
- **Supersedes:** none

## Summary

Every DNS lookup in the tree binds the same source port, 53000, and the
second lookup silently adopts the first one's socket.  This decides that a
lookup takes a port from a dynamic range for the length of the lookup and
gives it back when it ends, and that the transaction id becomes a random
number per query instead of the constant `0x0001` — because this change is
what makes port reuse possible, and a fixed id cannot filter an answer that
belongs to the lookup that used the port before.

## Motivation

RFC 0029 left this open and then said it could not be left open:
`DNS_EPHEMERAL_PORT` is a single constant shared by every caller, `bind`
answering `AlreadyExists` is ignored so the second resolver reuses the first
one's socket, and two concurrent lookups can therefore take each other's
answers.  Its own words: "the port allocation is therefore the next change to
this path, not a follow-up that can wait for a later one."

The shape of the failure changed when the resolver started waiting on the
socket.  A delivered datagram wakes *one* waiter on the shared socket, and
which one is up to the scheduler; the loser wakes, discards a datagram whose
transaction id is not its own, and parks again — its turn is the next
datagram, which may never come.  A wrong answer is caught by the id filter,
but a lookup that should have been answered waits out its retry budget.

There is a second reason the id cannot stay fixed.  A fixed port meant one
socket for everybody and a filter that was already doing nothing: the id was
`0x0001` for every query the kernel ever sent.  Rotating ports spreads
reuse out, but it does not eliminate it — and after a port is handed out
again, a delayed datagram from the previous lookup arrives on a socket that
is listening and carries the same id.  Port allocation without a random id
would trade a wrong-answer path that the id caught for one it cannot.

Both precedents are in the tree.  `TcpConnectionTable::alloc_port`
(`src/network/tcp/table.rs`) walks a rotating cursor over
`49152..=65535` and refuses with `AlreadyExists` when it is full;
`DccpConnectionTable::alloc_ephemeral_port` does the same over the same
range.  Neither needs a new mechanism — what is missing is the UDP socket
table having an allocator at all, and the DNS resolver using it.

## Current state

- `src/network/dns/resolve.rs` — `resolve_within` binds
  `DNS_EPHEMERAL_PORT`, sends, waits, and on the failure path unbinds *only*
  if this call made the binding (`bind_ephemeral_port` /
  `rebind_ephemeral_port`).  That ownership flag was RFC 0029's hardening;
  it stops a resolver from removing a socket another one is using, but it
  does not stop the two from sharing one.
- `src/network/dns/query.rs` — `build_query` and its siblings call
  `query_header(qdcount, arcount)`, which writes the constant `DNS_QUERY_ID`
  (`0x0001`).  There is no way to ask for a specific id.
- `src/network/udp.rs` — `UdpSocketTable::bind` reserves an exact port and
  answers `AlreadyExists` if it is taken.  There is no allocation among
  several.
- `src/kernel/random.rs` — `fill_random`, a CSPRNG that lazily initialises
  from platform entropy.  `src/network/dccp/ops.rs` and the TLS module
  already draw from it, so a network protocol naming it is established.
- `src/network/internet/nat.rs` — `NAT_PORT_START..=NAT_PORT_END` is
  `32768..=60999`, allocated from a table keyed by port alone.

## Design

**The UDP table allocates.**  `UdpSocketTable::bind_ephemeral` walks a
rotating cursor over the kernel's dynamic range, binds the first free port it
finds, and returns it; it answers `Error::AlreadyExists` when the range is
full, which is what the TCP allocator answers in the same situation.  One
lock, one decision: a caller cannot bind a port that another caller is being
given at the same moment.

**The range is `61000..=65535`, not the full dynamic block.**  TCP and DCCP
use `49152..=65535`, and copying them would be the obvious thing.  It is the
wrong range for UDP: NAT allocates its translation ports from
`32768..=60999` in a table keyed by port alone, so a local UDP socket bound
inside that window can be shadowed — an inbound datagram for the NAT
translation is delivered to the socket instead of being reverse-translated.
Starting above it costs nothing (4 536 ports is far more than this stack can
have in flight) and removes a class of collision the port allocator would
otherwise have to know about.  TCP does not need this because TCP and UDP
port spaces are separate.

**A lookup owns its port for its whole life, and Drop gives it back.**  The
resolver binds once, before the retry loop, and the port is released by a
guard whose `Drop` unbinds it.  That is not sugar: `send_to` answers `?`
inside the loop, so every early return between bind and the end is a path
that must not leak a port, and a guard is the only shape that cannot miss
one.  The guard unbinds the port it was given, never "the" port, so the
ownership question RFC 0029 introduced disappears rather than being
maintained.

**The transaction id is random per lookup, not per retry.**  A lookup draws
16 bits from `fill_random` once, builds every attempt from it, and filters
answers against it.  Per retry would be finer-grained but wrong: a
retransmission is the same question, and an answer to the first attempt that
arrives during the second is a correct answer.  The resolver reads the id
back out of the bytes it built rather than carrying it separately, so the
filter cannot disagree with the query.

**Both changes are one change.**  The id protects against a datagram that
belongs to another lookup; rotating ports create the situation where such a
datagram arrives.  Landing the ports alone would weaken the filter that
exists while appearing to improve the path.

**Landed:** `UdpSocketTable::bind_ephemeral` and the
`UDP_EPHEMERAL_PORT_START`/`END` constants (`src/network/udp.rs`), `PortGuard`
and `draw_transaction_id` (`src/network/dns/resolve.rs`), and
`build_query_with_id` with its AAAA sibling (`src/network/dns/query.rs`).  The
fixed `DNS_EPHEMERAL_PORT` is gone; the self-test names its own port below the
dynamic range, so it can never take one a lookup was given.

## Alternatives

**Keep one port and give each resolver a private queue.**  It fixes the
wakeup question without touching allocation, and it was considered because
it is smaller.  It loses because a port is the thing the network keys on:
two references in flight to port 53000 from one host are indistinguishable
to the server, and the second query's answer can be dropped by the server's
own socket bookkeeping rather than by anything here.  The bug lives at the
port, so the fix does.

**Allocate from the full dynamic range, as TCP does.**  Consistent with the
other two protocols in the tree, and one fewer rule to explain.  It loses on
the NAT overlap above: a port the kernel hands a socket must not be a port
NAT could translate a different connection to.

**Keep a fixed id and rely on the port.**  Sufficient if ports were never
reused.  They are: `65535 - 61000 + 1` lookups wrap the range, and a datagram
delayed across a wrap lands on a live socket with the same id.  The id is
cheap and it is the only defence against exactly that.

**Draw the id from a counter instead of the CSPRNG.**  Deterministic, which
is easier to test, and it does not pull randomness into the query builder.
It loses because an off-path attacker who can observe one answer knows the
next id.  The stack already has a CSPRNG and already uses it for TCP's
initial sequence number, which is the same threat.

## Drawbacks

Retries reuse one port, so a lookup that times out three times occupies its
port for its full six seconds.  With 4 536 ports that allows 4 536
simultaneous timed-out lookups before allocation fails; the old code allowed
one such lookup and then silently shared it.  `AlreadyExists` from the
allocator surfaces at the syscall as an error rather than as a wrong answer,
which is the trade this RFC prefers.

The query builder now draws randomness, so building a query can lazily
initialise the CSPRNG on the first DNS lookup of a boot.  That is a lock and
a hash on a path that runs once per name, and the resolver already reads the
clock and allocates.

A test that wants a fixed id can no longer get one from `build_query`; it
asks for `build_query_with_id`.  That is a smaller API than "the builder
takes an id", which every existing caller would have had to learn.

## Compatibility and migration

No ABI and no on-wire format change: a DNS query with a random id is the
format.  `SyscallNumber::ResolveHostname` keeps its signature and its
return value.

The fixed `DNS_EPHEMERAL_PORT` is removed rather than kept as a fallback, so
nothing can accidentally depend on it; the DNS self-test keeps its own fixed
port because it must name a port before the resolver allocates one, and it is
the test's, not the resolver's.

The host build is unaffected: the resolver is compiled there for the gate,
and the allocator is exercised by the same tests.

## How this is proven

**Allocation and release.**  `ephemeral_allocations_are_distinct_and_in_range`
binds 64 ports, asserts each is distinct and inside `61000..=65535`, and that
two consecutive allocations differ — the rotating cursor doing its job.
`exhausting_the_range_answers_already_exists` spends the whole range, asserts
the count is exactly the range's width, asserts the next allocation answers
`AlreadyExists`, and asserts that releasing one port gets an allocation again.

**The guard releases on every path.**  `a_lookup_that_cannot_park_gives_up`
runs `resolve_within` against a device that never answers: it returns
`TimedOut`, leaves `DNS_PARK_COUNT` unchanged, and leaves no dynamic port
bound — which is what the guard exists for, since `send_to` can answer `?`
from inside the retry loop.  `await_aaaa_takes_a_queued_answer` does the same
for the AAAA path's guard, which had no host coverage at all before this
change because the AAAA resolver was compiled only for bare metal.

**The id is random and filters.**  `transaction_ids_differ_between_lookups`
draws seventeen ids and asserts they are not all the same;
`a_query_carries_the_id_it_was_built_with` builds with an explicit id, asserts
the bytes carry it, and asserts an answer built with a different id does not
match.

**Two lookups at once do not meet.**  `two_lookups_at_once_take_their_own_ports_and_answers`
binds two ports before answering either, asserts they differ, then delivers
each answer to its own port and asserts each port holds its own address and
only its own.  Against the old fixed-port behaviour it fails on the first
assertion with "the two lookups were given the same source port" — checked by
putting that behaviour back and running it.

**The park count means a park.**  `delivery_before_waiting_is_not_lost` in
`tests/net/udp_wait.rs` asserts `DatagramWaitOutcome::AlreadyQueued` when the
datagram is already queued, and `resolve_takes_an_answer_that_is_already_queued`
asserts the resolver's park count is *unchanged* in that case.  That
distinction is why the self-test's `parked 1 time(s)` is evidence rather than
decoration: a resolver that spun, or one that counted a probe as a wait, fails
one of the two.

**The boot.**  The DNS self-test walks the wait path with a synthetic answer
on its own port, below the allocator's range, so it can never be handed one a
lookup was given.

## Unresolved questions

**Ports are not held after the lookup ends.**  *Answered by the linger
below.*  A closed port could be reallocated immediately, so two datagrams to
it in quick succession could reach two different lookups.  The random id makes
that a discarded answer rather than a wrong one, which is what the id is for.

A release now lingers: `UdpSocketTable::unbind_at` records the tick and
`bind_ephemeral_at` skips a port until `UDP_PORT_LINGER_TICKS` (one second)
has passed.  There is no timer and no thread — the entry is swept by the
allocation walk that would otherwise have handed the port out — so the cost is
one `BTreeMap` entry per port released in the last second.  One second is
enough for an answer that was already in flight when its lookup gave up, and
short enough that exhausting 4 536 ports would take 4 536 lookups ending
inside one second.

**NAT's range still overlaps TCP's.**  This RFC narrows UDP to stay out of
NAT's way, and TCP remains inside it.  Whether NAT should move, or TCP
should narrow too, is a decision about NAT that this one does not take.
