# RFC 0032: Decide what a full send buffer does

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-20
- **Supersedes:** none

## Summary

`TcpConnectionState::write` appends to `send_buffer` and answers with the whole
length, with no bound.  A peer that stops reading therefore grows the kernel's
memory for as long as the program keeps writing, and nothing refuses.  This
decides what a full send buffer should do — and it is a draft because the
answer is a socket-semantics choice rather than an obvious repair.

## Motivation

RFC 0031's first draft described this as "a writer blocked by a full peer
window still spins".  Reading the code showed that is not the shape: nothing
blocks, because nothing is refused.  `write` accepts every byte, `write_all`'s
retry loop finishes in one pass, and whatever the window will not take waits in
the buffer.

The consequence is the opposite of a spin, and worse for a hostile peer: a
program that writes in a loop to a peer that never reads grows an unbounded
`VecDeque` in kernel memory until the heap refuses.  `the
writing_to_a_peer_that_never_reads_grows_the_send_buffer` test pins it — 256 KiB
accepted against a zero window, nothing refused.

## Current state

- `src/network/tcp/types.rs` — `write` does `send_buffer.extend(data.iter())`
  and returns `data.len()`.  `MAX_RECV_BUFFER` bounds the *receive* side at
  64 KiB; there is no counterpart for sending.
- `src/network/tcp/ops.rs` — `try_flush_tcp_output` sends at most
  `min(window, mss, buffered - ahead)` and leaves the rest.  Peers' window
  updates arrive through `process_segment` and re-flush.
- `src/network/tcp/table.rs` — `write_all` loops on `write` until every byte is
  accepted, which with the current `write` is the first pass.
- `src/kernel/process/wait` — the primitive a parking writer would need exists.

## What the tree gives each option

Measured before choosing, because the numbers decide more than the principles
do.

- **The kernel heap is 64 MiB** (`KERNEL_HEAP_SIZE` in
  `src/memory/heap/tlsf.rs`).  A single connection that never drains can
  therefore take the whole heap; two can take it twice over, and the failure
  is an allocation failure somewhere else entirely.
- **`MAX_RECV_BUFFER` already bounds the other direction at 64 KiB.**  There
  is precedent in this file for the number, and the asymmetry — receive
  bounded, send not — is the bug rather than a policy difference.
- **The tree's own writers are small.**  TLS's handshake calls `write_all`
  with single records; the tests write `b"ping"`, `b"pong"`, `b"abc"`.  Nothing
  in the tree writes more than a segment in one call, so a 64 KiB bound would
  change no existing caller's behaviour.
- **`WriteSocket` returns a byte count**, so a short write is already
  expressible in the ABI and needs no new error path.  A program that wants
  all of its bytes written loops — which is what `write_all` does today,
  except that today the loop cannot iterate.

## Design

The bound is the decision; where to put it is not.  `MAX_SEND_BUFFER` beside
`MAX_RECV_BUFFER`, `write` accepting `min(room, buffer.len())`, and
`write_all` looping on the short write it now actually gets.

That leaves the question the previous draft could not answer: **what does a
`write` that finds a full buffer do?**  Refusing with a short write is the
answer that needs no new machinery — the ABI already carries a count, the
kernel already has the bound, and a program that wants to wait has `poll`,
whose absence from this ABI is a separate gap.  Parking is the answer that
does the waiting in the kernel, and it costs a queue per connection, a wake
per ACK, and a second place in the socket layer where a thread may sleep.

Choosing refusal, on the evidence above:

- It changes no caller in the tree: none writes more than 64 KiB.
- It needs no wake on the ACK path, so it cannot reintroduce the
  wake-without-poll failure RFC 0031 had to guard against.
- It makes the bound visible to the program, which is where a decision about
  what to do with the data belongs.  A kernel that parks a writer is deciding
  on the program's behalf, and this ABI has no way for the program to say
  whether it would rather block or fail.
- It is reversible: adding a wait queue later changes only `write`, and the
  bound it would wait against already exists.

Parking remains the better answer if this ABI grows `poll` with writability
and the socket layer gains a thread that may sleep in `write`.  This RFC
chooses the bound now and records that as the upgrade path rather than
pretending the question is closed for good.

**Refuse with a short write past a bound.**  A fixed `MAX_SEND_BUFFER` (the
receive side's 64 KiB is the natural number) and `write` returns what it
accepted.  A program that wants to send more loops, and its loop is the thing
that spins — but in user space, with a buffer whose size the kernel controls.
**Chosen.**

**Park until the window opens.**  The writer takes a wait queue the mirror of
RFC 0031's reader, and `process_segment` wakes it when an ACK opens the window.
This is what the tree would do if the writer were already a thread that may
sleep, and it is the shape both prior RFCs reached for.  It costs a queue per
connection and a wake per ACK.

**Keep growing, and bound only at the heap.**  What happens today, and it is
not an option so much as the absence of one: 64 MiB of heap means one stalled
peer can consume all of it, and the failure surfaces wherever the next
allocation happens to be.

## Alternatives

The three above are the alternatives, and the design section says which one and
why.  A fourth — send synchronously, one segment at a time, waiting for each
ACK — is what the write path would look like if it had been written for a
single-threaded boot.  It loses on throughput for any peer with a window wider
than one segment, and the stack already implements windowed sending.

## Drawbacks

A write of more than 64 KiB that used to "succeed" now returns a short count
and must be retried.  No caller in the tree does that, but a program outside it
might, and it will see the change.  That is the point — the old success was a
promise the kernel could not keep — but it is a behaviour change, and the bound
is a policy the socket layer now imposes where it previously imposed none.

A program with no `poll` has no way to wait for room, so a short write means
it must spin itself.  That is a worse loop than a parked thread and a better
one than exhausting the heap; `poll` with writability is the missing piece, and
this RFC does not add it.

## Compatibility and migration

No ABI change either way: `WriteSocket` returns a byte count, which a
`WouldBlock`-style refusal expresses as a short write.  A parking writer
changes nothing observable except that the machine does less work.

Programs in this tree that write more than a bound in one call would have to
retry; the tree's own callers are the place to check that before choosing.

## How this is proven

Whichever option is chosen, the gate is the same shape: a peer that stops
reading must not be able to grow the kernel's memory without bound, and the
test that pins today's behaviour is the one that must change.  For the parking
option, the further gate is RFC 0031's reader test run in the other direction —
a writer parks, an ACK opens the window, the writer resumes.

**Landed:** `MAX_SEND_BUFFER` and the bounded `write`
(`src/network/tcp/types.rs`), and `write_all`'s retry loop
(`src/network/tcp/table.rs`).

## Unresolved questions

**A short write with nowhere to wait.**  `WriteSocket` returns a count and the
ABI has no way to ask when more room appears, so a program that must send more
than the bound spins.  Adding `poll` with writability — and then the wait queue
this RFC declined — is the change that closes it, and it is larger than the
bound.

**The bound's value.**  64 KiB matches the receive side, and no caller in the
tree approaches it.  A connection to a high-latency peer may want more, and
that is a tuning question this RFC answers with symmetry rather than
measurement.
