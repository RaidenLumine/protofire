# RFC 0032: Decide what a full send buffer does

- **Status:** Draft
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

## Design

Not yet decided.  The options follow, and choosing between them is what this
RFC has to do before it becomes anything else.

**Refuse with `WouldBlock` past a bound.**  A fixed `MAX_SEND_BUFFER` (the
receive side's 64 KiB is the natural number) and `write` returns what it
accepted.  A program that wants to send more loops, and its loop is the thing
that spins — but in user space where `poll`/`select` conventions already exist,
and with a buffer whose size the kernel controls.

**Park until the window opens.**  The writer takes a wait queue the mirror of
RFC 0031's reader, and `process_segment` wakes it when an ACK opens the window.
This is what the tree would do if the writer were already a thread that may
sleep, and it is the shape both prior RFCs reached for.  It costs a queue per
connection and a wake per ACK.

**Keep growing, and bound only at the heap.**  What happens today.  It is
honest for a cooperative single-peer boot and indefensible against a peer that
stops reading — which the machine cannot tell apart from a slow one.

## Alternatives

The three above are the alternatives; the design section is where one of them
gets chosen.  A fourth — send synchronously, one segment at a time, waiting for
each ACK — is what the write path would look like if it had been written for a
single-threaded boot.  It loses on throughput for any peer with a window wider
than one segment, and the stack already implements windowed sending.

## Drawbacks

Every option that bounds the buffer makes a large write that used to succeed
into one that must be retried, which is a behaviour change for any program that
writes more than the bound in one call.  That is the point; but it lands on the
shell, on the demo programs, and on anything the ABI's users already do, so the
bound's value is part of the decision rather than an implementation detail.

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

## Unresolved questions

This document *is* an unresolved question: which of the three.  It is written
down so the choice is made deliberately rather than discovered, and so the test
that currently records the unbounded growth is a starting point rather than a
trap.
