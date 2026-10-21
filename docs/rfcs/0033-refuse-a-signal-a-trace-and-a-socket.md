# RFC 0033: Refuse a signal, a trace and a socket

- **Status:** Accepted
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-10-21
- **Supersedes:** none

## Summary

The MAC type-enforcement engine has three entry points.  One of them —
`check_file` — is called, from the single hook every VFS operation flows
through.  The other two, `check_process` and `check_network`, are complete,
tested in isolation, and called from nowhere: a policy can revoke a file
operation and cannot revoke a signal, a trace or a connection.  This decides
where those two are checked: **at the syscall boundary**, in the handlers
that hand the operation to the kernel, because a syscall is the only way a
process reaches either, and it is the one place the caller's token and the
target are both in hand.

## Motivation

`docs/status.md` records the gap in the MAC row's *Missing* column: "a policy
cannot refuse a signal, a trace or a connection".  It has been true since the
engine landed, and it is the difference between a type-enforcement engine and
a type-enforcement engine over one class of object.  An administrator who
writes a policy and turns enforcement on gets exactly one guarantee — file
access — and nothing tells them the other two classes are inert.

The gap is also load-bearing in a way a file-only policy is not.  A signal is
how one process stops, kills or resumes another; a trace is how one process
reads another's memory; a connection is how a process reaches the network.
Those are the operations a policy exists to constrain on a machine that runs
programs it did not build.

## Current state

- `src/kernel/security/mac/check.rs` — `check_file` classifies the object
  from the path and calls `decide`; `check_process(subject, target, perms,
  uid)` decides against `MAC_CLASS_PROCESS`; `check_network(subject, perms,
  uid)` decides against `MAC_CLASS_NETWORK` **with the subject as its own
  object** — a placeholder no caller has ever had an opinion about.
- `src/kernel/security/mac/policy.rs` — `MacPolicy::decision` is permissive
  while `enabled` is false, and once enabled denies anything no rule covers
  (`default_deny` starts true).  A denial emits a `MacDenial` audit record
  through `decide`.
- `src/fs/filesystem/security.rs` — the one call site, inside the access hook
  the VFS runs for every open, create, read and write.
- `src/syscall/process/signal.rs` — `send` decodes the request, calls
  `Scheduler::send_signal`, and then handles the job-control signals by
  stopping or resuming all of the target's threads.
- `src/syscall/ptrace.rs` — dispatches on the request; `PTRACE_ATTACH` reaches
  `kernel::process::ptrace::ptrace_attach`, which checks the target's
  integrity and then mutates it.
- `src/syscall/network.rs` and `src/syscall/network/local.rs` — the socket
  handlers.  Each validates its arguments and calls `network::…`; none of them
  looks at the caller's token.
- `Scheduler::send_signal` has four callers.  One is the syscall; the other
  three are the kernel's own — SIGCHLD when a child exits, SIGKILL from the OOM
  killer, and a POSIX timer's expiry — and they pass a `sender_pid` that is
  the kernel or the child, not a process that can be asked what it may do.

## Design

**One rule decides where the check goes.**  A process-facing authority check
is made in the handler that the process calls — the syscall boundary — and
nowhere below it.  For files, the boundary is the VFS access hook, which is
where every filesystem operation already converges and where the token is
already a parameter.  For processes and sockets the boundary is the syscall
handler, because that is where the caller's `SecurityToken` and the operation
are both named.

The kernel's internal senders are therefore ungated by construction, not by a
special case.  SIGCHLD at a child's exit, the OOM killer's SIGKILL and a POSIX
timer's expiry must not be refusable by a policy written for processes; they
are the kernel acting, and they keep calling `Scheduler::send_signal`, which
never consults the policy.

### Processes

`SendSignal` (`src/syscall/process/signal.rs`) resolves the target, then runs
`check_process(caller.mac_type, target.security_token().mac_type,
MAC_PERM_SIGNAL, caller.user_id)`.

The order is: target exists, then policy, then delivery.  A policy cannot be
asked about a process that is not there, and `send_signal`'s `NotFound` for an
unknown pid is kept so a denial does not become a way to probe the process
table.

One exemption: **a process signalling itself is not checked.**  No authority
crosses a process boundary when the sender and the target are the same, and
the alternative is a footgun rather than a safeguard — the shell's `sigasync`
builtin signals itself, so a policy denying an untrusted subject the signal
class would break a program that only touched itself.  The rule is applied to
ptrace for the same reason.

`Ptrace` (`src/syscall/ptrace.rs`) checks `MAC_PERM_TRACE` on `PTRACE_ATTACH`
only.  Every other request is gated by `verify_tracer`, which accepts nobody
but the process `ATTACH` made tracer, so the session is sealed by the one
request that can open it.  `PTRACE_TRACEME` is the target's own consent and is
not a policy question; it also cannot widen access, because a parent that
already holds the link finds the target traced and `ptrace_attach` answers
`Busy`.

### Sockets

`check_network`'s object becomes **`MAC_TYPE_NETWORK`** instead of the subject.
The subject-as-object pairing was a placeholder; a network operation has an
object — the network — and naming it makes the ABI's four permissions mean
what they say and makes a rule readable:

    (SYSTEM, NETWORK, NETWORK, BIND | CONNECT | SEND | RECV)

The handlers and their permissions:

| Handler | Permission |
|---|---|
| `connect_tcp`, `dccp_connect` | `MAC_PERM_CONNECT` |
| `listen_tcp`, `bind_udp`, `dccp_bind`, `dccp_listen`, `create_raw_socket` | `MAC_PERM_BIND` |
| `send_to_udp`, `send_raw_packet`, `dccp_send`, `resolve_hostname` | `MAC_PERM_SEND` |
| `recv_from_udp`, `recv_raw_packet`, `dccp_recv`, `accept_tcp`, `dccp_accept` | `MAC_PERM_RECV` |

`resolve_hostname` is a send: it puts a query on the wire.  The resolver's own
background lookups are kernel work and do not pass through the syscall, so
they are unaffected — the same line the kernel's own signals sit on.

The check runs **before** the operation reaches `network::…`, so a denied
request does not depend on whether the machine has a stack: on a host build
with no stack, a denied `bind_udp` answers `PermissionDenied` rather than
`Unsupported`, which is also what lets the deny path be tested without a
network.

Metadata operations are not checked: `getsockname`, `getpeername`,
`setsockopt`, `getsockopt` ask about or tune a socket the caller already holds
a descriptor for.

**Local sockets are out of scope, and the reason is written down rather than
left implied.**  A local socket's object is a name in a global namespace that
the zones do not cover, so there is no object type to decide against; calling
it `MAC_TYPE_NETWORK` would be inventing a label.  When local sockets get a
labelled namespace they get a checkpoint in the same change.

## Alternatives

**Check in the kernel primitive instead of the handler.**  `Scheduler::send_signal`
does have `sender_pid`, and `ptrace_attach` has both processes.  It loses for
signals because `sender_pid` cannot distinguish "a process asked" from "the
kernel is acting" — SIGCHLD carries the *child's* pid as sender — so the
primitive would have to grow a `is_this_the_kernel` flag that is exactly the
special case the handler avoids.  For ptrace it would work, and the cost of
not doing it is one `process_by_pid` lookup on a rare call.

**Check per request on every ptrace call.**  `PEEK`/`POKE`/`GETREGS`/`CONT`
each re-decide.  It buys revocation of a live tracing session; it costs a
policy lock per request and a second authority model on top of `verify_tracer`,
which already says nobody but the tracer may ask.  Not taken.

**Keep `check_network`'s subject-as-object pairing.**  It needs no ABI
comment change and no edit to `check_network`.  It loses because it cannot
express "the network" as an object: every rule is phrased about the caller,
the audit record's object field repeats the subject, and a class named
`MAC_CLASS_NETWORK` has no network in it.

**Check sockets inside the network stack.**  The stack would have to carry a
token into `connect_tcp`, `bind_udp`, `send_dccp` and the rest.  The stack has
no security vocabulary today, and the syscall layer already holds the token;
pushing it down is a larger interface change for a check whose inputs are
already assembled above.

**Cover local sockets under the same permissions.**  It is three lines and
makes the rule uniform.  It loses because the object type would be a lie; a
uniform rule over an invented label is worse than a stated gap.

## Drawbacks

- The comment on `MAC_TYPE_NETWORK` changes meaning: it stops being only a
  subject label for network-facing services and becomes the object label of
  the network as well.  One constant, two roles, and the document has to say
  both.
- Fifteen handlers gain two lines each.  It is mechanical, and the alternative
  shapes are argued above, but the diff is wider than the idea.
- A policy author must now allow the network class explicitly.  A policy that
  denies by default and forgets `MAC_CLASS_NETWORK` breaks a machine's
  resolution; nothing warns at load time, because the engine has no notion of
  a policy being "complete".
- The `syscall` layer gains an edge to `security`.  It is the same direction
  `fs` already has, and the baseline carries the argument.

## Compatibility and migration

No syscall number moves and no wire format changes.  With no policy loaded —
every boot today — `decision` answers `None` and every handler behaves exactly
as before; the change is inert until an administrator turns enforcement on.
`MAC_TYPE_NETWORK` keeps its value, so a policy written against the old
constants still parses; what changes is the object field a `MAC_CLASS_NETWORK`
rule must name, and a rule that repeated the subject there simply stops
matching, which is the deny-by-default answer rather than a wrong allow.

A half-deployed state does not exist: the handlers and the engine are in one
crate, and the check is either in the path or not.

## How this is proven

- `tests/syscall/mac_enforcement.rs` drives the real syscall table with a
  scheduler installed and a policy the test owns.  For a signal it asserts the
  denial **and the absence of the effect** (the target's pending queue stays
  empty); for ptrace that the tracer link stays unset; for `connect_tcp` that
  a denied request returns `PermissionDenied` without reaching a listener the
  test bound.  Each case is then re-run with an allow rule and must succeed,
  and once more with enforcement off.  The self-signal exemption is its own
  case.
- `src/kernel/security/mac/tests.rs` gains the object-type assertion for
  `check_network` and a deny/allow pair for `check_process`.
- The check is confirmed to be in the path by flipping it off: the same test
  against the pre-change handler answers `Ok` where it must answer
  `PermissionDenied`.
- `make test-fast` runs the new file; `make check-layering` carries the new
  edge; the three runtime smokes must stay green, which is the statement that
  a boot with no policy is unchanged.

## Unresolved questions

- Whether a policy change should revoke a tracing session already under way.
  `ATTACH`-only checking says no; the alternative is per-request checking,
  which is argued against above and may be revisited if a policy is ever
  reloaded at runtime rather than written before use.
- What a local socket's object label should be, which is the namespace
  question above rather than a MAC question.
