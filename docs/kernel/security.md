# Security

What a request may do is decided in three places, and they are layered: the
discretionary check asks whether the caller's identity is allowed by the
object's own descriptor, the integrity level adds an information-flow rule
the descriptor cannot express, and the mandatory-access policy can revoke
what the two allowed.  Around them sit the things that give a caller an
identity — login, a service declaration, the kernel's own token — the
architecture's user-access window, and the audit trail every refusal can
leave.

The layer lives in `src/kernel/security/` and, by design, below both
`process` and `fs`: a filesystem has to know who is asking, and the process
layer has to ask what a token may do, and neither should have to name the
other to do it.  `kernel::process::SecurityToken` is a re-export of the type
here, not a second definition.

## The token

`SecurityToken` (`src/kernel/security/token.rs`) is who a request runs as and
what it carries:

| Field | Meaning |
|---|---|
| `user_id`, `primary_group_id`, `supplementary_group_ids` | The identity the discretionary check reads |
| `integrity` | The Biba level (`System` > `High` > `Medium` > `Low`) |
| `mac_type` | The subject label the mandatory policy matches on |
| `elevated` | Set by the constructors that hand out more than the identity alone would |
| `authenticated` | Two states, not one: `false` for every token that no password produced |
| `provisioned` | The kernel *resolved* this identity rather than *being* it |
| `recovery` | The only thing that may bypass a read-only mount |

The distinction the last three carry is the point.  `is_kernel_token` is true
only for tokens the kernel built from its own identity; such a token bypasses
the discretionary check unconditionally.  A provisioned token — one built
from a service declaration's account — does not: `may_bypass_discretionary_permissions`
requires `authenticated` as well, so an identity the kernel merely resolved
faces the same standard as any other caller.  `may_bypass_read_only_mounts`
is narrower still and asks only for `recovery`.

The constructors say which identity each kind of caller gets: `system` for
the kernel's own threads, `guest` as the default for a program with no
account, `root` for an elevated root identity, and `provisioned` for a
resolved account at a chosen integrity level.

## Integrity (Biba)

`IntegrityLevel` orders `System` above `High` above `Medium` above `Low`, and
`dominates_integrity` is the comparison.  The level is read in three places,
and they are the whole of the mechanism:

- A `Low` token loses the write bit in an access-query view, whatever the
  descriptor says (`src/fs/vfs/types.rs`): a low-integrity subject may read,
  not write.
- Tracing another process needs the same user or `High` integrity
  (`src/kernel/process/ptrace.rs`).
- `is_system` is the pair (root user, `System` integrity), and `is_kernel_token`
  is what the discretionary bypass keys on.

This is an ordering and a small set of gates, not a full information-flow
engine: nothing tracks flows between objects, and the levels a token can be
given come from the constructors above.

## Discretionary access

An object's `SecurityDescriptor` is owner, group and mode; the check is the
POSIX-shaped one — owner bits for the owner, group bits for a member of the
group (primary or supplementary), other bits otherwise.  Where the
descriptor comes from, and how the zones and the credential store get their
modes, is [fs.md](fs.md)'s subject; what matters here is the order:
descriptor, then the integrity rule, then the mandatory policy — all three
on one path, so a request that the first allows can still be refused by the
other two.

## The user database

`src/kernel/user.rs` owns the accounts.  `/data/etc/passwd` is the
authoritative copy (`username:uid:gid:home` records, first match wins), and
`/data/etc/shadow` holds the hashes at mode `0600`; both are written with an
atomic replace, and the shadow save re-checks the descriptor afterwards
rather than assuming the replace kept it.  The demo distribution seeds
`root` and `guest`; a non-demo build seeds nothing and takes the
distribution's own file.

The hash is a salted SHA-256 (`hash_password`: salt then password, one
pass), compared with `constant_time_eq`.  A locked account is an all-zero
hash, which no password can produce.  `authenticate_user` is the entry point
that turns a password into a `UserRecord`, and the token built from it is
the one that may set `authenticated`.

`useradd`-shaped helpers create the home directory from `/data/etc/skel`,
and `resolve_home_dir`/`uid_to_username`/`username_to_uid` are how the rest
of the kernel maps between the two.

## Service authorization

A privileged service declares its account in its rc.d definition
(`src/kernel/service.rs`).  `ServiceSecurity::security_token(account)`
answers the token: `Guest` needs no account, `Admin` and `System` require
one and are *refused* without it rather than quietly handed the guest token.
The token it builds is `provisioned` — the kernel resolved the identity — so
it carries that account's uid and gid and the declared integrity level, and
it does not carry the discretionary bypass, because no password was
involved.

The declaration itself is a file in the read-only system zone, and the
kernel checks that path component by component against each directory's own
listing rather than trusting the resolved name, so a symlink shipped in a
writable zone cannot have the kernel read one declaration while the record
says another.  A grant or a refusal is audited, and the refusal is what
leaves a service recorded as not started rather than absent.

## The user-access window

x86_64's SMAP, AArch64's PAN and RISC-V's SUM all forbid the kernel from
touching user memory unless the CPU says so.  `with_user_access_guard`
(`src/arch/user_access.rs`) is the one place that opens the window: it runs
a closure with supervisor access to user memory permitted and restores the
previous state when the guard drops, so an early return or a panic cannot
leave it open.  The syscall layer asks this module rather than naming an
architecture, and the same module answers the other question — whether a
user address range can be walked against a page table at all.

The window is per-access, not per-syscall: a path that holds it across a
call that can block is a path that can be preempted with the window open.

## Mandatory access control

`src/kernel/security/mac/` is a type-enforcement engine in the SELinux
shape: a subject label (`SecurityToken::mac_type`), an object label derived
from the path, a class and a permission bitmask, and allow rules.

Object labels come from the path's zone (`object_type_for_path` in
`check.rs`): `/system` is `MAC_TYPE_SYSTEM`, `/apps` `MAC_TYPE_APPS`,
`/data` `MAC_TYPE_USER`, `/dev` `MAC_TYPE_DEVICE`, `/tmp` `MAC_TYPE_TMP`,
anything else unlabeled — with a runtime override map
(`set_path_type`) consulted first.  Classes and permissions mirror the
operation: file and directory read/write/exec/search, process signal/trace,
network bind/connect/send/receive.

`MacPolicy` holds the rules, a `default_deny` flag and an `enabled` flag.
When enforcement is off — the default — every check is permissive, so a
machine that loads no policy behaves exactly as it did before the engine
existed.  When it is on, a request that matches no rule is denied.

Enforcement is wired at **one** checkpoint: the shared file-access hook
(`src/fs/filesystem/security.rs`), which runs the MAC decision after the
descriptor and integrity checks and revokes the access if the policy says
no.  A denial emits a `MacDenial` audit record.  The process and network
entry points (`check_process`, `check_network`) exist in the module and have
no call site, so a policy cannot yet reach a signal, a trace or a connection.

The policy is managed through `MacSetMode`, `MacAddRule`, `MacSetPathType`
and `MacGetStatus`.  None of the four checks the caller's token: any process
that can make a syscall can enable enforcement, add rules or relabel a path.
That is a gap in the interface rather than a deliberate policy, and the
status table records it as one.

## Audit

`src/kernel/audit/` records classified events — syscall, file operation,
process create, network connect, authentication, configuration change and
MAC denial — into a fixed-size ring buffer.  Each process has an
`audit_enable_mask`, and the dispatcher emits a syscall record only when the
`AUDIT_ENABLE_SYSCALL` bit is set, so an unobserved event costs nothing.

`AuditSetEnable` sets the mask and `AuditReadLog` reads records.  A reader
peeks a batch and commits it only after the copy succeeds, so a short read
does not lose events; with no buffer installed the read answers zero
records.

Persistence is opt-in: `audit::persist::set_persistence(true)` gates the
flush, and the maintenance thread appends a batch to `/data/audit.log` on
its period when it is enabled.  Nothing in the tree calls `set_persistence`,
so a machine's records live in the ring buffer and are lost on reboot.

## Seccomp

`src/kernel/process/seccomp.rs` is a per-process filter: an ordered rule
list of `(syscall, action)` with `ALLOW`, `KILL` and `TRAP` actions, plus a
default action for a call that matches nothing.  The dispatch table consults
it before a handler runs (`src/syscall/table.rs`), so a killed call never
reaches the kernel code it names.  `Seccomp` installs a filter; `Prctl`
carries the option-shaped entry points around it.

## Launch integrity

An install or a launch verifies two things it was already given: the
SHA-256 digest of the program image and of its manifest, and — when the
metadata carries one — a detached Lamport-SHA256 signature
(`src/user/program/signature.rs`).  The signature names a key id, and the
public key is read from `/system/trusted-keys/<key-id>.toml`; the record's
own digest is checked when it carries one, and the signature is checked
against the bytes.

The check is opt-in: `verify_optional_signature` returns `Ok(())` when the
metadata has no signature field, so an artifact without one loads on its
digest alone.  There is no key rotation or revocation, and the trust root is
whatever the read-only system image ships.

## What is not here

- **MAC reaches files only.** A policy cannot refuse a signal, a trace or a
  connection yet, because the two entry points that would are not called.
- **MAC management is unprivileged.** The four policy syscalls accept any
  caller.
- **No stack-canary check.** `Thread` keeps a canary field, and nothing reads
  it; the real overrun detectors are the heap block's own canary and the
  guard page below a kernel stack (see [memory.md](memory.md)).
- **No group database.** Groups are numbers carried in the passwd records and
  in a token's supplementary list.
- **Audit is not persisted.** The path exists and nothing enables it, and the
  log file is append-only text with no rotation.
- **Signatures are optional.** An unsigned artifact is verified by digest
  alone, which is an integrity check against a corrupted download and not an
  authentication of its origin.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/kernel/security/token.rs` | Identities, the integrity level and the token |
| `src/kernel/security/mac/` | The type-enforcement engine and its policy |
| `src/kernel/user.rs` | The passwd and shadow databases, and authentication |
| `src/kernel/service.rs` | Service declarations, their accounts and their tokens |
| `src/fs/filesystem/security.rs` | The VFS checkpoint where descriptor, integrity and MAC meet |
| `src/kernel/audit/` | Event types, the ring buffer and the persistence path |
| `src/kernel/process/seccomp.rs` | The per-process syscall filter |
| `src/arch/user_access.rs` | The user-access window and the address walk |
| `src/user/program/signature.rs`, `integrity.rs` | Digests and detached signatures |
| `src/syscall/mac.rs`, `audit.rs`, `seccomp.rs` | The management syscalls |

## See also

- [fs.md](fs.md) — the descriptors, zones and credential store the first check reads
- [process.md](process.md) — the thread that carries a token and the handle rights
- [memory.md](memory.md) — the guard page, and why the canary is not one
