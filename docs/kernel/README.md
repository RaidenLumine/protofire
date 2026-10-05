# Kernel Documentation

These documents describe how the kernel works: the mechanisms, the interfaces
between subsystems, and the invariants each part is written to keep.  They are
about the code as it is, and every claim in them is meant to be checkable by
reading the file it names.

They are not a status report and not a changelog.  What exists, what is missing
and what is wired but unreachable is [ROADMAP.md](../../ROADMAP.md)'s;
decisions and the arguments behind them are [docs/rfcs/](../rfcs/README.md)'s;
the specifications a contributor has to follow are
[docs/fmts/](../fmts/README.md)'s.

## How these documents are written

The rules exist because the previous set of documents described features that
were never implemented — a signal range, an MSI-X programming path, a
filesystem pool size — and nothing noticed for years:

- **Describe the mechanism, not a snapshot of the numbers.**  A count, a
  capacity, a record size or a version is owned by a constant or a test; name
  it (`MAX_SYSCALLS`, `tests/syscall/abi_golden.rs`) instead of writing its
  value into prose, because a copied number is a number that will drift.
- **Name files and symbols.**  A reader has to be able to open the code and
  check the claim.  `make check-docs` fails a citation that names a file the
  tree does not have, and `make check-rfcs` holds the design documents to
  their own shape.
- **Say what the code does, not what it should do.**  An unimplemented feature
  is described by the code that is there for it (a handler nothing installs, a
  constant nothing reads) — or it is not described here at all.
- **Scope statements are welcome.**  "This driver polls; it has no interrupt
  path" is the most useful sentence a driver document can carry, and it is a
  fact about the code rather than a wish.

## The documents

This set is being rewritten from the code, one subsystem at a time; the table
lists the documents that exist today, and a document that is not in it is not
one of these.

| Document | Covers |
|----------|--------|
| [boot.md](boot.md) | Hand-off, the Rust entry, the init pipeline, SMP bring-up, platform assumptions |
| [drivers.md](drivers.md) | The driver framework, the device ledger, and each driver's completion path |
| [fs.md](fs.md) | The VFS, the block layer, SimpleFs, the mount-time layout, the views and FUSE |
| [ipc.md](ipc.md) | Locks, wait queues, pipes, the descriptor facilities and shared memory |
| [memory.md](memory.md) | Frames, the heap, page tables, kernel stacks, reclaim and swap |
| [interrupts.md](interrupts.md) | Controllers per machine, the identity registry, MSI, NMI, balancing |
| [network.md](network.md) | The stack's layers, TCP and UDP, DHCP/DNS/SLAAC, TLS, and what is not wired |
| [process.md](process.md) | Processes, threads, the scheduler, signals, handles, termination |
| [security.md](security.md) | Tokens, integrity, DAC, MAC, the audit trail, seccomp, launch integrity |
| [syscalls.md](syscalls.md) | The trap, the dispatch table, pointer validation, the ring-3 wrappers |
| [user-runtime.md](user-runtime.md) | The shared tree: ABI records, the mirror, the bridge, the shell library and signals |

The subsystems these will cover, in the order they are being written: boot and
the architectures, memory, process and scheduler, interrupts, drivers, the
filesystem, networking, IPC and synchronization, security, and the shared user
runtime.
