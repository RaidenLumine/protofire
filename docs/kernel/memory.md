# Memory

Physical frames, the heap that allocates on top of them, the page tables that
describe both, and the two ways the kernel gives memory back — reclaim and
swap.  The module is `src/memory/`; the per-architecture halves it dispatches to
live under `src/arch/<machine>/paging` (x86_64) and `src/arch/<machine>/mmu`
(AArch64, RISC-V).

## What the machine says

Early in boot the architecture records how much RAM the platform reported —
the Multiboot2 memory map on x86_64, a device tree's `/memory` node on the
other two — into one atomic in `src/memory/arch.rs`:

- `store_detected_memory` writes it once, before `MemoryManager::init`.
- `detected_memory` reads it, and answers `None` when nothing has run — an
  atomic that was never written is not a machine with no memory, and the
  difference matters.
- `detect_memory` is the fallback: the platform's answer, or the size of the
  kernel's own backing pool when there is none.

## Frames

`src/memory/frame.rs` holds the frame allocator, and the first thing to say
about it is what backs it: a static array inside the kernel image
(`PHYSICAL_POOL`, sized by `PHYSICAL_POOL_SIZE`, both in that file).  The
allocator manages that array, not the machine's RAM.  `init` clamps the
platform's reported size to it, so a machine with more memory than the pool has
the excess unmanaged, and a machine with less has the pool overhang ignored
rather than used.  A board port is where that changes.

Allocation is a bump pointer plus a free list: the allocator hands out from the
high-water mark when nothing smaller fits, and a `BTreeMap` of freed ranges
(keyed by start frame) is searched first-fit otherwise.  Frames come back
zeroed, and `deallocate` coalesces with its neighbours on both sides — merging
with a range that ends where the freed run begins and one that begins where it
ends — and rewinds the high-water mark when the freed run touches it, so a
program that frees its last allocation can get the same frames back rather than
the allocator's tail growing forever.

### NUMA

The manager holds one allocator per node, not one for the machine:
`frame_allocators` is indexed by node id, and `MAX_NODES` bounds it.  The
topology subsystem (`src/kernel/topology.rs`) fills it: `set_node_range`
declares that a range of the pool belongs to a node, and
`allocate_frame_on_node` allocates from one node and answers `None` when that
node cannot serve the request — there is no fallback there, so a caller asking
for a particular node is told when it is full.

The everyday path does fall back, and it is the only place the topology's
answer is read: `allocate_frames` allocates from the node the calling CPU is in
(`PerCpuData::numa_node_id`) and, if that node cannot serve the request,
from any node that can.  `Topology::node_for_cpu` is what fills that field in
at boot.  Nothing else reads it — the scheduler's work stealing picks the
busiest online CPU rather than the nearest one — so NUMA here is a
frame-placement policy and not a scheduling one.

## The paging model

`src/memory/paging.rs` is architecture-neutral and describes mappings rather
than hardware tables.  A mapping has a kind, permissions and a page size;
`MappingKind` exists because the *reason* a page is mapped decides what may
happen to it:

| Kind | What it means |
|------|---------------|
| `KernelHeap`, `KernelStack` | The heap and kernel stacks; `KernelStack` is also what keeps a stack out of reclaim and relocation, which select candidates by kind |
| `Anonymous`, `DemandPaged`, `Cow`, `Shared`, `Locked` | User memory: ordinary, lazily faulted, copy-on-write, shared between address spaces, and pinned against reclaim |
| `Identity`, `DeviceMemory` | Mappings that describe the machine rather than a program |

`PagePermissions` is three bits — read, write, execute — with `contains` for
"is this at least that" and `as_rwx` for a representation a log can print.
`AdviceHint` carries `madvise`'s answer about how a range will be used, which
the reclaim path reads.

The kernel's own ranges have one source of truth in `src/memory/map_facts.rs`:
`RegionKind` says what a kernel range is for (text, rodata, data, bss, heap,
stack window) and `Region` says whether it is writable and executable.  It is
deliberately dependency-free and allocation-free, because it is derived before
the heap exists, and it exists because the page plan, each architecture's
runtime table builder and the fault classifier had each worked the answer out
for themselves and disagreed.  Boot checks that the live tables cover what the
facts claim (`check_kernel_map_coverage`).

## The manager

`MemoryManager` (`src/memory/manager/`) is what the rest of the kernel holds:
frames, the heap, the paging backend and the per-process user mappings.  It is
installed once as a global (`src/memory/global.rs`) behind an `AtomicPtr` and a
lock, and reached through `global()` and `global_mut()`.  The lock disables
interrupts for its whole critical section — not for tidiness but because a
thread preempted while holding it can never be rescheduled on a single CPU,
and any path into the frame allocator (a `Vec` growing, say) takes it.

User mappings are installed in batches: `register_user_pages` takes
`(va, pa, permissions, kind)` tuples and answers whether the range was
accepted, and `register_shared_page` is the shape a shared-memory segment uses.
Unmapping (`unregister_user_page_range`) is where the bookkeeping has to happen
at once: it decrements copy-on-write frame reference counts, frees swap slots
that belonged to the range, and drops the translations.

## The heap

The kernel heap is a fixed region in BSS, managed by a TLSF allocator
(`src/memory/heap/tlsf.rs`): size classes for powers of two (`FL_*`) and
sub-classes within them (`SL_COUNT`), a block header before each allocation
(`HEADER_SIZE`), a minimum block size (`MIN_FREE_BLOCK`) and a block alignment
(`HEAP_BLOCK_ALIGNMENT`).  Its whole point is the bound: allocation and free
are constant-time, so an allocation cannot itself be the thing that
destabilises a path which is already in trouble.

`allocator.rs` holds the arena and its state, and `src/memory/heap/wrapper.rs`
wires it to `GlobalAlloc`, which is how `alloc` in this kernel lands here.  The
heap's window is fixed at boot (`KERNEL_HEAP_SIZE`): it is not growable, so a
long-running machine's allocation pressure is answered by reclaim and swap
rather than by asking the platform for more.

## Reclaim and swap

Two mechanisms give memory back, and they answer different pressures:

- **`src/memory/swap.rs`** moves a page out to a block device and remembers
  where: fixed-size slots holding whole pages, and a last-in-first-out free
  list rebuilt from scratch each boot, because swap contents are only valid
  for the session that wrote them.  A swap area is found rather than
  configured: `maybe_init_swap` probes block devices for a signature in the
  device's first block, so a disk prepared as swap is used without a command
  line.
- **`src/memory/compressed.rs`** is the zswap-shaped path: instead of writing a
  page out, it keeps the content in a compressed cache when the reclaimer
  cannot write it to a device, and decompresses on demand when the page is
  faulted back in.

The software page table records an accessed bit per mapping, and reclaim uses
it as a clock hand rather than a list: a page that has not been touched since
the last pass is a candidate, which is what makes the scan O(pages) with no
sorting and no per-page allocation.

## Kernel stacks

Kernel stacks are their own story, because a stack is the one mapping a fault
handler cannot do without.  `src/kernel/process/thread/kernel_stack.rs` owns
them, and all three architectures now name a window for them
(`src/arch/aarch64/mmu/mod.rs`, `src/arch/x86_64/paging/runtime.rs`,
`src/arch/riscv64/mmu/mod.rs`): a stack is a slice of that window whose guard
is a slice the allocator never hands out, so there is no mapping to remove and
nothing that can fail to remove it.

A slice a dead stack gives back is *retired* rather than freed: it is handed
out again only once every CPU has dropped its translation, because a stale TLB
entry would shadow the new mapping with the old frame.  On AArch64 the
invalidation is inner-shareable and the hardware has already done it; on x86_64
and RISC-V, where invalidation is local (`invlpg`, `sfence.vma`), a changed
range is posted to `src/kernel/smp/tlb.rs` and each other CPU walks it on its
next kernel entry, invalidating only the pages named and publishing how far it
has walked (`PostedLog`, `apply_remote_tlb_invalidations`).  A full flush still
happens when the log fills or the range is large, but it is no longer what an
unmap costs.  Nothing blocks: a slice that is not ready stays retired and the
allocator takes the next address.  A stack the window cannot serve becomes a
run of frames at its own addresses, and its guard is the page below it,
un-presented by the architecture's `unmap_page`.

## Architecture dispatch

`src/memory/arch.rs` is the one place the neutral memory code names a machine:
`shootdown_range`, `install_user_page_arch`, `unmap_user_page_arch`,
`map_stack_page_arch` and `unmap_stack_page_arch`, `stack_window`,
`ensure_identity_mapped_range`, `bootstrap_translation` and
`prepared_page_tables_active` are implemented per architecture and called from
here.  The rest of the module stays free of `#[cfg(target_arch = …)]`, which is
what keeps a fourth port a matter of writing one directory instead of finding
branches.

## Address-space layout

The kernel runs in the top half of the address space on x86_64 and in the
architecture's kernel window on the other two; the heap, the frame pool and the
stack window are all inside the kernel's own image and windows,
not at addresses chosen by the platform.  A user address space is a root plus
the shared kernel window: a stack mapped into the window after a root was
derived has to be visible in it, so windows are shared rather than copied into
each root.

The exact split — which ranges exist, which are writable and which executable —
is `src/memory/map_facts.rs`'s, and the per-architecture constants that place
them are in the arch modules named above.  This document does not repeat them:
a range that moves is a range that would have to be updated in two places.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/memory/frame.rs` | The frame allocator, its backing pool, and the per-node array |
| `src/memory/paging.rs` | `MappingKind`, `PagePermissions`, `AdviceHint`, the mapping primitives |
| `src/memory/map_facts.rs` | The kernel's own ranges and what they are for |
| `src/memory/manager/` | `MemoryManager`: init, mapping operations, user page registration |
| `src/memory/global.rs` | The global singleton and its lock discipline |
| `src/memory/heap/` | The TLSF allocator, its arena state and the `GlobalAlloc` wrapper |
| `src/memory/swap.rs`, `src/memory/compressed.rs` | Reclaim's two mechanisms |
| `src/memory/arch.rs` | The entry points each architecture implements |
| `src/kernel/smp/tlb.rs` | Posted invalidations and the cross-CPU walk |
| `src/kernel/process/thread/kernel_stack.rs` | Kernel stacks, guards and retirement |

## See also

- [boot.md](boot.md) — when these subsystems come up
- [process.md](../kernel-introduction/process.md) — the threads whose stacks
  and address spaces these are (until that document is rewritten)
