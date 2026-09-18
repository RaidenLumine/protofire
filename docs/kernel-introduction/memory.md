# Memory Subsystem Architecture

## Overview

The memory subsystem manages physical frames, virtual address
spaces, kernel heap allocation, and page-table operations.  It is organised
under `src/kernel/memory/` into the following layers, from bottom to top:

1. **Physical memory detection and frame allocation** — discovering available RAM
   and handing out 4 KiB frames.
2. **Virtual memory / paging** — per-process software page tables with
   `MappingKind` classification and `PagePermissions`.
3. **Kernel heap** — a TLSF-based `GlobalAlloc` for dynamic kernel allocations.
4. **MemoryManager** — the central coordinator that ties the above together and
   provides the externally visible API.

```
  ┌─────────────────────────────────────────────┐
  │            MemoryManager                    │
  │  (manager/mod.rs, manager/init.rs,          │
  │   manager/mapping.rs, manager/pfault.rs,    │
  │   manager/swap.rs)                          │
  ├───────────┬──────────┬──────────────────────┤
  │ Frame     │ PageTable│ HeapAllocator        │
  │ Allocator │ (paging) │ (heap/tlsf+allocator)│
  │ (frame.rs)│          │                      │
  ├───────────┴──────────┴──────────────────────┤
  │         arch.rs (platform dispatch)          │
  └─────────────────────────────────────────────┘
```

---

## 1. Physical Memory Detection

Early in boot the architecture-specific binary crate parses the bootloader's
memory map and records the total physical RAM in a global atomic:

```rust
// src/kernel/memory/arch.rs
static DETECTED_PHYSICAL_MEMORY: AtomicU64 = AtomicU64::new(0);
```

- `store_detected_memory(size: usize)` (line 23) — called **once** during early
  boot, before `MemoryManager::init()`.  Stores the value with `Release`
  ordering.
- `detected_memory() -> Option<usize>` (line 31) — reads with `Acquire`
  ordering; returns `None` if no detection has run (i.e. the atomic is still
  zero).
- `detect_memory() -> usize` (line 123) — the internal fallback: if the atomic
  is non-zero it is returned, otherwise the caller gets
  `frame::physical_pool_size()` (32 MiB).

The bootloader sources are:
- **x86_64** — Multiboot2 memory map (`mb2_tag_mmap`).
- **AArch64 / RISC-V** — FDT `/memory` node's `reg` property.

---

## 2. Frame Allocator

Defined in `src/kernel/memory/frame.rs`.

```rust
pub struct FrameAllocator {
    base: usize,                    // start of backing pool
    total_frames: usize,            // pool size / FRAME_SIZE
    next_frame: usize,              // bump-allocation high-water mark
    free_ranges: BTreeMap<usize, usize>, // start_frame -> count, O(log n)
    pub profiler: AllocProfiler,
}
```

### Backing store

A static 32 MiB pool (`PHYSICAL_POOL`) is the default backing store.  The
`init(total_size)` method clamps the caller's detected size to this pool and
rounds down to whole frames.  On real hardware the frame allocator would manage
true physical frames; the static pool serves for prototyping and host-side
testing.

### NUMA-Aware Frame Allocation

The frame allocator subsystem supports NUMA topologies with up to 8 nodes
(`MAX_NODES = 8`). The `MemoryManager` holds an array of per-node frame
allocators (`frame_allocators: [FrameAllocator; MAX_NODES]`) instead of a
single allocator. Key operations:

- **`set_node_range(node_id, base, size)`** — registers a physical memory
  range as belonging to a specific NUMA node. Callers (the topology subsystem)
  invoke this during NUMA discovery to partition physical frames by node.
- **`allocate_frame_on_node(node_id, count)`** — allocates from the specified
  node's allocator. Falls back to the default allocator (node 0) if the
  node-specific allocator is exhausted.
- **`allocate_frames(count)`** — allocates from node 0 (the default/fallback
  allocator), maintaining backward compatibility with non-NUMA code paths.

The topology subsystem (`src/kernel/topology.rs`) provides:
- `NumaNode` — a node with ID, CPU count, and memory range.
- `Topology` — the global topology singleton holding the node table and
  CPU-to-node affinity mapping.
- `NUMA_NODE_NONE` — sentinel value (0xFF) for unaffiliated CPUs.
- `global()` — returns `Option<&'static Topology>`; `None` when no NUMA
  hardware is detected (single-node fallback).
- `node_for_cpu(cpu_id)` — returns the NUMA node ID for a given CPU.

The scheduler uses NUMA information in `try_steal_work()`: when choosing a
victim CPU for work stealing, same-NUMA-node victims receive a doubled score,
biasing the scheduler to steal from CPUs that share the same memory node.

### Allocation strategy

`allocate(count)` (line 66) uses a **hybrid approach**:

1. **Reuse from free ranges** — first-fit search over `free_ranges` (ascending
   address order via `BTreeMap` iteration).  If a hole of sufficient size is
   found, it is carved and returned.
2. **Bump the tail** — if no reusable hole fits, the bump pointer
   (`next_frame`) is advanced.
3. All returned frames are **zeroed** via `write_bytes`.

`deallocate(ptr, count)` (line 98) inserts the freed range into `free_ranges`,
**coalescing adjacent ranges** both forward and backward.  If the freed range
touches the bump tail, the tail is eagerly rewound so future allocations reuse
the reclaimed region.

### Public API

Through `MemoryManager`:

```rust
// src/kernel/memory/manager/init.rs
pub fn allocate_frames(&mut self, count: usize) -> Option<*mut u8>
pub fn deallocate_frames(&mut self, ptr: *mut u8, count: usize) -> bool
```

---

## 3. Virtual Memory and Paging

Defined in `src/kernel/memory/paging.rs`.

### Page Table Model

```rust
pub struct PageTable {
    mappings: Vec<Mapping>,  // software page table entries
    initialized: bool,
    pub profiler: AllocProfiler,
}
```

Each `Mapping` stores virtual address, physical address, length, permissions,
kind, and an `accessed` flag for the clock page-reclamation algorithm.

Key operations:

| Method | Purpose |
|--------|---------|
| `map_region(va, len, perms)` | Anonymous mapping of `len` bytes at `va` |
| `map_region_with_kind(va, len, perms, kind)` | As above with explicit `MappingKind` |
| `map_to(va, pa, len, perms)` | Identity or device mapping (VA != PA) |
| `map_to_with_kind(va, pa, len, perms, kind)` | Full-control mapping |
| `unmap(va, len)` | Remove mapping, preserving prefix/suffix fragments |
| `lookup(va)` | Translate VA -> (PA, PagePermissions) |
| `lookup_mapping(va)` | As above, also returns `MappingKind` |

Mappings **must not overlap** in the virtual address space — the `overlaps()`
check (line 383) rejects conflicting ranges.  `unmap` handles partial overlap
by splitting the existing mapping into prefix and suffix fragments.

### MappingKind

```rust
// src/kernel/memory/paging.rs, line 12
pub enum MappingKind {
    KernelHeap,   // kernel heap region
    Anonymous,    // ordinary anonymous memory
    Identity,     // identity-mapped (VA == PA), used during bootstrap
    DeviceMemory, // MMIO / device memory
    DemandPaged,  // lazily allocated on first access
    Cow,          // copy-on-write (fork optimisation)
    Shared,       // shared memory (multi-process)
}
```

### PagePermissions

A 3-bit bitfield (line 47):

```rust
pub struct PagePermissions(u8);
pub const READ:   Self = Self(0b001);
pub const WRITE:  Self = Self(0b010);
pub const EXECUTE:Self = Self(0b100);
```

Convenience constants `READ_WRITE`, `READ_EXECUTE`, and `READ_WRITE_EXECUTE`
are defined, along with `contains()` and `as_rwx()` accessors.

### Page Size

```rust
pub const PAGE_SIZE: usize = 4096;  // paging.rs, line 9
```

---

## 4. Memory Manager

Located in `src/kernel/memory/manager/mod.rs`, the `MemoryManager` is the
central coordinator:

```rust
pub struct MemoryManager {
    pub(crate) frame_allocators: [FrameAllocator; MAX_NODES], // per-NUMA-node allocators
    pub(crate) heap_allocator: HeapAllocator,
    pub(crate) page_table: PageTable,
    pub(crate) fault_profiler: FaultProfiler,
    pub(crate) kernel_heap_start: usize,
    pub(crate) kernel_heap_end: usize,
    pub(crate) initialized: bool,
    pub(crate) page_content: Vec<(usize, Vec<u8>)>,   // DemandPaged backfill
    pub(crate) frame_refcounts: BTreeMap<usize, usize>, // CoW refcounts
    pub(crate) reclaim_hand: usize,                    // clock cursor
    pub(crate) swap_area: Option<SwapArea>,
    pub(crate) swap_map: BTreeMap<usize, u64>,         // VA -> swap slot
}
```

### Initialisation

`MemoryManager::init()` (in `manager/init.rs`, line 28):

1. Calls `detect_memory()` to determine total physical RAM.
2. Initialises the `FrameAllocator` with that size.
3. Initialises the `PageTable`.
4. Calls `init_kernel_heap()` which invokes `HeapAllocator::init()` (triggers
   TLSF bootstrap on first allocation).
5. Calls `map_kernel_heap_bootstrap()` to register the kernel heap range as a
   `MappingKind::KernelHeap` mapping.

The call sequence from the boot path is:

```
binary crate boot
  → store_detected_memory(size)
  → MemoryManager::new()
  → MemoryManager::init()
  → install_global_unchecked(&manager)
```

### Global Singleton

```rust
// src/kernel/memory/global.rs
pub(crate) static GLOBAL_MEMORY_MANAGER: AtomicPtr<MemoryManager> = ...;
```

Access is through:
- `global() -> Option<&'static MemoryManager>` — immutable reference.
- `global_mut() -> Option<MemoryManagerGuard>` — mutable reference behind an
  exponential-backoff spinlock (`MEMORY_MANAGER_LOCK`) for SMP safety.
- `install_global_unchecked(memory)` — called once to install the singleton.

### Mapping Operations (manager/mapping.rs)

Tying page-table operations to hardware:

| `MemoryManager` method | Delegates to | Also calls |
|------------------------|-------------|------------|
| `map_region` | `page_table.map_region_with_kind` | — |
| `map_region_with_kind` | `page_table.map_region_with_kind` | — |
| `map_to` | `page_table.map_to_with_kind` | — |
| `map_to_with_kind` | `page_table.map_to_with_kind` | `shootdown_range()` |
| `unmap` | `page_table.unmap` | `shootdown_range()` |
| `translate` | `page_table.lookup` | — |

After any mapping change, `shootdown_range()` (from `arch.rs`) broadcasts a TLB
invalidation IPI to all online CPUs.

### User Page Registration

```rust
// manager/mapping.rs
pub fn register_user_pages(
    &mut self,
    pages: &[(usize, usize, PagePermissions, MappingKind)],
) -> usize

pub fn register_shared_page(
    &mut self,
    virtual_address: usize,
    physical_address: usize,
    permissions: PagePermissions,
) -> Result<()>

pub fn unregister_user_page_range(
    &mut self,
    start: usize,
    len: usize,
) -> usize
```

`register_user_pages` (line 156) iterates over a slice of `(va, pa, perms,
kind)` tuples, skipping any that would conflict with kernel mappings
(`KernelHeap`, `Identity`, `DeviceMemory`).  Existing user mappings at the same
VA are silently replaced (unmapped first).

`unregister_user_page_range` (line 210) removes user mappings (`Anonymous`,
`DemandPaged`, `Cow`, `Shared`), decrements CoW frame refcounts, and frees any
associated swap slots.

### Diagnostic Probes

`page_fault_insight(va)` (line 91) assembles a layered diagnostic snapshot:

- Current runtime translation (from `PageTable::lookup_mapping`).
- Bootstrap translation (x86_64 identity mapping, via
  `arch::bootstrap_translation`).
- Prepared translation (runtime kernel tables, x86_64 only).
- Planned kernel region classification.
- Whether `va` falls within the kernel heap range.

---

## 5. Kernel Heap

The kernel heap is a **TLSF (Two-Level Segregated Fit)** allocator, defined
across `src/kernel/memory/heap/`.

```
heap/
  mod.rs        — module structure, re-exports
  allocator.rs  — KernelGlobalAllocator, GlobalAlloc impl, spinlock guard
  tlsf.rs       — TLSF constants, block header, free lists, bitmaps, coalescing
  wrapper.rs    — #[global_allocator] wiring, heap_model(), HeapAllocator API
  global.rs     — [alternate file] same content as allocator.rs+wrapper.rs
```

### TLSF Parameters

```
KERNEL_HEAP_SIZE  = 16 MiB
HEAP_BLOCK_ALIGNMENT = 16 bytes
HEADER_SIZE       = 16 bytes (size + prev_phys_block)
MIN_FREE_BLOCK    = 32 bytes
FL_MIN = 5, FL_MAX = 24  →  FL_COUNT = 20
SL_COUNT = 32
FREE_LISTS_COUNT  = 20 * 32 = 640
```

### Allocator State

```rust
// heap/tlsf.rs, line 59
pub(crate) struct AllocatorState {
    pub start: usize,          // heap base
    pub end: usize,            // heap end
    pub available: usize,      // free bytes
    pub initialized: bool,
    pub fl_bitmap: u32,        // one bit per first-level class
    pub sl_bitmaps: [u32; FL_COUNT],  // one bit per second-level subclass
    pub free_lists: [usize; FREE_LISTS_COUNT],  // 640 list heads
}
```

### Allocation Algorithm

`allocate_locked` (heap/allocator.rs, line 118):

1. Compute `min_block_size` from the requested `Layout` (size + alignment
   padding + header).
2. Search via `find_suitable_block` using the TLSF bitmaps to locate a free
   block of the appropriate size class — O(1) expected.
3. Carve the block: create a prefix free block (if the alignment gap is ≥
   `MIN_FREE_BLOCK`), a suffix free block (if remaining space ≥
   `MIN_FREE_BLOCK`), and mark the allocated block as used.
4. Update the `prev_phys` chain for coalescing.

If the chosen block turns out too tight after alignment, it is re-inserted and
the next size class is tried (this avoids infinite loops caused by the same
block being found again via the same bitmap entry).

### Deallocation and Coalescing

`deallocate_locked` (line 281):

1. Validate the pointer: must be non-null, within `[start, end)`, and marked
   used.
2. Mark the block free.
3. Call `coalesce()` to merge with physically adjacent free blocks (using the
   `prev_phys_block` field and the next block's header).
4. Insert the coalesced block into the appropriate free list.

### GlobalAlloc Wiring

```rust
// heap/wrapper.rs (or heap/global.rs)
#[global_allocator]
#[cfg(target_os = "none")]
static GLOBAL_ALLOCATOR: KernelGlobalAllocator = KernelGlobalAllocator::new();
```

This registers the TLSF allocator as Rust's global allocator.  On non-bare-metal
targets (`#[cfg(not(target_os = "none"))]`), the standard `System` allocator is
used instead.

```rust
pub(crate) fn heap_model() -> &'static KernelGlobalAllocator { ... }
```

`HeapAllocator` (line 21 of `wrapper.rs`) provides a public API:

```rust
pub struct HeapAllocator;
impl HeapAllocator {
    pub fn init(&self);        // lazy-init on first use
    pub fn bounds(&self) -> (usize, usize);
    pub fn remaining(&self) -> usize;
}
```

### Spinlock

`KernelGlobalAllocator::acquire_lock()` uses an **exponential-backoff
test-and-test-and-set** spinlock that **disables interrupts** while held.
Interrupts are disabled to prevent re-entrancy deadlocks: a timer interrupt can
preempt a thread holding the heap lock, schedule another thread that then tries
to allocate, and deadlock on the same CPU.  The guard restores the previous
interrupt state on drop.

---

## 6. Architecture Dispatch

`src/kernel/memory/arch.rs` provides thin wrappers around platform MMU
primitives.

### TLB Shootdown

```rust
pub(crate) fn shootdown_range(virtual_address: usize, length: usize)  // line 42
```

Aligns the range to page boundaries and calls `smp::tlb_shootdown(va)` for each
page.  On SMP targets this sends an IPI and waits for acknowledgment.

### User Page Installation

```rust
pub(crate) fn install_user_page_arch(va, pa, permissions) -> bool  // line 60
pub(crate) fn unmap_user_page_arch(va) -> bool                     // line 99
```

These dispatch to `crate::arch::mmu::install_user_page` / `unmap_page` per
target architecture (x86_64, AArch64, RISC-V), or return `false` on host
targets.

### Translation Diagnostics (x86_64)

- `bootstrap_translation(va)` — translates through the early identity mapping.
- `prepared_page_tables_active()` — checks whether runtime kernel tables are
  live.
- `prepared_translation(va, heap_bounds)` — translates through the runtime
  kernel tables.
- `planned_kernel_region(va, heap_bounds)` — classifies an address against the
  intended page-layout plan.

---

## 7. Address Space Layout

### Kernel Address Space

The kernel heap occupies a contiguous region (`KERNEL_HEAP_SIZE` = 16 MiB),
registered as `MappingKind::KernelHeap` in the software page table.  The heap
backs all `alloc`/`dealloc` calls via the `GlobalAlloc` trait.

Kernel stacks (described in `src/kernel/stack.rs`, not in the memory module
itself) are frame-backed regions with an unmapped guard page below the stack to
catch stack underflow.  Each thread receives its own dedicated kernel stack.

### User Address Space

Process address spaces are managed through the per-process `PageTable`.  User
pages are installed via `register_user_pages()` which accepts an array of
`(va, pa, perms, kind)` tuples.  Supported user-space `MappingKind` values are:

| Kind | Purpose |
|------|---------|
| `Anonymous` | Ordinary heap/stack/data mappings |
| `DemandPaged` | Lazily allocated; first access triggers a page fault that allocates a zeroed frame |
| `Cow` | Copy-on-write (fork); shared read-only until a write fault triggers a private copy |
| `Shared` | Cross-process shared memory; frames managed by a shared-memory segment registry |

Shared memory pages are registered via `register_shared_page()` which always
uses `MappingKind::Shared`.  Unmapping a range with `unregister_user_page_range`
automatically decrements CoW frame refcounts and frees any associated swap
slots.

---

## 8. Page Reclamation and Swap

The software page table tracks an `accessed` bit per mapping, used by a **clock
algorithm** for page reclamation (the clock hand is `reclaim_hand`).  When
physical memory is under pressure, the reclamation sweeper iterates mappings,
clears `accessed` bits, and reclaims pages that have not been recently used.

Reclaimed pages can be:
- Stored **in-memory** in `page_content` (the content store) for demand-page
  backfill — the original code/data is retained so a subsequent fault can
  repopulate the page.
- Written to a **swap device** via `SwapArea` — the VA-to-slot mapping is kept
  in `swap_map` (`BTreeMap<usize, u64>`).

### Swap Area (`src/kernel/memory/swap.rs`)

The `SwapArea` struct wraps an `Arc<dyn BlockDevice>` and manages page slots
in contiguous block ranges:

```rust
pub struct SwapArea {
    device: Arc<dyn BlockDevice>,
    start_lba: u64,
    total_pages: u64,
    free_slots: Vec<u64>,
}
```

Each page slot spans 8 × 512-byte blocks (4096 bytes, matching `PAGE_SIZE`).
Slots are allocated from a LIFO free list rebuilt on every boot — swap data
is valid only for the current boot session.

### Boot-Time Swap Detection

At boot, `maybe_init_swap()` (called from `Kernel::init()` after filesystem
initialization) scans registered block devices for a valid swap signature:

```rust
pub const SWAP_MAGIC: [u8; 8] = *b"ADASWAP\x00";

pub fn probe_device(device: &dyn BlockDevice) -> Option<(u64, u64)> {
    let mut header = [0u8; 512];
    device.read_blocks(0, &mut header).ok()?;
    if header[..8] != SWAP_MAGIC {
        return None;
    }
    let page_count = u64::from_le_bytes(header[8..16].try_into().ok()?);
    if page_count == 0 { return None; }
    Some((0, page_count))
}
```

If a device with the `ADASWAP` magic signature is found, `init_swap()` is
called with the device, start LBA (0), and page count. If no swap device is
discovered, the kernel falls back to in-memory `page_content` storage
(existing behaviour).

---

## Key Source Locations

| Component | File |
|-----------|------|
| Memory detection | `src/kernel/memory/arch.rs` (lines 12-34, 123-130) |
| Frame allocator | `src/kernel/memory/frame.rs` |
| NUMA-aware allocators | `src/kernel/memory/frame.rs` (`MAX_NODES`, `set_node_range()`) |
| NUMA topology | `src/kernel/topology.rs` |
| Page table / paging | `src/kernel/memory/paging.rs` |
| `MemoryManager` struct | `src/kernel/memory/manager/mod.rs` |
| `MemoryManager::init` | `src/kernel/memory/manager/init.rs` |
| Mapping operations | `src/kernel/memory/manager/mapping.rs` |
| Global singleton | `src/kernel/memory/global.rs` |
| TLSF allocator | `src/kernel/memory/heap/tlsf.rs` |
| `KernelGlobalAllocator` | `src/kernel/memory/heap/allocator.rs` |
| `#[global_allocator]` wiring | `src/kernel/memory/heap/wrapper.rs` |
| Arch MMU dispatch | `src/kernel/memory/arch.rs` |
| Page-fault handling | `src/kernel/memory/manager/pfault.rs` |
| Swap / page reclamation | `src/kernel/memory/manager/swap.rs`, `src/kernel/memory/swap.rs` |
| Swap boot probe | `src/kernel/memory/swap.rs` (`SWAP_MAGIC`, `probe_device()`) |
| Swap boot integration | `src/kernel/mod.rs` (`maybe_init_swap()`) |
| Allocator profiling | `src/kernel/memory/alloc_profiler.rs` |

---

## See Also

- [Subsystem overview](../en/memory.md) — high-level memory management description
- [Documentation index](../README.md) — complete document tree
