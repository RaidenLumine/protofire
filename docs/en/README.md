# Kernel Architecture

## Design Philosophy

This is a from-scratch hobby OS kernel written in Rust, targeting x86_64, AArch64, and RISC-V 64. It runs entirely `no_std` (no libc, no standard library) on bare metal. The kernel is **monolithic** -- all core subsystems (memory management, filesystem, scheduler, drivers, network stack, syscall dispatch) run in a single privileged address space with no microkernel IPC boundaries.

Key design goals:
- **Rust safety where possible**: the kernel uses `unsafe` only for MMIO, inline assembly, and pointer-level context-switch mechanics. Page table walks, filesystem operations, and network protocol parsing are safe Rust.
- **Single-address-space ELF loader**: ring-3 (user) programs are self-contained ELF files loaded into per-process page tables. No dynamic linking, no shared libraries -- each program is a standalone binary.
- **Cooperative threading**: the scheduler runs a simple round-robin of kernel and user threads. There is no preemption timer in the scheduler core; threads yield explicitly via `yield_current()` or blocking I/O. Timer interrupts increment a tick counter and drive scheduler timeslicing via `on_timer_tick_with_preemption`.
- **File-oriented ABI**: the syscall interface is modelled on POSIX-like operations (open, read, write, close, ioctl, mmap, fork, exec, wait) with a flat 100-slot dispatch table.
- **Minimal platform assumptions**: boot information is received via Multiboot2 (x86_64) or a flattened device tree FDT pointer (AArch64, RISC-V). PCI/ACPI table walks happen after early memory init.

The kernel is approximately **210,000+ lines of Rust** across **460+ source files** in the `src/` tree.

---

## Boot Flow

```
                 x86_64                              AArch64 / RISC-V
       ┌─────────────────────┐          ┌──────────────────────────┐
       │  GRUB / bootloader  │          │  QEMU virt / firmware    │
       │  Multiboot2 header  │          │  DTB pointer in x0/a0    │
       └────────┬────────────┘          └───────────┬──────────────┘
                │                                    │
                ▼                                    ▼
       ┌─────────────────────┐          ┌──────────────────────────┐
       │ arch/x86_64/boot.asm│          │ arch/aarch64/boot.S      │
       │ 32-bit entry,       │          │ or arch/riscv64/boot.S   │
       │ switch to long mode │          │ set up stack, jump to    │
       │ call kernel_entry() │          │ kernel_entry_*()         │
       └────────┬────────────┘          └───────────┬──────────────┘
                │                                    │
                ▼                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │ main.rs: kernel_entry*() -> boot_kernel(BootInfo)      │
       │   - store handoff address for later SMP/ACPI use       │
       │   - print banner                                       │
       │   - parse FDT (aarch64/riscv64) or store multiboot     │
       │   - construct Kernel::new()                            │
       │   - call Kernel::init()                                │
       └────────────────────────┬───────────────────────────────┘
                                │
                                ▼
       ┌────────────────────────────────────────────────────────┐
       │ Kernel::init()  (src/kernel/mod.rs)                    │
       │                                                        │
       │   1. memory::init()           TLSF heap allocator      │
       │   2. prepare_arch_paging()    Switch to kernel page    │
       │                               tables                   │
       │   3. init_numa()              NUMA topology detection  │
       │   4. console::init_global()                            │
       │   5. drivers::init()          Probe VirtIO (block,     │
       │                               net, input, GPU)         │
       │   6. fs::init_with_boot_disk()  Build/mount boot VFS   │
       │   7. maybe_init_swap()        Disk-backed swap detect  │
       │   8. PCI/PCIe enumeration     (x86_64 + AArch64)       │
       │   7. Network stack init       DHCP address acquisition │
       │   8. Volume recovery          Check-and-repair mounts  │
       │   9. user::init_user_database()                        │
       │  10. arch::interrupt_controller::init()                │
       │  11. arch::timer::init()                               │
       │  12. Per-CPU data + SMP AP bring-up  (x86_64)         │
       │  13. syscall::Table::init()    Populate dispatch table │
       │  14. spawn_init_program()     Load /system/init.elf    │
       │  15. spawn_system_programs()  (demo-disk feature)      │
       │  16. scheduler.start_idle_process()                    │
       └────────────────────────┬───────────────────────────────┘
                                │
                                ▼
       ┌────────────────────────────────────────────────────────┐
       │ Kernel::run()  (never returns)                         │
       │   loop {                                               │
       │     scheduler.process_deferred_dying()                 │
       │     arch::interrupts::disable()                        │
       │     scheduler.schedule()                               │
       │     arch::instructions::idle()                         │
       │   }                                                    │
       └────────────────────────────────────────────────────────┘
```

The `kernel_entry` functions per architecture are:

- **x86_64**: `kernel_entry(multiboot_magic, multiboot_info)` in `src/main.rs`, called from `src/arch/x86_64/boot.asm`. Parsed via `arch::boot::from_x86_64_multiboot2()`.
- **AArch64**: `kernel_entry_aarch64(device_tree_blob)` in `src/main.rs`, called from `src/arch/aarch64/boot.S`. Parsed via `arch::boot::from_aarch64_qemu_direct()`.
- **RISC-V**: `kernel_entry_riscv64(device_tree_blob)` in `src/main.rs`, called from `src/arch/riscv64/boot.S`. Parsed via `arch::boot::from_riscv64_qemu_direct()`.

On AArch64 and RISC-V the serial console is initialized before the banner; on x86_64 the UART is set up inside `X86_64::init_early()`.

---

## Subsystem Dependency Graph

```
kernel::Kernel
    ├── memory::MemoryManager        (TLSF heap, frame allocator, page tables)
    │     └── memory::paging         (arch-generic page table interface)
    ├── process::Scheduler           (cooperative round-robin, thread lifecycle)
    │     ├── process::Thread        (per-thread context, state machine)
    │     ├── process::Process       (address space, fd table, security token)
    │     └── process::Context       (arch register save area)
    ├── fs::FileSystem               (VFS + SimpleFS)
    │     └── fs::simplefs           (on-disk layout, two-phase commit)
    ├── drivers::DriverManager       (VirtIO block/net/input/gpu, PCI probe)
    │     └── device                 (console, keyboard, null, zero, serial)
    ├── syscall::Table               (100-slot dispatch table)
    │     ├── syscall::process_launch
    │     ├── syscall::process_management
    │     ├── syscall::fs
    │     ├── syscall::net
    │     └── syscall::ipc
    ├── network                      (TCP/UDP/DHCP/DNS, raw sockets)
    ├── shm                          (shared memory regions)
    ├── topology                     (NUMA topology, per-node allocators)
    ├── smp                          (SMP AP discovery and bring-up, x86_64)
    ├── percpu                       (per-CPU scheduler/APIC data, numa_node_id)
    ├── sync                         (Mutex, SpinLock, Condvar)
    ├── crypto                       (signing key verification)
    └── user                         (user database, program loader)

arch                                 (per-target dispatch layer)
    ├── boot                         (BootInfo, multiboot/FDT parsing)
    ├── mmu                          (page table prepare/activate/check)
    ├── trap                         (exception vector setup)
    ├── interrupt_controller         (APIC, GICv2, PLIC)
    ├── timer                        (PIT/HPET, generic timer, SBI timer)
    ├── syscall_trap                 (syscall entry asm glue)
    └── {x86_64, aarch64, riscv64}   (per-arch: serial, context switch, paging)
```

The `Kernel` struct in `src/kernel/mod.rs` owns the top-level subsystems:

```rust
pub struct Kernel {
    memory: MemoryManager,
    scheduler: Scheduler,
    fs: Mutex<FileSystem>,
    drivers: DriverManager,
    syscall_table: syscall::Table,
    initialized: bool,
}
```

Each subsystem is installed into a global slot after initialization (e.g. `memory::install_global_unchecked`, `syscall::install_global_unchecked`, `fs::install_global_unchecked`) so interrupt handlers and worker threads can access them without borrowing the `Kernel` object.

---

## Memory Layout

### Physical Memory

Physical memory is discovered via the Multiboot2 memory map (x86_64) or FDT `/memory` node (AArch64, RISC-V). The frame allocator (`memory::frame`) manages 4 KiB page frames using a bitmap allocator, with a separate TLSF heap for the kernel's own allocations.

### Virtual Memory Layout (x86_64 example)

```
0x0000_0000_0000_0000  ┌──────────────────────┐
                       │  User space (PML4     │  User ELF segments,
                       │  entries 0..255)      │  stacks, guard pages
                       │                       │
                       │  [user stack]         │
                       │  [guard page]         │
                       │  [ELF segments]       │
0x0000_8000_0000_0000  ├──────────────────────┤
                       │  (hole / canonical    │
                       │   address break)      │
0xFFFF_8000_0000_0000  ├──────────────────────┤
                       │  Kernel space (PML4   │  Kernel image,
                       │  entries 256..511)    │  heap, page tables
                       │                       │
                       │  [kernel text/data]   │
                       │  [TLSF heap]          │
                       │  [page table pages]   │
                       │  [frame allocator     │
                       │   bitmap]             │
0xFFFF_FFFF_FFFF_FFFF  └──────────────────────┘
```

On AArch64 and RISC-V the partitioning follows the same principle with arch-specific VA bit widths (48-bit or 39-bit).

### Kernel Stack and Guard Pages

Each kernel thread has a dedicated stack region backed by physical frames. Below each stack is a single unmapped guard page that triggers a page fault on stack overflow. The guard page is allocated and mapped during thread creation in `process/thread.rs` and is described in the [Kernel Stack Guard Pages](../en/memory.md#kernel-stack-guard-page) overview. This applies to both kernel threads and user-thread kernel stacks.

### Heap

The kernel heap uses a **TLSF (Two-Level Segregated Fit)** allocator implemented in `memory/heap/`. It is initialized early in `Kernel::init()` by `MemoryManager::init()`, which carves out a region from the frame allocator and seeds the TLSF pools. After that point, `extern crate alloc` provides `Box`, `Vec`, `Arc`, `String`, etc.

TLSF was chosen because it provides O(1) allocation/free with bounded fragmentation -- important for a kernel that cannot rely on a userspace malloc.

---

## Build System

### Makefile Targets

The top-level `Makefile` provides:

| Target | Description |
|--------|-------------|
| `build` | Build x86_64 kernel ELF (`x86_64-unknown-none`) |
| `build-aarch64` | Build AArch64 kernel ELF (`aarch64-unknown-none`) |
| `build-riscv64` | Build RISC-V kernel ELF (`riscv64gc-unknown-none-elf`) |
| `run` | Boot x86_64 on QEMU q35 (no disk, serial console) |
| `run-aarch64` | Boot AArch64 on QEMU virt |
| `run-riscv64` | Boot RISC-V on QEMU virt |
| `check` | Host + bare-metal type checks |
| `check-aarch64` / `check-riscv64` | Cross-target type checks |
| `test` | Host-side unit + integration tests (with `demo-disk`) |
| `verify-p{0,1,2,3}` | CI verification gates (increasing scope) |
| `fmt` / `fmt-check` | Rust formatting |
| `clippy` | Lint checks |

QEMU invocations pass a VirtIO net device for network stack testing and use `-serial stdio` for console output.

### Feature Flags

Defined in `Cargo.toml`:

| Feature | Purpose |
|---------|---------|
| `demo-disk` | Enable in-memory demo SimpleFS volumes, demo worker threads, and demo user programs |
| `fs_profiler` | Filesystem I/O profiling counters |
| `net_profiler` | Network stack profiling counters |
| `alloc_profiler` | Heap allocator profiling counters |
| `fault_profiler` | Page fault profiling counters |
| `educational_networking` | Enable pedagogical documentation in networking code |

The default feature set is empty. Most integration tests use `--features demo-disk` to populate a boot filesystem.

### Linker Scripts and `build.rs`

The `build.rs` script at the repository root selects the per-architecture linker script:

| Target | Linker Script |
|--------|---------------|
| `x86_64-unknown-none` | `linker.ld` |
| `aarch64-unknown-none` | `linker-aarch64.ld` |
| `riscv64gc-unknown-none-elf` | `linker-riscv64.ld` |

The demo system volume is constructed in-kernel by `src/kernel/fs/demo.rs`; the launch chain follows the `/apps/current → /apps/catalog → /apps/packages` layout, resolved by `crate::user::program::launch_reference`.

Ring-3 ELF payload construction is handled in-kernel by `src/user/demo/` (`elf_builder`); placeholder ELFs for the demo volume are inlined in `src/kernel/fs/demo.rs`.

### CI Verification Gates

The `scripts/verify.sh` script runs tiered checks:

- **P0**: format check + host/x86_64/AArch64 build checks + header coverage
- **P1**: P0 plus fast concurrency/path/I-O/ABI regression tests
- **P2** (default): P1 plus storage/recovery/fault-matrix regression tests
- **P3**: P2 plus clippy and optional AArch64 runtime smoke test (`make check-aarch64-runtime`)

---

## ABI Stability Policy

- **Syscall numbers are stable**. The 100-slot dispatch table (`syscall::Table` in `src/kernel/syscall/table.rs`) assigns fixed numbers to operations (open, read, write, close, ioctl, mmap, fork, exec, wait, etc.). New syscalls must use previously unassigned slots.
- **`src/user/shared/` is the ABI boundary**. This module defines the ABI record types (`FileStat`, `DirectoryEntryRecord`, `IoVec`, etc.) and syscall wrapper functions. Changes to its public types require coordination across all consumers.
- The kernel is versioned as `2026.7.1` (calendar versioning). There is no stability guarantee across major versions; ring-3 ELFs are shipped with the demo disk and rebuilt together with the kernel.

---

## Key Architecture Decisions

### Monolithic Kernel with Cooperative Threading

The entire kernel runs in a single privilege level (ring 0 / EL1 / S-mode) with a single virtual address space. There is no separate "kernel server" process. Drivers, the filesystem, the network stack, and the syscall dispatcher are all linked into the same binary and call each other directly.

Thread scheduling is **cooperative** by default: `schedule()` is called explicitly from the main loop, from blocking I/O paths, and from `yield_current()`. The timer interrupt handler (`on_timer_tick_with_preemption`) can mark the current thread as preemptible, but the actual context switch still happens in the main loop's `schedule()` call. This design avoids re-entrancy issues in the scheduler and keeps the context-switch path deterministic.

### Ring-3 Programs as Self-Contained ELFs

User programs (`/system/init.elf`, the shell, demo payloads) are standalone ELF binaries stored on the boot filesystem. The kernel's program loader (`src/user/program/`) parses the ELF headers, maps segments into the user address space, set up a stack with a guard page, and returns to user mode via an `iretq` / `eret` / `sret` instruction. There is no dynamic linker.

### Architecture Abstraction via `src/arch/`

The `src/arch/mod.rs` module defines the `Arch` trait (`init_early`, `halt`, `reboot`) and uses conditional compilation to delegate to:

- `src/arch/x86_64/` -- GDT, IDT, paging (4-level), APIC/IOAPIC, port I/O, MSI, UART 16550
- `src/arch/aarch64/` -- trap vectors (trap.S), MMU (4-level), GICv2, PL011 UART, FDT parsing, PCIe ECAM
- `src/arch/riscv64/` -- trap vectors (trap.S), MMU (Sv39), PLIC, NS16550A UART, SBI/Sstc timer, FDT parsing

The `mmu` and `interrupt_controller` facades re-export the per-arch implementation:

```rust
// src/arch/mmu.rs
#[cfg(target_arch = "x86_64")]
pub use super::x86_64::paging::*;
#[cfg(target_arch = "aarch64")]
pub use super::aarch64::mmu::*;
```

This allows code in `src/kernel/` to call `arch::mmu::prepare_runtime_kernel_page_tables()` without caring which architecture is targeted.

### Volume Recovery

On every boot the kernel runs `recover_volumes()` on each mounted volume (excluding the synthetic root). It calls `fs.check_and_repair_volume()` which runs the SimpleFS consistency checker: orphan data blocks, interrupted two-phase commits, checksum failures, and staging-directory orphans. A `VolumeRecoverySummary` is stored globally and can be queried at runtime via the `SystemHealth` syscall.

### SMP Support

Currently **x86_64 only** (with AArch64 and RISC-V planned). The BSP discovers APs via ACPI MADT during early boot (before page table switch, while the identity map is still active), saves the boot CR3 for the AP trampoline, then brings up APs after per-CPU data initialization. Each CPU has its own scheduler instance tracked in the percpu-scheduler table. See `src/kernel/smp/` and `src/arch/x86_64/ap_trampoline.asm`.

### NUMA Support

The kernel supports NUMA topologies with up to 8 nodes (`MAX_NODES = 8`).
Discovery is performed by `init_numa()` during early boot (after page table
preparation, before device drivers). The topology subsystem
(`src/kernel/topology.rs`) categorises discovered CPU cores and memory ranges
into NUMA nodes. Per-CPU data includes a `numa_node_id: u8` field for
CPU-to-node affinity lookup. The frame allocator maintains an array of 8
per-node allocators, and the scheduler's work-stealing algorithm prefers
victim CPUs on the same NUMA node. When no NUMA hardware is detected (the
common case), a default single-node topology maps all CPUs to node 0.

---

## Related Documentation

### Subsystem Overviews (`docs/en/`)

| Document | Description |
|----------|-------------|
| [`docs/en/README.md`](../en/README.md) | Architecture overview, subsystem dependency graph, memory layout, build system |
| [`docs/en/boot.md`](../en/boot.md) | Boot flow, Kernel::init() step-by-step, SMP |
| [`docs/en/memory.md`](../en/memory.md) | Physical/virtual memory management, TLSF heap, page tables |
| [`docs/en/process.md`](../en/process.md) | Process model, thread states, scheduler, security tokens |
| [`docs/en/filesystem.md`](../en/filesystem.md) | VFS layer, SimpleFS on-disk format, two-phase commit |
| [`docs/en/network.md`](../en/network.md) | Network stack, DHCP, TCP/UDP, DNS |
| [`docs/en/syscall.md`](../en/syscall.md) | Syscall dispatch table, ABI catalog |
| [`docs/en/shared-user-runtime.md`](../en/shared-user-runtime.md) | Shared ABI types and syscall wrappers (module `src/user/shared/`) |

### Kernel Developer Reference (`docs/kernel/`)

| Document | Description |
|----------|-------------|
| [`docs/kernel/boot.md`](../kernel/boot.md) | Arch-specific entries, PS/2 probe, filesystem init, file map |
| [`docs/kernel/memory.md`](../kernel/memory.md) | Frame allocator internals, TLSF layout, page table ops, swap |
| [`docs/kernel/process.md`](../kernel/process.md) | Scheduler core types, thread lifecycle, process groups, signals |
| [`docs/kernel/filesystem.md`](../kernel/filesystem.md) | VFS trait methods, filesystem driver table, file I/O internals |
| [`docs/kernel/network.md`](../kernel/network.md) | **Layered architecture, protocol files, sockopts, poll readiness** |
| [`docs/kernel/syscall.md`](../kernel/syscall.md) | `SyscallNumber` enum, `SYSCALL_REGISTRY`, pointer specs |
| [`docs/en/shared-user-runtime.md`](../en/shared-user-runtime.md) | Syscall wrapper conventions, dispatch internals, module map |
