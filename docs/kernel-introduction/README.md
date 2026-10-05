# Kernel Architecture

## Design Philosophy

This is a from-scratch hobby OS kernel written in Rust, targeting x86_64, AArch64, and RISC-V 64. It runs entirely `no_std` (no libc, no standard library) on bare metal. The kernel is **monolithic** -- all core subsystems (memory management, filesystem, scheduler, drivers, network stack, syscall dispatch) run in a single privileged address space with no microkernel IPC boundaries.

Key design goals:
- **Rust safety where possible**: the kernel uses `unsafe` only for MMIO, inline assembly, and pointer-level context-switch mechanics. Page table walks, filesystem operations, and network protocol parsing are safe Rust.
- **Single-address-space ELF loader**: ring-3 (user) programs are self-contained ELF files loaded into per-process page tables. No dynamic linking, no shared libraries -- each program is a standalone binary.
- **Preemptive round-robin**: the scheduler runs kernel and user threads round-robin. Timer interrupts advance a tick counter and drive time-slice preemption through `on_timer_tick_with_preemption`; a thread may also yield explicitly via `yield_current()` or block on I/O. FIFO threads are exempt from time-slice preemption.
- **File-oriented ABI**: the syscall interface is modelled on POSIX-like operations (open, read, write, close, ioctl, mmap, fork, exec, wait) over a flat dispatch table whose numbering is append-only and whose stable range is frozen. See [`../fmts/syscall-abi.md`](../fmts/syscall-abi.md) for the contract; the tree's own number→name table is the authority.
- **Minimal platform assumptions**: boot information is received via Multiboot2 (x86_64) or a flattened device tree FDT pointer (AArch64, RISC-V). PCI/ACPI table walks happen after early memory init.

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
       │   2. platform::describe()     ACPI / FDT / DTB         │
       │   3. prepare_arch_paging()    Switch to kernel page    │
       │                               tables                   │
       │   4. console::init_global()                            │
       │   5. drivers::init()          Probe VirtIO (block,     │
       │                               net, input, GPU)         │
       │   6. fs::init_with_boot_disk()  Build/mount boot VFS   │
       │   7. maybe_init_swap()        Disk-backed swap detect  │
       │   8. platform::enumerate_buses()  PCI/PCIe, all three  │
       │   9. network stack init       DHCP; SLAAC armed        │
       │  10. Volume recovery          Check-and-repair mounts  │
       │  11. user::init_user_database()                        │
       │  12. interrupt_controller::init()  APIC / GIC / PLIC   │
       │  13. timer::init()                                     │
       │  14. init_numa()              NUMA topology detection  │
       │  15. Per-CPU data + SMP AP bring-up (all three)        │
       │  16. syscall::Table::init()    Populate dispatch table │
       │  17. audit::init()             Ring buffer first       │
       │  18. spawn_init_program()     Load /system/init.elf    │
       │  19. spawn_system_programs()  (demo-disk feature)      │
       │  20. scheduler.start_idle_process()                    │
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
src/                                 (the crate root: peers under one roof)
    ├── kernel::Kernel               (boot phases, global install, procfs)
    │     ├── process::Scheduler     (preemptive round-robin, thread lifecycle)
    │     │     ├── process::Thread  (per-thread context, state machine)
    │     │     ├── process::Process (address space, fd table, security token)
    │     │     ├── process::wait    (WaitQueue, Event, Semaphore, Condvar)
    │     │     └── process::Context (arch register save area)
    │     ├── shm                    (shared memory regions)
    │     ├── topology               (NUMA topology, per-node allocators)
    │     ├── smp                    (SMP AP discovery and bring-up)
    │     ├── percpu                 (per-CPU scheduler/APIC data, numa_node_id)
    │     ├── sync                   (Mutex, SpinLock — the leaf layer)
    │     ├── ipc                    (anonymous pipes: a VNode that blocks)
    │     ├── crypto                 (signing key verification)
    │     └── user                   (user database, program loader)
    ├── memory::MemoryManager        (TLSF heap, frame allocator, page tables)
    │     └── memory::paging         (arch-generic page table interface)
    ├── fs::FileSystem               (VFS + SimpleFS)
    │     └── fs::simplefs           (on-disk layout, two-phase commit)
    ├── drivers::DriverManager       (VirtIO block/net/input/gpu, PCI probe)
    │     └── device                 (console, keyboard, null, zero, serial)
    ├── syscall::Table               (numbered dispatch table; the ABI contract pins the numbering)
    │     ├── syscall::process_launch
    │     ├── syscall::process_management
    │     ├── syscall::fs
    │     ├── syscall::net
    │     └── syscall::ipc
    ├── network                      (TCP/UDP/DHCP/DNS, raw sockets)
    ├── arch                         (per-target dispatch layer)
    ├── abi                          (syscall ABI constants)
    ├── util                         (logging, formatting)
    └── user                         (Ring-3 payloads and the shared library)

arch                                 (per-target dispatch layer)
    ├── boot                         (BootInfo, multiboot/FDT parsing)
    ├── mmu                          (page table prepare/activate/check)
    ├── trap                         (exception vector setup)
    ├── interrupt_controller         (APIC, GICv2, PLIC)
    ├── timer                        (PIT/HPET, generic timer, SBI timer)
    ├── syscall_trap                 (syscall entry asm glue)
    └── {x86_64, aarch64, riscv64}   (per-arch: serial, context switch, paging)
```

`memory`, `fs`, `drivers`, `syscall`, and `network` are peers of `kernel` at the
crate root, beside `arch`, `abi`, `util`, and `user`. They used to live under
`src/kernel/`; the move made the shape of the tree match the shape of the graph,
and it is why a path below reads `crate::fs::…` rather than `crate::kernel::fs::…`.

The `Kernel` struct in `src/kernel/mod.rs` still owns the top-level subsystems:

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

Physical memory is discovered via the Multiboot2 memory map (x86_64) or FDT `/memory` node (AArch64, RISC-V). The frame allocator (`memory::frame`) manages 4 KiB page frames as a bump pointer plus a `BTreeMap` of recycled free ranges, with a separate TLSF heap for the kernel's own allocations.

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
                       │   state]              │
0xFFFF_FFFF_FFFF_FFFF  └──────────────────────┘
```

On AArch64 and RISC-V the partitioning follows the same principle with arch-specific VA bit widths (48-bit or 39-bit).

### Kernel Stack and Guard Pages

Each kernel thread has a dedicated stack, and each stack has a guard page below it so that an overflow faults instead of writing over whatever comes next. On all three architectures the stack is a slice of that architecture's own stack window (`arch/aarch64/mmu/mod.rs`, `arch/x86_64/paging/runtime.rs`, `arch/riscv64/mmu/mod.rs`): the usable pages are backed by frames and the guard is a slice the allocator never hands out. A stack the window cannot serve — there are no slices left, or no translation-table pages for it — is a run of frames at its own addresses and the guard is the page below it, cleared by that architecture's `unmap_page`. Both shapes are described in the memory overview under [Kernel Address Space](memory.md#kernel-address-space), and both apply to kernel threads and to user-thread kernel stacks.

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
| `run` | x86_64 demo shell on QEMU q35, interactive over `-serial stdio` (no window) |
| `run-aarch64` | AArch64 demo shell on QEMU virt, interactive over `-serial stdio` (no window) |
| `run-riscv64` | RISC-V demo shell on QEMU virt, interactive over `-serial stdio` (no window) |
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

The demo volumes are constructed in-kernel by `src/fs/demo/`; the launch chain follows the `/apps/current → /apps/catalog → /apps/packages` layout, resolved by `crate::user::program::launch_reference`.

Ring-3 ELF payload construction is handled in-kernel by `src/user/demo/` (`elf_builder`): the demo's programs are built into images there and written into the apps zone by `src/fs/demo/`, so they are real ring3 code without a toolchain.  The shell is one of them on all three targets (`shell_payload_x86_64`, `shell_payload_aarch64`, `shell_payload_riscv64` — one program, emitted per architecture by `shell_payload`), and it reads its commands from the console.  The init program the system zone carries works the same way (`init_payload_x86_64`, `init_payload_aarch64`, `init_payload_riscv64` — one program, emitted per architecture by `init_payload`): it names the files in `/system/rc.d`, asks the kernel to read them and start what they declare, and installs the package the data zone leaves staged in the download cache — running with the system token, because that is what the app zone's descriptor asks of a program that installs into it.  No boot reaches a stand-in: the disk is the program, and the host-side runtime that stands in for a program whose image the disk does not carry (`src/user/program/demo_runtime.rs`) picks its entry by the program's own name.

### CI Verification Gates

The `scripts/verify.sh` script runs tiered checks:

- **P0**: format check + host/x86_64/AArch64 build checks + header coverage + documentation citations
- **P1**: P0 plus fast concurrency/path/I-O/ABI regression tests
- **P2** (default): P1 plus storage/recovery/fault-matrix regression tests
- **P3**: P2 plus clippy and optional AArch64 runtime smoke test (`make check-aarch64-runtime`)

---

## ABI Stability Policy

- **Syscall numbers are stable**. The dispatch table (`syscall::Table` in `src/syscall/table.rs`) names operations 0–192, every one of them with a handler, with 141–142 left reserved. New syscalls must use previously unassigned slots.
- **`src/user/shared/` is the ABI boundary**. This module defines the ABI record types (`FileStat`, `DirectoryEntryRecord`, `IoVec`, etc.) and syscall wrapper functions. Changes to its public types require coordination across all consumers.
- The kernel's own version lives in `Cargo.toml`, and it is not the ABI version: the syscall contract carries its own `SYSCALL_ABI_VERSION_MAJOR/MINOR`, reported to user space through `RuntimeAbiInfo`. Ring-3 ELFs are shipped with the demo disk and normally rebuilt together with the kernel; the frozen payloads are the exception, and they are what gives "we do not break userspace" something to break (`make check-abi-frozen-payload`).

---

## Key Architecture Decisions

### Monolithic Kernel with Preemptive Threading

The entire kernel runs in a single privilege level (ring 0 / EL1 / S-mode) with a single virtual address space. There is no separate "kernel server" process. Drivers, the filesystem, the network stack, and the syscall dispatcher are all linked into the same binary and call each other directly.

Thread scheduling is **preemptive**: the main loop calls `schedule()`,
blocking I/O paths and `yield_current()` give the CPU up explicitly, and the
timer tick can take the CPU away from a thread whose time slice has expired.
The interrupt-side path (`preempt_current_thread_from_interrupt`) saves the
thread's context, requeues it, and switches to the next one with interrupts
masked, so a nested IRQ cannot observe the old thread after it has been queued
as ready. FIFO threads are exempt from time-slice preemption.

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

All three targets bring up secondary CPUs. Each CPU has its own scheduler
instance tracked in the percpu-scheduler table, and the boot is only considered
up on a core that actually reaches kernel code.

- **x86_64** discovers APs via ACPI MADT during early boot (before the page
  table switch, while the identity map is still active), saves the boot CR3 for
  the AP trampoline, then releases the APs after per-CPU data initialization.
  See `src/kernel/smp/` and `src/arch/x86_64/ap_trampoline.asm`.
- **AArch64** uses PSCI CPU_ON and GIC SGIs for cross-core wakeups.
- **RISC-V** uses SBI HSM to start harts and a per-hart software-interrupt
  register for wakeups; the timer and PLIC context are per-hart.

Cross-core wakeups on RISC-V wait for the target hart's next tick, which is the
coarsest of the three and is recorded as a known limitation.

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

Every subsystem document ends with its own **Status and Gaps** section: what
the module does now and what it does not do yet. `current-status.md` is the
per-module census — one row per module, in the same shape — and it is the
document to update when a module's state changes. None of these documents
carries line counts, file counts, test counts, or completion percentages:
figures like those change with every commit, and the tree is the authority for
them.

### Subsystem Overviews (`docs/kernel-introduction/`)

| Document | Description |
|----------|-------------|
| [`README.md`](README.md) | Architecture overview, subsystem dependency graph, memory layout, build system |
| [`docs/kernel/boot.md`](../kernel/boot.md) | Hand-off, the init pipeline, SMP bring-up |
| [`memory.md`](memory.md) | Physical/virtual memory management, TLSF heap, page tables |
| [`process.md`](process.md) | Process model, thread states, scheduler, security tokens |
| [`filesystem.md`](filesystem.md) | VFS layer, SimpleFS on-disk format, two-phase commit |
| [`network.md`](network.md) | Network stack, DHCP, TCP/UDP, DNS |
| [`docs/kernel/syscalls.md`](../kernel/syscalls.md) | Syscall trap, dispatch table, pointer validation |
| [`shared-user-runtime.md`](shared-user-runtime.md) | Shared ABI types and syscall wrappers (module `src/user/shared/`) |
| [`current-status.md`](current-status.md) | Per-subsystem implementation status and known gaps |

### Contributor Specifications (`docs/fmts/`)

| Document | Description |
|----------|-------------|
| [`docs/fmts/README.md`](../fmts/README.md) | Index of the normative specifications, and how they are enforced |
| [`docs/fmts/code-style.md`](../fmts/code-style.md) | Formatting, naming, module layout, imports, error handling |
| [`docs/fmts/comments.md`](../fmts/comments.md) | File headers, module and item documentation, `// SAFETY:`, markers |
| [`docs/fmts/unsafe-and-safety.md`](../fmts/unsafe-and-safety.md) | `unsafe` discipline, MMIO, user-memory validation, panic policy |
| [`docs/fmts/testing.md`](../fmts/testing.md) | Test placement, registration, fault injection, fuzzing |
| [`docs/fmts/syscall-abi.md`](../fmts/syscall-abi.md) | `SyscallNumber` enum, `SYSCALL_REGISTRY`, pointer specs, wrappers |
