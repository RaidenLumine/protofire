# Kernel Boot Flow

This document describes the cold-boot sequence of the kernel from
firmware/bootloader handoff through to the idle loop, covering all three
supported architectures (x86_64, AArch64, RISC-V 64) and the
architecture-independent initialisation in `src/kernel/mod.rs`.

---

## 1. Entry Vector (per-architecture assembly)

The Rust entry point is never called directly -- each architecture has its own
assembly stub that the bootloader/firmware jumps to.

### 1.1 x86_64 -- `src/arch/x86_64/boot.asm`

```
GRUB / PVH ──> _start (32-bit) ──> setup_page_tables ──> enable_long_mode ──> long_mode_start ──> kernel_entry()
```

1. **Multiboot2 header** at `.multiboot_header` (magic `0xE85250D6`, arch 0,
   checksum).  Also includes a **Xen ELF note** (type 18 = `XEN_ELFNOTE_PHYS32_ENTRY`)
   for QEMU `-kernel` direct boot via the PVH protocol.
2. `_start` (32-bit): saves EAX (magic) and EBX (info) to `multiboot_magic` /
   `multiboot_info` in BSS, sets up a 64 KiB boot stack (`boot_stack`).
3. `setup_page_tables`: builds a 4-level page table hierarchy:
   - `boot_pml4` points to `boot_pdpt`
   - `boot_pdpt` points to `boot_pd`
   - `boot_pd` identity-maps the first 1 GiB with 2 MiB huge pages (PS=1,
     RW+Present)
4. `enable_long_mode`: loads `boot_pml4` → CR3, sets PAE (CR4.PAE=5),
   enables **LME** (IA32_EFER.LME=8) and **NXE** (IA32_EFER.NXE=11), then
   sets PG (CR0.PG=31).
5. `long_mode_start` (64-bit): reloads segment registers with the 64-bit GDT
   (offset 0x08 for code, 0x10 for data), loads the 64-bit stack pointer,
   then calls `kernel_entry(multiboot_magic, multiboot_info)`.

### 1.2 AArch64 -- `src/arch/aarch64/boot.S`

```
QEMU virt ──> _start (EL1) ──> BSS clear ──> kernel_entry_aarch64(dtb)
```

1. Reads `MPIDR_EL1` and extracts the low 8 bits (CPU affinity).
2. **Non-zero CPUs spin** in a `wfe` loop (spin-table pattern).  Only CPU 0
   (the BSP) proceeds.
3. BSP: sets SP to `__boot_stack_top`, clears BSS (`__bss_start` .. `__bss_end`),
   then calls `kernel_entry_aarch64(device_tree_blob)`.
4. The DTB address arrives in x0 (QEMU convention) and is passed through
   unchanged.

### 1.3 RISC-V 64 -- `src/arch/riscv64/boot.S`

```
OpenSBI ──> _start (S-mode) ──> BSS clear ──> kernel_entry_riscv64(dtb)
```

1. Arrives in **S-mode** (Supervisor mode) with OpenSBI having already
   filtered secondary harts -- only hart 0 reaches `_start`.
2. Saves the FDT pointer (a1 from OpenSBI convention) to callee-saved `s0`.
3. Sets SP to `__boot_stack_top`, clears BSS, passes the FDT pointer in a0,
   then calls `kernel_entry_riscv64(device_tree_blob)`.

---

## 2. Boot Info Handoff -- `src/arch/boot.rs`

Each assembly entry calls a Rust function that packages the bootloader
parameters into a `BootInfo` struct:

```rust
pub struct BootInfo {
    architecture: &'static str,
    protocol:     BootProtocol,   // Multiboot2 | QemuDirect | Unknown
    loader_magic: u32,
    handoff_address: usize,
}
```

| Entry point | Constructor | Protocol |
|---|---|---|
| `kernel_entry` | `from_x86_64_multiboot2(magic, info)` | `Multiboot2` |
| `kernel_entry_aarch64` | `from_aarch64_qemu_direct(dtb)` | `QemuDirect` |
| `kernel_entry_riscv64` | `from_riscv64_qemu_direct(dtb)` | `QemuDirect` |

The handoff address is stashed via `store_handoff_address()` for late-boot
consumers (SMP AP bring-up, ACPI table access).

---

## 3. Architecture-Independent Boot -- `src/main.rs`

All three entry points converge into the same `boot_kernel()` function:

```
boot_kernel(BootInfo)
  ├── store_handoff_address()
  ├── util::debug::init()
  ├── arch::serial::init()           # aarch64 / riscv64 only
  ├── print_banner()
  ├── FDT parse (aarch64 / riscv64)  # arch::fdt::parse_fdt()
  ├── RTC init (aarch64 / riscv64)
  ├── Kernel::new()
  ├── Kernel::init()
  └── Kernel::run()                  # never returns
```

### 3.1 FDT Parsing (aarch64 / riscv64)

On architectures without a Multiboot2 protocol, the flattened device tree
(FDT) at the handoff address is parsed by `arch::fdt::parse_fdt()`.  The
resulting `PlatformInfo` stores discovered addresses for:

- UART (serial console)
- Interrupt controller (GIC)
- Timer
- VirtIO MMIO transport
- RTC (PL031 on AArch64, Goldfish on RISC-V)

If the DTB address in x0 is zero (AArch64 QEMU edge case), a RAM scan at
2 MiB intervals over the first 512 MiB searches for the FDT magic
(`0xd00dfeed`) as a fallback.

### 3.2 Architecture Early Init

After `boot_kernel()` returns, each architecture calls `Arch::init_early()`:

- **x86_64**: serial init, GDT/IDT setup, exception handlers.
- **AArch64**: `enable_fp_simd()` (sets CPACR_EL1.FPEN for EL0/EL1), trap
  vector table init, serial init.
- **RISC-V 64**: serial init, trap handler init.

---

## 4. Kernel Init -- `src/kernel/mod.rs`

`Kernel::init()` runs the full subsystem initialisation pipeline:

```
Kernel::init()
  ├── self.memory.init()                          # MMU + heap bootstrap
  ├── memory::install_global_unchecked()
  ├── SMP AP discovery (x86_64)                   # ACPI MADT -> LAPIC IDs
  ├── prepare_arch_paging()                       # Runtime kernel page tables
  ├── init_numa()                                 # NUMA topology detection
  ├── console::init_global()                      # Print infrastructure
  ├── self.drivers.init()                         # Device discovery (includes virtio-gpu)
  ├── self.fs.lock().init_with_boot_disk()        # Root filesystem mount
  ├── maybe_init_swap()                           # Probe block devices for swap signature
  ├── PCI enumeration (x86_64)                    # pci::pci_enumerate_buses()
  ├── Network stack init                          # DHCP / IPv4
  ├── Volume recovery                             # check_and_repair_volume()
  ├── user::init_user_database()
  ├── arch::interrupt_controller::init()          # PIC / GIC init
  ├── arch::timer::init()                         # Timer interrupt
  ├── Per-CPU data init (x86_64)                  # percpu::init_bsp()
  ├── SMP AP bring-up (x86_64)                    # smp::bring_up_aps()
  ├── self.syscall_table.init()                   # Syscall dispatch table
  ├── spawn_init_program()                        # /system/init.elf
  ├── spawn_system_programs()                     # /system/rc.d/*.toml
  └── self.scheduler.start_idle_process()
```

### 4.1 MMU Init and Heap

`self.memory.init()` initialises the `MemoryManager` which:

1. Detects total physical RAM from the Multiboot2 memory map (x86_64) or
   FDT `/memory` node (AArch64 / RISC-V).
2. Initialises a frame allocator over available physical frames.
3. Allocates the kernel heap within the kernel virtual address range.

### 4.2 Runtime Page Tables

`prepare_arch_paging()` (called per-architecture via cfg) builds and
activates a new set of kernel page tables via
`arch::mmu::prepare_runtime_kernel_page_tables()` followed by
`arch::mmu::activate_prepared_runtime_kernel_page_tables()`.

On x86_64, the boot CR3 is saved before this switch so the AP trampoline
can use the identity-mapped boot page tables during bring-up.  After
activation, a self-check (`active_runtime_kernel_page_table_check`)
verifies that RIP, RSP, and heap are all mapped with the expected
permissions.

### 4.3 SMP AP Discovery and Bring-Up (x86_64)

**Discovery** (`src/kernel/smp/discovery.rs`): Parses the ACPI MADT table
(via the Multiboot2 RSDP tag) to enumerate LAPIC IDs.  The BSP records
its own LAPIC ID, and discovered AP IDs are stored as "early APs".

**Bring-up** (`src/kernel/smp/bringup.rs`):

```
bring_up_aps(aps)
  ├── Copy trampoline (ap_trampoline_start..ap_trampoline_end) to 0x8000
  └── For each AP:
        ├── Allocate PerCpuData + TSS
        ├── Write trampoline data page at 0x9000:
        │     boot_cr3 | stack_top | entry_point | cpu_id | lapic_id
        │     percpu_base | ap_started_flag | runtime_cr3
        ├── Send INIT-SIPI-SIPI via LAPIC ICR
        └── Wait for ap_started_flag
```

The AP trampoline (`src/arch/x86_64/ap_trampoline.asm`) transitions the AP
from 16-bit real mode through protected mode to 64-bit long mode, switches
to the runtime CR3, and jumps to `ap_entry()` which sets GS base to the
per-CPU data, configures the local APIC, and enters the idle loop.

### 4.4 Per-CPU Data

`struct PerCpuData` (`src/kernel/percpu.rs`, 64-byte cache-line-aligned):

| Offset | Field | Description |
|---|---|---|
| 0 | `cpu_id: u32` | Logical CPU ID |
| 4 | `lapic_id: u8` | Local APIC ID |
| 5 | `numa_node_id: u8` | NUMA node ID (0xFF = NUMA_NODE_NONE) |
| 8 | `scheduler: *mut Scheduler` | CPU scheduler pointer (GS fast-path) |
| 16 | `tss: *mut u8` | Task State Segment pointer |
| 24 | `tlb_generation_seen: u64` | TLB invalidation generation |
| 32 | `context_switches: u64` | Saturation counter |

On x86_64 the per-CPU data is accessed via the GS segment base
(IA32_GS_BASE MSR, `0xC0000101`).  The `scheduler` field is loaded with
`mov reg, gs:[8]` -- the offset is checked at compile time.

On AArch64, `TPIDR_EL1` serves the same role.

---

## 5. Init Program Spawning

### 5.1 Command-Line Parsing

`arch::boot::multiboot2_command_line()` walks the Multiboot2 info tags
to extract the kernel command line.  `init_path_from_command_line()`
scans for `init=<path>` among whitespace-delimited tokens.

On aarch64 / riscv64 there is no Multiboot2 command line, so the default
path is always used.

### 5.2 Default Init Path

```rust
const DEFAULT_INIT_PATH: &str = "/system/init.elf";
```

### 5.3 `spawn_init_program()` (`src/kernel/mod.rs:547`)

```
spawn_init_program(init_path)
  ├── fs.lock()
  ├── program::load_from_filesystem(&fs, "/", init_path)
  │     └── Parses ELF, loads segments into a new address space
  ├── program::launch_loaded_program_with_security_token(
  │       &scheduler, loaded, SecurityToken::guest(), start_suspended=false)
  └── Logs PID on success, or error on failure
```

`SecurityToken::guest()` assigns the lowest privilege level, restricting
the init process to guest-scoped operations.  The init program is never
started suspended.

If the ELF is missing (no boot disk, or distribution not installed), the
kernel prints a diagnostic and continues -- the system runs with only
kernel worker threads and the idle process.

### 5.4 `spawn_system_programs()` (`src/kernel/mod.rs:415`)

Service definitions are loaded from TOML files in `/system/rc.d/` via
`service::load_services_from_fs()`.

Each `ServiceDefinition` has a `kind`:

- `ServiceKind::KernelThread` -- a kernel worker thread started by
  resolving the entry name in the `WORKER_REGISTRY` table.
- `ServiceKind::UserProgram` -- an ELF binary loaded from a path and
  spawned as a user process.

When no rc.d files are present (e.g. demo-disk configuration), an
embedded fallback spawns demo kernel workers (`kworker-a`, `kworker-b`,
`demo_syscall_fs_worker`) and user programs (shell, I/O demo, fault
demons) via `spawn_embedded_default_services()`.

---

## 6. Main Loop

After all init is complete, `Kernel::run()` enters the scheduler loop:

```rust
loop {
    self.scheduler.process_deferred_dying();
    arch::interrupts::disable();
    self.scheduler.schedule();
    arch::instructions::idle();
}
```

The idle process is started before entering this loop.  The scheduler
selects the next runnable thread and context-switches to it.  When no
threads are ready, the CPU executes the idle instruction (`hlt` / `wfi`)
with interrupts enabled via the architecture-specific `idle()` function.

---

## 7. Build Targets and ISO Creation

### 7.1 Kernel Builds

| Make target | Triple | ELF output |
|---|---|---|
| `make build` | `x86_64-unknown-none` | `target/x86_64-unknown-none/debug|release/protofire` |
| `make build-aarch64` | `aarch64-unknown-none` | `target/aarch64-unknown-none/debug|release/protofire` |
| `make build-riscv64` | `riscv64gc-unknown-none-elf` | `target/riscv64gc-unknown-none-elf/debug|release/protofire` |

### 7.2 QEMU Direct Boot

The `make run` / `make run-aarch64` / `make run-riscv64` targets pass the
ELF directly via QEMU's `-kernel` flag.  No bootloader image is needed.

- x86_64 uses `-machine q35` with `virtio-net-pci`.
- AArch64 uses `-machine virt` with `virtio-net-device`.
- RISC-V 64 uses `-machine virt` with `virtio-net-device`.

### 7.3 GRUB ISO (distribution-level)

ISO creation is a distribution-level target.  The kernel is packaged into a
GRUB-bootable ISO using `grub-mkrescue` (requires `xorriso`).  The GRUB
configuration passes `init=/system/init.elf` via the Multiboot2 command line.
The ISO boot flow is:

```
UEFI/BIOS ──> GRUB ──> Multiboot2 ──> _start ──> kernel_entry() ──> boot_kernel()
```

### 7.4 Toolchain Checks

`make doctor` (via `scripts/doctor.sh`) verifies that `grub-mkrescue` and
`xorriso` are present in addition to the Rust toolchain.

---

## Boot Sequence Diagram (x86_64)

```
Firmware
   │
   ▼
GRUB (Multiboot2)       or      QEMU -kernel (PVH ELF note)
   │                                  │
   └──────────┬───────────────────────┘
              │
              ▼
       _start (32-bit)
              │
              ├── save multiboot_magic / multiboot_info
              ├── setup_page_tables   (PML4 → PDPT → PD: 1 GiB ID map)
              ├── enable_long_mode    (PAE | LME | NXE | PG)
              │
              ▼
       long_mode_start (64-bit)
              │
              ├── reload GDT, set SS=0x10
              ├── load 64-bit RSP
              │
              ▼
       kernel_entry(magic, info)
              │
              ▼
       boot_kernel(BootInfo)
              │
              ├── arch::boot::store_handoff_address()
              ├── util::debug::init()
              ├── print_banner()
              │
              ▼
       Kernel::new() → Kernel::init()
              │
              ├── memory::init()                  # Frame allocator + heap
              ├── prepare_arch_paging()            # Runtime page tables
              ├── console::init_global()
              ├── drivers::init() + fs::init()
              ├── PCI enumeration
              ├── interrupt_controller::init()
              ├── timer::init()
              ├── percpu::init_bsp()               # GS base → PerCpuData
              ├── smp::bring_up_aps()              # INIT-SIPI-SIPI
              ├── syscall_table::init()
              ├── spawn_init_program("/system/init.elf")
              ├── spawn_system_programs()          # rc.d/*.toml
              │
              ▼
       Kernel::run()  ──>  schedule() ──> idle()
```

## Key Source Files

| File | Role |
|---|---|
| `src/main.rs` | Architecture-independent entry (`boot_kernel`) |
| `src/arch/boot.rs` | `BootInfo`, `BootProtocol`, command-line parsing |
| `src/arch/x86_64/boot.asm` | x86_64 Multiboot2 + long mode entry |
| `src/arch/aarch64/boot.S` | AArch64 spin-table EL1 entry |
| `src/arch/riscv64/boot.S` | RISC-V S-mode entry via OpenSBI |
| `src/arch/x86_64/ap_trampoline.asm` | AP 16→32→64-bit trampoline |
| `src/kernel/mod.rs` | `Kernel::init()` pipeline, `maybe_init_swap()` |
| `src/kernel/topology.rs` | NUMA topology detection |
| `src/kernel/memory/swap.rs` | `SWAP_MAGIC`, `probe_device()` for boot-time swap detection |
| `src/kernel/smp/` | AP discovery, bring-up, TLB shootdown |
| `src/kernel/percpu.rs` | `PerCpuData` layout (`cpu_id`, `lapic_id`, `numa_node_id`, etc.) |
| `src/kernel/service.rs` | Service definition loading from rc.d |
| `src/kernel/smp/bringup.rs` | AP trampoline data page layout, entry |
| `Makefile` | Build / run / check targets |

---

## See Also

- [Subsystem overview](../en/boot.md) — high-level boot flow description
- [Documentation index](../README.md) — complete document tree
