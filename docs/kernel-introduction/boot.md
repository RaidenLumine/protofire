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
QEMU virt ──> _start (EL1) ──> park DTB ──> BSS clear ──> kernel_entry_aarch64(dtb)
```

1. Reads `MPIDR_EL1` and extracts the low 8 bits (CPU affinity).
2. **Non-zero CPUs spin** in a `wfe` loop (spin-table pattern).  Only CPU 0
   (the BSP) proceeds.
3. BSP: sets SP to `__boot_stack_top`, then **parks the device tree** in the
   reserved `.dtb_copy` region before clearing BSS.  QEMU's blob sits at
   `0x48000000`, which is inside the kernel's own 512 MiB frame-pool BSS array,
   so clearing BSS would erase it before the kernel could read it.  The copy is
   clamped to the region's size and its address is what Rust is handed.
4. Clears BSS (`__bss_start` .. `__bss_end`), then calls
   `kernel_entry_aarch64(parked_device_tree)`.

The blob is only there because the kernel is booted as an arm64 `Image`: QEMU
installs a device tree for the Linux boot path and for nothing else, so a
bare-metal ELF gets `x0 = 0` and no blob in memory at all.  `make
build-aarch64-image` produces that Image; see
[§7.2](#72-qemu-direct-boot).

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
  ├── arch::platform::capture_early_state()       # what the machine said before the switch
  ├── arch::platform::describe_platform()         # ACPI / FDT / DTB
  ├── prepare_arch_paging()                       # Runtime kernel page tables
  ├── memory::arch::check_kernel_map_coverage()   # The tables describe what they claim
  ├── console::init_global()                      # Print infrastructure
  ├── self.drivers.init()                         # Device discovery (includes virtio-gpu);
  │                                               #   each binding is recorded for `/dev`
  ├── self.fs.lock().init_with_boot_disk()        # Zone mounts; the system zone is the
  │                                               #   newest committed slot of its pair
  ├── maybe_init_swap()                           # Probe block devices for swap signature
  ├── arch::platform::enumerate_buses()           # PCI/PCIe, all three architectures
  ├── Network stack init                          # DHCP, IPv4; SLAAC armed, tick-driven
  ├── fs global + block-device publisher + /proc mount
  ├── Volume and install recovery                 # check_and_repair_volume()
  ├── user::init_user_database()
  ├── arch::interrupt_controller::init()          # APIC / GIC / PLIC init
  ├── arch::platform::program_device_msix()       # The half of an MSI claim a controller can check
  ├── arch::timer::init()                         # Timer interrupt
  ├── self.init_numa()                            # NUMA topology detection
  ├── arch::percpu::install_bsp()                 # This CPU's per-CPU block
  ├── arch::platform::bring_up_secondary_cpus()   # AP bring-up, per architecture
  ├── power::init()                               # CPU frequency scaling
  ├── self.syscall_table.init()                   # Syscall dispatch table
  ├── audit::init()                               # Audit ring buffer, before any producer
  ├── spawn_init_program()                        # /system/init.elf
  ├── spawn_system_programs()                     # /system/rc.d/*.toml
  ├── maintenance thread, plus the churn run when that feature is on
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

### 4.3 SMP AP Discovery and Bring-Up

All three targets start their secondary CPUs; each does it the way its platform
describes.

**Discovery.** On x86_64 (`src/arch/x86_64/acpi.rs`), the ACPI MADT is parsed
via the Multiboot2 RSDP tag to enumerate LAPIC IDs: the BSP records its own LAPIC
ID and the discovered AP IDs are stored as "early APs". AArch64 discovers its
secondary cores through PSCI, and RISC-V through its device tree's CPU nodes and
SBI HSM.

**Bring-up.** On x86_64 (`src/kernel/smp/bringup.rs` and
`src/arch/x86_64/ap_trampoline.asm`):

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

On AArch64, `PSCI CPU_ON` starts a core at an entry point the kernel chooses,
and cross-core wakeups use GIC SGIs. On RISC-V, `SBI HSM` starts a hart and the
kernel uses the per-hart software-interrupt register for wakeups; the timer and
PLIC context are per-hart, and a cross-hart wake waits for the target's next
tick.

**A core counts as online when it registers its scheduler**
(`register_percpu_scheduler`), which is the moment the kernel can dispatch a
thread on it and the only thing that writes the online-CPU set the scheduler,
the shootdown log and `/proc` read (`smp::online_cpu_count`).  Each
architecture reports for itself: x86_64's boot CPU registers an AP once its
`ap_started_flag` is set, and aarch64's AP registers itself from its own entry
point, so a core that never reaches kernel code never claimed to be up.

**A CPU's timer is that CPU's to enable.**  The aarch64 physical timer is a
private peripheral interrupt, and in GICv2 the registers that arm it
(`IGROUPR0`, `IPRIORITYR0-7`, `ISENABLER0`) are banked per core — the boot
CPU's `timer::init()` configures its own copy only, so `timer::init_ap()` arms
the core's own PPI as well as its countdown.  x86_64 wires its clock the other
way: the PIT is routed to LAPIC 0, so APs take no timer interrupt at all, and
the timeouts of a sleeping thread are swept by whichever CPU is ticking (see
`Scheduler::wake_expired_sleepers`).

### 4.4 Per-CPU Data

`struct PerCpuData` (`src/kernel/percpu.rs`, 64-byte cache-line-aligned):

| Offset | Field | Description |
|---|---|---|
| 0 | `cpu_id: u32` | Logical CPU ID |
| 4 | `lapic_id: u8` | Local APIC ID (x86_64) |
| 8 | `scheduler: *mut Scheduler` | CPU scheduler pointer (GS fast-path) |
| 16 | `tss: *mut u8` | Task State Segment pointer |
| 24 | `context_switches: u64` | Saturation counter |
| 32 | `kernel_entries: u64` | Kernel entry/exit counter |
| 40 | `numa_node_id: u8` | NUMA node ID (0xFF = NUMA_NODE_NONE) |
| 41 | `_reserved: [u8; 23]` | Reserved |

On x86_64 the per-CPU data is accessed via the GS segment base
(IA32_GS_BASE MSR, `0xC0000101`).  The `scheduler` field is loaded with
`mov reg, gs:[8]` -- the offset is checked at compile time.

On AArch64, `TPIDR_EL1` serves the same role.

### 4.5 Device interrupts: MSI where the machine has it

A device that signals by writing a message rather than by pulling a wire needs
three things: a controller that receives the message, a table on the device
that says where to write, and a driver that owns the identities the table
delivers.  The pipeline has the first as `arch::interrupt_controller::init()`
and the second as `arch::platform::program_device_msix()`; the third is the
driver's, claimed at probe time.

The three targets answer differently:

- **x86_64** delivers MSI and MSI-X through the local APIC.  Vectors are
  allocated from the kernel's pool and the device's table is programmed to
  write them (`src/arch/x86_64/msi.rs`).
- **RISC-V 64** delivers them through the AIA IMSIC.  The identities in a
  device's MSI-X table are allocated by the controller and claimed by the
  driver that owns the device before the function is unmasked, so a delivered
  message is attributed rather than counted spurious; the `aia=aplic-imsic`
  machine is the boot that covers this path.
- **AArch64 delivers them through the GICv3 ITS.** `src/arch/aarch64/mod.rs`
  reads `GICD_PIDR2` and picks the driver that matches: GICv2, or the GICv3 in
  `src/arch/aarch64/gicv3.rs` — the distributor, the per-PE redistributors, the
  `ICC_*` CPU interface, and the LPI tables a redistributor reads.  The message
  itself is translated by the ITS in `src/arch/aarch64/its.rs`: the kernel
  hands it a device table, a command queue and a translation table per device,
  maps the device's EventIDs to LPIs, and writes the same identities into the
  device's MSI-X table.  A device write then becomes an interrupt with no
  software in between.

  The limits are deliberate and written where they are implemented: every
  collection points at the boot CPU, so every MSI arrives there, and a device
  whose interconnect cannot carry a requester ID would need a window of its own
  in front of the ITS.  On a GICv2 machine there is no ITS to program, so the
  claim is refused, the table is never written, and the AArch64 runtime check's
  first boot — the GICv2 one — is the boot that still proves the polling path.

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

### 5.3 `spawn_init_program()`

```
spawn_init_program(init_path)
  ├── fs.lock()
  ├── program::load_from_filesystem(&fs, "/", init_path)
  │     └── Parses ELF, loads segments into a new address space
  ├── program::launch_loaded_program_with_security_token(
  │       &scheduler, loaded, SecurityToken::system(), start_suspended=false)
  └── Logs PID on success, or error on failure
```

`SecurityToken::system()` gives the init process the system token: it is the
distribution's own first program, loaded from the read-only system zone that no
runtime write can reach, and bringing the machine up — naming the declarations,
starting the services, installing the packages the disk staged — is the job it
exists for.  The init program is never started suspended.

If the ELF is missing (no boot disk, or distribution not installed), the
kernel prints a diagnostic and continues -- the system runs with only
kernel worker threads and the idle process.

On the demo disk that ELF is a program rather than a stub: the init payload
(`src/user/demo/init_payload.rs`, emitted per machine) lists `/system/rc.d`,
names each declaration file to the kernel through `service_declare`, and asks
for the services to be started through `service_start_all`.  It names the files
rather than handing over their text: the kernel reads them itself, so what it
registers is the read-only image's bytes and every service can be attributed to
the file that declared it (§5.4).  It reports what it did on the console, which
is what lets each target's runtime check assert that the file the kernel
spawned did something.  Whether it was launched is also what §5.4 asks before
starting the declared services: with a program on the disk the boot leaves the
start to it, and without one it starts them itself.  Declaring is idempotent
from the program's side, and a declaration never resets a service that has
already run, so a re-declaration updates what the service *is* without losing
what it *did*.

### 5.4 `spawn_system_programs()`

Service definitions are loaded from TOML files in `/system/rc.d/` via
`service::load_services_from_fs()`.

Both readers — the boot's walk of that directory and `service_declare` — go
through `service::read_declaration_file()`, so every definition carries the file
it was read from and the SHA-256 of that file's bytes (`ServiceOrigin`).  A
program can only name a file *inside* `/system` for the kernel to read, which is
what makes the origin worth recording: a declaration decides what runs and as
whom, and the bytes behind it are the READ-ONLY image's rather than anything a
caller assembled.  The path also has to be a *path*: every component is checked
against its directory's own listing — directories down to the file, and the file
a regular file — because the filesystem resolves through symlinks, and a link
shipped in the image could otherwise have the kernel read a declaration out of a
writable zone while the record said `/system`.  `/service/<name>/origin`,
`/service/<name>/sha256` and the `describe` rendering report the two facts, so
the attribution is visible from user space.

The demo disk ships `/system/rc.d/defaults.toml`, written by the demo-disk
builder from the same list the kernel falls back to when a disk declares
nothing (`service::default_definitions()`).  One list, two renderings: the
stock boot reads the declarations off the disk — the boot log says how many it
found — and a disk without the directory runs the same services from the
kernel's copy rather than a different set that has drifted from the shipped
one.

Who starts them depends on whether the disk ships an init program (see §5.3).
When it does, the boot **registers** the declarations and stops there: starting
them is the distribution's job, and `service_start_all` is how it asks.
Registering is still the kernel's half, so `/service` and the supervisor see
every service either way.  The wait has a deadline — five seconds — so a disk
whose init never asks is not a way to boot with no services at all: the
supervisor starts whatever is still pending when it passes, and the boot log
says how many.  A disk with no init program at all takes the older path and is
started by the boot directly.  The fallback has a boot of its own —
`make check-x8664-init-no-start`, whose disk carries an init program that reads
the declarations and asks for nothing — so it is exercised rather than merely
reasoned about.

Each `ServiceDefinition` has a `kind`:

- `ServiceKind::KernelThread` -- a kernel worker thread started by
  resolving the entry name in the `WORKER_REGISTRY` table.
- `ServiceKind::UserProgram` -- an ELF binary loaded from a path and
  spawned as a user process.

Each definition may also declare `security`, which selects the token the user
program runs under and is the only input to that choice:

| Declaration | Account needed | Token | Effect |
|---|---|---|---|
| `"guest"` (default) | no | `SecurityToken::guest()` | uid 1000, Medium integrity |
| `"admin"` | yes | provisioned as the account | that uid, High integrity, elevated |
| `"system"` | yes | provisioned as the account | that uid, System integrity, the kernel's MAC subject |

A privileged level names an account with `account = "<name>"`, defaulting to
`root`, and the name has to resolve in the user database before the service may
run: a service that asked for `admin` and did not get it refuses to start
rather than running as a guest, because the two are indistinguishable from
`/service` afterwards.  Both the grant and the refusal are audited.

#### Declared start order

A definition may also declare `after = ["other", …]`, naming services it must
be started after.  `service::plan_start_order()` turns the declarations into
the order the boot path follows and a list of services that have no place in
it.  The order is a function of the declarations alone — a service with nothing
to wait for keeps the position its declaration had — so two boots of the same
`/system/rc.d` start the same things in the same order, and a test can pin it.
That is also why a system that declares no order at all starts exactly as it
did before the order was computed.

`after` is ordering, not a promise about what the other service *achieves*: a
daemon that binds a port is not "done" when it has been spawned, and a manager
that waited for one would wait forever.  What the declaration buys is
attribution.  A service whose prerequisite is not declared, or is itself
blocked, or is part of a cycle, is not started at all: it is recorded as
`blocked` in `/service` with the reason in `last_error`, and the reason names
the service that could not start rather than leaving the reader to guess.  A
cycle is reported whole (`dependency cycle: a -> b -> a`), so one misconfigured
file reads as one error instead of several unrelated failures.

Every declaration is registered before any of them runs, so a blocked service
appears in `/service` next to the ones that started — `state` reads `blocked`,
and `describe` lists both its `After` line and the reason.

Neither token carries password authentication.  A service has nobody to ask, so
the kernel establishes the identity instead of proving it, and `authenticated`
stays clear — which is what keeps the discretionary-permission bypass a
password-derived token would have out of reach.  The trust boundary is the
config file's location: `/system/rc.d` is on a read-only zone, so only the
system image can raise a service's level.  A restart re-derives the token from
the stored definition rather than from anything the exiting process left behind.

Leaving the bypass out of reach is a policy, not an oversight.  No service
level gets it: not `admin`, which is elevated and may manage what root
owns — the system tree, the data zone's boundary directories, the syscalls
gated on admin mode — but cannot read another account's private files; and not
`system`, which carries the kernel's trust *level* but not its *identity*.  A
config file cannot ask a program to be the kernel.

The bypass has exactly two producers: the kernel's own threads, and a login
that verified a password.  A service that needs to reach across accounts is
asking for a capability neither level gives it, and widening a level is not the
way to add one.  Until such a capability exists, the two answers are the ones
already in the tree: state the access as a layout rule, so the path carries the
right owner and mode (this is how `/data/etc` is protected), or do the work in a
kernel thread, which is already the kernel.

`account` on a `security = "guest"` service is a config error rather than a
field to ignore: it reads like an escalation that silently did not happen.

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
| `make build` | `x86_64-unknown-none` | `target/x86_64-unknown-none/debug\|release/protofire` |
| `make build-aarch64` | `aarch64-unknown-none` | `target/aarch64-unknown-none/debug\|release/protofire` |
| `make build-aarch64-image` | `aarch64-unknown-none` | `target/aarch64-unknown-none/debug\|release/protofire.img` (bootable; plus the ELF) |
| `make build-riscv64` | `riscv64gc-unknown-none-elf` | `target/riscv64gc-unknown-none-elf/debug\|release/protofire` |

### 7.2 QEMU Direct Boot

The `make run` / `make run-aarch64` / `make run-riscv64` targets pass a kernel
image via QEMU's `-kernel` flag.  No bootloader is needed, but for aarch64 the
*format* of that image decides what the kernel can discover:

- x86_64 uses the ELF (Multiboot2 is not involved; QEMU jumps to the ELF
  entry).
- **aarch64 uses the arm64 `Image`**, the flat binary with the 64-byte header
  that QEMU recognises by its `ARM\x64` magic.  That is the Linux boot path,
  and it is the only one on which QEMU writes a device tree and hands its
  address over in `x0`.  Booted as a bare-metal ELF instead, the kernel gets
  `x0 = 0` and falls back to hardcoded `virt` constants for the GIC, the UART,
  the virtio-mmio window, the RTC and the CPU list — silently, which is what it
  did until the Image was produced.  `scripts/build-aarch64-image.sh` builds it;
  the header's `text_offset` parks the header 64 bytes before the kernel's link
  address so the code still runs where it was linked.
- riscv64 uses the ELF: OpenSBI hands the device tree over in `a1` regardless
  of the format, so `make run-riscv64` boots the ELF directly.

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

`make doctor` (via `scripts/doctor.sh`) reports the Rust toolchain, the three
pinned bare-metal targets and the optional `grub-mkrescue` / `xorriso` helpers.
It exits non-zero when a required tool or target is missing, so it doubles as
the environment check in CI.

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
              ├── audit::init()                    # Ring buffer, before any producer
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
| `src/memory/swap.rs` | `SWAP_MAGIC`, `probe_device()` for boot-time swap detection |
| `src/kernel/smp/` | AP discovery, bring-up, TLB shootdown |
| `src/kernel/percpu.rs` | `PerCpuData` layout (`cpu_id`, `lapic_id`, `numa_node_id`, etc.) |
| `src/kernel/service.rs` | Service definition loading from rc.d |
| `src/kernel/smp/bringup.rs` | AP trampoline data page layout, entry |
| `Makefile` | Build / run / check targets |

---

## Status and Gaps

The boot path is complete on all three targets: firmware handoff, FDT or
Multiboot2 parsing, the ordered kernel initialisation pipeline, and secondary
CPU bring-up. What is missing:

- **No bare-metal validation.** Every boot this document describes has been
  run under QEMU.
- **AArch64 delivers every MSI to one CPU.** The GICv3 machine brings up its
  redistributors, timer PPI, SGI delivery, LPIs and the ITS, and a PCIe
  device's message reaches its driver — but the ITS collection this kernel
  maps is the boot CPU's, so none of it is spread across cores (section 4.5).
- **RISC-V wakeups are the coarsest**: a cross-hart wake waits for the target
  hart's next tick, and the machine has no architectural NMI source.
- **The init program is a stub** that exits, so the boot's own service
  definitions are what start anything useful.

The per-module census lives in [current-status.md](current-status.md).

## See Also

- [Documentation index](README.md) — complete document tree
