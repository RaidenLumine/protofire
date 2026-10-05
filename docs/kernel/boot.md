# Boot and Bring-Up

From the bootloader's hand-off to the idle loop: the assembly stubs that hand
control to Rust, the architecture-independent entry, the subsystem pipeline,
and how the other CPUs join.

The exact order inside the pipeline is `Kernel::init` in `src/kernel/mod.rs` —
one function, one order, read it there.  This document is about the shape of
bring-up and the invariants that order exists to keep.

## The hand-off

### x86_64

`src/arch/x86_64/boot.asm` carries two headers so the ELF can be started either
way: a Multiboot2 header (GRUB, and anything else that speaks the protocol) and
a Xen ELF note of type 18, `XEN_ELFNOTE_PHYS32_ENTRY` — that note is what lets
QEMU boot this kernel directly with `-kernel` through the PVH protocol.

`_start` runs in 32-bit protected mode.  It saves the loader's magic and info
pointer, stands up a boot stack, builds a four-level identity map of low memory
with 2 MiB pages, and turns long mode on (`CR4.PAE`, `IA32_EFER.LME` and `.NXE`,
then `CR0.PG`).  It then reloads the segment registers from the 64-bit GDT and
calls `kernel_entry(multiboot_magic, multiboot_info)`.

### AArch64

`src/arch/aarch64/boot.S` runs at EL1.  Every PE reads its own `MPIDR_EL1`
affinity: the boot CPU takes the branch that hands control to Rust, and the
others index a spin table (`aarch64_spin_table`, one entry per core holding a
stack top and an entry address) and wait on `wfe` until the boot CPU fills
their slot — that table is how PSCI-less bring-up and the kernel's own SMP path
meet.

The boot CPU sets its stack, **parks the device tree**, clears BSS, and calls
`kernel_entry_aarch64(parked_blob)`.  The parking is not tidiness: the blob QEMU
supplies is placed inside the kernel's own BSS, where the frame pool lives, so
clearing BSS would erase the blob before Rust could read it.  The
linker script reserves `.dtb_copy` for the copy, and the address Rust is handed
is the copy.

The blob exists only because the kernel is booted as an arm64 `Image`: QEMU
installs a device tree for the Linux boot path.  A bare-metal ELF gets `x0 = 0`
and no blob, which the platform layer treats as "the machine described
nothing" — see Platform assumptions below.

### RISC-V 64

`src/arch/riscv64/boot.S` arrives in S-mode with OpenSBI having already stopped
the secondary harts, so only hart 0 runs.  `a0` carries the boot hart's id —
`mhartid` is not readable from S-mode, so the platform's answer is the only
one — and `a1` the device tree; both are moved into callee-saved registers
before anything clobbers them.  `tp` is zeroed so the per-CPU accessor uses its
early fallback until real per-CPU data exists.  The stub then sets the boot
stack, clears BSS, and calls `kernel_entry_riscv64(device_tree_blob)`.

## Boot information

Each entry point builds the same `BootInfo` (`src/arch/boot.rs`): the
architecture, the protocol the machine used (`Multiboot2` or `QemuDirect`), the
loader's magic, and the hand-off address.  The hand-off address is stored where
later stages can find it — ACPI table access and AP bring-up both need a
pointer the bootloader chose.

## The Rust entry

`src/arch/entry.rs` holds the three `kernel_entry*` functions and the one
`boot_kernel` they converge on:

- `util::debug::init()` — and this is where the architecture's `init_early`
  runs.  The console has to exist before anything can be said, including about
  a boot that stops: each architecture implements `Arch::init_early`
  (`src/arch/<machine>/mod.rs`) to bring up whatever the console needs, from
  the board's UART to the trap vectors that would otherwise turn the first
  fault into a silent hang.
- The banner, and then five announced stages — `Bootloader`, `Console`,
  `KernelObject`, `KernelInit`, `Scheduler`.  They are announced rather than
  inferred from timing, so a boot that stops has already said where.
- `Kernel::new()`, `Kernel::init()`, `Kernel::run()`.  The last never returns:
  from there the machine is running threads, and the boot is `Kernel::init`'s
  aftermath.

## The init pipeline

`Kernel::init` is a sequence of calls with no scheduler running yet, so the
order is the only thing keeping the assumptions true.  The shapes it keeps:

- **Memory before anything that allocates.**  The frame allocator and the heap
  come up first, then the runtime kernel page tables replace the boot-time
  identity map (`prepare_arch_paging`, which asks the architecture to install
  them).  Everything after this point can allocate; nothing before it can.
- **The machine's own description next.**  ACPI on x86_64, the device tree on
  the other two: `capture_early_state` takes what the bootloader left, and
  `describe_platform` parses it.  Both live in `src/arch/platform.rs`, and the
  answers are what every later driver and controller reads.
- **The console before the subsystems that talk**, so a failure in one of them
  is reported rather than inferred from a hang.
- **Controllers before the devices that signal through them**, and the
  interrupt controller before the secondary CPUs that need it.  Device tables
  are programmed after the cores exist: a placement that names a core which
  cannot receive yet is a message that is dropped rather than queued.
- **The syscall table before anything ring 3 can call**, and the audit ring
  before the producers that write to it.
- **Spawning last.**  Init is the first user program, and the pipeline's job is
  to have everything it might ask for in place before it runs.

## Bringing up the other CPUs

Each platform starts its secondary CPUs its own way, and the three have the
same problem: a core is not up because it was started, but because it is
dispatchable.

| | Started by | Woken for work by |
|---|---|---|
| x86_64 | INIT-SIPI-SIPI, with a trampoline copied to low memory (`src/arch/x86_64/ap_trampoline.asm`) | Local-APIC IPIs |
| AArch64 | `PSCI CPU_ON` to an entry point the kernel chooses | GIC SGIs |
| RISC-V 64 | `SBI HSM` | The per-hart software-interrupt register |

**A CPU is online when it registers its scheduler.**  That registration is what
writes the online set, and the set is the only answer the scheduler, the
shootdown log and `/proc` use.  Each architecture reports for itself: on x86_64
the boot CPU registers an AP once the trampoline's started flag says it is
running, and on AArch64 and RISC-V the AP runs the registration from its own
entry point — so a core that never reaches kernel code never claimed to be up.

**A core's timer is that core's to enable.**  AArch64's timer is a private
peripheral interrupt, and in GICv2 the registers that arm it are banked per
core: the boot CPU configuring its own copy does not arm the others, so the AP
path arms each core's own PPI (`timer::init_ap`).  x86_64 wires its clock the
other way — the PIT is routed to one LAPIC, so APs take no timer interrupt, and
the timeouts of sleeping threads are swept by whichever CPU is ticking
(`Scheduler::wake_expired_sleepers`).

## Device interrupts at bring-up

A device that signals by writing a message needs three things: a controller
that receives it, a table on the device saying where to write, and a driver
that owns the identities the table delivers.  Bring-up supplies the first
(`arch::interrupt_controller::init`), and the platform programs the second for
every claim a driver has already registered
(`arch::platform::program_device_msix`).  The claim itself is the driver's and
happens at probe time, because a registration is a table entry rather than a
hardware access.

The three architectures answer differently, and the difference is worth stating
because it decides which devices interrupt at all:

- **AArch64** routes a device's message through the GICv3 ITS, which translates
  it into an LPI; the kernel owns that translation.
- **RISC-V 64** writes the target hart's IMSIC identity into the device's
  MSI-X table; the kernel programs the table.
- **x86_64** has the message composition and fixed vector numbers, but no path
  programs a device's table.  A PCIe device's completions are polled there.

## Per-CPU data

Each CPU has a `PerCpuData` block (`src/kernel/percpu.rs`): its logical id, its
controller id, a pointer to its scheduler, the block backing kernel entry and
exit, and its NUMA node.  The offsets are part of a fast path, so they are
asserted rather than described — see the `offset_of!` checks in that file for
the layout, and the two accessors the architectures use to reach the block:
the GS base on x86_64, `TPIDR_EL1` on AArch64.

## The first program

The last thing `Kernel::init` does is start the first ring-3 program.  The path
is `DEFAULT_INIT_PATH` (`/system/init.elf`) unless the bootloader's command line
asks for another one with `init=`.  When that program is the distribution's
init, it reads `/system/rc.d/*.toml` and starts the services it declares; the
supervisor that owns those services will also start anything still pending when
the hand-off's deadline passes, which is the path that runs on a disk whose
init asks for nothing.

## Platform assumptions

The kernel is written to be told what the machine is, so the parts it takes
from the platform are worth naming next to the parts it does not ask for:

- **From the device tree or ACPI**: interrupt controllers, the console, the
  timer's frequency, the PCIe ECAM window and the memory window a bridge
  describes (`src/arch/fdt.rs`, `src/arch/fdt/parse.rs`, `src/arch/platform.rs`).
- **Not from the platform**: the frame pool is a fixed array inside the image
  (`src/memory/frame.rs`), and a machine that describes no controller gets the
  `virt` layout's constants as a fallback (`src/arch/aarch64/mod.rs`).  Both
  are the first things a real board would change, and the boot log prints which
  base it used, so a boot running on the fallbacks says so.
- **The entry contract is the bootloader's**: a Multiboot2 handshake, an arm64
  `Image` with the blob in `x0`, or OpenSBI's `a0`/`a1`.  A platform that hands
  over something else needs that contract written down first.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/arch/x86_64/boot.asm` | Multiboot2 and PVH headers, protected-mode and long-mode entry |
| `src/arch/x86_64/ap_trampoline.asm` | The real-mode-to-long-mode trampoline an AP starts through |
| `src/arch/aarch64/boot.S` | Spin table for secondary PEs, device-tree parking, BSS clear |
| `src/arch/riscv64/boot.S` | S-mode entry, hand-off registers, BSS clear |
| `src/arch/entry.rs` | The three `kernel_entry*` functions, `boot_kernel`, the announced stages |
| `src/arch/boot.rs` | `BootInfo` and the protocol-specific constructors |
| `src/kernel/mod.rs` | `Kernel::init` and the order everything appears in |
| `src/arch/platform.rs` | Early state, platform description, buses, MSI programming, secondary CPUs |
| `src/kernel/percpu.rs` | The per-CPU block every architecture shares |

## See also

- [../fmts/syscall-abi.md](../fmts/syscall-abi.md) — the contract the first
  ring-3 program is the first caller of
- [syscalls.md](syscalls.md) — the trap the first program enters through
