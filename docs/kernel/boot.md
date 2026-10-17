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

The Multiboot2 header asks for a framebuffer — header tag 5, geometry
1024x768x32, flags 0 so a firmware with no graphics mode still boots.  The
request is load-bearing rather than declarative: GRUB's multiboot2 loader
only calls `set_console(FRAMEBUFFER)` (and so `set_video_mode`) when the
kernel's header carries that tag, and without it it keeps the machine in EGA
text and hands over a text framebuffer tag — measured, both before the tag
existed (`kind 2 at 16 bpp`) and after (`console installed from the loader's
framebuffer (1024x768x32)`), which is why `install_loader_framebuffer` had
never run and the ISO gate asserts the line now.  A machine whose firmware
and GPU this kernel has no driver for is exactly the machine that path
exists for.

The requested geometry is what the loader is asked *for*, not what it must
give: a firmware with no 32-bit mode sets whatever it has, and
`install_loader_framebuffer` takes the tag's own depth — 24 or 32 bits — as
what the console must draw in.  A 24-bit surface is one pixel every three
bytes, which is why the console's stride is the depth's and not a fixed word
(`pixel_writes_stay_within_a_24_bit_row` holds that; the boot here always
receives 32, so the 24-bit path is the loader's to exercise on a machine
whose firmware offers it).

`_start` runs in 32-bit protected mode.  It saves the loader's magic and info
pointer, stands up a boot stack, builds a four-level identity map of the first
four gigabytes with 2 MiB pages, and turns long mode on (`CR4.PAE`,
`IA32_EFER.LME` and `.NXE`, then `CR0.PG`).  It then reloads the segment
registers from the 64-bit GDT and calls `kernel_entry(multiboot_magic,
multiboot_info)`.

The window is four gigabytes — `BOOTSTRAP_IDENTITY_MAP_LENGTH`,
`src/arch/x86_64/paging/types.rs`, and the same count in the assembly — because
of where a machine puts its own description: the boot reads ACPI (RSDP, RSDT,
then MADT/SRAT/SLIT) before the runtime page tables exist, and on RAM above
1 GiB the firmware places those tables above the first gigabyte (measured on
`q35`: the RSDT is at `0x3ffe2351` with 1 GiB and `0x7ffe2351` with 2 GiB).  A
one-gigabyte window faulted on the first RSDT entry of such a machine.  The
runtime tables are a different, narrower thing — the static ones name the
kernel's own memory below 1 GiB (`KERNEL_IDENTITY_MEMORY_END`, same file) and
everything above is mapped on demand (`map_device_mmio`, `apic.rs`'s
LAPIC/IOAPIC pages) — which is why the two bounds are separate constants
rather than one.

### AArch64

`src/arch/aarch64/boot.S` runs at EL1.  Every PE reads its own `MPIDR_EL1`
affinity: the boot CPU takes the branch that hands control to Rust, and the
others index a spin table (`aarch64_spin_table`, one entry per core holding a
stack top and an entry address) and wait on `wfe` until the boot CPU fills
their slot — that table is how PSCI-less bring-up and the kernel's own SMP path
meet.

The boot CPU sets its stack, **parks the device tree**, clears BSS, and calls
`kernel_entry_aarch64(parked_blob)`.  The parking is not tidiness: QEMU places
the blob just past the loaded image, which on this machine is inside the frame
pool's reserved span (measured at 0x48000000, pool
`[0x45800000, 0x75800000)`) — memory the allocator hands out and zeroes, and
before the pool became a reserved span it was the `.bss` array the boot
cleared, which wiped the blob on the Image path before Rust could read it.
The linker script reserves `.dtb_copy` for the copy, and the address Rust is
handed is the copy.

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

**Only a Multiboot2 block is one.**  The PC's two hand-offs arrive through the
same entry symbol, and their blocks are not the same thing: GRUB leaves the
Multiboot2 magic and a tag block, while a direct QEMU boot leaves a pointer to
Xen's `hvm_start_info`, whose fields are not tags.  The magic decides, and a boot
whose magic is not Multiboot2 records **no** hand-off address — so every reader
of a tag (the memory map, the command line, the framebuffer, ACPI's RSDP
lookup) answers "there is none" rather than reading a struct that merely looks
like one.  A framebuffer read out of the wrong block is a range mapped and
drawn on that was never a display.

The PVH block is not *nothing*, though, and it goes in a slot of its own
(`store_pvh_start_info`): from `hvm_start_info` version 1 it carries
`memmap_paddr`/`memmap_entries`, an E820-shaped table of the machine's memory
that `pvh_memory_regions` walks with its magic checked first.  So every PC
boot answers "how much RAM" — the tag block under a loader, the block's table
under QEMU — and only a hand-off with neither is the no-map boot the report
still names.

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
- **x86_64** composes the message and writes it into the device's MSI-X table
  through the same claim-and-arm path (`arch/x86_64/msi.rs`), with fixed
  vector numbers out of an IDT window whose stubs dispatch by vector.  A claim
  that fails leaves its owner polling, which is the path it would have taken
  on a machine with no MSI-X at all.

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

- **From the platform**: interrupt controllers, the console, the timer's
  frequency, the PCIe ECAM window and the memory window a bridge describes
  (`src/arch/fdt.rs`, `src/arch/fdt/parse.rs`, `src/arch/platform.rs`), and on
  the PC whichever memory map the hand-off carries — a Multiboot2 tag block
  under a loader, the PVH block's own E820-shaped table under a direct
  `-kernel` boot (`src/arch/boot.rs`).
- **Not from the platform**: where the frame pool *is* — a reserved span of
  the kernel's own address space that the linker places
  (`src/memory/frame.rs`) — and a machine that describes no controller gets
  the `virt` layout's constants as a fallback (`src/arch/aarch64/mod.rs`),
  which the boot now **names in its log** rather than applying silently: a
  silent fall to the `virt` address is indistinguishable from a described one
  when the two are the same address (they are on that machine), which hid a
  parse defect the runtime gate now refuses
  (`[irq   ] interrupt controller from the device tree at ...`).  What the
  pool is *sized* from is the machine's answer, which is why the
  memory map is on the list above; the span is a ceiling that a small machine
  takes only the part of.  A board port is where the span itself becomes a
  decision, and the boot log prints the pool's base and how much of its span
  the machine has.
- **The command line arrives three ways**, one per hand-off: a Multiboot2 tag
  under a loader, the PVH block's own `cmdline_paddr` on a direct PC `-kernel`
  boot, and a device tree's `/chosen` `bootargs` on the two device-tree
  machines (which QEMU fills from `-append`).  The capture is one piece of
  architecture-neutral code — it used to live inside the x86_64 block, so
  `init=` and every other option were silently absent on aarch64 and riscv64.
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

- [interrupts.md](interrupts.md) — the controllers the pipeline starts, and the
  message path it programs
- [../fmts/syscall-abi.md](../fmts/syscall-abi.md) — the contract the first
  ring-3 program is the first caller of
- [syscalls.md](syscalls.md) — the trap the first program enters through
