# Current Status

> **Last updated:** 2026-10-03
> **Targets:** x86_64 (full), AArch64 (full), RISC-V 64 (partial)

This document says what the kernel does today: the behaviour that exists, the
behaviour that is missing, and the parts that have only been exercised under
QEMU. It deliberately carries no line counts, file counts, test counts, or
completion percentages. Those figures change with every commit, and a number
that has to be maintained by hand is a number that will eventually be wrong —
the tree is the authority for how much code there is, and this document is the
authority for what that code does.

Two words are used strictly below:

- **implemented** means the code path exists and is reachable.
- **verified** means a gate boots it or a test pins it.

In the per-module tables, a dash in the *Missing* column means no gap is known
and recorded here — not that the module has none.

Where this document and the tree disagree, the tree is right and this document
is the bug. `make check-docs` enforces the part of that a machine can check:
every `src/…` or `tests/…` path named here has to exist, and a line-number
citation is refused outright because line numbers rot.

---

## Subsystem Status

Subsystems are described in the order they are brought up: drivers, I/O, the
filesystem, the scheduler, memory, interrupts, networking, IPC, security, and
the syscall interface.

### 1. Device Drivers

| Driver | Type | Now | Missing |
|--------|------|-----|---------|
| AHCI (SATA) | Block | Full read/write (DMA, polling) | Polling only, no interrupt path; x86_64 only; QEMU only |
| ATA (PIO) | Block | Full read/write | PIO only, no DMA; x86_64 only; QEMU only |
| VirtIO (block) | Block | Full read/write | QEMU only; no per-queue MSI-X claim |
| VirtIO (net) | Network | Full RX/TX, modern and legacy transports | MSI-X is claimed per device, not per queue; a transmit waits on the device's completion interrupt; no throughput baseline |
| VirtIO (GPU) | Display | 2D mode-setting (x86_64 PCI + AArch64/RISC-V device-tree MMIO) and the VIRGL 3D userspace interface (#181-189) | No userspace renderer is shipped against the interface; QEMU only |
| NVMe | Block | Full read/write, MSI-X interrupt, boot-disk probe | x86_64 only; QEMU only |
| xHCI | USB host | Controller bring-up and port status | Not end-to-end: USB storage and keyboard input are not usable yet |
| USB HID | HID (keyboard) | Report decoding and scancode injection | Not wired end-to-end until the xHCI path is complete |
| USB MSD | Storage | Bulk-only transport and SCSI command blocks | Not reachable end-to-end until the xHCI path is complete |
| Serial (UART 16550) | Text I/O | Full duplex | RISC-V falls back to the SBI console when it has no UART |
| PS/2 Keyboard | Input | Scancode buffering, decoding, console TTY bridge | The PS/2 interrupt path is x86_64; other targets rely on VirtIO input |
| Framebuffer | Display | Linear framebuffer the console draws on | No userspace graphics API beyond the VIRGL syscalls; QEMU only |
| Framebuffer Console | Display | Text rendering from a built-in 8×16 ASCII glyph table | Fixed font: characters outside the table draw as a fallback glyph, and there is no font or resolution management |
| HDA (Intel HD Audio) | Audio | CORB/RIRB, codec discovery, stream descriptors | No userspace stream interface, so audio is not usable from a program |
| PCIe ECAM | Bus | x86_64: full ECAM; AArch64/RISC-V: window found, BARs assigned, one driver attached, MSI-X through the machine's own controller | One driver on the device-tree machines; every other PCIe device still uses its architecture's own enumeration |

**Strengths:** driver coverage across storage, network, display, audio, and
input, mostly verified under QEMU.

- **Storage**: AHCI (SATA), ATA PIO, VirtIO, and NVMe provide independent block
  backends; NVMe uses MSI-X for interrupt-driven completion.
- **Network**: the VirtIO network driver is interrupt-driven and multi-queue
  ready.
- **Device ledger**: the thing that finds a device records it, where it finds
  it — a device-tree walk, a PCI scan, an MMIO window, or a driver's own
  `init()` — and the boot publishes the result into the ledger `/dev` reports:
  `driver`, `category`, `bus`, or all of them through `describe`.  The kernel's
  own devices (`console`, `null`, `serial0`, …) stay nodes a program can open,
  because they have handlers; a discovered device with no I/O interface yet is
  a directory of facts instead, so the difference between "served" and
  "described" is visible in the shape rather than only in the docs.
- **Display**: VirtIO GPU provides accelerated 2D mode-setting on the VirtIO
  MMIO transport, integrated directly with the framebuffer console (no separate
  bochs-display device); the **VIRGL 3D userspace interface** (syscalls
  #181-189) exposes the virtio-gpu VIRGL protocol to a userspace renderer —
  context create/destroy, 3D resources with kernel-managed DMA backing, host
  transfers, command submission, scanout — with actual 3D rendering executed
  host-side via virglrenderer.
- **Device-tree-driven driver probe**: `collect_dt_nodes` builds a node table
  (compatible/reg/interrupts/phandle/status) and
  `Driver::compatible_strings()`/`probe_dt()` bind nodes to drivers in
  `DriverManager::probe_dt_devices`; virtio-gpu/block/net are all probed from
  their DT node `reg`, making the GPU available on AArch64/RISC-V.
- **Audio**: the Intel HDA driver provides controller initialization, the
  CORB/RIRB engine, codec discovery, and stream descriptor configuration.
- **Hotplug, half-built**: the PCIe slot-status and hotplug-event reads exist
  (`arch::pci::pcie_read_slot_status`, `pcie_check_hotplug_event`) and the
  device manager has a removal path, but nothing polls either: no boot
  notices a slot change, and a removed device would stay in `/dev` until the
  next publish.

**Weaknesses:**

- **USB not end-to-end**: xHCI and USB HID are only "driver present"; USB
  storage and keyboard input are not fully usable yet.
- **HDA not surfaced to userspace**: audio has only the controller-level
  interface; there is no usable userspace stream interface yet.
- **One PCIe driver on the device-tree machines.** The ECAM walk finds devices,
  the kernel's own resource pass gives their memory BARs addresses out of the
  window the host bridge's `ranges` describes (no firmware ran one), and
  `drivers/virtio_net.rs` drives a `virtio-net-pci` through the modern (1.0)
  transport — that is the network device both gates boot with, DHCP and SLAAC
  included, while riscv64's default gate keeps the virtio-mmio path covered.
  On riscv64 the MSI-X table is programmed and *owned per device*: the driver
  claims the identities its device's table will deliver at probe time (a
  registration is a table entry, not a hardware access, so this works before
  the interrupt controller is up), the platform then programs the table with
  exactly those identities, reads it back, unmasks the function, and walks the
  receive side once through the driver's own handler so a delivered message is
  attributed rather than counted spurious. The identities themselves come from
  an allocator in the controller, so two devices cannot be handed the same ones
  and a second claimant is refused rather than silently replacing a handler
  somebody waits on. AArch64 reaches the same place by its own road: the GICv3
  controller (`src/arch/aarch64/gicv3.rs`) receives LPIs, and the ITS
  (`src/arch/aarch64/its.rs`) translates the messages that become them. What is
  still missing: MSI-X is claimed per device rather than per queue beyond the
  two the NIC uses; every LPI is delivered to the boot CPU, so a device's
  interrupt cannot be spread across cores; and every other PCIe device — NVMe,
  HDA — is still reached through its architecture's own enumeration rather
  than this one.
- **Verified under QEMU only**: no real-device validation on bare-metal
  hardware yet.

---

### 2. I/O Subsystem

| Component | Now | Missing |
|-----------|-----|---------|
| File descriptor table | Per-process table, dup/dup2/F_DUPFD, close-on-exec, inheritance across spawn | No descriptor passing between processes |
| Pipe | VFS-backed anonymous pipe, fcntl-resizable buffer, per-end O_NONBLOCK | No splice/tee; no named-pipe filesystem entry |
| Block cache | Fixed-size LRU, write-through for metadata and write-back for data, prefetch, dirty aging by the maintenance thread | Capacity is a fixed constant, so a large working set thrashes; no real-disk benchmark |
| Handle table | `KernelObject` + `HandleEntry { rights }` with a per-kind shape table, indexed by descriptor | Rights are only read and write, so a capability that needs anything finer has to be a syscall |
| Console I/O | One global console device, Ctrl-C handling, ring-3 reads through fd 0 | One console for the whole machine; no per-terminal isolation |

**Strengths:** complete file-descriptor and pipe semantics with runtime pipe and
block-cache management.

- **fd semantics**: inheritance across spawn, close-on-exec, and dup.
- **Pipes**: VFS-backed, using the same read/write path as regular files.
- **fcntl (#179)**: F_DUPFD / F_GETFD / F_SETFD / F_GETFL / F_SETFL, plus
  **F_GETPIPE_SZ / F_SETPIPE_SZ** — the pipe buffer can be resized at runtime
  (page-rounded, capped, buffered data preserved); a per-end **O_NONBLOCK**
  flag makes empty reads / full writes return EAGAIN instead of blocking.
- **Persistent block cache**: every dirty block is stamped with a cache-clock
  tick advanced by the scheduler; blocks dirty past the aging threshold are
  written back automatically by the maintenance thread, and **sync (#180)**
  provides the on-demand full flush (POSIX sync(2)) — write-back persists
  without an explicit fsync.

**Weaknesses:**

- **Small block cache**: a fixed-size LRU with limited hit rate under large
  working sets.
- **I/O paths verified under emulation only**: no latency/throughput testing on
  real disks or SSDs.

---

### 3. Virtual File System

The VFS is the largest subsystem in the tree. Its native filesystem, its
external drivers, its recovery machinery, and its Unicode layer are described
below.

#### 3.1 Native Filesystem

| Component | Now | Missing |
|-----------|-----|---------|
| SimpleFs core (V2/V3) | Full read/write, CRC32C-checked, two-phase commit, V3 persistent security descriptors | Recovery is exercised by the in-tree fault matrix rather than a searching fuzzer; no real-disk validation |
| TmpFs | In-memory, full read/write, xattrs | Contents do not survive a reboot |
| DevFs | The kernel's own devices as nodes, and every device a probe bound as a directory of facts (`driver`, `category`, `bus`) | Read-only; node metadata is the registry's, not the filesystem's; a discovered device has no I/O interface of its own yet |
| ProcFs | Process and runtime state as read-only files | Read-only view; process control stays in syscalls |
| Unicode layer | Unicode 15.1 NFC/NFD, case folding, GB18030, OEM code pages | Tables are fixed at Unicode 15.1; there is no locale database |

#### 3.2 External Filesystem Drivers

| Driver | Now | Missing |
|--------|-----|---------|
| ext4 | Read/write; journaling (revoke replay, v3 checksum tags), extent tree, dir index | Journal replay is verified on emulated images; not exercised against real corruption |
| F2FS | Read/write; checkpoint (SIT persistence), orphan recovery, atomic CP+SB write | Same emulation-only validation; no ageing or garbage-collection stress |
| XFS v5 | Read/write with journal replay; B+tree, CRC32C, v5 superblock | Same emulation-only validation; no xattr exposure |
| exFAT | Read/write; VFAT extension | No journal, so crash behaviour depends on the write order; QEMU only |
| FAT32 | Read/write; LFN, OEM code pages, FSInfo accounting | No journal; QEMU only |
| BtrFS | Read-only; B-tree traversal | Write support is the mid-term roadmap item |
| NTFS 3.1 | Read-only; MFT parsing, attribute resolution | Read-only; compressed and encrypted streams are not covered |
| SquashFS 4.0 | Read-only; several compression algorithms | Read-only |
| ISO 9660 | Read-only; Joliet, Rock Ridge | Read-only |
| EROFS v1 | Read-only; compact inode format | Read-only |

#### 3.3 VFS Layer

| Component | Now | Missing |
|-----------|-----|---------|
| VFS core (mount, path resolution, ops) | Full path resolution, mount and unmount, per-node operations | One mount table for the machine; no per-process mount namespace |
| Volume recovery | Transaction undo-log replay and check-and-repair at boot | Boot-time only, under the filesystem lock; no online repair |
| Fault injection matrix | Single- and dual-fault, multi-cycle crash testing | Deterministic and bounded, so it does not search for a failing sequence |
| Extended-attribute (xattr) table | SimpleFs V4 persistent storage and tmpfs in-memory; the four xattr syscalls | The VNode default is `Unsupported`, so the other filesystems do not expose xattrs |
| Transparent file compression | Per-file LZSS/raw chunked compression, reusing the memory codec | SimpleFs only; per-file toggle rather than a mount policy |
| Cross-file deduplication | Content-hash shared extents with mount-time refcount rebuild and CoW unsharing | SimpleFs only; no background scanner that finds new duplicates |
| Block backend abstraction | ATA, VirtIO and NVMe all implement one `BlockDevice` trait | No hot-remove or device-error recovery path |

**Strengths:** filesystem drivers for ext4, F2FS, XFS, exFAT, FAT32, BtrFS,
NTFS, SquashFS, ISO 9660, EROFS and the native SimpleFs; a crash-safe native
filesystem; and encryption at rest.

- **Multiple filesystems**: ext4, F2FS, and XFS support full journal replay from
  real disk; exFAT and FAT32 are read/write; btrfs/NTFS/SquashFS/ISO
  9660/EROFS are read-only.
- **Unicode 15.1**: full NFC/NFD normalization and a GB18030 codec.
- **Crash safety**: SimpleFs uses undo-log transactions and two-phase commit.
- **Encryption at rest**: EncryptedBlockDevice provides AES-256 XTS disk
  encryption, LUKS2-compatible headers, PBKDF2 key derivation, and layers
  transparently under any filesystem.
- **Read-only is structural**: the synthetic filesystems (`/proc`, `/service`)
  implement the VFS `ReadOnlyFileSystem` half, and one blanket impl supplies
  every mutation as `PermissionDenied` — a view cannot declare a mutation, so
  it cannot forget to refuse one.

**Weaknesses:**

- **Many read-only drivers**: btrfs, NTFS, SquashFS, ISO 9660, and EROFS are
  read-only; write support is a mid-term roadmap goal.
- **Journal replay verified on emulated disks**: coverage of real-corruption
  edge cases is limited.

**SimpleFs V4 data-reduction format** (inherits V3's persistent security
descriptors + `pending_commit` two-phase commit):

- **Extended attributes**: persist per-inode in active/shadow xattr-table slots
  flushed in the same two-phase commit as the inode/dirent tables — both
  SimpleFs and tmpfs support `setxattr`/`getxattr`/`listxattr`/`removexattr`
  semantics (syscalls #151-154).
- **Transparent per-file compression**: replaces a file's extent with a chunked
  encoded stream (each 4 KiB chunk encoded as zero/RLE/LZSS with a raw
  incompressible fallback), keeps `size` as the logical length, and decompresses
  only intersecting chunks on read; toggled via `SetFileFlags` (#155).
- **Cross-file deduplication**: merges identical-content files onto a single
  shared extent; refcounts are rebuilt at mount from the on-disk `DEDUPED`
  markers, overwrites/deletes unshare via copy-on-write, and an extent is freed
  only when its last reference goes away; both features are surfaced through
  `GetFileFlags` (#156).

#### 3.4 Encryption at Rest

| Component | Now | Missing |
|-----------|-----|---------|
| AES-256 + AES-XTS | Crypto engine in the kernel | No hardware acceleration path |
| PBKDF2 key derivation | Key stretching for disk encryption | One KDF; no Argon2 or keyring |
| EncryptedBlockDevice | Transparent block-device wrapper under any filesystem | No rekey or key rotation; one key per device |
| LUKS2 header parser | LUKS2 on-disk header parsing | Header only: no keyslot management or `cryptsetup`-style control surface |

---

### 4. CPU Scheduler

| Component | Now | Missing |
|-----------|-----|---------|
| Scheduler core | Preemptive round-robin with priority classes | Round-robin and FIFO only; no fair-share or deadline class |
| Thread lifecycle | Spawn, exit, terminate, detach | — |
| Context switch | x86_64, AArch64, RISC-V (per-arch assembly) | — |
| Process/thread types | States, priorities, credentials, scheduling policies | — |
| Job control | The shell tracks jobs and signals the foreground pid | No kernel process group: no `setpgid`-style call, so terminal ownership is not modelled |
| SMP discovery | x86_64: ACPI MADT; AArch64: PSCI; RISC-V: FDT CPU nodes and SBI HSM | — |
| Timer tick | Scheduler quantum management | On x86_64 the PIT is routed to one LAPIC, so APs take no timer interrupt; a sleeping thread's expiry is swept by whichever CPU ticks |
| Waker | Thread wakeup notification with a per-CPU reschedule flag | Cross-CPU wakeups set a flag or send an IPI; RISC-V waits for the target hart's next tick |
| Scheduler stats | Load average (sampled ring), per-thread CPU ticks, idle tracking, ProcFs integration | — |
| Priority boosting | Starvation boost: Normal → High after an idle threshold, demote after a short run | — |
| Work stealing | Cross-CPU load balancing, NUMA-aware victim selection | Validated under QEMU only; no real-load validation |
| Stack canary | Per-thread random canary, checked on context switch | Software check, not a hardware feature; it detects a smashed stack after the fact |
| Power management | CPU frequency scaling (x86_64 MSR P-state driver; aarch64/riscv64 DT OPP range discovery + target tracking), governors, scheduler-tick integration, DTS temperature reading | AArch64 and RISC-V only track the requested target; no SCMI or CPPC interface is wired |

**Strengths:** preemptive multi-threaded scheduling with NUMA-aware load
balancing and runtime stack protection.

- **Scheduling policies**: `SchedDefault` (round-robin), `SchedFifo`
  (run-to-completion), `SchedRoundRobin` (explicit RR); `START_SUSPENDED` flag
  and starvation protection via priority boosting.
- **Work stealing**: cross-CPU load balancing with NUMA-aware victim selection
  (higher score for same-node steals).
- **Kernel stack protection**: guard pages on all architectures; the
  `dying_thread` pattern prevents Arc leaks on context switch.
- **Per-thread stack canary**: a random 64-bit canary written to the kernel
  stack bottom at thread creation and verified on every context switch back to
  the scheduler.
- **A placement watchdog**: the scheduler periodically asks the process table
  whether every live process has at least one thread the scheduler can still
  find, and counts the ones it cannot. The counts are readable through `/proc`
  as `wake-refused`, `enqueue-refused`, `waiter-lost`, and `unplaced-process`,
  which is what turns a silent wedge into an attributable one.
- **CPU frequency scaling**: on x86_64 via IA32_PERF_CTL/PERF_STATUS MSRs (CPUID
  leaf 0x16 + PLATFORM_INFO detection, read-only fallback on AMD), governor
  policy (performance/powersave/ondemand/schedutil/userspace) driven from the
  scheduler tick, temperature readable from IA32_PACKAGE_THERM_STATUS; AArch64
  and RISC-V discover their range from device-tree OPP tables
  (`operating-points-v2` phandles / legacy `operating-points` tuples).

**Weaknesses:**

- **ARM/RISC-V frequency scaling not applied**: AArch64/RISC-V only track the
  requested target in software; real frequency switching needs a platform
  clock/firmware interface (SCMI, common-clock, SBI CPPC) that is not yet
  wired.
- **Load balancing lacks real-load validation**: SMP/NUMA scenarios are mostly
  tested under QEMU.

---

### 5. Memory Management

| Component | Now | Missing |
|-----------|-----|---------|
| Physical frame allocator | Dynamic detection via Multiboot2/FDT, bump pointer plus recycled free ranges | The pool has a fixed ceiling; no memory hotplug or hot-remove |
| NUMA frame allocators | Per-node allocators (`MAX_NODES`), `set_node_range()`, fallback to node 0 | Topology discovery is exercised under QEMU; no NUMA hardware validation |
| TLSF heap allocator | Bounded heap, fixed free-list table, O(1) alloc/free | Fixed size: the heap is carved once and does not grow |
| Page table management | Per-arch tables, identity map, user address spaces, 2 MiB and 1 GiB huge pages | x86_64 has no PCID, so a context switch invalidates translations |
| Copy-on-Write | Refcounted frames, fault-triggered copy | — |
| Demand paging | Content store plus swap-out | — |
| Swap area | Block-device-backed page slots, LIFO free list, magic-based boot-time detection | Verified under emulation only; no real memory-pressure run |
| Compressed page cache | Zswap-style zero/RLE/LZSS compression on reclaim, with raw-store eviction | Emulation only, and the budget is a fixed constant |
| Memory compaction | Frame-pool defragmentation: relocate movable user frames, coalesce free ranges | Movable user frames only; an unmovable barrier stops a pass early |
| ASID allocator | AArch64 and RISC-V bitmap allocators | — |
| User address space | Brk heap, ELF loading, guard pages | — |
| Kernel stack guard | Unmapped page below each kernel stack | — |

**Strengths:** covers the major virtual-memory features, plus NUMA,
disk-backed swap, compression, and defragmentation.

- **TLSF allocator**: bounded heap with O(1) allocation over a fixed free-list
  table.
- **Virtual memory**: CoW fork + demand paging with swap-out, automatic
  2 MiB / 1 GiB huge-page selection, kernel stack guard pages on all threads;
  mlock/munlock (#131-132) and madvise (#133).
- **NUMA**: per-node frame allocators, CPU-to-node mapping (`numa_node_id`),
  and automatic topology discovery (ACPI SRAT/SLIT on x86_64; FDT numa-node-id
  / distance-map on AArch64 and RISC-V); a default single-node topology always
  works when no NUMA hardware is detected.
- **Disk-backed swap**: `probe_device()` checks for the `ADASWAP` magic
  signature and `maybe_init_swap()` activates swap automatically at boot.
- **Memory compression & compaction**: zswap-style zero/RLE/LZSS compression
  and physical-pool defragmentation, exposed via the `CompactMemory` syscall
  (#150).

**Weaknesses:**

- **Fixed capacity ceilings**: the kernel heap and the physical pool are
  fixed-size (see the constants under `src/memory/`), which limits large
  workloads.
- **No ASID/PCID-level TLB tagging on x86_64**: context switches rely on TLB
  invalidation.
- **Swap-out/compression verified under emulation only**: real memory-pressure
  scenarios are not covered.

---

### 6. Interrupt & Exception Handling

| Component | Now | Missing |
|-----------|-----|---------|
| x86_64 IDT + exceptions | #PF, #GP, #UD, #DF, timer, IPI | — |
| x86_64 APIC + IOAPIC | SMP IPI, timer, I/O routing | — |
| AArch64 exception vectors | EL1 sync/IRQ/FIQ/SError, EL0 sync | — |
| AArch64 GIC | GICv2 and GICv3 register layouts, chosen from `GICD_PIDR2` (`src/arch/aarch64/gicv3.rs`); LPIs; the ITS that translates a device's message into one (`src/arch/aarch64/its.rs`) | Every LPI goes to the boot CPU's redistributor; a machine whose device cannot carry a requester ID would need a window of its own in front of the ITS |
| RISC-V trap handler | U-mode ecall, timer, external interrupts | — |
| RISC-V PLIC | PLIC initialization from FDT | The default machine has no IMSIC, so the PLIC stays the external controller there |
| Common interrupt abstraction | `InterruptController` trait | — |
| Thread exception handling | Page fault recovery, signal delivery | — |
| PAN/SMAP emulation | AArch64 PSTATE.PAN, x86_64 SMAP, RISC-V SUM | A window held across a block can be closed under the holder; the socket send paths still do that |
| MSI/MSI-X programming | Vector allocator and table programming on x86_64; AIA IMSIC with per-device claims on RISC-V; GICv3 ITS with per-device claims on AArch64 | On the device-tree machines only the virtio-net PCIe driver claims identities yet |
| NMI handling | x86_64 dedicated vector path, AArch64 SError/FIQ dedicated path, handler registry | No architectural NMI source on RISC-V, so that entry stays dormant |
| Interrupt load balancing (SMP) | IOAPIC redirection re-target, GIC SPI affinity, PLIC per-context enable | Runs from the tick; no routing-latency measurement |
| Interrupt stats interface | Per-CPU/per-vector counters, NMI/IPI totals, balancer state (SystemInfo #9) | — |

**Strengths:** architecture-complete exception handling across all three
targets, with PAN/SMAP emulation, MSI/MSI-X on the architectures that have an
MSI controller, NMI handling, and load balancing.

- **Exception handling**: complete on all three targets; double-fault handling
  on x86_64; the AArch64 vector table classifies synchronous exceptions, IRQs,
  FIQs, and SErrors; PAN/SMAP implemented (the `asm nomem` fix was deployed).
- **MSI/MSI-X**: vector allocator + table programming on x86_64; on RISC-V the
  AIA IMSIC receives MSIs and the PCIe virtio-net driver claims its device's
  identities. NVMe and VirtIO PCI modern transport use MSI-X where the
  controller offers it.
- **NMI handling**: dedicated minimal path for the x86_64 NMI vector and the
  AArch64 SError/FIQ vectors, with a handler registry (`kernel::nmi`) that works
  across the architectures that have a source.
- **Softirq/bottom-half**: a pending mask integrated into the scheduler loop and
  the arch trap dispatchers.
- **Interrupt load balancing (SMP)**: runs periodically from the scheduler tick,
  migrating the hottest migratable IRQ to the idlest CPU — x86_64 IOAPIC
  redirection, AArch64 GIC SPI affinity, RISC-V PLIC per-context enable.
- **Interrupt stats**: `SystemInfo` type 9 exposes per-CPU/per-vector IRQ
  counts, IPI/NMI/spurious totals, and load-balancer state.

**Weaknesses:**

- **One LPI collection on AArch64.** The ITS translates a device's message
  into an LPI, and every collection this kernel maps points at the boot CPU's
  redistributor — so every message-signalled interrupt lands on one core.
  Spreading them needs a collection and an LPI pending table per CPU, which is
  the next step rather than a property of the design.
- **MSI-X on RISC-V is one driver deep**: the AIA IMSIC is wired and a device's
  table is programmed, but only the virtio-net PCIe driver claims interrupts
  through it; the default machine has no IMSIC at all, so the PLIC remains the
  external-interrupt controller there.
- **No architectural NMI source on RISC-V**: the S-mode dispatch entry stays
  dormant (it would need an M-mode or `smnmi` path).
- **GIC/PLIC verified under emulation only**: no real-hardware routing or
  latency testing.

---

### 7. Network Stack

The network stack carries its own protocols rather than porting a small
embedded stack: link, internet, transport, application, security, VPN,
multicast routing, and raw sockets.

#### 7.1 Protocol Support

| Layer | Now | Missing |
|-------|-----|---------|
| **Link** | Ethernet, ARP, device abstraction | — |
| **Internet** | IPv4, IPv6, ICMP, ICMPv6, IGMP, MLD, NAT, IP options | — |
| **Transport** | TCP (congestion control, ECN), UDP, SCTP, DCCP | Congestion control is Tahoe/Reno only; no CUBIC or BBR |
| **Application** | DHCP (discovery and renewal), DNS (cache and resolve), mDNS, NTP, PPP | IPv4 only: no DHCPv6 or prefix delegation; DNS has no DNSSEC validation |
| **Security** | TLS 1.3 (handshake, record, certificate), IPsec (ESP + AH, SAD/SPD, transport/tunnel) | TLS has no trust-anchor management; IPsec SAD/SPD is manual |
| **VPN** | WireGuard handshake, transport and session tables (Noise_IKpsk2, ChaCha20-Poly1305, key management) | Not wired up: nothing outside the module constructs a device, so a program cannot open a tunnel yet |
| **Multicast routing** | MFC/VIF forwarding, IGMPv2/MLDv1 router mode, MRT API | PIM-DM only, and only under a feature flag; no PIM-SM |
| **Raw** | Raw sockets, raw packet | Not every raw entry has a typed shared-library wrapper |
| **Educational¹** | CSMA/CD, CSMA/CA, STP, IPv4 Options, Mobile IP, RSVP, PIM-DM | Compile-time gated, so it is outside the default build |

¹ Gated behind `feature = "educational_networking"`.

#### 7.2 TCP Implementation

| Component | Now | Missing |
|-----------|-----|---------|
| Segment handling | Segmentation, reassembly, retransmit | — |
| Connection table | Hash table and state machine | — |
| Congestion control | Pluggable framework with Tahoe and Reno | No CUBIC or BBR; no throughput baseline |
| ECN (Explicit Congestion Notification) | Negotiation and marking | — |
| Timer management | RTO, delayed ACK, keepalive | — |
| Window scaling | Window-scaling option | — |

#### 7.3 Network Syscalls

The network ranges are listed in `docs/kernel-introduction/syscall.md`. Not
every network syscall has a typed wrapper in the shared user library
(`src/user/shared/`); a program that needs an unwrapped one calls the raw entry
point.

**Strengths:** a complete, native (non-lwIP) TCP/IP stack with transport-layer
extensions and in-kernel security protocols.

- **Protocol coverage**: link (Ethernet, ARP), internet
  (IPv4/IPv6/ICMP/IGMP/MLD/NAT), transport (TCP with congestion control + ECN,
  UDP, SCTP, DCCP), application (DHCP, cached DNS, mDNS, NTP, PPP).
- **IPsec**: ESP + AH with AES-GCM / ChaCha20-Poly1305 AEAD and
  HMAC-SHA256, both transport and tunnel modes, SAD/SPD managed manually through
  dedicated syscalls.
- **Multicast routing**: MFC/VIF forwarding engine (RPF + TTL gating),
  IGMPv2/MLDv1 router mode, MRT management API, plus a PIM-DM flood-and-prune
  control plane under `educational_networking`.
- **IPv6 hardening**: path-MTU discovery (RFC 8201, with TX fragmentation),
  atomic fragments (RFC 6946), extension-header order and chain-length limits
  (RFC 8200 §4.1), routing-header type-0 rejection (RFC 5095),
  overlapping-fragment discard (RFC 5722).
- **TLS 1.3**: implemented as a kernel module — unusual, and potentially useful
  for secure bootstrapping.
- **Deferred periodic work**: the scheduler tick advances the stack's clock
  with a single atomic add; the pass that acts on it — ARP eviction, TCP
  retransmit and TimeWait, DHCP renewal, SLAAC, IGMP/MLD, NTP, mDNS — runs on
  the maintenance thread, so the transmits inside it wait for the device's
  completion interrupt in thread context instead of inside the interrupt
  handler that would have masked it.

**Weaknesses:**

- **Not every network syscall is wrapped** in the shared user library.
- **In-kernel TLS has no trust framework**: certificate and trust-anchor
  management is still minimal.
- **Educational protocols are feature-gated**: CSMA/CD, STP, Mobile IP, RSVP,
  PIM-DM, etc. compile only under `educational_networking`.
- **Performance not benchmarked**: throughput and concurrency baselines
  (multi-core, load-balanced) have yet to be established.

---

### 8. IPC / Synchronization

| Component | Now | Missing |
|-----------|-----|---------|
| Pipe | VFS-backed, anonymous, blocking read/write | No named pipe and no descriptor passing over a pipe |
| Signal | 43 slots (0-42), including 11 RT signals (32-42); u64 mask, install/enqueue/wait | No signal-storm stress baseline |
| Signal mask | Per-process blocked signal tracking, u64 bitfield | — |
| Async signal delivery | Signal frame on user stack, arch-specific trampoline, sigreturn; all three architectures | — |
| SA_SIGINFO support | siginfo_t delivery (si_signo, si_code, si_pid, si_uid, si_addr, si_value) | — |
| SA_RESTART support | Automatic syscall restart on signal return, RestartBlock per thread | — |
| sigsuspend (#135) | Atomic mask swap and thread suspend until a signal | — |
| POSIX timers (#137-140) | timer_create/settime/gettime/delete, per-process management, signal on expiry | — |
| eventfd (#107) | Counter/semaphore mode, EFD_NONBLOCK/EFD_CLOEXEC, poll/epoll integration, write-overflow EAGAIN | — |
| Event | Event flag synchronization | — |
| Condition variable | Blocking wait/wake | — |
| Mutex | Blocking mutex | No lock-contention benchmark |
| Semaphore | Counting semaphore | — |
| Spinlock | IRQ-safe spinlock | — |
| Shared memory | System V shm: shmget/shmat/shmdt/shmctl (#100-103) | Purpose-specific syscalls rather than a file- or handle-shaped IPC API; no POSIX `shm_open` |
| Shell pipeline | Two commands piped together by the ring-3 shell | No kernel process group; the shell tracks jobs itself |

**Strengths:** complete synchronization primitives and signal machinery,
including the POSIX signal interaction model.

- **Synchronization primitives**: mutex, semaphore, condvar, event, and IRQ-safe
  spinlock are complete; eventfd (#107) provides counter/semaphore semantics
  (`EFD_SEMAPHORE`/`EFD_NONBLOCK`/`EFD_CLOEXEC`, write-overflow `EAGAIN`)
  integrated with `poll`/`epoll`/`io_uring` readiness probes.
- **Signals**: 43 slots (0-42) including 11 RT signals (32-42) carrying
  `siginfo_t`; SA_SIGINFO with per-architecture `ucontext_t`; SA_RESTART rewinds
  the interrupted instruction pointer at syscall dispatch boundaries (2 bytes
  on x86_64 `int 0x80`, 4 bytes on AArch64 `svc #0`, 4 bytes on RISC-V `ecall`)
  and `restart_syscall` (#136) re-executes the interrupted call; sigsuspend
  (#135) atomically swaps the mask and suspends; POSIX timers (#137-140) deliver
  signals on expiry via the scheduler tick.
- **Async signal delivery**: signal frame injected on the user stack on all
  three architectures, with arch-specific trampoline and sigreturn.
- **Shell pipelines**: `cmd1 | cmd2` with process groups.

**Weaknesses:**

- **Limited IPC shapes**: IPC relies mainly on pipes, signals, eventfd/mq; there
  is no standardized shared-memory IPC API (shm remains a purpose-specific
  syscall).
- **Contention scenarios not benchmarked**: lock contention and signal storms
  lack stress baselines.

---

### 9. Security & Access Control

| Component | Now | Missing |
|-----------|-----|---------|
| Biba integrity model | System > High > Medium > Low | — |
| Zone-aware DAC | System (/system), Apps (/apps) and Data (/data) zones; the credential store is carved out of the guest-owned data zone | The zone set is a compile-time constant: no zone can be added or resized at boot |
| Security descriptors | Per-object owner, group and mode | — |
| User/group database | `/data/etc/passwd` and `/data/etc/shadow`, written back atomically | No group database; gids are numbers carried in the passwd records |
| Process security token | Per-thread credentials and integrity level | — |
| Access helpers | Central permission checking on VFS operations | — |
| SHA-256 integrity | Launch manifest and payload hashes; optional detached signatures | Verification is opt-in: an artifact carrying no signature loads anyway, and there is no key distribution or rotation policy |
| PAN/SMAP | Kernel-user memory isolation on all three architectures | See the interrupt section: a window held across a block can be closed under its holder |
| Stack canary | Per-thread random canary, verified on context switch | Software check: it detects a smashed stack rather than preventing the write |
| MAC type enforcement | Types on subjects and objects, allow rules, VFS/Process/Network hooks, exec transitions | Default is allow until a policy is loaded; deny-by-default needs an explicit policy |
| Audit subsystem | Classified event types, ring buffer, syscall entry/exit hooks, AuditSetEnable (#143) and AuditReadLog (#144) | Memory-only in practice: the persistence path exists but nothing enables it, so records are lost on reboot |
| Service authorization | A privileged rc.d declaration names an account that must resolve; the grant or refusal is audited | Provenance, not authentication: no password is involved, so the elevated token is unauthenticated |

**Strengths:** a formal multi-level security policy and mandatory access
control that are unusual in a hobby kernel.

- **Biba integrity model**: a formal information-flow policy (System > High >
  Medium > Low).
- **MAC type-enforcement engine**: security types on subjects and objects, an
  allow-rule policy enforced at central VFS checkpoints, Process-class
  (ptrace/signal) and Network-class checks, exec domain transitions, management
  syscalls (#175-178), and MacDenial audit records on refusal.
- **Zone-aware DAC**: segments the filesystem into regions with different trust
  levels (`/system` read-only, `/apps` executable and writable by the token
  its descriptor allows — installing is writing it — and `/data` writable for
  its users). User home directories live under `/data/users/<user>`, not in a
  zone of their own.
- **Persistent credentials**: `/data/etc/passwd` and `/data/etc/shadow` written
  back atomically, with the shadow file kept at 0600.
- **Service authorization**: a privileged rc.d declaration names an account that
  has to resolve in the user database before the service runs, and the grant or
  refusal is audited; the token it runs under carries that account's identity.
- **Service provenance**: a declaration is a file, and the kernel reads it
  itself — the boot walks `/system/rc.d`, and `service_declare` (#190) is handed
  a *path*, which has to name a file in the read-only system zone.  What gets
  registered is therefore the image's bytes and not text a caller assembled,
  and every definition carries where it came from: `/service/<name>/origin` and
  `/service/<name>/sha256` report the declaration file and the digest of its
  bytes, which is what a privileged level rests on.  The path is checked
  component by component against its directories' own listings — directories
  down to the file, and the file a regular file — because the filesystem
  resolves through symlinks, and a link shipped in the image would otherwise
  have the kernel read a declaration out of a writable zone while the record
  said `/system`.
- **Service security declarations**: a `security = "guest" | "admin" | "system"`
  key in an rc.d service definition selects the token the started program runs
  under (`ServiceSecurity::security_token()`); a definition that declares
  nothing keeps the guest default.
- **Declared service start order**: `after = ["other", …]` in an rc.d
  definition is ordering, and `service::plan_start_order()` turns the
  declarations into the order the boot path follows.  A service whose
  prerequisite is undeclared, itself blocked, or part of a cycle is recorded as
  `blocked` in `/service` with the reason, instead of being started early or
  failing later for an unattributable one.  `after` says nothing about what the
  other service achieves — a daemon is not "done" when it is spawned — which is
  why the mechanism orders and attributes rather than waits.
- **The disk declares, the kernel falls back**: the demo disk ships
  `/system/rc.d/defaults.toml`, rendered by the demo-disk builder from
  `service::default_definitions()` — the same list the kernel uses when a disk
  declares nothing — so the two cannot drift into "the disk says one thing and
  the boot runs another".  A stock boot reads the declarations off the disk and
  says so in the log (`N declaration(s) in /system/rc.d`).
- **Init is a program**: `/system/init.elf` on the demo disk is a ring-3 init
  payload on every target the disk is built for — one program
  (`src/user/demo/init_payload.rs`), emitted per architecture.  It lists
  `/system/rc.d`, names each declaration file through `service_declare` (#190)
  and asks for the services to be started by `service_start_all` (#191), then
  installs the package the disk left staged in the download cache through
  `install_package` (#192) — the same loop the host tests drive, on the machine,
  with the line it prints as the proof.  The kernel keeps the mechanism —
  registry, start order, supervision, `/service`, the install itself — and the
  distribution keeps the declarations and the packages; the two meet at those
  three syscalls.  It runs with the system token, because that is what the app
  zone's descriptor requires of a program that installs into it.
  `service_start_all` is idempotent, so whichever of the boot path, init or the
  supervisor arrives first starts a service and the others find nothing left to
  do.
- **The boot hands the start to init**: when the disk ships an init program, the
  kernel registers the declarations — `/service` and the supervisor need them
  either way — and leaves the start to that program, so the distribution, not
  the kernel, decides what the machine runs.  The wait has a five-second
  deadline: a disk whose init never asks, or never runs, has its pending
  services started by the supervisor instead, and a disk with no init program
  at all is started by the boot directly.  That fallback is exercised by a
  boot of its own — `make check-x8664-init-no-start` builds a disk whose init
  reads the declarations and asks for nothing — so it is not a path that only
  runs when something else has already gone wrong.
- **Code integrity**: SHA-256 over the launch manifest and payload, plus
  optional detached signatures verified against trusted public keys under
  `/system/trusted-keys`; a seccomp (#129) syscall filter for process
  sandboxing; PAN/SMAP prevents kernel access to user memory outside an
  explicit window.
- **The system volume is a pair**: a disk carries two system slots, each volume
  carries a build marker (`/etc/build`), and a boot takes the committed slot
  with the highest generation — falling back to the other when that one does
  not open.  An update writes a whole volume image into the inactive slot and
  refuses anything that is not a newer, committed system volume; rollback
  removes one file (the winner's marker) and the machine boots the other slot
  again, with the withdrawn build's payload untouched.  The demo disk ships
  both slots, B committed as the newer build, so every runtime check boots the
  pair's selection rather than a single-volume disk.
- **Where a running machine writes**: `/system` and `/apps` are mounted
  read-only, so a program has two places to write and the difference between
  them is what a reboot means — `/tmp`, a volume built empty on every boot, for
  scratch, and `/data`, its own zone, for user data, credentials, caches and
  logs.  The policy is written down in `src/fs/write_locations.rs` and the boot
  says it once, so a reader of a log can see what survives a reboot and what
  does not.  A system update replaces a *system volume* and never names a file
  inside either root, which is what makes it unable to lose runtime state — and
  what a test pins: two system switches later, the data zone holds what it held.
- **Install format and atomic switch**: a package is a directory named
  `<app-id>@<version>` holding a launch manifest (paths relative to itself) and
  the program it names.  `user::program::install` checks the manifest's digest
  and optional signature *before* committing anything, stages the payload
  beside its version root and renames it in, writes the versioned catalog
  record last — that record is what makes a version installed — and switches
  `/apps/current/<app-id>.toml` to it with the filesystem's `swap_paths`, so the
  active name always holds a complete record.  A failure before the record
  leaves the machine as it was; a failure after it leaves a transaction the
  boot reports as installed-but-not-activated, which is the rollback.  A ring-3
  program reaches it through `install_package` (#192), which adds no policy of
  its own: every read and every write the install makes goes through the
  filesystem under the *caller's* token, so a program installs exactly what it
  can read and exactly where it can write — and the demo's app zone, mounted
  read-only, refuses a guest before anything is written.
- **Stack canary**: a random 64-bit canary per thread, verified by
  `check_stack_canary()` before each context switch back to the scheduler.
- **Audit subsystem**: classified event types (Syscall, FileOp, Process,
  Network, Auth, MacDenial), a ring buffer for record storage, and dedicated
  syscalls (AuditSetEnable #143 / AuditReadLog #144). The ring buffer is
  installed during kernel initialisation, before anything can produce a record
  — the buffer has to exist or `emit_record` drops what it is handed — and a
  privileged service declaration is audited there.

**Weaknesses:**

- **Default allow**: until a MAC policy is loaded, the default is to allow;
  deny-by-default requires an explicit policy.
- **Audit log is memory-only in practice**: the ring buffer is installed and
  written, but the persistence path that would flush it to `/data/audit.log` is
  off by default (`audit::persist::set_persistence`) and nothing calls it, so
  records are lost on reboot. The maintenance thread already drives the flush;
  only the switch is missing.
- **Signature verification is opt-in**: a launch manifest or program image
  carrying `manifest_signature`/`entry_signature` is verified against a trusted
  key, but one that carries neither loads anyway, and nothing in the launch
  chain requires a signature. There is no key distribution or rotation policy,
  so the guarantee is "a signed artifact cannot be swapped" rather than "only
  signed artifacts run".
- **Service privilege is provenance, not authentication**: a definition
  declaring `security = "admin"` or `"system"` is trusted because
  `/system/rc.d` lives on a read-only zone and because the account it names
  exists. No password is involved, so the token it receives is elevated but
  unauthenticated, and no service level reaches the discretionary bypass: a
  service manages what root owns but cannot read another account's private
  files, and `system` carries the kernel's trust level without its identity.
  The bypass has exactly two producers — the kernel's own threads and a
  password-authenticated login — and a test in `kernel::service` pins both
  halves so the policy cannot be changed by accident. A service that needs to
  reach across accounts needs a capability, not a wider level.

---

### 10. Syscall Interface

| Component | Now | Missing |
|-----------|-----|---------|
| Syscall table | Numbered slots; the public count is derived from the highest enum discriminant, not written down in this document | The experimental range is not frozen, so it carries no cross-major stability guarantee |
| Dispatch engine | Context-aware dispatch with action return | — |
| User memory validation | `validate_user_mapping()` and `copy_user_bytes()`, driven by the central pointer-spec table | — |
| Shared wrappers (`src/user/shared/syscall.rs`) | Typed wrappers plus raw entry points | Not every syscall has a typed wrapper |
| ABI types | Wire-format records with compile-time layout assertions | — |
| Per-category handler files | fs, network, process, diagnostic, tls, filter, io_uring, ptrace, and the rest | — |
| Syscall profiling | Per-syscall counters behind an optional feature | Off by default, so a normal boot has no syscall profile |

**Categories of syscall handlers:**

| Category | Where |
|----------|-------|
| Process/thread lifecycle | `launch_metadata.rs`, `runtime.rs` |
| Process control | `misc/prctl.rs` |
| File/path operations | `fs/path_ops.rs` |
| I/O (read/write) | `io_fd.rs` |
| Network | `network.rs` |
| IPC & synchronization | `futex.rs`, `event_fd.rs`, `signal_fd.rs`, `timer_fd.rs`, `mq.rs`, `epoll.rs` |
| Memory management | `memory/map.rs`, `memory/brk.rs`, `memory/shm_handlers.rs` |
| Filesystem (mount/FUSE) | `fs/path_ops.rs`, `fs/fuse_mount.rs` |
| TLS encrypted connections | `tls.rs` |
| Packet filter / firewall | `filter.rs` |
| io_uring async I/O | `io_uring.rs` |
| ptrace process tracing | `ptrace.rs` (syscall) + `process/ptrace.rs` (core) |
| seccomp | `seccomp.rs` |
| Signal control | `signal.rs`, `signal_mask.rs`, `sigsuspend.rs`, `restart_syscall.rs` |
| Exception control | `exception_control.rs` |
| POSIX timers (#137-140) | `timer.rs` (timer_create/settime/gettime/delete) |
| Audit (#143-144) | `audit.rs` (AuditSetEnable, AuditReadLog) |
| Extended attrs + file flags (#151-156) | `fs/xattr.rs` (setxattr/getxattr/listxattr/removexattr/set_file_flags/get_file_flags) |
| Diagnostics | `diagnostic.rs` |
| ABI information | `abi_info.rs` |
| Miscellaneous | `misc.rs` |

**Strengths:** a stable ABI with a single source of truth and careful
user-memory validation.

- **Organized by category**: handler files are separated by concern (fs,
  network, process, tls, filter, io_uring, ptrace, etc.), and the dispatch table
  has room for expansion (`MAX_SYSCALLS = 256`).
- **Single source of truth**: `src/user/shared/` provides the ABI's one
  canonical manifest — both kernel and userspace compile against the same
  constant definitions; the `UserSyscall` type lets kernel-internal callers
  (demo workers) exercise the same path.
- **User-memory validation**: memory is validated before every access, through
  the central `SYSCALL_POINTER_SPECS` table.
- **Signals & timers**: dedicated **sigsuspend (#135)** and
  **restart_syscall (#136)** handlers complete the POSIX signal interaction
  model (SA_RESTART rewinds the instruction pointer and re-invokes the
  dispatcher); **POSIX timers (#137-140)**.
- **Management syscalls**: audit (#143-144), CPU frequency scaling (#145-149),
  extended attributes and file flags (#151-156), fcntl (#179), sync (#180).
- **VIRGL 3D interface (#181-189)**: gpu_ctx_create/destroy,
  gpu_res_create_3d/unref (kernel-allocated DMA backing),
  gpu_transfer_to_host_3d/from_host_3d, gpu_submit_3d, gpu_set_scanout,
  gpu_device_info.
- **Stable, versioned ABI**: all syscall numbers live in
  `src/user/shared/abi/syscall.rs`; the ABI is versioned via
  `SYSCALL_ABI_VERSION_MAJOR`/`SYSCALL_ABI_VERSION_MINOR`, reported at runtime
  through `RuntimeAbiInfo`; numbering is append-only — never renumber, never
  reuse a slot; syscalls are classified Stable or Experimental with a frozen
  boundary, and `tests/syscall/abi_golden.rs` pins the whole number→name table
  so a swap in the stable range fails the build.

**Weaknesses:**

- **The experimental range is still Experimental** (121-189): it is not frozen,
  so there is no cross-major stability guarantee above the boundary.
- **No external toolchain or conformance suite**: the ABI is self-consistent
  within the kernel crate but has no independent toolchain or POSIX conformance
  tests.

---

## Cross-Cutting Concerns

### Architecture Support

| Feature | x86_64 | AArch64 | RISC-V 64 |
|---------|--------|---------|-----------|
| Boot protocol | Multiboot2 / QEMU PVH | QEMU direct `-kernel` | QEMU direct `-kernel` |
| Interrupt controller | APIC + IOAPIC | GICv2 or GICv3, chosen from `GICD_PIDR2` | PLIC |
| Timer | PIT (IRQ0 → LAPIC 0) | Generic timer (per-core PPI 30) | CLINT timer |
| SMP | Full (MADT + AP bringup; the tick is the boot CPU's) | Full (PSCI + GIC SGI) | Full (SBI HSM + per-hart vector, timer, and PLIC context; a cross-hart wake waits for the target's tick) |
| Context switch | Full | Full | Full |
| PAN/SMAP | SMAP (stac/clac) | PSTATE.PAN (set/clear) | SUM (sstatus) |
| MSI/MSI-X | Full (vector allocator + table programming) | GICv3 ITS and LPIs; the PCIe virtio-net driver claims its device's identities, which all arrive on the boot CPU | AIA IMSIC; the PCIe virtio-net driver claims its device's identities |
| PCIe | Full ECAM | Basic probing | Basic probing |
| ASID allocator | — | Full (bitmap + CAS) | Full (bitmap + CAS) |
| FDT parsing | — | Full | Full |
| RTC | — | Full (from FDT) | Full |
| Serial | Full (UART 16550) | Full (UART 16550) | UART 16550 (SBI fallback) |
| NUMA discovery | Full (ACPI SRAT/SLIT) | Full (FDT numa-node-id, distance-map) | Full (FDT numa-node-id, distance-map) |
| CPU frequency scaling | Full (MSR P-state) | Full (DT OPP) | Full (DT OPP) |

What each target still lacks:

- **x86_64**: no PCID, so a context switch flushes translations; the PIT is
  routed to one LAPIC, so APs take no timer interrupt.
- **AArch64**: MSI machinery is there — GICv3, LPIs, an ITS — but all of it
  lands on the boot CPU, and only one driver claims identities through it.
- **RISC-V 64**: the most partial of the three. No architectural NMI source,
  a cross-hart wake waits for the target's next tick, and the default QEMU
  machine has no IMSIC.
- **All three**: verified under QEMU only; no bare-metal bring-up yet.

### Shared User Runtime (`src/user/shared/`)

| Module | Now | Missing |
|--------|-----|---------|
| `syscall.rs` | Typed syscall wrappers plus raw entry points | Not every syscall has a wrapper |
| `dispatch.rs` | Command-name to builtin dispatch | — |
| `commands/` | The shell's builtin implementations | Builtins are shell commands, not a libc; a standalone program links this module to reuse them |
| `signal.rs` | Signal API: u64 mask, sigsuspend, SA_SIGINFO | — |
| `passwd.rs` | `/data/etc/passwd` parsing | No group file to parse |
| `jobs.rs` | Job tracking for the shell | Jobs live in userspace, so they die with the shell |
| `abi/` | ABI record types, mirrored from `src/abi/` | — |
| `runtime.rs` | Architecture syscall bridge, brk allocator, argument parsing | Behind the `runtime` feature; the kernel build uses its own bridge instead |

The ABI records are the one thing here that exists twice: `src/abi/` holds them,
and `src/user/shared/abi/` mirrors them, the mirror carrying
`//! src/abi/<name>.rs` in its header to record where each file came from.
`make check-abi-mirror` keeps the two in step: every record has to be declared
by `src/abi/mod.rs` (a file the compiler never reads is not code), every mirror
has to record its origin, and the two bodies have to be identical below the
header — except for the differences `scripts/abi-mirror-baseline.txt` records
with a reason.

That check exists because the copies had drifted the one way copies drift. The
kernel's side had grown blocks of exactly the API user code needs — the `SA_*`
restart flags, the architecture-neutral exception-handler flags and the
`NetworkStatus` accessors — and the shared side had none of them, which is why
user code was reaching back into `src/abi/` for them. The mirrored records are
byte-identical below the header now, and the listed differences are the ones
that are not mirrors at all: `runtime.rs` (the kernel re-exports the shared
definition), `syscall.rs` (the kernel file encodes status words, the shared one
names syscalls), `mod.rs` (the shared tree carries no `virgl` record) and
`virgl.rs` itself.

Files that no module declared are gone with the same change: they were in
`src/abi/`, invisible to the compiler and to every gate, and one of them listed
prctl codes that collided with the implemented ones.

The other direction is fixed too. `src/user/` used to reach the ABI through
`crate::abi::`, which meant the vendored tree was in step with the kernel's copy
but could not have been lifted out of the crate: it named a path that would not
exist on the other side. The shared tree and the payload modules now go through
`crate::user::shared::abi::`, which `make check-abi-mirror` enforces by deriving
the payload list from the macro that gives those modules their linker sections.
Two places are deliberately still on the kernel's copy, and both are kernel
code: the host-proxy demonstration runtime, the in-kernel shell's `env` builtin,
and one `decode_result` call whose result is the kernel's own `Error` type. The
numbers it decodes against come from the shared copy.

### Testing

| Category | Now | Missing |
|----------|-----|---------|
| Unit tests (in-module) | Per-module behaviour, registered by feature | — |
| Integration tests | Filesystem, I/O, memory, process, network and syscall areas | Host-side only; the bare-metal side is covered by the runtime smokes, not by these |
| Fault injection | SimpleFs single- and dual-fault matrix | Deterministic and bounded; the other filesystems have no equivalent matrix |
| Recovery tests | Crash and replay scenarios | — |
| Concurrency tests | Scheduler, condvar, console, keyboard | — |
| Parser fuzz harnesses | Deterministic, in-tree, run by `make test-parsers`; coverage-guided targets in `fuzz/` run nightly | The gates are fixed-seed and bounded; the nightly corpora are not persisted across runs |
| virtio-gpu layout tests | Struct size and layout plus command wire format, against a mock device | Mock device only; no real GPU validation |
| CI workflow | fmt, check, build, clippy on every configuration, every static gate and ratchet, and the boots | The gates run as separate steps rather than through `make verify-p3` |
| Verification gates | P0-P3: fmt, tests, cross-builds, clippy, plus the QEMU smokes | The smokes are opt-in through environment variables, so a local `make verify-p3` without them does not boot anything |
| ABI number snapshot | `tests/syscall/abi_golden.rs`: a number's name may not change, and an experimental change has to bump the ABI minor in the same commit | Pins numbering and record layouts, not the object shapes behind them |

The demo disk was verified end-to-end on all three targets under QEMU:
interactive shell, demo payload (app-id/image/cwd/argv0/resume/exit code), 0
FATAL. The shell is ring-3 on all three targets and the runtime checks type a
command at its prompt and assert the answer.

### Userspace compatibility (the iron rule)

`docs/fmts/syscall-abi.md` states the compatibility contract — numbers assigned
once and never renumbered, records whose layout is asserted at compile time, and
a frozen range below a boundary with an experimental range above it. Three
things make that contract *testable* rather than merely written down:

| Item | State | Where |
|------|-------|-------|
| The number table is frozen | **done** | `tests/syscall/abi_golden.rs`: a snapshot of every number→name row. A change in the frozen range fails outright; a change in the experimental range fails unless the ABI minor version moves with it. Before this, swapping two stable syscalls left every test green. |
| Userspace can learn which ABI it is on | **done** | the `abi_info` syscall returns `syscall_abi_major`, `syscall_abi_minor` and `syscall_count` alongside the record's own `major`/`minor`/`record_size` (`src/user/shared/abi/runtime.rs`) |
| A program that was not rebuilt | **done, partially** | `src/user/demo/fixtures/` holds frozen payloads. `make check-abi-frozen-payload{,-aarch64,-riscv64}` build with `abi_frozen_payload`, so the demo disk carries *those* bytes instead of the freshly compiled ones, boots them, and requires the same user output the normal smokes do — plus a boot line naming the source, so a gate cannot pass while quietly testing a new payload. The x86_64 boot carries two: it runs the frozen launcher, and the launcher starts the frozen child. AArch64 and RISC-V have one each because their demo disks ship one payload program between them. Each freeze is a deliberate act; the remaining demo programs are not frozen. |

### Build & Development

- **Build system:** Cargo + Makefile (verified targets per architecture)
- **Layout:** the shared user runtime and demo payloads live inside the kernel
  crate as `src/user/shared/` and `src/user/demo/`
- **Optional features:** `demo-disk`, `fs_profiler`, `net_profiler`,
  `alloc_profiler`, `fault_profiler`, `educational_networking`, plus
  `abi_frozen_payload` and `init_no_start`, which change what the demo disk
  carries so a boot can exercise a path the normal disk does not reach
- **Release profile:** `panic = "abort"`, `opt-level = "s"`, `lto = true`,
  `codegen-units = 1`
- **Reproducible artifacts:** the same source built twice in two clean trees
  produces byte-identical artifacts for all three architectures — the two ELFs,
  the aarch64 `Image` and the demo disk image — and
  `make check-reproducible-build` is the gate that keeps it that way.  Nothing
  is pinned to a hash: the check asserts determinism, which is the property a
  verifiable release needs.  One artifact can be signed with a fresh one-time
  key (`cargo run -- sign-release …`, checked with `verify-signature`), using
  the same `lamport-sha256` scheme the kernel verifies manifests with.  Tagged
  releases, published key records and the documented verify-a-rebuild flow are
  still ahead (see the roadmap).

---

## Cross-Cutting Gaps

Each module's own gaps are in the tables above. What follows is the set that
spans modules and cannot be attributed to one of them.

- **Emulation-first verification**: apart from x86_64, AArch64 and RISC-V are
  verified under QEMU; there is no bare-metal bring-up yet (see the roadmap's
  "Real-hardware bring-up" milestone).
- **RISC-V 64 is still partial**: there is no architectural NMI source. The AIA
  IMSIC — the file that receives MSIs — is implemented and *booted*:
  `make check-riscv64-aia-runtime` runs the kernel on `-machine
  virt,aia=aplic-imsic`, where the IMSIC is the external-interrupt controller,
  and the kernel walks its own message path at boot (enable an identity, write
  the message a device would write into its own MSI page, claim it back) because
  nothing on that machine sends an MSI. The PCIe half above it now walks too —
  `make check-riscv64-pci-runtime` boots with a `virtio-net-pci` beside the MMIO
  device and asserts that the ECAM window the device tree names was read and the
  device was found — and `arch/riscv64/pci.rs` programs that device's MSI-X
  table at every boot, which is how the next gap became visible rather than
  silently skipped: **the machine assigned no BAR addresses.** QEMU boots this
  kernel directly, with no firmware to run a PCI resource pass, so every memory
  BAR read back as zero — and an MSI-X table lives in a BAR. The kernel runs
  that pass itself now: the memory window comes from the host bridge's `ranges`,
  `assign_memory_bars` gives each unaddressed memory BAR an aligned address
  inside it and verifies that the device took it, so the boot log reads `BAR
  assigned` and `MSI-X enabled` — which is device MMIO answering. The same
  machine's NIC runs over that bus: `make check-riscv64-pci-runtime` boots with
  *only* a `virtio-net-pci` and asserts the modern transport coming up and the
  network stack running on it. The identities that table delivers belong to that
  driver: it claims them at probe time, the platform programs them into the
  table and unmasks the function once the IMSIC is up, and the receive side is
  then walked once *through the driver's own handler* — the message a device
  writes into the hart's MSI page is claimed and handed to it — because the
  dispatch table had no callers at all, and every device interrupt would have
  been counted as spurious. AArch64 runs the same driver with one difference —
  its BAR is reached through a low alias, because its device window is above the
  range the kernel maps — and its gate boots the same way.
- **Thin userspace ecosystem**: there is no external toolchain and no real
  applications. What is there is more than it looks: the demo's ring-3 payloads
  (`demo-launcher`, its Rust and rust-io variants, and the fault demos) are real
  ELF images which run, make syscalls, read and write files under
  `/data/users/guest/`, and install their own exception handlers — built inside
  the kernel by `src/user/demo/`, not compiled by a toolchain. The shell is
  ring-3 code on all three targets: one program, written once in
  `src/user/demo/shell_payload.rs` and emitted into a section per target, with
  its own banner, prompt, `ls`, `cat`, `cd` and `echo` — so the boot's prompt is
  that program rather than the in-kernel Rust proxy it used to fall back to on
  every machine. The difference is testable rather than nominal: the three
  runtime checks type a command at the prompt and assert the answer, which is
  the only way to tell a shell that reads a line from one that only prints a
  banner.  The init program is ring-3 code on all three targets too, and each
  runtime check asserts the lines it prints as it declares what `/system/rc.d`
  holds.  What is still missing is the layer above *that*: nothing on the
  volume is signed or verified unless its manifest asks for it.
- **Single maintainer**: bus factor = 1; every module is currently held by one
  maintainer.
- **“We do not break userspace” has a handful of subjects, not a population**:
  the frozen payloads make the rule testable for the launcher and the shell on
  all three targets and for the launcher's child on x86_64. The three shells are
  the ones that wait for input, so those runs type at them; the others announce
  what they are and exit. Extending this means *writing* another demo program
  rather than freezing one.
- **A user-access window is not a semaphore**: x86_64's `AC`, AArch64's `PAN`
  and riscv64's `SUM` are per-hart bits, and the guard around a copy sets and
  then clears them. A window that is held *across a block* is therefore at the
  mercy of any other thread that opens and closes its own window while the first
  is waiting — the first thread's access is cleared under it, and the copy
  faults in the kernel. It took a ring-3 console reader to hit this, and the
  read and write paths now stage in kernel memory and hold the window only for
  the copy (`with_staged_input` on the write side, `copy_user_bytes` on the read
  side). The socket send paths still hand the caller's slices to the network
  stack, which can wait on the NIC's completion interrupt, so that is the
  remaining path where the window is held across a block; the invariant the
  guards document is "scoped to a single copy", and those paths do not keep it.
- **Coverage-guided fuzzing runs nightly, not per change**: the boundaries have
  deterministic harnesses as their gate — `tests/parsers/fuzz.rs`, run by
  `make test-parsers` and in CI, drives the ELF loader, the LUKS2 header and
  its scanners, the network packet parsers, and every filesystem image opener
  the tree has (including the MBR/GPT reader) with random bytes and
  structure-aware mutations. They are fixed-seed and bounded, so they catch
  the panics a seed happens to reach; the fuzzer that *searches* is the
  out-of-tree cargo-fuzz package in `fuzz/`, with a target per boundary,
  driven by `.github/workflows/fuzz.yml`. What is still missing is a corpus
  persisted across runs, so each nightly start is from the seedless mutator
  rather than from everything the previous runs found.
- **No reproducible releases**: no tagged releases with reproducible ISO/disk
  images and signed artifacts.

---

## What's Distinct About This Kernel

1. **Many filesystem drivers** — FAT32, exFAT, ext4, F2FS, btrfs, XFS, NTFS,
   ISO 9660, EROFS, SquashFS, and the native SimpleFs.
2. **A native TCP/IP stack** with TLS 1.3, SCTP, DCCP, IPsec, and multicast
   routing — not a port of lwIP/uIP, but a custom
   implementation with TCP congestion control, DNS caching, and DHCP.
3. **Three architecture targets** — x86_64, AArch64, RISC-V 64 — with PAN/SMAP
   on all three.
4. **A Biba integrity model** — a formal multi-level security policy, which is
   rare in a hobby kernel.
5. **Unicode 15.1 NFC/NFD normalization** plus a GB18030 codec.
6. **A TLSF heap allocator** — O(1) bounded-time alloc/free.
7. **`src/user/shared/`** — the userspace runtime lives inside the kernel
   crate, so each syscall wrapper, shell builtin, and ABI record is compiled on
   both sides of the boundary rather than re-implemented per side.
8. **Preemptive multi-threading with guard pages** on all architectures.
9. **NUMA-aware frame allocation, scheduling, and SRAT/FDT discovery** —
   per-node frame allocators with CPU-to-node mapping, NUMA-aware work stealing,
   and topology discovery via ACPI SRAT/SLIT (x86_64) and FDT numa-node-id
   (AArch64, RISC-V).
10. **virtio-gpu accelerated display with the VIRGL 3D protocol** — 2D
    mode-setting and the VIRGL 3D userspace interface, as an alternative to a
    bochs-display device.
11. **MSI/MSI-X on the architectures that have an MSI controller** — vector
    allocation and table programming on x86_64, and the AIA IMSIC with
    per-device identity claims on RISC-V, and the GICv3 ITS with LPIs on
    AArch64.
12. **Per-thread stack canary** — software-implemented canary verification on
    context switch for runtime buffer-overrun detection.
13. **Encryption at rest** — AES-256 XTS, PBKDF2 key derivation, LUKS2 header
    parsing, and a transparent EncryptedBlockDevice wrapper.
14. **Journal replay for ext4/XFS/F2FS** — real disk log recovery: revoke
    blocks, buffer/inode/dquot items, orphan recovery, SIT persistence.
15. **An audit subsystem** — system-call auditing with classified event types,
    a ring buffer, and dedicated audit syscalls.
16. **SCTP** — a full transport layer with a 4-way handshake and CRC32C
    verification.
17. **Hotplug reads** — the PCIe slot-status and hotplug-event reads, and a
    device-removal path in the device manager.  Nothing polls them yet, so a
    slot change is not noticed by a running boot.
18. **POSIX timers** — timer_create/settime/gettime/delete with per-process
    timer management and signal delivery.
19. **An HDA audio controller driver** — Intel HD Audio with CORB/RIRB, codec
    discovery, and stream descriptors.
20. **WireGuard** — Noise_IKpsk2 handshake state machine,
    ChaCha20-Poly1305 transport encryption, and session key management. It is
    not wired to an interface yet; see the network section's gaps.
21. **CPU frequency scaling & power management** — x86_64 MSR P-state driver,
    aarch64/riscv64 device-tree OPP discovery, governors, scheduler-tick
    integration, and cpufreq syscalls.
22. **Memory compression & defragmentation** — a zswap-style compressed page
    cache on reclaim, plus physical-pool compaction that relocates movable user
    frames to coalesce fragmented free ranges; `CompactMemory` (syscall #150).
23. **NMI handling, SMP IRQ load balancing, and interrupt stats** — dedicated
    NMI paths with a handler registry; periodic migration of the hottest
    migratable IRQ; `SystemInfo` type 9 exposing per-CPU/per-vector IRQ, IPI,
    and NMI counts plus load-balancer state.
24. **SimpleFs V4 data reduction & extended attributes** — a persistent xattr
    table, per-file transparent compression, cross-file content dedup with
    mount-time refcount rebuild, and copy-on-write unsharing, all crash-safe
    under V4's two-phase commit.
25. **DCCP (RFC 4340)** — a connection-oriented datagram transport with the
    Request/Response/Ack handshake, extended sequence numbers, feature
    negotiation, CCID 2 congestion control, and a full syscall API.
26. **IPsec (ESP + AH)** — RFC 4303/4302 data-plane transforms with AES-GCM,
    ChaCha20-Poly1305, and HMAC-SHA256-128, in transport and tunnel modes over
    IPv4 and IPv6, with a 64-bit anti-replay window and manual SAD/SPD
    management.
27. **Multicast routing** — an MFC/VIF forwarding engine with RPF and TTL
    gating, IGMPv2/MLDv1 router mode, MRT management syscalls, and a PIM-DM
    control plane under `educational_networking`.
28. **IPv6 edge-case hardening** — path-MTU discovery (RFC 8201), atomic
    fragments (RFC 6946), extension-header order and chain limits (RFC 8200
    §4.1), routing-header type-0 rejection (RFC 5095), and overlapping-fragment
    discard (RFC 5722).
29. **A MAC type-enforcement engine** — mandatory access control beyond Biba:
    security types on subjects and objects, an allow-rule policy with
    first-match and default-deny, a central VFS hook, Process- and Network-class
    checks, exec domain transitions, management syscalls, and MacDenial audit
    records on refusal.
30. **A persistent credential system** — `/data/etc/passwd` and
    `/data/etc/shadow` written back atomically, with the shadow file kept at
    0600.
31. **Descriptor control (#179)** — a POSIX fcntl subset including
    F_GETPIPE_SZ / F_SETPIPE_SZ and per-end O_NONBLOCK.
32. **A persistent block cache** — dirty blocks aged by a scheduler-advanced
    cache clock and written back by the maintenance thread, with `sync` (#180)
    for the on-demand flush.
33. **Device-tree-driven driver probe** — FDT nodes are bound to drivers by
    `compatible` string; virtio-gpu/block/net are all probed from their DT node
    `reg`.
34. **The VIRGL 3D userspace interface (#181-189)** — contexts, 3D resources
    with kernel-managed DMA backing, host transfers, command submission,
    scanout, and a capability report, with the actual rendering executed
    host-side via virglrenderer (plus mock-device wire-format tests).
