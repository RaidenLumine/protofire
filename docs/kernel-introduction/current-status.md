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

| Driver | Type | Status |
|--------|------|--------|
| AHCI (SATA) | Block | Full read/write (DMA, polling) |
| ATA (PIO) | Block | Full read/write |
| VirtIO (block) | Block | Full read/write |
| VirtIO (net) | Network | Full RX/TX |
| VirtIO (GPU) | Display | Full 2D mode-setting (x86_64 PCI + AArch64/RISC-V device-tree MMIO), VIRGL 3D userspace interface (#181-189) |
| NVMe | Block | Full read/write, MSI-X interrupt |
| xHCI | USB host | Driver present |
| USB HID | HID (keyboard) | Driver present |
| USB MSD | Storage | Present; drives the bulk-only transport |
| Serial (UART 16550) | Text I/O | Full duplex |
| PS/2 Keyboard | Input | Full |
| Framebuffer | Display | Linear framebuffer |
| Framebuffer Console | Display | Text rendering |
| HDA (Intel HD Audio) | Audio | CORB/RIRB, codec discovery, stream descriptors |
| PCIe ECAM | Bus | x86_64: full; AArch64/RISC-V: walked, BARs assigned, virtio-net driven |

**Strengths:** driver coverage across storage, network, display, audio, and
input, mostly verified under QEMU.

- **Storage**: AHCI (SATA), ATA PIO, VirtIO, and NVMe provide independent block
  backends; NVMe uses MSI-X for interrupt-driven completion.
- **Network**: the VirtIO network driver is interrupt-driven and multi-queue
  ready.
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
- **Hotplug**: PCIe slot status monitoring and xHCI port status change polling
  via the DeviceManager lifecycle framework.

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
  somebody waits on. What is still missing: **AArch64's PCIe MSI would need a
  GICv3 ITS, and this kernel has no ITS** (its AArch64 interrupt controller
  speaks GICv2 only and refuses to program a v3 in the v2 register layout);
  MSI-X is claimed per device rather than per queue beyond the two the NIC
  uses; and every other PCIe device — NVMe, HDA — is still reached through its
  architecture's own enumeration rather than this one.
- **Verified under QEMU only**: no real-device validation on bare-metal
  hardware yet.

---

### 2. I/O Subsystem

| Component | Status |
|-----------|--------|
| File descriptor table | Full (per-process fd table, dup, dup2, F_DUPFD, close-on-exec) |
| Pipe | Full (anonymous pipe in VFS, fcntl dynamic buffer, O_NONBLOCK) |
| Block cache | Fixed-size LRU, write-through/write-back, prefetch, dirty aging + background write-back |
| Handle table | Generic handle/object framework |
| Console I/O | Global console device, Ctrl-C handling |

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

| Component | Status |
|-----------|--------|
| SimpleFs core (V2/V3) | Full read/write, checksummed (CRC32C) |
| TmpFs | In-memory, full read/write |
| DevFs | Device node listing |
| ProcFs | Process info, runtime state |
| Unicode layer | Unicode 15.1 NFC/NFD, case folding, GB18030, OEM CP |

#### 3.2 External Filesystem Drivers

| Driver | Mode | Features |
|--------|------|----------|
| ext4 | **Read/write** | Journaling (revoke replay, v3 checksum tags), extent tree, dir index |
| F2FS | **Read/write** | Checkpoint (SIT persistence), orphan recovery, atomic CP+SB write |
| XFS v5 | **Read/write with journal replay** | B+tree, CRC32C, v5 superblock, log replay (buffer/inode/dquot items) |
| exFAT | Read/write | VFAT extension |
| FAT32 | Read/write | LFN, OEM code pages, FSInfo accounting |
| BtrFS | Read-only | B-tree traversal |
| NTFS 3.1 | Read-only | MFT parsing, attribute resolution |
| SquashFS 4.0 | Read-only | Multiple compression algorithms |
| ISO 9660 | Read-only | Joliet, Rock Ridge |
| EROFS v1 | Read-only | Compact inode format |

#### 3.3 VFS Layer

| Component | Status |
|-----------|--------|
| VFS core (mount, path resolution, ops) | Full |
| Volume recovery | Transaction undo-log, crash resilience, crash-matrix tests |
| Fault injection matrix | Single- and dual-fault / multi-cycle crash testing |
| Extended-attribute (xattr) table | SimpleFs V4 persistent storage + tmpfs in-memory |
| Transparent file compression | Per-file LZSS/raw chunked compression (reuses the memory codec) |
| Cross-file deduplication | Content-hash shared extents, mount-time refcount rebuild |
| Block backend abstraction | ATA, VirtIO, NVMe backends |

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

| Component | Status |
|-----------|--------|
| AES-256 + AES-XTS | Crypto engine |
| PBKDF2 key derivation | Key stretching for disk encryption |
| EncryptedBlockDevice | Block device encryption wrapper |
| LUKS2 header parser | LUKS2 on-disk format parsing |

---

### 4. CPU Scheduler

| Component | Status |
|-----------|--------|
| Scheduler core | Preemptive round-robin with priority |
| Thread lifecycle | Spawn, exit, terminate, detach |
| Context switch | x86_64, AArch64, RISC-V (per-arch assembly) |
| Process/thread types | States, priorities, credentials, scheduling policies |
| Process groups | Job control, foreground/background |
| SMP discovery | x86_64: ACPI MADT; AArch64: PSCI; RISC-V: FDT CPU nodes and SBI HSM |
| Timer tick | Scheduler quantum management |
| Waker | Thread wakeup notification |
| Scheduler stats | Load average (sampled ring), per-thread CPU ticks, idle tracking, ProcFs integration |
| Priority boosting | Starvation boost: Normal → High after an idle threshold, demote after a short run |
| Work stealing | Cross-CPU load balancing, NUMA-aware victim selection |
| Stack canary | Per-thread random canary, global guard on context switch |
| Power management | CPU frequency scaling (x86_64 MSR P-state driver; aarch64/riscv64 DT OPP range discovery + target tracking), governors, scheduler-tick integration, DTS temperature reading |

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

| Component | Status |
|-----------|--------|
| Physical frame allocator | Dynamic detection via Multiboot2/FDT, bump + free tracking |
| NUMA frame allocators | Per-node allocators (`MAX_NODES`), `set_node_range()`, fallback to node 0 |
| TLSF heap allocator | Bounded heap, fixed free-list table, O(1) alloc/free |
| Page table management | Per-arch tables, identity map, user address spaces, 2 MiB + 1 GiB huge page support |
| Copy-on-Write | Refcounted frames, fault-triggered copy |
| Demand paging | Content store + swap-out (disk-backed) |
| Swap area | Block-device-backed page slots, LIFO free list, magic-based boot-time detection |
| Compressed page cache | Zswap-style zero/RLE/LZSS page compression on reclaim, with raw-store eviction |
| Memory compaction | Frame-pool defragmentation: relocate movable user frames, coalesce free ranges |
| ASID allocator | AArch64 bitmap + CAS, RISC-V bitmap + CAS |
| User address space | Brk heap, ELF loading, guard pages |
| Kernel stack guard | Unmapped page below each kernel stack |

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

| Component | Status |
|-----------|--------|
| x86_64 IDT + exceptions | Full: #PF, #GP, #UD, #DF, timer, IPI |
| x86_64 APIC + IOAPIC | Full: SMP IPI, timer, I/O routing |
| AArch64 exception vectors | EL1 sync/IRQ/FIQ/SError, EL0 sync |
| AArch64 GIC | GICv2 register layout, detection from `GICD_PIDR2`, interrupt routing |
| RISC-V trap handler | U-mode ecall, timer, external interrupts |
| RISC-V PLIC | PLIC initialization from FDT |
| Common interrupt abstraction | `InterruptController` trait |
| Thread exception handling | Page fault recovery, signal delivery |
| PAN/SMAP emulation | AArch64 PSTATE.PAN, x86_64 SMAP, RISC-V SUM |
| MSI/MSI-X programming | Vector allocator and table programming on x86_64; AIA IMSIC on RISC-V |
| NMI handling | x86_64 dedicated vector path, AArch64 SError/FIQ dedicated path, handler registry |
| Interrupt load balancing (SMP) | IOAPIC redirection re-target, GIC SPI affinity, PLIC per-context enable |
| Interrupt stats interface | Per-CPU/per-vector counters, NMI/IPI totals, balancer state (SystemInfo #9) |

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

- **No MSI on AArch64.** The PCIe devices the device-tree machines enumerate
  have MSI-X tables, but routing an MSI on AArch64 needs a GICv3 ITS and this
  kernel has none; its AArch64 interrupt controller implements GICv2 and
  refuses a v3 rather than programming v2 registers at a v3. So AArch64 PCIe
  devices that expect an MSI have no interrupt path yet.
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

| Layer | Protocols | Status |
|-------|-----------|--------|
| **Link** | Ethernet, ARP, device abstraction | Full |
| **Internet** | IPv4, IPv6, ICMP, ICMPv6, IGMP, MLD, NAT, IP options | Full |
| **Transport** | TCP (congestion control, ECN), UDP, SCTP (4-way handshake, CRC32C), DCCP (RFC 4340, CCID 2, full syscall API) | Full |
| **Application** | DHCP, DNS (cache, resolve), mDNS, NTP, PPP | Full |
| **Security** | TLS 1.3 (handshake, record, certificate), IPsec (ESP + AH, SAD/SPD, transport/tunnel) | Full (kernel-side) |
| **VPN** | WireGuard (Noise_IKpsk2 handshake, ChaCha20-Poly1305 transport, key management) | Full |
| **Multicast routing** | MFC/VIF forwarding engine (RPF + TTL gating), IGMPv2/MLDv1 router mode, MRT management API | Full |
| **Raw** | Raw sockets, raw packet | Full |
| **Educational¹** | CSMA/CD, CSMA/CA, STP, IPv4 Options, Mobile IP, RSVP, PIM-DM (flood-and-prune) | Gated |

¹ Gated behind `feature = "educational_networking"`.

#### 7.2 TCP Implementation

| Component | Status |
|-----------|--------|
| Segment handling | Full (segmentation, reassembly, retransmit) |
| Connection table | Full (hash table, state machine) |
| Congestion control | Implemented |
| ECN (Explicit Congestion Notification) | Implemented |
| Timer management | Full (RTO, delayed ACK, keepalive) |
| Window scaling | Included |

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

| Component | Status |
|-----------|--------|
| Pipe | VFS-backed, anonymous, blocking read/write |
| Signal | 43 slots (0-42), including 11 RT signals (32-42); u64 mask, install/enqueue/wait |
| Signal mask | Per-process blocked signal tracking, u64 bitfield |
| Async signal delivery | Signal frame on user stack, arch-specific trampoline, sigreturn; x86_64, AArch64, RISC-V |
| SA_SIGINFO support | siginfo_t delivery (si_signo, si_code, si_pid, si_uid, si_addr, si_value) |
| SA_RESTART support | Automatic syscall restart on signal return, RestartBlock per thread |
| sigsuspend (#135) | Atomic mask swap + thread suspend until signal |
| POSIX timers (#137-140) | timer_create/settime/gettime/delete, per-process timer management, signal delivery on expiry |
| eventfd (#107) | Counter/semaphore mode, EFD_NONBLOCK/EFD_CLOEXEC, poll/epoll integration, write-overflow EAGAIN |
| Event | Event flag synchronization |
| Condition variable | Blocking wait/wake |
| Mutex | Blocking mutex |
| Semaphore | Counting semaphore |
| Spinlock | IRQ-safe spinlock |
| Shell pipeline | Command piping with process groups |

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

| Component | Status |
|-----------|--------|
| Biba integrity model | System > High > Medium > Low |
| Zone-aware DAC | System (/system), Apps (/apps), Data (/data) zones; credential store carved out of the guest-owned data zone |
| Security descriptors | Per-object security labels |
| User/group database | `/data/etc/passwd`, `/data/etc/shadow` |
| Process security token | Per-thread credentials |
| Access helpers | Permission checking on VFS ops |
| SHA-256 integrity | Launch payload hash verification (manifest_sha256 / entry_sha256) |
| PAN/SMAP | Kernel-user memory isolation |
| Stack canary | Per-thread random canary, stack verification on context switch |
| Audit subsystem | Audit event types (Syscall, FileOp, Process, Network, Auth), fixed-size ring buffer, syscall entry/exit hooks, AuditSetEnable (#143) and AuditReadLog (#144) syscalls |

**Strengths:** a formal multi-level security policy and mandatory access
control that are unusual in a hobby kernel.

- **Biba integrity model**: a formal information-flow policy (System > High >
  Medium > Low).
- **MAC type-enforcement engine**: security types on subjects and objects, an
  allow-rule policy enforced at central VFS checkpoints, Process-class
  (ptrace/signal) and Network-class checks, exec domain transitions, management
  syscalls (#175-178), and MacDenial audit records on refusal.
- **Zone-aware DAC**: segments the filesystem into regions with different trust
  levels (`/system` read-only, `/apps` read-only and executable, `/data`
  writable). User home directories live under `/data/users/<user>`, not in a
  zone of their own.
- **Persistent credentials**: `/data/etc/passwd` and `/data/etc/shadow` written
  back atomically, with the shadow file kept at 0600.
- **Service authorization**: a privileged rc.d declaration names an account that
  has to resolve in the user database before the service runs, and the grant or
  refusal is audited; the token it runs under carries that account's identity.
- **Service security declarations**: a `security = "guest" | "admin" | "system"`
  key in an rc.d service definition selects the token the started program runs
  under (`ServiceSecurity::security_token()`); a definition that declares
  nothing keeps the guest default.
- **Code integrity**: SHA-256 over the launch manifest and payload, plus
  optional detached signatures verified against trusted public keys under
  `/system/trusted-keys`; a seccomp (#129) syscall filter for process
  sandboxing; PAN/SMAP prevents kernel access to user memory outside an
  explicit window.
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

| Component | Status |
|-----------|--------|
| Syscall table | Numbered slots; the public count is derived from the highest enum discriminant, not written down in this document |
| Dispatch engine | Context-aware dispatch with action return |
| User memory validation | `validate_user_mapping()` + `copy_user_bytes()` |
| Shared wrappers (`src/user/shared/syscall.rs`) | Typed wrappers plus raw entry points |
| ABI types | Wire-format records, syscall encodings |
| Per-category handler files | fs, network, process, diagnostic, tls, filter, io_uring, ptrace, etc. |
| Syscall profiling | Per-syscall counters (optional feature) |

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
| Interrupt controller | APIC + IOAPIC | GICv2 (a GICv3 is detected and refused) | PLIC |
| Timer | PIT (IRQ0 → LAPIC 0) | Generic timer (per-core PPI 30) | CLINT timer |
| SMP | Full (MADT + AP bringup; the tick is the boot CPU's) | Full (PSCI + GIC SGI) | Full (SBI HSM + per-hart vector, timer, and PLIC context; a cross-hart wake waits for the target's tick) |
| Context switch | Full | Full | Full |
| PAN/SMAP | SMAP (stac/clac) | PSTATE.PAN (set/clear) | SUM (sstatus) |
| MSI/MSI-X | Full (vector allocator + table programming) | None: PCIe MSI would need a GICv3 ITS, which this kernel does not have | AIA IMSIC; the PCIe virtio-net driver claims its device's identities |
| PCIe | Full ECAM | Basic probing | Basic probing |
| ASID allocator | — | Full (bitmap + CAS) | Full (bitmap + CAS) |
| FDT parsing | — | Full | Full |
| RTC | — | Full (from FDT) | Full |
| Serial | Full (UART 16550) | Full (UART 16550) | UART 16550 (SBI fallback) |
| NUMA discovery | Full (ACPI SRAT/SLIT) | Full (FDT numa-node-id, distance-map) | Full (FDT numa-node-id, distance-map) |
| CPU frequency scaling | Full (MSR P-state) | Full (DT OPP) | Full (DT OPP) |

### Shared User Runtime (`src/user/shared/`)

| Module | Purpose |
|--------|---------|
| `syscall.rs` | Typed syscall wrappers |
| `dispatch.rs` | Shell builtin dispatch |
| `commands/` | Subcommand implementations |
| `signal.rs` | Signal handling API (u64 mask, sigsuspend, SA_SIGINFO) |
| `passwd.rs` | Password file parsing |
| `jobs.rs` | Job control logic |
| `abi/` | ABI type definitions |
| `runtime.rs` | Arch syscall wrappers, brk allocator, args |

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

| Category | What it covers |
|----------|----------------|
| Unit tests (in-module) | Per-module behaviour, registered by feature |
| Integration tests | Filesystem, I/O, memory, process, network, syscall areas |
| Fault injection | SimpleFs single- and dual-fault matrix |
| Recovery tests | Crash and replay scenarios |
| Concurrency tests | Scheduler, condvar, console, keyboard |
| Parser fuzz harnesses | Deterministic, in-tree, run by `make test-parsers` |
| virtio-gpu layout tests | Struct size/layout + command wire-format (mock device) |
| CI workflow | fmt, check, build, clippy on every configuration, every static gate and ratchet, and the boots |
| Verification gates | P0-P3: fmt → test → cross-build → clippy, plus the optional QEMU smokes |
| ABI number snapshot | `tests/syscall/abi_golden.rs`: any change to a number's name fails, and a change in the experimental range has to bump the ABI minor in the same commit |

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
  `alloc_profiler`, `fault_profiler`, `educational_networking`
- **Release profile:** `panic = "abort"`, `opt-level = "s"`, `lto = true`,
  `codegen-units = 1`

---

## Weaknesses & Known Gaps

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
  banner. What is still missing is the layer above *that*: the manifests still
  carry a `host_proxy` entry nothing reaches, the `/init.elf` in the system zone
  is a stub that exits, and nothing on the volume is signed or verified unless
  its manifest asks for it.
- **Single maintainer**: bus factor = 1; every module is currently held by one
  maintainer.
- **The experimental syscalls are unfrozen**: everything above the stable
  boundary is classified Experimental.
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
- **No coverage-guided fuzzing**: the boundaries have deterministic harnesses
  instead — `tests/parsers/fuzz.rs`, run by `make test-parsers` and in CI,
  drives the ELF loader, the LUKS2 header and its scanners, the network packet
  parsers, and every filesystem image opener the tree has (including the
  MBR/GPT reader) with random bytes and structure-aware mutations. What is
  missing is the fuzzer that *searches*: these are fixed-seed and bounded, so
  they catch the panics a seed happens to reach, not the ones a mutation chain
  would. `docs/fmts/testing.md` describes them the same way.
- **No reproducible releases**: no tagged releases with reproducible ISO/disk
  images and signed artifacts.

---

## What's Distinct About This Kernel

1. **Many filesystem drivers** — FAT32, exFAT, ext4, F2FS, btrfs, XFS, NTFS,
   ISO 9660, EROFS, SquashFS, and the native SimpleFs.
2. **A native TCP/IP stack** with TLS 1.3, SCTP, DCCP, IPsec, multicast
   routing, and WireGuard VPN — not a port of lwIP/uIP, but a custom
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
    per-device identity claims on RISC-V. AArch64 has a GICv2 controller and no
    ITS, so it has no PCIe MSI path.
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
17. **Hotplug support** — PCIe slot status monitoring and xHCI port status
    change polling via the DeviceManager lifecycle.
18. **POSIX timers** — timer_create/settime/gettime/delete with per-process
    timer management and signal delivery.
19. **An HDA audio controller driver** — Intel HD Audio with CORB/RIRB, codec
    discovery, and stream descriptors.
20. **WireGuard VPN** — Noise_IKpsk2 handshake state machine,
    ChaCha20-Poly1305 transport encryption, session key management.
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
