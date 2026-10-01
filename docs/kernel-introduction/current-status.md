# Current Status

> **Last updated:** 2026-09-30 **Codebase:** 653 Rust files, ~228,000 lines of
> Rust in `src/` (681 files and ~240,200 lines counting `tests/`)
> **Targets:** x86_64 (full), AArch64 (full), RISC-V 64 (partial)

---

## Subsystem Evaluation

> The number after each subsystem is that subsystem's own assessment of how
> much of its intended behaviour is implemented.  It is not a measured pass
> rate, and it says nothing about whether the behaviour has been demonstrated
> on a booting machine.
>
> Other figures here are maintained by hand, and two of them are marked
> unverified because the set they count is not defined anywhere: the "40 network
> syscalls" in §7.3 and the per-architecture code sizes under Architecture
> Support.  A count whose set is undefined cannot be rechecked, by a person or
> by the `check-docs` gate.

### 1. Device Drivers (87%)

| Driver | Lines | Type | Status |
|--------|-------|------|--------|
| AHCI (SATA) | 1,100+ | Block | Full read/write (DMA, polling) |
| ATA (PIO) | 3,554 | Block | Full read/write |
| VirtIO (block) | 1,200+ | Block | Full read/write |
| VirtIO (net) | 1,500+ | Network | Full RX/TX |
| VirtIO (GPU) | 1,200+ | Display | Full 2D mode-setting (x86_64 PCI + AArch64/RISC-V device-tree MMIO), VIRGL 3D userspace interface (#181-189) |
| NVMe | 500+ | Block | Full read/write, MSI-X interrupt |
| xHCI | 1,657 | USB host | Driver present |
| USB HID | 329 | HID (keyboard) | Driver present |
| Serial (UART 16550) | 2,000+ | Text I/O | Full duplex |
| PS/2 Keyboard | 841 | Input | Full |
| Framebuffer | 273 | Display | Linear framebuffer |
| Framebuffer Console | 692 | Display | Text rendering |
| HDA (Intel HD Audio) | 450+ | Audio | CORB/RIRB, codec discovery, stream descriptors |
| PCIe ECAM | Arch-specific | Bus | x86_64: full; AArch64/RISC-V: window walked, BARs assigned |

**Strengths:** Driver coverage across storage, network, display, audio, and input, mostly verified under QEMU.

- **Storage**: AHCI (SATA), ATA PIO, VirtIO, and NVMe provide four independent block backends; NVMe uses MSI-X for interrupt-driven completion.
- **Network**: VirtIO network driver is production-quality (multi-queue ready, interrupt-driven).
- **Display**: VirtIO GPU provides accelerated 2D mode-setting on the VirtIO MMIO transport, integrated directly with the framebuffer console (no separate bochs-display device); the **VIRGL 3D userspace interface** (syscalls #181-189) exposes the virtio-gpu VIRGL protocol to a userspace renderer — context create/destroy, 3D resources with kernel-managed DMA backing, host transfers, command submission, scanout — with actual 3D rendering executed host-side via virglrenderer.
- **Device-tree-driven driver probe**: `collect_dt_nodes` builds a node table (compatible/reg/interrupts/phandle/status) and `Driver::compatible_strings()`/`probe_dt()` bind nodes to drivers in `DriverManager::probe_dt_devices`; virtio-gpu/block/net are all probed from their DT node `reg`, making the GPU available on AArch64/RISC-V.
- **MSI/MSI-X**: capability parsing and vector programming available across all drivers (NVMe, VirtIO PCI).
- **Audio**: Intel HDA driver provides controller initialization, CORB/RIRB engine, codec discovery, and stream descriptor configuration.
- **Hotplug**: PCIe slot status monitoring and xHCI port status change polling via the DeviceManager lifecycle framework.

**Weaknesses:**

- **USB not end-to-end**: xHCI and USB HID are only "driver present"; USB storage/keyboard is not fully usable yet.
- **HDA not surfaced to userspace**: audio has only the controller-level interface; no usable userspace stream interface yet.
- **PCIe devices are addressable but not yet driven** on the two device-tree
  machines: the ECAM walk finds them, the kernel's own resource pass gives
  their memory BARs addresses out of the window the host bridge's `ranges`
  describes (no firmware ran one), and on riscv64 the MSI-X table inside one is
  programmed through the IMSIC and read back at every boot.  What is missing is
  the driver above that: the demo's networking is on virtio-*mmio*, and
  `drivers/virtio_net.rs`'s PCI path is still AArch64-only.  AArch64's own MSI
  side would need a GICv3 ITS, which this kernel does not implement.
- **Verified under QEMU only**: no real-device validation on bare-metal hardware yet.

---

### 2. I/O Subsystem (82%)

| Component | Lines | Status |
|-----------|-------|--------|
| File descriptor table | 300+ | Full (per-process fd table, dup, dup2, F_DUPFD, close-on-exec) |
| Pipe | 650+ | Full (anonymous pipe in VFS, fcntl dynamic buffer, O_NONBLOCK) |
| Block cache | 1,200+ | LRU (128 entries), write-through/write-back, prefetch, dirty aging + background write-back |
| Handle table | 300+ | Generic handle/object framework |
| Console I/O | 783 | Global console device, Ctrl-C handling |

**Strengths:** Complete file-descriptor and pipe semantics with runtime pipe and block-cache management.

- **fd semantics**: inheritance across spawn, close-on-exec, and dup.
- **Pipes**: VFS-backed, using the same read/write path as regular files.
- **fcntl (#179)**: F_DUPFD / F_GETFD / F_SETFD / F_GETFL / F_SETFL, plus **F_GETPIPE_SZ / F_SETPIPE_SZ** — the pipe buffer can be resized at runtime (page-rounded, capped at 1 MiB, buffered data preserved); a per-end **O_NONBLOCK** flag makes empty reads / full writes return EAGAIN instead of blocking.
- **Persistent block cache**: every dirty block is stamped with a cache-clock tick advanced by the scheduler; blocks dirty for more than 6 seconds (600 ticks) are written back automatically every 3 seconds, and **sync (#180)** provides the on-demand full flush (POSIX sync(2)) — write-back persists without an explicit fsync.

**Weaknesses:**

- **Small block cache**: LRU capped at 128 entries; limited hit rate under large working sets.
- **I/O paths verified under emulation only**: no latency/throughput testing on real disks or SSDs.

---

### 3. Virtual File System (91%)

The VFS is the most substantial subsystem at **62,700+ lines across 118 files**.

#### 3.1 Native Filesystem

| Component | Lines | Status |
|-----------|-------|--------|
| SimpleFs core (V2/V3) | 6,557 | Full read/write, checksummed (CRC32C) |
| TmpFs | 833 | In-memory, full read/write |
| DevFs | 327 | Device node listing |
| ProcFs | 828 | Process info, runtime state |
| Unicode layer | 4,579 | Unicode 15.1 NFC/NFD, case folding, GB18030, OEM CP |

#### 3.2 External Filesystem Drivers

| Driver | Lines | Mode | Features |
|--------|-------|------|----------|
| ext4 | 3,626 | **Read/write** | Journaling (revoke replay, v3 checksum tags), extent tree, dir index |
| F2FS | 3,594 | **Read/write** | Checkpoint (SIT persistence), orphan recovery, atomic CP+SB write |
| XFS v5 | 3,829 | **Read/write with journal replay** | B+tree, CRC32C, v5 superblock, log replay (buffer/inode/dquot items) |
| exFAT | 3,089 | Read/write | VFAT extension |
| BtrFS | 2,899 | Read-only | B-tree traversal |
| FAT32 | 2,794 | Read/write | LFN, OEM code pages, FSInfo accounting |
| NTFS 3.1 | 2,684 | Read-only | MFT parsing, attribute resolution |
| SquashFS 4.0 | 1,446 | Read-only | 5 compression algorithms |
| ISO 9660 | 1,475 | Read-only | Joliet, Rock Ridge |
| EROFS v1 | 1,219 | Read-only | Compact inode format |

#### 3.3 VFS Layer

| Component | Lines | Status |
|-----------|-------|--------|
| VFS core (mount, path resolution, ops) | 1,947 | Full |
| Volume recovery | 1,163 | Transaction undo-log, crash resilience, crash-matrix tests |
| Fault injection matrix | 1,245 | Comprehensive single- + dual-fault / multi-cycle crash testing |
| Extended-attribute (xattr) table | 315 | SimpleFs V4 persistent storage + tmpfs in-memory |
| Transparent file compression | 132+ | Per-file LZSS/raw chunked compression (reuses the memory codec) |
| Cross-file deduplication | 207+ | Content-hash shared extents, mount-time refcount rebuild |
| Block backend abstraction | ~2,500 | ATA, VirtIO, NVMe backends |

**Strengths:** 11 filesystem drivers (4 writable), a crash-safe native FS, and encryption at rest.

- **Multiple filesystems**: ext4, F2FS, and XFS support full journal replay from real disk; exFAT and FAT32 are read/write; btrfs/NTFS/SquashFS/ISO 9660/EROFS are read-only.
- **Unicode 15.1**: full NF C/D normalization and GB18030 codec.
- **Crash safety**: SimpleFs uses undo-log transactions and two-phase commit.
- **Encryption at rest**: EncryptedBlockDevice provides AES-256 XTS disk encryption, LUKS2 compatible, PBKDF2 key derivation, transparently layered under any filesystem.

**Weaknesses:**

- **Many read-only drivers**: btrfs, NTFS, SquashFS, ISO 9660, and EROFS are read-only; write support is a mid-term roadmap goal.
- **Journal replay verified on emulated disks**: coverage of real-corruption edge cases is limited.

**SimpleFs V4 data-reduction format** (inherits V3's persistent security descriptors + `pending_commit` two-phase commit):

- **Extended attributes**: persist per-inode in active/shadow xattr-table slots flushed in the same two-phase commit as the inode/dirent tables — both SimpleFs and tmpfs support `setxattr`/`getxattr`/`listxattr`/`removexattr` semantics (syscalls #151-154).
- **Transparent per-file compression**: replaces a file's extent with a chunked encoded stream (each 4 KiB chunk encoded as zero/RLE/LZSS with a raw incompressible fallback), keeps `size` as the logical length, and decompresses only intersecting chunks on read; toggled via `SetFileFlags` (#155).
- **Cross-file deduplication**: merges identical-content files onto a single shared extent; refcounts are rebuilt at mount from the on-disk `DEDUPED` markers, overwrites/deletes unshare via copy-on-write, and an extent is freed only when its last reference goes away; both features are surfaced through `GetFileFlags` (#156).

#### 3.4 Encryption at Rest

| Component | Lines | Status |
|-----------|-------|--------|
| AES-256 + AES-XTS | 500+ | Crypto engine (kernel/crypto.rs) |
| PBKDF2 key derivation | 100+ | Key stretching for disk encryption |
| EncryptedBlockDevice | 200+ | Block device encryption wrapper (fs/crypt_device.rs) |
| LUKS2 header parser | 300+ | LUKS2 on-disk format parsing (fs/luks2.rs) |

---

### 4. CPU Scheduler (90%)

| Component | Lines | Status |
|-----------|-------|--------|
| Scheduler core | 1,200+ | Preemptive round-robin with priority |
| Thread lifecycle | 1,500+ | Spawn, exit, terminate, detach |
| Context switch | 600+ | x86_64, AArch64, RISC-V (per-arch assembly) |
| Process/thread types | 800+ | States, priorities, credentials, scheduling policies |
| Process groups | 400+ | Job control, foreground/background |
| SMP discovery | 300+ | x86_64: ACPI MADT AP bringup; RISC-V: FDT CPU node |
| Timer tick | 200+ | Scheduler quantum management |
| Waker | 150+ | Thread wakeup notification |
| Scheduler stats | 200+ | Load average (1s samples, 300-entry ring), per-thread CPU ticks, idle tracking, ProcFs integration |
| Priority boosting | 100+ | Starvation boost: Normal → High after 50 ticks idle, demote after 8 ticks |
| Work stealing | 80+ | Cross-CPU load balancing, NUMA-aware victim selection |
| Stack canary | 60+ | Per-thread random canary, global guard on context switch |
| Power management | 400+ | CPU frequency scaling (x86_64 MSR P-state driver; aarch64/riscv64 DT OPP range discovery + target tracking), 5 governors, scheduler-tick integration, DTS temperature reading |

**Strengths:** Preemptive multi-threaded scheduling with NUMA-aware load balancing and runtime stack protection.

- **Scheduling policies**: `SchedDefault` (round-robin), `SchedFifo` (run-to-completion), `SchedRoundRobin` (explicit RR); `START_SUSPENDED` flag and starvation protection via priority boosting.
- **Work stealing**: cross-CPU load balancing with NUMA-aware victim selection (higher score for same-node steals).
- **Kernel stack protection**: guard pages on all architectures; the `dying_thread` pattern prevents Arc leaks on context switch.
- **Per-thread stack canary**: a random 64-bit canary written to the kernel stack bottom at thread creation and verified on every context switch back to the scheduler.
- **CPU frequency scaling**: on x86_64 via IA32_PERF_CTL/PERF_STATUS MSRs (CPUID leaf 0x16 + PLATFORM_INFO detection, read-only fallback on AMD), governor policy (performance/powersave/ondemand/schedutil/userspace) driven at 1 Hz from the scheduler tick, temperature readable from IA32_PACKAGE_THERM_STATUS; AArch64 and RISC-V discover their range from device-tree OPP tables (`operating-points-v2` phandles / legacy `operating-points` tuples).

**Weaknesses:**

- **ARM/RISC-V frequency scaling not applied**: AArch64/RISC-V only track the requested target in software; real frequency switching needs a platform clock/firmware interface (SCMI, common-clock, SBI CPPC) that is not yet wired.
- **Load balancing lacks real-load validation**: SMP/NUMA scenarios are mostly tested under QEMU.

---

### 5. Memory Management (93%)

| Component | Lines | Status |
|-----------|-------|--------|
| Physical frame allocator | 800+ | 512 MiB pool (dynamic detection via Multiboot2/FDT), bump + BTreeMap free tracking |
| NUMA frame allocators | 120+ | 8 per-node allocators (MAX_NODES), `set_node_range()`, fallback to node 0 |
| TLSF heap allocator | 1,200+ | 16 MiB, 640 free lists, O(1) alloc/free |
| Page table management | 1,500+ | Per-arch tables, identity map, user address spaces, 2 MiB + 1 GiB huge page support |
| Copy-on-Write | 400+ | Refcounted frames, fault-triggered copy |
| Demand paging | 500+ | Content store + swap-out (disk-backed) |
| Swap area | 350+ | Block-device-backed page slots, LIFO free list, magic-based boot-time detection |
| Compressed page cache | 200+ | Zswap-style zero/RLE/LZSS page compression on reclaim, 16 MiB budget with raw-store eviction |
| Memory compaction | 250+ | Frame-pool defragmentation: relocate movable user frames, coalesce free ranges |
| ASID allocator | 250+ | AArch64 bitmap + CAS, RISC-V bitmap + CAS (65536 ASIDs) |
| User address space | 600+ | Brk heap, ELF loading, guard pages |
| Kernel stack guard | 100+ | Unmapped page below each kernel stack |

**Strengths:** Covers the major virtual-memory features, plus NUMA, disk-backed swap, compression, and defragmentation.

- **TLSF allocator**: bounded 2^32 heap with O(1) allocation, 640 free lists.
- **Virtual memory**: CoW fork + demand paging with swap-out, automatic 2 MiB / 1 GiB huge-page selection, kernel stack guard pages on all threads; mlock/munlock (#131-132) and madvise (#133).
- **NUMA**: up to 8 per-node frame allocators, CPU-to-node mapping (`numa_node_id`), automatic topology discovery (ACPI SRAT/SLIT on x86_64; FDT numa-node-id / distance-map on AArch64 and RISC-V); a default single-node topology always works when no NUMA hardware is detected.
- **Disk-backed swap**: `probe_device()` checks for the `ADASWAP` magic signature and `maybe_init_swap()` activates swap automatically at boot.
- **Memory compression & compaction**: zswap-style zero/RLE/LZSS compression (16 MiB budget) and physical-pool defragmentation, exposed via the `CompactMemory` syscall (#150).

**Weaknesses:**

- **Fixed capacity ceilings**: kernel TLSF heap is fixed at 16 MiB and the physical pool defaults to 512 MiB — limited for large workloads.
- **No ASID/PCID-level TLB tagging on x86_64**: context switches rely on TLB invalidation.
- **Swap-out/compression verified under emulation only**: real memory-pressure scenarios are not covered.

---

### 6. Interrupt & Exception Handling (93%)

| Component | Lines | Status |
|-----------|-------|--------|
| x86_64 IDT + exceptions | 500+ | Full: #PF, #GP, #UD, #DF, timer, IPI |
| x86_64 APIC + IOAPIC | 211 | Full: SMP IPI, timer, I/O routing |
| AArch64 exception vectors | 839 | EL1 sync/IRQ/FIQ/SError, EL0 sync |
| AArch64 GIC | 471 (in arch mod) | GICv2/v3 detection from FDT, interrupt routing |
| RISC-V trap handler | 550 | U-mode ecall, timer, external interrupts |
| RISC-V PLIC | 440 (in arch mod) | PLIC initialization from FDT |
| Common interrupt abstraction | 137 | `InterruptController` trait |
| Thread exception handling | 401 | Page fault recovery, signal delivery |
| PAN/SMAP emulation | 500+ | AArch64 PSTATE.PAN, x86_64 SMAP, RISC-V SUM |
| MSI/MSI-X programming | 350+ | Vector allocator, MSI/MSI-X table entry programming (x86_64, AArch64 GIC ITS) |
| NMI handling | 130+ | x86_64 vector-2 dedicated path, AArch64 SError/FIQ dedicated path, handler registry |
| Interrupt load balancing (SMP) | 250+ | IOAPIC redirection re-target, GIC SPI affinity, PLIC per-context enable |
| Interrupt stats interface | 200+ | Per-CPU/per-vector counters, NMI/IPI totals, balancer state (SystemInfo #9) |

**Strengths:** Architecture-complete exception handling across all three targets, with PAN/SMAP emulation, MSI/MSI-X, NMI, and load balancing.

- **Exception handling**: complete on all three targets; double-fault handling on x86_64; the AArch64 vector table properly classifies synchronous exceptions, IRQs, FIQs, and SErrors; PAN/SMAP implemented correctly (the `asm nomem` fix was deployed).
- **MSI/MSI-X**: vector allocator + table programming on x86_64, and on AArch64 via the GICv3 ITS controller (command queue, device/collection tables, interrupt translation, LPI configuration); NVMe and VirtIO PCI modern transport use MSI-X.
- **NMI handling**: dedicated minimal path for x86_64 vector 2 and the AArch64 SError/FIQ vectors, with a handler registry (`kernel::nmi`) that works across all three architectures.
- **Softirq/bottom-half**: 32 vectors, AtomicU32 pending mask, integrated into the scheduler loop + all 3 arch trap dispatchers.
- **Interrupt load balancing (SMP)**: runs every 2 s from the scheduler tick, migrating the hottest migratable IRQ to the idlest CPU — x86_64 IOAPIC redirection, AArch64 GIC SPI affinity, RISC-V PLIC per-context enable.
- **Interrupt stats**: `SystemInfo` type 9 exposes per-CPU/per-vector IRQ counts, IPI/NMI/spurious totals, and load-balancer state.

**Weaknesses:**

- **No MSI/MSI-X on RISC-V**: the AIA is not wired; interrupts still go through the PLIC.
- **No architectural NMI source on RISC-V**: the S-mode dispatch entry stays dormant (needs an M-mode or `smnmi` path).
- **GIC/PLIC verified under emulation only**: no real-hardware routing or latency testing.

---

### 7. Network Stack (89%)

The network stack is the second-largest subsystem at **40,809 lines across 81 files** plus **TLS 1.3 (3,224 lines across 4 files)** with a ring3 userspace API (#121).

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

40 network syscalls defined; 35 have wrappers in the shared user library (`src/user/shared/`).

**Strengths:** A complete, native (non-lwIP) TCP/IP stack with transport-layer extensions and in-kernel security protocols.

- **Protocol coverage**: link (Ethernet, ARP), internet (IPv4/IPv6/ICMP/IGMP/MLD/NAT), transport (TCP with congestion control + ECN, UDP, SCTP, DCCP), application (DHCP, cached DNS, mDNS, NTP, PPP).
- **IPsec**: ESP + AH with AES-GCM / ChaCha20-Poly1305 AEAD and HMAC-SHA256, both transport and tunnel modes, SAD/SPD managed manually through dedicated syscalls.
- **Multicast routing**: MFC/VIF forwarding engine (RPF + TTL gating), IGMPv2/MLDv1 router mode, MRT management API, plus a PIM-DM flood-and-prune control plane under `educational_networking`.
- **IPv6 hardening**: path-MTU discovery (RFC 8201, with TX fragmentation), atomic fragments (RFC 6946), extension-header order and chain-length limits (RFC 8200 §4.1), routing-header type-0 rejection (RFC 5095), overlapping-fragment discard (RFC 5722).
- **TLS 1.3**: implemented as a kernel module — unusual, and potentially useful for secure bootstrapping.

**Weaknesses:**

- **Only 35 of 40 network syscalls have shared-library wrappers**.
- **In-kernel TLS has no trust framework**: certificate and trust-anchor management is still minimal.
- **Educational protocols are feature-gated**: CSMA/CD, STP, Mobile IP, RSVP, PIM-DM, etc. compile only under `educational_networking`.
- **Performance not benchmarked**: throughput and concurrency baselines (multi-core, load-balanced) have yet to be established.

---

### 8. IPC / Synchronization (92%)

| Component | Lines | Status |
|-----------|-------|--------|
| Pipe | 543 | VFS-backed, anonymous, blocking read/write |
| Signal | 600+ | 43 slots (0-42), 11 RT signals (32-42), u64 mask, install/enqueue/wait |
| Signal mask | 150+ | Per-process blocked signal tracking, u64 bitfield |
| Async signal delivery | 200+ | Signal frame on user stack, arch-specific trampoline, sigreturn; x86_64, AArch64, RISC-V |
| SA_SIGINFO support | 80+ | siginfo_t delivery (si_signo, si_code, si_pid, si_uid, si_addr, si_value) |
| SA_RESTART support | 100+ | Automatic syscall restart on signal return, RestartBlock per thread |
| sigsuspend (#135) | 60+ | Atomic mask swap + thread suspend until signal |
| POSIX timers (#137-140) | 300+ | timer_create/settime/gettime/delete, per-process timer management, signal delivery on expiry |
| eventfd (#107) | 130+ | Counter/semaphore mode, EFD_NONBLOCK/EFD_CLOEXEC, poll/epoll integration, write-overflow EAGAIN |
| Event | 100+ | Event flag synchronization |
| Condition variable | 200+ | Blocking wait/wake |
| Mutex | 150+ | Blocking mutex |
| Semaphore | 100+ | Counting semaphore |
| Spinlock | 100+ | IRQ-safe spinlock |
| Shell pipeline | 200+ | Command piping with process groups |

**Strengths:** Complete synchronization primitives and signal machinery, including the POSIX signal interaction model.

- **Synchronization primitives**: mutex, semaphore, condvar, event, and IRQ-safe spinlock are complete; eventfd (#107) provides full Linux-style counter/semaphore semantics (`EFD_SEMAPHORE`/`EFD_NONBLOCK`/`EFD_CLOEXEC`, write-overflow `EAGAIN`) integrated with `poll`/`epoll`/`io_uring` readiness probes.
- **Signals**: 43 slots (0-42), 11 RT signals (32-42) carrying `siginfo_t`; SA_SIGINFO with per-architecture `ucontext_t`; SA_RESTART rewinds the interrupted instruction pointer at syscall dispatch boundaries (2 bytes on x86_64 `int 0x80`, 4 bytes on AArch64 `svc #0`, 4 bytes on RISC-V `ecall`) and `restart_syscall` (#136) re-executes the interrupted call; sigsuspend (#135) atomically swaps the mask and suspends; POSIX timers (#137-140) deliver signals on expiry via the scheduler tick.
- **Async signal delivery**: signal frame injected on the user stack on all three architectures, with arch-specific trampoline and sigreturn.
- **Shell pipelines**: `cmd1 | cmd2` with process groups.

**Weaknesses:**

- **Limited IPC shapes**: IPC relies mainly on pipes, signals, eventfd/mq; there is no standardized shared-memory IPC API (shm remains a purpose-specific syscall).
- **Contention scenarios not benchmarked**: lock contention and signal storms lack stress baselines.

---

### 9. Security & Access Control (92%)

| Component | Lines | Status |
|-----------|-------|--------|
| Biba integrity model | 200+ | System > High > Medium > Low |
| Zone-aware DAC | 300+ | System (/system), Apps (/apps), Data (/data) zones; credential store carved out of the guest-owned data zone |
| Security descriptors | 200+ | Per-object security labels |
| User/group database | 300+ | `/data/etc/passwd`, `/data/etc/shadow` |
| Process security token | 165 | Per-thread credentials |
| Access helpers | 150+ | Permission checking on VFS ops |
| SHA-256 integrity | 100+ | Launch payload hash verification (manifest_sha256 / entry_sha256) |
| PAN/SMAP | 500+ | Kernel-user memory isolation |
| Stack canary | 60+ | Per-thread random canary, stack verification on context switch |
| Audit subsystem | 300+ | Audit event types (Syscall, FileOp, Process, Network, Auth), ring buffer (8192 entries), syscall entry/exit hooks, AuditSetEnable (#143) and AuditReadLog (#144) syscalls |

**Strengths:** A formal multi-level security policy and mandatory access control that are rare in hobby kernels.

- **Biba integrity model**: a formal information-flow policy (System > High > Medium > Low).
- **MAC type-enforcement engine** (SELinux/AppArmor equivalent): security types on subjects and objects, an allow-rule policy enforced at central VFS checkpoints, Process-class (ptrace/signal) and Network-class checks, exec domain transitions, management syscalls (#175-178), and MacDenial audit records on refusal.
- **Zone-aware DAC**: segments the filesystem into regions with different trust
  levels (`/system` read-only, `/apps` read-only and executable, `/data`
  writable).  User home directories live under `/data/users/<user>`, not in a
  zone of their own.
- **Persistent credentials**: `/data/etc/passwd` and `/data/etc/shadow` written back atomically, with the shadow file kept at 0600.
- **Service authorization**: a privileged rc.d declaration names an account that has to resolve in
  the user database before the service runs, and the grant or refusal is audited; the token it runs
  under carries that account's identity.
- **Service security declarations**: a `security = "guest" | "admin" | "system"`
  key in an rc.d service definition selects the token the started program runs
  under (`ServiceSecurity::security_token()`); a definition that declares
  nothing keeps the guest default.
- **Code integrity**: SHA-256 over the launch manifest and payload, plus
  optional detached Lamport-sha256 signatures verified against trusted public
  keys under `/system/trusted-keys`; seccomp (#129) syscall filter for process
  sandboxing; PAN/SMAP prevents kernel speculative access to user memory.
- **Stack canary**: a random 64-bit canary per thread, verified by `check_stack_canary()` before each context switch back to the scheduler.
- **Audit subsystem**: classified event types (Syscall, FileOp, Process, Network, Auth, MacDenial), a ring buffer for record storage, and dedicated syscalls (AuditSetEnable #143 / AuditReadLog #144).  The ring buffer is installed during kernel initialisation, before anything can produce a record — the buffer has to exist or `emit_record` drops what it is handed — and a privileged service declaration is audited there.

**Weaknesses:**

- **Default allow**: until a MAC policy is loaded, the default is to allow; deny-by-default requires an explicit policy.
- **Audit log is memory-only in practice**: the ring buffer is installed and
  written, but the persistence path that would flush it to `/data/audit.log` is
  off by default (`audit::persist::set_persistence`) and nothing calls it, so
  records are lost on reboot.  The maintenance thread already drives the flush
  every 200 ticks; only the switch is missing.
- **Signature verification is opt-in**: a launch manifest or program image
  carrying `manifest_signature`/`entry_signature` is verified against a trusted
  key, but one that carries neither loads anyway, and nothing in the launch
  chain requires a signature.  There is no key distribution or rotation policy,
  so the guarantee is "a signed artifact cannot be swapped" rather than "only
  signed artifacts run".
- **Service privilege is provenance, not authentication**: a definition
  declaring `security = "admin"` or `"system"` is trusted because
  `/system/rc.d` lives on a read-only zone and because the account it names
  exists.  No password is involved, so the token it receives is elevated but
  unauthenticated, and no service level reaches the discretionary bypass: a
  service manages what root owns but cannot read another account's private
  files, and `system` carries the kernel's trust level without its identity.
  The bypass has exactly two producers — the kernel's own threads and a
  password-authenticated login — and a test in `kernel::service` pins both
  halves so the policy cannot be changed by accident.  A service that needs to
  reach across accounts needs a capability, not a wider level.

---

### 10. Syscall Interface (93%)

| Component | Lines | Status |
|-----------|-------|--------|
| Syscall table | 1,300+ | 190 numbered slots (0-189); 188 carry a handler, 141-142 are reserved |
| Dispatch engine | 500+ | Context-aware dispatch with action return |
| User memory validation | 400+ | `validate_user_mapping()` + `copy_user_bytes()` |
| Shared wrappers (`src/user/shared/syscall.rs`) | 2,000+ | 90+ typed wrappers, 7 raw entry points |
| ABI types | 500+ | Wire-format records, syscall encodings |
| Per-category handler files | 14 files | fs, network, process, diagnostic, tls, filter, io_uring, ptrace, etc. |
| Syscall profiling | 200+ | Per-syscall counters (optional feature) |

**Categories of syscall handlers:**

| Category | Handlers | Files |
|----------|----------|-------|
| Process/thread lifecycle | 15+ | `launch_metadata.rs`, `runtime.rs` |
| Process control | 1 | `misc/prctl.rs` |
| File/path operations | 15+ | `fs/path_ops.rs` |
| I/O (read/write) | 8+ | `io_fd.rs` |
| Network | 22 | `network.rs` |
| IPC & synchronization | 12+ | `futex.rs`, `event_fd.rs`, `signal_fd.rs`, `timer_fd.rs`, `mq.rs`, `epoll.rs` |
| Memory management | 10+ | `memory/map.rs`, `memory/brk.rs`, `memory/shm_handlers.rs` |
| Filesystem (mount/FUSE) | 10+ | `fs/path_ops.rs`, `fs/fuse_mount.rs` |
| TLS encrypted connections | 1 | `tls.rs` |
| Packet filter / firewall | 4 | `filter.rs` |
| io_uring async I/O | 2 | `io_uring.rs` |
| ptrace process tracing | 1 | `ptrace.rs` (syscall) + `process/ptrace.rs` (core) |
| seccomp | 1 | `seccomp.rs` |
| Signal control | 4 | `signal.rs`, `signal_mask.rs`, `sigsuspend.rs`, `restart_syscall.rs` |
| Exception control | 6 | `exception_control.rs` |
| POSIX timers (#137-140) | 4 | `timer.rs` (timer_create/settime/gettime/delete) |
| Audit (#143-144) | 2 | `audit.rs` (AuditSetEnable, AuditReadLog) |
| Extended attrs + file flags (#151-156) | 6 | `fs/xattr.rs` (setxattr/getxattr/listxattr/removexattr/set_file_flags/get_file_flags) |
| Diagnostics | 10+ | `diagnostic.rs` |
| ABI information | 4+ | `abi_info.rs` |
| Miscellaneous | 5+ | `misc.rs` |

**Strengths:** A stable ABI with a single source of truth and careful user-memory validation.

- **Organized by category**: handler files are cleanly separated (fs, network, process, tls, filter, io_uring, ptrace, etc. across 14 files); slots are well-documented with room for expansion (up to 256).
- **Single source of truth**: `src/user/shared/` provides the ABI's one canonical manifest — both kernel and userspace compile against the same constant definitions; the `UserSyscall` type lets kernel-internal callers (demo workers) exercise the same path.
- **User-memory validation**: memory is validated before every access (no speculative copyin), pre-validated through the central `SYSCALL_POINTER_SPECS` table.
- **Signals & timers**: dedicated **sigsuspend (#135)** and **restart_syscall (#136)** handlers complete the POSIX signal interaction model (SA_RESTART rewinds the instruction pointer and re-invokes the dispatcher); **POSIX timers (#137-140)**.
- **Management syscalls**: audit (#143-144), CPU frequency scaling (#145-149), extended attributes and file flags (#151-156), fcntl (#179), sync (#180).
- **VIRGL 3D interface (#181-189)**: gpu_ctx_create/destroy, gpu_res_create_3d/unref (kernel-allocated DMA backing), gpu_transfer_to_host_3d/from_host_3d, gpu_submit_3d, gpu_set_scanout, gpu_device_info.
- **Stable, versioned ABI**: all syscall numbers live in `src/user/shared/abi/syscall.rs`; the ABI is versioned via `SYSCALL_ABI_VERSION_MAJOR/MINOR`, reported at runtime through `RuntimeAbiInfo`; numbering is append-only — never renumber, never reuse a slot; syscalls are classified Stable (0–120) or Experimental (121–189), with tests pinning the frozen numbers and asserting dense registry coverage.

**Weaknesses:**

- **121–189 are still Experimental**: 69 slots are not frozen, so no cross-major stability guarantee.
- **No external toolchain or conformance suite**: the ABI is self-consistent within the kernel crate but has no independent toolchain or POSIX conformance tests.

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
| MSI/MSI-X | Full (vector allocator + table programming) | Full (GIC ITS, LPI) | — |
| PCIe | Full ECAM | Basic probing | Basic probing |
| ASID allocator | — | Full (bitmap + CAS) | Full (bitmap + CAS, 65536 ASIDs) |
| FDT parsing | — | Full | Full |
| RTC | — | Full (from FDT) | Full |
| Serial | Full (UART 16550) | Full (UART 16550) | UART 16550 (SBI fallback) |
| NUMA discovery | Full (ACPI SRAT/SLIT) | Full (FDT numa-node-id, distance-map) | Full (FDT numa-node-id, distance-map) |
| CPU frequency scaling | Full (MSR P-state) | Full (DT OPP) | Full (DT OPP) |
| Code size | 10,824 lines | 6,663 lines | 3,500+ lines |

### Shared User Runtime (`src/user/shared/`)

| Module | Lines | Purpose |
|--------|-------|---------|
| `syscall.rs` | 2,000+ | 55+ typed syscall wrappers |
| `dispatch.rs` | 1,500+ | ~40 shell builtins (cat, ls, cp, mv, grep, etc.) |
| `commands/` | 2,000+ | Subcommand implementations |
| `signal.rs` | 150+ | Signal handling API (u64 mask, sigsuspend, SA_SIGINFO) |
| `passwd.rs` | 100+ | Password file parsing |
| `jobs.rs` | 100+ | Job control logic |
| `abi/` | 500+ | ABI type definitions |
| `runtime.rs` | 550+ | Arch syscall wrappers, brk allocator, args |

**Total:** 16 modules, 41 files, ~12,600 lines, merged into the kernel crate.

The ABI records are the one thing here that exists twice: `src/abi/` holds them,
and `src/user/shared/abi/` mirrors them, the mirror carrying `//! src/abi/<name>.rs`
in its header to record where each file came from.  `make check-abi-mirror`
keeps the two in step: every record has to be declared by `src/abi/mod.rs`
(a file the compiler never reads is not code), every mirror has to record its
origin, and the two bodies have to be identical below the header — except for
the four differences `scripts/abi-mirror-baseline.txt` records with a reason.

That check exists because the copies had drifted the one way copies drift.  The
kernel's side had grown three blocks of exactly the API user code needs — the
`SA_*` restart flags, the architecture-neutral exception-handler flags and the
`NetworkStatus` accessors — and the shared side had none of them, which is why
user code was reaching back into `src/abi/` for them.  All sixteen mirrored
records are byte-identical below the header now, and the four listed
differences are the ones that are not mirrors at all: `runtime.rs` (the kernel
re-exports the shared definition), `syscall.rs` (the kernel file encodes status
words, the shared one names syscalls), `mod.rs` (the shared tree carries no
`virgl` record) and `virgl.rs` itself.

Three files that no module declared are gone with the same change: they were in
`src/abi/`, invisible to the compiler and to every gate, and one of them listed
prctl codes that collided with the implemented ones.

The other direction is fixed too.  `src/user/` used to reach the ABI through
`crate::abi::` at 141 sites, which meant the vendored tree was in step with the
kernel's copy but could not have been lifted out of the crate: it named a path
that would not exist on the other side.  The shared tree and the payload
modules now go through `crate::user::shared::abi::` — zero uses of the kernel's
path in either, which `make check-abi-mirror` enforces by deriving the payload
list from the macro that gives those modules their linker sections.  Two places
are deliberately still on the kernel's copy, and both are kernel code: the
host-proxy demonstration runtime, the in-kernel shell's `env` builtin, and one
`decode_result` call whose result is the kernel's own `Error` type.  The
numbers it decodes against come from the shared copy.

### Testing

| Category | Count | Coverage |
|----------|-------|----------|
| Unit tests (in-module) | ~300 modules (1,858 tests) | Varies by module |
| Integration test files | 25 | 11,661 lines (277 tests) |
| Fault injection tests | 1,245 lines | SimpleFs single-fault matrix |
| Recovery tests | 1,163 lines | Crash + replay scenarios |
| Concurrency tests | 700+ lines | Scheduler, condvar, console, keyboard |
| virtio-gpu layout tests | 10+ | Struct size/layout + command wire-format (mock device) verification |
| CI workflow | ✅ | GitHub Actions: fmt, check, build, clippy, every static gate and ratchet, and the boots — x86_64 on four CPUs, AArch64 and RISC-V on four CPUs, the four frozen-payload runs, both churn boots, and the RISC-V AIA machine |
| Verification gates | P0–P3 | Multi-tier: fmt → test → cross-build → clippy |
| ABI number snapshot | 190 rows | [`tests/syscall/abi_golden.rs`](../../tests/syscall/abi_golden.rs): any change to a number's name fails, and a change in the experimental range has to bump the ABI minor in the same commit |

**2026-08-20 update:** the `demo-disk` feature was verified end-to-end on all
three targets under QEMU — interactive shell (≈40 builtins), demo payload
(app-id/image/cwd/argv0/resume-1/resume-2, exit code 42), 0 FATAL. The RISC-V 64
user ABI and demo shell are confirmed working. Host-side tests: **3,056 passed /
0 failed**.

### Userspace compatibility (the iron rule)

`docs/fmts/syscall-abi.md` states the compatibility contract — numbers assigned
once and never renumbered, records whose layout is asserted at compile time,
`0..=120` frozen and `121..=189` experimental. Three things make that contract
*testable* rather than merely written down, and they are at different stages:

| Item | State | Where |
|------|-------|-------|
| The number table is frozen | **done** | `tests/syscall/abi_golden.rs`: a snapshot of all 190 number→name rows. A change in the frozen range fails outright; a change in the experimental range fails unless the ABI minor version moves with it. Before this, swapping two stable syscalls left every test green. |
| Userspace can learn which ABI it is on | **already present** | the `abi_info` syscall (#39) returns `syscall_abi_major`, `syscall_abi_minor` and `syscall_count` alongside the record's own `major`/`minor`/`record_size` ([`src/user/shared/abi/runtime.rs`](../../src/user/shared/abi/runtime.rs)) |
| A program that was not rebuilt | **done, two on x86_64, one elsewhere** | `src/user/demo/fixtures/` holds four payloads: `rust_io_payload_x86_64.bin` (5036 bytes, `demo-launcher-rust-io`, Rust section, entry at 0), `rust_payload_x86_64.bin` (806 bytes, `demo-launcher-rust`, the child the first one spawns, entry at 0), `demo_payload_riscv64.bin` (676 bytes, `demo-launcher`, hand-written RISC-V assembly, entry at 0) and `demo_payload_aarch64_rust.bin` (2076 bytes, `demo-launcher`, Rust section, entry at 404). `make check-abi-frozen-payload{,-aarch64,-riscv64}` build with `abi_frozen_payload`, so the demo disk carries *those* bytes instead of the freshly compiled ones, boot, and require the same user output the normal smokes do — plus a boot line naming the source, `[abi   ] … payload: frozen (…)`, so a gate cannot pass while quietly testing a new payload. The x86_64 boot is the one that carries two: it runs the frozen launcher, and the launcher starts the frozen child. AArch64 and RISC-V have one each because their demo disks ship one payload program between them — aarch64's two services are the same bytes under two manifests — so there is no second program there to freeze. These are the configurations in which an ABI change can break a program, which is what makes the rule above testable. |

### Build & Development

- **Build system:** Cargo + Makefile (verified targets per architecture)
- **Layout:** the shared user runtime and demo payloads live inside the kernel crate as `src/user/shared/` and `src/user/demo/`
- **Optional features:** `demo-disk`, `fs_profiler`, `net_profiler`, `alloc_profiler`, `fault_profiler`, `educational_networking`
- **Release profile:** `panic = "abort"`, `opt-level = "s"`, `lto = true`, `codegen-units = 1`

---

## Weaknesses & Known Gaps

- **Emulation-first verification**: apart from x86_64, AArch64 and RISC-V are verified under QEMU; there is no bare-metal bring-up yet (see the roadmap's "Real-hardware bring-up" milestone).
- **RISC-V 64 is still partial**: there is no architectural NMI source, and
  PCIe devices are enumerated but not yet usable — the resource pass is
  missing.  The AIA IMSIC — the file that receives MSIs — is implemented and
  *booted*: `make check-riscv64-aia-runtime` runs the kernel on
  `-machine virt,aia=aplic-imsic`, where the IMSIC is the external-interrupt
  controller, and the kernel walks its own message path at boot (enable an
  identity, write the message a device would write into its own MSI page, claim
  it back) because nothing on that machine sends an MSI.  The PCIe half above
  it now walks too — `make check-riscv64-pci-runtime` boots with a
  `virtio-net-pci` beside the MMIO device and asserts that the ECAM window the
  device tree names was read and the device was found — and
  `arch/riscv64/pci.rs::probe_first_msix` calls `pci_enable_msix` on that
  device at every boot, which is how the next gap became visible rather than
  silently skipped: **the machine assigned no BAR addresses.**  QEMU boots this
  kernel directly, with no firmware to run a PCI resource pass, so every
  memory BAR read back as zero — and an MSI-X table lives in a BAR.  The
  kernel runs that pass itself now: the memory window comes from the host
  bridge's `ranges`, `assign_memory_bars` gives each unaddressed memory BAR an
  aligned address inside it and verifies that the device took it, so the boot
  log reads `BAR assigned ... 0x4000_0000`, `MSI-X enabled on 00:01.0 (4
  entries)` and `4 entries read back` — which is device MMIO answering.
  AArch64 is in the same state and runs the same pass, and its gate asserts its
  two assignments.
- **Thin userspace ecosystem**: there is no toolchain and no real applications.
  What is there is more than it looks: the demo's ring3 payloads
  (`demo-launcher`, its Rust and rust-io variants, and the four fault demos)
  are real ELF images which run, make syscalls, read and write files under
  `/data/users/guest/`, and install their own exception handlers — built inside
  the kernel by `src/user/demo/`, not compiled by a toolchain.  The shell is
  ring-3 code on all three targets: one program, written once in
  `src/user/demo/shell_payload.rs` and emitted into a section per target
  (`shell_payload_x86_64`, `shell_payload_aarch64`, `shell_payload_riscv64`),
  with its own banner, prompt, `ls`, `cat`, `cd` and `echo` — so the boot's
  prompt is that program rather than the in-kernel Rust proxy it used to fall
  back to on every machine.  The difference is testable rather than nominal: the
  three runtime checks type a command at the prompt and assert the answer, which
  is the only way to tell a shell that reads a line from one that only prints a
  banner.  What is still missing is the layer above *that*: the manifests still
  carry a `host_proxy` entry nothing reaches, the `/init.elf` in the system zone
  is a stub that exits, and nothing on the volume is signed or verified unless
  its manifest asks for it.
- **Single maintainer**: bus factor = 1; every module is currently held by one maintainer.
- **Experimental syscalls are unfrozen**: slots 121–189 are classified Experimental.
- **“We do not break userspace” has seven subjects, not a population**: the
  frozen payloads make the rule testable for three programs on x86_64 — the
  launcher, the child it starts, and the shell — and for two on each of the
  other targets — the launcher and the shell.  The three shells are the ones
  that wait for input, so those runs type at them; the other four announce what
  they are and exit.  Extending this means *writing* another demo program rather
  than freezing one.  Each freeze is a deliberate act, and the remaining demo
  programs (the fault variants and the assembly launchers) are not frozen.
- **A user-access window is not a semaphore**: x86_64's `AC`, AArch64's `PAN` and
  riscv64's `SUM` are per-hart bits, and the guard around a copy sets and then
  clears them.  A window that is held *across a block* is therefore at the mercy
  of any other thread that opens and closes its own window while the first is
  waiting — the first thread's access is cleared under it, and the copy faults
  in the kernel.  It took a ring-3 console reader to hit this (the read syscall
  held the window across a wait for a keystroke, on the first machine where the
  demo's own writes interleaved with it), and the read path now stages in kernel
  memory and copies out under a window held only for the copy.  The write path
  still holds its window for the duration of a blocking write, and the socket
  paths have the same shape; the invariant the guards document is "scoped to a
  single copy", and the remaining paths do not keep it.
- **No coverage-guided fuzzing**: the four boundaries have deterministic
  harnesses instead — `tests/parsers/fuzz.rs`, run by `make test-parsers` and
  in CI, drives the ELF loader, the LUKS2 header and its scanners, twenty-four
  network packet parsers, and every filesystem image opener the tree has
  (including the MBR/GPT reader) with random bytes and structure-aware
  mutations.  What is missing is the fuzzer that *searches*: these are
  fixed-seed and bounded, so they catch the panics a seed happens to reach, not
  the ones a mutation chain would.  `docs/fmts/testing.md` describes them the
  same way.
- **No reproducible releases**: no tagged releases with reproducible ISO/disk images and signed artifacts.

---

## What's Unique About This Kernel

1. **11 filesystem drivers** — FAT32, exFAT, ext4, F2FS, btrfs, XFS, NTFS, ISO 9660, EROFS, SquashFS + native SimpleFs
2. **Native TCP/IP stack** with TLS 1.3, SCTP, and WireGuard VPN — not a port of lwIP/uIP; custom implementation with full TCP congestion control, DNS caching, DHCP
3. **Three architecture targets** — x86_64, AArch64, RISC-V 64 — with PAN/SMAP on all three
4. **Biba integrity model** — formal multi-level security policy in a hobby kernel is rare
5. **Unicode 15.1 NFC/NFD normalization** + GB18030 codec — comprehensive internationalization
6. **TLSF heap allocator** — O(1) bounded-time alloc/free, 640 free lists
7. **`src/user/shared/`** — the userspace runtime lives inside the kernel crate, so each syscall wrapper, shell builtin, and ABI record is compiled on both sides of the boundary rather than re-implemented per side
8. **Preemptive multi-threading with guard pages** on all architectures
9. **NUMA-aware frame allocation, scheduling, and SRAT/FDT discovery** — per-node frame allocators with CPU-to-node mapping, NUMA-aware work stealing, and automatic topology discovery via ACPI SRAT/SLIT (x86_64) and FDT numa-node-id (AArch64, RISC-V)
10. **virtio-gpu accelerated display with VIRGL 3D protocol infrastructure** — VirtIO GPU driver providing 2D mode-setting and VIRGL 3D protocol support as an alternative to bochs-display
11. **MSI/MSI-X and GIC ITS interrupt support** — vector allocation and table programming for NVMe and VirtIO PCI drivers on x86_64, plus GICv3 ITS controller with LPI configuration on AArch64
12. **Per-thread stack canary** — software-implemented canary verification on context switch for runtime buffer-overrun detection
13. **Encryption at rest** — AES-256 XTS mode, PBKDF2 key derivation, LUKS2 header parsing, transparent EncryptedBlockDevice wrapper
14. **Journal replay for ext4/XFS/F2FS** — real disk log recovery: revoke blocks, buffer/inode/dquot items, orphan recovery, SIT persistence
15. **Audit subsystem** — system-call auditing with classified event types, ring buffer (8192 entries), and dedicated audit syscalls (#143-144)
16. **SCTP protocol** — full transport layer implementation with 4-way handshake and CRC32C verification
17. **Hotplug support** — PCIe slot status monitoring and xHCI port status change polling via DeviceManager lifecycle
18. **POSIX timers (#137-140)** — timer_create/timer_settime/timer_gettime/timer_delete with per-process timer management and signal delivery
19. **HDA audio controller driver** — Intel HD Audio with CORB/RIRB engine, codec discovery, and stream descriptors
20. **WireGuard VPN** — Noise_IKpsk2 handshake state machine, ChaCha20-Poly1305 transport encryption, session key management
21. **CPU frequency scaling & power management** — x86_64 MSR P-state driver (CPUID leaf 0x16 + PLATFORM_INFO detection, HWP handling, DTS temperature) + aarch64/riscv64 DT OPP range discovery and target tracking (`operating-points-v2` / legacy `operating-points`), 5 governors, scheduler-tick integration, cpufreq syscalls (#145-149)
22. **Memory compression & defragmentation** — zswap-style compressed page cache (zero/RLE/LZSS codec, 16 MiB budget) on reclaim, plus physical-pool compaction that relocates movable user frames to coalesce fragmented free ranges; `CompactMemory` syscall (#150)
23. **NMI handling + SMP IRQ load balancing + interrupt stats** — dedicated x86_64 vector-2 / AArch64 SError-FIQ NMI paths with a handler registry; every-2 s migration of the hottest migratable IRQ from the busiest CPU (IOAPIC redirection / GIC SPI affinity / PLIC per-context enable); `SystemInfo` type 9 exposes per-CPU/per-vector IRQ, IPI, and NMI counts plus load-balancer state
24. **SimpleFs V4 data reduction & extended attributes** — persistent xattr table on the native filesystem (`setxattr`/`getxattr`/`listxattr`/`removexattr`, syscalls #151-154), per-file transparent compression (chunked LZSS/raw encoding, on-demand decompression), and cross-file content dedup (shared extents with mount-time refcount rebuild and copy-on-write unsharing); toggled and queried via `set_file_flags`/`get_file_flags` (#155-156), all crash-safe under V4's `pending_commit` two-phase commit
25. **DCCP transport (RFC 4340)** — connection-oriented datagram transport: Request/Response/Ack handshake, 9-state machine, 48-bit extended sequence numbers, options and feature negotiation, CCID 2 congestion control (cwnd/ssthresh + Ack Vectors), service codes; full syscall API (bind/listen/connect/accept/send/recv/close, #157-163)
26. **IPsec (ESP + AH)** — RFC 4303/4302 data-plane transforms: ESP with AES-GCM (RFC 4106) and ChaCha20-Poly1305 (RFC 7634) AEAD, AH with HMAC-SHA256-128 (RFC 4868), both transport and tunnel modes, IPv4 + IPv6, 64-bit anti-replay window; manual SAD/SPD management (syscalls #164-168) with depth-guarded tunnel decapsulation
27. **Multicast routing** — MFC/VIF forwarding engine (RPF + TTL gating + counters), IGMPv2/MLDv1 router mode (membership tracking, general queries, timeout), MRT management syscalls (#169-174, mirroring Linux mroute); PIM-DM flood-and-prune control plane under `educational_networking`
28. **IPv6 edge-case hardening** — path-MTU discovery (RFC 8201, Packet Too Big → per-destination PMTU cache + TX fragmentation), atomic fragments (RFC 6946), extension-header order and 7-header limit (RFC 8200 §4.1), routing-header type-0 rejection (RFC 5095), overlapping-fragment discard (RFC 5722), RA MTU option

29. **MAC type-enforcement engine (SELinux/AppArmor equivalent)** — mandatory access control beyond Biba: security types on subjects (processes) and objects (files), an allow-rule policy (first-match + default-deny), a central VFS hook covering all file operations, Process-class (ptrace/signal) and Network-class checks, exec domain transitions (adopting the binary's type), management syscalls (#175-178), and MacDenial audit records on refusal
30. **Persistent credential system** — `/data/etc/passwd` and `/data/etc/shadow` are written back atomically (temp file + rename, crash-safe), the shadow file is re-chmodded 0600 after every save, and user removal also cleans up the shadow entry
31. **fcntl descriptor control (#179)** — a complete POSIX fcntl subset: F_DUPFD / F_GETFD / F_SETFD / F_GETFL / F_SETFL (O_NONBLOCK honoured per pipe end), plus F_GETPIPE_SZ / F_SETPIPE_SZ to resize the pipe buffer at runtime (page-rounded, capped at 1 MiB, data preserved) — breaking the "fixed-size pipe" limitation
32. **Persistent block cache** — every dirty block is stamped with a cache-clock tick advanced by the scheduler; blocks dirty for more than 6 seconds (600 ticks) are written back to the device automatically every 3 seconds, and `sync` (#180) provides the on-demand global flush, making write-back durable without an explicit fsync
33. **Device-tree-driven driver probe** — on AArch64/RISC-V, FDT nodes are bound to drivers by `compatible` string: `collect_dt_nodes` builds a node table (compatible/reg/interrupts/phandle/status) and `Driver::compatible_strings()`/`probe_dt()` bind nodes inside `DriverManager::probe_dt_devices`; virtio-gpu/block/net are all probed from their DT node `reg` (making the GPU available on AArch64/RISC-V), replacing hardcoded address-range scans
34. **VIRGL 3D userspace interface (#181-189)** — exposes the virtio-gpu VIRGL protocol to a userspace renderer: contexts, 3D resources with kernel-managed DMA backing, host transfers, command submission, scanout, and a capability report; actual 3D rendering executes host-side via virglrenderer, with the kernel providing the transport the renderer drives (with mock-device wire-format tests)
