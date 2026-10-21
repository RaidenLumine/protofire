# Status

This document is the per-module census of the kernel: for each subsystem, what
the code does today and what it does not do yet.  It deliberately carries no
line counts, file counts, test counts, or completion percentages.  Those
figures change with every commit, and a number that has to be maintained by
hand is a number that will eventually be wrong — the tree is the authority for
how much code there is, and this document is the authority for what that code
does.

The documents have one subject each, and the division between them is:

- **mechanism** — how a subsystem works — is
  [docs/kernel/](kernel/README.md)'s;
- **decisions** — what was chosen, and why — are
  [docs/rfcs/](rfcs/README.md)'s;
- **specifications** a contributor has to follow are
  [docs/fmts/](fmts/README.md)'s;
- **direction** — what is planned — is
  [ROADMAP.md](../ROADMAP.md)'s;
- and **status** — what exists, what is missing, and what is reached only
  under QEMU — is this file's.

Targets: x86_64 (full), AArch64 (full), RISC-V 64 (partial).

Two words are used strictly below:

- **implemented** means the code path exists and is reachable.
- **verified** means a gate boots it or a test pins it.

In the per-module tables, a dash in the *Missing* column means no gap is known
and recorded here — not that the module has none.  A subsystem's mechanism is
written out in `docs/kernel/`; the tables here are the census, and the columns
that say what is missing are the ones the roadmap draws from.

Where this document and the tree disagree, the tree is right and this document
is the bug. `make check-docs` enforces the part of that a machine can check:
every `src/…` or `tests/…` path named here has to exist, and a line-number
citation is refused outright because line numbers rot.

A row is a census, not a history: what landed in a subsystem stage by stage is
[docs/rfcs/](rfcs/README.md)'s to tell, and a row that grows into that story
stops being one.  `make check-status-rows` holds the line — a row may not grow
past what a census may be, and the rows still over it are the ones
`scripts/status-row-baseline.txt` records, each to be brought down by the
change that shortens it.

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
| VirtIO (block) | Block | Full read/write, on the virtio-mmio bus and on PCIe | QEMU only; the virtio-mmio transport has no vectors of its own, so only the PCIe path claims an identity per queue |
| VirtIO (net) | Network | Full RX/TX, modern and legacy transports; on all three machines each queue claims its own MSI-X identity, so a queue's completion wakes that queue's waiter; a boot with no NIC can initialize the stack on the loopback device instead (`net_loopback`), which is what `make check-perf-baseline-net` boots | No throughput baseline against a peer: what is gated is one datagram to itself (`nw-*`), not traffic through a NIC |
| VirtIO (GPU) | Display | 2D mode-setting (x86_64 PCI + AArch64/RISC-V device-tree MMIO) and the VIRGL 3D userspace interface (#181-189), driven by the demo renderer (`src/user/demo/virgl_renderer.rs`) | QEMU only |
| NVMe | Block | Controller bring-up (admin queues, Identify, I/O queue pair), single-block read/write, and boot-disk probe, on all three machines; the completion queue **claims one MSI-X table entry** (the entry the controller's own admin completions share, because `Create I/O Completion Queue` fixes a queue's vector before any table can be programmed) and the driver's waits park on it once the platform arms the claim, a machine that refused the claim or cannot arm it still polling; `make check-x8664-nvme`, `check-aarch64-nvme` and `check-riscv64-nvme` boot the host's own SimpleFs image on a namespace with no other disk attached and assert that the controller comes up, is chosen as the boot disk, mounts the volume, and — on each machine's message-capable configuration (the local APIC's window, a GICv3 ITS, the AIA IMSIC) — that a completion MSI reached the driver's own handler | QEMU only; the claim is one entry for the whole controller, so an I/O queue and the admin queue share the interrupt |
| xHCI | USB host | Controller reset and start, command and event rings, device enumeration (Enable Slot, Address Device, GET_DESCRIPTOR), a HID interrupt endpoint per device, and **root ports**: a port change (the change bits of `PORTSC`, read once the controller raises a Port Status Change Event) resets the port and enumerates a device that arrived, and releases the slots of one that left — the device and everything behind it — with the bits cleared after the boot's scan, because a port whose connect change is still set says nothing when its device is pulled; **hubs**: a hub's descriptor is read for its port count and its power-switching mode (a ganged hub is not told to power a port at a time — a class request a hub does not implement is answered with a stall, which halts the endpoint it came in on), its status-change endpoint is configured and armed, its ports are powered and reset, and a device on one is addressed by the *route string*, so it works like one on a root port, one tier down, including one plugged in after the boot's scan, for every hub found (a hub behind a hub is one more entry); the command, control, interrupt and bulk rings each carry a Link TRB with its Toggle Cycle bit and flip their producer cycle state at the wrap, with the link at the slot the lap ends in rather than the segment's end (a link the consumer cannot reach is a wrap that never happens); the event ring is consumed against the segment size the ERST states and a completion is matched to the TRB the event names; a controller-declared scratchpad buffer count (HCSPARAMS2) allocated as the DCBAA[0] array, each buffer one controller page; a claimed MSI-X vector whose interrupt drains the event ring when the rings are free; `make check-x8664-usb-hotplug` plugs a mouse into a hub's port, unplugs it, plugs it back in, pulls the keyboard out of its root port and plugs a mouse into a free one while the guest runs, and requires all of it to be seen, and `make check-x8664-runtime` boots a keyboard on a root port beside a mouse behind a hub, presses a key through QEMU's monitor, and offers the USB disk | The producer rings hold **one TD in flight per ring**: every submit path waits for its completion, and the work an event asks for — a hub's report, a root port's change — is run from the event-ring drain rather than under a transfer's wait, because that work is itself requests and would otherwise put a second TD on a ring whose first is still outstanding; and a submit asks its ring's `RingRoom` first — the TRBs submitted and not yet completed, which is the only honest measure, since the controller writes its dequeue back into an endpoint's context only when the endpoint stops or faults — refusing with `Busy` rather than letting the producer's next lap overwrite a TRB the controller has not read (unreached honestly — every submit waits — and `make check-x8664-usb-room-budget` drops releases to prove it); the timer tick still drains the ring as the fallback; the controller is built into its own allocation (boot stack: 64 KiB); x86_64 only; QEMU only (see [RFC 0006](rfcs/0006-end-a-producer-ring-lap-where-its-work-ends.md)) |
| USB HID | HID (keyboard) | A HID interrupt endpoint is configured on the enumerated device, its reports are decoded into the same keyboard core the PS/2 and VirtIO paths feed, and `make check-x8664-runtime` types a command on the USB keyboard and asserts the shell's answer | The report deshuffling is the boot's evidence rather than a synthetic matrix; a HID device behind a hub is enumerated when the hub reports the port (see the xHCI row) |
| USB MSD | Storage | Bulk-only transport and SCSI command blocks; `make check-x8664-runtime` attaches a disk whose first sector carries a pattern, and the driver enumerates it, identifies it (INQUIRY), reads its capacity and reads that sector back, with the pattern in the log as the evidence; `make check-x8664-usb-disk` boots the host's own SimpleFs image on a USB disk, and the shell *writes* a marker through `open`/`write` into the volume, reads it back with `cat`, and the host finds those bytes in the image afterwards | QEMU only |
| Serial (UART 16550) | Text I/O | Full duplex; the console UART's received-data interrupt feeds the console on all three machines — COM1's vector, the PL011's GIC SPI (GICv2 and GICv3, both typed at by `make check-aarch64-runtime`), the 16550's PLIC source, and on an AIA machine the supervisor APLIC turning that source into an MSI identity — so input no longer depends on the timer tick; a claim that was refused keeps the tick's poll instead of losing input | RISC-V falls back to the SBI console when it has no UART |
| PS/2 Keyboard | Input | Scancode buffering, decoding, console TTY bridge | The PS/2 interrupt path is x86_64; other targets rely on VirtIO input, whose MMIO transport carries no vector, so its completions ride the tick ([RFC 0021](rfcs/0021-what-the-timer-tick-still-polls.md)) |
| Framebuffer | Display | Linear framebuffer the console draws on at the tag's own depth (24 or 32 bits per pixel; the Multiboot2 header requests 1024x768x32, and `make check-x8664-iso` asserts the boot installed its console on the loader's frame) — either the one the bootloader set or, on a QEMU boot that hands none over, the kernel's own probe of the machine's display (bochs on the PC) | No userspace graphics API beyond the VIRGL syscalls; the tag's channel-position fields are not read, which the two colours the console draws need not tell apart; QEMU only |
| Framebuffer Console | Display | Text rendering from a built-in 8×16 ASCII glyph table | Fixed font: characters outside the table draw as a fallback glyph, and there is no font or resolution management |
| HDA (Intel HD Audio) | Audio | CORB/RIRB, codec discovery, the output converter, a BDL playback ring and the stream DMA that drains it, driven from `/system/dev/audio` ([`hda.rs`](../src/drivers/hda.rs)); the converter is bound to the stream by the same 16-bit format word the descriptor's SDFMT carries, so the codec derives the channel count from the format; the controller is found through the platform's PCI window, so the one file drives it on x86_64, AArch64 and **RISC-V**; `make check-x8664-hda`, `make check-aarch64-hda` and `make check-riscv64-hda` type `tone 440 200` at the shell, which writes the node's `[u32le rate][interleaved samples]` payload, read the samples back out of the WAV QEMU's `-audiodev wav` backend writes on the host, and measure the tone's frequency from the wave's own period | The tone lands ~0.8% below the frequency asked for (436 Hz for 440), which is the shell generator rounding a half-period to whole frames — 110 rather than 109.09 — and not a scaling side; the driver's waits are bounded polls: the controller offers no MSI-X table to claim (QEMU's `intel-hda` is classic MSI only — [RFC 0024](rfcs/0024-what-the-hda-controller-signals-with.md)); QEMU only |
| PCIe ECAM | Bus | AArch64/RISC-V: window **discovered** from the device tree (`pci-host-ecam-generic`), BARs assigned, one driver attached, MSI-X through the machine's own controller; x86_64 reaches configuration space through the legacy port pair, which the registers it reads (all within the 256-byte head) fit inside — so there is no window to discover and no fixed `Q35_MMCONFIG_BASE` to guess one at | One driver on the device-tree machines; every other PCIe device still uses its architecture's own enumeration; x86_64 has no ECAM window at all, so a future need for a register above `0xFF` would have to read MCFG |

**Strengths:** driver coverage across storage, network, display, audio, and
input, mostly verified under QEMU.

- **Storage**: AHCI (SATA), ATA PIO, VirtIO, and NVMe provide independent block
  backends; the NVMe driver's completion queue claims its own interrupt and its
  waits park on it, and the VirtIO block driver's interrupts are its queue's
  claim through the same path.
- **Network**: the VirtIO network driver is multi-queue ready, and on the two
  PCIe machines its queues are interrupt-driven — one MSI-X identity per queue,
  so a completion wakes the queue that caused it.
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
  their DT node `reg`, making the GPU available on AArch64/RISC-V.  The
  platform parser (`parse_fdt`) classifies a node by its **`compatible`** — a
  **whole entry** of the property, not a substring, since `arm,gic-v3` is a
  prefix of `arm,gic-v3-its` — with each node's `reg` settled at the end of the
  node, where both that property and the `compatible` that follows it are known,
  and a node's state saved across its **children** (a GIC's `v2m` frame or ITS)
  so a child does not clear the parent's flags; a board that places its console,
  its interrupt controller or its transports anywhere is read by what the nodes
  say they are, not by matching QEMU `virt`'s own addresses
  (`parse_fdt_classifies_nodes_by_compatible_not_by_address`,
  `a_compatible_name_matches_a_whole_entry_not_a_prefix`,
  `a_gic_with_a_child_still_settles_its_own_reg`).
- **Audio**: the Intel HDA driver provides controller initialization, the
  CORB/RIRB engine, codec discovery, and stream descriptor configuration, and
  it runs where the controller is — x86_64 and AArch64 — because it is handed
  the controller's BAR by the platform rather than by an architecture's own
  configuration code.
- **Hotplug, half-built**: the PCIe slot-status and hotplug-event reads exist
  (`arch::pci::pcie_read_slot_status`, `pcie_check_hotplug_event`) and the
  device manager has a removal path, but nothing polls either: no boot
  notices a slot change, and a removed device would stay in `/dev` until the
  next publish.

**Weaknesses:**

- **USB is gated through a key press, a mount and a write, but not through a
  filesystem API**: xHCI resets the controller, runs the command and event
  rings, enumerates both devices, configures a HID interrupt endpoint, claims
  an MSI-X vector and takes the interrupt a key press raises —
  `make check-x8664-runtime` boots all of that, presses a key through QEMU's
  monitor, reads the shell's answer, and offers a disk whose first sector
  carries a pattern the driver reads back; and `make check-x8664-usb-disk`
  boots the host's own SimpleFs image on a USB disk, reads enough of it to
  wrap the rings several times, loads a program out of it, has the shell write
  a marker into it through `open`/`write`, and checks on the host that those
  bytes are in the image; and `make check-x8664-usb-hotplug` moves a device on
  and off a **hub**'s port while the guest runs, so the hub's status-change
  endpoint is read rather than merely configured — the line order in its log
  is the evidence, because the enumeration happens after a marker typed at
  the shell long after the boot's scan. What is still missing: the rings
  assume one TD in flight per ring rather than checking for room, which a
  future pipelining path has to add before it can be correct
  ([RFC 0006](rfcs/0006-end-a-producer-ring-lap-where-its-work-ends.md)).
- **Audio plays, at the pitch it was asked for.** The path runs end to end —
  the shell's `tone` builtin opens `/system/dev/audio`, the driver points the
  codec's converter at the stream, drains a BDL ring, and QEMU's `wav` backend
  carries the samples to a file this project's gate reads. A device node's
  *open* was the blocker before this and no longer is: it is authorized by the
  node's own descriptor, the way the stat syscall always answered, and the
  audio node is writable by any user.

  It plays on the device-tree machine too. The probe used to read BAR0 out of
  x86_64's configuration mechanism by hand, which is why the module resolved
  to `hda_absent.rs` on AArch64; it now asks
  `arch::platform::pci_register_window` for a window, the same call NVMe
  makes, and the platform hands back the BAR already mapped — through port I/O
  on a PC, through the ECAM window and a low alias on `virt`. `make
  check-aarch64-hda` types the same `tone 440 200` at the shell and reads the
  same host WAV backend, so the file is one driver on two buses, and the
  `tone` builtin is no longer gated by architecture: the node exists on every
  machine, and a machine without a controller refuses the write.

  The wave used to come out an octave low, and the reason was the last place
  anyone looks: `SET_STREAM_FORMAT`'s payload. A codec's verbs come in two
  payload widths and the driver sent this one through the eight-bit form, so
  what reached the converter as its format word was the low byte of the
  stream tag — a *valid* word for a one-channel stream. The codec believed it,
  played the two interleaved samples of every stereo frame one after the
  other, and halved the pitch of everything, while each register read back
  exactly as written. `docs/status.md`'s own gate could not see it because it
  asserted the wave's shape and amplitude, which both survive; the check now
  measures the period and asserts the frequency, and the residual (436 Hz for
  440) is the shell generator rounding a half-period to whole frames rather
  than a copy of the old guesswork.
- **One PCIe driver on the device-tree machines.** The ECAM walk finds devices,
  the kernel's own resource pass gives their memory BARs addresses out of the
  window the host bridge's `ranges` describes (no firmware ran one), and
  `drivers/virtio_net.rs` drives a `virtio-net-pci` through the modern (1.0)
  transport — that is the network device both gates boot with, DHCP and SLAAC
  included, while riscv64's default gate keeps the virtio-mmio path covered.
  On riscv64 the MSI-X table is programmed and *owned per device*: the driver
  claims one identity per table entry it names at probe time (a
  registration is a table entry, not a hardware access, so this works before
  the interrupt controller is up), the platform then programs the table with
  exactly those identities, reads it back, unmasks the function, and walks the
  receive side once through the driver's own handler so a delivered message is
  attributed rather than counted spurious. The identities themselves come from
  an allocator in the controller, so two devices cannot be handed the same ones
  and a second claimant is refused rather than silently replacing a handler
  somebody waits on. AArch64 reaches the same place by its own road: the GICv3
  controller (`src/arch/aarch64/gicv3.rs`) receives LPIs, and the ITS
  (`src/arch/aarch64/its.rs`) translates the messages that become them. NVMe
  claims through the same path now — its completion queue takes one entry, on
  every machine whose controller can carry the message, so the class that has
  to be *woken* rather than one that also polls is what exercises the claim
  path here (`make check-aarch64-nvme` boots a GICv3 machine and asserts a
  completion MSI reached the driver's handler).  What is still missing: HDA,
  which plays a tone here (`make check-aarch64-hda`), asks the platform for a
  window and claims no identity — its controller has no MSI-X at all, so
  there is no table to claim.  What is *not* missing is the class itself: the
  same files the PC compiles drive the device-tree machine, which is what
  makes a second PCIe device *class* work here rather than a second device of
  the same class.
- **Verified under QEMU only**: no real-device validation on bare-metal
  hardware yet.

---

### 2. I/O Subsystem

| Component | Now | Missing |
|-----------|-----|---------|
| File descriptor table | Per-process table, dup/dup2/F_DUPFD, close-on-exec, inheritance across spawn | No descriptor passing between processes |
| Pipe | VFS-backed anonymous pipe, fcntl-resizable buffer, per-end O_NONBLOCK | No splice/tee; no named-pipe filesystem entry |
| Block cache | Fixed-size LRU, write-through for metadata and write-back for data, dirty aging by the maintenance thread, and read-ahead — on for SimpleFS at depth 4, where a sequential miss reads its own block and the lookahead in one request (stopping at the first cached block), so a demo boot asks a device for 175 reads and 259072 bytes, 17 of those requests being the metadata-slot comparison a commit makes against the slot it is about to overwrite (`BlockCache::cached`, which leaves the workload's hit and sequential counters alone).  All three write-back calls (`flush`, `flush_aged`, `flush_range`) are one helper that submits the dirty blocks a device can hold, drops the cache's lock while they are in flight, and clears a block's flag only if it was not rewritten meanwhile — so a flush no longer holds every reader behind it, and SimpleFS now takes part in the background write-back the maintenance thread drives (only fat32 did before, [RFC 0009](rfcs/0009-queue-the-writes-a-flush-makes.md)) | Capacity is a fixed constant, so a large working set thrashes; no real-disk benchmark, and the boot-work line reports the cache's counters but nothing compares them *per workload*; every *cache* read in the tree is synchronous and its lookahead rides in the same request as the demand, so read-ahead buys commands rather than concurrency here — the queued interface exists and the write half is used by the flush above, but overlapping *this* read means splitting a request the cache decided to keep whole, and [RFC 0008](rfcs/0008-keep-a-sequential-miss-in-one-request.md) decides against it: the coalescing is worth 36 % of a boot's device commands and the split buys the caller no earlier block; the other filesystems keep read-ahead off until a boot measures them |
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
- **I/O paths verified under emulation only**: the blocks a boot reads and
  writes are counted and gated (`make check-perf-baseline`), but no latency or
  throughput under load has been measured on real disks or SSDs.

---

### 3. Virtual File System

The VFS is the largest subsystem in the tree. Its native filesystem, its
external drivers, its recovery machinery, and its Unicode layer are described
below; the mechanism itself is [docs/kernel/fs.md](kernel/fs.md).

#### 3.1 Native Filesystem

| Component | Now | Missing |
|-----------|-----|---------|
| SimpleFs core (V2/V3/V4) | Full read/write, per-file data checksum, undo-log transactions and the V3+ two-phase commit; V3 persistent security descriptors, V4 xattr table and data-reduction flags; a commit writes only the metadata blocks the slot does not already hold, so a demo boot puts 229888 bytes on a device for 13611 bytes of `VNode::write` (735232 before, and 25088 bytes more read: the first differential commit reads a slot the mount never cached) | The image builders produce V2, so the V3/V4 layouts are exercised by the tests rather than by a boot; recovery is exercised by the in-tree fault matrix rather than a searching fuzzer; no real-disk validation; the commit compares against the slot's own bytes, which is exact but means it reads the slot each time rather than remembering the last image — a per-block shadow of the previous generation is the alternative if the reads ever show up; and the retired slot is left a generation behind, so `check_and_repair` reports one issue for a volume that has committed since it was mounted |
| Disk installation | `cargo run -- install <disk>` adds the kernel's three zones to a disk a machine already has, reading and writing it in blocks so a machine's own volume is installed without holding it ([RFC 0028](rfcs/0028-install-through-a-device-not-an-image.md)): a zone's slot is the entry with its type GUID or the first free one, and every other entry is copied back byte for byte.  `install --new-table` gives a table-less disk a fresh GPT ([RFC 0025](rfcs/0025-write-a-table-onto-a-disk-that-has-none.md)); anything else is refused.  The system zone is installed as the **pair** it is read as: A older, B newer, both committed ([RFC 0026](rfcs/0026-install-the-system-pair-not-one-slot.md)).  The install **shows a plan** computed without touching the disk, asks for a typed `yes` (`--yes` for scripts), and reaches a refusal before the question.  `make check-x8664-install` keeps a `stranger` partition through the install, boots the result and the fresh-GPT disk, and checks both answers; and a boot disk whose own table names no zone of this kernel's is left alone rather than read at the fixed offsets, which is the disk a real machine has ([RFC 0027](rfcs/0027-never-mount-a-fixed-offset-over-a-table.md)) |
| TmpFs | In-memory, full read/write, xattrs | Contents do not survive a reboot; no mount in the tree |
| DevFs | The kernel's own devices as nodes, and every device a probe bound as a directory of facts (`driver`, `category`, `bus`) | Read-only; node metadata is the registry's, not the filesystem's; a discovered device has no I/O interface of its own yet |
| ProcFs | Process and runtime state as read-only files | Read-only view; process control stays in syscalls |
| Unicode layer | Unicode 15.1 NFC/NFD, case folding, GB18030, OEM code pages | Tables are fixed at Unicode 15.1; there is no locale database |

#### 3.2 External Filesystem Drivers

These parsers and their tests are in the tree, but no boot path and no runtime
call registers or mounts one; the rows below describe what is implemented, not
what a running machine can reach. `install_zone_devices` has an ext4 branch
behind `rootfs_type`, and `set_rootfs_type` has no caller.

| Driver | Now | Missing |
|--------|-----|---------|
| ext4 | Read/write; journaling (revoke replay, v3 checksum tags), extent tree, dir index | Journal replay is verified on emulated images; not exercised against real corruption |
| F2FS | Read/write; checkpoint (SIT persistence), orphan recovery, atomic CP+SB write | Same emulation-only validation; no ageing or garbage-collection stress |
| XFS v5 | Read/write with journal replay; B+tree, CRC32C, v5 superblock | Same emulation-only validation; no xattr exposure |
| exFAT | Read/write; VFAT extension | No journal, so crash behaviour depends on the write order; QEMU only |
| FAT32 | Read/write; LFN, OEM code pages, FSInfo accounting | No journal; QEMU only |
| BtrFS | Read-only; B-tree traversal | Write support is the mid-term roadmap item |
| NTFS 3.1 | **Reads and writes a volume in the layouts the format gives**: MFT parsing and attribute resolution, a path through the index, `$INDEX_ROOT` into its `$INDEX_ALLOCATION` blocks and a *tree* of them; a write that lands, proved by a **second mount**; files and directories created, renamed — a name an `$ATTRIBUTE_LIST` moved included, and a name too long for the record it lives in given room inside another extension — and removed; an index block that **splits** — a leaf two levels down into the block above it, and a full block above a leaf **splits in its turn** — a promoted key **removed** by its predecessor, blocks merged, a freed block **taken again**, the index bitmap **grown**, as a value or a file, and the allocation's free **tail given back**; a value that **converts** to runs and back as it grows and shrinks, a **hole** punched or filled, a **compressed** stream **decoded and written**, and a **torn** write is refused rather than read as half old (the update sequence moves on); `$Bitmap`, `$UpCase`, `$ATTRIBUTE_LIST`, the **dirty** bit, and the **`$MFTMirr`** brought back in step when the volume **settles**.  [RFC 0012](rfcs/0012-the-harness-an-ntfs-write-is-proven-on.md) has the stages. | An **encrypted** stream is refused rather than misread ([RFC 0013](rfcs/0013-refuse-the-ntfs-streams-this-driver-cannot-read.md)); a sparse stream is read — its holes are zeros — and written into: a write into a hole claims the clusters it reaches; no `$LogFile`.  `make check-ntfs-image` mounts a volume `mkntfs` made and has `ntfs-3g` judge what the driver wrote; the rest is a fixture this driver built. |
| SquashFS 4.0 | Read-only; several compression algorithms | Read-only |
| ISO 9660 | Joliet, Rock Ridge, **file data, length and space writable**, **files and directories can be created, removed, renamed and moved**: a file is one raw contiguous extent whose two fields — where it starts and how long it is — are in its directory record, so writing bytes or a length changes nothing else; a create, a remove and a rename are a record appended to a directory's extent, shifted out of it, or moved between two.  Growing past the block an extent has takes blocks from the volume's **free space** — the system area, the descriptor set, the path tables, a boot catalog and its images, both directory trees and every continuation area a record names are what the volume's structures are, and a block map walks them all — in place when the extent is the volume's last and by moving it into a hole otherwise; a removal or a shrink that gives up the volume's last blocks also lowers the size it declares.  A directory's create, removal or move rebuilds that tree's **path tables** from it — they are derived, not edited, because a directory's number is its position — and its own ".." follows a move; each tree's tables go in the descriptor that names it, and the tests check them against the properties a reader depends on, since the reader itself walks records and never consults a table.  A created or renamed entry carries a Rock Ridge **name** entry, so the name is the caller's — lower case, spaces and all — and the identifier beside it is only the mangled form a reader that ignores Rock Ridge sees.  Opening a *writable* volume declares the extension those entries need: the root's own "." record gains `SP` and a `CE` naming a continuation block, because the `ER` entry is 237 bytes and cannot fit in a record, and the root extent is rebuilt elsewhere and the volume repointed at it ([RFC 0011](rfcs/0011-make-iso9660-file-data-writable.md)) | A name too long for the 255-byte record that has to hold it is refused; opening a writable volume **writes** — once, idempotently, and only where the volume does not already declare the extension — which is the retrofit's price, and it is skipped when the medium has no room for it or the descriptor's root size is a lie; the block map is **complete or absent**, so a volume with a descriptor this driver does not know, a supplementary descriptor that is not Joliet's, no descriptor-set terminator, an extended attribute record or a tree deeper than the walk follows is one it **appends** to instead of handing any block out of, and an extent with something after it still pays a copy to grow; a directory that still holds something refuses to be removed (`Busy`) and a move into itself is `InvalidArgument`; on a volume with **two trees** only what both trees agree on is written — an overwrite inside a file's length, because the data is one extent under both records — and a length change, a create, a removal and a rename are `Unsupported`, since the trees spell a name differently by design and nothing says which record in the other tree is the same file's; a torn write is a half-written file, because the format has no journal and no data checksum; the tests are the harness (there is no ISO image on the demo disk) |
| EROFS v1 | Read-only; compact inode format | Read-only |

#### 3.3 VFS Layer

| Component | Now | Missing |
|-----------|-----|---------|
| VFS core (mount, path resolution, ops) | Full path resolution, mount and unmount, per-node operations; a node answers where its data and its holes are (`VNode::next_extent`, [RFC 0017](rfcs/0017-ask-a-file-where-its-holes-are.md)) for the two `lseek` values that ask (`SEEK_DATA`, `SEEK_HOLE`), and a node with no holes answers from the trait's own default rather than a refusal | One mount table for the machine; no per-process mount namespace; the answers are the run list's, so a hole inside a compression unit is not one (the unit walk's reader is RFC 0014's) |
| Volume recovery | Transaction undo-log replay and check-and-repair at boot | Boot-time only, under the filesystem lock; no online repair |
| Fault injection matrix | Single- and dual-fault, multi-cycle crash testing, and the V4-only crash points — the shadow xattr table and the two superblock phases a V3+ commit adds (`tests/simplefs/fault_matrix.rs`) | Deterministic and bounded, so it does not search for a failing sequence; V3 has no case of its own, since its commit sequence is V4's without the xattr table |
| Extended-attribute (xattr) table | SimpleFs V4 persistent storage and tmpfs in-memory; the xattr syscalls | The VNode default is `Unsupported`, so the other filesystems do not expose xattrs; tmpfs is not mounted, and the shipped SimpleFs images are V2, so the persistent table is exercised by the tests |
| Transparent file compression | Encoder and decoder in `src/fs/simplefs/compression.rs`; the per-inode flag round-trips through the on-disk format | Nothing calls the encoder: no write path produces a compressed extent, and `set_file_flags` is unimplemented in every backend |
| Cross-file deduplication | Sharing and copy-on-write unsharing in `src/fs/simplefs/dedup.rs`; the refcount map starts empty at mount | `maybe_dedup_inode` and `unshare_inode_extent` have no caller, so no extent is ever pooled; `get_file_flags`/`set_file_flags` are unimplemented |
| Block backend abstraction | ATA, VirtIO and NVMe all implement one `BlockDevice` trait, which also carries the queued path: `queue_depth`, `submit_read` (whose buffer must outlive the ticket, so it is `unsafe`) and `submit_write` (which the driver copies, so it is safe), with one `poll` for both.  A request carries a **run** — a whole number of blocks — and the NVMe driver issues one command for it, up to the 16 blocks its two-frame per-slot buffer holds; a longer request is split by the waiting calls, and a driver may refuse a run it cannot hold ([RFC 0010](rfcs/0010-carry-a-run-in-one-queued-request.md)).  A waiting read and a waiting write are those pairs polled at once, so the driver has one path per direction.  Both halves have a caller that does work somebody wanted: the write half is a flush's independent dirty blocks ([RFC 0009](rfcs/0009-queue-the-writes-a-flush-makes.md)), and the read half is the mount — the two superblock mirrors and, now that a request can carry one, the inode and dirent tables ([RFC 0007](rfcs/0007-hold-a-second-request-on-a-device.md), [RFC 0008](rfcs/0008-keep-a-sequential-miss-in-one-request.md)) | No hot-remove or device-error recovery path; a run bigger than the driver's buffer is the caller's to split, and only the waiting calls do |

**Strengths:** the native SimpleFs with undo-log transactions and the two-phase
commit; a VFS that mounts the storage zones, the synthetic views and a
userspace FUSE server; parsers with their own tests for ext4, F2FS, XFS,
exFAT, FAT32, BtrFS, NTFS, SquashFS, ISO 9660 and EROFS; and the AES-XTS and
PBKDF2 primitives.

- **Multiple filesystems, one mounted set**: the external drivers are parsers
  with their own tests, but a machine boots SimpleFs zones, the synthetic
  views and whatever a `FuseMount` adds.
- **Unicode 15.1**: full NFC/NFD normalization and a GB18030 codec.
- **Crash safety**: SimpleFs uses undo-log transactions and two-phase commit.
- **Encryption at rest, unwired**: `EncryptedBlockDevice` wraps a block device
  in AES-256 XTS and the LUKS2 parser recovers a key with PBKDF2, but nothing
  constructs either and no mount is encrypted.
- **Read-only is structural**: the synthetic filesystems (`/proc`, `/service`)
  implement the VFS `ReadOnlyFileSystem` half, and one blanket impl supplies
  every mutation as `PermissionDenied` — a view cannot declare a mutation, so
  it cannot forget to refuse one.

**Weaknesses:**

- **Unmounted drivers**: ext4, F2FS, XFS, exFAT, FAT32, btrfs, NTFS,
  SquashFS, ISO 9660 and EROFS have parsers and tests but no mount.  Of the
  read-only ones, ISO 9660 has moved furthest: a file's *data*, its *length*
  and its *space* are writable, files and directories can be created, removed,
  renamed and moved, and a created name is kept in a Rock Ridge name entry —
  but none of the ten is reachable from a boot yet.
- **Journal replay verified on emulated disks**: coverage of real-corruption
  edge cases is limited.

**SimpleFs V4 format** (inherits V3's persistent security descriptors and
`pending_commit` two-phase commit):

- **Extended attributes**: persist per-inode in active/shadow xattr-table slots
  flushed in the same two-phase commit as the inode/dirent tables. SimpleFs
  and tmpfs both implement the `setxattr`/`getxattr`/`listxattr`/`removexattr`
  semantics.
- **Transparent per-file compression**: the encoder and decoder are in
  `src/fs/simplefs/compression.rs`, but no write path calls the encoder and no
  read path calls the decoder, so a compressed extent is never produced or
  consumed; `SetFileFlags` (#155) is unimplemented in every backend.
- **Cross-file deduplication**: the sharing and copy-on-write unsharing logic
  is in `src/fs/simplefs/dedup.rs`, but `maybe_dedup_inode` has no caller and
  the refcount map starts empty at mount, so no extent is pooled; `GetFileFlags`
  (#156) is unimplemented in every backend.

#### 3.4 Encryption at Rest

| Component | Now | Missing |
|-----------|-----|---------|
| AES-256 + AES-XTS | Crypto engine in the kernel | No hardware acceleration path |
| PBKDF2 key derivation | Key stretching for disk encryption | One KDF; no Argon2 or keyring |
| EncryptedBlockDevice | Transparent block-device wrapper under any filesystem | Nothing constructs one; no rekey or key rotation; one key per device |
| LUKS2 header parser | LUKS2 on-disk header parsing and `luks2_open` key recovery | No caller: no keyslot management or `cryptsetup`-style control surface |

---

### 4. CPU Scheduler

| Component | Now | Missing |
|-----------|-----|---------|
| Scheduler core | Preemptive round-robin with priority classes | Round-robin and FIFO only; no fair-share or deadline class |
| Thread lifecycle | Spawn, exit, terminate, detach | — |
| Context switch | x86_64, AArch64, RISC-V (per-arch assembly) | — |
| Process/thread types | States, priorities, credentials, scheduling policies | — |
| Job control | The shell tracks jobs and signals the foreground pid | No kernel process group: no `setpgid`-style call, so terminal ownership is not modelled |
| SMP discovery | x86_64: ACPI MADT, reading both processor record forms — the Local APIC (type 0) and the Local **x2APIC** (type 9, for a machine that names processors that way), an x2APIC ID past the byte this kernel addresses with skipped rather than truncated — and firmware's disabled placeholders skipped (`make check-smp-runtime` boots `-smp N,maxcpus=M` and asserts the skip count); AArch64: PSCI, each core started by the `reg` its device-tree node names rather than by its position in the tree; RISC-V: the same FDT `reg` list and SBI HSM, with the hart id translated to a logical slot by a table the trampoline reads. Both device-tree machines keep the two numbers apart — a hart id and an MPIDR are the machine's, a slot is the kernel's — and every per-CPU table is sized by one kernel-wide cap; `-smp 17` is the boundary the checks cross now, requiring all 16 APs online and the boot CPU at slot 0 | — |
| Timer tick | Scheduler quantum management | On x86_64 the PIT is routed to one LAPIC, so APs take no timer interrupt; a sleeping thread's expiry is swept by whichever CPU ticks |
| Waker | Thread wakeup notification with a per-CPU reschedule flag | Cross-CPU wakeups set a flag or send an IPI; RISC-V waits for the target hart's next tick |
| Scheduler stats | Load average (sampled ring), per-thread CPU ticks, idle tracking, ProcFs integration | — |
| Priority boosting | Starvation boost: Normal → High after an idle threshold, demote after a short run | — |
| Work stealing | Cross-CPU load balancing, NUMA-aware victim selection; the placement runs in a two-node boot (`make check-perf-baseline-numa`) | Validated under QEMU only; no real-load validation |
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
  tested under QEMU, and the work a four-CPU boot does is counted rather than
  measured against load (`make check-perf-baseline-smp`, and
  `make check-perf-baseline-numa` for the same four CPUs arranged as two
  nodes), so a balancer that keeps up with an idle machine and not a busy one
  still passes.  The two-node boot is the first gate that ever ran with a
  topology — the SRAT/SLIT walk, the node-aware allocators and the placement
  had only ever run in unit tests — and it found the discovery costs about
  seventy allocations and changes nothing else in the boot's work.

---

### 5. Memory Management

| Component | Now | Missing |
|-----------|-----|---------|
| Physical frame allocator | Dynamic detection via Multiboot2/FDT, and on the PC the PVH block's own E820-shaped table for a direct `-kernel` boot, so every machine answers with a map; bump pointer plus recycled free ranges; the pool is a reserved span of the kernel's address space (`__pool_start`..`__pool_end`, outside every loadable segment and outside the boot's clear), and the allocator is sized from the machine's answer by `managed_pool_bytes` — a boot whose RAM ends inside the span manages what is there and says so.  The minimum is **gated**, not claimed: `make check-x8664-low-memory` boots a 96 MiB machine and asserts it reports its own number, clamps the pool to it, and reaches the ring-3 shell — the floor itself is set by the fixed 64 MiB kernel heap and the image | The span's size is derived per machine by each linker script from the window the pool lives in (768 MiB on the device-tree machines, 512 MiB on the PC, where the stack window is nearer), and a link-time `ASSERT` refuses a pool that would cross its window's margin; no memory hotplug or hot-remove; a hand-off that describes nothing at all manages the whole span, since there is no answer to clamp with |
| NUMA frame allocators | Per-node allocators (`MAX_NODES`), `set_node_range()`, fallback to node 0; the SRAT/SLIT walk is a **pure parser over a table's bytes** (`parse_srat_bytes`/`parse_slit_bytes`), host-gated on the byte layout **QEMU writes** (the split proximity domain of a type-0 record, the two-byte reserved field of a type-2 one) and on truncated and overlong tables — the offsets a real machine and QEMU both use, which an earlier parse read wrong so every CPU landed on node 0 | Topology discovery is exercised under QEMU; no NUMA hardware validation |
| TLSF heap allocator | Bounded heap, fixed free-list table, O(1) alloc/free | Fixed size: the heap is carved once and does not grow |
| Page table management | Per-arch tables, identity map, user address spaces, 2 MiB and 1 GiB huge pages | x86_64 has no PCID, so a context switch invalidates translations |
| KASLR (x86_64, `kaslr` feature) | `kernel_entry` copies the image to a 2 MiB-aligned base the machine's memory map allows, patches the compiled-in relocation table's sites by the delta, moves `rsp` into the copy's boot stack and continues there (the kernel's own GDT is loaded by `init_early` before anything could use the boot stub's); the table is generated by `make gen-kaslr-relocs` and proven by `make check-kaslr-relocs` (every record equals the symbol it names plus its addend; the pool's ends and the image's end are in it), and `make check-x8664-kaslr-runtime` requires the tracked table to equal a fresh generation and boots the relocated kernel to a typed shell | APs come up under relocation too — the trampoline entry `ap_entry` is an absolute immediate whose site is in the table, so the copy enters the copy's own `ap_entry` — and the gate boots four CPUs and requires three APs online with threads dispatching (`make check-x8664-kaslr-runtime`); the loader assumption is asserted on the image (ET_EXEC, every `PT_LOAD` `p_paddr == p_vaddr`, entry == `_start`); the base is drawn from the TSC, so no unpredictability is claimed; the candidate search is a host-tested pure function (`src/arch/x86_64/kaslr_placement.rs`), so the hole cases no boot can describe are unit tests |
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
| x86_64 APIC + IOAPIC | SMP IPI, timer, I/O routing; ISA IRQs are routed by **global system interrupt**, read from the MADT's interrupt-source overrides (`parse_madt_interrupt_overrides`, host-gated on the byte layout and on the captured laptop's own two overrides) — so a machine that puts IRQ 0 on pin 2 has its tick routed there, and a machine naming no override keeps the identity map; the I/O APIC is driven at the address the machine **declares** in its MADT I/O APIC record (`parse_madt_ioapics`, host-gated), mapped through the general device mapper rather than a fixed window, so a board that places the controller elsewhere is followed | — |
| AArch64 exception vectors | EL1 sync/IRQ/FIQ/SError, EL0 sync | — |
| AArch64 GIC | GICv2 and GICv3 register layouts, chosen from `GICD_PIDR2` (`src/arch/aarch64/gicv3.rs`); LPIs, with one pending table per CPU; the ITS that translates a device's message into one, with a collection per CPU (`src/arch/aarch64/its.rs`) | A machine whose device cannot carry a requester ID would need a window of its own in front of the ITS |
| RISC-V trap handler | U-mode ecall, timer, external interrupts | — |
| RISC-V PLIC | PLIC initialization from FDT | The default machine has no IMSIC, so the PLIC stays the external controller there |
| RISC-V AIA APLIC | Both delivery modes.  MSI mode: a wire source is configured level-high, given an identity and a target hart, and delivered as the message an IMSIC receives.  Direct mode (`aia=aplic`, no IMSIC behind the domain): the source is configured for this hart's own delivery window (`idelivery`, `ithreshold`, the domain's `IE`) and the trap claims it by reading `claimi`, which answers `topi` — source and priority in one word, decoded to the source number so every path dispatches by the same identity (`src/arch/riscv64/aplic.rs`); `make check-riscv64-aplic-direct-runtime` types at the shell and asserts the RX-interrupt landmark, so the path is a gate rather than an arming that never delivers | The MSI destination is the boot hart, since the firmware's message address carries no hart index; direct mode's `iprio` is a two-role policy (console most urgent, device below it, threshold zero) rather than per-driver numbers |
| Common interrupt abstraction | `InterruptController` trait | — |
| Thread exception handling | Page fault recovery, signal delivery | — |
| PAN/SMAP emulation | AArch64 PSTATE.PAN, x86_64 SMAP, RISC-V SUM | Nothing known: the window is opened in one module, the guard restores what it found, and the paths that can wait stage first (`make check-user-access-windows`) |
| MSI/MSI-X programming | Message composition, fixed vector numbers and an acknowledge handler on x86_64; a vector window of its own IDT with a stub per vector, a table programmed once the local APIC is up, and the vector itself as the identity the handler registry answers; AIA IMSIC with per-device claims on RISC-V; GICv3 ITS with per-device claims on AArch64; a claim takes one identity per **table entry the driver names**, and every entry it does not name is written masked, so a device takes the vectors its work needs rather than the ones its table has ([RFC 0005](rfcs/0005-claim-the-msix-entries-a-driver-names.md)); a claim enables MSI-X with the **function mask set** and arming clears it — the order a device that consults the capability while being configured (NVMe's `Create I/O Completion Queue`) needs | The PCIe virtio-net, virtio-blk and NVMe drivers each claim their own identities on the machines whose controllers can carry them; HDA's controller has no MSI-X table (QEMU's offers classic MSI only) and keeps polling, which [RFC 0024](rfcs/0024-what-the-hda-controller-signals-with.md) decides |
| NMI handling | x86_64 dedicated vector path, AArch64 SError/FIQ dedicated path, handler registry | No architectural NMI source on RISC-V, so that entry stays dormant |
| Interrupt load balancing (SMP) | IOAPIC redirection re-target, GIC SPI affinity, PLIC per-context enable | Runs from the tick; no routing-latency measurement |
| Interrupt stats interface | Per-CPU/per-vector counters, NMI/IPI totals, balancer state (SystemInfo #9) | — |

**Strengths:** architecture-complete exception handling across all three
targets, with PAN/SMAP emulation, MSI/MSI-X on the machines whose kernel
programs a device's table, NMI handling, and load balancing.

- **Exception handling**: complete on all three targets; double-fault handling
  on x86_64; the AArch64 vector table classifies synchronous exceptions, IRQs,
  FIQs, and SErrors; PAN/SMAP implemented (the `asm nomem` fix was deployed).
- **MSI/MSI-X**: on RISC-V the AIA IMSIC receives MSIs and on AArch64 the GICv3
  ITS translates them, each with the PCIe virtio-net driver claiming its own
  device's identities.  On x86_64 the message is composed here, a device's
  table is programmed here, and the vector a message names is looked up in the
  same handler registry — so the NIC's queue completions arrive as interrupts
  on that machine too
  ([RFC 0003](rfcs/0003-program-the-msix-table-on-x86_64.md)).
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

- **Message-signalled interrupts are three drivers deep on AArch64, and the
  bus carries four device classes.** The ITS maps a collection and an LPI
  pending table per CPU, and a device's entries are placed round-robin over
  the CPUs that can receive, so the PCIe virtio-net driver's queues are
  completed by different cores, and the PCIe virtio-blk driver beside it
  claims a range of its own under its own DeviceID. What that buys is
  evidence: the placement is a property of the machine rather than of one
  driver. NVMe joined them: its completion queue claims one entry under its
  own DeviceID, and `make check-aarch64-nvme` now boots a GICv3 machine and
  asserts that a completion MSI reached the driver's own handler. What is
  still missing: HDA, which plays a tone through the same ECAM window
  (`make check-aarch64-hda`), claims no interrupt because its controller has
  none to claim — QEMU's `intel-hda` offers classic MSI, which this tree does
  not compose ([RFC 0024](rfcs/0024-what-the-hda-controller-signals-with.md)).  ([RFC 0001](rfcs/0001-spread-message-signalled-interrupts.md)
  is the design the placement follows.)
- **MSI-X on RISC-V is two drivers deep**: the AIA IMSIC is wired and a
  device's table is programmed; the virtio-net PCIe driver and NVMe's
  completion queue claim interrupts through it (`make check-riscv64-nvme`
  boots an `aia=aplic-imsic` machine and asserts delivery); the default
  machine has no IMSIC at all, so the PLIC remains the external-interrupt
  controller there, and NVMe on it polls.
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
| **Internet** | IPv4, IPv6, ICMP, ICMPv6, IGMP, MLD; NAT and IPv4 options are in the tree | NAT is consulted but never enabled outside tests; IPv4 options are feature-gated |
| **Transport** | TCP (congestion control, ECN), UDP; a UDP socket has a wait queue, so a receiver parks until a datagram is delivered; SCTP and DCCP are in the tree | Congestion control is Tahoe/Reno only; no CUBIC or BBR; DCCP has no receive dispatch and SCTP has no syscall, so neither carries a connection |
| **Application** | DHCP (discovery and renewal), DNS (cache and resolve, waiting on the socket rather than polling), mDNS, NTP; PPP/PPPoE state is in the tree | IPv4 only: no DHCPv6 or prefix delegation; DNS has no DNSSEC validation; each lookup allocates its own source port and transaction id, so the old shared-port collision is gone ([RFC 0030](rfcs/0030-give-each-dns-lookup-its-own-source-port.md)); the PPPoE consumer is enabled only by a test |
| **Security** | TLS 1.3 (handshake, record, certificate chain), IPsec outbound ESP/AH transform | TLS trust anchors are a fixed built-in demo set; IPsec inbound is unwired and SAD/SPD is manual |
| **VPN** | WireGuard handshake, transport and session tables (Noise_IKpsk2, ChaCha20-Poly1305, key management) | Not wired up: nothing outside the module constructs a device, so a program cannot open a tunnel yet |
| **Multicast routing** | MFC/VIF forwarding, IGMPv2/MLDv1 router mode, MRT API | PIM-DM only, and only under a feature flag; no PIM-SM |
| **Raw** | Raw sockets, raw packet | Not every raw entry has a typed shared-library wrapper |
| **Educational¹** | CSMA/CD, CSMA/CA, STP, IPv4 Options, Mobile IP, RSVP, PIM-DM | Compile-time gated, so it is outside the default build |

¹ Gated behind `feature = "educational_networking"`.

#### 7.2 TCP Implementation

| Component | Now | Missing |
|-----------|-----|---------|
| Segment handling | Segmentation, reassembly, retransmit | — |
| Connection table | `BTreeMap` keyed by `(local_port, remote_ip, remote_port)`, plus the state machine | — |
| Congestion control | Pluggable framework with Tahoe and Reno | No CUBIC or BBR; no throughput baseline — the loopback exchange `make check-perf-baseline-net` counts is one datagram, which never leaves the first congestion window |
| ECN (Explicit Congestion Notification) | Negotiation and marking | — |
| Timer management | RTO with exponential backoff, retransmit limit, TIME-WAIT | No delayed ACK; `SO_KEEPALIVE` is stored but no probe is sent |
| Window scaling | Window-scaling option | — |

#### 7.3 Network Syscalls

The network ranges are in the `SyscallNumber` enum. Not
every network syscall has a typed wrapper in the shared user library
(`src/user/shared/`); a program that needs an unwrapped one calls the raw entry
point.

**Strengths:** a native (non-lwIP) TCP/IP stack that carries a boot's
networking, with more protocols in the tree than the receive path dispatches.

- **Protocol coverage on the wire**: link (Ethernet, ARP), internet
  (IPv4/IPv6/ICMP/ICMPv6/IGMP/MLD), transport (TCP with congestion control +
  ECN, UDP), application (DHCP, cached DNS, mDNS, NTP, SLAAC).
- **IPsec**: ESP + AH with AES-GCM / ChaCha20-Poly1305 AEAD and HMAC-SHA256,
  transport and tunnel modes, SAD/SPD managed through dedicated syscalls — on
  the outbound path only.
- **Multicast**: IGMPv2/MLDv1 host state and the MRT management API; PIM-DM
  messages are parsed, but the flood/forward helpers have no live caller.
- **IPv6 hardening**: path-MTU discovery (RFC 8201, with TX fragmentation),
  atomic fragments (RFC 6946), extension-header order and chain-length limits
  (RFC 8200 §4.1), routing-header type-0 rejection (RFC 5095),
  overlapping-fragment discard (RFC 5722).
- **TLS 1.3**: implemented as a kernel module, with chain verification against
  a built-in demo root store.
- **Deferred periodic work**: the scheduler tick advances the stack's clock
  with a single atomic add; the pass that acts on it — ARP eviction, TCP
  retransmit and TimeWait, DHCP renewal, SLAAC, IGMP/MLD, NTP, mDNS — runs on
  the maintenance thread, so the transmits inside it wait for the device's
  completion interrupt in thread context instead of inside the interrupt
  handler that would have masked it.

**Weaknesses:**

- **Not every network syscall is wrapped** in the shared user library.
- **A short write has nowhere to wait**: a TCP read parks on the connection
  and `kernel-net-rx` polls for it ([RFC 0031](rfcs/0031-let-a-tcp-reader-wait-instead-of-spin.md)),
  and name resolution parks on its socket ([RFC 0029](rfcs/0029-wait-for-a-dns-answer-instead-of-polling.md)),
  but a write that finds `MAX_SEND_BUFFER` full returns a short count and the
  ABI has no way to ask when room appears ([RFC 0032](rfcs/0032-decide-what-a-full-send-buffer-does.md)).
  A caller that must send more retries by spinning; `poll` with writability is
  the missing piece.
- **In-kernel TLS has a fixed trust set**: the anchors are compiled in, with no
  way to add or replace one at runtime.
- **Educational protocols are feature-gated**: CSMA/CD, STP, Mobile IP, RSVP,
  PIM-DM, etc. compile only under `educational_networking`.
- **Throughput and concurrency not benchmarked**: the packets a boot sends and
  receives are counted and gated (`make check-perf-baseline`), and the work a
  four-CPU boot does — which is where the cross-CPU paths first have any work
  to do — is gated too (`make check-perf-baseline-smp`), but neither is a
  throughput measurement: no baseline has been established for what a loaded
  machine or a load-balanced, multi-core workload gets through.

---

### 8. IPC / Synchronization

| Component | Now | Missing |
|-----------|-----|---------|
| Pipe | VFS-backed, anonymous, blocking read/write | No named pipe and no descriptor passing over a pipe |
| Signal | Signals 1-31 (a 32-slot handler table, slot 0 unused); install/enqueue/wait | No real-time signals (32-42), and no signal-storm stress baseline |
| Signal mask | Per-process blocked signal tracking, u32 bitfield | — |
| Async signal delivery | Signal frame on user stack carrying the interrupted context, arch-specific trampoline, sigreturn; all three architectures | The kernel half is on all three; the user-side trampoline the path needs is shipped by the shell payload's `sigasync` builtin on x86_64 only, so aarch64 and RISC-V are unexercised end to end |
| SA_SIGINFO support | Not implemented: a handler is entered with the signal number, and `wait_signal` returns a `ProcessSignalRecord { signal, sender_pid, payload }` | An siginfo_t (`si_code`, `si_uid`, `si_addr`) and the `SA_SIGINFO` flag |
| SA_RESTART support | Automatic syscall restart on signal return, RestartBlock per thread | — |
| sigsuspend (#135) | Atomic mask swap and thread suspend until a signal | — |
| POSIX timers (#137-140) | timer_create/settime/gettime/delete, per-process management, signal on expiry | — |
| eventfd (#107) | Counter/semaphore mode, EFD_NONBLOCK/EFD_CLOEXEC, poll/epoll integration, write-overflow EAGAIN | — |
| Event | Event flag synchronization | — |
| Condition variable | Blocking wait/wake | — |
| Mutex | Spin mutex over the IRQ-safe spinlock; does not park a waiter | No lock-contention benchmark |
| Semaphore | Counting semaphore, exercised by the process stress tests | No caller in the kernel |
| Spinlock | IRQ-safe spinlock | — |
| Shared memory | System V shm: shmget/shmat/shmdt/shmctl (#100-103); IPC_RMID frees an unattached segment at once, and a mapped one when its last detach arrives | Purpose-specific syscalls rather than a file- or handle-shaped IPC API; no POSIX `shm_open` |
| Shell pipeline | Two commands piped together by the ring-3 shell | No kernel process group; the shell tracks jobs itself |

**Strengths:** complete synchronization primitives, and signal machinery for
the POSIX subset it implements — see the missing column for what that subset
leaves out.

- **Synchronization primitives**: mutex, semaphore, condvar, event, and IRQ-safe
  spinlock are complete; eventfd (#107) provides counter/semaphore semantics
  (`EFD_SEMAPHORE`/`EFD_NONBLOCK`/`EFD_CLOEXEC`, write-overflow `EAGAIN`)
  integrated with `poll`/`epoll`/`io_uring` readiness probes.
- **Signals**: signals 1-31 with a `u32` mask; a handler is entered with the
  signal number (the sender's pid and the payload come back through
  `wait_signal` as a `ProcessSignalRecord`); `SA_RESTART` rewinds the
  interrupted instruction pointer at syscall dispatch boundaries (2 bytes on
  x86_64 `int 0x80`, 4 bytes on AArch64 `svc #0`, 4 bytes on RISC-V `ecall`)
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
- **Async delivery is gated on one architecture.** `make check-x8664-runtime`
  drives the shell payload's `sigasync` builtin, which installs a handler with
  its own trampoline, signals itself, and checks that a register the trampoline
  clobbers came back — so delivery, the trampoline, `sigreturn` and the
  register restore are all asserted there (RFC 0002).  The kernel's half is the
  same on all three machines, but the aarch64 and RISC-V payloads do not carry
  the builtin yet, so their halves of the path are compiled and unexercised.
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
| PAN/SMAP | Kernel-user memory isolation on all three architectures | See the interrupt section: the window is opened where the copy is, and the guard saves and restores it |
| Stack canary | `Thread::canary` exists and is never read | There is no check: the heap block's own canary and the guard page below a kernel stack are what detect an overrun |
| MAC type enforcement | Types on subjects and objects, allow rules enforced at the VFS file-access hook, `MacDenial` audit records; the three policy-writing syscalls (#175-177) require an admin token | Enforcement reaches files only: `check_process` and `check_network` exist with no call site, so a policy cannot refuse a signal, a trace or a connection; default is allow until a policy is loaded |
| Audit subsystem | Classified event types, ring buffer, syscall entry/exit hooks, AuditSetEnable (#143) and AuditReadLog (#144); persistence is **opt-in** from the boot's command line — `audit=persist` has the maintenance thread drain the ring to `/data/audit.log` (append, sync, then commit the consumer index), and the boot emits a `ConfigChange` record saying so.  `make check-x8664-audit-persist` types at the shell and reads that record back out of the file; the default stays memory-only, which the boot names and the gate checks | A boot without `audit=` captures nothing and persists nothing (the default, left to the operator); a process still enables its own event types with AuditSetEnable (#143), so a machine that records only the kernel's own events is the shape a default boot has |
| Service authorization | A privileged rc.d declaration names an account that must resolve; the grant or refusal is audited | Provenance, not authentication: no password is involved, so the elevated token is unauthenticated |

**Strengths:** a formal multi-level security policy and mandatory access
control that are unusual in a hobby kernel.

- **Biba integrity model**: a formal information-flow policy (System > High >
  Medium > Low).
- **MAC type-enforcement engine**: security types on subjects and objects, an
  allow-rule policy enforced at the VFS file-access checkpoint, management
  syscalls (#175-178), and MacDenial audit records on refusal.  The
  Process-class (ptrace/signal) and Network-class entry points are written but
  not called, so enforcement does not reach them yet.
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
- **Audit log is memory-only unless the boot asks otherwise**: the ring buffer
  is installed and written, and the maintenance thread drains it to
  `/data/audit.log` when the boot passes `audit=persist`.  Without that option
  the volume is memory-only and records are lost on reboot — the default, left
  to the operator rather than assumed.  Which records a *process* produces is
  still its own choice (`AuditSetEnable` #143), so a default boot records only
  the kernel's own events.
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
| SMP | Full (MADT + AP bringup; the tick is the boot CPU's) | Full (PSCI + GIC SGI; a core is started by the MPIDR its node's `reg` names) | Full (SBI HSM + per-hart vector, timer, and PLIC context; hart ids are translated to slots; a cross-hart wake waits for the target's tick) |
| Context switch | Full | Full | Full |
| PAN/SMAP | SMAP (stac/clac) | PSTATE.PAN (set/clear) | SUM (sstatus) |
| MSI/MSI-X | A vector window of its own IDT with a stub per vector, a table programmed once the local APIC is up, and the vector itself as the identity the handler registry answers; the PCIe virtio-net and NVMe drivers and the xHCI controller each claim their own identities | GICv3 ITS and LPIs, with a collection and a pending table per CPU; the PCIe virtio-net, virtio-blk and NVMe drivers each claim their own identities, and the NIC's queues are completed by different CPUs | AIA IMSIC; the PCIe virtio-net, virtio-blk and NVMe drivers each claim their own identities |
| PCIe | The legacy port pair (the 256-byte head holds every register read here; no ECAM window) | ECAM from the device tree, BARs assigned | ECAM from the device tree, BARs assigned |
| ASID allocator | — | Full (bitmap + CAS) | Full (bitmap + CAS) |
| FDT parsing | — | Full, including `/chosen`'s `bootargs` as the command line (QEMU fills it from `-append`) | Full, likewise |
| RTC | CMOS (ports 0x70/0x71) | PL031 from the device tree | goldfish RTC from the device tree (64-bit nanoseconds read as two words); both device-tree machines report the wall clock in their boot log, and their runtime gates assert it |
| Serial | Full (UART 16550) | Full (UART 16550) | UART 16550 (SBI fallback) |
| NUMA discovery | Full (ACPI SRAT/SLIT) | Full (FDT numa-node-id, distance-map) | Full (FDT numa-node-id, distance-map) |
| CPU frequency scaling | Full (MSR P-state) | Full (DT OPP) | Full (DT OPP) |

What each target still lacks:

- **x86_64**: no PCID, so a context switch flushes translations; the PIT is
  routed to one LAPIC, so APs take no timer interrupt.
- **AArch64**: MSI machinery is there — GICv3, LPIs, an ITS, and a placement
  that spreads a device's entries over the CPUs that can receive — and the
  PCIe virtio-net, virtio-blk and NVMe drivers each claim their own
  identities through it; a GICv2 machine has no ITS, where the claims are
  refused and the drivers poll.
- **RISC-V 64**: the most partial of the three. No architectural NMI source,
  a cross-hart wake waits for the target's next tick, and the default QEMU
  machine has no IMSIC, where a claim is refused and the driver polls.
- **All three**: verified under QEMU only; no bare-metal bring-up yet.

### Shared User Runtime (`src/user/shared/`)

| Module | Now | Missing |
|--------|-----|---------|
| `syscall.rs` | Typed syscall wrappers plus raw entry points | Not every syscall has a wrapper |
| `dispatch.rs` | Command-name to builtin dispatch | — |
| `commands/` | The shell's builtin implementations | Builtins are shell commands, not a libc; a standalone program links this module to reuse them |
| `signal.rs` | Signal API: `u32` mask, wait/poll/send, handler installation | No siginfo record; `SA_SIGINFO` is not accepted |
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
| Fault injection | SimpleFs single- and dual-fault matrix, including V4's xattr table and two-phase superblock writes | Deterministic and bounded; the other filesystems have no equivalent matrix |
| Recovery tests | Crash and replay scenarios | — |
| Concurrency tests | Scheduler, condvar, console, keyboard | — |
| Parser fuzz harnesses | Deterministic, in-tree, run by `make test-parsers`; coverage-guided targets in `fuzz/` run nightly | The gates are fixed-seed and bounded; the nightly corpora are not persisted across runs |
| virtio-gpu layout tests | Struct size and layout plus command wire format, against a mock device | Mock device only; no real GPU validation |
| Boot-work baseline | `make check-perf-baseline` compares a boot's counters against `scripts/perf-baseline.txt` (`src/kernel/perf_baseline.rs` prints them; the gate and its tolerances are [CONTRIBUTING.md](../CONTRIBUTING.md)'s).  The read side is counted at three heights: the filesystem's own operations and the bytes those operations were asked for (`fs-read-bytes`, `fs-write-bytes`, `src/fs/filesystem/profiler.rs`), what the block cache served (`cache-*`), and what actually reached a device (`blk-*`, `src/kernel/block.rs`).  A fourth height sits below them: `blk-commands` counts the requests a *driver* put on its device's own queue, which is what a run-capable request moves — one command however many blocks it covers ([RFC 0010](rfcs/0010-carry-a-run-in-one-queued-request.md)) — and it is **0** on the four flavours whose volumes are memory, because a memory volume has no queue to put a command on, and **497** on the disk baseline for 503 caller requests.  The concurrency those devices were asked for is counted **per direction** — `blk-read-high-water` and `blk-write-high-water` — because one number that two changes can move attributes neither.  `blk-read-high-water` is **2** on the disk baseline, because the mount submits its independent reads — both superblock mirrors, then the inode and dirent tables — before polling them ([RFC 0007](rfcs/0007-hold-a-second-request-on-a-device.md)), and **1** on the other four, because a device of depth one completes each submit in place.  `blk-write-high-water` is **1 everywhere** — a fact about the sample, not the write path: it is sampled when storage stops, the only flush an unaided boot performs is the background write-back, and a block is not eligible until it is 600 ticks old — so the durability path's device work is invisible to this line on every flavour, which is why the write half's overlap is gated by a test instead ([RFC 0009](rfcs/0009-queue-the-writes-a-flush-makes.md)).  `wl-*` rows are the boot's own defined [storage workload](kernel/fs.md) (`src/kernel/workload.rs`) counted as deltas around its run — eight files written three times and read back — so a change that makes the filesystem do more work per write is attributed to the workload rather than to the boot, and `wl-device-bytes-per-asked-byte` is its write amplification (5 today).  Its duration is printed on a line of its own that no gate compares, because a gate that measures a duration measures the machine it ran on.  `make check-perf-baseline-smp` boots the same demo on four CPUs against `scripts/perf-baseline-smp.txt`, so the work that only exists with a second CPU — waking the APs, the per-CPU tick, the IPIs a TLB shootdown sends — is compared rather than invisible, and `make check-perf-baseline-disk` boots it with an NVMe namespace as the only disk, where the workload's counters come out the same as the in-memory run except for the frame per slot the run buffers cost the boot — the filesystem asks a device for exactly what it asks a memory volume for — while the duration it prints grows by about four fifths; each file names the shape it was recorded on, and a boot of another shape is refused instead of compared | Counters, not seconds: it answers "did this do less work", not "was this faster"; the workload is in-memory on two of the three baselines, so a *physical* disk or SSD, NUMA-node stress and network throughput are still unmeasured (the disk baseline's device is QEMU's NVMe model) — the four-CPU baseline says what a boot does with four CPUs, not what a loaded machine does — and the counters are per boot plus one defined workload rather than per arbitrary workload, and the background write-back is outside the sample's window as above |
| CI workflow | the gates run per commit, each as its own step (`.github/workflows/ci.yml`) | The gates run as separate steps rather than through `make verify-p3` |
| Verification gates | P0-P3, described in [CONTRIBUTING.md](../CONTRIBUTING.md) | The smokes and the boot-work baseline are opt-in through environment variables, so a local `make verify-p3` without them does not boot anything |
| ABI number snapshot | `tests/syscall/abi_golden.rs`: a number's name may not change, and an experimental change has to bump the ABI minor in the same commit | Pins numbering and record layouts, not the object shapes behind them |

The demo disk was verified end-to-end on all three targets under QEMU:
interactive shell, demo payload (app-id/image/cwd/argv0/resume/exit code), 0
FATAL. The shell is ring-3 on all three targets and the runtime checks type a
command at its prompt and assert the answer.

### Userspace compatibility (the iron rule)

The contract itself — numbers assigned once and never renumbered, record
layouts asserted at compile time, a frozen range below a boundary — is
[docs/fmts/syscall-abi.md](fmts/syscall-abi.md)'s.  Three things make it
*testable* rather than merely written down:

| Item | State | Where |
|------|-------|-------|
| The number table is frozen | **done** | `tests/syscall/abi_golden.rs`: a snapshot of every number→name row. A change in the frozen range fails outright; a change in the experimental range fails unless the ABI minor version moves with it. Before this, swapping two stable syscalls left every test green. The one change that range *does* permit is additive optional behaviour, and it has taken one: `lseek`'s `SEEK_DATA` and `SEEK_HOLE` are two values a call that predates the boundary newly accepts (minor 5, [RFC 0017](rfcs/0017-ask-a-file-where-its-holes-are.md)), so a program that never passes them sees exactly what it saw before. |
| Userspace can learn which ABI it is on | **done** | the `abi_info` syscall returns `syscall_abi_major`, `syscall_abi_minor` and `syscall_count` alongside the record's own `major`/`minor`/`record_size` (`src/user/shared/abi/runtime.rs`) |
| A program that was not rebuilt | **done, partially** | `src/user/demo/fixtures/` holds frozen payloads. `make check-abi-frozen-payload{,-aarch64,-riscv64}` build with `abi_frozen_payload`, so the demo disk carries *those* bytes instead of the freshly compiled ones, boots them, and requires the same user output the normal smokes do — plus a boot line naming the source, so a gate cannot pass while quietly testing a new payload. The x86_64 boot carries two: it runs the frozen launcher, and the launcher starts the frozen child. AArch64 and RISC-V have one each because their demo disks ship one payload program between them. Each freeze is a deliberate act; the remaining demo programs are not frozen. |

### Build & Development

The build system, the optional features and the release profile belong to the
root [README.md](../README.md) and `Cargo.toml`; what this document has to
say is what the tree *is*, not how it is built:

- **The userspace runtime lives inside the kernel crate** (`src/user/shared/`,
  `src/user/demo/`), so a syscall wrapper, a shell builtin and an ABI record
  are compiled on both sides of the boundary rather than re-implemented per
  side.
- **Reproducible artifacts:** the same source built twice in two clean trees
  produces byte-identical artifacts for all three architectures — the two ELFs,
  the aarch64 `Image` and the demo disk image — and
  `make check-reproducible-build` is the gate that keeps it that way.  Nothing
  is pinned to a hash: the check asserts determinism, which is the property a
  verifiable release needs.  `make release` builds the four artifacts, names
  them for shipping, signs each with its own one-time key and verifies every
  signature; [CONTRIBUTING.md](../CONTRIBUTING.md) carries the order around
  it.  Tagged 1.x releases and the first published key records are still ahead
  (see the roadmap).

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
  the message a device would write into its own MSI page, claim it back),
  because no *device* on that machine sends an MSI by itself.  The machine's
  *wire* interrupts are carried by the supervisor APLIC domain now: the console
  UART's line is armed there and arrives as the MSI carrying identity 10
  (`src/arch/riscv64/aplic.rs`), which the same check proves by typing at the
  shell, so the identity the message path walks is the one a real sender uses.
  The PCIe half above it now walks too —
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
  faults in the kernel. It took a ring-3 console reader to hit this, and every
  path that can wait now stages in kernel memory and holds the window only for
  the copy: the read and write paths through `with_staged_input` and
  `copy_user_bytes`, the UDP and raw sends through `with_staged_input_exact`,
  which stages the *whole* payload because a truncated datagram is a different
  message rather than a short one. The guard underneath also had the second half
  of the bug: it set the protection bit on drop instead of restoring what it
  found, so a helper called inside an open window closed the enclosing one. It
  saves and restores now, and the window is opened in exactly one module —
  `syscall/memory/user.rs` — which is what `make check-user-access-windows`
  holds.
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
- **No release has been made yet**: the artifacts are reproducible and gated,
  and `make release` builds and signs them, but no tagged 1.x release exists
  and no key record has been published (see the roadmap).
