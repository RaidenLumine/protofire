# Protofire Roadmap

This roadmap describes where the Protofire kernel is headed. It is maintained
by the project maintainers and updated as work lands. Milestones are indicative,
not commitments — priorities can shift with contributors' interest.

The authoritative picture of what exists today is
[docs/status.md](docs/status.md).

---

## Guiding Principles

1. **ABI stability first.** The syscall ABI is the compatibility boundary.
   Stable slots (0–120) are frozen; numbering is append-only, never renumbered.
2. **Correctness over features.** Crash-safety, fault-injection tests, and
   transactional recovery come before adding more surface area.
3. **Architecture parity.** Where the hardware permits, features should land on
   all three targets (x86_64, AArch64, RISC-V 64) — not just one.
4. **Verifiable progress.** Every milestone ends in tests, docs, and a green
   `make verify-p3`.

---

## Near Term (next 3–6 months)

- **RISC-V 64 → full target support.** The user ABI, interactive demo shell, and
  demo payload are verified on RISC-V 64 under QEMU, and so is the AIA IMSIC —
  the kernel boots on `aia=aplic-imsic` and walks its own MSI path there.  The
  PCIe window is walked too, now that the device-tree parser settles it at the
  end of the node instead of when it reads `reg`, the kernel's own resource
  pass gives a device's BARs addresses, a `virtio-net-pci` is driven through
  the modern transport (that is the NIC the runtime check boots with), and an
  MSI-X table is programmed through the IMSIC, read back, its identities
  allocated by the controller and claimed by the driver that owns the device
  before it is allowed to signal, and the NIC's queues are routed to them — so
  the device signals on its own and a completion waits on that interrupt
  (checking the ring first, spinning last).  Remaining gaps: MSI-X is claimed
  per queue now, with each entry placed on a hart in turn; NVMe is a second
  device class on this bus, driven by the same file the PC compiles — which
  also made `arch::mmu::phys_addr_of` answer here, since its queues are DMA
  buffers and this machine's RAM window is identity-mapped.  What remains is
  another class still, and broader device-tree driver coverage.
- **AArch64 PCIe.** The ECAM window is found, its buses enumerated, its BARs
  assigned, and its `virtio-net-pci` driven — the same code as riscv64 with a
  different way of reaching a BAR.  Its devices signal by MSI too now: the
  GICv3, the LPIs and the ITS that translates a device's message into one are
  all there, one collection and one pending table per CPU, and a device's
  entries are placed over those CPUs in turn — so the NIC's queues are
  completed by different cores.  A second PCIe driver claims through the ITS
  too: `virtio-blk` on the same bus has its own DeviceID, its own LPI range and
  its own completion path that waits on it, which is what makes the placement a
  property of the machine rather than of one driver.  Two more device classes
  are driven here as well, both by the files the PC compiles: NVMe, so
  `make check-aarch64-nvme` mounts a real filesystem from a namespace on this
  bus, and HDA, so `make check-aarch64-hda` plays a tone through the
  controller and reads the samples out of the host's WAV backend.  What is
  left is the first class that has to *claim an interrupt of its own*: both
  NVMe and HDA poll their own completion rings, so neither of the two classes
  added on top of virtio has yet exercised the ITS through a driver that must
  be woken.
  [RFC 0001](docs/rfcs/0001-spread-message-signalled-interrupts.md) is the
  design the placement follows.
- **USB host (xHCI) completion.** Storage and HID work end to end, and a
  **hub** is enumerated too: its port count is read, its ports are powered and
  reset, and the device behind one is addressed by the route string the
  controller walks — `make check-x8664-runtime` boots a keyboard on a root port
  beside a mouse behind a hub, and keeps the key press and the disk.  The hub's
  status-change endpoint is now **watched**: a device plugged into (or pulled
  from) one of its ports after the boot's scan is enumerated — or released —
  when the hub says so, and **root ports** are watched the same way: the
  controller's own Port Status Change Event names a port, `PORTSC`'s change
  bits say what happened to it, and the boot clears them so a later removal is
  a change the controller will report.  `make check-x8664-usb-hotplug` plugs,
  unplugs and re-plugs a device behind a hub and pulls a device out of a root
  port and plugs another in, all while the guest runs.  Every hub found is
  watched at once — the watches are a list, not a table, and a hub behind a hub
  is one of them (the gate plugs one in and puts a mouse behind it).  The
  rings' one TD in flight per ring is measured now, not assumed: a submit takes
  room from `RingRoom`, which counts the TRBs submitted and not yet completed
  and refuses when the ring cannot hold one more, so a pipelining caller has
  the check it needs before it can be written
  ([RFC 0006](docs/rfcs/0006-end-a-producer-ring-lap-where-its-work-ends.md)).
- **HDA audio to userspace.** Done and gated: the engine runs (CORB/RIRB,
  codec discovery, the output converter, a BDL playback ring, the stream DMA),
  a program reaches it — the shell's `tone` builtin writes PCM to
  `/system/dev/audio`, which is now authorized by the node's own descriptor —
  and `make check-x8664-hda` and `make check-aarch64-hda` read the samples back
  out of the WAV QEMU's audio backend writes on the host and measure the tone's
  frequency from the wave's own period, so the one driver runs on the PC's
  configuration ports and on the device-tree machine's PCIe window alike.  The
  octave it used to lose was the converter's format word:
  `SET_STREAM_FORMAT` carries sixteen bits of payload through the verb encoding
  reserved for that width, and the driver sent it through the eight-bit one, so
  the codec was told "one channel" and played a stereo stream's interleaved
  samples in sequence.  What is left is the shell generator's own rounding,
  under a percent, and a codec that is not QEMU's.

## Mid Term (6–18 months)

- **Write support for more filesystems.** The read-only drivers — NTFS,
  BtrFS, SquashFS, ISO 9660, EROFS — move toward read-write, matching ext4 /
  F2FS / XFS / exFAT / FAT32.  The first of them is moving:
  [RFC 0011](docs/rfcs/0011-make-iso9660-file-data-writable.md) made an ISO
  9660 file's *data*, its *length*, its *space* — from an allocator that hands
  out the volume's free space and no longer refuses at the block boundary — its
  *record*, so files can be created and removed, then *directories*, which is
  both path tables rebuilt from the tree, and then entries that can be renamed
  and moved, which is the same two halves as one operation.  The RFC records
  why ISO 9660 went first (no compression to redo, no checksum tree to update,
  and a test image builder that already exists), and what it costs: a growth
  with something after it pays a copy, and what is free is only known for a
  volume whose structures the driver can name — anything it cannot account for
  is appended to instead, which is a decision rather than a gap.  The volume
  also declares the extension its entries belong to, which a writable open
  writes once by rebuilding the root directory's extent.  What is left of
  ISO 9660 is a decision rather than a gap: a volume whose structures the driver
  cannot name is appended to, and a volume with a second directory tree is
  written only where both trees agree — an overwrite inside a file's length —
  because the trees spell a name differently and nothing says which record in
  the other tree is the same file's.
  NTFS is the prize and the largest step, and its RFC has done the first thing
  it had to: [RFC 0012](docs/rfcs/0012-the-harness-an-ntfs-write-is-proven-on.md)
  decides the fixture volume its writes are proven on, and the fixture found
  three format mistakes in the reader at once — a record's size read as whole
  clusters, a resident value read from a fixed offset, a runlist read from the
  wrong base — and then two more in the index: an entry's name is at a fixed
  sixteen bytes and the field beside it is the name's *length*, and an
  allocation block's node clears its own update sequence array.  With those
  fixed the driver **reads a file end to end**: a path resolves through the
  directory index, and the bytes come through the runs — or out of the record,
  when the `$DATA` is resident.  And a **write lands**: the field is written
  where it lives, one block read-modify-written at a time, and a second mount
  is what proves it — an overwrite, a shorter length, and a length change
  inside what the file already has, with the volume's dirty bit up until it is
  synced.  Growth followed: the `$Bitmap` is read as a file, clusters are
  claimed, and the run list is rewritten by the mapping pairs' rules — an
  attribute that has outgrown its room *moves* inside the record, and the
  update sequence array is packed again for it.  Creation and removal followed:
  a new file's record comes from the MFT's own free space, and the bit `$MFT`'s
  `$BITMAP` keeps is raised before the record is written and lowered after the
  record is given back; the name goes into the parent's index where the
  volume's `$UpCase` table puts it, and a name is *matched* through that same
  table; a removal returns the file's clusters to the `$Bitmap` and moves the
  record's sequence past the number that named it.  Directories followed: a
  directory's record carries an empty `$INDEX_ROOT` in the place of `$DATA`, a
  name added to a small one makes that resident value *longer* — the free
  space its own record has is what it grows into, with everything after the
  attribute shifted up and the record written whole — and a directory that
  still holds something refuses to be removed.  A volume whose records are all
  spoken for **grows the MFT**: a cluster comes from the `$Bitmap`, `$MFT`'s
  own run list gains a run, its own bitmap is extended over the records the
  growth made, and those records are written as zeros so they are free.  The
  **attribute list** is *read* now: a record whose attributes did not fit one
  record names each attribute and the record that holds it, an attribute can be
  split across records by virtual cluster number, and the reader answers with
  the one attribute the parts are — which is what makes a volume another writer
  took apart readable here.  It is *written* now too: a record with no room
  moves its largest attribute that is not the one that has to grow into an
  extension record of its own, and the list names where everything went — so a
  record that is *full* grows.  The attribute that needs the room is the one
  that moves — as the format's own writer does — the largest others go with it
  when the list needs more, and a list the record already has is *extended*
  rather than refused.  And a directory whose entries do not fit any record's
  index root keeps them in an **`$INDEX_ALLOCATION` block**: the entries leave
  the root's value, the runs and the `$I30` bitmap of the blocks go into a
  record of their own that the base's list names, and the root's node keeps only
  the pointer — written after the record and the block, so every window between
  the writes is one a mount reads.  What is left of the stage is a *second*
  index block — an entries set that does not fit one block is a split, and the
  index bitmap would have to grow with it — and the two shapes the fixture does
  not carry: a record that is itself an extension, and a record where even
  moving everything leaves no room for the list.
  A **name moves** too: a rename is the two index changes and the record's own
  `$FILE_NAME`, in the order that leaves two names rather than none, and a
  record's number never changes, so a directory is renamed with everything
  inside it untouched.  A resident value that outgrows its record **converts**
  to one whose value is where runs say, so a file created empty takes content,
  and the volume's own state is shared by every handle to a mount — a clone of
  the record cache let a write through a vnode leave the mount that made it
  answering with the old record.  What is left of the stage is a `$FILE_NAME`
  that lives in a record of its own, the reverse conversion that a file
  shrinking back into its record would need, and the compressed, sparse and
  encrypted streams this RFC never decided.  A directory whose index is a
  **tree** is *read* now: an internal node holds a key and the child it points
  at, so a promoted key — one that lives in the node above and in no block — is
  a name like any other, and a walk takes each child and then its key, which is
  the order the names sort in.  A change is *routed* now too: it reaches the
  block the name's key belongs in, so a name can be created while its block has
  room and a leaf's name removed, and a name that *is* a key — the one a split
  promoted — comes out by its predecessor.  A block that is full now
  **splits**: half its entries move to a block of their own, the entry between
  the halves is promoted into the node above as its key,
  and the index bitmap gains a bit for the new block — whose virtual cluster
  number is the one the allocation's own size names, which is the leaf's number
  plus one only while the leaf is the last block.  The index bitmap **grows**
  now too: a bit past the last byte of the value extends it, and the record it
  lives in makes
  room for the growth when it has none — so a ninth block does not go unnamed
  because the bitmap the tree started with was one byte long.  And a name
  **comes back out**: a block that has lost names is merged with the one next to
  it when the two fit one again, the key that separated them moving down between
  the halves and the block that went being given back, and a name the node above
  holds — a key a split promoted — comes out by its *predecessor*, the child's
  largest name taking the key's place so that no child is left unreachable.
  And a block a deletion gives back is taken again: a split takes the first
  block the index bitmap says is free before it grows the allocation, so a
  directory's index stops claiming clusters for blocks nothing is stored in.
  What is left of the tree is the **split** of a leaf two levels down, whose
  node above is a block, and the allocation's own shrink, which this driver
  does not do at all: a kept block costs nothing to use again.
  A **real volume** is a gate now: `make check-ntfs-image` makes a volume with
  `mkntfs`, injects a file with `ntfscp`, has the driver read it and write one
  of its own, and hands the result to `ntfs-3g`'s own reader — so the format is
  proven on a volume this driver did not build.  What is still open is the
  *boot* path: mounting NTFS at boot needs the zone dispatch in
  [`src/fs/filesystem/`](src/fs/filesystem) to know the type, which is a step
  of its own.
- **Real-hardware bring-up.** Validate on bare-metal x86_64 boards and AArch64
  SoCs, not just QEMU; harden the device-tree probe path accordingly.  The
  assumptions a port has to remove — a fixed memory pool, `virt`-shaped
  fallbacks, fixed device windows, and the entry contract — are listed in
  [boot.md](docs/kernel/boot.md#platform-assumptions).
- **Stabilise the syscall ABI.** Graduate Experimental syscalls into Stable as
  they mature, moving the frozen boundary up; the append-only rule already
  reserves everything above the current highest slot.
- **Userspace VIRGL 3D demo.** Ship a demo renderer driving the virtio-gpu VIRGL
  interface (#181–189) to scanout.
- **Fuzzing & robustness.** The cargo-fuzz-style targets for the ELF loader,
  filesystem image parsers, network packet parsers, and the LUKS2 header are
  there; the SimpleFs crash matrix now enumerates V4's own crash points as
  well — the shadow xattr table, which V2 has no equivalent of, and the two
  superblock *phases* a V3+ commit adds around it.  What is left is a case for
  V3 itself (its sequence is V4's without the xattr table) and a searching
  fuzzer over the recovery path rather than a bounded matrix.
- **Performance validation.** The work a boot does is counted and gated today:
  `make check-perf-baseline` compares the counters a boot reports against a
  recorded baseline, so a change that does more work fails without anyone
  measuring seconds.  A read is now counted at all three heights it passes —
  the filesystem's operations and their bytes, the cache's hits and misses,
  and what reached a device — and the findings have landed: read-ahead, its
  lookahead sharing one request with the read that asked for it, and a commit
  that writes only the blocks the slot does not already hold, which cut the
  bytes a demo boot writes to a device from 735232 to 229888 for 25088 more
  read.  The counters are no longer only a boot's: the boot now runs a **defined
  storage workload** (`src/kernel/workload.rs`) — eight files written three
  times and read back — and the line reports that workload's own share as
  `wl-*` counters beside the boot's, with
  `wl-device-bytes-per-asked-byte` as its write amplification.  Both halves are
  gated, so a change that costs the filesystem more work per write fails with
  the workload named.  Its duration is printed separately and compared by
  nothing, because a gate that measures a duration measures the machine it ran
  on; the number is there to explain a counter, not to be one.
  What remains: an asynchronous device interface (a thread issuing the
  same synchronous reads cannot be ahead of a reader this fast, so overlap has
  to be a queue at the device), the same workload where the volumes are not
  memory, and on the network.  The first of those has landed:
  `make check-perf-baseline-disk` boots the demo with an NVMe namespace as the
  only disk, so the workload writes to `/data` on a device.  Its counters come
  back **identical** to the in-memory run — the filesystem asks a device for
  exactly what it asks a memory volume for — and the duration it prints grows
  by about four fifths, which is what a person wanted to know.  What that gate
  does not measure is a physical disk: QEMU's NVMe is a device model, and its
  latency is the host's, so the number stays a report.  A NUMA-shaped boot is
  gated too (`make check-perf-baseline-numa`, two nodes of two CPUs over the
  same four), which is the first gate that ever ran with a topology: it found
  the SRAT/SLIT walk costing about seventy allocations and changing nothing
  else.  Still open: a real SSD or spinning disk, load *on* a NUMA machine
  rather than a boot with its shape (the work a four-CPU boot does is gated by
  `make check-perf-baseline-smp`, but that is a boot, not a load), network
  throughput against a peer (a boot with no NIC can initialize the stack on
  the loopback device, and `make check-perf-baseline-net` counts the defined
  exchange it then runs — one datagram to itself, `nw-*` rows and an
  `nw-completed` that has to be 1 — which is a measurement of the stack's own
  work rather than throughput through a NIC), and the commit
  comparison's own reads, which a per-block
  shadow of the previous generation would remove if they ever show up against
  real disks.  The prerequisite was measured, not argued, and it has moved:
  [RFC 0007](docs/rfcs/0007-hold-a-second-request-on-a-device.md) landed the
  queued interface — a submit/poll pair beside the waiting call, defaulted so
  a device that cannot hold two requests keeps today's path — and its read
  half now has a caller that is not a stand-in: the mount submits the reads it
  can overlap — both superblock mirrors, then the inode and dirent tables —
  before polling them, and [RFC 0010](docs/rfcs/0010-carry-a-run-in-one-queued-request.md)
  gave a queued request the *run* that made the second pair possible, so a
  multi-block read is one device command rather than one per block
  (`blk-commands` is the row that says so).  `blk-read-high-water` is **2** on
  the disk baseline and stays **1** on the four depth-one ones.  The block
  cache's lookahead is the caller it does
  *not* have: its lookahead rides in the same request as the block it was
  asked for, so overlapping that read means
  splitting a request the cache decided to keep whole — and
  [RFC 0008](docs/rfcs/0008-keep-a-sequential-miss-in-one-request.md) decides
  against it, with the coalescing measured at 36 % of a boot's device commands
  and no earlier block to show for the split.  The candidate left is the write
  path: a flush of independent dirty blocks has no order between them and a
  buffer that goes *into* the device, which is the safe shape the read path
  lacks.
  [RFC 0009](docs/rfcs/0009-queue-the-writes-a-flush-makes.md) landed that
  half and that caller: the flush's three calls are now one mechanism that
  submits the dirty blocks a device can hold, drops the cache's lock while
  they are in flight, and wires SimpleFS into the background write-back it
  never implemented.  What a boot still cannot *show* is the overlap — the
  boot-work sample is taken at tick 500 and the background write-back cannot
  fire before a block is 600 ticks old, so `blk-write-high-water` reads 1 on
  every baseline and the cache's own test is the gate.  The payoff of the
  queue itself remains a hardware question: the tree's devices are models.

## Long Term (1–3 years)

- **Broader POSIX surface.** Grow the file-oriented userspace ABI toward a
  practical UNIX subset; evolve the shell and runtime (`src/user/shared/`).
- **Userspace ecosystem.** An init/service manager and a lightweight package
  story for the demo disk.
- **Formal-verification seeds.** Property-based testing (proptest) and model
  checking for the TLSF allocator, the scheduler invariants, and the FS
  undo-log — the subsystems where a subtle bug hurts most.
- **Security hardening pass.** Default-deny MAC policies, audit tooling, and a
  full attack-surface review.
- **Reproducible releases.** The artifacts are reproducible and gated
  (`make check-reproducible-build`), and one can be signed with a fresh
  one-time key (`cargo run -- sign-release …`, checked with `verify-signature`).
  `make release` builds the four artifacts, names them for shipping, signs each
  with its own one-time key, verifies every signature, and writes the checksum
  manifest, and [CONTRIBUTING.md](CONTRIBUTING.md) carries the order around it
  — the gate, the tag, the upload, and the rebuild a user can check a signature
  against.  What remains is the release itself: tagged 1.x versions and the
  first published key records.
- **Governance.** Design documents for large changes live under
  [`docs/rfcs/`](docs/rfcs/README.md), with a lifecycle that ends in a record
  of what was decided and why; [MAINTAINERS.md](MAINTAINERS.md) names who
  accepts one.  What remains is growing the maintainer team beyond one person.

---

## How to Help

Pick a milestone, open an issue to claim it, and read
[CONTRIBUTING.md](CONTRIBUTING.md). Known gaps in the code are tracked in
[docs/status.md](docs/status.md); anything labelled `good first issue` is a
good starting point.
