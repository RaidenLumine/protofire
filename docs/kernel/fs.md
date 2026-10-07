# Filesystem

`src/fs/` presents one namespace — paths, files, directories and device
nodes — over things that are not alike: a disk format the kernel owns,
synthetic views of kernel state, and a userspace server the kernel reaches
down a pipe pair.  The layer that presents is the VFS; the layer underneath is
the block interface in `src/kernel/block.rs`, which sits below the filesystem
rather than inside it, so a disk driver can implement it without naming `fs`.

Two questions decide most of what follows: what a running machine actually
mounts, and what a write to a volume may leave behind if it is interrupted.
The first is `src/fs/filesystem/layout.rs`'s answer; the second is SimpleFs's.

## The facade and the two traits

`FileSystem` (`src/fs/mod.rs`) is the object the rest of the kernel holds.  It
owns the root node, the registered backends, the block devices it knows, the
mount table, the current working directory, the handle counter, the storage
init report and the root filesystem type.  A boot constructs one, and
`install_global` publishes it behind an `AtomicPtr` for `global()` — the
same singleton shape the memory manager uses.

Backends implement the `FileSystem` trait in `src/fs/vfs/filesystem.rs`:
`lookup`, `stat`, `read_dir`, `create_file`, `create_dir`, `remove_path`,
`rename`, `swap_paths`, `check_and_repair`, the security-descriptor methods,
the xattr methods and the profiler snapshot.  Nodes implement `VNode`
(`src/fs/vfs/vnode.rs`): `kind`, `size`, `metadata`, `read`, `write`,
`set_len`, `readlink`, `sync`.  The defaults are the interesting part —
`VNode::write` and `VNode::set_len` answer `PermissionDenied` unless a node
overrides them, so a node that only produces bytes is read-only because it
declares nothing, not because a flag was remembered.

`ReadOnlyFileSystem` (`src/fs/vfs/filesystem.rs`) is the same idea one level
up.  A view implements `lookup`, `read_dir` and optionally `stat`, and a
blanket implementation supplies every mutation as `PermissionDenied`.  The
refusal is `PermissionDenied` rather than `Unsupported` on purpose: a
read-only view is closed by design, not unfinished.  `StaticFileSystem` is the
in-memory implementation behind the synthetic mounts.

`NodeKind` is the four node kinds the trait models — directory, file, device,
symlink.  `Metadata` carries the kind, size, timestamps and a
`SecurityDescriptor` (owner, group, mode); whether a descriptor grants an
access is the descriptor's own question, answered by
`granted_mode_bits_for`/`grants_access` in `src/fs/vfs/types.rs`.

## Paths

`normalize_path` in `src/fs/path.rs` is the one place a path becomes
canonical.  It produces an absolute path with no `.`, no `..`, no empty
components and no redundant slashes; a relative argument is resolved against
the current working directory first.  It rejects what the namespace does not
speak: an embedded control character, a backslash, a `C:`-style drive prefix
and the `//?/` device form.  No Unicode normalisation is applied — a filename
is bytes the caller chose, and callers that want NFC/NFD equivalence opt in
through `src/fs/unicode/`.

The facade wraps this with the working directory (`normalize_path_from`), and
the per-call cwd is machine-wide: `current_working_dir` is one string, not one
per process.

## The mount table

A mount point records the backend, its name, the device string and a flag
word (`src/fs/layout.rs`): `MOUNT_READ_ONLY`, `MOUNT_EXECUTABLE`,
`MOUNT_USER_DATA`.  `resolve_mount_entry`
(`src/fs/filesystem/resolve.rs`) picks the longest matching prefix and hands
the backend the path relative to that mount, so a nested mount shadows the
volume that holds it.

A directory listing is therefore a merge, not a read: `read_dir` on the
backend plus the mount points that hang under the path, keyed by name so a
mount shadows a same-named entry of the volume below
(`merged_directory_entries` in `src/fs/filesystem/overlay.rs`).

The mount table is behind the filesystem lock, and `/proc/mounts` is produced
while that lock is held — the producer runs inside the lookup that found the
node.  A second reader taking the lock there deadlocks.  `mount_snapshot`
exists for that case: the table is still the source of truth and
`publish_mount_snapshot` rewrites a copy of it at the two points that change
it, so a reader inside the lock takes only the snapshot.  The order is always
filesystem lock then snapshot, never the reverse.

## What a running machine mounts

`FileSystem::init_with_boot_disk` (`src/fs/filesystem/init.rs`) is the boot
path.  Given a boot disk it reads the MBR with `read_mbr_partitions`
(`src/fs/partition.rs`), which validates the signature and hands back the
present entries, and requires every expected zone partition to be there;
failing that it falls back to the fixed zone offsets in `src/fs/layout.rs`;
failing that, on a build that has the demo disk, it mounts an in-memory MBR
image, and otherwise reports a failed storage init.  The result is recorded
as a `StorageInitReport`, and `install_default_layout` then adds the mounts
that do not come from the boot disk.

| Mount | Backend | Policy |
|---|---|---|
| `/system` | SimpleFs | read-only, case-sensitive |
| `/apps` | SimpleFs | executable, writable by its owner — an install *is* a write |
| `/data` | SimpleFs | user data, case-insensitive |
| `/tmp` | SimpleFs on a `MemoryBlockDevice` | built empty every boot |
| `/system/dev` | `StaticFileSystem` over the device ledger | read-only |
| `/system/logs` | `KernelLogFileSystem` (`src/kernel/kernel_log.rs`) | read-only |
| `/dev` | `devfs::DevFs` | read-only |
| `/service` | `servicefs::ServiceFs` | read-only |
| `/proc` | `procfs::ProcFs` (`src/kernel/procfs.rs`) | read-only |

`/proc` is mounted by `Kernel::init` through `procfs::mount_procfs`, not by
`install_default_layout`: it is a view over the process table, so it lives in
`src/kernel/` above both `fs` and `process`, and it has to wait until the
filesystem singleton exists.

The writable policy is a property of the zone and is stated once, in
`src/fs/write_locations.rs`: `/tmp` is scratch that does not survive a reboot,
`/data` is state that survives a reboot and a system update, `/apps` is where
an install writes, and `/system` is closed — a running kernel cannot change
the code it is running.  `log_write_locations` prints that policy once, after
the mounts are up, so a boot log carries it without a reader having to find
the source.

## Files, handles and permissions

An open is one of three dispositions, named in `src/fs/mod.rs`:
`OPEN_EXISTING`, `CREATE_NEW`, `OPEN_ALWAYS`.  `create_file_normalized_*`
(`src/fs/filesystem/open.rs`) resolves the mount, authorizes the open and
returns a `FileHandle` (`src/fs/handle.rs`): a `VNode`, a security descriptor,
the mount flags and a cursor.  `read` and `write` move bytes through the node
and advance the cursor; `seek` takes `SEEK_SET`, `SEEK_CUR` or `SEEK_END`;
`set_len` truncates or extends and clamps the cursor.  Handle numbers come
from `alloc_handles`, which reserves a consecutive run in one atomic step.

Authorization is descriptor-based and the descriptor depends on where the
path is.  `default_security_descriptor_for_path`
(`src/fs/filesystem/security_helpers.rs`) derives one for a path whose
backend cannot store one: `/system` and `/apps` are root-owned, `/data` below
its boundary directories is the guest's with `0775`/`0664` (`/data` and
`/data/users` themselves stay root-owned), and `/data/etc` — the credential
store — is carved out as root-owned `0700`/`0600`, because on a volume
without persistent descriptors that rule is the only place the exception can
live.
Opening a file for write also has to pass the mount: a read-only mount refuses
unless the caller's token may bypass read-only mounts
(`mount_allows_write_for_security_token` in
`src/fs/filesystem/access_helpers.rs`).

Much of the way through the tree the namespace work happens under the global
filesystem lock while the data path — an open `FileHandle` — does not take it.
`src/fs/lock_timing.rs` measures how long the remaining holds are, including
boot recovery, so that a decision about mount lifetime can be driven by a
measurement.

## SimpleFs

SimpleFs (`src/fs/simplefs/`) is the format the kernel owns.  Everything about
it starts from three fixed decisions: a volume is a block range, metadata
lives in two tables each of which has an active and a shadow copy, and the
superblock has two mirrored copies (`PRIMARY_SUPERBLOCK_BLOCK` and
`SECONDARY_SUPERBLOCK_BLOCK`).

### The format versions

`SimpleFsFormatVersion` (`src/fs/simplefs/types.rs`) names the three versions
and each one is a superset of the one before:

- **V2** leaves the inode's security fields to the layout rules above and
  uses the inode's last word for a data checksum.
- **V3** reuses those bytes for a persistent owner/group/mode, and adds the
  `pending_commit` marker that makes the two-phase commit detectable.
- **V4** adds a persistent xattr table and the per-inode data-reduction flags.

The image builders matter here: `SimpleFs::build_image` and
`build_image_with_headroom` (`src/fs/simplefs/image_staging.rs`) produce V2,
and that is what the demo disk builder and the `/tmp` volume use, so a
machine's zone volumes are V2 and their security descriptors are derived from
the path.  `build_v4_image_with_headroom` and the V3/V4 mount paths exist and
are exercised by the test suites.

### The superblock and the tables

The superblock is a fixed layout in `src/fs/simplefs/constants.rs`: the magic
(`MAGIC`), the label (`SUPERBLOCK_LABEL_OFFSET`/`_LEN`), the inode and dirent
table block counts, the active and shadow block of each table, the generation,
the checksum, and — from V3 — the pending-commit word.  The mount path is
`superblock.rs`; `read_superblock_record` (`format_io.rs`) is the reader that
the mount, the repair path and the pending-commit count all share.

Table capacity is a function of the superblock's block counts, not a compile
constant, so a volume's size is what says how many inodes and entries it can
hold.  An inode (`OnDiskInode`) carries its kind and deleted bit, its extent
(`data_block`, `block_count`), its size, its optional persistent security
descriptor, and its flags; a directory inode names a run of entries in the
dirent table, and each `OnDiskDirEntry` names an inode and a name.  Geometry
constants (`INODE_SIZE`, `DIRENT_SIZE`) are the ones `format_io.rs` writes
and reads with.

Names are validated per format when a node is created, and lookups can be
case-insensitive: the zone decides (`StorageZone::case_sensitive` in
`src/fs/layout.rs`), and `src/fs/unicode/` supplies the folding used by the
formats that need it.  Symlinks are inline when the target fits in the inode's
extent fields (`MAX_INLINE_SYMLINK_LEN`) and resolution is bounded by
`MAX_SYMLINK_DEPTH`.

### Transactions and the two-phase commit

Every metadata mutation goes through `commit_metadata_update`
(`src/fs/simplefs/file_io.rs`), which wraps a closure in an undo-log
transaction.  `begin_undo` clears the log; each mutator saves the value it is
about to overwrite (`save_inode_for_undo`, `save_dirent_for_undo`,
`save_free_extents_for_undo`, …); a failure runs `rollback_undo`, which
restores the saved values in reverse order and truncates the vectors that a
failed allocation grew.  On success `commit_undo` discards the log.

The flush that ends a successful transaction is `flush_metadata`
(`src/fs/simplefs/extent_repair.rs`) and has three phases:

1. **Mark** (V3+): write `pending_commit = target_generation` into both
   superblock mirrors, which still point at the current active tables.
2. **Write**: write the parts of the shadow inode and dirent tables, and of
   the shadow xattr table on V4, that differ from the image being committed.
3. **Publish**: write both mirrors with the active and shadow pointers
   swapped and `pending_commit` cleared, and only then swap the in-memory
   pointers.

Phase 2 used to write both tables and the xattr table *whole*, every commit,
which is why a boot's write traffic dwarfed its files: a demo boot of the
in-memory volumes put 735232 bytes on a device for the 13611 bytes a caller
asked for, and a probe that read each written block back counted **1436 blocks
written and 370 that differed**.  A commit now compares the image it is
committing against the bytes the slot already holds — through the block cache,
where the previous write left them — and writes out only the runs that differ.
That same demo boot writes 229888 bytes instead of 735232, for 25088 bytes
more read: the first commit after a mount writes its slot whole (nothing has
described it yet), so the first *differential* commit is the one that reads a
slot the mount never cached.

The comparison is against the *slot*, not against the last commit, and that is
what makes it a commit-protocol change rather than a smaller write loop.  A
publish swaps the pointers, so the slot the next commit overwrites holds the
table from **two** generations back; the difference is therefore the union of
the last two generations' changes, and "what changed since last time" would
leave a block the previous commit wrote unwritten in the copy about to become
active.  Reading the slot is what makes the set exact without a per-block
shadow of the last commit.  It also leaves the retired slot a generation
behind, which is the drift `check_and_repair` reports as one issue and clears
with a single synchronising commit.

A crash before the publish leaves the mark; a mount then loads the *active*
tables, which a commit never writes, so the visible namespace stays the one
the last publish described.  A crash between the two mirror writes leaves one
mirror stale, which is why the pending superblock is written with the
pre-transaction table counts: it may be the only readable one, and it has to
describe the tables it still points at.

### Recovery

`check_and_repair` (`src/fs/simplefs/extent_repair.rs`, through
`SimpleFsVolume::check_and_repair`) is the other half.  It compares both
superblock mirrors with the state in memory, counts checksum failures and
non-zero pending marks, removes staging roots a crash left behind, zeroes the
data blocks no inode references so stale content cannot be recovered, and
rebuilds the free-extent map.  If the mirrors disagree it republishes the
current tree into the inactive slot and rewrites both mirrors, retrying once;
a second failure is an internal error.  The result is a `VolumeCheckReport`
with one counter per class of found-and-fixed problem.

Recovery runs at boot, not on demand: `Kernel::init` calls `recover_volumes`
for every mount except `/`, under the filesystem lock, and stores the totals
for the runtime health query.  There is no online repair.

### Data, staging and observed counters

File data lives in a contiguous extent.  Reads check the stored checksum when
the whole file is read; writes that touch already-visible bytes stage a
replacement copy first, so a crash cannot expose a half-rewritten prefix.
`write_file` also re-derives the checksum from the merged view, and it writes
data blocks before the inode update so a failure orphans data rather than
referencing blocks that are not on the device — recovery zeroes those.

Two named operations sit above the transaction layer.  `StagingArea`
(`src/fs/simplefs/image_staging.rs`) is a directory for content that is not
yet visible, registered as a staging root so recovery can remove orphans; its
publish step is a rename.  `swap_paths` exchanges two paths in one commit
through a generation-named temporary, which is what a version switch needs:
neither name is ever absent while the exchange happens.

`FsProfiler` (`src/fs/filesystem/profiler.rs`) counts lookups, reads, writes,
the bytes those reads and writes were *asked* for, creates, deletes, renames,
transactions and metadata flushes.  It counts only when the `fs_profiler`
feature is on; with the feature off it is a zero-sized type whose every method
is a no-op, and the snapshot is all zeros.  The byte counters are what the
boot-work line reports as
`fs-read-bytes` and `fs-write-bytes`: a filesystem can say how much the layer
above wanted, and how much of it a cache served or a device moved is the layer
below's to count.

### The V4 data-reduction modules

`src/fs/simplefs/compression.rs` encodes a file as a chunked stream and
decodes a byte range from it, and `src/fs/simplefs/dedup.rs` implements
sharing of an extent between inodes with refcounts and copy-on-write
unsharing.  In the write path today, nothing calls them:
`maybe_dedup_inode` and `unshare_inode_extent` have no caller, and a
compressed extent is never written, so the per-inode
`INODE_FLAG_COMPRESSED`/`INODE_FLAG_DEDUPED` bits round-trip through
`format_io.rs` but no operation produces them.  `get_file_flags` and
`set_file_flags` keep their `FileSystem` defaults, which refuse, in every
backend.

## The block layer

`src/kernel/block.rs` defines `BLOCK_SIZE` and the `BlockDevice` trait:
`read_blocks`, `write_blocks`, `flush`, `block_count`, `is_read_only` and
`device_health`.  `MemoryBlockDevice` is a `Vec<u8>` that pads to a block
boundary; `BlockSliceDevice` is a sub-range of a parent device, which is what
an MBR partition becomes.  The filesystem re-exports the module as `fs::block`
for the callers that used to name it there, but the dependency is one-way.

The trait also has the queued path: `queue_depth` is how many reads a device
can hold at once (one by default), and `submit_read`/`poll_read` are a
submit/poll pair beside `read_blocks` whose default completes the read in
place, so a device that does not queue is exactly the device it was.  A
queued read borrows the caller's buffer across a window the compiler cannot
see, which is why `submit_read` is `unsafe`; the `InFlight` guard the
boot-work counters keep moves from the call to the ticket, so
`blk-in-flight-high-water` means "requests a device is holding".  The NVMe
driver answers a depth of two, matches completions by command identifier, and
implements its waiting `read_blocks` as that pair polled at once — so there is
one read path, and a boot exercises it.  Nothing in the tree queues reads
yet: the cache keeps its lookahead folded into the demand's own request
([RFC 0008](../rfcs/0008-keep-a-sequential-miss-in-one-request.md) is why).
See [RFC 0007](../rfcs/0007-hold-a-second-request-on-a-device.md) for the
interface itself.

A driver that finds a disk does not know about the filesystem.  It calls
`publish_device`, and `set_device_publisher` — installed by `Kernel::init`
with a closure that locks the filesystem and calls `register_block_device` —
is how the device lands in the map that owns it.  `MemoryBlockDevice` and
`BlockSliceDevice` both report their health, and `Failed` is what a read path
checks before it touches the device.

### The block cache

`src/fs/block_cache.rs` is a fixed pool of block slots (`CACHE_CAPACITY`) that
sits between a filesystem and its device.  It has two write shapes:
`write_through` persists the block and leaves the cached copy clean, and
`write_back` updates the cache, marks the entry dirty and defers the device
write.  A read (`read_cached`) serves a hit from the pool and on a sequential
miss prefetches the next few blocks — *if the volume asked for read-ahead*:
the depth defaults to 0, `BlockCache::with_read_ahead` is how a volume asks,
and no volume in the tree asks today, so the path is exercised by the cache's
own tests and by no boot.  Eviction prefers the least-recently-used clean
entry, so a dirty block is only written back when the pool is entirely dirty.
Read-ahead is **on for SimpleFS, at depth 4, and it shares its request with the
read that asked for it**.  A sequential miss reads the block the caller wants
*and* the blocks after it in **one** device request — the demand and the
lookahead are contiguous and a device charges per request rather than per byte
— stopping at the first block that is already cached, because those are
exactly the blocks a previous request read ahead.  The scratch buffer is a
constant `(1 + PREFETCH_RUN_BLOCKS)` blocks on the stack.  A demo boot of the
in-memory volumes then asks a device for

  * 158 reads and 233984 bytes: **24 % fewer commands than read-ahead off (327
    reads) for exactly the same bytes**, with 87 caller-visible misses against
    256;
  * 208 reads and 236032 bytes when the lookahead is a second request (the
    first shape it was written in), and 154 reads with 243712 bytes when the
    shared request does not stop at cached blocks — three shapes, measured,
    and the one kept is the one that adds no traffic;
  * 189 reads at depth 8 against 208 at depth 4 with the lookahead separate, so
    depth 4 is where the curve flattens.

What this buys is still *commands*, not concurrency: every read in the tree is
synchronous, so a miss waits for its share of one request.  Overlapping them
would take an asynchronous device interface — a *thread* that issues the same
synchronous reads cannot be ahead of a reader this fast, which a probe in the
counters would show as lookahead that arrives after the ask.  The other
filesystems keep read-ahead off until a boot measures them.

`CacheStats` counts hits, misses, evictions, dirty and aged writebacks, blocks
prefetched and *sequential* hits — a sequential hit is a hit on the block
right after the one read before it, which is what the cache can tell from its
own last access; telling a block that arrived by read-ahead from one the
caller read itself would take an entry that remembers where it came from.  The
boot-work line reports the sum of these counters over the mounted volumes as
`cache-*`.

Write-back data needs a clock to age against, and the clock is the scheduler
tick: `advance_cache_tick` runs from the timer
(`src/kernel/process/scheduler/timer.rs`), `WRITE_BACK_PERIOD_TICKS` sets the
scan period, and the periodic job is not done in the interrupt — the tick
only asks the maintenance thread (`src/kernel/maintenance.rs`), which calls
`sync_global_caches_aged` -> `BlockCache::flush_aged` outside interrupt
context.  The same module gives the whole machine `sync_global_all` and
`sync_global_data` for the POSIX-shaped syncs.

SimpleFs uses the write-through side for both data and metadata
(`write_blocks_cached` in `src/fs/simplefs/superblock.rs`); the write-back
entry point in SimpleFs is present but marked unused.  FAT32 is the only
backend that overrides `FileSystem::flush_aged` and it is not mounted, so the
aged write-back pass a tick requests reaches the trait default and writes
nothing on a machine as shipped.

## Partitions and the system pair

`src/fs/partition.rs` parses an MBR: signature checked, four fixed-size
entries, overlap rejected, 32-bit LBA fields.  Protofire's own partition
types mark the system, apps and data zones, and slot 0 and slot 3 both carry
the system type because they are the two halves of a pair.

The pair is `src/fs/system_image.rs`'s subject.  Each system volume carries a
build marker at `/etc/build` (`SYSTEM_BUILD_MARKER_PATH`) written in a fixed
format with a generation.  `system_slots` reads a build from each system
partition, and `select_system_slot` takes the highest committed generation —
where "committed" means the volume opened and carried the marker — falling
back to the first slot when nothing is committed, which is what a disk built
before the pair looks like.  `install_system_build` writes an image into the
slot that is not active and refuses one that is not a system volume, carries
no marker, or is not newer, so a torn image cannot commit itself and an
update cannot go backwards.  `withdraw_active_build` removes the winner's
marker and nothing else: the payload stays on disk, which is what makes
rollback cheap and a reinstall of the same bytes possible.

## A userspace filesystem

`src/fs/fuse/` lets a ring-3 daemon serve a mount.  The `FuseMount` syscall
(`src/syscall/fs/fuse_mount.rs`) creates a request pipe and a response pipe,
builds a `FuseFileSystem` over them, registers and mounts it, and hands the
daemon end of both pipes back as descriptors — so the server is an ordinary
userspace program using ordinary reads and writes.

The wire format is a fixed header plus an opcode-specific payload
(`protocol.rs`); the opcodes are pinned to the userspace daemon's constants by
`opcode_wire_values_match_daemon` in `src/fs/fuse/mod.rs`, because the wire
bytes, not the variant order, are the contract.  Dispatch is sequential:
`FuseConnection::dispatch` holds a mutex across the request and its response,
which serialises every caller on the mount and is what makes a single pipe
pair sufficient.  The root inode is discovered with a lazy `LOOKUP("/")`
handshake, falling back to the FUSE convention inode 1.

## Drivers the tree has

`src/fs/` also contains format drivers for ext4, FAT32, exFAT, NTFS, btrfs,
XFS, F2FS, EROFS, SquashFS and ISO 9660 (`src/fs/ext4/`, `src/fs/fat32/` and
so on), each with its own parser, `VNode` implementation and tests.  None of
them is mounted by the boot path and nothing registers one at runtime:
`install_zone_devices` has an ext4 branch behind `rootfs_type`, but
`set_rootfs_type` has no caller, so a machine's zones are SimpleFs.  The
read-only views above and FUSE are the backends a boot or a syscall can
actually reach; the rest are code and tests awaiting a mount.

The same is true of two encryption modules: `src/fs/crypt_device.rs` wraps a
`BlockDevice` in AES-XTS and `src/fs/luks2.rs` parses a LUKS2 header and
recovers a key, but nothing constructs an `EncryptedBlockDevice`.  `tmpfs`
(`src/fs/tmpfs/mod.rs`) is a complete in-memory filesystem with xattrs, hard
links and rename, and it too has no mount in the tree — `/tmp` is a SimpleFs
volume on a memory device instead.

## Where the code is

| File | What it holds |
|------|---------------|
| `src/fs/mod.rs` | The `FileSystem` facade, the global singleton, the mount snapshot |
| `src/fs/vfs/filesystem.rs`, `src/fs/vfs/vnode.rs` | The `FileSystem`/`VNode` traits, `ReadOnlyFileSystem`, `StaticFileSystem` |
| `src/fs/vfs/types.rs` | `NodeKind`, `Metadata`, `SecurityDescriptor`, `VolumeCheckReport` |
| `src/fs/path.rs` | Path normalisation |
| `src/fs/filesystem/` | Boot layout, mount and resolve, open, I/O, rename, overlay, security, profiler |
| `src/fs/simplefs/` | SimpleFs: superblock, tables, transactions, recovery, staging, xattrs |
| `src/fs/layout.rs` | Zones, mount flags and the fixed fallback disk ranges |
| `src/fs/partition.rs`, `src/fs/system_image.rs` | MBR parsing, and the system A/B pair |
| `src/kernel/block.rs`, `src/fs/block_cache.rs` | The block interface and the cache |
| `src/fs/devfs.rs`, `src/fs/servicefs.rs`, `src/kernel/procfs.rs` | The synthetic views |
| `src/fs/fuse/` | The userspace-served filesystem and its wire format |
| `src/fs/write_locations.rs` | Where a running machine writes, stated once |

## See also

- [boot.md](boot.md) — when the zones are mounted and recovery runs
- [process.md](process.md) — the handle table the file descriptors land in
- [drivers.md](drivers.md) — the drivers that publish block devices
