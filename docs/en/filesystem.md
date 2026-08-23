# Filesystem Architecture

## Overview

The filesystem layer (`src/kernel/fs/`) provides a Virtual File System (VFS) that
mounts volumes, resolves paths, and exposes unified file/directory/device I/O to userspace. It
supports multiple on-disk formats (SimpleFs, ext4, FAT32, NTFS, btrfs, XFS, F2FS, EROFS, squashfs,
iso9660) and in-memory pseudo-filesystems (tmpfs, procfs, devfs). The primary native format is
**SimpleFs**, a custom lightweight filesystem designed for embedded use.

---

## VFS Architecture

### FileSystem facade

The top-level `FileSystem` struct (`src/kernel/fs/mod.rs`) is a singleton managing:

| Field | Purpose |
|---|---|
| `root: Arc<dyn VNode>` | Virtual root node (`/`) |
| `filesystems: BTreeMap<String, Arc<dyn VfsTrait>>` | Registered filesystem backends |
| `block_devices: BTreeMap<String, Arc<dyn BlockDevice>>` | Known block devices |
| `mounted_fs: BTreeMap<String, MountPoint>` | Active mount points |
| `current_working_dir: Mutex<String>` | Per-session CWD |
| `next_handle: Mutex<u64>` | Monotonic file handle counter |
| `rootfs_type: String` | `"simplefs"` or `"ext4"` |

It is stored in a global `AtomicPtr<Mutex<FileSystem>>` and accessed via `global()` /
`install_global()`. Initialization occurs in `filesystem/init.rs` via `init_with_boot_disk()` which:

1. Parses MBR partitions from the boot block device, or falls back to fixed-zone offsets.
2. Opens SimpleFs (or ext4) volumes for each zone (System/Apps/Data).
3. Registers them as mounted filesystems.
4. Falls back to in-memory demo volumes if no real boot disk is present.

### FileSystem trait

Defined in `src/kernel/fs/vfs/filesystem.rs` — methods include `lookup()`, `stat()`, `read_dir()`,
`rename()`, `create_file()`, `create_dir()`, `create_symlink()`, `create_device()`, `hard_link()`,
`remove_path()`, `check_and_repair()`, `fs_profiler_snapshot()`, `list_xattrs()`,
`update_security_descriptor()`. `StaticFileSystem` provides a read-only tree from compile-time
entries — used for procfs, devfs, and similar pseudo-filesystems.

### VNode trait

Defined in `src/kernel/fs/vfs/vnode.rs` — methods include `name()`, `kind()` (File | Directory |
Device | Symlink), `size()`, `metadata()`, `read()`, `write()`, `set_len()`, `readlink()`, `sync()`,
`sync_data()`, `list_xattrs()`. All filesystem objects implement this trait.

### Path resolution

Path normalization lives in `src/kernel/fs/path.rs` (`normalize_path`). It produces absolute,
canonical paths with no `.`/`..`/redundant slashes, rejects drive prefixes (`C:`) and embedded
control characters. The facade's `normalize_path` (in `query.rs`) wraps this with the current
working directory.

The `filesystem/path_helpers.rs` module provides utilities used internally by the mount system:
`matches_mount`, `direct_mount_child_name`, `join_normalized_child`, `parent_normalized_path`,
`is_valid_child_name`.

### Mount system

Mount points are tracked in `FileSystem::mounted_fs` (`BTreeMap<String, MountPoint>`) where each
`MountPoint` (`src/kernel/fs/filesystem/types.rs`) holds `fs: Arc<dyn VfsTrait>`, `fs_name`,
`device`, and `flags` (bitmask of `MOUNT_READ_ONLY=1`, `MOUNT_EXECUTABLE=2`, `MOUNT_USER_DATA=4`,
defined in `layout.rs`). `mount()` normalizes the target path, looks up the filesystem by name, and
inserts the mount point. `unmount()` removes it.

The built-in virtual mounts are:

| Mount path | Device | Backend |
|---|---|---|
| `/system` | `/dev/protofire-system` | SimpleFs (read-only) |
| `/apps` | `/dev/protofire-apps` | SimpleFs (exec) |
| `/data` | `/dev/protofire-data` | SimpleFs (user data) |
| `/tmp` | `/dev/protofire-temp` | SimpleFs (writable scratch) |
| `/proc` | — | StaticFileSystem |
| `/dev` | — | StaticFileSystem (device nodes) |
| `/system/dev` | — | Virtual device FS |
| `/system/logs` | — | Kernel logs FS |

---

## SimpleFs — On-Disk Format

Source: `src/kernel/fs/simplefs/`. SimpleFs is a custom embedded filesystem with a fixed-block
layout, dual-superblock design, and undo-log-based transactions.

### Format versions

- **V2**: 32-byte inodes, 64-byte directory entries, data checksum at byte 28.
- **V3** (`V3PersistentSecurityDescriptors`): Reuses bytes 24..31 for `owner_uid`/`owner_gid` —
  persistent security descriptors replace the V2 checksum field. Supports a pending-commit
  two-phase protocol for crash safety.

### Superblock

Each SimpleFs volume has two superblock copies (blocks 0 and 1), defined in `constants.rs`:

```
Block 0: Primary superblock
  [0..8)    Magic: "ADAFS1\0\0"
  [24..28)  Active inode table block
  [28..32)  Active dirent table block
  [32..36)  Data block start
  [36..40)  Shadow inode table block
  [40..44)  Shadow dirent table block
  [44..48)  Inode table block count
  [48..52)  Dirent table block count
  [52..56)  Generation number
  [56..64)  Checksum
  [64..96)  Volume label (32 bytes)
  [96..100) Pending commit marker (V3+)
Block 1: Secondary superblock (same layout)
```

Parsing happens in `superblock.rs` via `SimpleFs::open()`. The active/shadow table pair enables
atomic metadata updates.

### Zone layout (layout.rs)

A disk is divided into zones, each being a SimpleFs volume:

```
+--------+--------+--------+--------+--------+
| MBR    | System |  Apps  |  Data  | Temp   |
| sector |  (256) | (1536) | (2048) | (128)  |
+--------+--------+--------+--------+--------+
0        2048     2304     3840     5888     6016  blocks
```

`StorageZone` enum maps each zone to its root path, filesystem name, device path, mount flags, and
MBR partition type:

| Zone | Root | MBR type | Flags | Case sensitive |
|---|---|---|---|---|
| System | `/system` | 0xa1 | Read-only | Yes |
| Apps | `/apps` | 0xa2 | Executable | Yes |
| Data | `/data` | 0xa3 | User data | No |

### Inode and directory entry

32-byte `OnDiskInode` (`types.rs`): `kind`, `deleted`, `entry_start` (dirent table start for
directories), `entry_count`, `data_block`, `block_count`, `size`,
`persistent_security` (V3), `data_checksum` (V2).

64-byte `OnDiskDirEntry` (`types.rs`): `inode_index`, `kind`, `name` (56-byte embedded).

### ImageEntry

The image builder uses `ImageEntry` (`src/kernel/fs/simplefs/mod.rs`): `{ path: &str, data: &[u8] }`
for `SimpleFs::build_image()` and `build_image_with_headroom()`.

---

## Block Layer

### BLOCK_SIZE

`src/kernel/fs/block.rs` defines `BLOCK_SIZE = 512`. All block I/O operates in multiples of this.

### BlockDevice trait

`src/kernel/fs/block.rs` — key methods: `name()`, `block_size()` (default 512), `block_count()`,
`is_read_only()`, `read_blocks(lba, buffer)`, `write_blocks(lba, data)`, `flush()`,
`device_health()` (returns `Healthy` | `Degraded` | `Failed`).

Two concrete implementations:

- **`MemoryBlockDevice`** (`block.rs`): In-memory `Vec<u8>` storage, auto-pads to block boundary.
  Used for demo disks and tests.
- **`BlockSliceDevice`** (`block.rs`): A sub-range of a parent device — delegates reads/writes at
  offset `start_block`. Used for partition slices.

### BlockCache

`src/kernel/fs/block_cache.rs` provides a 128-slot LRU cache with:

- **Write-through** (metadata): `write_through()` persists to device and updates cache.
- **Write-back** (file data): `write_back()` marks dirty; `flush()` writes to device.
- **Read-ahead**: Optional sequential prefetch (configurable depth) for file reads.
- **Clean-before-dirty eviction**: Eviction always prefers clean entries first; if all are dirty,
  the LRU dirty entry is flushed before eviction.

Statistics are tracked via `CacheStats` (hits, misses, evictions, dirty writebacks, prefetches).

SimpleFs uses the cache via `cached_read_blocks()` and `write_blocks_cached()` (metadata writes
with immediate device persistence and clean cache population) and `write_blocks_cached_wb()` for
deferred data writes.

---

## Partition Table Parsing

`src/kernel/fs/partition.rs` implements standard MBR parsing via `read_mbr_partitions()` which
reads block 0, validates the 0x55AA signature, parses four partition entries at offset 446
(each `MbrPartitionEntry`: `bootable`, `partition_type`, `start_block`, `block_count`), checks
for overlap, and returns `Option<MbrPartitionTable>`. LBA fields are 32-bit (~2 TiB max).
Partition types 0xa1/0xa2/0xa3 identify protofire zones. `write_mbr_partitions()` serialises to a
sector buffer.

---

## Transaction / Recovery

Source: `src/kernel/fs/simplefs/transaction.rs`.

### Undo-log transactions

All SimpleFs metadata mutations are performed inside an undo-log transaction. The flow:

1. `SimpleFsState::begin_undo()` snapshots dirty flags.
2. For each mutation, the current value is saved (`save_inode_for_undo`,
   `save_dirent_for_undo`, `save_free_extents_for_undo`, etc.).
3. `rollback_undo()` restores all saved values in LIFO order — critical for insert/remove
   operations that shift arrays.
4. `commit_undo()` discards the log on success.

### TransactionContext

`TransactionContext` provides methods for batched metadata mutations (`create_dir`,
`create_dir_with_security`, `remove_path`, `update_security_descriptor`) that all operate on
the locked in-memory state and are flushed atomically.

### Two-phase commit (V3)

V3 superblock has a `pending_commit` field (offset 96). Before a metadata flush:

1. Set `pending_commit` to the target generation on disk.
2. Write metadata tables (inode + dirent) to shadow blocks.
3. Flip the superblock to point active/shadow tables.
4. Clear `pending_commit`.

On mount, a non-zero `pending_commit` indicates an interrupted commit — detected by
`check_and_repair()` which clears the stale marker and verifies table consistency via
`RuntimeHealthSnapshot`.

### VolumeCheckReport

Returned by `check_and_repair()` (`src/kernel/fs/vfs/types.rs`): tracks `issues_detected`,
`repairs_applied`, `orphan_data_blocks`, `checksum_failures`, `staging_orphans_cleaned`,
`orphan_blocks_cleaned`, and `interrupted_commits`.

---

## Filesystem Operations

All operations are dispatched through the `FileSystem` facade, which normalizes the path,
resolves the mount point, and delegates to the backend.

### open / create_file

`src/kernel/fs/filesystem/open.rs`. `create_file_normalized_with_security_token()` implements
three dispositions:

| Constant | Value | Behavior |
|---|---|---|
| `OPEN_EXISTING` | 0 | Open existing; error if absent |
| `CREATE_NEW` | 1 | Create new; error if exists |
| `OPEN_ALWAYS` | 2 | Open existing or create new |

Returns a `FileHandle` with position, security descriptor, mount flags, and share mode.

### FileHandle

`src/kernel/fs/handle.rs`. Wraps `Arc<dyn VNode>` with cursor position and security context:

- `read()` / `write()`: Delegates to `VNode` at current position, advances cursor.
- `seek()`: Supports `SEEK_SET` (0), `SEEK_CUR` (1), `SEEK_END` (2).
- `set_len()`: Truncates or extends; clamps cursor.
- `sync()` / `sync_data()`: Flushes to stable storage.

### read / write / replace

`src/kernel/fs/filesystem/io.rs`. The facade's `read()` and `write()` forward to
`FileHandle::read`/`write`. `replace_file_contents_normalized_with_security_token()` opens a file
with `OPEN_ALWAYS`, truncates, writes, and verifies byte count.

### stat / read_dir / query

`src/kernel/fs/filesystem/query.rs`:

- `stat_normalized_path()`: Merges backend metadata with mount-level security and overlays.
- `read_dir()`: Merges directory entries from the backend with cross-mount children.
- `mount_points()` / `block_devices()`: Enumerate active mounts and known block devices.
- `fs_profiler_snapshot()`: Aggregates operation counters across all volumes.

### mkdir / rm

`src/kernel/fs/filesystem/dir.rs`:

- `create_dir()` / `create_dir_from()`: Normalizes path, delegates to backend.
- `remove_path()` / `remove_path_from()`: Normalizes path, delegates to backend.
- `remove_normalized_path_if_exists_with_security_token()`: Swallows `NotFound`.

### rename

`src/kernel/fs/filesystem/rename.rs`:

- `rename_path()` / `rename_path_from()`: Normalizes both paths, resolves to the same mount,
  authorizes, and calls `FileSystem::rename()` on the backend.

---

## Pipe Support

`src/kernel/fs/pipe.rs` implements anonymous pipes as a pair of `VNode`s sharing a ring buffer.

**Key types:**

| Type | Role |
|---|---|
| `PipeRing` | Fixed-capacity circular byte buffer (default 16 KiB) |
| `PipeChannel` | Shared state: `Mutex<PipeRing>` + read/write `Condvar`s |
| `PipeReadEnd` | `VNode` that supports `read()`; returns `PermissionDenied` on `write()` |
| `PipeWriteEnd` | `VNode` that supports `write()`; returns `PermissionDenied` on `read()` |

**Blocking semantics:**

- Reader blocks on `read_wait` when buffer is empty; writer signals after inserting data.
- Writer blocks on `write_wait` when buffer is full; reader signals after consuming data.
- Dropping `PipeWriteEnd` sets `write_closed`, wakes readers, and `read()` returns 0 (EOF).
- Dropping `PipeReadEnd` sets `read_closed`, wakes writers, and `write()` returns `DeviceError`.

Created via `pipe_channel()` (16 KiB default) or `pipe_channel_with_capacity(n)`.

---

## FUSE (Design / Deferred)

`src/kernel/fs/fuse/mod.rs` contains the design document and public type stubs for a minimal FUSE
framework. Implementation submodules (not yet built):

- `protocol.rs`: Wire format (`FuseHeader` + TLV payload)
- `connection.rs`: `FuseConnection` — per-mount pipe pair + sequential dispatch
- `filesystem.rs`: `FuseFileSystem` — implements `FileSystem` trait by forwarding through pipes
- `vnode.rs`: `FuseVNode` — lightweight wrapper around a remote inode number
- `error.rs`: `FuseError` to kernel `Error` mapping

**Protocol**: 24-byte header (`seq: u64`, `opcode: u32`, `ino: u64`, `payload_len: u32`) followed
by opcode-specific payloads. Opcodes include LOOKUP, STAT, READ, WRITE, READDIR, CREATE, REMOVE,
CREATE_DIR, RENAME, SET_LEN, FLUSH, ERROR. Sequential dispatch (phase 1) avoids threading
complexity.

---

## Key Files Reference

| File | Purpose |
|---|---|
| `src/kernel/fs/mod.rs` | Top-level facade, re-exports, global singleton |
| `src/kernel/fs/vfs/filesystem.rs` | `FileSystem` trait, `StaticFileSystem` |
| `src/kernel/fs/vfs/vnode.rs` | `VNode` trait, `StaticVNode` |
| `src/kernel/fs/vfs/types.rs` | `NodeKind`, `Metadata`, `SecurityDescriptor`, `DirectoryEntry`, `VolumeCheckReport` |
| `src/kernel/fs/filesystem/{init,mount,open,io,dir,rename}.rs` | VFS operations (init, mount, open, read/write, mkdir/rm, rename) |
| `src/kernel/fs/filesystem/{path_helpers,resolve,overlay}.rs` | Path resolution, mount resolution, cross-mount directory overlay |
| `src/kernel/fs/filesystem/{security,security_helpers}.rs` | Access control and security descriptor authorization |
| `src/kernel/fs/filesystem/types.rs` | `MountPoint`, `MountInfo`, `StorageInitReport` |
| `src/kernel/fs/filesystem/profiler.rs` | `FsProfiler` — operation counters |
| `src/kernel/fs/path.rs` | `normalize_path()` — canonical path normalization |
| `src/kernel/fs/block.rs` | `BlockDevice` trait, `MemoryBlockDevice`, `BlockSliceDevice`, `BLOCK_SIZE` |
| `src/kernel/fs/block_cache.rs` | `BlockCache` — 128-slot LRU cache with write-through/back |
| `src/kernel/fs/partition.rs` | MBR partition table parsing/writing |
| `src/kernel/fs/layout.rs` | `StorageZone` enum, mount flags, zone block ranges |
| `src/kernel/fs/handle.rs` | `FileHandle` — open file descriptor |
| `src/kernel/fs/pipe.rs` | Anonymous pipe (`pipe_channel()`, `PipeReadEnd`, `PipeWriteEnd`) |
| `src/kernel/fs/simplefs/mod.rs` | `SimpleFs`, `SimpleFsState`, `UndoLog`, `ImageEntry` |
| `src/kernel/fs/simplefs/{superblock,types,constants}.rs` | On-disk format: superblock, `OnDiskInode`, `OnDiskDirEntry`, geometry |
| `src/kernel/fs/simplefs/transaction.rs` | Undo-log transactions, `TransactionContext` |
| `src/kernel/fs/simplefs/image_staging.rs` | `SimpleFs::build_image()`, `build_image_with_headroom()` |
| `src/kernel/fs/simplefs/{vfs,file_io,dir_ops,inode_dirent}.rs` | SimpleFs VFS trait impl, data I/O, dirent manipulation, disk serialization |
| `src/kernel/fs/fuse/mod.rs` | FUSE design doc, protocol types (`FuseOpcode`, `FuseHeader`) |
| `src/kernel/fs/demo.rs` | Legacy demo disk builder (zone images, MBR layout) |
| `src/kernel/fs/test_support.rs` | `build_test_zone_image()`, `build_minimal_test_zone_image()` |

---

## See Also

- [Subsystem overview](../en/filesystem.md) — high-level VFS and SimpleFs description
- [Documentation index](../README.md) — complete document tree
