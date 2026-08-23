//! src/kernel/fs/tmpfs/mod.rs
//! Pure in-memory tmpfs filesystem.
//!
//! Provides a simple read-write filesystem backed entirely by RAM.
//! Supports files, directories, symlinks, rename, and hard links.
//!
//! ## Architecture
//!
//! [`TmpFsVolume`] wraps an [`Arc<Mutex<TmpFsInner>>`] containing the inode
//! table and directory entries. All operations acquire the lock briefly.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::filesystem::profiler::FsProfilerSnapshot;
use crate::kernel::fs::vfs::{
    DirectoryEntry, FileSystem as VfsFileSystem, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport, XattrEntry, DEFAULT_DEVICE_MODE,
};
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Current Unix timestamp in seconds (0 if RTC is unavailable).
fn now_unix() -> u64 {
    crate::arch::timer::rtc_now_unix().unwrap_or(0)
}

// ── Inode data ────────────────────────────────────────────────────────────

enum InodeData {
    File(Vec<u8>),
    Directory(BTreeMap<String, u64>),
    Symlink(String),
    Device { major: u32, minor: u32 },
}

struct Inode {
    data: InodeData,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    created: u64,
    modified: u64,
    accessed: u64,
    /// In-memory extended attributes (name → value).
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

// ── Inner state ───────────────────────────────────────────────────────────

struct TmpFsInner {
    inodes: BTreeMap<u64, Inode>,
    next_ino: u64,
    max_size: usize,
    used_size: usize,
    file_mode: u16,
    dir_mode: u16,
    default_uid: u32,
    default_gid: u32,
}

impl TmpFsInner {
    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    fn insert_inode(&mut self, data: InodeData, mode: u16) -> u64 {
        let ino = self.alloc_ino();
        let now = now_unix();
        self.inodes.insert(
            ino,
            Inode {
                data,
                nlink: 1,
                uid: self.default_uid,
                gid: self.default_gid,
                mode,
                created: now,
                modified: now,
                accessed: now,
                xattrs: BTreeMap::new(),
            },
        );
        ino
    }
}

// ── Volume ────────────────────────────────────────────────────────────────

pub struct TmpFsVolume {
    name: String,
    inner: Arc<Mutex<TmpFsInner>>,
}

impl TmpFsVolume {
    pub fn new(name: &str, max_size: usize) -> Self {
        let mut inner = TmpFsInner {
            inodes: BTreeMap::new(),
            next_ino: 2,
            max_size,
            used_size: 0,
            file_mode: 0o666,
            dir_mode: 0o777,
            default_uid: 0,
            default_gid: 0,
        };

        // Create root directory (ino 1).
        let now = now_unix();
        inner.inodes.insert(
            1,
            Inode {
                data: InodeData::Directory(BTreeMap::new()),
                nlink: 2,
                uid: 0,
                gid: 0,
                mode: 0o777,
                created: now,
                modified: now,
                accessed: now,
                xattrs: BTreeMap::new(),
            },
        );

        Self {
            name: name.into(),
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    fn resolve_parent(&self, path: &str) -> Result<(u64, String)> {
        let clean = clean_path(path);
        if clean == "/" {
            return Err(Error::InvalidArgument);
        }
        let (parent_path, name) = split_parent(&clean);
        let parent_ino = self.resolve_path(parent_path)?;
        Ok((parent_ino, name))
    }

    fn resolve_path(&self, path: &str) -> Result<u64> {
        let clean = clean_path(path);
        if clean == "/" {
            return Ok(1);
        }

        let inner = self.inner.lock();
        let segments: Vec<&str> = clean
            .strip_prefix('/')
            .unwrap_or(&clean)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut ino: u64 = 1;
        for seg in &segments {
            let inode = inner.inodes.get(&ino).ok_or(Error::NotFound)?;
            let entries = match &inode.data {
                InodeData::Directory(entries) => entries,
                _ => return Err(Error::InvalidArgument),
            };
            ino = *entries.get(*seg).ok_or(Error::NotFound)?;
        }
        Ok(ino)
    }
}

impl VfsFileSystem for TmpFsVolume {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let clean = clean_path(path);
        let ino = self.resolve_path(&clean)?;
        let inner = self.inner.lock();
        let inode = inner.inodes.get(&ino).ok_or(Error::NotFound)?;

        let kind = match &inode.data {
            InodeData::File(_) => NodeKind::File,
            InodeData::Directory(_) => NodeKind::Directory,
            InodeData::Symlink(_) => NodeKind::Symlink,
            InodeData::Device { .. } => NodeKind::Device,
        };

        let size = match &inode.data {
            InodeData::File(data) => data.len(),
            _ => 0,
        };

        Ok(Arc::new(TmpFsVNode {
            name: extract_name(&clean),
            kind,
            ino,
            size,
            fs: self.inner.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        self.lookup(path)?.metadata()
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let clean = clean_path(path);
        let ino = self.resolve_path(&clean)?;
        let inner = self.inner.lock();
        let inode = inner.inodes.get(&ino).ok_or(Error::NotFound)?;
        let entries = match &inode.data {
            InodeData::Directory(entries) => entries,
            _ => return Err(Error::InvalidArgument),
        };

        let (name, child_ino) = entries.iter().nth(index).ok_or(Error::NotFound)?;
        let child = inner.inodes.get(child_ino).ok_or(Error::NotFound)?;

        let kind = match &child.data {
            InodeData::File(_) => NodeKind::File,
            InodeData::Directory(_) => NodeKind::Directory,
            InodeData::Symlink(_) => NodeKind::Symlink,
            InodeData::Device { .. } => NodeKind::Device,
        };

        let size = match &child.data {
            InodeData::File(data) => data.len(),
            _ => 0,
        };

        Ok(DirectoryEntry {
            kind,
            size,
            name: name.clone(),
            security: SecurityDescriptor {
                owner_uid: child.uid,
                owner_gid: child.gid,
                mode: child.mode,
            },
        })
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (parent_ino, name) = self.resolve_parent(path)?;
        let mut inner = self.inner.lock();

        // Reject when the parent is not a directory or an entry with this
        // name already exists; otherwise the freshly allocated inode would
        // be orphaned by the entry overwrite below.
        {
            let parent = inner.inodes.get(&parent_ino).ok_or(Error::NotFound)?;
            match &parent.data {
                InodeData::Directory(entries) => {
                    if entries.contains_key(&name) {
                        return Err(Error::AlreadyExists);
                    }
                }
                _ => return Err(Error::InvalidArgument),
            }
        }

        let file_mode = inner.file_mode;
        let ino = inner.insert_inode(InodeData::File(Vec::new()), file_mode);

        {
            let parent = inner.inodes.get_mut(&parent_ino).ok_or(Error::NotFound)?;
            if let InodeData::Directory(ref mut entries) = parent.data {
                entries.insert(name.clone(), ino);
            }
        }

        Ok(Arc::new(TmpFsVNode {
            name,
            kind: NodeKind::File,
            ino,
            size: 0,
            fs: self.inner.clone(),
        }))
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        let (parent_ino, name) = self.resolve_parent(path)?;
        let mut inner = self.inner.lock();

        // Reject when the parent is not a directory or the name already
        // exists; otherwise the fresh inode would be orphaned.
        {
            let parent = inner.inodes.get(&parent_ino).ok_or(Error::NotFound)?;
            match &parent.data {
                InodeData::Directory(entries) => {
                    if entries.contains_key(&name) {
                        return Err(Error::AlreadyExists);
                    }
                }
                _ => return Err(Error::InvalidArgument),
            }
        }

        let dir_mode = inner.dir_mode;
        let ino = inner.insert_inode(InodeData::Directory(BTreeMap::new()), dir_mode);

        {
            let parent = inner.inodes.get_mut(&parent_ino).ok_or(Error::NotFound)?;
            if let InodeData::Directory(ref mut entries) = parent.data {
                entries.insert(name, ino);
            }
            // Bump parent nlink for "..".
            if let Some(parent_inode) = inner.inodes.get_mut(&parent_ino) {
                parent_inode.nlink += 1;
            }
        }

        Ok(())
    }

    fn create_symlink(&self, target: &str, path: &str) -> Result<Arc<dyn VNode>> {
        let (parent_ino, name) = self.resolve_parent(path)?;
        let mut inner = self.inner.lock();

        // Reject when the parent is not a directory or the name already
        // exists; otherwise the fresh inode would be orphaned.
        {
            let parent = inner.inodes.get(&parent_ino).ok_or(Error::NotFound)?;
            match &parent.data {
                InodeData::Directory(entries) => {
                    if entries.contains_key(&name) {
                        return Err(Error::AlreadyExists);
                    }
                }
                _ => return Err(Error::InvalidArgument),
            }
        }

        let ino = inner.insert_inode(InodeData::Symlink(target.into()), 0o777);

        {
            let parent = inner.inodes.get_mut(&parent_ino).ok_or(Error::NotFound)?;
            if let InodeData::Directory(ref mut entries) = parent.data {
                entries.insert(name.clone(), ino);
            }
        }

        Ok(Arc::new(TmpFsVNode {
            name,
            kind: NodeKind::Symlink,
            ino,
            size: 0,
            fs: self.inner.clone(),
        }))
    }

    fn create_device(&self, path: &str, major: u32, minor: u32) -> Result<Arc<dyn VNode>> {
        let (parent_ino, name) = self.resolve_parent(path)?;
        let mut inner = self.inner.lock();

        // Reject when the parent is not a directory or the name already
        // exists; otherwise the fresh inode would be orphaned.
        {
            let parent = inner.inodes.get(&parent_ino).ok_or(Error::NotFound)?;
            match &parent.data {
                InodeData::Directory(entries) => {
                    if entries.contains_key(&name) {
                        return Err(Error::AlreadyExists);
                    }
                }
                _ => return Err(Error::InvalidArgument),
            }
        }

        let dev_mode = DEFAULT_DEVICE_MODE;
        let ino = inner.insert_inode(InodeData::Device { major, minor }, dev_mode);

        {
            let parent = inner.inodes.get_mut(&parent_ino).ok_or(Error::NotFound)?;
            if let InodeData::Directory(ref mut entries) = parent.data {
                entries.insert(name.clone(), ino);
            }
        }

        Ok(Arc::new(TmpFsVNode {
            name,
            kind: NodeKind::Device,
            ino,
            size: 0,
            fs: self.inner.clone(),
        }))
    }

    fn hard_link(&self, target: &str, link_path: &str) -> Result<()> {
        let target_ino = self.resolve_path(target)?;
        let (parent_ino, name) = self.resolve_parent(link_path)?;
        let mut inner = self.inner.lock();

        // Verify target exists and is not a directory.
        let target_inode = inner.inodes.get(&target_ino).ok_or(Error::NotFound)?;
        if matches!(target_inode.data, InodeData::Directory(_)) {
            return Err(Error::PermissionDenied);
        }

        // Add entry in parent directory.
        let parent = inner.inodes.get_mut(&parent_ino).ok_or(Error::NotFound)?;
        if let InodeData::Directory(ref mut entries) = parent.data {
            if entries.contains_key(&name) {
                return Err(Error::AlreadyExists);
            }
            entries.insert(name, target_ino);
        }

        // Increment link count.
        if let Some(inode) = inner.inodes.get_mut(&target_ino) {
            inode.nlink += 1;
        }

        Ok(())
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        let (parent_ino, name) = self.resolve_parent(path)?;
        let mut inner = self.inner.lock();

        let child_ino = {
            let parent = inner.inodes.get(&parent_ino).ok_or(Error::NotFound)?;
            match &parent.data {
                InodeData::Directory(ref entries) => *entries.get(&name).ok_or(Error::NotFound)?,
                _ => return Err(Error::InvalidArgument),
            }
        };

        // Refuse to remove a non-empty directory; removing it here would
        // orphan every inode it still references.
        if let Some(child) = inner.inodes.get(&child_ino) {
            if let InodeData::Directory(entries) = &child.data {
                if !entries.is_empty() {
                    return Err(Error::Busy);
                }
            }
        }

        {
            let parent = inner.inodes.get_mut(&parent_ino).ok_or(Error::NotFound)?;
            if let InodeData::Directory(ref mut entries) = parent.data {
                entries.remove(&name);
            }
        }

        // Decrement nlink and remove inode if nlink reaches 0.
        let remove = if let Some(child) = inner.inodes.get_mut(&child_ino) {
            child.nlink -= 1;
            child.nlink == 0
        } else {
            false
        };

        if remove {
            // Update used_size if file data.
            if let Some(inode) = inner.inodes.remove(&child_ino) {
                if let InodeData::File(ref data) = inode.data {
                    inner.used_size = inner.used_size.saturating_sub(data.len());
                }
            }

            // Decrement parent nlink if child was a directory.
            if let Some(parent) = inner.inodes.get_mut(&parent_ino) {
                parent.nlink -= 1;
            }
        }

        Ok(())
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let (old_parent_ino, old_name) = self.resolve_parent(old_path)?;
        let (new_parent_ino, new_name) = self.resolve_parent(new_path)?;
        let mut inner = self.inner.lock();

        let child_ino = {
            let old_parent = inner.inodes.get(&old_parent_ino).ok_or(Error::NotFound)?;
            match &old_parent.data {
                InodeData::Directory(ref entries) => {
                    *entries.get(&old_name).ok_or(Error::NotFound)?
                }
                _ => return Err(Error::InvalidArgument),
            }
        };

        let child_is_dir = matches!(
            inner.inodes.get(&child_ino).map(|inode| &inode.data),
            Some(InodeData::Directory(_))
        );

        // Renaming a directory into its own subtree would create a cycle
        // that makes future path lookups loop forever.
        if child_is_dir && subtree_contains(&inner, child_ino, new_parent_ino) {
            return Err(Error::InvalidArgument);
        }

        let existing = {
            let new_parent = inner.inodes.get(&new_parent_ino).ok_or(Error::NotFound)?;
            match &new_parent.data {
                InodeData::Directory(ref entries) => entries.get(&new_name).copied(),
                _ => return Err(Error::InvalidArgument),
            }
        };

        // Renaming a node onto itself (same name, or both names hard-linking
        // the same inode) is a no-op.
        if existing == Some(child_ino) {
            return Ok(());
        }

        // Remove a stale target, validating kind compatibility first: a
        // directory may only replace a directory (and only an empty one),
        // and a non-directory may only replace a non-directory.
        if let Some(existing_ino) = existing {
            let target_is_dir = matches!(
                inner.inodes.get(&existing_ino).map(|inode| &inode.data),
                Some(InodeData::Directory(_))
            );
            if child_is_dir != target_is_dir {
                return Err(Error::InvalidArgument);
            }
            if target_is_dir {
                let target = inner.inodes.get(&existing_ino).ok_or(Error::NotFound)?;
                if let InodeData::Directory(entries) = &target.data {
                    if !entries.is_empty() {
                        return Err(Error::Busy);
                    }
                }
            }

            let target_gone = {
                let target = inner.inodes.get_mut(&existing_ino).ok_or(Error::NotFound)?;
                target.nlink -= 1;
                target.nlink == 0
            };
            if target_gone {
                if let Some(target) = inner.inodes.remove(&existing_ino) {
                    if let InodeData::File(ref data) = target.data {
                        inner.used_size = inner.used_size.saturating_sub(data.len());
                    }
                }
                // The replaced directory's ".." disappears from the parent.
                if target_is_dir {
                    if let Some(parent) = inner.inodes.get_mut(&new_parent_ino) {
                        parent.nlink = parent.nlink.saturating_sub(1);
                    }
                }
            }
        }

        // Move entry from old parent to new parent.
        {
            let old_parent = inner
                .inodes
                .get_mut(&old_parent_ino)
                .ok_or(Error::NotFound)?;
            if let InodeData::Directory(ref mut entries) = old_parent.data {
                entries.remove(&old_name);
            }
        }

        {
            let new_parent = inner
                .inodes
                .get_mut(&new_parent_ino)
                .ok_or(Error::NotFound)?;
            if let InodeData::Directory(ref mut entries) = new_parent.data {
                entries.insert(new_name, child_ino);
            }
        }

        // A moved directory's ".." leaves the old parent and arrives at the
        // new one (a no-op when the parents coincide).
        if child_is_dir && old_parent_ino != new_parent_ino {
            if let Some(parent) = inner.inodes.get_mut(&old_parent_ino) {
                parent.nlink = parent.nlink.saturating_sub(1);
            }
            if let Some(parent) = inner.inodes.get_mut(&new_parent_ino) {
                parent.nlink = parent.nlink.saturating_add(1);
            }
        }

        Ok(())
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::Persistent
    }

    fn update_security_descriptor(&self, path: &str, sd: SecurityDescriptor) -> Result<()> {
        let clean = clean_path(path);
        let ino = self.resolve_path(&clean)?;
        let mut inner = self.inner.lock();
        let inode = inner.inodes.get_mut(&ino).ok_or(Error::NotFound)?;
        inode.uid = sd.owner_uid;
        inode.gid = sd.owner_gid;
        inode.mode = sd.mode;
        Ok(())
    }

    fn list_xattrs(&self, path: &str) -> Result<Vec<XattrEntry>> {
        let clean = clean_path(path);
        let ino = self.resolve_path(&clean)?;
        let inner = self.inner.lock();
        let inode = inner.inodes.get(&ino).ok_or(Error::NotFound)?;
        Ok(inode
            .xattrs
            .iter()
            .map(|(name, value)| XattrEntry::new(name.clone(), value.clone()))
            .collect())
    }

    fn get_xattr(&self, path: &str, name: &[u8]) -> Result<Option<Vec<u8>>> {
        let clean = clean_path(path);
        let ino = self.resolve_path(&clean)?;
        let inner = self.inner.lock();
        let inode = inner.inodes.get(&ino).ok_or(Error::NotFound)?;
        Ok(inode.xattrs.get(name).cloned())
    }

    fn set_xattr(&self, path: &str, name: &[u8], value: &[u8]) -> Result<()> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let clean = clean_path(path);
        let ino = self.resolve_path(&clean)?;
        let mut inner = self.inner.lock();
        let inode = inner.inodes.get_mut(&ino).ok_or(Error::NotFound)?;
        inode.xattrs.insert(name.to_vec(), value.to_vec());
        Ok(())
    }

    fn remove_xattr(&self, path: &str, name: &[u8]) -> Result<()> {
        let clean = clean_path(path);
        let ino = self.resolve_path(&clean)?;
        let mut inner = self.inner.lock();
        let inode = inner.inodes.get_mut(&ino).ok_or(Error::NotFound)?;
        if inode.xattrs.remove(name).is_none() {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        Ok(VolumeCheckReport {
            issues_detected: 0,
            repairs_applied: 0,
            orphan_data_blocks: 0,
            checksum_failures: 0,
            staging_orphans_cleaned: 0,
            orphan_blocks_cleaned: 0,
            interrupted_commits: 0,
        })
    }

    fn fs_profiler_snapshot(&self) -> FsProfilerSnapshot {
        FsProfilerSnapshot::default()
    }
}

// ── VNode ─────────────────────────────────────────────────────────────────

struct TmpFsVNode {
    name: String,
    kind: NodeKind,
    ino: u64,
    size: usize,
    fs: Arc<Mutex<TmpFsInner>>,
}

impl VNode for TmpFsVNode {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> NodeKind {
        self.kind
    }
    fn size(&self) -> usize {
        if self.kind == NodeKind::File {
            let inner = self.fs.lock();
            if let Some(inode) = inner.inodes.get(&self.ino) {
                if let InodeData::File(ref data) = inode.data {
                    return data.len();
                }
            }
        }
        self.size
    }

    fn metadata(&self) -> Result<Metadata> {
        let inner = self.fs.lock();
        let inode = inner.inodes.get(&self.ino).ok_or(Error::NotFound)?;
        // Use the current data length for files (self.size may be stale
        // after writes), falling back to self.size for non-files.
        let size = if let InodeData::File(ref data) = inode.data {
            data.len()
        } else {
            self.size
        };
        Ok(Metadata {
            kind: self.kind,
            size,
            security: SecurityDescriptor {
                owner_uid: inode.uid,
                owner_gid: inode.gid,
                mode: inode.mode,
            },
            created: inode.created,
            modified: inode.modified,
            accessed: inode.accessed,
        })
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let mut inner = self.fs.lock();
        let inode = inner.inodes.get_mut(&self.ino).ok_or(Error::NotFound)?;
        let data = match &inode.data {
            InodeData::File(data) => data,
            _ => return Err(Error::InvalidArgument),
        };
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = buffer.len().min(data.len() - off);
        buffer[..n].copy_from_slice(&data[off..off + n]);
        inode.accessed = now_unix();
        Ok(n)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let mut inner = self.fs.lock();
        let max_size = inner.max_size;
        let old_used = inner.used_size;

        let new_used = {
            let inode = inner.inodes.get_mut(&self.ino).ok_or(Error::NotFound)?;
            let data = match &mut inode.data {
                InodeData::File(data) => data,
                _ => return Err(Error::InvalidArgument),
            };

            let off = offset as usize;
            let write_end = off + buffer.len();
            let old_len = data.len();

            let new_used = if write_end > data.len() {
                let new_len = write_end;
                let new_total = old_used.saturating_sub(old_len).saturating_add(new_len);
                if new_total > max_size && max_size > 0 {
                    return Err(Error::OutOfMemory);
                }
                data.resize(new_len, 0);
                new_total
            } else {
                old_used
            };

            data[off..write_end].copy_from_slice(buffer);
            let now = now_unix();
            inode.modified = now;
            inode.accessed = now;
            new_used
        };

        inner.used_size = new_used;
        Ok(buffer.len())
    }

    fn set_len(&self, new_len: u64) -> Result<()> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let mut inner = self.fs.lock();
        let max_size = inner.max_size;
        let old_used = inner.used_size;

        let new_used = {
            let inode = inner.inodes.get_mut(&self.ino).ok_or(Error::NotFound)?;
            let data = match &mut inode.data {
                InodeData::File(data) => data,
                _ => return Err(Error::InvalidArgument),
            };

            let new_len = new_len as usize;
            let old_len = data.len();

            let new_used = if new_len > old_len {
                let new_total = old_used.saturating_sub(old_len).saturating_add(new_len);
                if new_total > max_size && max_size > 0 {
                    return Err(Error::OutOfMemory);
                }
                data.resize(new_len, 0);
                new_total
            } else {
                data.truncate(new_len);
                old_used.saturating_sub(old_len).saturating_add(new_len)
            };

            inode.modified = now_unix();
            new_used
        };

        inner.used_size = new_used;
        Ok(())
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        if self.kind != NodeKind::Symlink {
            return Err(Error::InvalidArgument);
        }
        let inner = self.fs.lock();
        let inode = inner.inodes.get(&self.ino).ok_or(Error::NotFound)?;
        match &inode.data {
            InodeData::Symlink(target) => Ok(target.as_bytes().to_vec()),
            _ => Err(Error::InvalidArgument),
        }
    }

    fn list_xattrs(&self) -> Result<Vec<crate::kernel::fs::vfs::XattrEntry>> {
        let inner = self.fs.lock();
        let inode = inner.inodes.get(&self.ino).ok_or(Error::NotFound)?;
        Ok(inode
            .xattrs
            .iter()
            .map(|(name, value)| {
                crate::kernel::fs::vfs::XattrEntry::new(name.clone(), value.clone())
            })
            .collect())
    }

    fn get_xattr(&self, name: &[u8]) -> Result<Option<Vec<u8>>> {
        let inner = self.fs.lock();
        let inode = inner.inodes.get(&self.ino).ok_or(Error::NotFound)?;
        Ok(inode.xattrs.get(name).cloned())
    }

    fn set_xattr(&self, name: &[u8], value: &[u8]) -> Result<()> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let mut inner = self.fs.lock();
        let inode = inner.inodes.get_mut(&self.ino).ok_or(Error::NotFound)?;
        inode.xattrs.insert(name.to_vec(), value.to_vec());
        Ok(())
    }

    fn remove_xattr(&self, name: &[u8]) -> Result<()> {
        let mut inner = self.fs.lock();
        let inode = inner.inodes.get_mut(&self.ino).ok_or(Error::NotFound)?;
        if inode.xattrs.remove(name).is_none() {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn sync_data(&self) -> Result<()> {
        Ok(())
    }

    fn device_id(&self) -> Result<(u32, u32)> {
        if self.kind != NodeKind::Device {
            return Err(Error::InvalidArgument);
        }
        let inner = self.fs.lock();
        let inode = inner.inodes.get(&self.ino).ok_or(Error::NotFound)?;
        match &inode.data {
            InodeData::Device { major, minor } => Ok((*major, *minor)),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn clean_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".into();
    }
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn extract_name(path: &str) -> String {
    let clean = clean_path(path);
    if clean == "/" {
        return "/".into();
    }
    clean
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("/")
        .into()
}

fn split_parent(path: &str) -> (&str, String) {
    debug_assert!(path != "/", "split_parent called on root");
    let last_slash = path.rfind('/').unwrap_or(0);
    let parent = if last_slash == 0 {
        "/"
    } else {
        &path[..last_slash]
    };
    let name = &path[last_slash + 1..];
    (parent, name.into())
}

/// Return true if `needle` is an inode inside the directory subtree rooted
/// at `ancestor` (excluding `ancestor` itself).  Used by `rename` to reject
/// moves that would make a directory its own descendant.
fn subtree_contains(inner: &TmpFsInner, ancestor: u64, needle: u64) -> bool {
    let inode = match inner.inodes.get(&ancestor) {
        Some(inode) => inode,
        None => return false,
    };
    let entries = match &inode.data {
        InodeData::Directory(entries) => entries,
        _ => return false,
    };
    let mut stack: Vec<u64> = entries.values().copied().collect();
    while let Some(idx) = stack.pop() {
        if idx == needle {
            return true;
        }
        if let Some(child) = inner.inodes.get(&idx) {
            if let InodeData::Directory(entries) = &child.data {
                stack.extend(entries.values().copied());
            }
        }
    }
    false
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::fs::NodeKind;
    use alloc::vec;

    fn setup() -> TmpFsVolume {
        TmpFsVolume::new("test", 1024 * 1024)
    }

    #[test]
    fn tmpfs_root_lookup() {
        let vol = setup();
        let vnode = vol.lookup("/").expect("lookup root");
        assert_eq!(vnode.kind(), NodeKind::Directory);
    }

    #[test]
    fn tmpfs_create_and_read_file() {
        let vol = setup();
        let vnode = vol.create_file("/hello").expect("create file");
        assert_eq!(vnode.kind(), NodeKind::File);

        let n = vnode.write(0, b"Hello, tmpfs!").expect("write");
        assert_eq!(n, 13);

        let mut buf = vec![0u8; 32];
        let n = vnode.read(0, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"Hello, tmpfs!");
    }

    #[test]
    fn tmpfs_create_dir_and_lookup() {
        let vol = setup();
        vol.create_dir("/sub").expect("create dir");
        vol.create_file("/sub/nested").expect("create nested file");

        let vnode = vol.lookup("/sub/nested").expect("lookup");
        assert_eq!(vnode.kind(), NodeKind::File);
    }

    #[test]
    fn tmpfs_symlink() {
        let vol = setup();
        vol.create_file("/target").expect("create target");
        vol.create_symlink("/target", "/link")
            .expect("create symlink");

        let vnode = vol.lookup("/link").expect("lookup symlink");
        assert_eq!(vnode.kind(), NodeKind::Symlink);
        let target = vnode.readlink().expect("readlink");
        assert_eq!(target, b"/target");
    }

    #[test]
    fn tmpfs_rename() {
        let vol = setup();
        vol.create_file("/old").expect("create file");
        vol.rename("/old", "/new").expect("rename");

        assert!(vol.lookup("/new").is_ok());
        assert!(matches!(vol.lookup("/old"), Err(Error::NotFound)));
    }

    #[test]
    fn tmpfs_remove_file() {
        let vol = setup();
        vol.create_file("/gone").expect("create file");
        vol.remove_path("/gone").expect("remove");
        assert!(matches!(vol.lookup("/gone"), Err(Error::NotFound)));
    }

    #[test]
    fn tmpfs_stat() {
        let vol = setup();
        vol.create_file("/statme").expect("create");
        let meta = vol.stat("/statme").expect("stat");
        assert_eq!(meta.kind, NodeKind::File);
    }

    #[test]
    fn tmpfs_read_dir() {
        let vol = setup();
        vol.create_file("/a").expect("create a");
        vol.create_file("/b").expect("create b");

        let e0 = vol.read_dir("/", 0).expect("read_dir 0");
        let e1 = vol.read_dir("/", 1).expect("read_dir 1");
        // Directory entries are in BTreeMap order (alphabetical).
        assert_eq!(e0.name, "a");
        assert_eq!(e1.name, "b");
    }

    #[test]
    fn tmpfs_size_quota() {
        let vol = TmpFsVolume::new("quota", 10);
        let vnode = vol.create_file("/small").expect("create");
        // Writing more than max_size should fail.
        let result = vnode.write(0, &[0u8; 20]);
        assert!(matches!(result, Err(Error::OutOfMemory)));
    }

    #[test]
    fn tmpfs_set_len() {
        let vol = setup();
        let vnode = vol.create_file("/resize").expect("create");
        vnode.set_len(42).expect("set_len");
        assert_eq!(vnode.size(), 42);
    }
}
