//! src/kernel/fs/vfs/filesystem.rs
//!
//! FileSystem trait and StaticFileSystem implementation.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::types::DirectoryEntry;
use super::types::Metadata;
use super::types::NodeKind;
use super::types::SecurityDescriptor;
use super::types::SecurityDescriptorMutationSupport;
use super::types::VolumeCheckReport;
use super::types::XattrEntry;
use super::vnode::StaticVNode;
use super::vnode::VNode;
use crate::kernel::fs::filesystem::profiler::FsProfilerSnapshot;
use crate::Error;
use crate::Result;

/// Filesystem backend that the VFS layer can mount and traverse.
///
/// ## UTF-8 path contract
///
/// All path and filename parameters (`path`, `old_path`, `new_path`,
/// `link_path`) are valid UTF-8 strings — the kernel enforces this at the
/// user-kernel boundary (macOS-style).  Backend implementations **may**
/// assume `&str` validity; they do not need to validate UTF-8 a second time.
///
/// Disk data that is not valid UTF-8 must be handled gracefully (e.g. via
/// [`String::from_utf8_lossy`] with a U+FFFD replacement, as SimpleFs and
/// ext2 do).  See §3.11 of the code-quality review plan for details.
pub trait FileSystem: Send + Sync {
    /// Return the human-readable name of this filesystem.
    fn name(&self) -> &str;
    /// Look up a path and return the corresponding VNode.
    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>>;

    /// Return the metadata for the node at `path`.
    fn stat(&self, path: &str) -> Result<Metadata> {
        let node = self.lookup(path)?;
        Ok(Metadata::new(node.kind(), node.size()))
    }

    /// Read directory entries from the directory at `path`.
    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry>;

    /// Rename `from` to `to`, replacing the target if it exists.
    fn rename(&self, old_path: &str, new_path: &str) -> Result<()>;

    /// Create a regular file at `path`.
    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>>;

    /// Create a directory at `path`.
    fn create_dir(&self, path: &str) -> Result<()>;

    /// Create a symbolic link at `path` pointing to `target`.
    fn create_symlink(&self, target: &str, link_path: &str) -> Result<Arc<dyn VNode>> {
        let _ = (target, link_path);
        Err(Error::Unsupported)
    }

    /// Create a device node at `path`.
    fn create_device(&self, path: &str, major: u32, minor: u32) -> Result<Arc<dyn VNode>> {
        let _ = (path, major, minor);
        Err(Error::Unsupported)
    }

    /// Create a hard link at `link_path` pointing to the same inode as
    /// `target`.
    fn hard_link(&self, target: &str, link_path: &str) -> Result<()> {
        let _ = (target, link_path);
        Err(Error::Unsupported)
    }

    /// Remove the file, directory, or symlink at `path`.
    fn remove_path(&self, path: &str) -> Result<()>;

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn update_security_descriptor(&self, _path: &str, _security: SecurityDescriptor) -> Result<()> {
        Err(Error::Unsupported)
    }

    /// Check filesystem integrity and repair if possible. Returns a
    /// VolumeCheckReport.
    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        Err(Error::Unsupported)
    }

    /// Return a point-in-time snapshot of filesystem operation counters.
    ///
    /// The default implementation returns all zeros.  Filesystems that maintain
    /// operation counters (e.g. `SimpleFsVolume`) override this.
    fn fs_profiler_snapshot(&self) -> FsProfilerSnapshot {
        FsProfilerSnapshot::default()
    }

    /// List extended attributes attached to the node at `path`.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn list_xattrs(&self, _path: &str) -> Result<Vec<XattrEntry>> {
        Err(Error::Unsupported)
    }

    /// Read the value of an extended attribute attached to the node at
    /// `path`.  Returns `Ok(None)` when the attribute is not present.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn get_xattr(&self, _path: &str, _name: &[u8]) -> Result<Option<Vec<u8>>> {
        Err(Error::Unsupported)
    }

    /// Set (create or overwrite) an extended attribute on the node at `path`.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn set_xattr(&self, _path: &str, _name: &[u8], _value: &[u8]) -> Result<()> {
        Err(Error::Unsupported)
    }

    /// Remove an extended attribute from the node at `path`.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn remove_xattr(&self, _path: &str, _name: &[u8]) -> Result<()> {
        Err(Error::Unsupported)
    }

    /// Return the per-file data-reduction flags (`FILE_FLAG_*`) for the node
    /// at `path`.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn get_file_flags(&self, _path: &str) -> Result<u32> {
        Err(Error::Unsupported)
    }

    /// Toggle per-file data-reduction flags (`FILE_FLAG_*`) on the node at
    /// `path`.  Only the compression flag is directly settable; the dedup
    /// flag is maintained by the filesystem.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn set_file_flags(&self, _path: &str, _set: u32, _clear: u32) -> Result<()> {
        Err(Error::Unsupported)
    }

    /// Flush all pending filesystem data and metadata to stable storage.
    /// Backs the global `sync()` syscall and `fsync`.
    ///
    /// The default implementation is a no-op.
    fn sync(&self) -> Result<()> {
        Ok(())
    }

    /// Flush pending file data to stable storage without guaranteeing the
    /// metadata write.  Backs `fdatasync`.
    ///
    /// The default implementation delegates to [`Self::sync`].
    fn sync_data(&self) -> Result<()> {
        self.sync()
    }

    /// Write back dirty blocks that have aged past `age_ticks` to stable
    /// storage (the persistent-cache durability path).  Returns the number of
    /// blocks written when the filesystem reports it, `0` otherwise.
    fn flush_aged(&self, _age_ticks: u64) -> Result<usize> {
        Ok(0)
    }
}

pub struct StaticFileSystem {
    name: &'static str,
    nodes: BTreeMap<String, Arc<dyn VNode>>,
}

impl StaticFileSystem {
    pub fn with_entries(
        name: &'static str,
        entries: &[(&'static str, NodeKind, &'static [u8])],
    ) -> Self {
        let mut fs = Self {
            name,
            nodes: BTreeMap::new(),
        };

        for (path, kind, data) in entries {
            fs.insert(path, *kind, data);
        }

        fs
    }

    pub fn insert(&mut self, path: &'static str, kind: NodeKind, data: &'static [u8]) {
        let key = canonical_path(path);
        let name = path
            .rsplit('/')
            .find(|segment| !segment.is_empty())
            .unwrap_or(path);

        let node: Arc<dyn VNode> = match kind {
            NodeKind::Directory => Arc::new(StaticVNode::directory(name)),
            NodeKind::File => Arc::new(StaticVNode::file(name, data)),
            NodeKind::Device => Arc::new(StaticVNode::device(name, data)),
            NodeKind::Symlink => Arc::new(StaticVNode::symlink(name, data)),
        };

        self.nodes.insert(key, node);
    }
}

impl FileSystem for StaticFileSystem {
    fn name(&self) -> &str {
        self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let key = canonical_path(path);
        self.nodes.get(&key).cloned().ok_or(Error::NotFound)
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let key = canonical_path(path);
        let node = self.nodes.get(&key).ok_or(Error::NotFound)?;
        if node.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let children = direct_children(&self.nodes, &key);
        children.get(index).cloned().ok_or(Error::NotFound)
    }

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn hard_link(&self, _target: &str, _link_path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }
}

fn canonical_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".to_string();
    }

    let mut normalized = String::new();
    normalized.push('/');

    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }

        if normalized.len() > 1 {
            normalized.push('/');
        }

        normalized.push_str(segment);
    }

    normalized
}

fn direct_children(nodes: &BTreeMap<String, Arc<dyn VNode>>, parent: &str) -> Vec<DirectoryEntry> {
    let mut children = Vec::new();
    for (path, node) in nodes {
        let Some(name) = direct_child_name(parent, path) else {
            continue;
        };
        children.push(DirectoryEntry::new(
            node.kind(),
            node.size(),
            name.to_string(),
        ));
    }

    children
}

fn direct_child_name<'a>(parent: &str, path: &'a str) -> Option<&'a str> {
    if parent == "/" {
        let relative = path.strip_prefix('/')?;
        if relative.is_empty() {
            return None;
        }

        let (name, remainder) = relative.split_once('/').unwrap_or((relative, ""));
        if name.is_empty() || !remainder.is_empty() {
            return if remainder.is_empty() {
                Some(name)
            } else {
                None
            };
        }

        return Some(name);
    }

    let prefix = if parent.ends_with('/') {
        parent.to_string()
    } else {
        format!("{parent}/")
    };
    let relative = path.strip_prefix(&prefix)?;
    if relative.is_empty() || relative.contains('/') {
        return None;
    }

    Some(relative)
}
