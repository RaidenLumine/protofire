//! src/kernel/fs/fuse/filesystem.rs
//!
//! FUSE filesystem implementation of the [`FileSystem`] trait.
//!
//! [`FuseFileSystem`] translates each VFS operation
//! (lookup, read_dir, read, write, create, remove, stat, rename, etc.)
//! into a [`FuseRequest`] dispatched through the [`FuseConnection`].

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::fuse::protocol::{
    build_request, kind_from_wire, parse_node_info_payload, parse_readdir_entry_payload,
};
use crate::kernel::fs::fuse::FuseVNode;
use crate::kernel::fs::fuse::{FuseConnection, FuseFileSystem, FuseOpcode};
use crate::kernel::fs::vfs::{
    DirectoryEntry, FileSystem, Metadata, SecurityDescriptor, SecurityDescriptorMutationSupport,
};
use crate::{Error, Result};

// ── Internal helpers ─────────────────────────────────────────────────────

/// Split a mount-relative path (e.g. "/foo/bar") into parent path and the
/// final component name.  Returns `(parent_path, name)`.
///
/// - `"/"` → `("/", "")`
/// - `"/foo"` → `("/", "foo")`
/// - `"/foo/bar"` → `("/foo", "bar")`
fn split_parent_name(path: &str) -> (&str, &str) {
    let trimmed = path.trim_end_matches('/');
    if let Some(pos) = trimmed.rfind('/') {
        let parent = if pos == 0 { "/" } else { &trimmed[..pos] };
        let name = &trimmed[pos + 1..];
        (parent, name)
    } else {
        ("/", trimmed)
    }
}

// ── FuseFileSystem implementation ───────────────────────────────────────

impl FuseFileSystem {
    /// Create a new FUSE-backed filesystem.
    ///
    /// The root inode is set to 1 by convention (FUSE convention).
    /// The daemon must use inode 1 for the root directory.
    pub fn new(name: String, conn: Arc<FuseConnection>) -> Self {
        Self {
            name,
            conn,
            root_ino: core::sync::atomic::AtomicU64::new(1),
            handshake_done: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Perform the initial handshake: send `LOOKUP("/")` to discover the
    /// root inode number from the daemon.
    ///
    /// Must be called once the daemon is ready to serve requests.
    /// Returns the root inode number on success.  If not called, the root
    /// inode defaults to 1.
    pub fn mount_init(&self) -> Result<u64> {
        let root_name = b"/";
        let resp = self
            .conn
            .dispatch(&build_request(0, FuseOpcode::Lookup, 0, root_name))?;
        let (ino, _kind, _size, _name) = parse_node_info_payload(&resp.payload)?;
        self.root_ino
            .store(ino, core::sync::atomic::Ordering::Release);
        Ok(ino)
    }

    // ── Path resolution helpers ────────────────────────────────────────

    /// Best-effort handshake with the daemon: try to discover the real root
    /// inode via an initial `LOOKUP("/")`.  This runs once, lazily, on the
    /// first VFS operation (by then the daemon is running — the mount syscall
    /// itself never touches the pipes).
    ///
    /// If the daemon does not support a root LOOKUP (e.g. the demo daemon,
    /// which only accepts lookups under an existing parent inode), fall back
    /// to the FUSE convention root inode 1.
    fn ensure_mounted(&self) -> Result<()> {
        if self
            .handshake_done
            .swap(true, core::sync::atomic::Ordering::AcqRel)
        {
            return Ok(());
        }
        if let Ok(ino) = self.mount_init() {
            self.root_ino
                .store(ino, core::sync::atomic::Ordering::Release);
        }
        Ok(())
    }

    /// Walk a path component by component, sending LOOKUP for each, and
    /// return the NodeInfo of the final component.
    fn resolve_path(&self, path: &str) -> Result<(u64, u32, u64, String)> {
        self.ensure_mounted()?;
        let root_ino = self.root_ino.load(core::sync::atomic::Ordering::Acquire);
        let trimmed = path.trim_start_matches('/');
        if trimmed.is_empty() {
            // Root — return root inode info via STAT.
            let resp = self
                .conn
                .dispatch(&build_request(0, FuseOpcode::Stat, root_ino, &[]))?;
            if resp.header.opcode != FuseOpcode::Stat as u32 {
                return Err(Error::InternalError);
            }
            return parse_node_info_payload(&resp.payload);
        }

        let components: Vec<&str> = trimmed.split('/').collect();
        let mut current_ino = root_ino;

        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let payload = component.as_bytes();
            let resp =
                self.conn
                    .dispatch(&build_request(0, FuseOpcode::Lookup, current_ino, payload))?;
            if resp.header.opcode != FuseOpcode::Lookup as u32 {
                return Err(Error::InternalError);
            }
            let info = parse_node_info_payload(&resp.payload)?;
            if is_last {
                return Ok(info);
            }
            current_ino = info.0;
        }

        Err(Error::NotFound)
    }

    /// Resolve the parent inode and leaf name for a path.
    fn resolve_parent(&self, path: &str) -> Result<(u64, String)> {
        let (parent_path, name) = split_parent_name(path);
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let (parent_ino, _kind, _size, _name) = self.resolve_path(parent_path)?;
        Ok((parent_ino, name.to_string()))
    }
}

// ── FileSystem trait implementation ─────────────────────────────────────

impl FileSystem for FuseFileSystem {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn crate::kernel::fs::vfs::VNode>> {
        let (ino, kind, size, name) = self.resolve_path(path)?;
        Ok(Arc::new(FuseVNode::new(
            name,
            ino,
            kind_from_wire(kind),
            size,
            Arc::clone(&self.conn),
        )))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let (_ino, kind, size, _name) = self.resolve_path(path)?;
        Ok(Metadata::new(kind_from_wire(kind), size as usize))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let (dir_ino, _kind, _size, _name) = self.resolve_path(path)?;
        let payload = (index as u32).to_le_bytes().to_vec();
        let resp = self
            .conn
            .dispatch(&build_request(0, FuseOpcode::ReadDir, dir_ino, &payload))?;
        if resp.header.opcode != FuseOpcode::ReadDir as u32 {
            return Err(Error::InternalError);
        }

        if resp.payload.is_empty() {
            return Err(Error::NotFound); // No more entries
        }

        let (ino, kind, size, name) = parse_readdir_entry_payload(&resp.payload)?;
        let _ = ino; // inode consumed by the entry
        Ok(DirectoryEntry::new(
            kind_from_wire(kind),
            size as usize,
            name,
        ))
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let (old_parent_ino, old_name) = self.resolve_parent(old_path)?;
        let (_new_parent_ino, new_name) = self.resolve_parent(new_path)?;

        let mut payload = Vec::new();
        payload.extend_from_slice(old_name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(new_name.as_bytes());

        self.conn.dispatch(&build_request(
            0,
            FuseOpcode::Rename,
            old_parent_ino,
            &payload,
        ))?;
        Ok(())
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn crate::kernel::fs::vfs::VNode>> {
        let (parent_ino, name) = self.resolve_parent(path)?;
        let payload = name.as_bytes().to_vec();
        let resp =
            self.conn
                .dispatch(&build_request(0, FuseOpcode::Create, parent_ino, &payload))?;
        if resp.header.opcode != FuseOpcode::Create as u32 {
            return Err(Error::InternalError);
        }
        let (ino, kind, size, _name) = parse_node_info_payload(&resp.payload)?;
        Ok(Arc::new(FuseVNode::new(
            name,
            ino,
            kind_from_wire(kind),
            size,
            Arc::clone(&self.conn),
        )))
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        let (parent_ino, name) = self.resolve_parent(path)?;
        let payload = name.as_bytes().to_vec();
        self.conn.dispatch(&build_request(
            0,
            FuseOpcode::CreateDir,
            parent_ino,
            &payload,
        ))?;
        Ok(())
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        let (parent_ino, name) = self.resolve_parent(path)?;
        let payload = name.as_bytes().to_vec();
        self.conn
            .dispatch(&build_request(0, FuseOpcode::Remove, parent_ino, &payload))?;
        Ok(())
    }

    fn create_symlink(
        &self,
        _target: &str,
        _link_path: &str,
    ) -> Result<Arc<dyn crate::kernel::fs::vfs::VNode>> {
        Err(Error::Unsupported)
    }

    fn create_device(
        &self,
        _path: &str,
        _major: u32,
        _minor: u32,
    ) -> Result<Arc<dyn crate::kernel::fs::vfs::VNode>> {
        Err(Error::Unsupported)
    }

    fn hard_link(&self, _target: &str, _link_path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn update_security_descriptor(&self, _path: &str, _security: SecurityDescriptor) -> Result<()> {
        Err(Error::Unsupported)
    }
}
