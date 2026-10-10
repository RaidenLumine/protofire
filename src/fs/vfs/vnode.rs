//! src/fs/vfs/vnode.rs
//!
//! VNode trait and StaticVNode implementation.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::types::Metadata;
use super::types::NodeKind;
use super::types::XattrEntry;
use crate::Error;
use crate::Result;

/// Which of the two extents a file is made of a caller is asking for.
///
/// A file is data and holes ([RFC 0017](../../../docs/rfcs/
/// 0017-ask-a-file-where-its-holes-are.md)): a hole is a range that reads as
/// zeros and whose storage the filesystem does not hold, and the end of a file
/// counts as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentKind {
    /// The first byte at or after an offset that is data.
    Data,
    /// The first byte at or after an offset that is a hole.
    Hole,
}

/// Virtual Node trait - represents a file, directory, or device in the VFS
/// All filesystem objects implement this trait to provide a unified interface
///
/// ## UTF-8 filename contract
///
/// [`name`](Self::name) returns a valid UTF-8 `&str`.  Backends that discover
/// non-UTF-8 filenames on disk must convert them lossily (U+FFFD replacement)
/// so the VFS layer never observes invalid Unicode.
pub trait VNode: Send + Sync {
    /// Return the name of this node.
    fn name(&self) -> &str;

    /// Return the kind of this node (file, directory, device, symlink).
    fn kind(&self) -> NodeKind;

    /// Return the size of this node in bytes.
    fn size(&self) -> usize;

    /// Return the metadata (permissions, timestamps, owner) for this node.
    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata::new(self.kind(), self.size()))
    }

    /// Read up to `len` bytes at offset `off` into `buf`. Returns bytes read.
    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize>;

    /// Write `len` bytes from `buf` at offset `off`. Returns bytes written.
    ///
    /// The default implementation refuses with [`Error::PermissionDenied`]: a
    /// node that does not override this is read-only, which is what all of a
    /// synthetic filesystem's nodes are.
    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }

    /// Truncate or extend this node to `len` bytes.
    ///
    /// The default implementation refuses with [`Error::PermissionDenied`],
    /// for the same reason as [`Self::write`].
    fn set_len(&self, _length: u64) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    /// Punch a hole in this node: the range reads as zeros, and the storage the
    /// filesystem can give back for it is released.
    ///
    /// The length of the node does not change — that is what a punch is, as
    /// against a truncation — and neither does anything else about it.  The
    /// default implementation refuses with [`Error::PermissionDenied`], for the
    /// same reason as [`Self::write`]; a filesystem that does not make holes
    /// says [`Error::NotImplemented`].
    fn punch_hole(&self, _offset: u64, _length: u64) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    /// Where the next data or hole at or after `offset` begins, or `None` when
    /// there is none — POSIX's `ENXIO`, which the caller answers `NotFound`
    /// with.
    ///
    /// The default implementation is **exact for a node that has no holes**:
    /// every byte below [`size`](Self::size) of a node that does not override
    /// this is data, so `Data` answers the offset it was given and `Hole` the
    /// end of the file.  A filesystem whose bytes include holes overrides it;
    /// one that cannot say where its holes are refuses with
    /// [`Error::NotImplemented`], which is a different claim from "there are
    /// none".  An `offset` past the end is the caller's refusal, not this
    /// method's.
    fn next_extent(&self, offset: u64, kind: ExtentKind) -> Result<Option<u64>> {
        let size = self.size() as u64;
        match kind {
            ExtentKind::Data if offset < size => Ok(Some(offset)),
            ExtentKind::Hole => Ok(Some(size)),
            _ => Ok(None),
        }
    }

    /// Read the target path of this symlink into `buf`.
    fn readlink(&self) -> Result<Vec<u8>> {
        Err(Error::InvalidArgument)
    }

    /// Return the device identifier for device nodes.
    fn device_id(&self) -> Result<(u32, u32)> {
        Err(Error::InvalidArgument)
    }

    /// Flush all pending metadata and data to stable storage.
    fn sync(&self) -> Result<()> {
        Ok(())
    }

    /// Flush pending data to stable storage.
    fn sync_data(&self) -> Result<()> {
        self.sync()
    }

    /// List extended attributes attached to this node.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn list_xattrs(&self) -> Result<Vec<XattrEntry>> {
        Err(Error::Unsupported)
    }

    /// Read the value of an extended attribute attached to this node.
    /// Returns `Ok(None)` when the attribute is not present.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn get_xattr(&self, _name: &[u8]) -> Result<Option<Vec<u8>>> {
        Err(Error::Unsupported)
    }

    /// Set (create or overwrite) an extended attribute on this node.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn set_xattr(&self, _name: &[u8], _value: &[u8]) -> Result<()> {
        Err(Error::Unsupported)
    }

    /// Remove an extended attribute from this node.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn remove_xattr(&self, _name: &[u8]) -> Result<()> {
        Err(Error::Unsupported)
    }

    /// Return the per-file data-reduction flags (`FILE_FLAG_*`).
    ///
    /// The default implementation returns [`Error::Unsupported`].
    fn get_file_flags(&self) -> Result<u32> {
        Err(Error::Unsupported)
    }

    /// Set the per-file data-reduction flags (`FILE_FLAG_*`).
    ///
    /// `set` bits are turned on and `clear` bits are turned off; bits outside
    /// the user-settable mask are rejected by the caller.  The default
    /// implementation returns [`Error::Unsupported`].
    fn set_file_flags(&self, _set: u32, _clear: u32) -> Result<()> {
        Err(Error::Unsupported)
    }

    /// Return the current pipe buffer capacity when this node is an anonymous
    /// pipe, `None` otherwise.  Backs `fcntl(F_GETPIPE_SZ)`.
    fn pipe_capacity(&self) -> Option<usize> {
        None
    }

    /// Resize the pipe buffer, preserving any buffered data.  Backs
    /// `fcntl(F_SETPIPE_SZ)`.  Non-pipe nodes return [`Error::Unsupported`].
    fn set_pipe_capacity(&self, _capacity: usize) -> Result<()> {
        Err(Error::Unsupported)
    }

    /// Set the non-blocking I/O flag on this node's open file description.
    /// Backs `fcntl(F_SETFL)` with `O_NONBLOCK`.  Nodes that never block on
    /// I/O (regular files, static nodes) accept the flag as a no-op; nodes
    /// with real blocking semantics (pipes) override this to record it.
    fn set_nonblocking(&self, _nonblocking: bool) -> Result<()> {
        Ok(())
    }

    /// Return the non-blocking I/O flag.  Backs `fcntl(F_GETFL)`.  Nodes
    /// that never block on I/O always report `false`.
    fn is_nonblocking(&self) -> bool {
        false
    }
}

pub struct StaticVNode {
    name: &'static str,
    kind: NodeKind,
    data: &'static [u8],
}

impl StaticVNode {
    pub const fn directory(name: &'static str) -> Self {
        Self {
            name,
            kind: NodeKind::Directory,
            data: &[],
        }
    }

    pub const fn file(name: &'static str, data: &'static [u8]) -> Self {
        Self {
            name,
            kind: NodeKind::File,
            data,
        }
    }

    pub const fn device(name: &'static str, data: &'static [u8]) -> Self {
        Self {
            name,
            kind: NodeKind::Device,
            data,
        }
    }

    pub const fn symlink(name: &'static str, target: &'static [u8]) -> Self {
        Self {
            name,
            kind: NodeKind::Symlink,
            data: target,
        }
    }
}

impl VNode for StaticVNode {
    fn name(&self) -> &str {
        self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        self.data.len()
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if self.kind != NodeKind::File && self.kind != NodeKind::Device {
            return Err(Error::InvalidArgument);
        }

        let start = offset as usize;
        if start >= self.data.len() {
            return Ok(0);
        }

        let slice = &self.data[start..];
        let count = slice.len().min(buffer.len());
        buffer[..count].copy_from_slice(&slice[..count]);
        Ok(count)
    }

    fn device_id(&self) -> Result<(u32, u32)> {
        if self.kind != NodeKind::Device {
            return Err(Error::InvalidArgument);
        }
        if self.data.len() >= 4 {
            let dev = u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]);
            Ok(((dev >> 8), (dev & 0xFF)))
        } else {
            Ok((0, 0))
        }
    }
}

pub fn directory_node(name: &'static str) -> Arc<dyn VNode> {
    Arc::new(StaticVNode::directory(name))
}
