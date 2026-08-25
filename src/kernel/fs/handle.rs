//! src/kernel/fs/handle.rs
//!
//! FileHandle struct and its implementation for open file descriptors.

use alloc::sync::Arc;

use crate::kernel::process::SecurityToken;
use crate::Result;

use super::filesystem::access_helpers::mount_allows_write_for_security_token;
use super::vfs::Metadata;
use super::vfs::MetadataAccessQueryContext;
use super::vfs::NodeKind;
use super::vfs::PermissionMetadataRecord;
use super::vfs::SecurityDescriptor;
use super::vfs::SecurityDescriptorMutationSupport;
use super::vfs::VNode;
use super::ACCESS_WRITE_BIT;
use super::SEEK_CUR;
use super::SEEK_END;
use super::SEEK_SET;

pub struct FileHandle {
    pub handle: u64,
    pub(crate) vnode: Arc<dyn VNode>,
    pub(crate) security: SecurityDescriptor,
    pub(crate) security_source: SecurityDescriptorMutationSupport,
    pub(crate) mount_flags: u32,
    pub position: u64,
    pub flags: u32,
    pub share_mode: u32,
}

impl FileHandle {
    /// Construct a new [`FileHandle`] from its constituent parts.
    ///
    /// This is the escape hatch for kernel subsystems (pipe, device nodes)
    /// that create file handles without going through the VFS mount/lookup
    /// machinery.  The caller is responsible for providing a unique `handle`
    /// number obtained via [`FileSystem::alloc_handles`].
    pub fn new(
        handle: u64,
        vnode: Arc<dyn VNode>,
        security: SecurityDescriptor,
        security_source: SecurityDescriptorMutationSupport,
        mount_flags: u32,
    ) -> Self {
        Self {
            handle,
            vnode,
            security,
            security_source,
            mount_flags,
            position: 0,
            flags: 0,
            share_mode: 0,
        }
    }

    pub fn kind(&self) -> NodeKind {
        self.vnode.kind()
    }

    pub fn size(&self) -> usize {
        self.vnode.size()
    }

    fn metadata(&self) -> Result<Metadata> {
        let metadata = self.vnode.metadata()?;
        if self.security_source.provides_persistent_metadata() {
            Ok(metadata)
        } else {
            Ok(metadata.with_security(self.security))
        }
    }

    pub(crate) fn permission_metadata_record(&self) -> Result<PermissionMetadataRecord> {
        Ok(self.metadata()?.permission_metadata_record())
    }

    pub(crate) fn access_query_context_for(
        &self,
        required_access: u16,
        security_token: SecurityToken,
    ) -> Result<MetadataAccessQueryContext> {
        let metadata = self.metadata()?;
        let mut context = metadata.access_query_context_for(required_access, security_token);
        if metadata.kind != NodeKind::Device
            && context.access.can_write
            && !mount_allows_write_for_security_token(self.mount_flags, security_token)
        {
            context.access.granted_mode_bits &= !ACCESS_WRITE_BIT;
            context.access.can_write = false;
            context.access.allowed = required_access & !context.access.granted_mode_bits == 0;
        }

        Ok(context)
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let bytes_read = self.vnode.read(self.position, buffer)?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }

    pub fn write(&mut self, buffer: &[u8]) -> Result<usize> {
        let bytes_written = self.vnode.write(self.position, buffer)?;
        self.position += bytes_written as u64;
        Ok(bytes_written)
    }

    pub fn seek(&mut self, offset: i64, whence: usize) -> Result<u64> {
        let base = match whence {
            SEEK_SET => 0_i128,
            SEEK_CUR => self.position as i128,
            SEEK_END => self.vnode.size() as i128,
            _ => return Err(crate::Error::InvalidArgument),
        };

        let next = base
            .checked_add(offset as i128)
            .ok_or(crate::Error::InvalidArgument)?;
        if next < 0 {
            return Err(crate::Error::InvalidArgument);
        }

        let next = u64::try_from(next).map_err(|_| crate::Error::InvalidArgument)?;
        self.position = next;
        Ok(next)
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    pub fn set_len(&mut self, length: u64) -> Result<u64> {
        self.vnode.set_len(length)?;
        if self.position > length {
            self.position = length;
        }

        Ok(length)
    }

    pub fn sync(&self) -> Result<()> {
        self.vnode.sync()
    }

    pub fn sync_data(&self) -> Result<()> {
        self.vnode.sync_data()
    }

    /// Return the pipe buffer capacity when the underlying node is an
    /// anonymous pipe; `None` otherwise (`fcntl(F_GETPIPE_SZ)`).
    pub fn pipe_capacity(&self) -> Option<usize> {
        self.vnode.pipe_capacity()
    }

    /// Resize the pipe buffer, preserving buffered data
    /// (`fcntl(F_SETPIPE_SZ)`).  Non-pipe nodes return
    /// [`Error::Unsupported`].
    pub fn set_pipe_capacity(&self, capacity: usize) -> Result<()> {
        self.vnode.set_pipe_capacity(capacity)
    }

    /// Set the non-blocking I/O flag on the underlying node
    /// (`fcntl(F_SETFL)` with `O_NONBLOCK`).
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.vnode.set_nonblocking(nonblocking)
    }

    /// Return the non-blocking I/O flag (`fcntl(F_GETFL)`).
    pub fn is_nonblocking(&self) -> bool {
        self.vnode.is_nonblocking()
    }
}
