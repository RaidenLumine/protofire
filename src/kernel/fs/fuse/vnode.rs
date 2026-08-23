//! src/kernel/fs/fuse/vnode.rs
//! Per-node wrapper for FUSE-backed files.
//!
//! [`FuseVNode`] implements [`VNode`] by storing a cached inode
//! number, name, kind and size, and delegating read/write to
//! the connection.

use alloc::string::String;
use alloc::sync::Arc;

use crate::kernel::fs::fuse::{FuseConnection, FuseVNode};
use crate::kernel::fs::vfs::{Metadata, VNode};
use crate::kernel::fs::NodeKind;
use crate::Result;

impl FuseVNode {
    /// Create a new FUSE VNode.
    pub fn new(
        name: String,
        ino: u64,
        kind: NodeKind,
        size: u64,
        conn: Arc<FuseConnection>,
    ) -> Self {
        Self {
            name,
            ino,
            kind,
            size: core::sync::atomic::AtomicUsize::new(size as usize),
            conn,
        }
    }

    /// Build a read request payload: offset (8 bytes LE) + size (4 bytes LE).
    fn build_read_payload(offset: u64, size: u32) -> alloc::vec::Vec<u8> {
        let mut payload = alloc::vec::Vec::with_capacity(12);
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&size.to_le_bytes());
        payload
    }

    /// Build a write request payload: offset (8 bytes LE) + data.
    fn build_write_payload(offset: u64, data: &[u8]) -> alloc::vec::Vec<u8> {
        let mut payload = alloc::vec::Vec::with_capacity(8 + data.len());
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(data);
        payload
    }
}

impl VNode for FuseVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        self.size.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        use crate::kernel::fs::fuse::protocol::build_request;
        use crate::kernel::fs::fuse::FuseOpcode;
        let payload = Self::build_read_payload(offset, buffer.len() as u32);
        let resp = self
            .conn
            .dispatch(&build_request(0, FuseOpcode::Read, self.ino, &payload))?;
        let n = resp.payload.len().min(buffer.len());
        buffer[..n].copy_from_slice(&resp.payload[..n]);
        Ok(n)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        use crate::kernel::fs::fuse::protocol::build_request;
        use crate::kernel::fs::fuse::FuseOpcode;
        let payload = Self::build_write_payload(offset, buffer);
        let resp = self
            .conn
            .dispatch(&build_request(0, FuseOpcode::Write, self.ino, &payload))?;
        if resp.payload.len() < 4 {
            return Err(crate::Error::DeviceError);
        }
        let written = u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()) as usize;
        Ok(written)
    }

    fn set_len(&self, length: u64) -> Result<()> {
        use crate::kernel::fs::fuse::protocol::build_request;
        use crate::kernel::fs::fuse::FuseOpcode;
        let payload = length.to_le_bytes().to_vec();
        self.conn
            .dispatch(&build_request(0, FuseOpcode::SetLen, self.ino, &payload))?;
        Ok(())
    }

    fn metadata(&self) -> Result<Metadata> {
        use crate::kernel::fs::fuse::protocol::{
            build_request, kind_from_wire, parse_node_info_payload,
        };
        use crate::kernel::fs::fuse::FuseOpcode;
        let resp = self
            .conn
            .dispatch(&build_request(0, FuseOpcode::Stat, self.ino, &[]))?;
        let (_ino, kind, size, _name) = parse_node_info_payload(&resp.payload)?;
        Ok(Metadata::new(kind_from_wire(kind), size as usize))
    }

    fn sync(&self) -> Result<()> {
        // Forward a FLUSH to the daemon so it can persist any buffered data
        // for this inode (best-effort; the daemon decides what "sync" means).
        use crate::kernel::fs::fuse::protocol::build_request;
        use crate::kernel::fs::fuse::FuseOpcode;
        self.conn
            .dispatch(&build_request(0, FuseOpcode::Flush, self.ino, &[]))?;
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        self.sync()
    }
}
