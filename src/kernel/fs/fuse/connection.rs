//! src/kernel/fs/fuse/connection.rs
//! Per-mount FUSE channel: request/response pipe pair + sequential dispatch.
//!
//! [`FuseConnection`] holds the kernel-end pipe ends and provides
//! [`dispatch`](FuseConnection::dispatch), which serialises a request,
//! writes it to the request pipe, reads the response from the response
//! pipe, and returns the raw payload to the caller.
//!
//! Phase 1 uses **sequential dispatch**: each `dispatch()` call writes
//! the request, then reads the response.  This avoids threading complexity
//! entirely.  Multiple VFS callers contending on the same mount point will
//! naturally serialise on the connection's mutex.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::fuse::error::fuse_error_code_to_kernel;
use crate::kernel::fs::fuse::protocol::{deserialize_header, serialize_header};
use crate::kernel::fs::fuse::{FuseConnection, FuseHeader, FuseOpcode, FuseRequest, FuseResponse};
use crate::kernel::fs::vfs::VNode;
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

impl FuseConnection {
    /// Create a new FUSE connection from the kernel-end pipe VNodes.
    ///
    /// - `req_write`: write-end of the request pipe (kernel → daemon)
    /// - `resp_read`: read-end of the response pipe (daemon → kernel)
    pub fn new(req_write: Arc<dyn VNode>, resp_read: Arc<dyn VNode>) -> Self {
        Self {
            req_write,
            resp_read,
            next_seq: core::sync::atomic::AtomicU64::new(1),
            lock: Mutex::new(()),
        }
    }

    /// Send a request to the daemon and wait for the matching response.
    ///
    /// Phase 1 uses sequential dispatch: the calling thread writes the
    /// request, then blocks reading until the full response arrives.
    /// The connection's mutex is held for the entire exchange, serialising
    /// all concurrent callers.
    ///
    /// The caller must set `request.header.seq` to 0 — this method
    /// assigns the next sequence number automatically.
    ///
    /// Returns the deserialised response on success, or a kernel [`Error`]
    /// if the pipe breaks, the daemon returns an error, or the response is
    /// malformed.
    pub fn dispatch(&self, request: &FuseRequest) -> Result<FuseResponse> {
        let _guard = self.lock.lock();

        // Assign a fresh sequence number.
        let seq = self
            .next_seq
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        // Build the wire buffer: header + payload.
        let request_header = FuseHeader {
            seq,
            ..request.header
        };
        let wire_header = serialize_header(&request_header);
        let wire_buf: Vec<u8> = wire_header
            .iter()
            .copied()
            .chain(request.payload.iter().copied())
            .collect();

        // ── Write request to the request pipe ──
        let mut pos = 0;
        while pos < wire_buf.len() {
            let n = self
                .req_write
                .write(0, &wire_buf[pos..])
                .map_err(|_| Error::DeviceError)?;
            if n == 0 {
                return Err(Error::DeviceError); // write end closed
            }
            pos += n;
        }

        // ── Read response header (24 bytes) ──
        let mut header_buf = [0u8; 24];
        let mut offset = 0;
        while offset < 24 {
            let n = self
                .resp_read
                .read(0, &mut header_buf[offset..])
                .map_err(|_| Error::DeviceError)?;
            if n == 0 {
                return Err(Error::DeviceError); // EOF — daemon died
            }
            offset += n;
        }
        let resp_header = deserialize_header(&header_buf);

        // ── Read response payload ──
        let payload_len = resp_header.payload_len as usize;
        let mut payload = Vec::with_capacity(payload_len);
        if payload_len > 0 {
            payload.resize(payload_len, 0);
            let mut offset = 0;
            while offset < payload_len {
                let n = self
                    .resp_read
                    .read(0, &mut payload[offset..])
                    .map_err(|_| Error::DeviceError)?;
                if n == 0 {
                    return Err(Error::DeviceError); // EOF
                }
                offset += n;
            }
        }

        // Convert ERROR responses.
        if resp_header.opcode == FuseOpcode::Error as u32 {
            if payload.len() >= 4 {
                let code = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                return Err(fuse_error_code_to_kernel(code));
            }
            return Err(Error::DeviceError);
        }

        Ok(FuseResponse {
            header: resp_header,
            payload,
        })
    }
}
