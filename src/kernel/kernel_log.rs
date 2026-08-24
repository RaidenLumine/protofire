//! src/kernel/kernel_log.rs
//!
//! Kernel log ring buffer with a virtual file at `/system/logs/kernel`.
//!
//! All `println!` / `print!` output and serial debug writes are captured
//! into a fixed-capacity ring buffer.  The buffer is exposed as a read-only
//! virtual file through a lightweight filesystem mounted at `/system/logs`.

use alloc::string::String;
use alloc::sync::Arc;

use crate::kernel::fs::vfs::{FileSystem, NodeKind, VNode};
use crate::kernel::fs::DirectoryEntry;
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

// ─── Ring buffer ───

const RING_CAPACITY: usize = 65536; // 64 KB

struct RingInner {
    buf: [u8; RING_CAPACITY],
    /// Next write index.  When the buffer is full this points to the oldest byte.
    write_pos: usize,
    /// Current number of valid bytes (0 … RING_CAPACITY).
    len: usize,
}

impl RingInner {
    const fn new() -> Self {
        Self {
            buf: [0; RING_CAPACITY],
            write_pos: 0,
            len: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.buf[self.write_pos] = b;
            self.write_pos = (self.write_pos + 1) % RING_CAPACITY;
            if self.len < RING_CAPACITY {
                self.len += 1;
            }
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn read_byte(&self, offset: usize) -> Option<u8> {
        if offset >= self.len {
            return None;
        }
        let idx = if self.len < RING_CAPACITY {
            // Buffer hasn't wrapped — data starts at index 0.
            offset
        } else {
            // Buffer is full — oldest byte is at write_pos.
            (self.write_pos + offset) % RING_CAPACITY
        };
        Some(self.buf[idx])
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> usize {
        let mut count = 0;
        for (i, slot) in buffer.iter_mut().enumerate() {
            let byte_offset = offset as usize + i;
            match self.read_byte(byte_offset) {
                Some(b) => {
                    *slot = b;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}

/// Global kernel log ring buffer.
pub struct KernelLogRing {
    inner: Mutex<RingInner>,
}

impl Default for KernelLogRing {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelLogRing {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(RingInner::new()),
        }
    }

    /// Append raw bytes to the ring buffer.
    pub fn append(&self, bytes: &[u8]) {
        self.inner.lock().append(bytes);
    }

    /// Return the current number of bytes in the buffer.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Return true when the buffer contains no data.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read bytes from the buffer starting at `offset`.
    /// Returns the number of bytes copied into `buffer`.
    pub fn read(&self, offset: u64, buffer: &mut [u8]) -> usize {
        self.inner.lock().read(offset, buffer)
    }
}

// Safety: the ring buffer is self-contained and only accessed under the Mutex.
unsafe impl Send for KernelLogRing {}
unsafe impl Sync for KernelLogRing {}

static KLOG: KernelLogRing = KernelLogRing::new();

/// Append bytes to the global kernel log (called from the print path).
pub fn append_bytes(bytes: &[u8]) {
    KLOG.append(bytes);
}

/// Read from the global kernel log (called by the VNode).
pub fn read_bytes(offset: u64, buffer: &mut [u8]) -> usize {
    KLOG.read(offset, buffer)
}

/// Current size of the kernel log.
pub fn log_len() -> usize {
    KLOG.len()
}

// ─── Virtual file node ───

/// A VNode that represents either the `/system/logs` root directory or the
/// `kernel` file within it.
enum LogNode {
    Root,
    Kernel,
}

impl VNode for LogNode {
    fn name(&self) -> &str {
        match self {
            LogNode::Root => "",
            LogNode::Kernel => "kernel",
        }
    }

    fn kind(&self) -> NodeKind {
        match self {
            LogNode::Root => NodeKind::Directory,
            LogNode::Kernel => NodeKind::File,
        }
    }

    fn size(&self) -> usize {
        match self {
            LogNode::Root => 1, // one child: "kernel"
            LogNode::Kernel => log_len(),
        }
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        match self {
            LogNode::Root => Err(Error::InvalidArgument),
            LogNode::Kernel => Ok(read_bytes(offset, buffer)),
        }
    }
}

// ─── Lightweight filesystem ───

/// A read-only virtual filesystem that hosts a single `kernel` log file.
pub struct KernelLogFileSystem;

impl FileSystem for KernelLogFileSystem {
    fn name(&self) -> &str {
        "kernel-logs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        match path {
            "/" => Ok(Arc::new(LogNode::Root)),
            "/kernel" => Ok(Arc::new(LogNode::Kernel)),
            _ => Err(Error::NotFound),
        }
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        if path != "/" {
            return Err(Error::NotFound);
        }
        if index == 0 {
            Ok(DirectoryEntry::new(
                NodeKind::File,
                log_len(),
                String::from("kernel"),
            ))
        } else {
            Err(Error::NotFound)
        }
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

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }
}

// ─── tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_append_and_read() {
        let ring = KernelLogRing::new();
        ring.append(b"hello");
        ring.append(b" world");
        assert_eq!(ring.len(), 11);

        let mut buf = [0u8; 32];
        let n = ring.read(0, &mut buf);
        assert_eq!(&buf[..n], b"hello world");
    }

    #[test]
    fn ring_buffer_read_with_offset() {
        let ring = KernelLogRing::new();
        ring.append(b"abcdefghij");

        let mut buf = [0u8; 5];
        let n = ring.read(3, &mut buf);
        assert_eq!(&buf[..n], b"defgh");
    }

    #[test]
    fn ring_buffer_read_past_end() {
        let ring = KernelLogRing::new();
        ring.append(b"abc");

        let mut buf = [0u8; 16];
        let n = ring.read(5, &mut buf);
        assert_eq!(n, 0);
    }

    #[test]
    fn ring_buffer_wraps_correctly() {
        // Use a small capacity by filling the buffer many times.
        let ring = KernelLogRing::new();
        // Write enough data to wrap the 64 KB buffer at least once.
        let pattern = b"0123456789";
        let total = RING_CAPACITY + 128;
        let mut written = 0;
        while written < total {
            ring.append(pattern);
            written += pattern.len();
        }

        // The buffer should be full (RING_CAPACITY bytes).
        assert_eq!(ring.len(), RING_CAPACITY);

        // Reading should return RING_CAPACITY bytes of contiguous data.
        let mut buf = [0u8; 128];
        let n = ring.read(0, &mut buf);
        assert!(n > 0, "should have read some data");

        // The data should be recent (just the last RING_CAPACITY bytes).
        // Verify we can read the whole buffer without gaps.
        let mut total_read = 0;
        let mut offset = 0u64;
        let mut chunk = [0u8; 1024];
        loop {
            let n = ring.read(offset, &mut chunk);
            if n == 0 {
                break;
            }
            total_read += n;
            offset += n as u64;
        }
        assert_eq!(total_read, RING_CAPACITY);
    }

    #[test]
    fn log_node_root_is_directory() {
        let root = LogNode::Root;
        assert_eq!(root.kind(), NodeKind::Directory);
        assert!(root.read(0, &mut [0; 16]).is_err());
    }

    #[test]
    fn log_node_kernel_is_file() {
        let kernel = LogNode::Kernel;
        assert_eq!(kernel.kind(), NodeKind::File);
    }

    #[test]
    fn log_filesystem_lookup_root() {
        let fs = KernelLogFileSystem;
        let node = fs.lookup("/").expect("root should exist");
        assert_eq!(node.kind(), NodeKind::Directory);
    }

    #[test]
    fn log_filesystem_lookup_kernel() {
        let fs = KernelLogFileSystem;
        let node = fs.lookup("/kernel").expect("kernel should exist");
        assert_eq!(node.kind(), NodeKind::File);
    }

    #[test]
    fn log_filesystem_lookup_unknown() {
        let fs = KernelLogFileSystem;
        assert!(fs.lookup("/bogus").is_err());
    }

    #[test]
    fn log_filesystem_read_dir() {
        let fs = KernelLogFileSystem;
        let entry = fs.read_dir("/", 0).expect("first entry should exist");
        assert_eq!(entry.name, "kernel");
        assert_eq!(entry.kind, NodeKind::File);
        assert!(fs.read_dir("/", 1).is_err());
    }

    #[test]
    fn log_filesystem_denies_mutations() {
        let fs = KernelLogFileSystem;
        assert!(fs.create_file("/new").is_err());
        assert!(fs.create_dir("/new-dir").is_err());
        assert!(fs.remove_path("/kernel").is_err());
        assert!(fs.rename("/kernel", "/foo").is_err());
    }
}
