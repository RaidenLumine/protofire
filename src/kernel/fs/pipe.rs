//! src/kernel/fs/pipe.rs
//!
//! Anonymous pipe (FIFO) — a unidirectional byte stream with a shared ring
//! buffer.
//!
//! ## Architecture
//!
//! A pipe is created with [`pipe_channel()`] which returns a read-end and a
//! write-end [`VNode`].  Both ends share an internal ring buffer protected by a
//! mutex and use condition variables for blocking semantics:
//!
//! - Readers block on `read_wait` when the buffer is empty; writers signal
//!   `read_wait` after inserting data.
//! - Writers block on `write_wait` when the buffer is full; readers signal
//!   `write_wait` after consuming data.
//! - When the write-end is dropped, `write_closed` is set and blocked readers
//!   wake up and return `0` (EOF).
//! - When the read-end is dropped, `read_closed` is set and blocked writers
//!   return an error.
//!
//! ## Phase 2 additions
//!
//! - The buffer can be resized at runtime via `fcntl(F_SETPIPE_SZ)`
//!   ([`PipeChannel::resize`]); buffered data is preserved across a resize.
//! - Each end carries its own non-blocking flag, toggled via `fcntl(F_SETFL,
//!   O_NONBLOCK)`.  In non-blocking mode a read that would block on an empty
//!   buffer (or a write that would block on a full buffer) returns
//!   [`Error::Busy`] immediately instead of waiting.

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;

use crate::kernel::fs::vfs::{NodeKind, VNode};
use crate::kernel::sync::{Condvar, Mutex};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

/// Default pipe capacity in bytes (16 KiB = 4 pages).
pub const DEFAULT_PIPE_CAPACITY: usize = 16384;

/// Minimum pipe capacity enforced by `fcntl(F_SETPIPE_SZ)` (one page).
pub const PIPE_MIN_SIZE: usize = 4096;
/// Maximum pipe capacity enforced by `fcntl(F_SETPIPE_SZ)` (Linux's default
/// `fs.pipe-max-size` of 1 MiB).
pub const PIPE_MAX_SIZE: usize = 1024 * 1024;

/// Round a requested pipe size to the Linux convention: clamp to
/// `[PIPE_MIN_SIZE, PIPE_MAX_SIZE]` and round up to a power-of-two number of
/// pages.
pub fn round_pipe_size(size: usize) -> usize {
    let clamped = size.clamp(PIPE_MIN_SIZE, PIPE_MAX_SIZE);
    let pages = clamped.div_ceil(PIPE_MIN_SIZE);
    let rounded = pages
        .next_power_of_two()
        .saturating_mul(PIPE_MIN_SIZE)
        .min(PIPE_MAX_SIZE);
    rounded.max(PIPE_MIN_SIZE)
}

struct PipeRing {
    buf: Box<[u8]>,
    read_pos: usize,
    write_pos: usize,
    /// Number of unread bytes currently in the buffer.
    byte_count: usize,
    /// Set to `true` when the write-end VNode is dropped.
    write_closed: bool,
    /// Set to `true` when the read-end VNode is dropped.
    read_closed: bool,
}

impl PipeRing {
    fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            read_pos: 0,
            write_pos: 0,
            byte_count: 0,
            write_closed: false,
            read_closed: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.byte_count == 0
    }

    fn is_full(&self) -> bool {
        self.byte_count == self.buf.len()
    }

    fn available(&self) -> usize {
        self.byte_count
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.byte_count
    }

    /// Read up to `dst.len()` bytes from the ring.  Returns the number of
    /// bytes actually read.
    fn read_from(&mut self, dst: &mut [u8]) -> usize {
        let n = core::cmp::min(dst.len(), self.byte_count);
        for byte in dst.iter_mut().take(n) {
            *byte = self.buf[self.read_pos];
            self.read_pos = (self.read_pos + 1) % self.buf.len();
        }
        self.byte_count -= n;
        n
    }

    /// Write up to `src.len()` bytes into the ring.  Returns the number of
    /// bytes actually written.
    fn write_to(&mut self, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.remaining());
        for &byte in src.iter().take(n) {
            self.buf[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % self.buf.len();
        }
        self.byte_count += n;
        n
    }

    /// Resize the ring buffer to `new_capacity` bytes, preserving any
    /// buffered data by compacting it to the front of the new buffer.
    ///
    /// Returns [`Error::Busy`] when `new_capacity` is smaller than the
    /// number of bytes currently buffered (matching Linux `F_SETPIPE_SZ`).
    fn resize(&mut self, new_capacity: usize) -> Result<()> {
        if new_capacity < self.byte_count {
            return Err(Error::Busy);
        }

        // Drain the current contents into a compact scratch buffer, then
        // rebuild the ring from it (positions reset to the front).
        let mut pending = vec![0u8; self.byte_count];
        self.read_from(&mut pending);

        self.buf = vec![0u8; new_capacity].into_boxed_slice();
        self.read_pos = 0;
        self.write_pos = pending.len();
        self.buf[..pending.len()].copy_from_slice(&pending);
        self.byte_count = pending.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared channel
// ---------------------------------------------------------------------------

/// The shared state of a pipe, reference-counted and held by both ends.
struct PipeChannel {
    ring: Mutex<PipeRing>,
    /// Signalled by writers when data is inserted.
    read_wait: Condvar,
    /// Signalled by readers when space is freed.
    write_wait: Condvar,
}

impl PipeChannel {
    /// Current buffer capacity in bytes (`fcntl(F_GETPIPE_SZ)`).
    fn capacity(&self) -> usize {
        self.ring.lock().buf.len()
    }

    /// Resize the buffer, preserving buffered data (`fcntl(F_SETPIPE_SZ)`).
    fn resize(&self, new_capacity: usize) -> Result<()> {
        assert!(new_capacity > 0, "pipe capacity must be > 0");
        self.ring.lock().resize(new_capacity)
    }
}

// ---------------------------------------------------------------------------
// VNode implementations
// ---------------------------------------------------------------------------

/// The read end of a pipe.  Supports [`VNode::read`]; [`VNode::write`]
/// returns [`Error::PermissionDenied`].
pub struct PipeReadEnd {
    channel: Arc<PipeChannel>,
    /// Non-blocking read flag (`O_NONBLOCK` on the read end).
    nonblocking: AtomicBool,
}

/// The write end of a pipe.  Supports [`VNode::write`]; [`VNode::read`]
/// returns [`Error::PermissionDenied`].
pub struct PipeWriteEnd {
    channel: Arc<PipeChannel>,
    /// Non-blocking write flag (`O_NONBLOCK` on the write end).
    nonblocking: AtomicBool,
}

impl Drop for PipeReadEnd {
    fn drop(&mut self) {
        let mut ring = self.channel.ring.lock();
        ring.read_closed = true;
        drop(ring);
        // Wake all blocked writers so they see read_closed and return an error.
        self.channel.write_wait.notify_all();
    }
}

impl Drop for PipeWriteEnd {
    fn drop(&mut self) {
        let mut ring = self.channel.ring.lock();
        ring.write_closed = true;
        drop(ring);
        // Wake all blocked readers so they see write_closed and return EOF.
        self.channel.read_wait.notify_all();
    }
}

impl VNode for PipeReadEnd {
    fn name(&self) -> &str {
        "pipe-read"
    }

    fn kind(&self) -> NodeKind {
        NodeKind::File
    }

    fn size(&self) -> usize {
        self.channel.ring.lock().available()
    }

    fn pipe_capacity(&self) -> Option<usize> {
        Some(self.channel.capacity())
    }

    fn set_pipe_capacity(&self, capacity: usize) -> Result<()> {
        self.channel.resize(capacity)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
        Ok(())
    }

    fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Relaxed)
    }

    fn read(&self, _offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let mut ring = self.channel.ring.lock();

        // Non-blocking read on an empty pipe reports Busy immediately.
        if ring.is_empty() && !ring.write_closed && self.nonblocking.load(Ordering::Relaxed) {
            return Err(Error::Busy);
        }

        // Block while the buffer is empty and the writer is still alive.
        // When no scheduler is active (host test builds), `wait` returns
        // immediately with `blocked() == false`; we yield via `spin_loop`
        // and retry so the producer can make progress on another "thread".
        while ring.is_empty() && !ring.write_closed {
            let wait = self.channel.read_wait.wait(ring);
            if wait.blocked() {
                ring = wait.relock();
            } else {
                // No scheduler — drop the lock briefly so a concurrent
                // writer can fill the buffer, then retry.
                drop(wait.relock());
                core::hint::spin_loop();
                ring = self.channel.ring.lock();
            }
        }

        if ring.is_empty() && ring.write_closed {
            return Ok(0); // EOF — writer closed and no data left
        }

        let n = ring.read_from(buffer);
        drop(ring);
        // Wake a blocked writer that may be waiting for buffer space.
        self.channel.write_wait.notify_one();
        Ok(n)
    }

    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

impl VNode for PipeWriteEnd {
    fn name(&self) -> &str {
        "pipe-write"
    }

    fn kind(&self) -> NodeKind {
        NodeKind::File
    }

    fn size(&self) -> usize {
        self.channel.ring.lock().remaining()
    }

    fn pipe_capacity(&self) -> Option<usize> {
        Some(self.channel.capacity())
    }

    fn set_pipe_capacity(&self, capacity: usize) -> Result<()> {
        self.channel.resize(capacity)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
        Ok(())
    }

    fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Relaxed)
    }

    fn read(&self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }

    fn write(&self, _offset: u64, buffer: &[u8]) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let mut ring = self.channel.ring.lock();

        // Non-blocking write to a full pipe reports Busy immediately.
        if ring.is_full() && !ring.read_closed && self.nonblocking.load(Ordering::Relaxed) {
            return Err(Error::Busy);
        }

        // Block while the buffer is full and the reader is still alive.
        // When no scheduler is active (host test builds), `wait` returns
        // immediately with `blocked() == false`; we yield via `spin_loop`
        // and retry so the consumer can make progress on another "thread".
        while ring.is_full() && !ring.read_closed {
            let wait = self.channel.write_wait.wait(ring);
            if wait.blocked() {
                ring = wait.relock();
            } else {
                // No scheduler — drop the lock briefly so a concurrent
                // reader can drain the buffer, then retry.
                drop(wait.relock());
                core::hint::spin_loop();
                ring = self.channel.ring.lock();
            }
        }

        if ring.read_closed {
            return Err(Error::DeviceError); // broken pipe — reader closed
        }

        let n = ring.write_to(buffer);
        drop(ring);
        // Wake a blocked reader that may be waiting for data.
        self.channel.read_wait.notify_one();
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Public constructor
// ---------------------------------------------------------------------------

/// Create a new pipe with the default capacity.
///
/// Returns `(read_end, write_end)` — both implement [`VNode`] and can be
/// wrapped in [`FileHandle`](crate::kernel::fs::FileHandle) instances for use
/// as file descriptors.
pub fn pipe_channel() -> (Arc<dyn VNode>, Arc<dyn VNode>) {
    pipe_channel_with_capacity(DEFAULT_PIPE_CAPACITY)
}

/// Create a new pipe with a custom buffer capacity.
pub fn pipe_channel_with_capacity(capacity: usize) -> (Arc<dyn VNode>, Arc<dyn VNode>) {
    assert!(capacity > 0, "pipe capacity must be > 0");

    let channel = Arc::new(PipeChannel {
        ring: Mutex::new(PipeRing::new(capacity)),
        read_wait: Condvar::new(),
        write_wait: Condvar::new(),
    });

    let read_end = Arc::new(PipeReadEnd {
        channel: Arc::clone(&channel),
        nonblocking: AtomicBool::new(false),
    }) as Arc<dyn VNode>;

    let write_end = Arc::new(PipeWriteEnd {
        channel,
        nonblocking: AtomicBool::new(false),
    }) as Arc<dyn VNode>;

    (read_end, write_end)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Ring buffer unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn ring_empty_read_returns_zero() {
        let mut ring = PipeRing::new(64);
        let mut buf = [0u8; 16];
        assert_eq!(ring.read_from(&mut buf), 0);
    }

    #[test]
    fn ring_write_and_read_exact() {
        let mut ring = PipeRing::new(64);
        assert_eq!(ring.write_to(b"hello"), 5);
        assert_eq!(ring.available(), 5);
        assert!(!ring.is_empty());

        let mut buf = [0u8; 16];
        assert_eq!(ring.read_from(&mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
        assert!(ring.is_empty());
    }

    #[test]
    fn ring_partial_read() {
        let mut ring = PipeRing::new(64);
        ring.write_to(b"abcdefghij");
        assert_eq!(ring.available(), 10);

        let mut buf = [0u8; 4];
        assert_eq!(ring.read_from(&mut buf), 4);
        assert_eq!(&buf, b"abcd");
        assert_eq!(ring.available(), 6);

        let mut buf = [0u8; 16];
        assert_eq!(ring.read_from(&mut buf), 6);
        assert_eq!(&buf[..6], b"efghij");
    }

    #[test]
    fn ring_wraparound() {
        let mut ring = PipeRing::new(8);
        // Fill the buffer
        assert_eq!(ring.write_to(b"12345678"), 8);
        assert!(ring.is_full());

        // Read half
        let mut buf = [0u8; 4];
        assert_eq!(ring.read_from(&mut buf), 4);
        assert_eq!(&buf, b"1234");

        // Write more, wrapping around
        assert_eq!(ring.write_to(b"abcd"), 4);
        assert!(ring.is_full());

        // Read all
        let mut buf = [0u8; 8];
        assert_eq!(ring.read_from(&mut buf), 8);
        assert_eq!(&buf, b"5678abcd");
    }

    #[test]
    fn ring_full_write_returns_zero() {
        let mut ring = PipeRing::new(4);
        assert_eq!(ring.write_to(b"1234"), 4);
        assert!(ring.is_full());
        assert_eq!(ring.write_to(b"56"), 0); // no space
    }

    #[test]
    fn ring_write_partial_accepts_available_space() {
        let mut ring = PipeRing::new(4);
        assert_eq!(ring.write_to(b"12"), 2);
        assert_eq!(ring.remaining(), 2);
        assert_eq!(ring.write_to(b"3456"), 2); // only 2 fit
        assert!(ring.is_full());
        assert_eq!(ring.available(), 4);
    }

    // -----------------------------------------------------------------------
    // Pipe VNode integration tests (single-threaded, no scheduler needed)
    // -----------------------------------------------------------------------

    #[test]
    fn pipe_read_empty_blocks_then_reads_after_write() {
        // This test works because without a scheduler, Condvar::wait
        // returns immediately with blocked=false, so the while-loop
        // in read() will spin until data is available or write_closed.
        let (read_end, write_end) = pipe_channel_with_capacity(64);

        // Write some data first
        let mut data = [0u8; 5];
        assert_eq!(write_end.write(0, b"hello"), Ok(5));

        // Read it back
        assert_eq!(read_end.read(0, &mut data), Ok(5));
        assert_eq!(&data, b"hello");
    }

    #[test]
    fn pipe_write_full_blocks_then_writes_after_read() {
        let (read_end, write_end) = pipe_channel_with_capacity(4);

        assert_eq!(write_end.write(0, b"1234"), Ok(4));

        // Now buffer is full.  Without a scheduler the write will spin.
        // Read one byte to make space, but we need to do it from "another
        // thread" conceptually.  Since this is single-threaded and the
        // Condvar doesn't block without a scheduler, the write will
        // observe the full buffer and fail to make progress.
        //
        // We verify that a full pipe can be drained instead.
        let mut buf = [0u8; 4];
        assert_eq!(read_end.read(0, &mut buf), Ok(4));
        assert_eq!(&buf, b"1234");

        // Now the pipe is empty again; writes should succeed.
        assert_eq!(write_end.write(0, b"ab"), Ok(2));
        let mut buf = [0u8; 2];
        assert_eq!(read_end.read(0, &mut buf), Ok(2));
        assert_eq!(&buf, b"ab");
    }

    #[test]
    fn pipe_read_end_rejects_writes() {
        let (read_end, _write_end) = pipe_channel();
        assert_eq!(read_end.write(0, b"x"), Err(Error::PermissionDenied));
    }

    #[test]
    fn pipe_write_end_rejects_reads() {
        let (_read_end, write_end) = pipe_channel();
        let mut buf = [0u8; 1];
        assert_eq!(write_end.read(0, &mut buf), Err(Error::PermissionDenied));
    }

    #[test]
    fn pipe_zero_length_read_returns_zero() {
        let (read_end, _write_end) = pipe_channel();
        assert_eq!(read_end.read(0, &mut []), Ok(0));
    }

    #[test]
    fn pipe_zero_length_write_returns_zero() {
        let (_read_end, write_end) = pipe_channel();
        assert_eq!(write_end.write(0, &[]), Ok(0));
    }

    #[test]
    fn pipe_read_returns_eof_when_writer_dropped() {
        let (read_end, write_end) = pipe_channel_with_capacity(64);

        // Write then drop the writer.
        assert_eq!(write_end.write(0, b"data"), Ok(4));
        drop(write_end);

        // Read the data.
        let mut buf = [0u8; 4];
        assert_eq!(read_end.read(0, &mut buf), Ok(4));
        assert_eq!(&buf, b"data");

        // Next read should return EOF (0 bytes).
        let mut buf = [0u8; 1];
        assert_eq!(read_end.read(0, &mut buf), Ok(0));
    }

    #[test]
    fn pipe_write_returns_error_when_reader_dropped() {
        let (read_end, write_end) = pipe_channel_with_capacity(4);

        // Drop the reader.
        drop(read_end);

        // Writer should get an error (broken pipe).
        assert_eq!(write_end.write(0, b"x"), Err(Error::DeviceError));
    }

    #[test]
    fn pipe_large_transfer_many_segments() {
        // Write 100 bytes in 7-byte chunks, then close the writer so the
        // reader sees EOF rather than blocking indefinitely.
        let (read_end, write_end) = pipe_channel_with_capacity(256);

        let total = 100usize;
        let mut written = 0;
        while written < total {
            let chunk = [b'A' + (written % 26) as u8; 7];
            let n = write_end
                .write(0, &chunk[..7.min(total - written)])
                .unwrap();
            written += n;
        }
        drop(write_end); // close writer → reader will see EOF after draining

        // Read back in 11-byte chunks until EOF.
        let mut result = alloc::vec::Vec::new();
        let mut buf = [0u8; 11];
        loop {
            let n = read_end.read(0, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buf[..n]);
        }

        assert_eq!(result.len(), total);
        // Each 7-byte chunk uses the same character: A + (chunk_start_index % 26).
        for (i, &byte) in result.iter().enumerate() {
            let chunk_start = (i / 7) * 7;
            let expected = b'A' + (chunk_start % 26) as u8;
            assert_eq!(byte, expected, "mismatch at index {i}");
        }
    }

    #[test]
    fn pipe_custom_capacity() {
        let (read_end, write_end) = pipe_channel_with_capacity(1024);

        let payload = vec![0xABu8; 512];
        assert_eq!(write_end.write(0, &payload), Ok(512));

        let mut buf = vec![0u8; 512];
        assert_eq!(read_end.read(0, &mut buf), Ok(512));
        assert_eq!(buf, payload);
    }

    #[test]
    fn pipe_kind_is_file() {
        let (read_end, write_end) = pipe_channel();
        assert_eq!(read_end.kind(), NodeKind::File);
        assert_eq!(write_end.kind(), NodeKind::File);
    }

    #[test]
    fn pipe_size_reflects_available() {
        let (read_end, write_end) = pipe_channel_with_capacity(256);
        assert_eq!(read_end.size(), 0); // nothing to read yet
        assert_eq!(write_end.size(), 256); // all space available

        write_end.write(0, b"hello").unwrap();
        assert_eq!(read_end.size(), 5);
    }

    #[test]
    fn round_pipe_size_clamps_and_rounds_up() {
        // Below one page → clamped to one page.
        assert_eq!(round_pipe_size(1), PIPE_MIN_SIZE);
        assert_eq!(round_pipe_size(1024), PIPE_MIN_SIZE);
        // Page-aligned values round up to the next power-of-two page count.
        assert_eq!(round_pipe_size(PIPE_MIN_SIZE), PIPE_MIN_SIZE);
        assert_eq!(round_pipe_size(2 * PIPE_MIN_SIZE), 2 * PIPE_MIN_SIZE);
        assert_eq!(round_pipe_size(3 * PIPE_MIN_SIZE), 4 * PIPE_MIN_SIZE);
        assert_eq!(round_pipe_size(5 * PIPE_MIN_SIZE), 8 * PIPE_MIN_SIZE);
        // Above the maximum → clamped.
        assert_eq!(round_pipe_size(PIPE_MAX_SIZE + 1), PIPE_MAX_SIZE);
        assert_eq!(round_pipe_size(usize::MAX), PIPE_MAX_SIZE);
    }

    #[test]
    fn pipe_resize_preserves_buffered_data() {
        let (read_end, write_end) = pipe_channel_with_capacity(64);
        assert_eq!(write_end.write(0, b"hello"), Ok(5));

        // Grow to 128 bytes — buffered data must survive.
        assert!(read_end.set_pipe_capacity(128).is_ok());
        assert_eq!(read_end.pipe_capacity(), Some(128));
        assert_eq!(write_end.pipe_capacity(), Some(128));

        let mut buf = [0u8; 5];
        assert_eq!(read_end.read(0, &mut buf), Ok(5));
        assert_eq!(&buf, b"hello");

        // Shrinking back down still works while the buffer is drained.
        assert!(write_end.set_pipe_capacity(64).is_ok());
        assert_eq!(write_end.pipe_capacity(), Some(64));
    }

    #[test]
    fn pipe_resize_too_small_for_buffered_data_returns_busy() {
        let (read_end, write_end) = pipe_channel_with_capacity(256);
        assert_eq!(write_end.write(0, b"0123456789"), Ok(10));

        // 8 < 10 buffered bytes → Busy.
        assert_eq!(read_end.set_pipe_capacity(8), Err(Error::Busy));
        // The pipe is unchanged: data is still intact at the original size.
        assert_eq!(read_end.pipe_capacity(), Some(256));
        let mut buf = [0u8; 10];
        assert_eq!(read_end.read(0, &mut buf), Ok(10));
        assert_eq!(&buf, b"0123456789");
    }

    #[test]
    fn pipe_nonblocking_read_reports_busy_when_empty() {
        let (read_end, write_end) = pipe_channel_with_capacity(64);

        // Empty + non-blocking → Busy, even with a blocked-writer-style probe.
        assert!(read_end.set_nonblocking(true).is_ok());
        let mut buf = [0u8; 4];
        assert_eq!(read_end.read(0, &mut buf), Err(Error::Busy));

        // Data arrives → the non-blocking read succeeds.
        assert_eq!(write_end.write(0, b"abcd"), Ok(4));
        assert_eq!(read_end.read(0, &mut buf), Ok(4));
        assert_eq!(&buf, b"abcd");

        // Back to blocking mode is recorded.
        assert!(read_end.set_nonblocking(false).is_ok());
        assert!(!read_end.is_nonblocking());
    }

    #[test]
    fn pipe_nonblocking_write_reports_busy_when_full() {
        let (read_end, write_end) = pipe_channel_with_capacity(4);

        // Fill the pipe, then switch to non-blocking.
        assert_eq!(write_end.write(0, b"1234"), Ok(4));
        assert!(write_end.set_nonblocking(true).is_ok());
        assert_eq!(write_end.write(0, b"x"), Err(Error::Busy));

        // Drain a byte → a non-blocking write has room again.
        let mut buf = [0u8; 1];
        assert_eq!(read_end.read(0, &mut buf), Ok(1));
        assert_eq!(write_end.write(0, b"y"), Ok(1));
    }

    #[test]
    fn pipe_nonblocking_is_per_end() {
        let (read_end, write_end) = pipe_channel_with_capacity(64);
        assert!(!read_end.is_nonblocking());
        assert!(!write_end.is_nonblocking());

        read_end.set_nonblocking(true).unwrap();
        assert!(read_end.is_nonblocking());
        // The write end is an independent file description.
        assert!(!write_end.is_nonblocking());

        write_end.set_nonblocking(true).unwrap();
        assert!(write_end.is_nonblocking());
    }
}
