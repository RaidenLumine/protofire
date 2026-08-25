//! src/kernel/audit/buffer.rs
//!
//! Kernel audit ring-buffer primitives.
//! Lock-free ring buffer of fixed-size `AuditRecord` entries.
//!
//! The buffer is backed by a heap-allocated array of 8192 records
//! (8192 × 256 = 2 MiB).  A producer claims a slot by advancing `head`
//! with a CAS, writes the record, then publishes it by advancing
//! `published` with a Release store; consumers only read records below
//! `published` and advance `tail` with `AcqRel` semantics.  Overwrite is
//! silently rejected when the buffer is full (returns `false`).

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::kernel::audit::types::AuditRecord;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Default number of entries in the audit ring buffer.
pub const AUDIT_BUFFER_CAPACITY: usize = 8192;

/// Lock-free ring buffer of fixed-size audit records.
pub struct AuditBuffer {
    /// Heap-allocated storage.
    entries: Box<[UnsafeCell<MaybeUninit<AuditRecord>>]>,
    /// Producer index (logical write position, monotonically increasing).
    head: AtomicU64,
    /// Consumer-visible publish index: records with a logical index strictly
    /// below this value have been fully written by a producer.
    published: AtomicU64,
    /// Consumer index (logical read position, monotonically increasing).
    tail: AtomicU64,
    /// Monotonically increasing sequence counter assigned to each record.
    sequence: AtomicU64,
    capacity: u64,
}

// SAFETY: the buffer is Sync because all data races are mediated through
// the atomic head/published/tail indices.  Each producer writes a slot it
// claimed exclusively via the head CAS, and only publishes it (advancing
// `published` with a Release store) after the write completes; consumers
// only read slots strictly below `published` after an Acquire load, and
// advance `tail` (Release) before the producer wraps around to reuse a slot.
unsafe impl Sync for AuditBuffer {}

impl AuditBuffer {
    /// Allocate a new ring buffer with the default capacity (8192).
    pub fn new() -> Self {
        Self::with_capacity(AUDIT_BUFFER_CAPACITY)
    }

    /// Allocate a new ring buffer with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let mut entries = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            entries.push(UnsafeCell::new(MaybeUninit::uninit()));
        }
        Self {
            entries: entries.into_boxed_slice(),
            head: AtomicU64::new(0),
            published: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            sequence: AtomicU64::new(1),
            capacity: capacity as u64,
        }
    }

    /// Try to emit a record.  Returns `false` if the buffer is full.
    ///
    /// Thread-safe: uses a CAS loop so that concurrent producers each claim
    /// a unique slot.  The record is written only after its producer has won
    /// the CAS claim, and it is published (via the `published` counter) only
    /// after the write completes.  Consumers Acquire-load `published` and
    /// only read slots strictly below it (modulo capacity), so they never
    /// observe a slot that is not fully written.
    pub fn emit(&self, mut record: AuditRecord) -> bool {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        record.id = seq;
        record.sequence = seq;

        loop {
            let head = self.head.load(Ordering::Relaxed);
            let tail = self.tail.load(Ordering::Acquire);

            if head - tail >= self.capacity {
                return false; // buffer full
            }

            // Try to atomically claim this slot.  Only one producer
            // succeeds per CAS — others retry with a fresh head.  The
            // Acquire ordering keeps the slot write below from being
            // hoisted above the claim.
            if self
                .head
                .compare_exchange_weak(head, head + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let idx = (head % self.capacity) as usize;
                // SAFETY: `idx` is in bounds (head < tail + capacity), and
                // no consumer touches this slot because consumers only read
                // slots whose logical index is strictly below `published`.
                unsafe {
                    let slot = &mut *self.entries[idx].get();
                    slot.as_mut_ptr().write(record);
                }

                // Publish the record in claim order: wait until every slot
                // claimed before ours has been published, then make our slot
                // visible with a Release store.  The chain always progresses
                // because each claim is unique and every producer eventually
                // publishes its own slot.
                while self.published.load(Ordering::Acquire) != head {
                    core::hint::spin_loop();
                }
                self.published.store(head + 1, Ordering::Release);
                return true;
            }
        }
    }

    /// Copy up to `max` records into `buf`.  Returns the number of records
    /// actually copied.  Data is read from the oldest unread record forward.
    ///
    /// `buf` must be large enough to hold `max * size_of::<AuditRecord>()`
    /// bytes.
    pub fn read_events(&self, buf: &mut [AuditRecord]) -> usize {
        let published = self.published.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);

        let available = (published - tail) as usize;
        let to_copy = available.min(buf.len());

        #[allow(clippy::needless_range_loop)]
        for i in 0..to_copy {
            let idx = ((tail + i as u64) % self.capacity) as usize;
            // SAFETY: the slot at `idx` has been written and published by the
            // producer and not yet overwritten (tail + i < published).
            unsafe {
                let slot = &*self.entries[idx].get();
                buf[i] = *slot.as_ptr();
            }
        }

        if to_copy > 0 {
            self.tail.store(tail + to_copy as u64, Ordering::Release);
        }

        to_copy
    }

    /// Return the number of records currently in the buffer.
    pub fn len(&self) -> u64 {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.saturating_sub(tail)
    }

    /// Return `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the capacity (max number of entries).
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
}

impl Default for AuditBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::audit::types::AuditEventType;

    fn sample_record(data: &[u8]) -> AuditRecord {
        let mut rec = AuditRecord::zeroed();
        rec.fill(0, 0, 42, AuditEventType::Syscall, 7, 1000, 0, data);
        rec
    }

    #[test]
    fn emit_and_read_round_trip() {
        let buf = AuditBuffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);

        let rec = sample_record(b"hello");
        assert!(buf.emit(rec));
        assert_eq!(buf.len(), 1);

        let mut out = [AuditRecord::zeroed(); 10];
        let n = buf.read_events(&mut out);
        assert_eq!(n, 1);
        let data_slice = &out[0].data[..out[0].data_len as usize];
        assert_eq!(data_slice, b"hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn emit_rejects_full_buffer() {
        let buf = AuditBuffer::with_capacity(4);
        for i in 0..4 {
            assert!(buf.emit(sample_record(&[i as u8])));
        }
        // Fifth emit should fail.
        assert!(!buf.emit(sample_record(b"overflow")));
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn read_events_drains_partial_batch() {
        let buf = AuditBuffer::new();
        for i in 0..10 {
            assert!(buf.emit(sample_record(&[i])));
        }
        assert_eq!(buf.len(), 10);

        let mut out = [AuditRecord::zeroed(); 3];
        let n = buf.read_events(&mut out);
        assert_eq!(n, 3);
        assert_eq!(buf.len(), 7);
    }

    #[test]
    fn read_events_respects_output_capacity() {
        let buf = AuditBuffer::new();
        for i in 0..5 {
            assert!(buf.emit(sample_record(&[i])));
        }

        let mut out = [AuditRecord::zeroed(); 2];
        let n = buf.read_events(&mut out);
        assert_eq!(n, 2);
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let buf = AuditBuffer::new();
        assert!(buf.emit(sample_record(b"a")));
        assert!(buf.emit(sample_record(b"b")));

        let mut out = [AuditRecord::zeroed(); 10];
        let n = buf.read_events(&mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0].sequence, 1);
        assert_eq!(out[1].sequence, 2);
    }

    #[test]
    fn wrap_around_behaviour() {
        let buf = AuditBuffer::with_capacity(4);
        // Fill and drain to create a wraparound condition.
        for i in 0..4 {
            assert!(buf.emit(sample_record(&[i])));
        }
        let mut out = [AuditRecord::zeroed(); 4];
        assert_eq!(buf.read_events(&mut out), 4);

        // Now tail == head == 4; further emits should work.
        for i in 0..4 {
            assert!(buf.emit(sample_record(&[i])));
        }
        let n = buf.read_events(&mut out);
        assert_eq!(n, 4);
    }
}
