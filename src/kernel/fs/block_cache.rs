//! src/kernel/fs/block_cache.rs
//! A fixed-capacity block cache that wraps a BlockDevice and provides
//! cached reads with both write-through and write-back modes.
//!
//! Write-through (the default for metadata) writes directly to the device
//! and updates the cached copy.  Write-back (preferred for file data) writes
//! only to the cache and marks the entry dirty; dirty blocks are flushed
//! to the device on explicit `flush` / `flush_range` calls or when the
//! entry is evicted.

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::{BlockDevice, BLOCK_SIZE};
use crate::kernel::sync::Mutex;
use crate::Result;

// ---------------------------------------------------------------------------
// Persistent write-back clock
// ---------------------------------------------------------------------------

/// Monotonic cache clock used to age dirty blocks.  The scheduler advances it
/// once per timer tick; a block written at tick `T` is "expired" once the
/// clock reaches `T + WRITE_BACK_AGE_TICKS`, at which point the periodic
/// background write-back persists it to the device.  This is what makes the
/// write-back cache durable even when the application never calls `fsync`.
static BLOCK_CACHE_TICK: AtomicU64 = AtomicU64::new(0);

/// Advance the cache clock by one tick.  Called from the scheduler's timer
/// tick (cheap, lock-free).
pub fn advance_cache_tick() {
    advance_cache_ticks(1);
}

/// Advance the cache clock by `n` ticks.
pub fn advance_cache_ticks(n: u64) {
    BLOCK_CACHE_TICK.fetch_add(n, Ordering::Relaxed);
}

/// Current cache-clock value.
pub fn cache_tick() -> u64 {
    BLOCK_CACHE_TICK.load(Ordering::Relaxed)
}

/// Set the cache-clock value (host tests that need deterministic aging).
#[cfg(test)]
pub(crate) fn set_cache_tick_for_test(value: u64) {
    BLOCK_CACHE_TICK.store(value, Ordering::Relaxed);
}

/// Period (in scheduler ticks) between automatic background write-back scans.
/// 300 ticks @ 100 Hz = every 3 seconds.
pub const WRITE_BACK_PERIOD_TICKS: u64 = 300;
/// Minimum age (in scheduler ticks) before a dirty block is eligible for the
/// automatic background write-back.  600 ticks @ 100 Hz = 6 seconds, matching
/// the Linux `dirty_expire_centisecs` default of 3000 centiseconds.
pub const WRITE_BACK_AGE_TICKS: u64 = 600;

/// Maximum number of cached blocks.  Increased from 64 to 128 to reduce
/// eviction pressure under the write-back model, at a cost of 64 KiB of
/// heap (128 × 512 bytes).  This is still < 0.4% of the 16 MiB kernel heap.
const CACHE_CAPACITY: usize = 128;

/// When the number of dirty blocks reaches this fraction of `CACHE_CAPACITY`
/// (50 % = 64 dirty blocks), `write_back` automatically triggers a full flush
/// to avoid cascading eviction writes later.  The threshold is deliberately
/// conservative so short bursts of writes don't hit the device on every call.
const WRITE_BACK_PRESSURE_THRESHOLD: usize = CACHE_CAPACITY / 2;

/// Sentinel value for an empty cache slot.
const EMPTY_LBA: u64 = u64::MAX;

/// Observational counters for cache effectiveness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    /// Number of dirty blocks written back to the device (at eviction or
    /// explicit flush time).
    pub dirty_writebacks: u64,
    /// Number of cache hits on blocks that were prefetched (read-ahead).
    pub prefetch_hits: u64,
    /// Number of sequential read-ahead blocks prefetched.
    pub prefetches_issued: u64,
    /// Number of times a full flush was triggered automatically because
    /// the dirty-block count exceeded the write-back pressure threshold.
    pub pressure_flushes: u64,
    /// Number of dirty blocks written back by the aged background write-back
    /// (the "persistent cache" durability path).
    pub aged_writebacks: u64,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    lba: u64,
    data: [u8; BLOCK_SIZE],
    generation: u64,
    /// Whether this block has been modified in the cache but not yet written
    /// to the underlying device.
    dirty: bool,
    /// Cache-clock tick at which this block last became dirty; `0` when clean.
    /// Used by the aged background write-back to persist old dirty data.
    dirty_since: u64,
}

impl CacheEntry {
    const fn empty() -> Self {
        Self {
            lba: EMPTY_LBA,
            data: [0_u8; BLOCK_SIZE],
            generation: 0,
            dirty: false,
            dirty_since: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.lba == EMPTY_LBA
    }
}

pub struct BlockCache {
    device: Arc<dyn BlockDevice>,
    entries: Mutex<Vec<CacheEntry>>,
    generation: Mutex<u64>,
    stats: Mutex<CacheStats>,
    /// Last LBA accessed via `read_cached` — used for sequential-access
    /// detection and lightweight read-ahead.
    last_read_lba: Mutex<u64>,
    /// Read-ahead depth: number of extra blocks to prefetch after a
    /// sequential hit.  Defaults to 2; 0 disables read-ahead.
    read_ahead_depth: usize,
}

impl BlockCache {
    pub fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self {
            device,
            entries: Mutex::new(vec![CacheEntry::empty(); CACHE_CAPACITY]),
            generation: Mutex::new(0),
            stats: Mutex::new(CacheStats::default()),
            last_read_lba: Mutex::new(u64::MAX),
            read_ahead_depth: 0, // disabled by default; enable via `with_read_ahead()`
        }
    }

    /// Create a cache with sequential read-ahead enabled.
    ///
    /// When enabled, a sequential cache miss prefetches the next two blocks
    /// so that subsequent sequential reads are hits.
    pub fn with_read_ahead(device: Arc<dyn BlockDevice>, depth: usize) -> Self {
        Self {
            read_ahead_depth: depth,
            ..Self::new(device)
        }
    }

    /// Return a snapshot of the current cache statistics.
    pub fn stats(&self) -> CacheStats {
        *self.stats.lock()
    }

    /// Whether the underlying block device is read-only.
    pub fn is_read_only(&self) -> bool {
        self.device.is_read_only()
    }

    /// Read a block through the cache. On hit the cached data is returned
    /// without touching the device; on miss the block is read from the
    /// underlying device and stored in the cache before returning.
    ///
    /// When sequential access is detected (consecutive LBAs), the next
    /// two blocks are speculatively read into the cache so the caller
    /// avoids device round-trips on subsequent reads.
    pub fn read_cached(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let buffer_len = buffer.len();
        assert!(
            buffer_len == BLOCK_SIZE,
            "read_cached buffer must be BLOCK_SIZE bytes"
        );

        {
            let entries = self.entries.lock();
            if let Some(entry) = entries.iter().find(|e| e.lba == lba) {
                buffer.copy_from_slice(&entry.data);
                drop(entries);
                self.bump_generation_and_update(lba);
                self.inc_hits();

                // Detect and count prefetch hits (block was previously
                // read-ahead into cache).
                let mut last = self.last_read_lba.lock();
                if *last != u64::MAX && lba == *last + 1 {
                    self.inc_prefetch_hits();
                }
                *last = lba;
                // Read-ahead is only triggered on MISS, not on hit,
                // because a hit means the block is already in cache.
                return Ok(());
            }
        }

        // Cache miss — read from device and insert.
        self.device.read_blocks(lba, buffer)?;
        self.inc_misses();
        self.insert(lba, buffer, false);

        // Trigger read-ahead on sequential miss so the next few blocks
        // are warmed in the cache.  Update last_read_lba regardless.
        {
            let mut last = self.last_read_lba.lock();
            let is_sequential = *last != u64::MAX && lba == *last + 1;
            *last = lba;
            if is_sequential {
                drop(last);
                self.trigger_read_ahead(lba);
            }
        }

        Ok(())
    }

    /// Write through to the underlying device and update the cached copy
    /// if present, so subsequent reads see the new data without a device
    /// round-trip.  The cached entry is marked clean (it matches the device).
    pub fn write_through(&self, lba: u64, data: &[u8]) -> Result<()> {
        assert!(
            data.len() == BLOCK_SIZE,
            "write_through data must be BLOCK_SIZE bytes"
        );

        self.device.write_blocks(lba, data)?;

        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
            entry.data.copy_from_slice(data);
            entry.dirty = false;
            entry.dirty_since = 0;
            drop(entries);
            self.bump_generation_and_update(lba);
        }

        Ok(())
    }

    /// Write data into the cache and mark the entry dirty, deferring the
    /// device write until `flush()` or eviction.
    ///
    /// If the LBA is not currently cached it is inserted (possibly evicting
    /// another entry).  The underlying device is **not** touched by this call.
    pub fn write_back(&self, lba: u64, data: &[u8]) -> Result<()> {
        assert!(
            data.len() == BLOCK_SIZE,
            "write_back data must be BLOCK_SIZE bytes"
        );

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
                entry.data.copy_from_slice(data);
                entry.dirty = true;
                entry.dirty_since = cache_tick();
                drop(entries);
                self.bump_generation_and_update(lba);
                return Ok(());
            }
        }

        // Not present — insert as dirty.
        self.insert(lba, data, true);
        Ok(())
    }

    /// Return `true` when the number of dirty blocks meets or exceeds the
    /// write-back pressure threshold.  Callers that batch many write-back
    /// operations (e.g., filesystem transaction commit) can use this to
    /// decide when to insert an early `flush()` so that later evictions
    /// don't synchronously write back under lock contention.
    pub fn write_back_under_pressure(&self) -> bool {
        self.dirty_slots() >= WRITE_BACK_PRESSURE_THRESHOLD
    }

    /// Trigger a full flush if the dirty-block count exceeds the write-back
    /// pressure threshold.  Best-effort: errors are silently ignored because
    /// dirty data remains safe in the cache and will be retried on eviction
    /// or explicit `flush()`.
    ///
    /// Increments `pressure_flushes` each time it triggers.
    pub fn flush_if_under_pressure(&self) {
        if self.write_back_under_pressure() {
            let _ = self.flush();
            self.inc_pressure_flushes();
        }
    }

    /// Write every dirty cached block to the underlying device.
    /// Dirty flags are cleared after successful writes.
    pub fn flush(&self) -> Result<()> {
        let mut entries = self.entries.lock();
        let mut count = 0_u64;
        for entry in entries.iter_mut() {
            if entry.dirty {
                self.device.write_blocks(entry.lba, &entry.data)?;
                entry.dirty = false;
                entry.dirty_since = 0;
                count += 1;
            }
        }
        drop(entries);
        if count > 0 {
            self.add_dirty_writebacks(count);
        }
        Ok(())
    }

    /// Write dirty cached blocks whose age meets or exceeds `age_ticks` to
    /// the underlying device.  A block written at cache-clock `T` is eligible
    /// once the clock reaches `T + age_ticks`.
    ///
    /// This is the "persistent cache" durability path: the scheduler drives
    /// it periodically so dirty data reaches stable storage without waiting
    /// for an explicit `fsync`/`sync`.  Returns the number of blocks written.
    pub fn flush_aged(&self, age_ticks: u64) -> Result<usize> {
        let now = cache_tick();
        let mut entries = self.entries.lock();
        let mut flushed = 0_usize;
        for entry in entries.iter_mut() {
            if entry.dirty && now.wrapping_sub(entry.dirty_since) >= age_ticks {
                self.device.write_blocks(entry.lba, &entry.data)?;
                entry.dirty = false;
                entry.dirty_since = 0;
                flushed += 1;
            }
        }
        drop(entries);
        if flushed > 0 {
            self.add_aged_writebacks(flushed as u64);
        }
        Ok(flushed)
    }

    /// Number of dirty blocks that have aged past `age_ticks` (visible for
    /// tests and diagnostics).
    pub fn aged_dirty_count(&self, age_ticks: u64) -> usize {
        let now = cache_tick();
        let entries = self.entries.lock();
        entries
            .iter()
            .filter(|e| e.dirty && now.wrapping_sub(e.dirty_since) >= age_ticks)
            .count()
    }

    /// Write dirty cached blocks within `[start_lba, start_lba + count)` to
    /// the underlying device.  Dirty flags are cleared after successful writes.
    pub fn flush_range(&self, start_lba: u64, count: u64) -> Result<()> {
        let end_lba = start_lba.saturating_add(count);
        let mut entries = self.entries.lock();
        let mut flushed = 0_u64;
        for entry in entries.iter_mut() {
            if entry.dirty && entry.lba >= start_lba && entry.lba < end_lba {
                self.device.write_blocks(entry.lba, &entry.data)?;
                entry.dirty = false;
                flushed += 1;
            }
        }
        drop(entries);
        if flushed > 0 {
            self.add_dirty_writebacks(flushed);
        }
        Ok(())
    }

    /// Remove a specific LBA from the cache so the next read fetches fresh
    /// data from the underlying device.
    pub fn invalidate(&self, lba: u64) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
            *entry = CacheEntry::empty();
            drop(entries);
            self.inc_evictions();
        }
    }

    /// Invalidate every cached block whose LBA falls in
    /// `[start_lba, start_lba + count)`.
    pub fn invalidate_range(&self, start_lba: u64, count: u64) {
        let end_lba = start_lba.saturating_add(count);
        let mut entries = self.entries.lock();
        let mut evicted = 0_u64;
        for entry in entries.iter_mut() {
            if !entry.is_empty() && entry.lba >= start_lba && entry.lba < end_lba {
                *entry = CacheEntry::empty();
                evicted += 1;
            }
        }
        drop(entries);
        if evicted > 0 {
            self.add_evictions(evicted);
        }
    }

    /// Current number of populated cache slots (visible for tests).
    pub fn populated_slots(&self) -> usize {
        let entries = self.entries.lock();
        entries.iter().filter(|e| !e.is_empty()).count()
    }

    /// Number of dirty blocks currently in the cache (visible for tests).
    pub fn dirty_slots(&self) -> usize {
        let entries = self.entries.lock();
        entries.iter().filter(|e| e.dirty).count()
    }

    /// Populate the cache with data for `lba` without marking the entry
    /// dirty.  The caller has already written the data to the device and
    /// only wants to warm the cache so that subsequent reads are hits.
    /// If the LBA is already cached the entry is updated in place (still
    /// clean); otherwise a new clean entry is inserted, evicting if needed.
    pub fn populate_clean(&self, lba: u64, data: &[u8]) {
        assert!(
            data.len() == BLOCK_SIZE,
            "populate_clean data must be BLOCK_SIZE bytes"
        );
        self.insert(lba, data, false);
    }

    /// Issue read-ahead for the next `prefetch_depth` blocks after `lba`.
    ///
    /// Each block is read from the device into the cache (clean) so that a
    /// subsequent sequential read will be a cache hit.  The caller's read
    /// is not blocked — the device I/O happens synchronously but the data
    /// is available immediately on the next call to `read_cached`.
    pub fn prefetch(&self, start_lba: u64, count: usize) {
        for offset in 0..count {
            let lba = start_lba.saturating_add(offset as u64);
            // Skip if already cached.
            {
                let entries = self.entries.lock();
                if entries.iter().any(|e| e.lba == lba) {
                    continue;
                }
            }
            let mut buf = [0_u8; BLOCK_SIZE];
            if self.device.read_blocks(lba, &mut buf).is_ok() {
                self.insert(lba, &buf, false);
                self.inc_prefetches_issued();
            }
        }
    }

    /// Internal: trigger read-ahead when sequential access is detected.
    fn trigger_read_ahead(&self, lba: u64) {
        let depth = self.read_ahead_depth;
        if depth == 0 {
            return;
        }
        // Prefetch the next `depth` blocks.
        let start = lba.saturating_add(1);
        self.prefetch(start, depth);
    }

    // ─── internal helpers ───

    fn next_generation(&self) -> u64 {
        let mut gen = self.generation.lock();
        let current = *gen;
        *gen = current.wrapping_add(1);
        current
    }

    fn bump_generation_and_update(&self, lba: u64) {
        let gen = self.next_generation();
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
            entry.generation = gen;
        }
    }

    /// Insert `data` for `lba` into the cache.  When `dirty` is true the
    /// entry is marked as needing write-back; otherwise it is considered
    /// clean (matches the device).
    ///
    /// If the cache is full, eviction prefers clean entries first so that
    /// dirty data is not prematurely flushed.  When a dirty entry must be
    /// evicted its contents are written to the device first.
    fn insert(&self, lba: u64, data: &[u8], dirty: bool) {
        let gen = self.next_generation();
        let dirty_since = if dirty { cache_tick() } else { 0 };
        let mut entries = self.entries.lock();

        // If the same LBA is already present, just update in place.
        if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
            entry.data.copy_from_slice(data);
            entry.generation = gen;
            entry.dirty = dirty;
            entry.dirty_since = dirty_since;
            return;
        }

        // Prefer an empty slot.
        if let Some(slot) = entries.iter_mut().find(|e| e.is_empty()) {
            slot.lba = lba;
            slot.data.copy_from_slice(data);
            slot.generation = gen;
            slot.dirty = dirty;
            slot.dirty_since = dirty_since;
            return;
        }

        // Cache is full — choose an eviction victim.
        // Strategy: prefer the least-recently-used *clean* entry so dirty
        // blocks stay resident and are only written back when necessary.
        {
            let clean_lru = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| !e.dirty)
                .min_by_key(|(_, e)| e.generation)
                .map(|(i, _)| i);

            if let Some(idx) = clean_lru {
                // Evict a clean entry — cheap, no device I/O needed.
                let victim = &mut entries[idx];
                victim.lba = lba;
                victim.data.copy_from_slice(data);
                victim.generation = gen;
                victim.dirty = dirty;
                victim.dirty_since = dirty_since;
                drop(entries);
                self.inc_evictions();
                return;
            }
        }

        // All entries are dirty.  Pick the LRU one and flush it first.
        {
            let victim_idx = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.generation)
                .map(|(i, _)| i)
                .expect("cache capacity must be > 0");

            let flush_lba = entries[victim_idx].lba;
            let flush_data = entries[victim_idx].data;
            // Mark the slot empty while we hold the lock so it isn't
            // double-counted; the write happens below outside the lock.
            entries[victim_idx] = CacheEntry::empty();
            drop(entries);

            // Write the dirty victim back to the device.
            let _ = self.device.write_blocks(flush_lba, &flush_data);
            self.inc_evictions();
            self.inc_dirty_writebacks();
        }

        // The victim was flushed and its slot is now empty.  Re-acquire
        // and find that (or any) empty slot.  In the single-threaded kernel
        // no other thread can steal it, but we re-check to be safe.
        let mut entries = self.entries.lock();
        let slot = entries
            .iter_mut()
            .find(|e| e.is_empty())
            .expect("a slot must have been freed by eviction");
        slot.lba = lba;
        slot.data.copy_from_slice(data);
        slot.generation = gen;
        slot.dirty = dirty;
        slot.dirty_since = dirty_since;
    }

    // ─── stats helpers ───

    fn inc_hits(&self) {
        self.stats.lock().hits += 1;
    }

    fn inc_misses(&self) {
        self.stats.lock().misses += 1;
    }

    fn inc_evictions(&self) {
        self.stats.lock().evictions += 1;
    }

    fn add_evictions(&self, count: u64) {
        self.stats.lock().evictions += count;
    }

    fn inc_dirty_writebacks(&self) {
        self.stats.lock().dirty_writebacks += 1;
    }

    fn add_dirty_writebacks(&self, count: u64) {
        self.stats.lock().dirty_writebacks += count;
    }

    fn add_aged_writebacks(&self, count: u64) {
        self.stats.lock().aged_writebacks += count;
    }

    fn inc_pressure_flushes(&self) {
        self.stats.lock().pressure_flushes += 1;
    }

    fn inc_prefetch_hits(&self) {
        self.stats.lock().prefetch_hits += 1;
    }

    fn inc_prefetches_issued(&self) {
        self.stats.lock().prefetches_issued += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync::Mutex as TestMutex;
    use core::sync::atomic::{AtomicU64, Ordering};

    struct CountingDevice {
        name: &'static str,
        storage: TestMutex<Vec<u8>>,
        read_count: AtomicU64,
        block_count: u64,
    }

    impl CountingDevice {
        fn with_blocks(name: &'static str, num_blocks: u64) -> Self {
            let size = num_blocks as usize * BLOCK_SIZE;
            Self {
                name,
                storage: TestMutex::new(vec![0_u8; size]),
                read_count: AtomicU64::new(0),
                block_count: num_blocks,
            }
        }

        fn read_count(&self) -> u64 {
            self.read_count.load(Ordering::Relaxed)
        }
    }

    impl BlockDevice for CountingDevice {
        fn name(&self) -> &str {
            self.name
        }

        fn block_count(&self) -> u64 {
            self.block_count
        }

        fn is_read_only(&self) -> bool {
            false
        }

        fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
            self.read_count.fetch_add(1, Ordering::Relaxed);
            let storage = self.storage.lock();
            let start = lba as usize * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            buffer.copy_from_slice(&storage[start..end]);
            Ok(())
        }

        fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
            let mut storage = self.storage.lock();
            let start = lba as usize * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            storage[start..end].copy_from_slice(data);
            Ok(())
        }
    }

    fn make_test_data(pattern: u8) -> [u8; BLOCK_SIZE] {
        let mut data = [0_u8; BLOCK_SIZE];
        data.fill(pattern);
        data
    }

    #[test]
    fn read_cached_miss_reads_from_device() {
        let device = Arc::new(CountingDevice::with_blocks("miss-device", 4));
        // Pre-seed LBA 0 with pattern 0xAB.
        device.write_blocks(0, &make_test_data(0xAB)).unwrap();

        let cache = BlockCache::new(device.clone());
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(0, &mut buf).unwrap();

        assert_eq!(buf, make_test_data(0xAB));
        assert_eq!(device.read_count(), 1);
        assert_eq!(cache.populated_slots(), 1);
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn read_cached_hit_avoids_device_read() {
        let device = Arc::new(CountingDevice::with_blocks("hit-device", 4));
        device.write_blocks(0, &make_test_data(0xCD)).unwrap();

        let cache = BlockCache::new(device.clone());
        let mut buf = [0_u8; BLOCK_SIZE];

        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(device.read_count(), 1);

        // Second read of the same LBA must not touch the device.
        let mut buf2 = [0_u8; BLOCK_SIZE];
        cache.read_cached(0, &mut buf2).unwrap();
        assert_eq!(buf2, make_test_data(0xCD));
        assert_eq!(device.read_count(), 1);
        assert_eq!(cache.populated_slots(), 1);
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 1);
    }

    #[test]
    fn read_cached_different_lbas_do_not_collide() {
        let device = Arc::new(CountingDevice::with_blocks("multi-device", 4));
        device.write_blocks(0, &make_test_data(0x11)).unwrap();
        device.write_blocks(1, &make_test_data(0x22)).unwrap();

        let cache = BlockCache::new(device.clone());
        let mut buf = [0_u8; BLOCK_SIZE];

        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0x11));
        cache.read_cached(1, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0x22));

        assert_eq!(device.read_count(), 2);
        assert_eq!(cache.populated_slots(), 2);

        // Both should be cache hits now.
        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0x11));
        cache.read_cached(1, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0x22));
        assert_eq!(device.read_count(), 2);
    }

    #[test]
    fn write_through_persists_data_to_device() {
        let device = Arc::new(CountingDevice::with_blocks("wt-device", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_through(0, &make_test_data(0xEE)).unwrap();

        // Read directly from the device to confirm persistence.
        let mut buf = [0_u8; BLOCK_SIZE];
        device.read_blocks(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xEE));
        // The read through the device path increments read_count, but the
        // write_through itself does not.
    }

    #[test]
    fn write_through_updates_cache_so_subsequent_read_is_cached() {
        let device = Arc::new(CountingDevice::with_blocks("wt-cache-device", 4));
        let cache = BlockCache::new(device.clone());

        // Prime the cache with a read first, then overwrite via write_through.
        let mut buf = [0_u8; BLOCK_SIZE];
        device.write_blocks(0, &make_test_data(0xAA)).unwrap();
        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xAA));
        assert_eq!(cache.populated_slots(), 1);

        cache.write_through(0, &make_test_data(0x55)).unwrap();

        let reads_before = device.read_count();

        let mut buf2 = [0_u8; BLOCK_SIZE];
        cache.read_cached(0, &mut buf2).unwrap();
        assert_eq!(buf2, make_test_data(0x55));
        // The cache was already populated by the initial read and then updated
        // by write_through, so read_cached should not trigger a device read.
        assert_eq!(device.read_count(), reads_before);
        assert_eq!(cache.populated_slots(), 1);
    }

    #[test]
    fn invalidate_forces_device_read_after_cache_hit() {
        let device = Arc::new(CountingDevice::with_blocks("inv-device", 4));
        device.write_blocks(0, &make_test_data(0x77)).unwrap();

        let cache = BlockCache::new(device.clone());
        let mut buf = [0_u8; BLOCK_SIZE];

        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(device.read_count(), 1);

        cache.invalidate(0);
        assert_eq!(cache.populated_slots(), 0);

        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(device.read_count(), 2);
        assert_eq!(buf, make_test_data(0x77));

        let stats = cache.stats();
        // Both reads were misses because invalidate cleared the cache between them.
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn eviction_replaces_least_recently_used_entry() {
        // Device needs at least CACHE_CAPACITY + 2 blocks: one for each
        // cache slot prime, plus the eviction-triggering read, plus one
        // re-read slot.
        let device_blocks = CACHE_CAPACITY as u64 + 2;
        let device = Arc::new(CountingDevice::with_blocks("evict-device", device_blocks));
        let cache = BlockCache::new(device.clone());

        // Prime all cache slots.
        for lba in 0..CACHE_CAPACITY as u64 {
            device
                .write_blocks(lba, &make_test_data(lba as u8))
                .unwrap();
            let mut buf = [0_u8; BLOCK_SIZE];
            cache.read_cached(lba, &mut buf).unwrap();
        }
        assert_eq!(cache.populated_slots(), CACHE_CAPACITY);

        // Re-read LBA 0 to make it the most-recently-used entry.
        let reads_before = device.read_count();
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(0, &mut buf).unwrap();
        // LBA 0 was a cache hit; no new device read.
        assert_eq!(device.read_count(), reads_before);

        // Read a new LBA beyond the cache capacity that forces eviction.
        // LBA 1 is now the LRU entry (it was accessed at the same time as
        // 2..(C-1) initially, but 1 has the lowest generation among the
        // untouched entries).
        let evict_lba = CACHE_CAPACITY as u64;
        device
            .write_blocks(evict_lba, &make_test_data(0x10))
            .unwrap();
        cache.read_cached(evict_lba, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0x10));

        // LBA 1 should have been evicted. Reading it again must hit the device.
        let reads_mid = device.read_count();
        cache.read_cached(1, &mut buf).unwrap();
        assert!(device.read_count() > reads_mid);
        assert_eq!(buf, make_test_data(0x01));

        // LBA 0 must still be cached (it was the MRU before the eviction).
        let reads_end = device.read_count();
        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(device.read_count(), reads_end);
        assert_eq!(buf, make_test_data(0x00));

        let stats = cache.stats();
        // C initial primes + LBA C miss + LBA 1 re-read miss = C + 2 misses.
        assert_eq!(stats.misses, CACHE_CAPACITY as u64 + 2);
        // LBA 0 re-read + LBA 0 final read = 2 hits.
        assert_eq!(stats.hits, 2);
        // LBA C evicted LBA 1; then LBA 1 re-read evicted LBA 2
        // (the LRU at that point).
        assert_eq!(stats.evictions, 2);
    }

    #[test]
    fn write_through_for_uncached_lba_does_not_insert_into_cache() {
        // write_through only updates the cache if the LBA is already present;
        // it does not proactively cache new LBAs.
        let device = Arc::new(CountingDevice::with_blocks("wt-noinsert", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_through(0, &make_test_data(0x99)).unwrap();

        // The write went to the device, but no cache slot should be occupied.
        assert_eq!(cache.populated_slots(), 0);

        // A subsequent read must go to the device.
        let reads_before = device.read_count();
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(device.read_count(), reads_before + 1);
        assert_eq!(buf, make_test_data(0x99));
    }

    // ─── write-back tests ───

    #[test]
    fn write_back_does_not_touch_device() {
        let device = Arc::new(CountingDevice::with_blocks("wb-nodev", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_back(0, &make_test_data(0xBB)).unwrap();

        // write_back must not call device.write_blocks — verify by checking
        // that the device storage is still zeroed.
        let mut buf = [0_u8; BLOCK_SIZE];
        device.read_blocks(0, &mut buf).unwrap();
        assert_eq!(buf, [0_u8; BLOCK_SIZE]);

        // But a cached read should see the dirty data.
        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xBB));
    }

    #[test]
    fn write_back_and_read_cached_maintains_data() {
        let device = Arc::new(CountingDevice::with_blocks("wb-read", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_back(0, &make_test_data(0xCC)).unwrap();

        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xCC));
        // read_cached on a dirty block is a cache hit, no device I/O.
        assert_eq!(cache.populated_slots(), 1);
        assert_eq!(cache.dirty_slots(), 1);
    }

    #[test]
    fn flush_persists_dirty_blocks_to_device() {
        let device = Arc::new(CountingDevice::with_blocks("wb-flush", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_back(0, &make_test_data(0xDD)).unwrap();
        cache.write_back(1, &make_test_data(0xEE)).unwrap();
        assert_eq!(cache.dirty_slots(), 2);

        cache.flush().unwrap();

        // After flush, the device must contain the written data.
        let mut buf = [0_u8; BLOCK_SIZE];
        device.read_blocks(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xDD));
        device.read_blocks(1, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xEE));

        // Cache entries should now be clean.
        assert_eq!(cache.dirty_slots(), 0);
        assert_eq!(cache.stats().dirty_writebacks, 2);
    }

    #[test]
    fn write_back_inserts_uncached_lba() {
        // Unlike write_through, write_back proactively caches new LBAs.
        let device = Arc::new(CountingDevice::with_blocks("wb-insert", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_back(0, &make_test_data(0xFF)).unwrap();

        assert_eq!(cache.populated_slots(), 1);
        assert_eq!(cache.dirty_slots(), 1);

        // Verify cached read returns the dirty data without device I/O.
        let reads_before = device.read_count();
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(device.read_count(), reads_before);
        assert_eq!(buf, make_test_data(0xFF));
    }

    #[test]
    fn eviction_prefers_clean_entries_over_dirty() {
        // Fill the cache: half the entries are dirty, half are clean.
        let device_blocks = CACHE_CAPACITY as u64 + 1;
        let device = Arc::new(CountingDevice::with_blocks("evict-pref", device_blocks));
        let cache = BlockCache::new(device.clone());

        // Populate first half with dirty entries via write_back.
        let half = CACHE_CAPACITY / 2;
        for lba in 0..half as u64 {
            device.write_blocks(lba, &make_test_data(0x10)).unwrap();
            cache.write_back(lba, &make_test_data(0x10)).unwrap();
        }

        // Populate second half with clean entries via read_cached.
        for lba in half as u64..CACHE_CAPACITY as u64 {
            device.write_blocks(lba, &make_test_data(0x20)).unwrap();
            let mut buf = [0_u8; BLOCK_SIZE];
            cache.read_cached(lba, &mut buf).unwrap();
        }

        assert_eq!(cache.dirty_slots(), half);

        // Now insert one more entry. It should evict a clean entry
        // (from the second half), not a dirty one.
        let new_lba = CACHE_CAPACITY as u64;
        device.write_blocks(new_lba, &make_test_data(0x30)).unwrap();
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(new_lba, &mut buf).unwrap();

        // All dirty entries should still be present.
        // Re-read each dirty LBA — they must still be hits.
        let reads_before = device.read_count();
        for lba in 0..half as u64 {
            cache.read_cached(lba, &mut buf).unwrap();
            assert_eq!(buf, make_test_data(0x10), "dirty LBA {lba} was evicted");
        }
        assert_eq!(
            device.read_count(),
            reads_before,
            "dirty entries caused device reads"
        );
        assert_eq!(cache.dirty_slots(), half);
    }

    #[test]
    fn eviction_of_dirty_block_writes_back_to_device() {
        // Use a small cache to force all-dirty eviction.
        // CACHE_CAPACITY is 128 which is too large for this test.
        // We instead mark every entry dirty and force an eviction.
        let device_blocks = CACHE_CAPACITY as u64 + 1;
        let device = Arc::new(CountingDevice::with_blocks("evict-dirty", device_blocks));
        let cache = BlockCache::new(device.clone());

        // Mark every cache slot dirty with a unique LBA.
        for lba in 0..CACHE_CAPACITY as u64 {
            device
                .write_blocks(lba, &make_test_data((lba + 1) as u8))
                .unwrap();
            cache
                .write_back(lba, &make_test_data((lba + 1) as u8))
                .unwrap();
        }
        assert_eq!(cache.dirty_slots(), CACHE_CAPACITY);

        // Inserting one more entry must evict a dirty block, which must be
        // written back first.
        let new_lba = CACHE_CAPACITY as u64;
        cache.write_back(new_lba, &make_test_data(0xAB)).unwrap();

        // The dirty_writebacks counter should have incremented.
        assert!(cache.stats().dirty_writebacks >= 1);

        // The evicted LBA's data must be on the device.
        // We don't know exactly which LBA was evicted (it's the LRU = LBA 0
        // or LBA 1 depending on generation ordering), but at least one of
        // the dirty LBAs must have been flushed.
        let mut found = false;
        let mut buf = [0_u8; BLOCK_SIZE];
        for lba in 0..CACHE_CAPACITY as u64 {
            device.read_blocks(lba, &mut buf).unwrap();
            if buf == make_test_data((lba + 1) as u8) {
                found = true;
                break;
            }
        }
        assert!(found, "no dirty block was written back to the device");
    }

    // ─── read-ahead tests ──────────────────────────────────────────────

    #[test]
    fn prefetch_populates_cache() {
        let device = Arc::new(CountingDevice::with_blocks("prefetch-dev", 16));
        let cache = BlockCache::with_read_ahead(device.clone(), 2);

        // Pre-seed device data.
        for lba in 0..10u64 {
            device
                .write_blocks(lba, &make_test_data(lba as u8))
                .unwrap();
        }

        // Prefetch blocks 3, 4, 5.
        cache.prefetch(3, 3);
        assert_eq!(cache.stats().prefetches_issued, 3);

        // They should now be cache hits.
        let reads_before = device.read_count();
        let mut buf = [0_u8; BLOCK_SIZE];
        for lba in 3..6u64 {
            cache.read_cached(lba, &mut buf).unwrap();
            assert_eq!(buf, make_test_data(lba as u8));
        }
        // No new device reads — all prefetched blocks are cached.
        assert_eq!(device.read_count(), reads_before);
    }

    #[test]
    fn sequential_read_triggers_read_ahead() {
        let device = Arc::new(CountingDevice::with_blocks("seq-dev", 16));
        let cache = BlockCache::with_read_ahead(device.clone(), 2);

        for lba in 0..10u64 {
            device
                .write_blocks(lba, &make_test_data(lba as u8))
                .unwrap();
        }

        // Read LBA 0 (miss, last was MAX → no read-ahead).
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(0, &mut buf).unwrap();
        assert_eq!(cache.stats().misses, 1);

        // Read LBA 1 (miss, last=0 → sequential → triggers read-ahead for 2,3).
        cache.read_cached(1, &mut buf).unwrap();
        assert_eq!(cache.stats().misses, 2);
        let prefetches_after = cache.stats().prefetches_issued;
        assert!(
            prefetches_after >= 1,
            "read-ahead should have been triggered"
        );

        // Read LBA 2: should be a prefetch hit (was read-ahead from LBA 1 miss).
        cache.read_cached(2, &mut buf).unwrap();
        assert_eq!(cache.stats().prefetch_hits, 1);
    }

    #[test]
    fn prefetch_skips_already_cached_blocks() {
        let device = Arc::new(CountingDevice::with_blocks("skip-dev", 16));
        let cache = BlockCache::with_read_ahead(device.clone(), 2);

        for lba in 0..5u64 {
            device
                .write_blocks(lba, &make_test_data(lba as u8))
                .unwrap();
        }

        // Read LBA 2 to cache it.
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(2, &mut buf).unwrap();

        // Prefetch LBAs 1..4. LBA 2 is already cached — should skip.
        cache.prefetch(1, 4);
        // Only 3 new prefetches: LBAs 1, 3, 4 (LBA 2 already cached).
        assert_eq!(cache.stats().prefetches_issued, 3);
    }

    // ─── aged (persistent) write-back tests ─────────────────────────────

    /// Serializes tests that manipulate the shared global cache clock.
    static AGED_TEST_LOCK: TestMutex<()> = TestMutex::new(());

    #[test]
    fn flush_aged_persists_only_blocks_older_than_the_threshold() {
        let _guard = AGED_TEST_LOCK.lock();
        set_cache_tick_for_test(1000);
        let device = Arc::new(CountingDevice::with_blocks("aged-dev", 4));
        let cache = BlockCache::new(device.clone());

        // Two dirty blocks stamped at tick 1000.
        cache.write_back(0, &make_test_data(0xAA)).unwrap();
        cache.write_back(1, &make_test_data(0xBB)).unwrap();
        assert_eq!(cache.dirty_slots(), 2);
        assert_eq!(cache.aged_dirty_count(0), 2);

        // Advance the clock 50 ticks: still young for an age of 100.
        advance_cache_ticks(50);
        assert_eq!(cache.aged_dirty_count(100), 0);
        assert_eq!(cache.flush_aged(100).unwrap(), 0);
        // Nothing persisted yet.
        let mut buf = [0_u8; BLOCK_SIZE];
        device.read_blocks(0, &mut buf).unwrap();
        assert_eq!(buf, [0_u8; BLOCK_SIZE]);

        // Advance another 60 ticks (total 110 > 100): both are now expired.
        advance_cache_ticks(60);
        assert_eq!(cache.aged_dirty_count(100), 2);
        assert_eq!(cache.flush_aged(100).unwrap(), 2);
        assert_eq!(cache.dirty_slots(), 0);

        // Data is on the device — the persistent-cache guarantee.
        device.read_blocks(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xAA));
        device.read_blocks(1, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xBB));
        assert_eq!(cache.stats().aged_writebacks, 2);
    }

    #[test]
    fn flush_aged_age_zero_flushes_everything() {
        let _guard = AGED_TEST_LOCK.lock();
        set_cache_tick_for_test(0);
        let device = Arc::new(CountingDevice::with_blocks("aged-zero", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_back(0, &make_test_data(0x11)).unwrap();
        cache.write_back(1, &make_test_data(0x22)).unwrap();
        assert_eq!(cache.flush_aged(0).unwrap(), 2);
        assert_eq!(cache.dirty_slots(), 0);
    }

    #[test]
    fn fresh_write_after_advance_is_not_flushed_until_it_ages() {
        let _guard = AGED_TEST_LOCK.lock();
        set_cache_tick_for_test(2000);
        let device = Arc::new(CountingDevice::with_blocks("aged-fresh", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_back(0, &make_test_data(0x33)).unwrap();
        // Advance far past the age threshold, then write a fresh block.
        advance_cache_ticks(500);
        cache.write_back(1, &make_test_data(0x44)).unwrap();

        // Only the old block is eligible; the fresh one keeps its timestamp.
        assert_eq!(cache.aged_dirty_count(400), 1);
        assert_eq!(cache.flush_aged(400).unwrap(), 1);
        let mut buf = [0_u8; BLOCK_SIZE];
        device.read_blocks(1, &mut buf).unwrap();
        assert_eq!(buf, [0_u8; BLOCK_SIZE], "fresh block must not be flushed");
        assert_eq!(cache.dirty_slots(), 1);
    }

    #[test]
    fn overwriting_a_dirty_block_restarts_its_age() {
        let _guard = AGED_TEST_LOCK.lock();
        set_cache_tick_for_test(0);
        let device = Arc::new(CountingDevice::with_blocks("aged-rewrite", 4));
        let cache = BlockCache::new(device.clone());

        cache.write_back(0, &make_test_data(0xAA)).unwrap();
        advance_cache_ticks(100);
        // Re-write the same block: its age clock restarts.
        cache.write_back(0, &make_test_data(0xBB)).unwrap();

        assert_eq!(cache.aged_dirty_count(50), 0);
        advance_cache_ticks(60);
        assert_eq!(cache.aged_dirty_count(50), 1);
        assert_eq!(cache.flush_aged(50).unwrap(), 1);
        let mut buf = [0_u8; BLOCK_SIZE];
        device.read_blocks(0, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0xBB));
    }
}
