//! src/kernel/smp/tlb.rs
//!
//! TLB shootdown, cross-CPU invalidation, and boot CR3 management.

// The posted log is the same code on the machine and in tests, so the import
// follows the log rather than the architecture.
#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
use core::sync::atomic::Ordering;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::apic;

// ── TLB shootdown ─────────────────────────────────────────────────────

/// Virtual address for the pending TLB shootdown (0 = none).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static SHOOTDOWN_VA: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Number of CPUs that have acknowledged the current shootdown.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static SHOOTDOWN_ACK_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Serialises TLB shootdown protocol entry so that only one CPU at a time
/// publishes a VA and collects acknowledgements.  Uses the same
/// exponential-backoff pattern as [`MEMORY_MANAGER_LOCK`] — interrupts
/// are NOT disabled, so other CPUs can handle our IPI while spinning here.
///
/// Currently unused while cross-CPU IPI delivery is being debugged;
/// see [`tlb_shootdown`] for the generation-counter workaround.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
static SHOOTDOWN_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Acquire the shootdown serialisation lock with exponential backoff.
/// Interrupts remain enabled so the caller (and other CPUs) can still
/// receive IPIs while contending for this lock.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
fn acquire_shootdown_lock() {
    let mut backoff: u32 = 1;
    while SHOOTDOWN_LOCK
        .compare_exchange_weak(
            false,
            true,
            core::sync::atomic::Ordering::Acquire,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_err()
    {
        while SHOOTDOWN_LOCK.load(core::sync::atomic::Ordering::Relaxed) {
            for _ in 0..backoff.min(64) {
                core::hint::spin_loop();
            }
            backoff = backoff.saturating_mul(2).min(1024);
        }
        backoff = 1;
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
fn release_shootdown_lock() {
    SHOOTDOWN_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

/// Full-flush counter for the architectures that keep their latch here.
///
/// x86_64's counter lives in its posted log instead — the log is where the
/// sequences have to agree with each other, and a counter shared with the host
/// build would let one test's flush look like another test's.
///
/// aarch64 and riscv64 compare this against their per-CPU latch in their IPI
/// handlers.  Nothing in this tree bumps it: they broadcast their page
/// invalidations where the page table is edited, so the handler is the path
/// that would serve a request nobody has needed yet.
#[cfg(all(target_os = "none", not(target_arch = "x86_64")))]
static TLB_GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many invalidations can be waiting to be walked at once.
///
/// A CPU walks what is posted on its next kernel entry, so the log only has to
/// hold what a tick's worth of page-table work produces.  When it does fill
/// up, the request that cannot be appended asks for a full flush instead of
/// waiting for room — see [`PostedLog::post`].
///
/// 256 is far above what the demo boot produces — `/proc/tlb` reports
/// `pending: 0` there, drained every tick — and far below the burst the churn
/// check makes on purpose, which is the pair of observations this number is
/// sized from: enough headroom that a healthy machine never promotes, and
/// small enough that the promotion path is the one that covers the burst.
/// Read the file on a different workload before changing it.
#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
const POSTED_SLOTS: usize = 256;

/// Ranges longer than this are dropped with a full flush rather than walked.
///
/// Past a certain length the per-page invalidations cost more than the flush
/// they are trying to avoid — tearing down an address space is one request for
/// thousands of pages — and a single entry that long would also hold the log
/// against everyone else.
///
/// One page of the demo's own page-table traffic is a user-page map or a stack
/// guard; the ranges that go past this are the ones that free memory in bulk,
/// which is exactly where a targeted invalidation would be doing thousands of
/// `invlpg`s to save a flush.
#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
const FULL_FLUSH_PAGES: usize = 32;

/// How many CPU ids the log keeps cursors for.
///
/// This is the kernel's `MAX_CPUS` on the machine.  On the host it is the same
/// number, so the storage has one shape everywhere and a test can drive it with
/// any id the machine could produce; the assertions below keep the two from
/// drifting apart.
#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
const LOG_CPUS: usize = 17;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const _: () = assert!(LOG_CPUS == super::bringup::MAX_CPUS);

/// What a caller keeps so it can tell when its request has been honoured.
///
/// The variant carries the evidence: a posted range is honoured when every CPU
/// has walked past its position, and a flush is honoured when every CPU has
/// published a flush at or after its generation.  `Nothing` is what an
/// architecture answers when it has already invalidated the range everywhere
/// (AArch64 broadcasts its page invalidations) or when there is no hardware
/// TLB to invalidate (host builds).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(
    not(any(all(target_arch = "x86_64", target_os = "none"), test)),
    allow(dead_code)
)]
pub(crate) enum InvalidationMark {
    /// The request is at this position in the posted log.
    Posted(u64),
    /// The request asked for a full flush, at this generation.
    Flushed(u64),
    /// The architecture invalidated it everywhere already.
    Nothing,
}

/// A snapshot of the posted-invalidation log.
///
/// Read by the `/proc/tlb` file and by the churn check: the numbers are what
/// says whether the log is sized for the machine (`pending` riding at the
/// limit and `full_flushes` climbing) or whether a CPU is being left behind
/// (`lag` growing).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct PostedStats {
    /// Requests that went into the log.
    pub(crate) postings: u64,
    /// Entries a CPU has walked out of it.
    pub(crate) walked: u64,
    /// Requests that asked for a full flush instead of a slot: a range too
    /// long to walk, a log with no room for the entry, or the PCID allocator
    /// reusing a PCID.
    pub(crate) full_flushes: u64,
    /// Entries posted and not yet walked by every CPU.
    pub(crate) pending: u64,
    /// How far apart the CPUs' cursors are.  Wide means one CPU is behind.
    pub(crate) lag: u64,
}

/// One pending invalidation: a page-aligned byte range `[start, end)`.
#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
struct PostedSlot {
    start: core::sync::atomic::AtomicUsize,
    end: core::sync::atomic::AtomicUsize,
}

#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
impl PostedSlot {
    const fn new() -> Self {
        Self {
            start: core::sync::atomic::AtomicUsize::new(0),
            end: core::sync::atomic::AtomicUsize::new(0),
        }
    }
}

/// Invalidations waiting to be walked, one entry per request.
///
/// A producer appends the range it changed; every CPU walks the whole log on
/// its next kernel entry, invalidating only the pages named there, and
/// publishes how far it has walked.  That publication is what a caller waits
/// on before it is allowed to reuse an address — so a CPU that has not been
/// through the kernel since the edit is never assumed to have dropped it.
///
/// The log is a fixed ring, and an entry is only ever overwritten once every
/// CPU has walked past it (checked through the published cursors).  A producer
/// that finds no room does not overwrite, and does not wait: it promotes its
/// request to a full flush, which covers it and every request already pending.
///
/// Everything here is per-instance rather than global so the mechanism can be
/// driven by tests on the host, where the effects are recordings instead of
/// `invlpg`s.
#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
pub(crate) struct PostedLog {
    slots: [PostedSlot; POSTED_SLOTS],
    /// Next position to hand out.  A consumer walks up to the value it read.
    head: core::sync::atomic::AtomicU64,
    /// Position each CPU has walked to, published for producers (which need to
    /// know a slot is spent) and for callers waiting on a mark.
    cursors: [core::sync::atomic::AtomicU64; LOG_CPUS],
    /// Generation of the last full flush each CPU has completed.
    flushed: [core::sync::atomic::AtomicU64; LOG_CPUS],
    /// Serialises producers.  Held for a handful of atomics, with this CPU's
    /// interrupts off: a handler can retire a stack too, and it would
    /// otherwise spin on a lock its own interrupted context is holding.
    appending: core::sync::atomic::AtomicBool,
    /// Requests that went into the log.
    postings: core::sync::atomic::AtomicU64,
    /// Entries a CPU has walked.
    walked: core::sync::atomic::AtomicU64,
    /// Requests that asked for a full flush.
    full_flushes: core::sync::atomic::AtomicU64,
    /// Full-flush generation: the value a mark carries and a CPU publishes
    /// after flushing.  Instance-owned, because the sequences a caller waits
    /// on are this log's and nothing else's.
    generation: core::sync::atomic::AtomicU64,
}

#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
impl PostedLog {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { PostedSlot::new() }; POSTED_SLOTS],
            head: core::sync::atomic::AtomicU64::new(0),
            cursors: [const { core::sync::atomic::AtomicU64::new(0) }; LOG_CPUS],
            flushed: [const { core::sync::atomic::AtomicU64::new(0) }; LOG_CPUS],
            appending: core::sync::atomic::AtomicBool::new(false),
            postings: core::sync::atomic::AtomicU64::new(0),
            walked: core::sync::atomic::AtomicU64::new(0),
            full_flushes: core::sync::atomic::AtomicU64::new(0),
            generation: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The current full-flush generation.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The CPUs whose cursors have to pass an entry before its slot is spent.
    fn cpus(&self, online: u32) -> usize {
        (online as usize).min(LOG_CPUS)
    }

    fn min_cursor(&self, online: u32) -> u64 {
        (0..self.cpus(online))
            .map(|cpu| self.cursors[cpu].load(Ordering::Acquire))
            .min()
            .unwrap_or(0)
    }

    /// Post a range, or ask for a full flush when the log cannot take it.
    ///
    /// Must be called after the page-table edit: the entry carries no ordering
    /// of its own beyond the release store that publishes it, which is what
    /// makes "every CPU has walked past it" mean "every CPU has invalidated
    /// the edit".
    pub(crate) fn post(&self, start: usize, end: usize, online: u32) -> InvalidationMark {
        if end <= start {
            return InvalidationMark::Nothing;
        }
        let pages = (end - start) / crate::kernel::memory::paging::PAGE_SIZE;
        if pages > FULL_FLUSH_PAGES {
            return self.post_full_flush();
        }

        let _appending = AppendGuard::take(&self.appending);
        let head = self.head.load(Ordering::Relaxed);
        if head - self.min_cursor(online) >= POSTED_SLOTS as u64 {
            // No room.  Dropping the request would leave a stale translation
            // behind, and waiting would make a page-table edit block on other
            // CPUs, so the request becomes the one thing that covers every
            // pending entry at once.
            drop(_appending);
            return self.post_full_flush();
        }
        let slot = &self.slots[(head as usize) % POSTED_SLOTS];
        slot.start.store(start, Ordering::Relaxed);
        slot.end.store(end, Ordering::Relaxed);
        self.head.store(head + 1, Ordering::Release);
        self.postings.fetch_add(1, Ordering::Relaxed);
        InvalidationMark::Posted(head)
    }

    /// Ask every CPU to drop everything, at a fresh generation.
    pub(crate) fn post_full_flush(&self) -> InvalidationMark {
        self.full_flushes.fetch_add(1, Ordering::Relaxed);
        let generation = self.generation.fetch_add(1, Ordering::Release) + 1;
        InvalidationMark::Flushed(generation)
    }

    /// Walk everything posted since this CPU last caught up, then take any
    /// full flush that was requested in the meantime.
    ///
    /// `invalidate` is handed each pending range; `flush` is called when the
    /// CPU owes a full flush.  A flush drops every translation, so the entries
    /// posted up to the head read here are covered without walking them.
    pub(crate) fn catch_up(
        &self,
        cpu: u32,
        online: u32,
        invalidate: &mut impl FnMut(usize, usize),
        flush: &mut impl FnMut(),
    ) {
        let cpu = cpu as usize;
        if cpu >= self.cpus(online) {
            return;
        }
        let head = self.head.load(Ordering::Acquire);
        let generation = self.generation.load(Ordering::Acquire);
        if generation > self.flushed[cpu].load(Ordering::Relaxed) {
            flush();
            // Both records say "everything asked for before this point is
            // gone", and both are written only after the flush.
            self.flushed[cpu].store(generation, Ordering::Release);
            self.cursors[cpu].store(head, Ordering::Release);
            return;
        }

        let start = self.cursors[cpu].load(Ordering::Relaxed);
        let mut cursor = start;
        while cursor < head {
            let slot = &self.slots[(cursor as usize) % POSTED_SLOTS];
            let start = slot.start.load(Ordering::Acquire);
            let end = slot.end.load(Ordering::Acquire);
            invalidate(start, end);
            cursor += 1;
            self.walked.fetch_add(1, Ordering::Relaxed);
        }
        // Only publish when there was something to walk: this runs on every
        // kernel entry, and the cursor is a line the other CPUs read.
        if cursor != start {
            self.cursors[cpu].store(cursor, Ordering::Release);
        }
    }

    /// Has every online CPU dropped what `mark` asked for?
    pub(crate) fn flushed(&self, mark: InvalidationMark, online: u32) -> bool {
        match mark {
            InvalidationMark::Nothing => true,
            InvalidationMark::Posted(position) => (0..self.cpus(online))
                .all(|cpu| self.cursors[cpu].load(Ordering::Acquire) > position),
            InvalidationMark::Flushed(generation) => (0..self.cpus(online))
                .all(|cpu| self.flushed[cpu].load(Ordering::Acquire) >= generation),
        }
    }

    /// Take a snapshot of the log's counters.
    pub(crate) fn stats(&self, online: u32) -> PostedStats {
        let head = self.head.load(Ordering::Acquire);
        let cursors: alloc::vec::Vec<u64> = (0..self.cpus(online))
            .map(|cpu| self.cursors[cpu].load(Ordering::Acquire))
            .collect();
        let min = cursors.iter().copied().min().unwrap_or(head);
        let max = cursors.iter().copied().max().unwrap_or(head);
        PostedStats {
            postings: self.postings.load(Ordering::Relaxed),
            walked: self.walked.load(Ordering::Relaxed),
            full_flushes: self.full_flushes.load(Ordering::Relaxed),
            pending: head.saturating_sub(min),
            lag: max.saturating_sub(min),
        }
    }
}

/// Keep this CPU's interrupts off while a producer holds the append lock.
#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
struct AppendGuard {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    rflags: u64,
    lock: *const core::sync::atomic::AtomicBool,
}

#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
impl AppendGuard {
    fn take(lock: &core::sync::atomic::AtomicBool) -> Self {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        let rflags = unsafe {
            let flags: u64;
            core::arch::asm!(
                "pushfq",
                "pop {}",
                "cli",
                out(reg) flags,
            );
            flags
        };
        while lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self {
            #[cfg(all(target_arch = "x86_64", target_os = "none"))]
            rflags,
            lock,
        }
    }
}

#[cfg(any(all(target_arch = "x86_64", target_os = "none"), test))]
impl Drop for AppendGuard {
    fn drop(&mut self) {
        unsafe { (*self.lock).store(false, Ordering::Release) };
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        if self.rflags & (1 << 9) != 0 {
            unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };
        }
    }
}

/// Diagnostic: total number of shootdown IPI handler invocations per CPU.
/// Incremented unconditionally so we can tell whether the IPI ever arrived.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub static SHOOTDOWN_HANDLER_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// The log of invalidations waiting to be walked.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static POSTED: PostedLog = PostedLog::new();

/// Drop this CPU's translations for every page in `[start, end)`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn invalidate_local_range(start: usize, end: usize) {
    let page = crate::kernel::memory::paging::PAGE_SIZE;
    let mut va = start;
    while va < end {
        // SAFETY: invalidating a translation is safe for any address; the next
        // access walks the tables again.
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack)) };
        va += page;
    }
}

/// Request a TLB shootdown for the given virtual address on all CPUs.
///
/// The local entry goes immediately and the request itself is posted to the
/// log, where each other CPU walks it on its next kernel entry and drops only
/// that page.  This used to bump a generation that made every CPU flush its
/// whole TLB, which cost far more than the translation being replaced —
/// especially for the user address space, where a single unmap used to ask for
/// one per page.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn tlb_shootdown(va: usize) {
    let page = crate::kernel::memory::paging::PAGE_SIZE;
    let start = va & !(page - 1);
    unsafe { invalidate_local_range(start, start + page) };
    POSTED.post(start, start + page, online_cpu_count());
}

/// Request a shootdown for a run of pages, as one request.
///
/// A range is one entry in the log rather than one per page: tearing down an
/// address space is a single edit from the TLB's point of view, and the log is
/// fixed size.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn tlb_shootdown_range(virtual_address: usize, byte_len: usize) {
    let page = crate::kernel::memory::paging::PAGE_SIZE;
    let start = virtual_address & !(page - 1);
    let Some(end) = virtual_address
        .checked_add(byte_len)
        .map(|end| end.saturating_add(page - 1) & !(page - 1))
    else {
        return;
    };
    if end <= start {
        return;
    }
    if (end - start) / page > FULL_FLUSH_PAGES {
        // Past a certain length the walk costs more than the flush it avoids,
        // which is also why such a range is promoted on the other CPUs.
        crate::arch::x86_64::paging::pcid::flush_all_tlb();
    } else {
        unsafe { invalidate_local_range(start, end) };
    }
    POSTED.post(start, end, online_cpu_count());
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn tlb_shootdown_range(_virtual_address: usize, _byte_len: usize) {
    // The architectures that broadcast their invalidations do it where the
    // page table is edited, so there is nothing to post here.
}

/// Apply the invalidations another CPU has posted since this CPU last looked.
///
/// Must be called on every kernel entry (timer tick, syscall, exception)
/// *after* the interrupt context has been saved: it is what makes another
/// CPU's page-table edit visible here, and what lets that CPU know its edit
/// has been seen everywhere.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn apply_remote_tlb_invalidations() {
    let percpu = crate::kernel::percpu::get_mut();
    let cpu_id = percpu.cpu_id;
    let online = online_cpu_count();
    POSTED.catch_up(
        cpu_id,
        online,
        &mut |start, end| unsafe { invalidate_local_range(start, end) },
        &mut || crate::arch::x86_64::paging::pcid::flush_all_tlb(),
    );
    // The log keeps its own record for the marks; this arch-neutral field is
    // what the other architectures' IPI handlers compare against, so keep it
    // telling the same story.  On x86_64 the counter that matters is the log's
    // own; this is the log's answer, not a second one.
    percpu.tlb_generation_seen = POSTED.generation();
}

/// Ask every CPU to drop everything on its next kernel entry.
///
/// Used by the PCID allocator when a wrap-around reuses PCIDs that may still
/// be tagged in remote TLBs, where naming a range is not possible.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn request_remote_tlb_flush() {
    let _ = POSTED.post_full_flush();
}

/// Post an invalidation for a range and answer with the mark for it.
///
/// The caller keeps the mark and hands it back to [`all_cpus_flushed`] until
/// that says every CPU has dropped the range — which is the grace an address
/// needs before it can be handed out again.  The request must be made *after*
/// the page-table edit; that ordering is what the mark's answer rests on.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn post_range_invalidation(virtual_address: usize, byte_len: usize) -> InvalidationMark {
    let page = crate::kernel::memory::paging::PAGE_SIZE;
    let start = virtual_address & !(page - 1);
    let Some(end) = virtual_address
        .checked_add(byte_len)
        .map(|end| end.saturating_add(page - 1) & !(page - 1))
    else {
        return InvalidationMark::Nothing;
    };
    POSTED.post(start, end, online_cpu_count())
}

/// Nothing to post where the architecture's invalidation is a broadcast.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn post_range_invalidation(_virtual_address: usize, _byte_len: usize) -> InvalidationMark {
    InvalidationMark::Nothing
}

/// Has every online CPU dropped what `mark` asked for?
///
/// The answer is what the stack window waits for before handing an address out
/// again: a stale translation anywhere would shadow the new mapping with the
/// frame the old owner used.  It is a question about finished work, not about
/// elapsed time — a CPU that has not reported in keeps the answer `false`, and
/// the caller then keeps the address retired a little longer rather than
/// blocking.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn all_cpus_flushed(mark: InvalidationMark) -> bool {
    POSTED.flushed(mark, online_cpu_count())
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn all_cpus_flushed(mark: InvalidationMark) -> bool {
    // Only `Nothing` is ever produced where this build cannot check a mark:
    // AArch64's page invalidation is inner-shareable and already done, and a
    // host build has no TLB.  Anything else would be asking a question this
    // build has no way to answer.
    debug_assert!(matches!(mark, InvalidationMark::Nothing));
    true
}

/// A snapshot of the posted-invalidation log, for diagnostics.
///
/// Zeroes where this build has no log to read: the architectures that
/// broadcast their invalidations never post anything, and a host build has no
/// hardware TLB to keep one for.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn posted_invalidation_stats() -> PostedStats {
    POSTED.stats(online_cpu_count())
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn posted_invalidation_stats() -> PostedStats {
    PostedStats::default()
}

/// Handle a TLB shootdown IPI on any CPU (BSP or AP).
///
/// Called from the IDT handler for `IPI_SHOOTDOWN_VECTOR`.
/// Invalidates the local TLB entry for the address in [`SHOOTDOWN_VA`]
/// and increments the acknowledgment counter.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn handle_tlb_shootdown() {
    SHOOTDOWN_HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
    let va = SHOOTDOWN_VA.load(Ordering::Acquire);
    if va != 0 {
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack));
        }
    }
    SHOOTDOWN_ACK_COUNT.fetch_add(1, Ordering::Release);
}

// ── Reschedule IPI ─────────────────────────────────────────────────────

/// Send a reschedule IPI to a specific CPU.
///
/// cpu_id=0 is the BSP (self-IPI not needed — the BSP checks need_resched on
/// every kernel exit).  For APs (cpu_id >= 1), sends `IPI_RESCHEDULE_VECTOR`
/// so the target CPU invokes its scheduler.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn send_reschedule_ipi(cpu_id: u32) {
    if cpu_id == 0 {
        return; // BSP: no self-IPI needed
    }
    let idx = (cpu_id - 1) as usize;
    let count = super::bringup::ONLINE_AP_COUNT.load(Ordering::Acquire) as usize;
    if idx >= count {
        return;
    }
    let ids = unsafe { &*super::bringup::AP_LAPIC_IDS.get() };
    super::bringup::send_ipi(
        ids[idx],
        super::bringup::IPI_RESCHEDULE_VECTOR as u32 | apic::ICR_DELIVERY_FIXED,
    );
}

/// Stub for non-bare-metal targets.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn send_reschedule_ipi(_cpu_id: u32) {}

// ── Online CPU count ───────────────────────────────────────────────────

/// Return the total number of online CPUs (BSP + APs).
///
/// Before AP bring-up completes, returns 1 (BSP only).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn online_cpu_count() -> u32 {
    1 + super::bringup::ONLINE_AP_COUNT.load(Ordering::Acquire)
}

/// Stub for non-bare-metal targets.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn online_cpu_count() -> u32 {
    // On non-x86_64, report 1 for BSP; updated by `bringup::set_online_ap_count`.
    1
}

/// Return the current TLB shootdown generation counter.
///
/// This is what AArch64/RISC-V SMP compare their own latches against; their
/// page invalidations are broadcasts, so nothing here bumps it.
#[cfg(all(target_os = "none", not(target_arch = "x86_64")))]
pub fn tlb_generation() -> u64 {
    TLB_GENERATION.load(core::sync::atomic::Ordering::Acquire)
}

/// Return the current TLB shootdown generation counter.
///
/// Host builds never perform remote TLB invalidations, so the counter the
/// per-arch SMP helpers compare against stays at zero.
#[cfg(all(
    not(target_os = "none"),
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
pub fn tlb_generation() -> u64 {
    0
}

// ── Boot CR3 ───────────────────────────────────────────────────────────

/// Boot Page Table root (PML4) physical address.  Saved before
/// [`crate::arch::mmu::activate_prepared_runtime_kernel_page_tables`]
/// switches away from the bootstrap identity map.  The boot page tables
/// identity-map the first 1 GiB with 2 MiB pages, which covers all AP
/// trampoline code/data (0x8000–0xA000) and any ACPI table below 1 GiB.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) static BOOT_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Save the current CR3 value (the boot page-table root) for AP startup.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn save_boot_cr3() {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    BOOT_CR3.store(cr3, core::sync::atomic::Ordering::Release);
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[allow(dead_code)]
pub fn save_boot_cr3() {}

// ── Stubs for non-bare-metal targets ───────────────────────────────────

/// Stub for non-bare-metal targets (tests, other architectures).
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[allow(dead_code)] // the arch-facing API; only x86_64 posts to the log
pub fn tlb_shootdown(_va: usize) {
    // no-op: single-CPU or test environment
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[allow(dead_code)]
pub fn handle_tlb_shootdown() {}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[allow(dead_code)]
pub fn apply_remote_tlb_invalidations() {}

#[cfg(test)]
mod tests {
    use super::InvalidationMark;
    use super::PostedLog;
    use super::FULL_FLUSH_PAGES;
    use super::POSTED_SLOTS;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    const PAGE: usize = crate::kernel::memory::paging::PAGE_SIZE;
    const CPUS: u32 = 4;
    const PAGES: usize = 64;

    /// One CPU's TLB, as far as this mechanism is concerned: the version of
    /// each page it still has a translation for.
    #[derive(Default)]
    struct Tlb {
        cached: BTreeMap<usize, u64>,
        flushes: usize,
    }

    /// A machine that can be driven: pages get edited and posted, CPUs walk
    /// the log, and every CPU's TLB is a record that can be checked.
    struct Machine {
        log: PostedLog,
        versions: Vec<u64>,
        tlvs: Vec<Tlb>,
        /// Every request posted so far: its mark and, per page, the version
        /// the edit left behind.  A translation older than that is stale.
        requests: Vec<(InvalidationMark, Vec<(usize, u64)>)>,
    }

    impl Machine {
        fn new() -> Self {
            Self {
                log: PostedLog::new(),
                versions: alloc::vec![0; PAGES],
                tlvs: (0..CPUS).map(|_| Tlb::default()).collect(),
                requests: Vec::new(),
            }
        }

        fn touch(&mut self, cpu: u32, page: usize) {
            let version = self.versions[page];
            self.tlvs[cpu as usize].cached.insert(page, version);
        }

        /// Edit `pages` pages and post the range, exactly as a page-table edit
        /// followed by `post_range_invalidation` does.
        fn edit_and_post(&mut self, first_page: usize, pages: usize) -> InvalidationMark {
            for page in first_page..first_page + pages {
                self.versions[page] += 1;
            }
            let start = first_page * PAGE;
            let end = (first_page + pages) * PAGE;
            let mark = self.log.post(start, end, CPUS);
            let edited = (first_page..first_page + pages)
                .map(|page| (page, self.versions[page]))
                .collect();
            self.requests.push((mark, edited));
            mark
        }

        fn catch_up(&mut self, cpu: u32) {
            let tlb = core::cell::RefCell::new(core::mem::take(&mut self.tlvs[cpu as usize]));
            self.log.catch_up(
                cpu,
                CPUS,
                &mut |start, end| {
                    let mut tlb = tlb.borrow_mut();
                    for page in start / PAGE..end / PAGE {
                        tlb.cached.remove(&page);
                    }
                },
                &mut || {
                    let mut tlb = tlb.borrow_mut();
                    tlb.cached.clear();
                    tlb.flushes += 1;
                },
            );
            self.tlvs[cpu as usize] = tlb.into_inner();
        }

        fn catch_up_everyone(&mut self) {
            for cpu in 0..CPUS {
                self.catch_up(cpu);
            }
        }

        /// The promise: once a request's mark says every CPU has dropped it,
        /// no CPU may still hold a translation older than the edit.
        fn assert_no_stale_translations(&self) {
            for (mark, edited) in &self.requests {
                if !self.log.flushed(*mark, CPUS) {
                    continue;
                }
                for tlb in &self.tlvs {
                    for (page, version) in edited {
                        if let Some(cached) = tlb.cached.get(page) {
                            assert!(
                                cached >= version,
                                "mark {mark:?} was spent while a stale translation of \
                                 page {page} was still cached"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_posted_range_waits_for_every_cpu() {
        let mut machine = Machine::new();
        let mark = machine.edit_and_post(8, 2);
        assert!(matches!(mark, InvalidationMark::Posted(_)));

        machine.catch_up(0);
        // One CPU is not every CPU.
        assert!(!machine.log.flushed(mark, CPUS));
        machine.catch_up(1);
        assert!(!machine.log.flushed(mark, CPUS));
        machine.catch_up(2);
        machine.catch_up(3);
        assert!(machine.log.flushed(mark, CPUS));
        machine.assert_no_stale_translations();

        // The counters say what happened: one request posted, walked once per
        // CPU, nothing left pending and no CPU ahead of another.
        let stats = machine.log.stats(CPUS);
        assert_eq!(stats.postings, 1);
        assert_eq!(stats.walked, CPUS as u64);
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.lag, 0);
        assert_eq!(stats.full_flushes, 0);
    }

    #[test]
    fn a_huge_range_is_flushed_rather_than_walked() {
        let mut machine = Machine::new();
        let mark = machine.edit_and_post(0, FULL_FLUSH_PAGES + 1);
        assert!(matches!(mark, InvalidationMark::Flushed(_)));

        machine.catch_up_everyone();
        assert!(machine.log.flushed(mark, CPUS));
        machine.assert_no_stale_translations();
    }

    #[test]
    fn a_full_log_promotes_instead_of_losing_a_request() {
        let mut machine = Machine::new();
        // Touch the pages every request will be about, so a lost request
        // would show up as a stale translation.
        let mut marks = Vec::new();
        for step in 0..POSTED_SLOTS + 4 {
            let first_page = step % (PAGES - 1);
            for cpu in 0..CPUS {
                machine.touch(cpu, first_page);
            }
            marks.push(machine.edit_and_post(first_page, 1));
        }

        // The log filled up and the requests behind it asked for a flush
        // instead of waiting for room.
        let promoted = marks
            .iter()
            .filter(|mark| matches!(mark, InvalidationMark::Flushed(_)))
            .count();
        assert!(promoted > 0, "the log never filled up");
        assert_eq!(machine.log.stats(CPUS).full_flushes, promoted as u64);
        // The generation is the sequence the marks carry, so one bump per
        // promoted request puts it exactly at the count of them.
        assert_eq!(machine.log.generation(), promoted as u64);

        // One catch-up per CPU honours all of them, including the ones that
        // had to be promoted, without walking what the flush already covered.
        machine.catch_up_everyone();
        for mark in &marks {
            assert!(
                machine.log.flushed(*mark, CPUS),
                "a request was lost when the log filled"
            );
        }
        machine.assert_no_stale_translations();
        let flushes: usize = machine.tlvs.iter().map(|tlb| tlb.flushes).sum();
        assert!(
            flushes <= CPUS as usize,
            "a promoted request cost more than one flush per CPU"
        );
        // The log is drained afterwards, and the burst is what is left of it.
        let stats = machine.log.stats(CPUS);
        assert!(stats.pending <= POSTED_SLOTS as u64);
        assert_eq!(stats.lag, 0);
    }

    /// The mechanism under churn: edits, touches and catch-ups interleaved for
    /// thousands of steps, with the promise checked throughout.
    #[test]
    fn churn_never_leaves_a_stale_translation_behind_a_spent_mark() {
        let mut machine = Machine::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut random = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for step in 0..20_000u64 {
            match random() % 8 {
                0..=2 => {
                    // A CPU uses a page, caching whatever is mapped then.
                    machine.touch((random() % CPUS as u64) as u32, (random() as usize) % PAGES);
                }
                3..=5 => {
                    // A page table is edited and the range posted.
                    let pages = 1 + (random() as usize) % 4;
                    let first_page = (random() as usize) % (PAGES - pages);
                    machine.edit_and_post(first_page, pages);
                }
                6 => {
                    machine.catch_up((random() % CPUS as u64) as u32);
                }
                _ => {
                    // Every CPU catches up; a request whose mark is spent now
                    // has to be stale-free from here on.
                    machine.catch_up_everyone();
                }
            }
            if step % 64 == 0 {
                machine.assert_no_stale_translations();
            }
        }

        machine.catch_up_everyone();
        for (mark, ..) in &machine.requests {
            assert!(
                machine.log.flushed(*mark, CPUS),
                "the churn left a request unhonoured"
            );
        }
        machine.assert_no_stale_translations();
    }
}
