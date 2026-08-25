//! src/arch/riscv64/mmu/asid.rs
//!
//! RISC-V 64 ASID (Address Space ID) management.
//!
//! ASIDs tag TLB entries so that switching between user address spaces
//! does not require a full TLB flush. The kernel runs with ASID 0.
//!
//! SATP format: [63:60] = MODE, [59:44] = ASID, [43:0] = PPN
//! The ASID field is 16 bits wide, supporting up to 65536 unique ASIDs.
//!
//! Usage:
//! 1. Call `init_asid()` once during early boot.
//! 2. Allocate ASIDs via `allocate_asid()` when creating address spaces.
//! 3. Free ASIDs via `free_asid()` when destroying address spaces.
//! 4. Use `satp_with_asid(ppn, asid)` to construct SATP register values.

use core::arch::asm;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

/// Number of bitmap words: 1024 × 64 bits = 65536 bits = 65536 ASIDs.
const ASID_BITMAP_WORDS: usize = 1024;

/// Maximum ASID value (inclusive). ASID 0 is reserved for the kernel.
const ASID_MAX: u64 = 65535;

/// BSS-backed storage for the free-ASID bitmap. The all-zero .bss
/// initialisation gives us a clean bitmap at no code size cost.
///
/// We access elements through `bitmap_word()` which casts from `u64` to
/// `AtomicU64` — both have identical size / alignment and `AtomicU64` adds
/// no extra fields, so the cast is safe.
#[repr(C, align(8))]
struct AsidBitmapStore([u64; ASID_BITMAP_WORDS]);

static ASID_BITMAP_STORE: AsidBitmapStore = AsidBitmapStore([0u64; ASID_BITMAP_WORDS]);

/// Monotonically-increasing ASID counter fallback. Used only when the free
/// bitmap is empty.
static NEXT_ASID: AtomicU64 = AtomicU64::new(1);

// ── Bitmap access helper ────────────────────────────────────────────────

/// Return a reference to the `word_idx`-th atomic word in the free bitmap.
#[inline]
fn bitmap_word(word_idx: usize) -> &'static AtomicU64 {
    // SAFETY: AtomicU64 and u64 have identical size (8) and alignment (8).
    // The static storage is valid for the lifetime of the program.  No other
    // mutable reference aliases these bytes.
    unsafe { &*(&ASID_BITMAP_STORE.0[word_idx] as *const u64 as *const AtomicU64) }
}

// ── Public API ──────────────────────────────────────────────────────────

/// Initialise the ASID allocator. Called once during early boot.
///
/// On RISC-V the SATP ASID field is fixed at 16 bits — no feature register
/// needs to be probed.  The bitmap and counter are already zeroed / set to
/// sensible defaults by their static initialisers.
#[allow(dead_code)]
pub(crate) fn init_asid() {
    // Reserve ASID 0 for the kernel in the bitmap.
    bitmap_word(0).fetch_or(1u64 << 0, Ordering::Release);
    // NEXT_ASID starts at 1 (ASID 0 is reserved for the kernel).
}

/// Allocate an ASID for a new address space.
///
/// Prefers recycled ASIDs from the free bitmap.  When the bitmap is empty
/// and the counter wraps past `ASID_MAX`, the caller should perform a full
/// TLB flush (`sfence.vma x0, x0`) to invalidate entries tagged with the
/// previous rotation's ASID values.
///
/// Returns the allocated ASID (always > 0). Returns 0 only if the allocator
/// is not yet initialised (should not happen in practice).
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) fn allocate_asid() -> u64 {
    // Try the free bitmap first.
    for word_idx in 0..ASID_BITMAP_WORDS {
        let mut word = bitmap_word(word_idx).load(Ordering::Acquire);
        while word != 0 {
            let bit = word.trailing_zeros() as usize;
            let asid = word_idx * 64 + bit;
            let mask = 1u64 << bit;
            if asid > 0 && (asid as u64) <= ASID_MAX {
                if bitmap_word(word_idx)
                    .compare_exchange(word, word & !mask, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return asid as u64;
                }
            }
            // CAS failed or ASID out of range — refresh and retry.
            word = bitmap_word(word_idx).load(Ordering::Acquire);
        }
    }

    // Free bitmap empty — fall back to the monotonic counter.
    // Use a CAS loop to atomically handle wrap-around: only one thread
    // resets the counter, and duplicate ASID 1 is impossible.
    loop {
        let current = NEXT_ASID.load(Ordering::Acquire);
        let (next, result) = if current > ASID_MAX {
            // Wrapped around. Reset to 2 (ASID 1 will be allocated next).
            (2, 1)
        } else {
            (current + 1, current)
        };
        if NEXT_ASID
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return result;
        }
    }
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub(crate) fn allocate_asid() -> u64 {
    0 // stub for host-side builds
}

/// Return an ASID to the free pool for future reuse.
///
/// The TLB entries tagged with this ASID are flushed before the ASID is
/// marked free, so callers do not need to issue a separate `sfence.vma`.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) fn free_asid(asid: u64) {
    if asid == 0 || asid > ASID_MAX {
        return;
    }

    // Flush TLB entries tagged with this ASID before recycling it.
    sfence_asid(asid);

    let idx = asid as usize;
    let word_idx = idx / 64;
    let bit = idx % 64;
    if word_idx < ASID_BITMAP_WORDS {
        let mask = 1u64 << bit;
        bitmap_word(word_idx).fetch_or(mask, Ordering::AcqRel);
    }
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub(crate) fn free_asid(_asid: u64) {}

/// Construct a SATP register value from a root page table physical page
/// number (PPN) and an ASID.
///
/// SATP format: [63:60]=MODE, [59:44]=ASID, [43:0]=PPN
/// MODE_SV39 = 8
pub(crate) fn satp_with_asid(ppn: u64, asid: u64) -> u64 {
    let mode = 8u64 << 60; // Sv39
    let asid_field = (asid & 0xFFFF) << 44;
    let ppn_field = ppn & 0x0000_0FFF_FFFF_FFFF;
    mode | asid_field | ppn_field
}

/// Flush TLB entries tagged with the given ASID.
///
/// Uses `sfence.vma x0, rs2` to invalidate only entries whose ASID matches
/// `asid`, leaving entries for other ASIDs intact.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) fn sfence_asid(asid: u64) {
    unsafe {
        asm!(
            "sfence.vma zero, {asid}",
            asid = in(reg) asid,
            options(nostack, preserves_flags)
        );
    }
}
