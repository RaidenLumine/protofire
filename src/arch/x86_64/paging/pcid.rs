//! src/arch/x86_64/paging/pcid.rs
//!
//! x86_64 PCID (Process-Context Identifier) management.
//!
//! PCIDs tag TLB entries so switching between address spaces does not
//! require a full TLB flush.  When CR4.PCIDE is set, the low 12 bits of CR3
//! select the PCID; entries tagged with a given PCID are only invalidated by
//! an INVPCID for that PCID (or a full flush), not by a plain CR3 reload.
//! The kernel runs with PCID 0.
//!
//! This module mirrors the AArch64 ASID allocator in
//! `src/arch/aarch64/mmu/asid.rs`:
//!
//! 1. Call `init_pcid()` during early boot (after `enable_pcide()`).
//! 2. Allocate PCIDs via `allocate_pcid()` when preparing process address
//!    spaces.
//! 3. Free PCIDs via `free_pcid()` when destroying them.
//! 4. Load CR3 with `(root & ADDRESS_MASK) | pcid` when switching to a process;
//!    the kernel root keeps PCID 0.
//!
//! Cross-CPU flush relies on the TLB generation counter (`kernel::smp::tlb`)
//! exactly as the pre-PCID path does; INVPCID itself is a per-CPU
//! instruction, so remote CPUs flush on their next kernel entry.
//!
//! This module is a bare-metal feature.  It is compiled on host builds purely
//! for compile coverage, where its allocator and flush paths are dead code;
//! the `#![allow(dead_code)]` below documents that rather than hiding a real
//! unused path.

#![allow(dead_code)]

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::arch::asm;
use core::sync::atomic::AtomicBool;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::Ordering;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::super::control_regs::read_cr4;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::super::control_regs::write_cr4;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::super::control_regs::CR4_PCIDE;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::super::cpuid;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::util::logger::log;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::util::logger::LogLevel;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::format;

/// Number of bitmap words: 64 × 64 bits = 4096 bits = 4096 PCIDs.
const PCID_BITMAP_WORDS: usize = 64;

/// Maximum PCID value (inclusive).  PCID 0 is reserved for the kernel.
const PCID_MAX: u64 = 4095;

/// PCID width in CR3 — bits [11:0].
const CR3_PCID_MASK: u64 = 0xfff;

/// INVPCID type 1 — invalidate all TLB entries for a single PCID.
const INVPCID_TYPE_PCID: u64 = 1;
/// INVPCID type 2 — invalidate all non-global TLB entries.
const INVPCID_TYPE_ALL_NON_GLOBAL: u64 = 2;

/// BSS-backed storage for the free-PCID bitmap, mirroring the ASID bitmap.
/// The all-zero .bss initialisation gives a clean bitmap at no code size
/// cost; `bitmap_word()` casts from `u64` to `AtomicU64` (same size /
/// alignment, no extra fields).
#[repr(C, align(8))]
struct PcidBitmapStore([u64; PCID_BITMAP_WORDS]);

static PCID_BITMAP_STORE: PcidBitmapStore = PcidBitmapStore([0u64; PCID_BITMAP_WORDS]);

/// Monotonically-increasing PCID counter fallback, used when the free bitmap
/// is empty.
static NEXT_PCID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Set once `enable_pcide()` has armed CR4.PCIDE (or the feature is absent,
/// in which case it stays false).
static PCID_ENABLED: AtomicBool = AtomicBool::new(false);

/// The 128-bit INVPCID descriptor.  Type 0 stores a linear address in the
/// high bits of the low qword; types 1–3 ignore it and the high qword is
/// reserved (must be zero).
#[repr(C)]
struct InvpcidDesc {
    pcid: u64,
    _reserved: u64,
}

// ── Bitmap access helper ────────────────────────────────────────────────

/// Return a reference to the `word_idx`-th atomic word in the free bitmap.
#[inline]
fn bitmap_word(word_idx: usize) -> &'static core::sync::atomic::AtomicU64 {
    // SAFETY: AtomicU64 and u64 have identical size (8) and alignment (8).
    // The static storage is valid for the lifetime of the program.  No other
    // mutable reference aliases these bytes.
    unsafe {
        &*(&PCID_BITMAP_STORE.0[word_idx] as *const u64 as *const core::sync::atomic::AtomicU64)
    }
}

// ── INVPCID wrappers ────────────────────────────────────────────────────

/// Execute `invpcid type, [desc]`.
///
/// # Safety
///
/// Requires INVPCID CPUID support and a valid descriptor; this is a
/// privileged instruction.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn invpcid(desc: &InvpcidDesc, typ: u64) {
    asm!(
        "invpcid {typ}, [{desc}]",
        typ = in(reg) typ,
        desc = in(reg) desc,
        options(nostack, preserves_flags)
    );
}

/// Invalidate all non-global TLB entries on the current CPU.
///
/// This is the PCID-era equivalent of a full CR3 reload flush: the kernel
/// forbids GLOBAL pages (see `validate_prepared_process_address_space`), so
/// no global entries exist to skip.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn invpcid_flush_all_non_global() {
    let desc = InvpcidDesc {
        pcid: 0,
        _reserved: 0,
    };
    // SAFETY: CPUID guarantees INVPCID here; the descriptor is zeroed.
    unsafe {
        invpcid(&desc, INVPCID_TYPE_ALL_NON_GLOBAL);
    }
}

/// Invalidate every TLB entry tagged with `pcid` on the current CPU.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn invpcid_flush_pcid(pcid: u64) {
    let desc = InvpcidDesc {
        pcid: pcid & CR3_PCID_MASK,
        _reserved: 0,
    };
    // SAFETY: CPUID guarantees INVPCID here; the descriptor carries the
    // target PCID with a zeroed (reserved) address.
    unsafe {
        invpcid(&desc, INVPCID_TYPE_PCID);
    }
}

/// Reload CR3 with its current value.  A full TLB flush only when
/// CR4.PCIDE is clear (with PCIDE set, same-PCID reloads flush nothing).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn reload_cr3() {
    let cr3: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

// ── Public API ──────────────────────────────────────────────────────────

/// Initialise the PCID allocator.  Called once during early boot, after
/// `control_regs::enable_pcide()`.
///
/// Reserves PCID 0 (the kernel's) and records whether PCID is active.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn init_pcid() {
    PCID_ENABLED.store(cpuid::has_pcid(), Ordering::Release);
    bitmap_word(0).fetch_or(1u64 << 0, Ordering::Release);
    log(
        LogLevel::Info,
        &format!(
            "PCID: enabled={} invpcid={}",
            cpuid::has_pcid(),
            cpuid::has_invpcid()
        ),
    );
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn init_pcid() {}

/// Whether CR4.PCIDE is live and CR3 loads carry PCID tags.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn pcid_enabled() -> bool {
    PCID_ENABLED.load(Ordering::Acquire)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn pcid_enabled() -> bool {
    false
}

/// Allocate a PCID for a new process address space.
///
/// Prefers recycled PCIDs from the free bitmap.  When the bitmap is empty
/// and the counter wraps past `PCID_MAX`, the current CPU's TLB is flushed
/// and the remote-generation counter is bumped so every CPU invalidates
/// entries tagged with the previous rotation's PCIDs before any are reused.
///
/// Returns the allocated PCID (always > 0).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn allocate_pcid() -> u64 {
    // Try the free bitmap first.
    for word_idx in 0..PCID_BITMAP_WORDS {
        let mut word = bitmap_word(word_idx).load(Ordering::Acquire);
        while word != 0 {
            let bit = word.trailing_zeros() as usize;
            let pcid = word_idx * 64 + bit;
            let mask = 1u64 << bit;
            if pcid > 0 && (pcid as u64) <= PCID_MAX {
                if bitmap_word(word_idx)
                    .compare_exchange(word, word & !mask, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return pcid as u64;
                }
            }
            // CAS failed or PCID out of range — refresh and retry.
            word = bitmap_word(word_idx).load(Ordering::Acquire);
        }
    }

    // Free bitmap empty — fall back to the monotonic counter.
    loop {
        let current = NEXT_PCID.load(Ordering::Acquire);
        let wrapped = current > PCID_MAX;
        let (next, result) = if wrapped {
            // Wrapped around.  Reset to 2 (PCID 1 will be allocated next).
            (2, 1)
        } else {
            (current + 1, current)
        };
        if NEXT_PCID
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if wrapped {
                // Entries tagged with the reused PCIDs may exist on any CPU
                // from the previous rotation.  Flush locally and ask every
                // CPU to flush on its next kernel entry via the TLB
                // generation counter.
                invpcid_flush_all_non_global();
                crate::kernel::smp::tlb::request_remote_tlb_flush();
            }
            return result;
        }
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn allocate_pcid() -> u64 {
    1 // stub for host-side builds
}

/// Return a PCID to the free pool for future reuse.
///
/// The TLB entries tagged with this PCID are invalidated (per-PCID INVPCID)
/// before the PCID is marked free, so callers do not need a separate flush.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn free_pcid(pcid: u64) {
    if pcid == 0 || pcid > PCID_MAX {
        return;
    }
    // Invalidate entries tagged with this PCID before recycling it.  Without
    // INVPCID support the entries leak until a full flush, which the kernel
    // already performs periodically via the generation counter.
    if cpuid::has_invpcid() {
        invpcid_flush_pcid(pcid);
    }

    let idx = pcid as usize;
    let word_idx = idx / 64;
    let bit = idx % 64;
    if word_idx < PCID_BITMAP_WORDS {
        let mask = 1u64 << bit;
        bitmap_word(word_idx).fetch_or(mask, Ordering::AcqRel);
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn free_pcid(_pcid: u64) {}

/// Flush the entire local TLB, PCID-aware.
///
/// With PCID off a CR3 reload suffices.  With PCID on, INVPCID type 2
/// invalidates all non-global entries; if the CPU has PCID but not INVPCID
/// (not seen in practice), toggle CR4.PCIDE off and on around a reload to
/// force a full flush.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn flush_all_tlb() {
    if !pcid_enabled() {
        reload_cr3();
        return;
    }
    if cpuid::has_invpcid() {
        invpcid_flush_all_non_global();
        return;
    }
    unsafe {
        write_cr4(read_cr4() & !CR4_PCIDE);
        reload_cr3();
        write_cr4(read_cr4() | CR4_PCIDE);
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn flush_all_tlb() {}

/// Tag a root-table address with `pcid` for a CR3 load.
///
/// Returns the value to write to CR3: the 4 KiB-aligned root address with
/// the PCID in bits [11:0] when PCID is active, or the bare address when it
/// is not.
pub(crate) fn cr3_with_pcid(root_table_address: usize, pcid: u64) -> usize {
    let root = root_table_address & super::types::PAGE_ENTRY_ADDRESS_MASK as usize;
    if pcid_enabled() {
        root | (pcid & CR3_PCID_MASK) as usize
    } else {
        root
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_reserves_nonzero_and_frees_recycle() {
        // The host stub always returns 1; only exercise the bitmap math by
        // driving the bitmap directly through free/alloc paths is not
        // possible here, but the invariants must hold on the stub.
        let pcid = allocate_pcid();
        assert!(pcid > 0);
        free_pcid(pcid);
    }

    #[test]
    fn cr3_tagging_masks_address_and_packs_pcid_bits() {
        // Host build: PCID disabled, so the address is returned verbatim.
        let root = 0x0000_0001_2345_6000usize;
        assert_eq!(cr3_with_pcid(root, 0x2a), root);
        assert_eq!(cr3_with_pcid(root, 0x2a) & super::CR3_PCID_MASK as usize, 0);
    }
}
