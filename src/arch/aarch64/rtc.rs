//! src/arch/aarch64/rtc.rs
//! PL031 Real-Time Clock driver for AArch64 (QEMU `virt` platform).
//!
//! The PrimeCell PL031 RTC is a simple MMIO device that provides a 32-bit
//! seconds-since-epoch counter at offset 0x00.  On QEMU `virt` machines it
//! resides at `0x0901_0000` and is described in the FDT as
//! `compatible = "arm,pl031"`.
//!
//! ## References
//!
//! - ARM PrimeCell RTC (PL031) Technical Reference Manual (DDI 0224)
//! - QEMU `hw/rtc/pl031.c`

// ---------------------------------------------------------------------------
// PL031 register offsets (from base)
// ---------------------------------------------------------------------------

/// Data register — reads return the current time in seconds since epoch.
const PL031_DR: usize = 0x00;

// ---------------------------------------------------------------------------
// QEMU `virt` default base address (fallback when FDT is unavailable)
// ---------------------------------------------------------------------------

/// Default PL031 base address on QEMU `virt` (discovered via FDT at boot).
pub const PL031_QEMU_VIRT_BASE: usize = 0x0901_0000;

/// Global PL031 base address, set during early boot.
static RTC_BASE: crate::util::sync_unsafe_cell::SyncUnsafeCell<Option<usize>> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Store the PL031 base address for later reads.  Called during boot after
/// FDT parsing (or with the QEMU `virt` hardcoded fallback).
pub fn init_rtc(base: usize) {
    unsafe { RTC_BASE.write(Some(base)) };
}

/// Return the base address of the PL031, if initialised.
fn rtc_base() -> Option<usize> {
    unsafe { RTC_BASE.read() }
}

/// Read the current Unix timestamp (seconds since 1970-01-01 UTC) from the
/// PL031 RTC.
///
/// Returns `None` if the RTC has not been initialised or the MMIO read
/// returns an implausible value (zero is treated as "not set" by some
/// firmware — see the note below).
///
/// # Safety
///
/// `rtc_base()` must point to a valid, mapped PL031 MMIO region.
pub fn rtc_now_unix() -> Option<u64> {
    let base = rtc_base()?;
    // SAFETY: `base` is verified to be valid MMIO during initialisation.
    let seconds: u32 = unsafe { core::ptr::read_volatile((base + PL031_DR) as *const u32) };
    // If the RTC has never been set by firmware, it may read 0.  Treat 0
    // as "not available" — firmware typically sets the RTC to a valid
    // epoch value during boot.
    if seconds == 0 {
        return None;
    }
    Some(seconds as u64)
}
