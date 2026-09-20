//! src/arch/timer.rs
//!
//! Architecture-neutral timer facade used by the scheduler tick path.

/// Return a free-running cycle counter for interval measurement.
///
/// The scheduler tick is 100 Hz, which cannot resolve the durations that
/// matter for lock-hold analysis — a metadata operation is microseconds and a
/// device read is milliseconds, and both are inside one tick.  This reads the
/// per-architecture counter instead, so a caller can measure an interval and
/// scale it with [`cycles_per_second`].
///
/// The counter is monotonic but its rate is not architectural, so a duration
/// is only meaningful after calibration.  Returns `0` where no counter exists
/// (host builds), which makes any measurement that uses it inert rather than
/// wrong.
pub fn monotonic_cycles() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        // SAFETY: `rdtsc` reads the time-stamp counter and has no side effects.
        // It is not serialising, which is the right trade here: the value only
        // feeds a duration histogram, and serialising every sample would cost
        // more than the measurement is worth.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let counter: u64;
        // SAFETY: reading the virtual counter has no side effects.
        unsafe {
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) counter, options(nomem, nostack));
        }
        counter
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let counter: u64;
        // SAFETY: reading the cycle counter has no side effects.
        unsafe {
            core::arch::asm!("rdcycle {}", out(reg) counter, options(nomem, nostack));
        }
        counter
    }

    #[cfg(not(all(
        target_os = "none",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    )))]
    {
        0
    }
}

/// Counters per second, measured once by sampling [`monotonic_cycles`] across a
/// known interval.  Returns `None` until the calibration has run, and on hosts
/// where the counter is absent.
pub fn cycles_per_second() -> Option<u64> {
    match CALIBRATED_CYCLES_PER_SECOND.load(core::sync::atomic::Ordering::Relaxed) {
        0 => None,
        rate => Some(rate),
    }
}

/// Record a calibration: `cycles` elapsed across `ticks` scheduler ticks.
///
/// Callers own the timing; this only stores the ratio.  The first call wins,
/// so a later, noisier sample cannot replace a good one.
///
/// The tick is the reference rather than the second because it is the only
/// clock the kernel has this early, and the scheduler programs it at a known
/// rate.  That rate is nominal, not measured, which is fine for a report whose
/// conclusions are drawn in orders of magnitude.
pub fn record_cycles_per_tick(cycles: u64, ticks: u64) {
    const NOMINAL_TICKS_PER_SECOND: u64 = 100;

    if ticks == 0 || cycles == 0 {
        return;
    }
    let rate = (cycles / ticks) * NOMINAL_TICKS_PER_SECOND;
    let _ = CALIBRATED_CYCLES_PER_SECOND.compare_exchange(
        0,
        rate,
        core::sync::atomic::Ordering::Relaxed,
        core::sync::atomic::Ordering::Relaxed,
    );
}

static CALIBRATED_CYCLES_PER_SECOND: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn init() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    super::aarch64::timer::init();

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    super::riscv64::timer::init();

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    super::x86_64::timer::init();
}

/// Return the current wall-clock time as a Unix timestamp (seconds since
/// 1970-01-01 00:00:00 UTC), or `None` if the RTC is not available.
pub fn rtc_now_unix() -> Option<u64> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        super::aarch64::rtc::rtc_now_unix()
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        super::riscv64::rtc::rtc_now_unix()
    }

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        super::x86_64::rtc::rtc_now_unix()
    }

    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    {
        None
    }
}

pub fn ticks() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        super::aarch64::timer::ticks()
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        super::riscv64::timer::ticks()
    }

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        super::x86_64::timer::ticks()
    }

    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    {
        0
    }
}
