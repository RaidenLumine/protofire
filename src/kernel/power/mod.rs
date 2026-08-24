//! src/kernel/power/mod.rs
//!
//! Power management subsystem: CPU frequency scaling, thermal management.

pub mod cpufreq_driver;
pub mod governors;

#[cfg(test)]
mod tests;

use crate::arch;
use crate::kernel::sync::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Global state
// ============================================================================

/// Current frequency cache (KHz)
static CURRENT_FREQ_KHZ: AtomicU32 = AtomicU32::new(0);

/// Current governor
static CURRENT_GOVERNOR: Mutex<Option<governors::GovernorType>> = Mutex::new(None);

/// Initialize the power management subsystem.
///
/// Probes the arch-level CPU frequency driver and enables the `ondemand`
/// governor by default. On platforms with no discoverable frequency range
/// (QEMU, host tests) the whole subsystem stays inert.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::cpufreq::init();
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::arch::aarch64::cpufreq::init();
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::arch::riscv64::cpufreq::init();
    }

    let freq = arch::arch_get_freq();
    CURRENT_FREQ_KHZ.store(freq, Ordering::Relaxed);

    // Use the OnDemand governor by default.
    set_governor(governors::GovernorType::Ondemand);

    if let Some((min, max)) = arch::arch_get_freq_range() {
        crate::println!(
            "[power ] initialized, freq range {} - {} KHz, current {} KHz",
            min,
            max,
            freq
        );
    } else {
        crate::println!(
            "[power ] initialized, current freq {} KHz (no range info)",
            freq
        );
    }
}

/// Get the current frequency (KHz)
pub fn get_current_freq() -> u32 {
    CURRENT_FREQ_KHZ.load(Ordering::Relaxed)
}

/// Refresh the frequency cache
pub fn update_freq_cache() {
    let freq = arch::arch_get_freq();
    CURRENT_FREQ_KHZ.store(freq, Ordering::Relaxed);
}

/// Get the (min, max) frequency range
pub fn get_freq_range() -> Option<(u32, u32)> {
    arch::arch_get_freq_range()
}

/// Set the governor
pub fn set_governor(gov: governors::GovernorType) {
    let mut guard = CURRENT_GOVERNOR.lock();
    *guard = Some(gov);
    crate::println!("[power ] governor set to {}", gov.name());
}

/// Get the current governor
pub fn get_governor() -> Option<governors::GovernorType> {
    *CURRENT_GOVERNOR.lock()
}

/// Run a policy update (called periodically from the scheduler tick).
///
/// `load` is the CPU load percentage in 0..=100. On platforms without
/// frequency scaling support (no range to query) this returns immediately,
/// avoiding repeated warnings.
pub fn update_policy(load: u8) {
    let Some((min_freq, max_freq)) = get_freq_range() else {
        return;
    };

    let gov = *CURRENT_GOVERNOR.lock();
    let Some(gov_type) = gov else { return };

    // The Userspace governor never scales automatically
    if matches!(gov_type, governors::GovernorType::Userspace) {
        return;
    }

    let current = get_current_freq();
    let Some(new_freq) = governors::calculate_target(gov_type, load, min_freq, max_freq, current)
    else {
        return;
    };
    if new_freq == current {
        return;
    }

    if let Err(e) = arch::arch_set_freq(new_freq) {
        crate::println!("[power ] failed to set freq {} KHz: {:?}", new_freq, e);
    } else {
        CURRENT_FREQ_KHZ.store(new_freq, Ordering::Relaxed);
        crate::println!(
            "[power ] freq {} -> {} KHz (load={}%)",
            current,
            new_freq,
            load
        );
    }
}

/// Get the CPU temperature (millidegrees Celsius)
pub fn get_temperature_mc() -> Option<u32> {
    arch::arch_get_temperature_mc()
}
