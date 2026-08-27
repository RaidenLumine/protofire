//! src/arch/riscv64/cpufreq.rs
//!
//! RISC-V CPU frequency control from device-tree OPP tables.
//!
//! RISC-V has no architectural CPU-frequency register.  The driver discovers
//! the supported frequency range from the device-tree OPP tables parsed at
//! boot (`operating-points-v2` phandles and legacy `operating-points` tuples —
//! the same sources Linux `cpufreq-dt` consumes on RISC-V boards).  When the
//! device tree also describes the CPU's clock (`clocks` →
//! `fixed-clock`/`fixed-factor-clock`), frequency requests are routed through
//! the common-clock framework ([`crate::kernel::power::clock`]); otherwise
//! `set_freq` records the clamped target the way a userspace governor reports
//! its request.  A programmable SCMI/SBI CPPC backend is a later
//! mailbox-transport milestone.  On QEMU `virt` the DTB ships no OPP table or
//! CPU clock, so this driver stays inert (the same graceful path x86_64 takes
//! on QEMU).

use crate::kernel::power::clock::DtFreqDriver;
use crate::kernel::power::cpufreq_driver::CpuFreqDriver;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

// ============================================================================
// Global singleton
// ============================================================================

static DT_FREQ_DRIVER: Mutex<Option<DtFreqDriver>> = Mutex::new(None);

/// Initialise the RISC-V frequency driver.  Idempotent; safe to call once per
/// boot.  On platforms whose DTB lacks OPP tables (QEMU `virt`) this is a
/// no-op.
pub fn init() {
    let mut guard = DT_FREQ_DRIVER.lock();
    if guard.is_some() {
        return;
    }
    let Some(driver) = DtFreqDriver::detect("riscv64 cpufreq-dt") else {
        crate::println!("[cpufreq] no riscv64 frequency scaling support");
        return;
    };
    crate::println!("[cpufreq] riscv64 driver initialized: {}", driver.name());
    if let Some((min, max)) = driver.get_freq_range() {
        crate::println!("[cpufreq] freq range {} - {} KHz", min, max);
    }
    *guard = Some(driver);
}

// ============================================================================
// Arch interface (forwarded from `crate::arch`)
// ============================================================================

/// Current core frequency in KHz (0 when no driver is present).
pub fn arch_get_freq() -> u32 {
    let guard = DT_FREQ_DRIVER.lock();
    guard.as_ref().map(|d| d.get_current_freq()).unwrap_or(0)
}

/// Request a core frequency in KHz.
pub fn arch_set_freq(freq_khz: u32) -> Result<()> {
    let mut guard = DT_FREQ_DRIVER.lock();
    match guard.as_mut() {
        Some(driver) => driver.set_freq(freq_khz),
        None => Err(Error::Unsupported),
    }
}

/// (min, max) achievable frequency in KHz.
pub fn arch_get_freq_range() -> Option<(u32, u32)> {
    let guard = DT_FREQ_DRIVER.lock();
    guard.as_ref().and_then(|d| d.get_freq_range())
}

/// Package temperature in millidegrees Celsius.
pub fn arch_get_temperature_mc() -> Option<u32> {
    let guard = DT_FREQ_DRIVER.lock();
    guard.as_ref().and_then(|d| d.get_temperature_mc())
}
