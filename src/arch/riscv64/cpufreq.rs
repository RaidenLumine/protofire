//! src/arch/riscv64/cpufreq.rs
//!
//! RISC-V CPU frequency control from device-tree OPP tables.
//!
//! RISC-V has no architectural CPU-frequency register.  This driver discovers
//! the supported frequency range from the device-tree OPP tables parsed at
//! boot (`operating-points-v2` phandles and legacy `operating-points`
//! tuples — the same sources Linux `cpufreq-dt` consumes on RISC-V boards)
//! and tracks the requested frequency in software.  Applying the request on
//! real hardware requires a platform clock/firmware interface (SCMI, the
//! common-clock framework, SBI CPPC, ...) which the kernel does not drive
//! yet, so `set_freq` records the clamped target the way a userspace governor
//! reports its request.  On QEMU `virt` the DTB ships no OPP table, so this
//! driver stays inert (the same graceful path x86_64 takes on QEMU).

use crate::kernel::power::cpufreq_driver::CpuFreqDriver;
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

// ============================================================================
// Driver struct
// ============================================================================

/// Device-tree OPP-based CPU frequency driver.
///
/// Frequencies are in KHz.  `current_khz` is the last-requested target,
/// initialised to the maximum OPP — firmware typically boots near the top of
/// the OPP range.
pub struct DtFreqDriver {
    /// Minimum achievable frequency in KHz.
    min_khz: u32,
    /// Maximum achievable frequency in KHz.
    max_khz: u32,
    /// Last-requested frequency in KHz.
    current_khz: u32,
}

impl DtFreqDriver {
    /// Detect and construct the driver from FDT OPP data.  Returns `None`
    /// when the device tree describes no CPU frequency range (e.g. QEMU
    /// `virt`, which ships no OPP table).
    pub fn detect() -> Option<Self> {
        let info = crate::arch::fdt::platform_info();
        let min_hz = info.cpu_freq_min_hz?;
        let max_hz = info.cpu_freq_max_hz?;
        if min_hz == 0 || max_hz < min_hz {
            return None;
        }
        let min_khz = u32::try_from(min_hz / 1000).ok()?;
        let max_khz = u32::try_from(max_hz / 1000).ok()?;
        if min_khz == 0 || max_khz <= min_khz {
            return None;
        }
        Some(Self {
            min_khz,
            max_khz,
            current_khz: max_khz,
        })
    }
}

impl CpuFreqDriver for DtFreqDriver {
    fn name(&self) -> &'static str {
        "riscv64 cpufreq-dt"
    }

    fn is_supported(&self) -> bool {
        true
    }

    fn get_current_freq(&self) -> u32 {
        self.current_khz
    }

    fn set_freq(&mut self, freq_khz: u32) -> Result<()> {
        self.current_khz = freq_khz.clamp(self.min_khz, self.max_khz);
        Ok(())
    }

    fn get_freq_range(&self) -> Option<(u32, u32)> {
        Some((self.min_khz, self.max_khz))
    }

    fn get_temperature_mc(&self) -> Option<u32> {
        None
    }
}

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
    let Some(driver) = DtFreqDriver::detect() else {
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
