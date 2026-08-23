//! src/kernel/power/cpufreq_driver.rs
//! CPU frequency driver trait.

use crate::Result;

/// CPU frequency driver trait.
///
/// Architecture-specific drivers (e.g. x86_64 MSR-based P-state control)
/// implement this trait and are exposed to the power-management layer through
/// the `crate::arch::arch_get_freq` family of dispatchers.  Frequencies are
/// expressed in KHz.
pub trait CpuFreqDriver {
    /// Driver name, e.g. `"x86_64 MSR"`.
    fn name(&self) -> &'static str;

    /// Whether this driver can actually scale frequency.  A driver may be
    /// constructed in report-only mode when no writable control path exists.
    fn is_supported(&self) -> bool;

    /// Current core frequency in KHz.
    fn get_current_freq(&self) -> u32;

    /// Request a core frequency in KHz.  The driver clamps to its supported
    /// range.  Returns `Error::Unsupported` in report-only mode.
    fn set_freq(&mut self, freq_khz: u32) -> Result<()>;

    /// (min, max) achievable frequency in KHz, if known.
    fn get_freq_range(&self) -> Option<(u32, u32)>;

    /// Current package temperature in millidegrees Celsius, if readable.
    fn get_temperature_mc(&self) -> Option<u32>;
}
