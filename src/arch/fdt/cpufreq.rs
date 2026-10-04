//! src/arch/fdt/cpufreq.rs
//!
//! The CPU frequency driver the device tree describes.
//!
//! It lives beside the parser that answers it rather than in
//! [`crate::kernel::power`]: what it reads — an OPP range, a
//! `fixed-clock`/`fixed-factor-clock` behind the CPU — is device-tree data, and
//! a machine without a device tree has nothing here to answer with.  The
//! generic half it plugs into is [`crate::kernel::power::cpufreq_driver`], and
//! the clocks it routes through are
//! [`crate::kernel::power::clock::Clock`].

use alloc::boxed::Box;

use super::platform_info;
use crate::kernel::power::clock::Clock;
use crate::kernel::power::clock::FixedClock;
use crate::kernel::power::cpufreq_driver::CpuFreqDriver;
use crate::Result;

/// CPU frequency driver backed by the device tree.
///
/// Discovers the supported range from the FDT OPP tables and, when present, a
/// `fixed-clock`/`fixed-factor-clock` backing the CPU.  With a clock wired,
/// `set_freq` routes the clamped target through the common-clock framework;
/// without one the driver records the clamped target in software (report-only,
/// the same graceful path x86_64 takes for unsupported P-states).
pub struct DtFreqDriver {
    name: &'static str,
    min_khz: u32,
    max_khz: u32,
    /// Programmable clock backing the request.  `None` in report-only mode.
    clock: Option<Box<dyn Clock>>,
    /// Last-requested frequency in KHz (report-only tracking).
    current_khz: u32,
}

impl DtFreqDriver {
    /// Construct a driver from the OPP range and an optional backing clock.
    pub fn new(
        name: &'static str,
        min_khz: u32,
        max_khz: u32,
        clock: Option<Box<dyn Clock>>,
    ) -> Self {
        Self {
            name,
            min_khz,
            max_khz,
            clock,
            current_khz: max_khz,
        }
    }

    /// Detect and construct the driver from FDT OPP/clock data.
    ///
    /// Returns `None` when the device tree describes neither an OPP range nor
    /// a CPU clock (e.g. QEMU `virt`, which ships neither).  A lone CPU clock
    /// is treated as a single-point range.
    pub fn detect(name: &'static str) -> Option<Self> {
        let info = platform_info();
        let clock = info
            .cpu_clock_rate_hz
            .map(|hz| Box::new(FixedClock::new("cpu", hz)) as Box<dyn Clock>);
        let (min_hz, max_hz) = match (
            info.cpu_freq_min_hz,
            info.cpu_freq_max_hz,
            info.cpu_clock_rate_hz,
        ) {
            (Some(min), Some(max), _) if min > 0 && max >= min => (min, max),
            (None, None, Some(rate)) if rate > 0 => (rate, rate),
            _ => return None,
        };
        let min_khz = u32::try_from(min_hz / 1000).ok()?;
        let max_khz = u32::try_from(max_hz / 1000).ok()?;
        if min_khz == 0 || max_khz < min_khz {
            return None;
        }
        Some(Self::new(name, min_khz, max_khz, clock))
    }
}

impl CpuFreqDriver for DtFreqDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn is_supported(&self) -> bool {
        // A fixed clock answers `set_rate` only at its nominal rate; true
        // scaling waits for a programmable SCMI/CPPC backend.
        self.clock.is_some()
    }

    fn get_current_freq(&self) -> u32 {
        match &self.clock {
            Some(clock) => (clock.get_rate() / 1000) as u32,
            None => self.current_khz,
        }
    }

    fn set_freq(&mut self, freq_khz: u32) -> Result<()> {
        let target = freq_khz.clamp(self.min_khz, self.max_khz);
        match &mut self.clock {
            Some(clock) => {
                clock.set_rate(u64::from(target) * 1000)?;
                self.current_khz = target;
                Ok(())
            }
            None => {
                self.current_khz = target;
                Ok(())
            }
        }
    }

    fn get_freq_range(&self) -> Option<(u32, u32)> {
        Some((self.min_khz, self.max_khz))
    }

    fn get_temperature_mc(&self) -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn dt_freq_driver_routes_fixed_clock() {
        let mut driver = DtFreqDriver::new(
            "test cpufreq-dt",
            1_280_000,
            1_600_000,
            Some(Box::new(FixedClock::new("cpu", 1_500_000_000))),
        );
        assert!(driver.is_supported());
        // A fixed clock refuses any non-nominal target.
        assert_eq!(driver.set_freq(1_400_000), Err(Error::Unsupported));
        // The nominal rate through the clamp succeeds.
        assert!(driver.set_freq(1_500_000).is_ok());
        assert_eq!(driver.get_current_freq(), 1_500_000);
        assert_eq!(driver.get_freq_range(), Some((1_280_000, 1_600_000)));
    }

    #[test]
    fn dt_freq_driver_report_only_clamps_without_clock() {
        let mut driver = DtFreqDriver::new("test cpufreq-dt", 1_280_000, 1_600_000, None);
        assert!(!driver.is_supported());
        assert!(driver.set_freq(1_400_000).is_ok());
        assert_eq!(driver.get_current_freq(), 1_400_000);
        // Clamped into the supported range.
        assert!(driver.set_freq(99_999).is_ok());
        assert_eq!(driver.get_current_freq(), 1_280_000);
    }

    #[test]
    fn dt_freq_driver_detect_is_inert_without_dt_data() {
        // The host platform-info default carries no OPP range and no clock,
        // mirroring QEMU virt: detection must be a graceful no-op.
        assert!(DtFreqDriver::detect("test cpufreq-dt").is_none());
    }
}
