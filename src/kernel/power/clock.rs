//! src/kernel/power/clock.rs
//!
//! A minimal common-clock framework for non-x86 CPU frequency control.
//!
//! Real DVFS on ARM/RISC-V is driven by a platform firmware/mailbox interface
//! (SCMI, SBI CPPC, ...) that the kernel does not yet speak; that is a later
//! mailbox-transport milestone.  This module covers the simple device-tree
//! clocks Linux models with `clk-fixed-rate` and `clk-fixed-factor`: a
//! `fixed-clock` holds a constant output rate, and a `fixed-factor-clock`
//! scales a parent clock by `mult / div`.  The CPU frequency driver
//! ([`DtFreqDriver`]) consumes one of these to apply a frequency request from
//! the power-management layer, degrading to report-only mode when the device
//! tree describes no clock.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::sync::Mutex;
use crate::Result;

// ============================================================================
// Clock trait
// ============================================================================

/// A common-clock framework clock.
///
/// Rates are in Hz.  `Send` lets clocks live behind an `Arc` in the global
/// registry.
pub trait Clock: Send {
    /// Stable driver/controller name, e.g. `"cpu"`.
    fn name(&self) -> &'static str;

    /// Current output rate in Hz.
    fn get_rate(&self) -> u64;

    /// Request a new output rate in Hz.
    ///
    /// Fixed clocks accept only their nominal rate; any other target is
    /// [`crate::Error::Unsupported`] because the hardware exposes no
    /// programming interface.  A future SCMI/CPPC-backed clock will accept a
    /// range of rates.
    fn set_rate(&mut self, rate_hz: u64) -> Result<()>;
}

/// A `fixed-clock`: a constant output rate with no programming interface.
pub struct FixedClock {
    name: &'static str,
    rate_hz: u64,
}

impl FixedClock {
    /// Construct a clock with a constant `rate_hz`.
    pub const fn new(name: &'static str, rate_hz: u64) -> Self {
        Self { name, rate_hz }
    }
}

impl Clock for FixedClock {
    fn name(&self) -> &'static str {
        self.name
    }

    fn get_rate(&self) -> u64 {
        self.rate_hz
    }

    fn set_rate(&mut self, rate_hz: u64) -> Result<()> {
        if rate_hz == self.rate_hz {
            Ok(())
        } else {
            Err(crate::Error::Unsupported)
        }
    }
}

/// A `fixed-factor-clock`: scales a parent clock's rate by `mult / div`.
///
/// The parent rate is fixed at construction; the kernel does not yet resolve
/// a chain of programmable parents.
pub struct FixedFactorClock {
    name: &'static str,
    parent_rate_hz: u64,
    mult: u32,
    div: u32,
}

impl FixedFactorClock {
    /// Construct a clock whose output rate is `parent_rate_hz * mult / div`.
    pub const fn new(name: &'static str, parent_rate_hz: u64, mult: u32, div: u32) -> Self {
        Self {
            name,
            parent_rate_hz,
            mult,
            div,
        }
    }
}

impl Clock for FixedFactorClock {
    fn name(&self) -> &'static str {
        self.name
    }

    fn get_rate(&self) -> u64 {
        if self.div == 0 {
            0
        } else {
            self.parent_rate_hz * self.mult as u64 / self.div as u64
        }
    }

    fn set_rate(&mut self, rate_hz: u64) -> Result<()> {
        if rate_hz == self.get_rate() {
            Ok(())
        } else {
            Err(crate::Error::Unsupported)
        }
    }
}

// ============================================================================
// Clock registry
// ============================================================================

/// A handle to a registered clock: the trait object is boxed so the kernel
/// `Mutex` (which requires a sized value) can guard it.
pub type ClockHandle = Arc<Mutex<Box<dyn Clock>>>;

/// Registered clocks, keyed by name.
static CLOCK_REGISTRY: Mutex<Vec<(String, ClockHandle)>> = Mutex::new(Vec::new());

/// Register (or replace) a named clock so other subsystems can resolve it by
/// name.
pub fn register_clock(name: &str, clock: ClockHandle) {
    let mut registry = CLOCK_REGISTRY.lock();
    if let Some(slot) = registry.iter_mut().find(|(n, _)| n.as_str() == name) {
        slot.1 = clock;
    } else {
        registry.push((String::from(name), clock));
    }
}

/// Resolve a registered clock by name.
pub fn get_clock(name: &str) -> Option<ClockHandle> {
    let registry = CLOCK_REGISTRY.lock();
    registry
        .iter()
        .find(|(n, _)| n.as_str() == name)
        .map(|(_, clock)| clock.clone())
}

// ============================================================================
// Shared DT + common-clock CPU frequency driver
// ============================================================================

/// Device-tree OPP + common-clock CPU frequency driver (aarch64 / riscv64).
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
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
    pub fn detect(name: &'static str) -> Option<Self> {
        let info = crate::arch::fdt::platform_info();
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

impl crate::kernel::power::cpufreq_driver::CpuFreqDriver for DtFreqDriver {
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
    use crate::kernel::power::cpufreq_driver::CpuFreqDriver;
    use crate::Error;

    #[test]
    fn fixed_clock_holds_nominal_rate() {
        let mut clock = FixedClock::new("cpu", 1_600_000_000);
        assert_eq!(clock.get_rate(), 1_600_000_000);
        assert!(clock.set_rate(1_600_000_000).is_ok());
        assert_eq!(clock.set_rate(800_000_000), Err(Error::Unsupported));
    }

    #[test]
    fn fixed_factor_clock_scales_parent_rate() {
        let mut clock = FixedFactorClock::new("cpu-f", 100_000_000, 3, 2);
        assert_eq!(clock.get_rate(), 150_000_000);
        assert!(clock.set_rate(150_000_000).is_ok());
        assert_eq!(clock.set_rate(100_000_000), Err(Error::Unsupported));
    }

    #[test]
    fn fixed_factor_clock_rejects_zero_divisor() {
        let clock = FixedFactorClock::new("bad", 100_000_000, 1, 0);
        assert_eq!(clock.get_rate(), 0);
    }

    #[test]
    fn registry_round_trips_by_name() {
        let clock: ClockHandle =
            Arc::new(Mutex::new(Box::new(FixedClock::new("cpu", 1_000_000_000))));
        register_clock("registry-test-cpu", clock.clone());
        let found = get_clock("registry-test-cpu").expect("registered clock");
        assert_eq!(found.lock().get_rate(), 1_000_000_000);
    }

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
