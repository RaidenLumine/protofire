//! src/kernel/power/clock.rs
//!
//! A minimal common-clock framework for CPU frequency control.
//!
//! Real DVFS on ARM/RISC-V is driven by a platform firmware/mailbox interface
//! (SCMI, SBI CPPC, ...) that the kernel does not yet speak; that is a later
//! mailbox-transport milestone.  This module covers the simple device-tree
//! clocks Linux models with `clk-fixed-rate` and `clk-fixed-factor`: a
//! `fixed-clock` holds a constant output rate, and a `fixed-factor-clock`
//! scales a parent clock by `mult / div`.
//!
//! What *uses* those clocks is the platform's business: the driver that reads
//! the device tree's OPP tables lives beside the parser that answers it
//! ([`crate::arch::fdt::cpufreq`]), and this module is only the framework it
//! plugs into.

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
