//! src/arch/x86_64/cpufreq.rs
//!
//! x86_64 CPU frequency control via Model-Specific Registers.
//!
//! Implements Intel-style ACPI P-state control: the bus-clock (BCLK) ratio is
//! read from `IA32_PERF_STATUS` (0x198) and requested through `IA32_PERF_CTL`
//! (0x199).  The core frequency in KHz is `ratio × bus_khz`, where `bus_khz`
//! is the bus clock (typically 100 MHz = 100_000 KHz).  On CPUs with HWP,
//! HWP is disabled at init so the legacy `PERF_CTL` path can take over.
//!
//! Detection is conservative: if no reliable frequency information is
//! available (no `IA32_PLATFORM_INFO` ratios and no CPUID leaf 0x16), the
//! driver reports `None` and the power subsystem stays inert.  AMD P-state
//! control (different MSRs) is out of scope; AMD systems are report-only.

use crate::kernel::power::cpufreq_driver::CpuFreqDriver;
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

// ============================================================================
// MSR addresses (Intel)
// ============================================================================

/// IA32_PERF_CTL — bits 15:0 request an operating ratio.
const IA32_PERF_CTL: u32 = 0x199;
/// IA32_PM_ENABLE — bit 0 enables/disables HWP.
const IA32_PM_ENABLE: u32 = 0x770;
/// IA32_PACKAGE_THERM_STATUS — bit 31 valid, bits 22:16 delta below TjMax.
const IA32_PACKAGE_THERM_STATUS: u32 = 0x1C1;
/// IA32_TEMPERATURE_TARGET — bits 23:16 TjMax in °C.
const IA32_TEMPERATURE_TARGET: u32 = 0x1A2;

// The remaining MSRs are only touched on bare metal (reading/writing them
// in host userspace faults with #GP), so they are gated out of host builds.
/// IA32_PERF_STATUS — bits 15:0 hold the current operating ratio.
#[cfg(target_os = "none")]
const IA32_PERF_STATUS: u32 = 0x198;
/// IA32_PLATFORM_INFO — bits 15:8 max non-turbo ratio, bits 45:40 min ratio.
#[cfg(target_os = "none")]
const IA32_PLATFORM_INFO: u32 = 0xCE;

// ============================================================================
// Low-level MSR / CPUID access (bare-metal only)
// ============================================================================

/// Read a Model-Specific Register.
///
/// Bare-metal only: `rdmsr` faults with #GP when executed in ring 3 (e.g.
/// host unit tests).  The power subsystem therefore never runs this code on
/// the host — `detect()` reports no driver there.
#[cfg(target_os = "none")]
#[inline]
fn rdmsr(msr: u32) -> u64 {
    let hi: u32;
    let lo: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write a Model-Specific Register.
#[cfg(target_os = "none")]
#[inline]
fn wrmsr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack)
        );
    }
}

#[cfg(not(target_os = "none"))]
#[inline]
fn rdmsr(_msr: u32) -> u64 {
    0
}

#[cfg(not(target_os = "none"))]
#[inline]
fn wrmsr(_msr: u32, _value: u64) {}

/// Whether the CPU exposes DTS (Digital Thermal Sensor) readings: CPUID
/// leaf 6, EAX bit 0.
#[cfg(target_os = "none")]
#[inline]
fn has_dts() -> bool {
    unsafe { (crate::arch::x86_64::cpuid::cpuid(6, 0).eax & 1) != 0 }
}

#[cfg(not(target_os = "none"))]
#[inline]
fn has_dts() -> bool {
    false
}

/// Whether the CPU supports HWP (Hardware P-states): CPUID leaf 6, ECX bit 7.
///
/// Only relevant inside `detect()` on bare metal; gated out of host builds.
#[cfg(target_os = "none")]
#[inline]
fn hwp_supported_cpu() -> bool {
    unsafe { (crate::arch::x86_64::cpuid::cpuid(6, 0).ecx & (1 << 7)) != 0 }
}

// ============================================================================
// Driver struct
// ============================================================================

/// x86_64 MSR-based CPU frequency driver.
pub struct X86FreqDriver {
    /// Bus clock in KHz — the frequency a single ratio unit represents
    /// (100 MHz BCLK → 100_000).
    bus_khz: u32,
    /// Maximum non-turbo operating ratio.
    max_ratio: u32,
    /// Minimum operating ratio.
    min_ratio: u32,
    /// Most recently observed ratio.
    current_ratio: u32,
    /// Whether `IA32_PERF_CTL` writes are effective (report-only on AMD).
    writable: bool,
    /// Whether HWP is present (gates `IA32_PM_ENABLE` access).
    hwp_supported: bool,
}

impl X86FreqDriver {
    /// Detect and construct the driver.  Returns `None` when the CPU exposes
    /// no usable frequency information or on the host (test) build.
    pub fn detect() -> Option<Self> {
        #[cfg(target_os = "none")]
        {
            let vendor = {
                let res = unsafe { crate::arch::x86_64::cpuid::cpuid(0, 0) };
                let mut v = [0u8; 12];
                v[..4].copy_from_slice(&res.ebx.to_le_bytes());
                v[4..8].copy_from_slice(&res.edx.to_le_bytes());
                v[8..12].copy_from_slice(&res.ecx.to_le_bytes());
                v
            };
            let is_intel = &vendor == b"GenuineIntel";

            let hwp = hwp_supported_cpu();

            // CPUID leaf 0x16 (Processor Frequency Information, Skylake+).
            let freq_info = unsafe { crate::arch::x86_64::cpuid::cpuid(0x16, 0) };
            let has_freq_info = (freq_info.eax & (1 << 31)) != 0;
            let base_mhz = freq_info.eax & 0xFFFF;
            let max_mhz = freq_info.ebx & 0xFFFF;
            let bus_mhz = freq_info.ecx & 0xFFFF;

            let platform_info = rdmsr(IA32_PLATFORM_INFO);
            let platform_max_ratio = ((platform_info >> 8) & 0xFF) as u32;
            let platform_min_ratio = ((platform_info >> 16) & 0xFF) as u32;

            // Derive the bus clock.  A ratio unit is one BCLK period.
            let bus_khz = if bus_mhz != 0 {
                bus_mhz * 1000
            } else if platform_max_ratio != 0 && has_freq_info && max_mhz != 0 {
                max_mhz * 1000 / platform_max_ratio
            } else {
                100_000 // assume a 100 MHz BCLK
            };

            // Resolve the operating ratio range, preferring PLATFORM_INFO.
            let (max_ratio, min_ratio) = if platform_max_ratio != 0 {
                (platform_max_ratio, platform_min_ratio.max(1))
            } else if has_freq_info && max_mhz != 0 && bus_khz != 0 {
                let hi = max_mhz * 1000 / bus_khz;
                let lo = if base_mhz != 0 {
                    base_mhz * 1000 / bus_khz
                } else {
                    1
                };
                (hi.max(1), lo.max(1))
            } else {
                // No reliable frequency information: no scaling support.
                return None;
            };

            let max_ratio = max_ratio.max(1);
            let min_ratio = min_ratio.max(1).min(max_ratio);

            let status = rdmsr(IA32_PERF_STATUS);
            let current_ratio = ((status & 0xFFFF) as u32).max(1).min(max_ratio);

            Some(Self {
                bus_khz,
                max_ratio,
                min_ratio,
                current_ratio,
                writable: is_intel,
                hwp_supported: hwp,
            })
        }
        #[cfg(not(target_os = "none"))]
        {
            None
        }
    }

    /// Disable HWP so the legacy `IA32_PERF_CTL` path controls the ratio.
    /// Safe only when HWP is supported; the MSR does not exist otherwise.
    fn disable_hwp(&self) {
        if self.hwp_supported {
            wrmsr(IA32_PM_ENABLE, 0);
        }
    }
}

impl CpuFreqDriver for X86FreqDriver {
    fn name(&self) -> &'static str {
        "x86_64 MSR"
    }

    fn is_supported(&self) -> bool {
        self.writable && self.max_ratio > 0
    }

    fn get_current_freq(&self) -> u32 {
        #[cfg(target_os = "none")]
        let ratio = ((rdmsr(IA32_PERF_STATUS) & 0xFFFF) as u32).max(1);
        #[cfg(not(target_os = "none"))]
        let ratio = self.current_ratio;
        self.bus_khz.saturating_mul(ratio)
    }

    fn set_freq(&mut self, freq_khz: u32) -> Result<()> {
        if !self.writable {
            return Err(Error::Unsupported);
        }
        if self.bus_khz == 0 {
            return Err(Error::Unsupported);
        }

        let target_ratio = freq_khz.div_ceil(self.bus_khz);
        let clamped = target_ratio.clamp(self.min_ratio, self.max_ratio);

        if clamped != target_ratio {
            crate::println!(
                "[cpufreq] freq {} KHz clamped to {} KHz",
                freq_khz,
                clamped.saturating_mul(self.bus_khz)
            );
        }

        wrmsr(IA32_PERF_CTL, clamped as u64);
        self.current_ratio = clamped;
        Ok(())
    }

    fn get_freq_range(&self) -> Option<(u32, u32)> {
        Some((
            self.min_ratio.saturating_mul(self.bus_khz),
            self.max_ratio.saturating_mul(self.bus_khz),
        ))
    }

    fn get_temperature_mc(&self) -> Option<u32> {
        if !has_dts() {
            return None;
        }
        let tjmax = ((rdmsr(IA32_TEMPERATURE_TARGET) >> 16) & 0xFF) as u32;
        if tjmax == 0 {
            return None;
        }
        let status = rdmsr(IA32_PACKAGE_THERM_STATUS);
        // Bit 31 = valid; bits 22:16 = temperature offset below TjMax.
        if (status & (1 << 31)) == 0 {
            return None;
        }
        let delta = ((status >> 16) & 0x7F) as u32;
        Some(tjmax.saturating_sub(delta).saturating_mul(1000))
    }
}

static X86_FREQ_DRIVER: Mutex<Option<X86FreqDriver>> = Mutex::new(None);

/// Initialise the x86_64 frequency driver.  Idempotent; safe to call once per
/// boot.  On the host build this is a no-op (no driver is ever detected).
pub fn init() {
    let mut guard = X86_FREQ_DRIVER.lock();
    if guard.is_some() {
        return;
    }
    let Some(driver) = X86FreqDriver::detect() else {
        crate::println!("[cpufreq] no x86_64 frequency scaling support");
        return;
    };
    if driver.hwp_supported {
        driver.disable_hwp();
    }
    crate::println!("[cpufreq] x86_64 driver initialized: {}", driver.name());
    if let Some((min, max)) = driver.get_freq_range() {
        crate::println!("[cpufreq] freq range {} - {} KHz", min, max);
    }
    *guard = Some(driver);
}

/// Current core frequency in KHz (0 when no driver is present).
pub fn arch_get_freq() -> u32 {
    let guard = X86_FREQ_DRIVER.lock();
    guard.as_ref().map(|d| d.get_current_freq()).unwrap_or(0)
}

/// Request a core frequency in KHz.
pub fn arch_set_freq(freq_khz: u32) -> Result<()> {
    let mut guard = X86_FREQ_DRIVER.lock();
    match guard.as_mut() {
        Some(driver) => driver.set_freq(freq_khz),
        None => Err(Error::Unsupported),
    }
}

/// (min, max) achievable frequency in KHz.
pub fn arch_get_freq_range() -> Option<(u32, u32)> {
    let guard = X86_FREQ_DRIVER.lock();
    guard.as_ref().and_then(|d| d.get_freq_range())
}

/// Package temperature in millidegrees Celsius.
pub fn arch_get_temperature_mc() -> Option<u32> {
    let guard = X86_FREQ_DRIVER.lock();
    guard.as_ref().and_then(|d| d.get_temperature_mc())
}
