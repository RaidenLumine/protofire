//! src/arch/timer.rs
//! Architecture-neutral timer facade used by the scheduler tick path.

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
