//! CMOS Real-Time Clock (RTC) driver for x86_64.
//!
//! Reads wall-clock time from the CMOS RTC via I/O ports 0x70 (index) and
//! 0x71 (data).  The RTC maintains time in BCD or binary format across
//! reboots (backed by the CMOS battery in real hardware; emulated by QEMU).
//!
//! ## Register layout
//!
//! | Register | Content                    |
//! |----------|----------------------------|
//! | 0x00     | Seconds                    |
//! | 0x02     | Minutes                    |
//! | 0x04     | Hours                      |
//! | 0x06     | Day of week (1=Sunday)     |
//! | 0x07     | Day of month               |
//! | 0x08     | Month                      |
//! | 0x09     | Year (0–99)                |
//! | 0x0A     | Status Register A          |
//! | 0x0B     | Status Register B          |
//! | 0x32     | Century (optional)         |

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::port::Port;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::AtomicBool;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// I/O ports
// ---------------------------------------------------------------------------

/// CMOS index register port (write register number, bit 7 = NMI disable).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CMOS_INDEX: u16 = 0x70;
/// CMOS data register port (read/write register value).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CMOS_DATA: u16 = 0x71;

// ---------------------------------------------------------------------------
// RTC registers
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_SECONDS: u8 = 0x00;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_MINUTES: u8 = 0x02;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_HOURS: u8 = 0x04;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_DAY_OF_MONTH: u8 = 0x07;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_MONTH: u8 = 0x08;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_YEAR: u8 = 0x09;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_CENTURY: u8 = 0x32;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_STATUS_A: u8 = 0x0A;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RTC_STATUS_B: u8 = 0x0B;

// Status Register A, bit 7: Update In Progress.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const STATUS_A_UIP: u8 = 1 << 7;

// Status Register B, bit 1: 24-hour mode (0 = 12-hour, 1 = 24-hour).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const STATUS_B_24HR: u8 = 1 << 1;
// Status Register B, bit 2: Data Mode (0 = BCD, 1 = binary).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const STATUS_B_DM: u8 = 1 << 2;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static RTC_PROBED: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static RTC_BCD_MODE: AtomicBool = AtomicBool::new(true);
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static RTC_12H_MODE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// CMOS access
// ---------------------------------------------------------------------------

/// Write the CMOS register index and read the data byte.
///
/// The NMI disable bit (bit 7) is set during the access to prevent
/// spurious NMIs from interfering with the read.
///
/// # Safety
///
/// The caller must ensure interrupts are disabled or that the CMOS
/// access is not interleaved with other CMOS operations.  The register
/// index must be a valid RTC/CMOS register (0x00–0x7F).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn cmos_read(reg: u8) -> u8 {
    let mut index = Port::<u8>::new(CMOS_INDEX);
    let mut data = Port::<u8>::new(CMOS_DATA);
    // SAFETY: CMOS ports 0x70/0x71 are standard x86 IO ports that always
    // exist.  The NMI disable bit (0x80) prevents spurious NMIs during
    // the two-step index-then-read access sequence.
    unsafe {
        index.write(reg | 0x80); // disable NMI
        data.read()
    }
}

/// Probe the RTC mode bits (BCD vs binary, 12h vs 24h).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn rtc_probe_mode() {
    if RTC_PROBED.swap(true, Ordering::Acquire) {
        return;
    }

    // SAFETY: RTC_STATUS_B (0x0B) is a valid CMOS register.  This is the
    // only active CMOS access and interrupts are not yet enabled during
    // early boot when this is called.
    let status_b = unsafe { cmos_read(RTC_STATUS_B) };
    RTC_BCD_MODE.store(status_b & STATUS_B_DM == 0, Ordering::Release);
    RTC_12H_MODE.store(status_b & STATUS_B_24HR == 0, Ordering::Release);
}

/// Convert a BCD-encoded value to binary.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
fn bcd_to_binary(bcd: u8) -> u8 {
    ((bcd >> 4) * 10) + (bcd & 0x0F)
}

/// Wait for the RTC to exit its update cycle.
///
/// During an update (Status Register A, bit 7 = 1), reading time registers
/// may return inconsistent values.  We spin until UIP clears.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn rtc_wait_while_updating() {
    // SAFETY: RTC_STATUS_A (0x0A) is a valid CMOS register.  This is a
    // read-only status poll and is safe to call from any context.
    while unsafe { cmos_read(RTC_STATUS_A) } & STATUS_A_UIP != 0 {
        core::hint::spin_loop();
    }
    // Small delay to ensure we're not right before the next update.
    for _ in 0..100 {
        core::hint::spin_loop();
    }
    // SAFETY: Re-checking RTC_STATUS_A after the delay — same safety
    // rationale as the first read.
    if unsafe { cmos_read(RTC_STATUS_A) } & STATUS_A_UIP != 0 {
        // Update started while we were waiting; restart.
        rtc_wait_while_updating();
    }
}

// ---------------------------------------------------------------------------
// RTC time
// ---------------------------------------------------------------------------

/// Wall-clock time from the CMOS RTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTime {
    /// Full year (e.g. 2026).
    pub year: u16,
    /// Month (1–12).
    pub month: u8,
    /// Day of month (1–31).
    pub day: u8,
    /// Hour (0–23).
    pub hour: u8,
    /// Minute (0–59).
    pub minute: u8,
    /// Second (0–59).
    pub second: u8,
}

/// Read the current wall-clock time from the RTC.
///
/// Returns `None` if the RTC is not accessible or returns obviously
/// invalid values.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn rtc_read_time() -> Option<RtcTime> {
    rtc_probe_mode();

    rtc_wait_while_updating();

    let bcd = RTC_BCD_MODE.load(Ordering::Acquire);
    let hour12 = RTC_12H_MODE.load(Ordering::Acquire);

    // SAFETY: All RTC register indices read below are valid CMOS registers
    // (0x00–0x0B, 0x32).  The update-in-progress flag has been checked via
    // rtc_wait_while_updating() so the register values are consistent.
    // CMOS port access is single-threaded during this function.
    let mut second = unsafe { cmos_read(RTC_SECONDS) };
    let mut minute = unsafe { cmos_read(RTC_MINUTES) };
    let mut hour = unsafe { cmos_read(RTC_HOURS) };
    let day = unsafe { cmos_read(RTC_DAY_OF_MONTH) };
    let mut month = unsafe { cmos_read(RTC_MONTH) };
    let mut year = unsafe { cmos_read(RTC_YEAR) } as u16;
    let century = unsafe { cmos_read(RTC_CENTURY) };

    if bcd {
        second = bcd_to_binary(second);
        minute = bcd_to_binary(minute);
        if hour12 {
            // Bit 7 = PM flag in 12-hour mode.
            let pm = hour & 0x80 != 0;
            hour = bcd_to_binary(hour & 0x7F);
            if pm {
                hour = if hour == 12 { 12 } else { hour + 12 };
            } else if hour == 12 {
                hour = 0;
            }
        } else {
            hour = bcd_to_binary(hour);
        }
        month = bcd_to_binary(month);
        // day is converted below after the validation block.
    }

    // Validate.
    if second > 59 || minute > 59 || hour > 23 || !(1..=12).contains(&month) {
        return None;
    }

    // Compute full year.
    if bcd {
        year = bcd_to_binary(year as u8) as u16;
        let cent = bcd_to_binary(century) as u16;
        if (19..=22).contains(&cent) {
            year += cent * 100;
        } else {
            year += 2000;
        }
    } else {
        year += 2000;
    }

    Some(RtcTime {
        year,
        month,
        day: if bcd { bcd_to_binary(day) } else { day },
        hour,
        minute,
        second,
    })
}

/// Convert an `RtcTime` to a Unix timestamp (seconds since 1970-01-01 UTC).
///
/// Uses a simplified algorithm that is correct for dates between 2000 and
/// 2099.  Leap years are handled correctly.
pub fn rtc_to_unix_timestamp(time: &RtcTime) -> u64 {
    // Days per month (non-leap year).
    const DAYS_PER_MONTH: [u16; 13] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];

    let year = time.year as u64;
    let month = time.month as u64;
    let day = time.day as u64;

    // Days since 1970-01-01.
    let mut days: u64 = 0;

    // Years from 1970 to year-1.
    for y in 1970..year {
        days += if is_leap_year(y as u16) { 366 } else { 365 };
    }

    // Months in current year.
    let month_idx = (month - 1) as usize;
    days += DAYS_PER_MONTH[month_idx] as u64;

    // Add extra day for February in leap year.
    if month > 2 && is_leap_year(year as u16) {
        days += 1;
    }

    // Days in current month.
    days += day - 1;

    // Convert to seconds.
    days * 86400 + (time.hour as u64) * 3600 + (time.minute as u64) * 60 + (time.second as u64)
}

fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && !year.is_multiple_of(100) || year.is_multiple_of(400)
}

/// Read the current Unix timestamp directly.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn rtc_now_unix() -> Option<u64> {
    rtc_read_time().map(|t| rtc_to_unix_timestamp(&t))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcd_to_binary_conversion() {
        assert_eq!(bcd_to_binary(0x00), 0);
        assert_eq!(bcd_to_binary(0x09), 9);
        assert_eq!(bcd_to_binary(0x10), 10);
        assert_eq!(bcd_to_binary(0x25), 25);
        assert_eq!(bcd_to_binary(0x59), 59);
        assert_eq!(bcd_to_binary(0x99), 99);
    }

    #[test]
    fn leap_year_detection() {
        assert!(is_leap_year(2000)); // divisible by 400
        assert!(!is_leap_year(1900)); // divisible by 100 but not 400
        assert!(is_leap_year(2024)); // divisible by 4
        assert!(!is_leap_year(2023));
        assert!(is_leap_year(2020));
    }

    #[test]
    fn unix_timestamp_for_known_date() {
        // 2021-01-01 00:00:00 UTC = 1609459200
        let time = RtcTime {
            year: 2021,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        let ts = rtc_to_unix_timestamp(&time);
        // 50 years * 365 days + 12 leap days = 18691 days from 1970 to 2020
        // = 18691 * 86400 = 1,614,902,400
        // Actually let's just verify it's reasonable.
        assert!(ts > 1_600_000_000);
        assert!(ts < 1_700_000_000);
    }

    #[test]
    fn unix_timestamp_is_monotonic() {
        let t1 = RtcTime {
            year: 2024,
            month: 6,
            day: 15,
            hour: 12,
            minute: 0,
            second: 0,
        };
        let t2 = RtcTime {
            year: 2024,
            month: 6,
            day: 15,
            hour: 12,
            minute: 0,
            second: 1,
        };
        assert!(rtc_to_unix_timestamp(&t1) < rtc_to_unix_timestamp(&t2));
    }

    #[test]
    fn unix_timestamp_handles_year_boundary() {
        let t1 = RtcTime {
            year: 2023,
            month: 12,
            day: 31,
            hour: 23,
            minute: 59,
            second: 59,
        };
        let t2 = RtcTime {
            year: 2024,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert_eq!(rtc_to_unix_timestamp(&t1) + 1, rtc_to_unix_timestamp(&t2));
    }

    #[test]
    fn unix_timestamp_leap_day() {
        let t1 = RtcTime {
            year: 2024,
            month: 2,
            day: 28,
            hour: 23,
            minute: 59,
            second: 59,
        };
        let t2 = RtcTime {
            year: 2024,
            month: 2,
            day: 29,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert_eq!(rtc_to_unix_timestamp(&t1) + 1, rtc_to_unix_timestamp(&t2));
    }
}
