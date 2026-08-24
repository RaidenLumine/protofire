//! src/arch/riscv64/rtc.rs
//!
//! Real-Time Clock (RTC) driver.
//!
//! The CMOS-based driver below is shared with the x86_64 architecture but
//! is only compilable there (it reads x86 I/O ports 0x70/0x71).  On riscv64
//! no RTC hardware is wired up yet, so [`rtc_now_unix`] reports the clock as
//! unavailable and returns `None`.

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

/// Convert a civil wall-clock time to a Unix timestamp (seconds since
/// 1970-01-01 00:00:00 UTC) using the proleptic Gregorian calendar.
///
/// Uses the standard civil-from-days algorithm so no external date library
/// is needed in the kernel.
pub fn rtc_to_unix_timestamp(time: &RtcTime) -> u64 {
    let year = i64::from(time.year);
    let month = i64::from(time.month);
    let day = i64::from(time.day);

    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    let seconds = days * 86400
        + i64::from(time.hour) * 3600
        + i64::from(time.minute) * 60
        + i64::from(time.second);
    seconds as u64
}

/// Read the current wall-clock time from the RTC as a Unix timestamp.
///
/// Returns `None` if the RTC is unavailable or returns implausible values.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn rtc_now_unix() -> Option<u64> {
    let time = rtc_read_time()?;
    if time.year < 1970 {
        return None;
    }
    Some(rtc_to_unix_timestamp(&time))
}

/// Read the current Unix timestamp.
///
/// Returns `None` if the RTC is unavailable.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub fn rtc_now_unix() -> Option<u64> {
    None
}
