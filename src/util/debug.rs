//! src/util/debug.rs
//!
//! Early debug output plumbing and low-level print helpers.

use core::fmt;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    if INITIALIZED.swap(true, Ordering::Acquire) {
        return;
    }

    crate::arch::init_early();
    crate::arch::serial::init();
}

/// Per-CPU log prefix for SMP systems, e.g. `"[cpu0] "`.
/// Returns an empty string on single-CPU / non-bare-metal targets.
fn cpu_log_prefix() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        if crate::kernel::smp::online_cpu_count() > 1 {
            return match crate::kernel::percpu::get().cpu_id {
                0 => "[cpu0] ",
                1 => "[cpu1] ",
                2 => "[cpu2] ",
                3 => "[cpu3] ",
                4 => "[cpu4] ",
                5 => "[cpu5] ",
                6 => "[cpu6] ",
                7 => "[cpu7] ",
                _ => "[cpu?] ",
            };
        }
    }
    ""
}

pub fn _print(args: fmt::Arguments<'_>) {
    // Prepend per-CPU prefix on SMP systems.
    let prefix = cpu_log_prefix();
    if !prefix.is_empty() {
        let _ = crate::arch::write_fmt(format_args!("{}", prefix));
        let _ = fmt::write(&mut KernelLogWriter, format_args!("{}", prefix));
        let _ = fmt::write(&mut FbConsoleWriter, format_args!("{}", prefix));
    }
    let _ = crate::arch::write_fmt(args);
    // Also capture into the kernel log ring buffer so `/system/logs/kernel`
    // and `dmesg` can surface all console output.
    let _ = fmt::write(&mut KernelLogWriter, args);
    // Render to the framebuffer console (no-op if not installed).
    let _ = fmt::write(&mut FbConsoleWriter, args);
}

/// A `fmt::Write` adapter that feeds formatted strings into the kernel log
/// ring buffer as raw bytes.
struct KernelLogWriter;

impl fmt::Write for KernelLogWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::kernel::kernel_log::append_bytes(s.as_bytes());
        Ok(())
    }
}

/// A `fmt::Write` adapter that renders formatted strings to the framebuffer
/// console.  When no framebuffer console is installed this is a no-op.
struct FbConsoleWriter;

impl fmt::Write for FbConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::kernel::drivers::framebuffer_console::console_write(s);
        Ok(())
    }
}

pub fn write_bytes(bytes: &[u8]) {
    // Runtime debug output shares the serial device sink so `/system/dev/debug`
    // and `/system/dev/serial0` observe the same byte stream in tests and on
    // hardware.
    let _ = crate::kernel::drivers::serial::write_bytes(bytes);
    // Also capture into the kernel log ring buffer.
    crate::kernel::kernel_log::append_bytes(bytes);
    // Render to the framebuffer console (no-op if not installed).
    crate::kernel::drivers::framebuffer_console::console_write(
        core::str::from_utf8(bytes).unwrap_or("\u{FFFD}"),
    );
}
