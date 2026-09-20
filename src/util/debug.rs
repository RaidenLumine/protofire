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

/// Serialises one formatted line onto the console.
///
/// Without it, concurrent `print!` calls from different CPUs interleave *at
/// byte granularity*: the UART write loop takes no lock (see
/// `SerialDevice::write_bytes`), and `_print` reaches it in two separate calls
/// — the per-CPU prefix and then the message.  The result is text like
/// `p[user  ] rust data: rotofire shell (user)`, where another CPU's prefix
/// landed inside a word and a character was lost.
///
/// That is worse than untidy output.  The console is the only diagnostic
/// channel this kernel has, and every log-based tool — including
/// `scripts/check-smp-runtime.sh` — reads it.  A mangled line turns a healthy
/// boot into a reported failure, which is exactly what happened twice before
/// this lock existed.
///
/// Held across the serial write only.  The ring buffer and framebuffer writers
/// that follow take their own locks, and nesting those under this one would
/// invite a lock-order cycle for no gain to the console output itself.
static CONSOLE_LOCK: crate::kernel::sync::Mutex<()> = crate::kernel::sync::Mutex::new(());

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

/// Announce, once, that the console dropped bytes.
///
/// A transmitter that times out leaves no trace on its own: the UART is where
/// the trace would go.  From the outside it looks like the machine stopped,
/// which is the same thing a CPU stuck for an unrelated reason looks like —
/// and that ambiguity is what let a stalled console write masquerade as a
/// halted AP bring-up.
///
/// Reported lazily, from the layer *above* the UART: the first message that
/// gets through afterwards carries the notice, so the count and the message it
/// interrupted appear together.  Written through `arch::write_fmt` rather than
/// `_print` so it cannot recurse back into this function.
fn report_transmit_timeouts() {
    static REPORTED: AtomicBool = AtomicBool::new(false);

    if REPORTED.load(Ordering::Relaxed) {
        return;
    }
    let dropped = crate::arch::serial::transmit_timeout_count();
    if dropped == 0 {
        return;
    }
    REPORTED.store(true, Ordering::Relaxed);

    let _ = crate::arch::write_fmt(format_args!(
        "[uart  ] transmitter timed out {} time(s); {} byte(s) dropped. \
         The console was not writable, so a log that stops here may be a \
         stalled write rather than a stalled CPU.\n",
        dropped, dropped
    ));
}

pub fn _print(args: fmt::Arguments<'_>) {
    // One line, one holder: the prefix and the message must reach the UART as
    // a unit.
    let _console = CONSOLE_LOCK.lock();

    report_transmit_timeouts();

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
    // The same lock `_print` takes.  This path carries console and shell
    // output, which does not go through `_print`, and both end up in the same
    // UART — so they need the same lock or they interleave with each other.
    let _console = CONSOLE_LOCK.lock();

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
