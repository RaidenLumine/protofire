//! src/lib.rs
//!
//! Protofire Kernel Library
//!
//! This is the main library crate for the Protofire kernel.
//! It provides the core error types, module structure, and logging macros used
//! throughout the kernel and shared ring-3 library.

#![no_std]

extern crate alloc;
#[cfg(not(target_os = "none"))]
extern crate std;

pub mod abi;
pub mod arch;
pub mod drivers;
pub mod fs;
pub mod kernel;
pub mod memory;
pub mod network;
pub mod syscall;
pub mod user;
pub mod util;

/// The `__stack_chk_guard` slot a `-Z stack-protector` build links against.
///
/// It is `#[no_mangle]` because the protector's ABI names the *symbol*, not a
/// Rust path: the compiler emits a load of `__stack_chk_guard` and a call to
/// `__stack_chk_fail`, and a mangled static leaves the first undefined at link
/// time — which is what it did until this attribute was added.
///
/// **A fixed value, set by the linker, never written at run time.**  Three
/// boots settled that, and each ruled out the previous explanation:
///
/// 1. Written on every context switch with the incoming thread's canary — the
///    wiring the tree had — panicked on every boot.
/// 2. Written on every switch with the *same* constant for every thread still
///    panicked, which ruled out "two threads disagree" and left the write
///    itself.
/// 3. A compile-time constant with nothing writing it ran clean.
///
/// The mechanism is the ABI: a protected function stores this value into its
/// frame in the prologue and reloads the global slot to compare in the
/// epilogue.  Any write in between — a context switch, an install call, this
/// thread's or another CPU's — makes that frame report corruption that never
/// happened.  There is no placement for the write that avoids it, because the
/// write happens while some frame is always live on some CPU.
///
/// What that costs is unpredictability: a value in the image is a value an
/// attacker who can read the image knows.  Per-CPU canaries need a slot each
/// CPU reads without a memory load that another CPU can rewrite mid-frame — an
/// `fs:`/`tp:`-relative slot, a change to the context switch rather than to
/// this static.  `docs/status.md` records that as the remaining work.  What
/// this value does buy, and the reason it is worth having: an overflow past a
/// frame turns a silent corruption into `__stack_chk_fail`.
const STACK_CANARY: usize = 0x4F3A_9C15_B7E2_D806;

#[allow(non_upper_case_globals)]
#[no_mangle]
pub static __stack_chk_guard: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(STACK_CANARY);

/// Returns a raw `*mut usize` to the stack canary guard slot.
///
/// Used by the `__stack_chk_fail` / `__stack_chk_guard` linkage the compiler
/// generates for `-Z stack-protector` support on bare-metal targets.
pub fn __stack_chk_guard_ptr() -> *mut usize {
    &__stack_chk_guard as *const core::sync::atomic::AtomicUsize as *mut usize
}

/// What a `-Z stack-protector` build calls when a frame's canary did not come
/// back.
///
/// The kernel aborts rather than returns: a canary that changed means the
/// frame it belonged to was written past its end, and continuing runs code
/// whose return address may have been written by whatever did it.  The abort is
/// the right answer here because the alternative — unwinding — needs a frame
/// whose return address is exactly what is in doubt.
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    crate::println!("[panic ] stack canary mismatch: a frame was written past its end");
    loop {
        crate::arch::halt();
    }
}

/// Result type used throughout the kernel
pub type Result<T> = core::result::Result<T, Error>;

/// Error codes used by the kernel and user-space programs
/// These are represented as usize values for system call return codes
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidArgument,   // Invalid argument passed to syscall
    NotFound,          // Resource or file not found
    AlreadyExists,     // Resource or file already exists
    PermissionDenied,  // Insufficient permissions
    OutOfMemory,       // Memory allocation failed
    DeviceError,       // Hardware/device error
    Busy,              // Resource is busy
    TimedOut,          // Operation timed out
    Unsupported,       // Operation not supported
    NotImplemented,    // Feature not implemented
    InternalError,     // Internal kernel error
    InvalidCredential, // Authentication failed (bad password, etc.)
    ConnectionReset,   // TCP/DCCP connection reset by peer (or network)
    NoSpace,           // Device or filesystem has no free space left
}

impl Error {
    /// Convert error code to human-readable string
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid argument",
            Self::NotFound => "not found",
            Self::AlreadyExists => "already exists",
            Self::PermissionDenied => "permission denied",
            Self::OutOfMemory => "out of memory",
            Self::DeviceError => "device error",
            Self::Busy => "resource busy",
            Self::TimedOut => "timed out",
            Self::Unsupported => "unsupported",
            Self::NotImplemented => "not implemented",
            Self::InternalError => "internal error",
            Self::InvalidCredential => "invalid credential",
            Self::ConnectionReset => "connection reset",
            Self::NoSpace => "no space left on device",
        }
    }

    /// Convert raw syscall return code to Error enum
    /// Returns None if the code doesn't match any known error
    pub const fn from_syscall_code(code: usize) -> Option<Self> {
        match code {
            0 => Some(Self::InvalidArgument),
            1 => Some(Self::NotFound),
            2 => Some(Self::AlreadyExists),
            3 => Some(Self::PermissionDenied),
            4 => Some(Self::OutOfMemory),
            5 => Some(Self::DeviceError),
            6 => Some(Self::Busy),
            7 => Some(Self::TimedOut),
            8 => Some(Self::Unsupported),
            9 => Some(Self::NotImplemented),
            10 => Some(Self::InternalError),
            11 => Some(Self::InvalidCredential),
            12 => Some(Self::ConnectionReset),
            13 => Some(Self::NoSpace),
            _ => None,
        }
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::util::debug::_print(core::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n");
    };
    ($fmt:expr) => {
        $crate::print!(concat!($fmt, "\n"));
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::print!(concat!($fmt, "\n"), $($arg)*);
    };
}
