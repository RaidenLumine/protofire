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
pub mod kernel;
pub mod user;
pub mod util;

/// Stack canary guard, written per-thread by the scheduler before entry.
///
/// The compiler-inserted stack protector reads/writes this via the
/// `__stack_chk_guard` ABI; we expose it as an atomic so per-thread canaries
/// can be installed race-free by [`kernel::process::scheduler::dispatch`].
#[allow(non_upper_case_globals)]
pub static __stack_chk_guard: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Returns a raw `*mut usize` to the stack canary guard slot.
///
/// Used by the `__stack_chk_fail` / `__stack_chk_guard` linkage the compiler
/// generates for `-C stack-protector` support on bare-metal targets.
pub fn __stack_chk_guard_ptr() -> *mut usize {
    &__stack_chk_guard as *const core::sync::atomic::AtomicUsize as *mut usize
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
