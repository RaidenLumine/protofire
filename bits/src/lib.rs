//! bits/src/lib.rs
//!
//! The parts of this kernel that nothing else in it depends on.
//!
//! See the manifest for why this is a crate.  The rule for anything added
//! here: no `crate::` reference, only `core` and `alloc`.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

pub mod compression;
pub mod crypto;
/// An ELF image's header, program headers and section headers.
pub mod elf;
/// An internet address, which is arithmetic over bytes and nothing else.
pub mod internet_ip;
/// An internet protocol version 4 address, its header and its checksums.
pub mod ipv4;
/// The base path type and its normalisation.
///
/// Named `path` here and re-exported as `fs::path` from the kernel, because a
/// path is not a filesystem's — a program builds one before it has a volume.
pub mod path;
/// The point-to-point protocol's frame and control protocols.
pub mod ppp;
/// The stream control transmission protocol's chunks and association.
pub mod sctp;
/// A cell whose contents are only touched under a lock the caller owns.
///
/// The kernel's `Sync` impls use it to say "these fields are not aliased"
/// without `unsafe` at every use site.
pub mod sync_unsafe_cell;
/// Unicode normalisation, case folding and the code-page tables.
///
/// 4596 lines with no `crate::` reference in any of them — the one part of
/// this tree that was already a crate looking for a place to be one.
pub mod unicode;

/// Result type used throughout the kernel.
///
/// Here rather than in the crate root because every module names it, and a
/// module that names the root cannot be a crate: `fs` needing `Error` would
/// otherwise reach through `kernel` to get it.  The error a filesystem returns
/// and the error a scheduler returns are the same kind of thing, and this is
/// where that is true by construction rather than by convention.
pub type Result<T> = core::result::Result<T, Error>;

/// Error codes used by the kernel and user-space programs.
///
/// The numbers are the syscall ABI's: `from_syscall_code` decodes what a
/// userspace caller sees, so these cannot be reordered without a matching
/// change to the ABI — see `docs/fmts/syscall-abi.md`.
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
