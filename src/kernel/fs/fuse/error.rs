//! src/kernel/fs/fuse/error.rs
//! FUSE protocol error codes and conversion to kernel [`Error`].
//!
//! This module provides the single-choke-point conversion from FUSE wire-format
//! error codes to the kernel's internal [`Error`] type.  Unknown codes map to
//! [`Error::DeviceError`].

use crate::kernel::fs::fuse::FuseError;
use crate::Error;

impl FuseError {
    /// Decode a FUSE wire error code (a `u32` from a FUSE_ERROR response
    /// payload) into a [`FuseError`].
    ///
    /// Returns `None` for codes outside the known range.
    pub fn from_wire(code: u32) -> Option<FuseError> {
        match code {
            0 => Some(FuseError::Ok),
            1 => Some(FuseError::ENoEnt),
            2 => Some(FuseError::EPerm),
            3 => Some(FuseError::EIo),
            4 => Some(FuseError::ENomem),
            5 => Some(FuseError::EExists),
            6 => Some(FuseError::ENosys),
            7 => Some(FuseError::EBusy),
            8 => Some(FuseError::EInval),
            _ => None,
        }
    }

    /// Map a [`FuseError`] enum value into a kernel [`Error`].
    pub fn to_kernel_error(self) -> Error {
        match self {
            FuseError::Ok => Error::InvalidArgument, // FUSE_OK should never appear as an error
            FuseError::ENoEnt => Error::NotFound,
            FuseError::EPerm => Error::PermissionDenied,
            FuseError::EIo => Error::DeviceError,
            FuseError::ENomem => Error::OutOfMemory,
            FuseError::EExists => Error::AlreadyExists,
            FuseError::ENosys => Error::Unsupported,
            FuseError::EBusy => Error::Busy,
            FuseError::EInval => Error::InvalidArgument,
        }
    }
}

/// Convert a FUSE wire-format error code (a `u32` from a FUSE_ERROR response
/// payload) into a kernel [`Error`].
///
/// Codes outside the known range map to [`Error::DeviceError`].
pub fn fuse_error_code_to_kernel(code: u32) -> Error {
    FuseError::from_wire(code)
        .map(FuseError::to_kernel_error)
        .unwrap_or(Error::DeviceError)
}
