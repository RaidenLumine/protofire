//! src/abi/syscall.rs
//!
//! Shared syscall status encoding helpers and low-level ABI constants.

use crate::Error;
use crate::Result;

// The numbers are the ABI's, and the ABI's copy is the shared one — user space
// has to encode and decode the same words without this crate's `Error` type.
// What stays here is the typed half, and the assertion that pins it.
pub use crate::user::shared::abi::syscall::ARG_COUNT;
pub use crate::user::shared::abi::syscall::ERROR_CODE_MAX;
pub use crate::user::shared::abi::syscall::ERROR_STATUS_FLOOR;
pub use crate::user::shared::abi::syscall::X86_64_INTERRUPT_VECTOR;

// The one thing the shared copy cannot state is where the codes end, because
// that is a property of the kernel's own error type: `InternalError` is the
// last of them.  So the enum is asserted against the pinned number here, and a
// variant added without moving the pin fails at this line rather than
// mis-encoding every error the kernel returns.
const _: () = assert!(ERROR_CODE_MAX == Error::InternalError as usize);

pub const fn encode_error(error: Error) -> usize {
    usize::MAX - error as usize
}

pub fn encode_result(result: Result<usize>) -> usize {
    match result {
        Ok(value) => value,
        Err(error) => encode_error(error),
    }
}

pub const fn is_error_status(status: usize) -> bool {
    status >= ERROR_STATUS_FLOOR
}

pub fn decode_result(status: usize) -> Result<usize> {
    if !is_error_status(status) {
        return Ok(status);
    }

    let code = usize::MAX - status;
    Err(Error::from_syscall_code(code).unwrap_or(Error::InternalError))
}

#[cfg(test)]
mod tests {
    use super::decode_result;
    use super::encode_error;
    use super::encode_result;
    use super::is_error_status;
    use super::ERROR_STATUS_FLOOR;
    use crate::Error;

    #[test]
    fn encoded_ok_status_round_trips() {
        assert_eq!(encode_result(Ok(1234)), 1234);
        assert_eq!(decode_result(1234), Ok(1234));
    }

    #[test]
    fn encoded_error_status_round_trips() {
        let status = encode_error(Error::TimedOut);
        assert!(is_error_status(status));
        assert_eq!(decode_result(status), Err(Error::TimedOut));
    }

    #[test]
    fn error_status_floor_marks_reserved_high_range() {
        assert!(is_error_status(ERROR_STATUS_FLOOR));
        assert!(!is_error_status(ERROR_STATUS_FLOOR.saturating_sub(1)));
    }
}
