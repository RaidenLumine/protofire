//! src/abi/syscall.rs
//!
//! Shared syscall status encoding helpers and low-level ABI constants.

use crate::Error;
use crate::Result;

pub const ARG_COUNT: usize = 6;
pub const X86_64_INTERRUPT_VECTOR: u8 = 0x80;
pub const ERROR_CODE_MAX: usize = Error::InternalError as usize;
pub const ERROR_STATUS_FLOOR: usize = usize::MAX - ERROR_CODE_MAX;

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
