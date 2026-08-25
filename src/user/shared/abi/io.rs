//! src/user/shared/abi/io.rs
//!
//! src/abi/io.rs
//! Shared I/O ABI constants for open, seek, and descriptor-oriented syscalls.

pub const OPEN_FLAG_NONE: usize = 0;
pub const OPEN_FLAG_READ: usize = 1 << 0;
pub const OPEN_FLAG_WRITE: usize = 1 << 1;
pub const OPEN_FLAG_CREATE: usize = 1 << 2;
pub const OPEN_FLAG_READ_WRITE: usize = OPEN_FLAG_READ | OPEN_FLAG_WRITE;
pub const OPEN_FLAG_READ_CREATE: usize = OPEN_FLAG_READ | OPEN_FLAG_CREATE;
pub const OPEN_FLAG_WRITE_CREATE: usize = OPEN_FLAG_WRITE | OPEN_FLAG_CREATE;
pub const OPEN_FLAG_READ_WRITE_CREATE: usize = OPEN_FLAG_READ | OPEN_FLAG_WRITE | OPEN_FLAG_CREATE;
pub const OPEN_KNOWN_FLAGS: usize = OPEN_FLAG_READ | OPEN_FLAG_WRITE | OPEN_FLAG_CREATE;

#[cfg(test)]
mod tests {
    use super::OPEN_FLAG_CREATE;
    use super::OPEN_FLAG_NONE;
    use super::OPEN_FLAG_READ;
    use super::OPEN_FLAG_READ_CREATE;
    use super::OPEN_FLAG_READ_WRITE;
    use super::OPEN_FLAG_READ_WRITE_CREATE;
    use super::OPEN_FLAG_WRITE;
    use super::OPEN_FLAG_WRITE_CREATE;
    use super::OPEN_KNOWN_FLAGS;

    #[test]
    fn open_flag_combinations_match_expected_masks() {
        assert_eq!(OPEN_FLAG_NONE, 0);
        assert_eq!(OPEN_FLAG_READ, 1);
        assert_eq!(OPEN_FLAG_WRITE, 2);
        assert_eq!(OPEN_FLAG_CREATE, 4);
        assert_eq!(OPEN_FLAG_READ_WRITE, OPEN_FLAG_READ | OPEN_FLAG_WRITE);
        assert_eq!(OPEN_FLAG_READ_CREATE, OPEN_FLAG_READ | OPEN_FLAG_CREATE);
        assert_eq!(OPEN_FLAG_WRITE_CREATE, OPEN_FLAG_WRITE | OPEN_FLAG_CREATE);
        assert_eq!(
            OPEN_FLAG_READ_WRITE_CREATE,
            OPEN_FLAG_READ | OPEN_FLAG_WRITE | OPEN_FLAG_CREATE
        );
        assert_eq!(OPEN_KNOWN_FLAGS, OPEN_FLAG_READ_WRITE_CREATE);
    }
}
