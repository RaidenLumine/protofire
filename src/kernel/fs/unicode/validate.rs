//! src/kernel/fs/unicode/validate.rs
//!
//! UTF-8 validation and sanitisation helpers for on-disk metadata.
//!
//! These functions check and sanitise byte sequences that are expected to be
//! well-formed UTF-8.  They are used when reading on-disk metadata (directory
//! entries, file names) that *should* be valid but may contain legacy
//! non-UTF-8 encodings.

use alloc::string::String;

/// Returns `true` if `data` is well-formed UTF-8.
///
/// This is a byte-level check; it does not inspect character semantics.
/// Surrogate halves (U+D800–U+DFFF) and overlong encodings are rejected
/// by the standard UTF-8 well-formedness rules.
pub fn is_valid_utf8(data: &[u8]) -> bool {
    core::str::from_utf8(data).is_ok()
}

/// Return the longest well-formed UTF-8 prefix of `data` as a `&str`,
/// together with the number of valid bytes consumed.
///
/// Invalid bytes and any bytes that follow them are silently discarded.
/// This is a lenient variant useful when reading on-disk metadata that
/// *should* be UTF-8 but may contain legacy non-UTF-8 encodings.
pub fn sanitize_utf8(data: &[u8]) -> (&str, usize) {
    match core::str::from_utf8(data) {
        Ok(s) => (s, data.len()),
        Err(e) => {
            let valid_up_to = e.valid_up_to();
            // SAFETY: `valid_up_to` is guaranteed by `from_utf8` to fall on a
            // valid UTF-8 boundary.
            let s = unsafe { core::str::from_utf8_unchecked(&data[..valid_up_to]) };
            (s, valid_up_to)
        }
    }
}

/// Return the longest well-formed UTF-8 prefix of `data` as an owned `String`.
///
/// This is a convenience wrapper around [`sanitize_utf8`].
pub fn sanitize_utf8_owned(data: &[u8]) -> String {
    let (s, _) = sanitize_utf8(data);
    s.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_utf8_passes() {
        assert!(is_valid_utf8(b"hello"));
        assert!(is_valid_utf8("文件名.txt".as_bytes()));
        assert!(is_valid_utf8("日本語".as_bytes()));
    }

    #[test]
    fn invalid_utf8_fails() {
        // 0xFF is never valid UTF-8.
        assert!(!is_valid_utf8(b"\xFF"));
        // Overlong encoding of '\0'.
        assert!(!is_valid_utf8(&[0xC0, 0x80]));
    }

    #[test]
    fn sanitize_utf8_truncates_at_first_error() {
        let data = b"good\xFFmore";
        let (s, n) = sanitize_utf8(data);
        assert_eq!(s, "good");
        assert_eq!(n, 4);
    }

    #[test]
    fn sanitize_utf8_fully_valid() {
        let data = b"perfectly valid";
        let (s, n) = sanitize_utf8(data);
        assert_eq!(s, "perfectly valid");
        assert_eq!(n, data.len());
    }
}
