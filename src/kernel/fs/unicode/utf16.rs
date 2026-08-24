//! src/kernel/fs/unicode/utf16.rs
//!
//! UTF-8 ↔ UTF-16LE conversion for FAT32 LFN and exFAT filename entries.
//!
//! FAT32 LFN entries store 13 UTF-16LE code units per 32-byte directory entry.
//! exFAT filename extensions store 15 UTF-16LE code units per 32-byte entry.
//! Both filesystem drivers use the functions in this module so the conversion
//! logic lives in exactly one place.
//!
//! Surrogate pairs (non-BMP characters like emoji) are fully supported in both
//! the encode and decode directions.

use alloc::string::String;
use alloc::vec::Vec;

// ── Public API ────────────────────────────────────────────────────────────

/// Convert a single UTF-16LE code unit (BMP only) to a Rust `char`.
///
/// Surrogate halves (U+D800–U+DFFF) and invalid code points are replaced with
/// U+FFFD REPLACEMENT CHARACTER.  For surrogate-aware decoding of a sequence,
/// use [`utf16le_to_utf8`] which handles surrogate pairs via
/// [`char::decode_utf16`].
///
/// # Example
///
/// ```
/// assert_eq!(utf16le_code_unit_to_char(0x0041), 'A');
/// assert_eq!(utf16le_code_unit_to_char(0x4E2D), '中');
/// assert_eq!(utf16le_code_unit_to_char(0xD800), '\u{FFFD}'); // surrogate
/// ```
pub fn utf16le_code_unit_to_char(cu: u16) -> char {
    match cu {
        // Surrogate halves are not valid scalar values.
        0xD800..=0xDFFF => '\u{FFFD}',
        other => char::from_u32(other as u32).unwrap_or('\u{FFFD}'),
    }
}

/// Decode a sequence of UTF-16 code units into a UTF-8 `String`.
///
/// Surrogate pairs are combined into the corresponding non-BMP character;
/// unpaired surrogates are replaced with U+FFFD.
///
/// # Example
///
/// ```
/// assert_eq!(utf16le_to_utf8(&[0x0041]), "A");
/// assert_eq!(utf16le_to_utf8(&[0x4E2D]), "中");
/// assert_eq!(utf16le_to_utf8(&[0xD83D, 0xDE00]), "\u{1F600}"); // 😀
/// ```
pub fn utf16le_to_utf8(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Encode a UTF-8 string into a `Vec` of UTF-16 code units.
///
/// Non-BMP characters are emitted as surrogate pairs.  Callers that need the
/// little-endian byte representation (e.g. directory-entry writers) can use
/// [`write_utf16le_chars`] or flatten each unit with `u16::to_le_bytes`.
///
/// # Example
///
/// ```
/// assert_eq!(utf8_to_utf16le("A"), vec![0x0041]);
/// assert_eq!(utf8_to_utf16le("中"), vec![0x4E2D]);
/// assert_eq!(utf8_to_utf16le("\u{1F600}"), vec![0xD83D, 0xDE00]);
/// ```
pub fn utf8_to_utf16le(input: &str) -> Vec<u16> {
    input.encode_utf16().collect()
}

/// Write `count` UTF-16 code units from `chars` into `buf` starting at the
/// byte offset `offset`, in little-endian order.
///
/// This is the primitive used by the FAT32 LFN writer to fill the three
/// code-unit groups (5 / 6 / 2 chars) inside a single 32-byte entry.  The
/// caller is responsible for providing a buffer large enough to hold
/// `offset + count * 2` bytes.
pub fn write_utf16le_chars(buf: &mut [u8], offset: usize, chars: &[u16], count: usize) {
    let count = count.min(chars.len());
    debug_assert!(offset + count * 2 <= buf.len());
    for (i, &cu) in chars[..count].iter().enumerate() {
        let o = offset + i * 2;
        buf[o] = cu as u8;
        buf[o + 1] = (cu >> 8) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn code_unit_to_char_bmp() {
        assert_eq!(utf16le_code_unit_to_char(0x0041), 'A');
        assert_eq!(utf16le_code_unit_to_char(0x4E2D), '中');
        assert_eq!(utf16le_code_unit_to_char(0xD800), '\u{FFFD}');
        assert_eq!(utf16le_code_unit_to_char(0xDFFF), '\u{FFFD}');
    }

    #[test]
    fn decodes_surrogate_pairs() {
        assert_eq!(utf16le_to_utf8(&[0xD83D, 0xDE00]), "\u{1F600}");
        assert_eq!(utf16le_to_utf8(&[0x4E2D, 0x0041]), "中A");
        // Unpaired high surrogate → U+FFFD.
        assert_eq!(utf16le_to_utf8(&[0xD83D, 0x0041]), "\u{FFFD}A");
    }

    #[test]
    fn encodes_to_code_units() {
        assert_eq!(utf8_to_utf16le("A"), vec![0x0041]);
        assert_eq!(utf8_to_utf16le("中"), vec![0x4E2D]);
        assert_eq!(utf8_to_utf16le("\u{1F600}"), vec![0xD83D, 0xDE00]);
    }

    #[test]
    fn writes_le_bytes_into_buffer() {
        let mut buf = [0u8; 32];
        write_utf16le_chars(&mut buf, 1, &[0x0041, 0x4E2D], 2);
        assert_eq!(&buf[1..5], &[0x41, 0x00, 0x2D, 0x4E]);
        // Clamped count.
        write_utf16le_chars(&mut buf, 14, &[0x0042; 6], 100);
        assert_eq!(&buf[14..14 + 6 * 2], &[0x42, 0x00].repeat(6));
    }
}
