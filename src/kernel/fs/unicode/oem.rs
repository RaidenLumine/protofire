//! src/kernel/fs/unicode/oem.rs
//!
//! OEM code-page ↔ Unicode conversion (CP437, CP850, CP852, CP866, CP874).
//!
//! FAT32 8.3 short filenames are encoded using OEM code pages (not Unicode).
//! This module provides lookup tables and conversion functions for CP437 (US
//! default) and CP850 (Western European) → UTF-8.

use alloc::vec::Vec;

use super::casefold::fold_char;

// ---------------------------------------------------------------------------
// OEM code-page → Unicode conversion (FAT32 8.3 short filenames)
// ---------------------------------------------------------------------------

/// OEM code page identifier for FAT32 short filename (8.3) decoding.
///
/// Only CP437 and CP850 have full lookup tables in this module; the other
/// legacy code pages are recognised but fall back to U+FFFD on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OemCodePage {
    /// US English (IBM PC).
    Cp437,
    /// Western European / Latin-1.
    Cp850,
    /// Central European.
    Cp852,
    /// Cyrillic (DOS).
    Cp866,
    /// Thai.
    Cp874,
}

/// Convert a single OEM code-page byte to a Unicode `char`.
///
/// ASCII bytes (`0x00–0x7F`) map directly; high-half bytes are looked up in
/// the selected code page table.  Unknown bytes map to U+FFFD.
///
/// # Example
///
/// ```
/// use protofire::kernel::fs::unicode::oem::{oem_byte_to_char, OemCodePage};
///
/// assert_eq!(oem_byte_to_char(0x41, OemCodePage::Cp437), 'A'); // ASCII
/// assert_eq!(oem_byte_to_char(0x82, OemCodePage::Cp437), 'é'); // CP437
/// assert_eq!(oem_byte_to_char(0x82, OemCodePage::Cp850), 'é'); // same in CP850
/// assert_eq!(oem_byte_to_char(0x9B, OemCodePage::Cp437), '¢'); // CP437: cent
/// assert_eq!(oem_byte_to_char(0x9B, OemCodePage::Cp850), 'ø'); // CP850: o-slash
/// ```
pub fn oem_byte_to_char(byte: u8, code_page: OemCodePage) -> char {
    if byte < 0x80 {
        return byte as char;
    }
    let idx = (byte - 0x80) as usize;
    let scalar = match code_page {
        OemCodePage::Cp437 => CP437_UPPER[idx],
        OemCodePage::Cp850 => CP850_UPPER[idx],
        _ => return '\u{FFFD}',
    };
    char::from_u32(scalar as u32).unwrap_or('\u{FFFD}')
}

/// Convert a Unicode `char` to the corresponding OEM code-page byte.
///
/// Returns `Some(byte)` if the character is representable in the selected
/// code page (either as an ASCII byte 0x00–0x7F or as a high-half entry),
/// or `None` otherwise.
///
/// Characters that are mapped use the **lowercase** form where applicable
/// for case-insensitive lookups (e.g. both 'É' and 'é' map to 0x82 in CP437).
///
/// # Example
///
/// ```
/// use protofire::kernel::fs::unicode::oem::{char_to_oem_byte, OemCodePage};
///
/// assert_eq!(char_to_oem_byte('A', OemCodePage::Cp437), Some(0x41));
/// assert_eq!(char_to_oem_byte('é', OemCodePage::Cp437), Some(0x82));
/// assert_eq!(char_to_oem_byte('中', OemCodePage::Cp437), None); // CJK not in CP437
/// ```
pub fn char_to_oem_byte(ch: char, code_page: OemCodePage) -> Option<u8> {
    let code = ch as u32;

    // ASCII range: direct passthrough.
    if code < 0x80 {
        return Some(code as u8);
    }

    // Search the high-half table for the given code page.  Prefer the
    // folded (lowercase) form so uppercase letters resolve to the same byte
    // as their lowercase counterparts.
    let table: &[u16] = match code_page {
        OemCodePage::Cp437 => &CP437_UPPER,
        OemCodePage::Cp850 => &CP850_UPPER,
        _ => return None,
    };
    // Prefer the folded (lowercase) form so uppercase letters resolve to the
    // same byte as their lowercase counterparts (e.g. both 'É' and 'é' map to
    // 0x82 in CP437).  Fall back to the exact character if folding doesn't
    // match.
    for probe in [fold_char(ch), ch] {
        if let Some(idx) = table.iter().position(|&s| s == probe as u16) {
            return Some((idx + 0x80) as u8);
        }
    }
    None
}

/// Encode a UTF-8 string into an OEM code-page byte sequence.
///
/// Characters that cannot be represented in the target code page are
/// replaced with `0x3F` (`'?'`).  This matches the behaviour of Windows
/// FAT filesystem drivers when a Unicode character has no OEM equivalent.
///
/// # Example
///
/// ```
/// use protofire::kernel::fs::unicode::oem::utf8_to_oem;
/// use protofire::kernel::fs::unicode::oem::OemCodePage;
///
/// assert_eq!(
///     utf8_to_oem("Café", OemCodePage::Cp437),
///     vec![0x43, 0x61, 0x66, 0x82]
/// );
/// assert_eq!(utf8_to_oem("中文", OemCodePage::Cp437), vec![b'?', b'?']);
/// ```
pub fn utf8_to_oem(input: &str, code_page: OemCodePage) -> Vec<u8> {
    let mut v = Vec::with_capacity(input.len());
    for ch in input.chars() {
        v.push(char_to_oem_byte(ch, code_page).unwrap_or(0x3F));
    }
    v
}

// ── CP437 upper half (0x80–0xFF) → Unicode scalar values ────────────────
// Derived from the IBM CP437 character set.
// <https://en.wikipedia.org/wiki/Code_page_437>

const CP437_UPPER: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, //
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, //
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, //
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, //
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, //
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, //
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, //
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, //
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, //
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, //
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, //
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, //
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, //
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229, //
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, //
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0, //
];

// ── CP850 upper half (0x80–0xFF) → Unicode scalar values ────────────────
// Derived from the IBM CP850 (Latin-1 / Western European) character set.

const CP850_UPPER: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, //
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5, //
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, //
    0x00FF, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7, 0x0192, //
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, //
    0x00BF, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, //
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00C1, 0x00C2, 0x00C0, //
    0x00A9, 0x2563, 0x2551, 0x2557, 0x255D, 0x00A2, 0x00A5, 0x2510, //
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x00E3, 0x00C3, //
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4, //
    0x00F0, 0x00D0, 0x00CA, 0x00CB, 0x00C8, 0x0131, 0x00CD, 0x00CE, //
    0x00CF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0x00CC, 0x2580, //
    0x00D3, 0x00DF, 0x00D4, 0x00D2, 0x00F5, 0x00D5, 0x00B5, 0x00FE, //
    0x00DE, 0x00DA, 0x00DB, 0x00D9, 0x00FD, 0x00DD, 0x00AF, 0x00B4, //
    0x00AD, 0x00B1, 0x2017, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8, //
    0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0, //
];

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn ascii_maps_directly() {
        for b in 0x00..0x80 {
            assert_eq!(oem_byte_to_char(b, OemCodePage::Cp437), b as char);
            assert_eq!(char_to_oem_byte(b as char, OemCodePage::Cp437), Some(b));
        }
    }

    #[test]
    fn cp437_known_mappings() {
        assert_eq!(oem_byte_to_char(0x82, OemCodePage::Cp437), 'é');
        assert_eq!(oem_byte_to_char(0x9B, OemCodePage::Cp437), '¢');
        assert_eq!(char_to_oem_byte('é', OemCodePage::Cp437), Some(0x82));
        assert_eq!(char_to_oem_byte('É', OemCodePage::Cp437), Some(0x82));
        assert_eq!(char_to_oem_byte('中', OemCodePage::Cp437), None);
    }

    #[test]
    fn cp850_known_mappings() {
        assert_eq!(oem_byte_to_char(0x9B, OemCodePage::Cp850), 'ø');
        assert_eq!(oem_byte_to_char(0x82, OemCodePage::Cp850), 'é');
    }

    #[test]
    fn utf8_to_oem_replaces_unmappable() {
        assert_eq!(
            utf8_to_oem("Café", OemCodePage::Cp437),
            vec![0x43, 0x61, 0x66, 0x82]
        );
        assert_eq!(utf8_to_oem("中文", OemCodePage::Cp437), vec![b'?', b'?']);
    }
}
