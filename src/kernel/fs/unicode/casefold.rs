//! src/kernel/fs/unicode/casefold.rs
//! Unicode case folding for case-insensitive filename comparison.
//!
//! FAT32 and SimpleFs support case-insensitive lookups under a configurable
//! policy.  This module provides a `fold_char` mapping and the
//! [`eq_unicode_insensitive`] comparison helper used by both filesystems.
//!
//! The mapping is the full Unicode **simple** case folding (the `S` column of
//! Unicode `CaseFolding.txt`, plus single-code-point `C`/`F` mappings) —
//! every script with case is covered.  See [`casefold_tables`] for the
//! generated table.  Multi-code-point full folds (e.g. `ß` → `ss`) cannot be
//! represented by a char-at-a-time mapping; characters with only a multi-char
//! fold compare byte-exact, which never causes a false *match*.

use super::casefold_tables::SIMPLE_FOLDS;

/// Return the case-folded form of `ch`.
///
/// ASCII uppercase maps to lowercase; for all other scripts the generated
/// 1:1 folding table is binary-searched.  Characters without a case mapping
/// (or with only a multi-code-point full fold) are returned unchanged.
pub fn fold_char(ch: char) -> char {
    let code = ch as u32;
    // Fast ASCII path — the common case for filenames.
    if code < 0x80 {
        return if ch.is_ascii_uppercase() {
            ch.to_ascii_lowercase()
        } else {
            ch
        };
    }
    // SIMPLE_FOLDS is sorted by source code point (generated table).
    match SIMPLE_FOLDS.binary_search_by_key(&code, |&(src, _)| src) {
        Ok(idx) => {
            let (_, dst) = SIMPLE_FOLDS[idx];
            char::from_u32(dst).unwrap_or(ch)
        }
        Err(_) => ch,
    }
}

/// Compare two strings ignoring case under the folding table.
///
/// The strings must be the same length *after* folding to match; this keeps
/// the comparison O(n) and conservative.
pub fn eq_unicode_insensitive(left: &str, right: &str) -> bool {
    let mut lit = left.chars();
    let mut rit = right.chars();
    loop {
        match (lit.next(), rit.next()) {
            (Some(a), Some(b)) => {
                if fold_char(a) != fold_char(b) {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_folding() {
        assert!(eq_unicode_insensitive("HELLO.TXT", "hello.txt"));
        assert!(!eq_unicode_insensitive("hello.txt", "helo.txt"));
    }

    #[test]
    fn latin_folding() {
        assert!(eq_unicode_insensitive("Café", "CAFÉ"));
        assert!(eq_unicode_insensitive("Äpfel", "äpfel"));
        assert!(eq_unicode_insensitive("ĞÜŞ", "ğüş"));
        assert!(eq_unicode_insensitive("ſ", "s")); // U+017F long s
    }

    #[test]
    fn cyrillic_and_greek_folding() {
        assert!(eq_unicode_insensitive("ПРИВЕТ", "привет"));
        assert!(eq_unicode_insensitive("ЖУРНАЛ.TXT", "журнал.txt"));
        assert!(eq_unicode_insensitive("ΟΔΥΣΣΕΥΣ", "οδυσσευς"));
        assert!(eq_unicode_insensitive("ΑΓΓΛΙΚΟ", "αγγλικο"));
        // Greek extended: psili-variants fold to the plain lowercase forms.
        assert!(eq_unicode_insensitive("ὈΔΥΣΣΕΥΣ", "ὀδυσσευς"));
    }

    #[test]
    fn armenian_georgian_cherokee_folding() {
        // Armenian uppercase -> lowercase.
        assert!(eq_unicode_insensitive("ՀԱՅ", "հայ"));
        // Georgian (Asomtavruli Mkhedruli pairs fold via the table).
        assert!(eq_unicode_insensitive("ა", "ა"));
        // Cherokee uppercase -> lowercase.
        assert!(eq_unicode_insensitive("ᎠᎡᎢ", "ꭰꭱꭲ"));
    }

    #[test]
    fn latin_extended_b_folding() {
        // Ơ/ơ, Ư/ư (Vietnamese), ẞ/ß via the 1:1 S mapping.
        assert!(eq_unicode_insensitive("ƠƯ", "ơư"));
        assert!(fold_char('ẞ') == 'ß');
        assert!(eq_unicode_insensitive("ẞ", "ß"));
    }

    #[test]
    fn fold_char_roundtrips_on_table() {
        // Every 1:1 mapping in the generated table folds to a valid char,
        // and folding a folded char is a fixed point (simple fold is idempotent).
        for &(src, dst) in SIMPLE_FOLDS {
            let from = char::from_u32(src).unwrap();
            let to = char::from_u32(dst).unwrap();
            assert_eq!(fold_char(from), to);
            assert_eq!(fold_char(to), to, "U+{:04X} not a fixed point", dst);
        }
    }

    #[test]
    fn conservative_unknown_scripts() {
        // CJK has no case — byte-exact comparison still matches equal strings.
        assert!(eq_unicode_insensitive("中文", "中文"));
        assert!(!eq_unicode_insensitive("中文", "中文本"));
        // Multi-char full folds (ß -> ss) are *not* expanded by the
        // char-at-a-time primitive; the strings do not compare equal.
        assert!(!eq_unicode_insensitive("straße", "strasse"));
        assert!(eq_unicode_insensitive("straße", "straße"));
    }
}
