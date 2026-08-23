//! src/kernel/fs/unicode/normalize.rs
//! Unicode NFD / NFC normalization for on-disk filenames.
//!
//! Uses the auto-generated [`super::normalize_tables`] tables.  Only the
//! canonical decompositions (NFD) and the two-code-point compositions (NFC)
//! are supported — compatibility decompositions (NFKD/NFKC) are deliberately
//! excluded because filenames rarely need them and the table would balloon.
//!
//! The entry points are [`is_normalized_nfd`] / [`normalize_nfd`] and
//! [`is_normalized_nfc`] / [`normalize_nfc`].

use alloc::string::String;

use super::normalize_tables::{COMP_TABLE, DECOMP_TABLE};

/// Look up the canonical decomposition of `cp`, returning `None` if `cp`
/// is already fully decomposed.
fn canonical_decomposition(cp: u32) -> Option<&'static str> {
    DECOMP_TABLE
        .binary_search_by_key(&cp, |&(c, _)| c)
        .ok()
        .map(|idx| DECOMP_TABLE[idx].1)
}

/// Returns `true` if `s` is already in NFD (no decomposable code point).
pub fn is_normalized_nfd(s: &str) -> bool {
    s.chars()
        .all(|ch| canonical_decomposition(ch as u32).is_none())
}

/// Decompose `s` into NFD, recursively expanding every canonical
/// decomposition.
pub fn normalize_nfd(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        push_nfd(ch as u32, &mut out);
    }
    out
}

fn push_nfd(cp: u32, out: &mut String) {
    match canonical_decomposition(cp) {
        Some(decomp) => {
            for sub in decomp.chars() {
                push_nfd(sub as u32, out);
            }
        }
        None => {
            if let Some(ch) = char::from_u32(cp) {
                out.push(ch);
            }
        }
    }
}

/// Returns `true` if `s` is already in NFC (fully composed).
pub fn is_normalized_nfc(s: &str) -> bool {
    let mut out = String::with_capacity(s.len());
    compose_nfc(s, &mut out);
    out == s
}

/// Compose `s` into NFC using the two-code-point composition table.
///
/// This is a single-pass composition that handles the common case (base +
/// combining mark → precomposed).  It does not perform full reordering of
/// combining marks, which is adequate for the scripts used in on-disk names.
pub fn normalize_nfc(s: &str) -> String {
    let nfd = normalize_nfd(s);
    let mut out = String::with_capacity(nfd.len());
    compose_nfc(&nfd, &mut out);
    out
}

fn compose_nfc(s: &str, out: &mut String) {
    let chars: alloc::vec::Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let base = chars[i];
        // Try to compose `base` with the following combining character.
        if i + 1 < chars.len() {
            let comb = chars[i + 1];
            if let Some(composed) = compose_pair(base as u32, comb as u32) {
                out.push(composed);
                i += 2;
                continue;
            }
        }
        out.push(base);
        i += 1;
    }
}

fn compose_pair(base: u32, combining: u32) -> Option<char> {
    COMP_TABLE
        .binary_search_by(|&(b, c, _)| (b, c).cmp(&(base, combining)))
        .ok()
        .map(|idx| char::from_u32(COMP_TABLE[idx].2).expect("table entries are valid scalars"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfd_decomposes_accented_chars() {
        // U+00C1 LATIN CAPITAL LETTER A WITH ACUTE → A + U+0301
        assert_eq!(normalize_nfd("Á"), "A\u{301}");
        assert!(is_normalized_nfd("A\u{301}"));
        assert!(!is_normalized_nfd("Á"));
    }

    #[test]
    fn nfc_composes_back() {
        // NFC of "A + combining acute" is the precomposed Á.
        assert_eq!(normalize_nfc("A\u{301}"), "Á");
        assert!(is_normalized_nfc("Á"));
    }

    #[test]
    fn ascii_is_untouched() {
        assert_eq!(normalize_nfd("hello.txt"), "hello.txt");
        assert_eq!(normalize_nfc("hello.txt"), "hello.txt");
        assert!(is_normalized_nfd("hello.txt"));
        assert!(is_normalized_nfc("hello.txt"));
    }
}
