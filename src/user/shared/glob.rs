//! ring3-common/glob.rs
//! Glob pattern matching (`*`, `?`, `[...]` character classes).
//!
//! These are pure string-matching functions with no platform dependencies.
//! The pattern syntax follows POSIX shell glob conventions:
//!
//! - `*` matches any sequence of characters (including empty)
//! - `?` matches exactly one character
//! - `[...]` matches one character in the set; `[!...]` / `[^...]` negate
//! - `a-z` specifies a character range inside brackets
//! - Backslash escapes the next character for a literal match

use alloc::vec::Vec;

/// Check whether `name` matches the glob `pattern`.
///
/// Supports `*` (any sequence), `?` (any single char),
/// and `[...]` character classes with ranges and negation.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let nam: Vec<char> = name.chars().collect();
    glob_match_slice(&pat, 0, &nam, 0)
}

/// Recursive backtracking implementation of glob matching.
fn glob_match_slice(pat: &[char], pi: usize, s: &[char], si: usize) -> bool {
    let mut pi = pi;
    let mut si = si;

    while pi < pat.len() {
        match pat[pi] {
            '*' => {
                // Skip consecutive stars.
                while pi < pat.len() && pat[pi] == '*' {
                    pi += 1;
                }
                if pi == pat.len() {
                    return true; // trailing * matches everything
                }
                // Try matching the rest of the pattern at every position.
                for k in si..=s.len() {
                    if glob_match_slice(pat, pi, s, k) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                if si >= s.len() {
                    return false;
                }
                pi += 1;
                si += 1;
            }
            '[' => {
                if si >= s.len() {
                    return false;
                }
                pi += 1; // skip '['
                let mut matched = false;
                let mut negate = false;
                if pi < pat.len() && (pat[pi] == '!' || pat[pi] == '^') {
                    negate = true;
                    pi += 1;
                }
                let mut prev: Option<char> = None;
                loop {
                    if pi >= pat.len() {
                        return false; // unterminated bracket
                    }
                    if pat[pi] == ']' && prev.is_some() && prev != Some('[') {
                        pi += 1; // skip ']'
                        break;
                    }
                    // Range: a-z
                    if pi + 2 < pat.len() && pat[pi + 1] == '-' && pat[pi + 2] != ']' {
                        let lo = pat[pi];
                        let hi = pat[pi + 2];
                        if (lo..=hi).contains(&s[si]) {
                            matched = true;
                        }
                        pi += 3;
                        prev = Some(hi);
                    } else {
                        if pat[pi] == s[si] {
                            matched = true;
                        }
                        prev = Some(pat[pi]);
                        pi += 1;
                    }
                }
                if negate {
                    matched = !matched;
                }
                if !matched {
                    return false;
                }
                si += 1;
            }
            '\\' => {
                // Escaped character: match literally.
                pi += 1;
                if pi < pat.len() {
                    if si >= s.len() || pat[pi] != s[si] {
                        return false;
                    }
                    pi += 1;
                    si += 1;
                }
            }
            ch => {
                if si >= s.len() || ch != s[si] {
                    return false;
                }
                pi += 1;
                si += 1;
            }
        }
    }

    // Pattern exhausted — must also have exhausted the string.
    si == s.len()
}

/// Returns `true` if `s` contains any glob-special characters (`*`, `?`, `[`).
pub fn has_glob_chars(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_match() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn star_matches_everything() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*.txt", "file.txt"));
        assert!(!glob_match("*.txt", "file.md"));
    }

    #[test]
    fn question_matches_one_char() {
        assert!(glob_match("h?llo", "hello"));
        assert!(!glob_match("h?llo", "hllo"));
    }

    #[test]
    fn char_class() {
        assert!(glob_match("file[0-9].txt", "file5.txt"));
        assert!(!glob_match("file[0-9].txt", "filea.txt"));
        assert!(glob_match("file[!0-9].txt", "filea.txt"));
        assert!(!glob_match("file[!0-9].txt", "file5.txt"));
    }

    #[test]
    fn has_glob_chars_detects() {
        assert!(has_glob_chars("*.txt"));
        assert!(has_glob_chars("file?.txt"));
        assert!(has_glob_chars("file[0-9].txt"));
        assert!(!has_glob_chars("plain.txt"));
    }

    #[test]
    fn star_then_text() {
        assert!(glob_match("foo*bar", "foobar"));
        assert!(glob_match("foo*bar", "fooXXXbar"));
        assert!(!glob_match("foo*bar", "fooXXXbaz"));
    }

    #[test]
    fn escaped_literal() {
        assert!(glob_match("file\\*.txt", "file*.txt"));
        assert!(!glob_match("file\\*.txt", "fileX.txt"));
    }
}
