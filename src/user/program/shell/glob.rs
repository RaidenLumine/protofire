//! src/user/program/shell/glob.rs
//!
//! Glob pattern matching (`*`, `?`, `[...]` character classes).

use super::*;
use crate::user::shared::abi::fs::{DirectoryEntryRecord, DIRECTORY_ENTRY_RECORD_SIZE};
use crate::user::shared::syscall;

/// Check whether `name` matches the glob `pattern`.
/// Supports `*` (any sequence), `?` (any single char),
/// and `[...]` character classes.
pub(crate) fn glob_match(pattern: &str, name: &str) -> bool {
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
pub(crate) fn has_glob_chars(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Expand glob patterns in a token list.  Only tokens after index 0 (the
/// command name) are candidates for expansion.
pub(crate) fn expand_globs_in_tokens(tokens: &[String], cwd: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::with_capacity(tokens.len());
    for (i, token) in tokens.iter().enumerate() {
        if i > 0 && has_glob_chars(token) {
            let (dir, file_pat) = if let Some(last_slash) = token.rfind('/') {
                if last_slash == 0 {
                    (String::from("/"), token[1..].to_string())
                } else if token.starts_with('/') {
                    (
                        token[..last_slash].to_string(),
                        token[last_slash + 1..].to_string(),
                    )
                } else {
                    let mut d = cwd.to_string();
                    if !d.ends_with('/') {
                        d.push('/');
                    }
                    d.push_str(&token[..last_slash]);
                    (d, token[last_slash + 1..].to_string())
                }
            } else {
                (cwd.to_string(), token.clone())
            };

            let mut matches: Vec<String> = Vec::new();
            let name_buf_len = DIRECTORY_ENTRY_RECORD_SIZE + 256;
            let mut name_buf: Vec<u8> = alloc::vec![0u8; name_buf_len];
            let mut index = 0;
            while let Ok(()) = syscall::sys_read_dir(&dir, index, &mut name_buf) {
                let record: &DirectoryEntryRecord =
                    unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
                let name = core::str::from_utf8(
                    &name_buf[record.name_offset..record.name_offset + record.name_len],
                )
                .unwrap_or("");
                if name.starts_with('.') && !file_pat.starts_with('.') {
                    index += 1;
                    continue;
                }
                if glob_match(&file_pat, name) {
                    matches.push(name.to_string());
                }
                index += 1;
            }

            if matches.is_empty() {
                result.push(token.clone());
            } else {
                matches.sort();
                result.extend(matches);
            }
        } else {
            result.push(token.clone());
        }
    }
    result
}
