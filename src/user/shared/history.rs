//! src/user/shared/history.rs
//!
//! Command history utilities.
//!
//! All functions accept state explicitly via parameters rather than accessing
//! global statics.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Find the longest common prefix of a list of strings.
pub fn common_prefix(strings: &[String]) -> String {
    if strings.is_empty() {
        return String::new();
    }
    let first = strings[0].as_bytes();
    let mut len = first.len();
    for s in &strings[1..] {
        let b = s.as_bytes();
        let mut i = 0;
        while i < len && i < b.len() && first[i] == b[i] {
            i += 1;
        }
        len = i;
        if len == 0 {
            break;
        }
    }
    String::from_utf8_lossy(&first[..len]).to_string()
}

/// Add a command to the history ring buffer.
///
/// `max_entries` controls the maximum number of entries retained.
/// Duplicate consecutive entries and empty/`!!` lines are rejected.
pub fn add_history(line: &str, history: &mut Vec<String>, max_entries: usize) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed == "!!" {
        return;
    }
    // De-duplicate: don't push consecutive identical lines.
    if history.last().map(|s| s.as_str()) == Some(trimmed) {
        return;
    }
    history.push(trimmed.to_string());
    if history.len() > max_entries {
        history.remove(0);
    }
}

/// Expand `!!` (last command) and `!N` (command N in history).
pub fn expand_history(line: &str, history: &[String]) -> String {
    if let Some(rest) = line.strip_prefix("!!") {
        if let Some(last) = history.last() {
            let mut expanded = last.clone();
            expanded.push_str(rest);
            return expanded;
        }
        return "echo shell: no previous command".to_string();
    }
    if let Some(rest) = line.strip_prefix('!') {
        if let Ok(n) = rest.parse::<usize>() {
            if n > 0 && n <= history.len() {
                return history[history.len() - n].clone();
            }
            return alloc::format!("echo shell: !{n}: event not found");
        }
    }
    line.to_string()
}
