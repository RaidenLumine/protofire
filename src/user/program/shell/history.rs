//! src/user/program/shell/history.rs
//! Readline callbacks, command history, and history expansion.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

// ─── History recording ────────────────────────────────────────────────

/// Append `line` to the command history, capping the history at
/// [`HISTORY_MAX`] entries and skipping consecutive duplicates.
pub(crate) fn add_history(line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let mut history = HISTORY.lock();
    if history.last().map(|last| last == line).unwrap_or(false) {
        return;
    }
    history.push(line.to_string());
    while history.len() > HISTORY_MAX {
        history.remove(0);
    }
}

// ── History expansion ─────────────────────────────────────────────────

/// Expand `!!` (last command), `!N` (Nth command), and `!-N` (N commands
/// back) references in `line`.  Unresolvable references are left literal.
pub(crate) fn expand_history(line: String) -> String {
    if !line.contains('!') {
        return line;
    }
    let history = HISTORY.lock();
    if history.is_empty() {
        return line;
    }

    let chars: Vec<char> = line.chars().collect();
    let mut result = String::with_capacity(line.len());
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '!' && i + 1 < chars.len() {
            let next = chars[i + 1];
            if next == '!' {
                // `!!` — the most recent command.
                if let Some(last) = history.last() {
                    result.push_str(last);
                    i += 2;
                    continue;
                }
            } else if next.is_ascii_digit() || next == '-' {
                // `!N` / `!-N` — numeric reference.
                let neg = next == '-';
                let mut j = i + 1 + usize::from(neg);
                let digits_start = j;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
                if j > digits_start {
                    let number: String = chars[digits_start..j].iter().collect();
                    if let Ok(n) = number.parse::<usize>() {
                        let index = if neg {
                            history.len().saturating_sub(n)
                        } else {
                            // `!1` is the first command in history.
                            n.saturating_sub(1)
                        };
                        if index < history.len() {
                            result.push_str(&history[index]);
                            i = j;
                            continue;
                        }
                    }
                }
            }
        }
        result.push(ch);
        i += 1;
    }
    result
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_double_bang_uses_last_command() {
        {
            let mut history = HISTORY.lock();
            history.clear();
            history.push(String::from("echo one"));
            history.push(String::from("echo two"));
        }
        assert_eq!(expand_history(String::from("!! extra")), "echo two extra");
        assert_eq!(expand_history(String::from("echo three")), "echo three");
    }

    #[test]
    fn expand_numeric_references() {
        {
            let mut history = HISTORY.lock();
            history.clear();
            history.push(String::from("ls"));
            history.push(String::from("cd /tmp"));
            history.push(String::from("pwd"));
        }
        assert_eq!(expand_history(String::from("!1")), "ls");
        assert_eq!(expand_history(String::from("!3")), "pwd");
        assert_eq!(expand_history(String::from("!-2")), "cd /tmp");
        // Out-of-range references stay literal.
        assert_eq!(expand_history(String::from("!99")), "!99");
    }

    #[test]
    fn add_history_dedupes_and_caps() {
        {
            let mut history = HISTORY.lock();
            history.clear();
        }
        add_history("  echo a  ");
        add_history("echo a");
        add_history("echo b");
        add_history("echo c");
        add_history("echo d");
        let history = HISTORY.lock();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0], "echo a");
        assert_eq!(history[3], "echo d");
    }
}
