//! ring3-common/pipeline.rs
//! Conditional chaining (`&&` / `||`), pipeline splitting, and redirect parsing.
//!
//! These are pure string-processing functions with no platform dependencies.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ─── Conditional chaining (&& / ||) ───────────────────────────────────

/// A segment of a conditionally-chained command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CondToken {
    /// A command string (may contain pipes and redirects).
    Cmd(String),
    /// `&&` operator — next command runs only if previous succeeded.
    And,
    /// `||` operator — next command runs only if previous failed.
    Or,
}

/// Tokenize a command line into [`CondToken`] segments, splitting on
/// unquoted `&&` and `||` operators.
pub fn tokenize_conditionals(line: &str) -> Vec<CondToken> {
    let mut tokens: Vec<CondToken> = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if escape {
            current.push(ch);
            escape = false;
            i += 1;
            continue;
        }

        match ch {
            '\\' => {
                current.push(ch);
                escape = true;
                i += 1;
            }
            '\'' if !in_double => {
                current.push(ch);
                in_single = !in_single;
                i += 1;
            }
            '"' if !in_single => {
                current.push(ch);
                in_double = !in_double;
                i += 1;
            }
            '&' if !in_single && !in_double && i + 1 < chars.len() && chars[i + 1] == '&' => {
                // && operator
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    tokens.push(CondToken::Cmd(trimmed));
                }
                current.clear();
                tokens.push(CondToken::And);
                i += 2;
            }
            '|' if !in_single && !in_double && i + 1 < chars.len() && chars[i + 1] == '|' => {
                // || operator
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    tokens.push(CondToken::Cmd(trimmed));
                }
                current.clear();
                tokens.push(CondToken::Or);
                i += 2;
            }
            _ => {
                current.push(ch);
                i += 1;
            }
        }
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        tokens.push(CondToken::Cmd(trimmed));
    }

    tokens
}

// ─── Pipeline and redirect parsing helpers ────────────────────────────

/// Returns `true` if the line contains any shell operator (`|`, `>`, `<`).
pub fn has_shell_operator(line: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    for ch in line.chars() {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' => escape = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '|' | '>' | '<' if !in_single && !in_double => return true,
            _ => {}
        }
    }
    false
}

/// Split a command line on unquoted `|` into pipeline stages.
pub fn split_pipeline(line: &str) -> Vec<String> {
    let mut stages = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for ch in line.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' => {
                current.push(ch);
                escape = true;
            }
            '\'' if !in_double => {
                current.push(ch);
                in_single = !in_single;
            }
            '"' if !in_single => {
                current.push(ch);
                in_double = !in_double;
            }
            '|' if !in_single && !in_double => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    stages.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        stages.push(trimmed);
    }

    stages
}

/// Parse redirect operators from a pipeline stage, returning
/// `(command_string, output_redirect_file, input_redirect_file)`.
pub fn parse_redirects(stage: &str) -> (String, Option<String>, Option<String>) {
    let mut redirect_out: Option<String> = None;
    let mut redirect_in: Option<String> = None;
    let mut cmd = String::new();
    let mut i = 0;
    let chars: Vec<char> = stage.chars().collect();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    while i < chars.len() {
        let ch = chars[i];

        if escape {
            cmd.push(ch);
            escape = false;
            i += 1;
            continue;
        }

        match ch {
            '\\' => {
                cmd.push(ch);
                escape = true;
                i += 1;
                continue;
            }
            '\'' if !in_double => {
                cmd.push(ch);
                in_single = !in_single;
                i += 1;
                continue;
            }
            '"' if !in_single => {
                cmd.push(ch);
                in_double = !in_double;
                i += 1;
                continue;
            }
            '>' | '<' if !in_single && !in_double => {
                let is_output = ch == '>';

                // Check for "2>" (stderr redirect).  The '2' must be a
                // separate token: at the very start or preceded by a space.
                let is_stderr =
                    is_output && i > 0 && chars[i - 1] == '2' && (i == 1 || chars[i - 2] == ' ');

                if is_stderr {
                    // Remove the " 2" prefix from cmd.
                    cmd = cmd.trim_end().to_string();
                    if cmd.ends_with('2') {
                        cmd.pop();
                    }
                }

                i += 1; // consume '>' or '<'

                // Skip whitespace between operator and filename.
                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }

                // Read filename — support quoted filenames so that
                // `> "my file.txt"` works.
                let filename = read_redirect_filename(&chars, &mut i);

                if !filename.is_empty() {
                    if is_output || is_stderr {
                        redirect_out = Some(filename);
                    } else {
                        redirect_in = Some(filename);
                    }
                }
                // Remove trailing space from cmd (the one before the
                // operator).
                cmd = cmd.trim_end().to_string();
            }
            _ => {
                cmd.push(ch);
                i += 1;
            }
        }
    }

    (cmd.trim().to_string(), redirect_out, redirect_in)
}

/// Read a filename token following a redirect operator.
///
/// Supports unquoted, single-quoted, and double-quoted filenames.
/// Stops at an unquoted space or `|`.
pub fn read_redirect_filename(chars: &[char], i: &mut usize) -> String {
    let mut filename = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    while *i < chars.len() {
        let ch = chars[*i];

        if escape {
            filename.push(ch);
            escape = false;
            *i += 1;
            continue;
        }

        if in_single {
            filename.push(ch);
            if ch == '\'' {
                in_single = false;
            }
            *i += 1;
            continue;
        }

        if in_double {
            if ch == '\\' {
                escape = true;
            } else {
                filename.push(ch);
                if ch == '"' {
                    in_double = false;
                }
            }
            *i += 1;
            continue;
        }

        match ch {
            ' ' | '\t' | '|' => break,
            '\\' => {
                escape = true;
                *i += 1;
            }
            '\'' => {
                filename.push(ch);
                in_single = true;
                *i += 1;
            }
            '"' => {
                filename.push(ch);
                in_double = true;
                *i += 1;
            }
            _ => {
                filename.push(ch);
                *i += 1;
            }
        }
    }

    filename
}

/// Strip a single trailing `\n` from a string, if present.
pub fn strip_trailing_newline(s: String) -> String {
    if s.ends_with('\n') {
        let mut trimmed = s;
        trimmed.pop();
        trimmed
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn tokenize_conditionals_and() {
        let tokens = tokenize_conditionals("echo hello && echo world");
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], CondToken::Cmd("echo hello".to_string()));
        assert_eq!(tokens[1], CondToken::And);
        assert_eq!(tokens[2], CondToken::Cmd("echo world".to_string()));
    }

    #[test]
    fn tokenize_conditionals_or() {
        let tokens = tokenize_conditionals("false || true");
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], CondToken::Cmd("false".to_string()));
        assert_eq!(tokens[1], CondToken::Or);
        assert_eq!(tokens[2], CondToken::Cmd("true".to_string()));
    }

    #[test]
    fn split_pipe() {
        let stages = split_pipeline("cat file | grep foo");
        assert_eq!(stages.len(), 2);
        assert_eq!(stages[0], "cat file");
        assert_eq!(stages[1], "grep foo");
    }

    #[test]
    fn split_no_pipe() {
        let stages = split_pipeline("echo hello");
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0], "echo hello");
    }

    #[test]
    fn parse_output_redirect() {
        let (cmd, out, inp) = parse_redirects("echo hello > out.txt");
        assert_eq!(cmd, "echo hello");
        assert_eq!(out, Some("out.txt".to_string()));
        assert_eq!(inp, None);
    }

    #[test]
    fn parse_input_redirect() {
        let (cmd, out, inp) = parse_redirects("cat < in.txt");
        assert_eq!(cmd, "cat");
        assert_eq!(out, None);
        assert_eq!(inp, Some("in.txt".to_string()));
    }

    #[test]
    fn has_shell_operator_detects_pipe() {
        assert!(has_shell_operator("cat | grep"));
        assert!(!has_shell_operator("echo hello"));
    }

    #[test]
    fn strip_newline_removes_trailing() {
        assert_eq!(strip_trailing_newline("hello\n".to_string()), "hello");
        assert_eq!(strip_trailing_newline("hello".to_string()), "hello");
    }

    #[test]
    fn quoted_operators_not_split() {
        let stages = split_pipeline("echo \"hello | world\"");
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0], "echo \"hello | world\"");
    }
}
