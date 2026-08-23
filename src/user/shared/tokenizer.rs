//! ring3-common/tokenizer.rs
//! Shell word tokenizer — splits input lines into argument tokens.
//!
//! Supports single-quoted strings, double-quoted strings, and backslash
//! escapes.  Reports unterminated quotes as errors.

use alloc::string::String;
use alloc::vec::Vec;

/// Result type for [`tokenize`]: either a list of tokens or an error message.
pub type TokenizeResult = Result<Vec<String>, String>;

/// Split a shell input line into argument tokens.
///
/// Rules:
/// - Unquoted whitespace separates tokens.
/// - Single quotes (`'...'`) preserve literal text (no escapes).
/// - Double quotes (`"..."`) preserve literal text except for backslash
///   escapes (`\n`, `\t`, `\\`, `\"`, etc.).
/// - Backslash outside quotes escapes the next character.
///
/// # Errors
///
/// Returns `Err` with a human-readable message when a quoted string is
/// never closed.
pub fn tokenize(line: &str) -> TokenizeResult {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if escape {
            // Process escaped character.
            match ch {
                'n' => current.push('\n'),
                't' => current.push('\t'),
                'r' => current.push('\r'),
                '\\' => current.push('\\'),
                '"' => current.push('"'),
                '\'' => current.push('\''),
                ' ' => current.push(' '),
                other => {
                    // Unknown escape — emit the backslash and the character literally.
                    current.push('\\');
                    current.push(other);
                }
            }
            escape = false;
            i += 1;
            continue;
        }

        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
        } else if in_double {
            if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_double = false;
            } else {
                current.push(ch);
            }
        } else {
            match ch {
                '\\' => escape = true,
                '\'' => in_single = true,
                '"' => in_double = true,
                ' ' | '\t' | '\r' | '\n' => {
                    if !current.is_empty() {
                        tokens.push(current.clone());
                        current.clear();
                    }
                }
                _ => current.push(ch),
            }
        }
        i += 1;
    }

    // Trailing backslash outside quotes: treat as literal backslash.
    if escape {
        current.push('\\');
    }

    // Report unterminated quotes.
    if in_single {
        return Err(String::from("unterminated single quote (expected ')"));
    }
    if in_double {
        return Err(String::from("unterminated double quote (expected \")"));
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Ok(tokens)
}
