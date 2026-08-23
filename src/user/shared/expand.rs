//! src/user/shared/expand.rs
//! Environment variable expansion and shell utility functions.
//!
//! All functions accept state explicitly via parameters rather than accessing
//! global statics, making them usable in both ring0 (kernel) and ring3.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Expand `$VAR` and `${VAR}` references in the command line.
///
/// `last_exit_code` provides the value for `$?`.
/// `positional_params` provides `$1`-`$9`, `$*`, `$@`, `$#`.
/// `get_env` looks up named environment variables.
pub fn expand_env_vars(
    line: &str,
    last_exit_code: i32,
    positional_params: &[String],
    get_env: impl Fn(&str) -> Option<String>,
) -> String {
    let mut result = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\'' {
            // Don't expand inside single quotes.
            result.push(chars[i]);
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                result.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                result.push(chars[i]);
                i += 1;
            }
            continue;
        }
        if chars[i] == '$' && i + 1 < chars.len() {
            let start = i + 1;
            // $? — exit code of last foreground command
            if chars[start] == '?' {
                result.push_str(&last_exit_code.to_string());
                i += 2;
                continue;
            }
            // $# — positional parameter count
            if chars[start] == '#' {
                result.push_str(&positional_params.len().to_string());
                i += 2;
                continue;
            }
            // $* / $@ — all positional parameters (space-joined)
            if chars[start] == '*' || chars[start] == '@' {
                let joined: Vec<&str> = positional_params.iter().map(|s| s.as_str()).collect();
                result.push_str(&joined.join(" "));
                i += 2;
                continue;
            }
            // $1–$9 — single-digit positional parameter
            if chars[start].is_ascii_digit() && chars[start] != '0' {
                let mut num = 0usize;
                let mut j = start;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    num = num
                        .saturating_mul(10)
                        .saturating_add((chars[j] as usize).wrapping_sub('0' as usize));
                    j += 1;
                }
                if let Some(val) = positional_params.get(num.wrapping_sub(1)) {
                    result.push_str(val);
                }
                i = j;
                continue;
            }
            if chars[start] == '{' {
                // ${VAR} form
                let mut var = String::new();
                i = start + 1;
                while i < chars.len() && chars[i] != '}' {
                    var.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    i += 1; // skip '}'
                }
                // ${N} — positional parameter (numeric name)
                if var.chars().all(|c| c.is_ascii_digit()) && !var.is_empty() {
                    if let Ok(n) = var.parse::<usize>() {
                        if let Some(val) = positional_params.get(n.wrapping_sub(1)) {
                            result.push_str(val);
                        }
                        continue;
                    }
                }
                result.push_str(&get_env(&var).unwrap_or_default());
            } else if chars[start].is_alphanumeric() || chars[start] == '_' {
                // $VAR form
                let mut var = String::new();
                i = start;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    var.push(chars[i]);
                    i += 1;
                }
                result.push_str(&get_env(&var).unwrap_or_default());
            } else {
                result.push(chars[i]);
                i += 1;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

/// Look up an environment variable in the provided list.
pub fn get_env(name: &str, env_vars: &[(String, String)]) -> Option<String> {
    for (key, val) in env_vars {
        if key == name {
            return Some(val.clone());
        }
    }
    None
}

/// Set (or remove, if val is empty) an environment variable.
pub fn set_env(name: &str, val: &str, env_vars: &mut Vec<(String, String)>) {
    if val.is_empty() {
        env_vars.retain(|(k, _)| k != name);
    } else {
        for (key, value) in env_vars.iter_mut() {
            if key == name {
                *value = val.to_string();
                return;
            }
        }
        env_vars.push((name.to_string(), val.to_string()));
    }
}

/// Check whether `line` ends with an unquoted `&` (background marker).
pub fn is_background(line: &str) -> bool {
    let trimmed = line.trim_end();
    if !trimmed.ends_with('&') {
        return false;
    }
    // Check the & isn't inside quotes.
    let mut in_single = false;
    let mut in_double = false;
    for ch in trimmed.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            _ => {}
        }
    }
    !in_single && !in_double
}
