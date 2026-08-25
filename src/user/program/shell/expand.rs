//! src/user/program/shell/expand.rs
//!
//! Environment variable expansion, source/profile execution, and background
//! launch.

use super::dispatch::{dispatch_single_command, run_shell_command};
use super::entry::current_process;
use super::*;
use crate::user::shared::abi::fs::FILE_STAT_SIZE;
use crate::user::shared::abi::io::OPEN_FLAG_READ;
use crate::user::shared::syscall;

/// Save positional parameters from a slice of strings.
pub(crate) fn set_positional_params(args: &[String]) {
    let mut params = POSITIONAL_PARAMS.lock();
    params.clear();
    for a in args {
        params.push(a.clone());
    }
}

/// Source `~/.profile` if it exists.
pub(crate) fn source_profile(cwd: &mut String) {
    let home = match current_process() {
        Some(process) => process.home_dir(),
        None => return,
    };

    let profile_path = if home.ends_with('/') {
        format!("{home}.profile")
    } else {
        format!("{home}/.profile")
    };

    // Check if the file exists before trying to source it.
    let mut stat_buf = [0u8; FILE_STAT_SIZE];
    if syscall::sys_stat(&profile_path, &mut stat_buf).is_err() {
        return;
    }

    // Read and execute the profile file directly (avoid cmd_source to skip
    // the depth guard and extra error reporting).
    let content = match syscall::sys_open(&profile_path, OPEN_FLAG_READ) {
        Ok(fd) => {
            let mut buf = Vec::new();
            let mut chunk = [0u8; CAT_BUF_SIZE];
            loop {
                match syscall::sys_read(fd, &mut chunk, 0) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => {
                        let _ = syscall::sys_close(fd);
                        return;
                    }
                }
            }
            let _ = syscall::sys_close(fd);
            Some(String::from_utf8_lossy(&buf).into_owned())
        }
        Err(_) => None,
    };

    let content = match content {
        Some(c) => c,
        None => return,
    };

    let previous_cwd = cwd.clone();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let expanded = expand_env_vars(line);
        let result = run_shell_command(&expanded, cwd);
        if !result.output.is_empty() {
            crate::print!("{}", result.output);
        }
    }
    // Restore cwd (profile may have cd'd).
    *cwd = previous_cwd;
}

/// Entry point for a background command thread.
pub(crate) fn bg_entry() {
    let (cmd, cwd) = match BG_COMMAND.lock().take() {
        Some(v) => v,
        None => return,
    };
    let mut cwd_ref = cwd;
    let result = dispatch_single_command(&cmd, &mut cwd_ref, None);
    if !result.output.is_empty() && result.output != "\n" {
        crate::print!("{}", result.output);
    }
}

/// Expand `$VAR` and `${VAR}` references in the command line.
pub(crate) fn expand_env_vars(line: &str) -> String {
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
                let code = LAST_EXIT_CODE.load(core::sync::atomic::Ordering::Relaxed);
                result.push_str(&code.to_string());
                i += 2;
                continue;
            }
            // $# — positional parameter count
            if chars[start] == '#' {
                let count = POSITIONAL_PARAMS.lock().len();
                result.push_str(&count.to_string());
                i += 2;
                continue;
            }
            // $* / $@ — all positional parameters (space-joined)
            if chars[start] == '*' || chars[start] == '@' {
                let params = POSITIONAL_PARAMS.lock();
                let joined: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
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
                let params = POSITIONAL_PARAMS.lock();
                if let Some(val) = params.get(num.wrapping_sub(1)) {
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
                        let params = POSITIONAL_PARAMS.lock();
                        if let Some(val) = params.get(n.wrapping_sub(1)) {
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

/// Look up an environment variable.
pub(crate) fn get_env(name: &str) -> Option<String> {
    let vars = ENV_VARS.lock();
    for (key, val) in vars.iter() {
        if key == name {
            return Some(val.clone());
        }
    }
    None
}

/// Set (or remove, if val is empty) an environment variable.
pub(crate) fn set_env(name: &str, val: &str) {
    let mut vars = ENV_VARS.lock();
    if val.is_empty() {
        vars.retain(|(k, _)| k != name);
    } else {
        for (key, value) in vars.iter_mut() {
            if key == name {
                *value = val.to_string();
                return;
            }
        }
        vars.push((name.to_string(), val.to_string()));
    }
}

/// Check whether `line` ends with an unquoted `&` (background marker).
pub(crate) fn is_background(line: &str) -> bool {
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
