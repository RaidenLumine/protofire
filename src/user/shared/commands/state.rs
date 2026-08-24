//! src/user/shared/commands/state.rs
//!
//! Shell state management commands (export, alias, history, shift, read, source).
//!
//! All commands accept shell state via explicit parameters so they work
//! identically in ring0 (kernel Mutex statics) and ring3 (local variables).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::user::shared::abi::io::OPEN_FLAG_READ;
use crate::user::shared::expand::expand_env_vars;
use crate::user::shared::path_util::resolve_path;
use crate::user::shared::syscall;
use crate::user::shared::types::CmdResult;

const CAT_BUF_SIZE: usize = 4096;

// ── Helpers ─────────────────────────────────────────────────────────────

/// Look up an environment variable by name.
fn get_env(name: &str, env_vars: &[(String, String)]) -> Option<String> {
    env_vars
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// Set (or replace) an environment variable.
fn set_env(name: &str, val: &str, env_vars: &mut Vec<(String, String)>) {
    if let Some(existing) = env_vars.iter_mut().find(|(k, _)| k == name) {
        existing.1 = val.to_string();
    } else {
        env_vars.push((name.to_string(), val.to_string()));
    }
}

// ─── export ─────────────────────────────────────────────────────────────

pub fn cmd_export(argv: &[String], env_vars: &mut Vec<(String, String)>) -> CmdResult {
    if argv.len() < 2 {
        // Print all env vars.
        if env_vars.is_empty() {
            return CmdResult::from_output(String::from("(no environment variables set)\n"));
        }
        let mut out = String::new();
        for (key, val) in env_vars.iter() {
            out.push_str(&format!("{key}={val}\n"));
        }
        return CmdResult::from_output(out);
    }
    let arg = &argv[1];
    if let Some(eq) = arg.find('=') {
        let name = &arg[..eq];
        let val = &arg[eq + 1..];
        if name.is_empty() {
            return CmdResult::error(1, String::from("export: invalid identifier\n"));
        }
        set_env(name, val, env_vars);
        CmdResult::empty()
    } else {
        // Print specific variable.
        match get_env(arg, env_vars) {
            Some(val) => CmdResult::from_output(format!("{val}\n")),
            None => CmdResult::empty(),
        }
    }
}

// ─── alias ──────────────────────────────────────────────────────────────

pub fn cmd_alias(argv: &[String], aliases: &mut Vec<(String, String)>) -> CmdResult {
    if argv.len() < 2 {
        // List all aliases.
        if aliases.is_empty() {
            return CmdResult::from_output(String::from("(no aliases defined)\n"));
        }
        let mut out = String::new();
        for (name, value) in aliases.iter() {
            out.push_str(&format!("alias {name}='{value}'\n"));
        }
        return CmdResult::from_output(out);
    }

    let arg = &argv[1];

    // Check for `name=value` form.
    if let Some(eq) = arg.find('=') {
        let name = &arg[..eq];
        let value = &arg[eq + 1..];
        if name.is_empty() {
            return CmdResult::error(1, String::from("alias: invalid alias name\n"));
        }
        // Remove existing alias with the same name.
        aliases.retain(|(n, _)| n != name);
        aliases.push((name.to_string(), value.to_string()));
        return CmdResult::empty();
    }

    // `alias name` — show specific alias.
    for (name, value) in aliases.iter() {
        if name == arg {
            return CmdResult::from_output(format!("alias {name}='{value}'\n"));
        }
    }
    CmdResult::error(1, format!("alias: {arg}: not found\n"))
}

// ─── history ────────────────────────────────────────────────────────────

pub fn cmd_history(history: &[String]) -> CmdResult {
    if history.is_empty() {
        return CmdResult::from_output(String::from("(no history)\n"));
    }
    let mut out = String::new();
    for (i, cmd) in history.iter().enumerate() {
        out.push_str(&format!("{:>4}  {}\n", i + 1, cmd));
    }
    CmdResult::from_output(out)
}

// ─── shift ──────────────────────────────────────────────────────────────

pub fn cmd_shift(argv: &[String], positional_params: &mut Vec<String>) -> CmdResult {
    let n: usize = if argv.len() > 1 {
        match argv[1].parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => return CmdResult::error(1, format!("shift: invalid count `{}`\n", argv[1])),
        }
    } else {
        1
    };

    if n >= positional_params.len() {
        positional_params.clear();
    } else {
        positional_params.drain(..n);
    }
    CmdResult::empty()
}

// ─── read ───────────────────────────────────────────────────────────────

/// `read <variable>` — read a line from stdin into an environment variable.
///
/// `read_line_fn` abstracts stdin reading (kernel console vs ring3 fd 0).
pub fn cmd_read(
    argv: &[String],
    env_vars: &mut Vec<(String, String)>,
    mut read_line_fn: impl FnMut() -> Option<String>,
) -> CmdResult {
    if argv.len() < 2 {
        return CmdResult::error(1, String::from("read: usage: read <variable>\n"));
    }
    let var_name = &argv[1];

    match read_line_fn() {
        Some(line) => {
            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
            set_env(var_name, trimmed, env_vars);
            CmdResult::empty()
        }
        None => CmdResult::error(1, String::from("read: read error or timed out\n")),
    }
}

// ─── source ─────────────────────────────────────────────────────────────

/// `source <file> [args...]` — execute commands from a file.
///
/// `exec_fn(cmd_line, cwd) -> CmdResult` runs each line as a shell command.
/// `source_depth` tracks nesting to prevent infinite recursion.
pub fn cmd_source(
    cwd: &mut String,
    argv: &[String],
    env_vars: &[(String, String)],
    positional_params: &mut Vec<String>,
    source_depth: &mut u32,
    max_depth: u32,
    exec_fn: impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    if argv.len() < 2 {
        return CmdResult::error(1, String::from("source: usage: source <file> [args...]\n"));
    }

    // Depth guard.
    if *source_depth >= max_depth {
        return CmdResult::error(
            1,
            format!("source: maximum nesting depth ({max_depth}) exceeded\n"),
        );
    }
    *source_depth += 1;

    // Save and restore positional parameters.
    let saved_params = positional_params.clone();
    if argv.len() > 2 {
        positional_params.clear();
        for arg in &argv[2..] {
            positional_params.push(arg.clone());
        }
    }

    let result = source_impl(cwd, argv, env_vars, exec_fn);

    // Restore positional parameters.
    *positional_params = saved_params;
    *source_depth = source_depth.saturating_sub(1);

    result
}

fn source_impl(
    cwd: &mut String,
    argv: &[String],
    env_vars: &[(String, String)],
    mut exec_fn: impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    let path = resolve_path(cwd, &argv[1]);

    let fd = match syscall::sys_open(&path, OPEN_FLAG_READ) {
        Ok(fd) => fd,
        Err(_) => {
            return CmdResult::error(1, format!("source: cannot open `{}`\n", argv[1]));
        }
    };

    let mut content = Vec::new();
    let mut chunk = [0u8; CAT_BUF_SIZE];
    loop {
        match syscall::sys_read(fd, &mut chunk, 0) {
            Ok(0) => break,
            Ok(n) => content.extend_from_slice(&chunk[..n]),
            Err(_) => {
                let _ = syscall::sys_close(fd);
                return CmdResult::error(1, format!("source: read error `{}`\n", argv[1]));
            }
        }
    }
    let _ = syscall::sys_close(fd);

    let script = String::from_utf8_lossy(&content).into_owned();
    let mut last_result = CmdResult::empty();

    let get_env_closure = |name: &str| -> Option<String> { get_env(name, env_vars) };

    for raw_line in script.lines() {
        let line = raw_line.trim();
        // Skip empty lines and comments (including shebang).
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Expand environment variables.
        let expanded = expand_env_vars(line, 0, &[], get_env_closure);
        last_result = exec_fn(&expanded, cwd);
    }

    last_result
}
