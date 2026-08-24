//! src/user/program/shell/commands/env.rs
//!
//! Environment, variable, and shell-state commands (source).

use super::super::dispatch::run_shell_command;
use super::super::expand::{expand_env_vars, set_positional_params};
use super::super::*;
use crate::abi::io::OPEN_FLAG_READ;
use crate::user::shared::syscall;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// `source <file> [args...]` — run a shell script from the current context.
pub(crate) fn cmd_source(cwd: &mut String, argv: &[String]) -> CmdResult {
    if argv.len() < 2 {
        return CmdResult::error(2, "source: usage: source <file> [args...]\n".into());
    }

    // Depth guard.
    {
        let mut depth = SOURCE_DEPTH.lock();
        if *depth >= SOURCE_MAX_DEPTH {
            return CmdResult::error(
                1,
                format!("source: maximum nesting depth ({SOURCE_MAX_DEPTH}) exceeded\n"),
            );
        }
        *depth += 1;
    }

    // Save and restore positional parameters.
    let saved_params = POSITIONAL_PARAMS.lock().clone();
    if argv.len() > 2 {
        set_positional_params(&argv[2..]);
    }

    let result = source_impl(cwd, argv);

    // Restore positional parameters.
    {
        let mut params = POSITIONAL_PARAMS.lock();
        *params = saved_params;
    }

    {
        let mut depth = SOURCE_DEPTH.lock();
        *depth = depth.saturating_sub(1);
    }

    result
}

fn source_impl(cwd: &mut String, argv: &[String]) -> CmdResult {
    let path = resolve_path(cwd, &argv[1]);

    let content = {
        match syscall::sys_open(&path, OPEN_FLAG_READ) {
            Ok(fd) => {
                let mut buf = Vec::new();
                let mut chunk = [0u8; CAT_BUF_SIZE];
                let inner = loop {
                    match syscall::sys_read(fd, &mut chunk, 0) {
                        Ok(0) => {
                            break CmdResult::success(String::from_utf8_lossy(&buf).into_owned())
                        }
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => {
                            let _ = syscall::sys_close(fd);
                            break CmdResult::error(
                                1,
                                format!("source: read error `{}`\n", argv[1]),
                            );
                        }
                    }
                };
                let _ = syscall::sys_close(fd);
                inner
            }
            Err(_) => CmdResult::error(1, format!("source: cannot open `{}`\n", argv[1])),
        }
    };

    if content.exit_code != 0 {
        return content;
    }

    let script = content.output;
    let mut last_result = CmdResult::empty();

    for raw_line in script.lines() {
        let line = raw_line.trim();
        // Skip empty lines and comments (including shebang).
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Expand environment variables.
        let expanded = expand_env_vars(line);
        last_result = run_shell_command(&expanded, cwd);
    }

    last_result
}
