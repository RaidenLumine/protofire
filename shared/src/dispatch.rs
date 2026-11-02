//! shared/src/dispatch.rs
//!
//! ring3-common/src/dispatch.rs
//! Shared command dispatch table.
//!
//! Maps command names to their implementations.  The kernel extends this with
//! kernel-only commands (network, user management, job control) in its own
//! dispatch wrapper.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::commands::cmd_alias;
use crate::commands::cmd_cat;
use crate::commands::cmd_cd;
use crate::commands::cmd_chmod;
use crate::commands::cmd_clear;
use crate::commands::cmd_cp;
use crate::commands::cmd_df;
use crate::commands::cmd_diff;
use crate::commands::cmd_dmesg;
use crate::commands::cmd_du;
use crate::commands::cmd_echo;
use crate::commands::cmd_edit;
use crate::commands::cmd_export;
use crate::commands::cmd_false;
use crate::commands::cmd_find;
use crate::commands::cmd_fuse;
use crate::commands::cmd_grep;
use crate::commands::cmd_head;
use crate::commands::cmd_help;
use crate::commands::cmd_hexdump;
use crate::commands::cmd_history;
use crate::commands::cmd_kill;
use crate::commands::cmd_ls;
use crate::commands::cmd_mkdir;
use crate::commands::cmd_mv;
use crate::commands::cmd_perf;
use crate::commands::cmd_ps;
use crate::commands::cmd_pwd;
use crate::commands::cmd_read;
use crate::commands::cmd_rm;
use crate::commands::cmd_shift;
use crate::commands::cmd_sleep;
use crate::commands::cmd_sort;
use crate::commands::cmd_source;
use crate::commands::cmd_sysinfo;
use crate::commands::cmd_tail;
use crate::commands::cmd_test;
use crate::commands::cmd_top;
use crate::commands::cmd_touch;
use crate::commands::cmd_true;
use crate::commands::cmd_uname;
use crate::commands::cmd_uniq;
use crate::commands::cmd_uptime;
use crate::commands::cmd_wc;
use crate::tokenizer::tokenize;
use crate::types::CmdResult;

/// Maximum nesting depth for `source` commands.
const SOURCE_MAX_DEPTH: u32 = 16;

/// Dispatch a single command line (already expanded, tokenized internally).
///
/// State parameters are passed explicitly so this works in both ring0 (kernel
/// Mutex statics) and ring3 (local variables).
///
/// `cwd` is the current working directory (mutated by `cd`).
/// `stdin` is optional input for commands that read from stdin (via `<`
/// redirect). `home_dir` is the home directory for `cd ~`.
/// `env_vars` — environment variables (for `export`, `read`, `source`).
/// `aliases` — command aliases (for `alias`).
/// `history` — command history (for `history`).
/// `positional_params` — $1, $2, ... (for `shift`, `source`).
/// `source_depth` — nesting counter (for `source`).
/// `read_line_fn` — reads a line from stdin (for `read`).
/// `exec_fn` — executes a shell command line (for `source`).
#[allow(clippy::too_many_arguments)]
pub fn dispatch_single_command(
    cmd_line: &str,
    cwd: &mut String,
    stdin: Option<&str>,
    home_dir: Option<&str>,
    env_vars: &mut Vec<(String, String)>,
    aliases: &mut Vec<(String, String)>,
    history: &[String],
    positional_params: &mut Vec<String>,
    source_depth: &mut u32,
    read_line_fn: impl FnMut() -> Option<String>,
    exec_fn: impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    let tokens = match tokenize(cmd_line) {
        Ok(t) => t,
        Err(e) => return CmdResult::error(1, format!("shell: {e}\n")),
    };
    dispatch_tokens(
        &tokens,
        cwd,
        stdin,
        home_dir,
        env_vars,
        aliases,
        history,
        positional_params,
        source_depth,
        read_line_fn,
        exec_fn,
    )
}

/// Dispatch pre-tokenized argv (no tokenization, no alias/glob expansion).
///
/// Callers that do their own pre-processing (alias expansion, glob expansion)
/// should call this directly to avoid redundant tokenization.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_tokens(
    tokens: &[String],
    cwd: &mut String,
    stdin: Option<&str>,
    home_dir: Option<&str>,
    env_vars: &mut Vec<(String, String)>,
    aliases: &mut Vec<(String, String)>,
    history: &[String],
    positional_params: &mut Vec<String>,
    source_depth: &mut u32,
    read_line_fn: impl FnMut() -> Option<String>,
    exec_fn: impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    if tokens.is_empty() {
        return CmdResult::empty();
    }

    let command = tokens[0].as_str();
    let argv = tokens;

    match command {
        "help" => cmd_help(argv),
        "echo" => cmd_echo(argv),
        "clear" => cmd_clear(),
        "true" => cmd_true(),
        "false" => cmd_false(),
        "fuse" => cmd_fuse(argv),
        "pwd" => cmd_pwd(cwd),
        "cd" => cmd_cd(cwd, argv, home_dir),
        "cat" => cmd_cat(cwd, argv, stdin),
        "hexdump" => cmd_hexdump(cwd, argv),
        "ls" => cmd_ls(cwd, argv),
        "mkdir" => cmd_mkdir(cwd, argv),
        "rm" => cmd_rm(cwd, argv),
        "touch" => cmd_touch(cwd, argv),
        "cp" => cmd_cp(cwd, argv),
        "mv" => cmd_mv(cwd, argv),
        "grep" => cmd_grep(cwd, argv, stdin),
        "find" => cmd_find(cwd, argv),
        "head" => cmd_head(cwd, argv, stdin),
        "tail" => cmd_tail(cwd, argv, stdin),
        "wc" => cmd_wc(cwd, argv, stdin),
        "sort" => cmd_sort(cwd, argv, stdin),
        "uniq" => cmd_uniq(cwd, argv, stdin),
        "diff" => cmd_diff(cwd, argv),
        "edit" => cmd_edit(cwd, argv),
        "ps" => cmd_ps(argv),
        "kill" => cmd_kill(argv),
        "sysinfo" => cmd_sysinfo(),
        "top" => cmd_top(argv),
        "dmesg" => cmd_dmesg(argv),
        "uname" => cmd_uname(argv),
        "uptime" => cmd_uptime(),
        "sleep" => cmd_sleep(argv),
        "perf" => cmd_perf(argv),
        "export" => cmd_export(argv, env_vars),
        "alias" => cmd_alias(argv, aliases),
        "history" => cmd_history(history),
        "shift" => cmd_shift(argv, positional_params),
        "read" => cmd_read(argv, env_vars, read_line_fn),
        "source" => cmd_source(
            cwd,
            argv,
            env_vars,
            positional_params,
            source_depth,
            SOURCE_MAX_DEPTH,
            exec_fn,
        ),
        "du" => cmd_du(cwd, argv),
        "df" => cmd_df(argv),
        "chmod" => cmd_chmod(cwd, argv),
        "test" => cmd_test(cwd, argv),
        _ => CmdResult::error(127, format!("shell: unknown command `{command}`\n")),
    }
}
