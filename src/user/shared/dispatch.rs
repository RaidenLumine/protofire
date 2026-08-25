//! src/user/shared/dispatch.rs
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

use crate::user::shared::commands::{
    cmd_alias, cmd_cat, cmd_cd, cmd_chmod, cmd_clear, cmd_cp, cmd_df, cmd_diff, cmd_dmesg, cmd_du,
    cmd_echo, cmd_edit, cmd_export, cmd_false, cmd_find, cmd_grep, cmd_head, cmd_help, cmd_hexdump,
    cmd_history, cmd_kill, cmd_ls, cmd_mkdir, cmd_mv, cmd_perf, cmd_ps, cmd_pwd, cmd_read, cmd_rm,
    cmd_shift, cmd_sleep, cmd_sort, cmd_source, cmd_sysinfo, cmd_tail, cmd_test, cmd_top,
    cmd_touch, cmd_true, cmd_uname, cmd_uniq, cmd_uptime, cmd_wc,
};
use crate::user::shared::tokenizer::tokenize;
use crate::user::shared::types::CmdResult;

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
