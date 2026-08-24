//! src/user/program/shell/mod.rs
//!
//! Interactive shell connected to the console TTY.
//!
//! Provides a single entry point:
//! - [`shell_user_main`] — user-mode shell using fd 0 (console TTY input)
//!   and fd 1 (console TTY output) through the process handle I/O path.
//!
//! Sub-module organisation:
//! - `entry`    — Main REPL loops and terminal I/O
//! - `history`  — Readline callbacks, command history, history expansion
//! - `expand`   — Environment variable expansion, source/profile, background launch
//! - `glob`     — Glob pattern matching (`*`, `?`, `[...]`)
//! - `dispatch` — Command dispatch (single, pipeline, conditional chaining)
//! - `control_flow` — if/for/while/until control flow
//! - `pipeline` — Pipeline splitting, redirect parsing, conditional tokenizer
//! - `tokenizer` — Shell word tokenizer
//! - `commands` — All builtin command handlers
//! - `tests`    — Unit and integration tests

// ── sub-modules ───────────────────────────────────────────────────────

pub(crate) mod commands;
pub(crate) mod control_flow;
pub(crate) mod dispatch;
pub(crate) mod entry;
pub(crate) mod expand;
pub(crate) mod glob;
pub(crate) mod history;
pub(crate) mod pipeline;
// The kernel-side syscall bridge provides the `#[no_mangle] __shell_syscallN`
// symbols when the shell runs in the kernel.  A standalone ring3 shell ELF
// (built with the `runtime` feature) gets those symbols from
// `shared::runtime` instead — enabling both would duplicate them.
#[cfg(not(feature = "runtime"))]
pub(crate) mod syscall_bridge;
#[cfg(test)]
mod tests;
pub(crate) mod tokenizer;

// ── public re-exports ─────────────────────────────────────────────────

pub use entry::shell_user_main;

// ── shared imports ────────────────────────────────────────────────────

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::console;
use crate::kernel::process::{Process, Scheduler, STDOUT_FD};
use crate::kernel::sync::Mutex;

// ─── Shell constants ──────────────────────────────────────────────────

/// Shell prompt prefix.
pub(crate) const SHELL_PROMPT: &str = "protofire";

/// Maximum line read timeout in ticks (6000 = 60 s at 100 Hz).
pub(crate) const READLINE_TIMEOUT: u64 = 6000;

/// Buffer size for `cat`.
pub(crate) const CAT_BUF_SIZE: usize = 4096;

/// Maximum number of history entries retained.
pub(crate) const HISTORY_MAX: usize = 32;

/// Maximum nesting depth for `source` commands.
pub(crate) const SOURCE_MAX_DEPTH: u32 = 16;

// ─── Shell state ──────────────────────────────────────────────────────

/// Environment variables set via `export VAR=value`.
pub(crate) static ENV_VARS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// Command history for `!!` / `!N` recall and arrow-key browsing.
pub(crate) static HISTORY: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Background job counter (incremented for each `cmd &`).
pub(crate) static NEXT_JOB_ID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

/// Slot for passing a command string to `bg_entry()`.
pub(crate) static BG_COMMAND: Mutex<Option<(String, String)>> = Mutex::new(None);

/// Set to `true` by `login`/`su` after spawning a new authenticated shell.
/// The REPL loop checks this flag after each command and exits when set.
pub(crate) static LOGIN_EXIT_REQUESTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Positional parameters set by `source <script> <args...>` or function calls.
/// Index 0 = $1, index 1 = $2, etc.
pub(crate) static POSITIONAL_PARAMS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Command aliases (name → expansion).  Used by the `alias` builtin.
pub(crate) static ALIASES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// Multi-line control-flow continuation state.
pub(crate) static BLOCK_DEPTH: Mutex<u32> = Mutex::new(0);

/// Accumulates lines during multi-line control-flow continuation.
pub(crate) static CONTINUATION_BUF: Mutex<String> = Mutex::new(String::new());

/// Persistent buffer for bytes read from fd 0 that haven't been returned
/// as a complete line yet.
pub(crate) static STDIN_REMAINDER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

// ─── Job control ──────────────────────────────────────────────────────
// Types and formatting helpers are shared with shared.

pub(crate) use crate::user::shared::jobs::{Job, JobState};

/// Job table — tracks all background and suspended jobs.
pub(crate) static JOBS: Mutex<Vec<Job>> = Mutex::new(Vec::new());

/// Job ID currently in the foreground, if any (for Ctrl-Z / Ctrl-C targeting).
pub(crate) static FOREGROUND_JOB_ID: Mutex<Option<u32>> = Mutex::new(None);

// ─── Structured command result ────────────────────────────────────────
//
// Re-exported from shared so that the kernel shell and ring3-shell
// share a single CmdResult definition.  The shared type is identical
// to the previous kernel-side definition (same fields, same methods).

pub(crate) use crate::user::shared::types::CmdResult;

/// Exit code of the last foreground command (for `$?` expansion).
pub(crate) static LAST_EXIT_CODE: core::sync::atomic::AtomicI32 =
    core::sync::atomic::AtomicI32::new(0);

/// Current source nesting depth (guards against infinite recursion).
pub(crate) static SOURCE_DEPTH: Mutex<u32> = Mutex::new(0);

// ─── Shared utility functions ─────────────────────────────────────────

/// Resolve a user-supplied path against the current working directory.
pub(crate) fn resolve_path(cwd: &str, path: &str) -> String {
    if path.is_empty() {
        return cwd.to_string();
    }

    // Absolute paths are used as-is.
    if path.starts_with('/') {
        return normalize_path_segments(path);
    }

    // Relative path — join with cwd.
    let base = cwd.trim_end_matches('/');
    let joined = if base.is_empty() {
        format!("/{path}")
    } else {
        format!("{base}/{path}")
    };
    normalize_path_segments(&joined)
}

/// Collapse `.` and `..` segments and strip trailing slashes.
pub(crate) fn normalize_path_segments(path: &str) -> String {
    let parts: Vec<&str> = path
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();

    let mut result: Vec<&str> = Vec::new();
    for part in parts {
        if part == ".." {
            result.pop();
        } else {
            result.push(part);
        }
    }

    if result.is_empty() {
        return String::from("/");
    }

    let mut normalized = String::from("/");
    for (i, part) in result.iter().enumerate() {
        if i > 0 {
            normalized.push('/');
        }
        normalized.push_str(part);
    }
    normalized
}
