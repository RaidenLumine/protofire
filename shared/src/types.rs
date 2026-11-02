//! src/user/shared/types.rs
//!
//! Shared shell types used by both kernel and ring3 environments.

use alloc::string::String;

/// Structured result from a shell command execution.
///
/// Replaces plain `String` return types so that control-flow constructs
/// (`if`, `while`, `&&`, `||`) can branch on success/failure.
#[derive(Clone, Debug)]
pub struct CmdResult {
    pub exit_code: i32,
    pub output: String,
}

impl CmdResult {
    /// Success with output text (exit code 0).
    pub fn success(output: String) -> Self {
        CmdResult {
            exit_code: 0,
            output,
        }
    }

    /// Error with explicit exit code and message.
    pub fn error(exit_code: i32, output: String) -> Self {
        CmdResult { exit_code, output }
    }

    /// Backward-compatible constructor: from any output string, exit code 0.
    pub fn from_output(output: String) -> Self {
        CmdResult {
            exit_code: 0,
            output,
        }
    }

    /// Empty success result (no output, exit code 0).
    pub fn empty() -> Self {
        CmdResult {
            exit_code: 0,
            output: String::new(),
        }
    }

    /// Check if the command succeeded (exit code 0).
    pub fn is_ok(&self) -> bool {
        self.exit_code == 0
    }
}
