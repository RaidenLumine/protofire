//! src/user/program/shell/entry.rs
//!
//! Main REPL loop (`shell_user_main`) and terminal I/O helpers.

use super::control_flow::{count_keywords, execute_control_flow_block, needs_continuation};
use super::dispatch::run_shell_command;
use super::expand::{expand_env_vars, source_profile};
use super::history::{add_history, expand_history};
use super::*;

// ─── Signal handlers ──────────────────────────────────────────────────

/// Ctrl-C handler: send SIGTERM to the foreground job.
fn shell_ctrl_c_handler() {
    if let Some(job_id) = *FOREGROUND_JOB_ID.lock() {
        let jobs = JOBS.lock();
        if let Some(job) = jobs.iter().find(|j| j.id == job_id) {
            let mut ctx =
                crate::user::syscall::UserSyscall::send_signal(job.pid as usize, 15, 0, 0);
            let _ = crate::kernel::syscall::dispatch(&mut ctx);
        }
    }
}

/// Ctrl-Z handler: send SIGTSTP to the foreground job, mark as Stopped.
fn shell_ctrl_z_handler() {
    if let Some(job_id) = *FOREGROUND_JOB_ID.lock() {
        let mut jobs = JOBS.lock();
        if let Some(job) = jobs.iter_mut().find(|j| j.id == job_id) {
            let mut ctx =
                crate::user::syscall::UserSyscall::send_signal(job.pid as usize, 20, 0, 0);
            let _ = crate::kernel::syscall::dispatch(&mut ctx);
            job.state = JobState::Stopped;
        }
    }
}

// ─── User-mode shell (fd-based I/O) ───────────────────────────────────

/// Return the current process via the scheduler's current-thread binding.
pub(crate) fn current_process() -> Option<Arc<Process>> {
    let scheduler = Scheduler::global()?;
    let thread = scheduler.current_thread()?;
    Some(thread.process().clone())
}

/// Read a single cooked line from stdin (fd 0).
///
/// Blocks for up to `timeout_ticks` for the first byte, then drains any
/// immediately-available bytes.  Returns `None` on timeout or error.
pub(crate) fn read_stdin_line(timeout_ticks: u64) -> Option<String> {
    let process = current_process()?;

    // First, check whether a previous read left a complete line buffered.
    {
        let mut remainder = STDIN_REMAINDER.lock();
        if let Some(pos) = remainder.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = remainder.drain(..=pos).collect();
            return Some(String::from_utf8_lossy(&line).into_owned());
        }
    }

    // Read from fd 0.  The console device's read handler calls
    // `console::read_bytes_timeout`, which blocks for the first byte then
    // drains anything else in the cooked queue without blocking.
    let entry = process.fd_entry(0).ok()?;
    let mut buf = [0u8; 256];
    let n = entry.read_stream(&mut buf, timeout_ticks).ok()?;
    if n == 0 {
        return None;
    }

    let mut remainder = STDIN_REMAINDER.lock();
    remainder.extend_from_slice(&buf[..n]);

    if let Some(pos) = remainder.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = remainder.drain(..=pos).collect();
        Some(String::from_utf8_lossy(&line).into_owned())
    } else {
        // Only a partial line arrived — keep reading with short timeouts
        // until we see a newline.
        drop(remainder);
        loop {
            let entry = process.fd_entry(0).ok()?;
            // 1 tick = 10 ms; short poll for the rest of the line.
            let n2 = entry.read_stream(&mut buf, 1).ok()?;
            if n2 == 0 {
                // Timed out — return what we have so far.
                let mut remainder = STDIN_REMAINDER.lock();
                if remainder.is_empty() {
                    return None;
                }
                let line: Vec<u8> = remainder.drain(..).collect();
                return Some(String::from_utf8_lossy(&line).into_owned());
            }
            let mut remainder = STDIN_REMAINDER.lock();
            remainder.extend_from_slice(&buf[..n2]);
            if let Some(pos) = remainder.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = remainder.drain(..=pos).collect();
                return Some(String::from_utf8_lossy(&line).into_owned());
            }
        }
    }
}

/// Read a line from stdin without echoing.  Used by `login`, `su`, and
/// `passwd` for password prompts.
///
/// Note: on the current console input layer, echo is always on.  For now
/// this behaves identically to [`read_stdin_line`] but is documented as a
/// distinct function so that echo suppression can be wired in once the
/// console layer supports it.
pub(crate) fn read_stdin_secret(prompt: &str) -> Option<String> {
    crate::print!("{prompt}");
    read_stdin_line(u64::MAX)
}

/// Write bytes to stdout (fd 1).  Falls back to the `println!` path when
/// no process context is available (e.g. early boot).
fn write_stdout(bytes: &[u8]) {
    if let Some(process) = current_process() {
        if let Ok(entry) = process.fd_entry(STDOUT_FD) {
            let _ = entry.write_stream(bytes);
            return;
        }
    }
    // Fallback: write directly to the debug device.
    crate::util::debug::write_bytes(bytes);
}

/// User-mode shell entry point — reads commands from fd 0 (console TTY)
/// and writes output to fd 1 (console TTY) through the process handle
/// I/O path, just like a user-process would via the `read` / `write` syscalls.
///
/// On bare-metal this function is intended to be the proxy entry for the
/// shell ELF; on host it is called as a kernel thread that uses the same
/// fd-based I/O path that the syscall layer dispatches through.
pub fn shell_user_main() {
    // Register signal-generating callbacks for job control.
    console::set_interrupt_callback(shell_ctrl_c_handler);
    console::set_stop_callback(shell_ctrl_z_handler);
    write_stdout(b"protofire shell (user) -- type 'help' for available commands\n");
    let mut cwd = String::from("/");

    // Source ~/.profile if it exists.
    source_profile(&mut cwd);

    loop {
        let in_continuation = *BLOCK_DEPTH.lock() > 0;
        let prompt = if in_continuation {
            format!("{SHELL_PROMPT}:{cwd}> ")
        } else {
            format!("{SHELL_PROMPT}:{cwd}$ ")
        };
        write_stdout(prompt.as_bytes());

        let Some(line) = read_stdin_line(READLINE_TIMEOUT) else {
            write_stdout(b"\n"); // timeout
            continue;
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            if in_continuation {
                CONTINUATION_BUF.lock().push('\n');
            }
            continue;
        }

        // ── History expansion ──
        let line = expand_history(line);

        if in_continuation {
            let mut buf = CONTINUATION_BUF.lock();
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(&line);
            add_history(&line);

            let openers = count_keywords(&line, &["if", "for", "while"]);
            let closers = count_keywords(&line, &["fi", "done"]);
            let mut depth = BLOCK_DEPTH.lock();
            *depth = depth.saturating_add(openers).saturating_sub(closers);

            if *depth == 0 {
                let accumulated = buf.clone();
                buf.clear();
                drop(buf);
                drop(depth);

                let expanded = expand_env_vars(&accumulated);
                let result = execute_control_flow_block(&expanded, &mut cwd);
                write_stdout(result.output.as_bytes());
                LAST_EXIT_CODE.store(result.exit_code, core::sync::atomic::Ordering::Relaxed);
            }
            continue;
        }

        add_history(&line);

        if needs_continuation(&line) {
            let openers = count_keywords(&line, &["if", "for", "while"]);
            let closers = count_keywords(&line, &["fi", "done"]);
            *BLOCK_DEPTH.lock() = openers.saturating_sub(closers);
            *CONTINUATION_BUF.lock() = line;
            continue;
        }

        let line = expand_env_vars(&line);
        if count_keywords(&line, &["if", "for", "while"]) > 0 {
            let result = execute_control_flow_block(&line, &mut cwd);
            write_stdout(result.output.as_bytes());
            LAST_EXIT_CODE.store(result.exit_code, core::sync::atomic::Ordering::Relaxed);
        } else {
            let result = run_shell_command(&line, &mut cwd);
            write_stdout(result.output.as_bytes());
        }
    }
}
