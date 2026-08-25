//! src/user/program/shell/dispatch.rs
//!
//! Command dispatch: single commands, pipelines, and conditional chaining.

use super::expand::is_background;
use super::glob::expand_globs_in_tokens;
use super::pipeline::has_shell_operator;
use super::pipeline::parse_redirects;
use super::pipeline::split_pipeline;
use super::pipeline::strip_trailing_newline;
use super::pipeline::tokenize_conditionals;
use super::pipeline::CondToken;
use super::tokenizer::tokenize;
use super::*;
// Kernel-only commands (network, user mgmt, job control, app services, source).
use super::commands::cmd_bg;
use super::commands::cmd_fg;
use super::commands::cmd_jobs;
use super::commands::cmd_login;
use super::commands::cmd_ping;
use super::commands::cmd_source;
use super::commands::cmd_su;
// ring3-common shared dispatch — kernel-only commands are checked first, then
// the shared dispatch table handles everything else with explicit state params.
use crate::user::shared::abi::io::OPEN_FLAG_CREATE;
use crate::user::shared::abi::io::OPEN_FLAG_READ;
use crate::user::shared::abi::io::OPEN_FLAG_WRITE;
use crate::user::shared::dispatch;
use crate::user::shared::syscall;

// External command spawning uses the kernel's ELF loader and process launcher.
// Only functional on bare-metal; host-side tests skip external spawn.
#[cfg(target_os = "none")]
use crate::kernel::process::SecurityToken;

/// Execute a single command or conditional chain.
pub(crate) fn run_shell_command(line: &str, cwd: &mut String) -> CmdResult {
    // ── Background task detection ──
    if is_background(line) {
        let cmd = line.trim_end().trim_end_matches('&').trim().to_string();
        if cmd.is_empty() {
            return CmdResult::empty();
        }
        let job_id = NEXT_JOB_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        *BG_COMMAND.lock() = Some((cmd.clone(), String::clone(cwd)));
        if let Some(scheduler) = crate::kernel::process::Scheduler::global() {
            let name = cmd.split_whitespace().next().unwrap_or("?").to_string();
            let bg_name = format!("bg[{job_id}]-{name}");
            let thread = scheduler.spawn_kernel_named(&bg_name, super::expand::bg_entry);
            let pid = thread.process().pid();
            JOBS.lock().push(Job {
                id: job_id,
                pid,
                name: name.clone(),
                state: JobState::Running,
                command: cmd.clone(),
            });
            return CmdResult::success(format!("[{job_id}] {pid} launched: {cmd}\n"));
        }
        *BG_COMMAND.lock() = None;
        return CmdResult::error(
            1,
            "shell: no scheduler available for background tasks\n".into(),
        );
    }

    // ── Conditional chaining (&& / ||) ──
    let cond_tokens = tokenize_conditionals(line);

    if cond_tokens.len() > 1
        && cond_tokens
            .iter()
            .any(|t| matches!(t, CondToken::And | CondToken::Or))
    {
        let mut last_result = CmdResult::empty();
        let mut expect_and: Option<bool> = None;

        for token in &cond_tokens {
            match token {
                CondToken::Cmd(cmd) => {
                    let should_run = match expect_and {
                        None => true,
                        Some(true) => last_result.is_ok(),
                        Some(false) => !last_result.is_ok(),
                    };
                    if should_run {
                        last_result = execute_single_or_pipeline(cmd, cwd);
                    }
                    expect_and = None;
                }
                CondToken::And => expect_and = Some(true),
                CondToken::Or => expect_and = Some(false),
            }
        }
        LAST_EXIT_CODE.store(last_result.exit_code, core::sync::atomic::Ordering::Relaxed);
        return last_result;
    }

    // ── Pipeline & redirect (no conditionals) ──
    execute_single_or_pipeline(line, cwd)
}

/// Execute a single command or pipeline (no conditional operators).
pub(crate) fn execute_single_or_pipeline(cmd_line: &str, cwd: &mut String) -> CmdResult {
    let pipeline = split_pipeline(cmd_line);

    if pipeline.len() == 1 && !has_shell_operator(&pipeline[0]) {
        let result = dispatch_single_command(&pipeline[0], cwd, None);
        LAST_EXIT_CODE.store(result.exit_code, core::sync::atomic::Ordering::Relaxed);
        return result;
    }

    let mut next_stdin: Option<String> = None;
    let mut last_exit_code: i32 = 0;
    let num_stages = pipeline.len();

    for (stage_idx, stage) in pipeline.iter().enumerate() {
        let trimmed = stage.trim();
        if trimmed.is_empty() {
            return CmdResult::error(1, "shell: empty pipeline stage\n".into());
        }

        let (cmd_str, redirect_out, redirect_in) = parse_redirects(trimmed);

        // ── Input redirect ──
        if let Some(ref in_file) = redirect_in {
            let path = resolve_path(cwd, in_file);
            let fd = match syscall::sys_open(&path, OPEN_FLAG_READ) {
                Ok(fd) => fd,
                Err(_) => {
                    return CmdResult::error(1, format!("shell: cannot open `{in_file}`\n"));
                }
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; CAT_BUF_SIZE];
            let mut read_err = None;
            loop {
                match syscall::sys_read(fd, &mut chunk, 0) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) => {
                        read_err = Some(e);
                        break;
                    }
                }
            }
            let _ = syscall::sys_close(fd);
            if let Some(e) = read_err {
                return CmdResult::error(1, format!("shell: read error `{in_file}` — {e}\n"));
            }
            next_stdin = Some(String::from_utf8_lossy(&buf).into_owned());
        }

        // ── Dispatch ──
        let result = dispatch_single_command(&cmd_str, cwd, next_stdin.as_deref());
        last_exit_code = result.exit_code;
        let stage_output = strip_trailing_newline(result.output);

        // ── Output redirect ──
        if let Some(ref out_file) = redirect_out {
            let path = resolve_path(cwd, out_file);
            let fd = match syscall::sys_open(&path, OPEN_FLAG_WRITE | OPEN_FLAG_CREATE) {
                Ok(fd) => fd,
                Err(_) => {
                    return CmdResult::error(1, format!("shell: cannot create `{out_file}`\n"));
                }
            };
            let data = stage_output.as_bytes();
            if let Err(e) = syscall::sys_write(fd, data) {
                let _ = syscall::sys_close(fd);
                return CmdResult::error(1, format!("shell: cannot write `{out_file}` — {e}\n"));
            }
            let _ = syscall::sys_close(fd);
            next_stdin = None;
        } else if stage_idx < num_stages - 1 {
            next_stdin = Some(stage_output);
        } else {
            let final_result = CmdResult {
                exit_code: last_exit_code,
                output: stage_output + "\n",
            };
            LAST_EXIT_CODE.store(
                final_result.exit_code,
                core::sync::atomic::Ordering::Relaxed,
            );
            return final_result;
        }
    }

    // Every stage wrote to an output redirect, so the loop never reached the
    // final-stage return above — preserve and propagate the last stage's exit
    // code instead of reporting a hardcoded success.
    LAST_EXIT_CODE.store(last_exit_code, core::sync::atomic::Ordering::Relaxed);
    CmdResult {
        exit_code: last_exit_code,
        output: String::new(),
    }
}

/// Dispatch a single command (no pipes), returning its output.
pub(crate) fn dispatch_single_command(
    cmd_line: &str,
    cwd: &mut String,
    stdin: Option<&str>,
) -> CmdResult {
    let mut tokens = match tokenize(cmd_line) {
        Ok(tokens) => tokens,
        Err(error) => return CmdResult::error(2, format!("shell: {error}\n")),
    };
    if tokens.is_empty() {
        return CmdResult::empty();
    }

    // ── Alias expansion (with recursion guard) ──
    {
        let mut alias_depth = 0u32;
        const MAX_ALIAS_DEPTH: u32 = 10;
        while alias_depth < MAX_ALIAS_DEPTH {
            let aliases = ALIASES.lock();
            let expansion = aliases
                .iter()
                .find(|(name, _)| name == &tokens[0])
                .map(|(_, val)| val.clone());
            drop(aliases);

            match expansion {
                Some(exp) => {
                    let mut new_tokens = match tokenize(&exp) {
                        Ok(t) => t,
                        Err(_) => break,
                    };
                    new_tokens.extend_from_slice(&tokens[1..]);
                    tokens = new_tokens;
                    alias_depth += 1;
                }
                None => break,
            }
        }
    }

    // ── Glob expansion on arguments (skip command name, index 0) ──
    tokens = expand_globs_in_tokens(&tokens, cwd);

    // Pipeline/redirect stdin is NOT appended to argv — commands that consume
    // it (grep, head, tail, wc, ...) receive it through the `stdin` channel
    // plumbed into the shared dispatch below.
    let command = tokens[0].as_str();
    let argv = &tokens;

    // ── Kernel-only commands (fast path, no extra locking) ──
    // Also handles `exit` and `source` which need special kernel treatment.
    match command {
        // Ring3 network utilities → /system/netutil.elf
        "fetch" | "nslookup" => {
            return spawn_ring3_utility(cwd, "/system/netutil.elf", argv);
        }
        // Ring3 core utilities → /system/coreutil.elf
        "whoami" | "id" | "users" | "useradd" | "userdel" | "passwd" | "chown" => {
            return spawn_ring3_utility(cwd, "/system/coreutil.elf", argv);
        }
        // Kernel-only: ping (ring3 version is a stub — ICMP requires kernel APIs)
        "ping" => return CmdResult::from_output(cmd_ping(cwd, argv)),
        // Kernel-only: authentication (SecurityToken construction)
        "login" => return CmdResult::from_output(cmd_login(cwd, argv)),
        "su" => return CmdResult::from_output(cmd_su(cwd, argv)),
        // Kernel-only: job control
        "jobs" => return cmd_jobs(),
        "fg" => return cmd_fg(argv),
        "bg" => return cmd_bg(argv),
        // Special: exit the shell
        "exit" => {
            return CmdResult {
                exit_code: 0,
                output: String::from("bye\n"),
            }
        }
        // Kernel `source`: recursive dispatch via run_shell_command (full
        // pipeline/conditional support).  Kept kernel-side to avoid deadlock
        // — it calls back into dispatch, which would re-lock the globals.
        "source" => return cmd_source(cwd, argv),
        _ => {}
    }

    // ── Shared commands: delegate to crate::user::shared::dispatch_tokens ──
    // All state is plumbed as explicit parameters so ring3-common doesn't
    // depend on kernel Mutex statics.  The same dispatch_tokens runs in
    // ring3-shell with local variables instead.
    let mut env_vars = ENV_VARS.lock();
    let mut aliases = ALIASES.lock();
    let history = HISTORY.lock();
    let mut positional_params = POSITIONAL_PARAMS.lock();
    let mut source_depth = SOURCE_DEPTH.lock();

    let result = dispatch::dispatch_tokens(
        &tokens,
        cwd,
        stdin,
        None, // home_dir — cd ~ resolves via HOME env var or /accounts/<uid>/home
        &mut env_vars,
        &mut aliases,
        &history,
        &mut positional_params,
        &mut source_depth,
        || console::read_line_timeout(READLINE_TIMEOUT),
        run_shell_command,
    );

    // If the shared dispatch recognised the command, return its result.
    // Exit code 127 means "unknown command" — fall through to external spawn.
    if result.exit_code != 127 {
        return result;
    }

    // ── External command spawn fallback ──
    // Try to spawn the command as an external ring3 ELF program.
    // Only works on bare-metal; host-side tests skip this path.
    if let Some(ext_result) = try_spawn_external(cwd, command, argv) {
        return ext_result;
    }

    // Nothing matched — return the original "unknown command" error.
    result
}

// ── External command spawning ──────────────────────────────────────────────

/// Spawn a ring3 utility ELF by its absolute filesystem path, passing `argv`
/// through as the subprocess arguments.  The utility writes directly to the
/// console; the shell blocks until the subprocess exits.
///
/// On the host (unit-test) side ring3 ELFs cannot run natively — return an
/// error so the caller can fall back gracefully.
fn spawn_ring3_utility(_cwd: &str, elf_path: &str, _argv: &[String]) -> CmdResult {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (_cwd, elf_path, _argv);
        CmdResult::error(
            127,
            alloc::format!("shell: `{}` requires bare-metal\n", elf_path),
        )
    }

    #[cfg(target_os = "none")]
    {
        let fs = match crate::kernel::fs::global() {
            Some(fs) => fs,
            None => return CmdResult::error(1, "shell: filesystem not available\n".into()),
        };
        let fs_guard = fs.lock_without_irq_disable();
        let loaded =
            match crate::user::program::loader::load_from_filesystem(&fs_guard, _cwd, elf_path) {
                Ok(l) => l,
                Err(e) => {
                    drop(fs_guard);
                    return CmdResult::error(
                        126,
                        alloc::format!("shell: cannot load `{}` — {:?}\n", elf_path, e),
                    );
                }
            };
        drop(fs_guard);

        let scheduler = match crate::kernel::process::Scheduler::global() {
            Some(s) => s,
            None => return CmdResult::error(1, "shell: scheduler not available\n".into()),
        };

        let launched = match crate::user::program::spawn::launch_loaded_program_with_security_token(
            scheduler,
            loaded,
            crate::kernel::process::SecurityToken::guest(),
            false,
        ) {
            Ok(l) => l,
            Err(e) => {
                return CmdResult::error(
                    126,
                    alloc::format!("shell: cannot spawn `{}` — {:?}\n", elf_path, e),
                );
            }
        };

        launched.process.wait_for_termination();
        CmdResult::success(String::new())
    }
}

/// Default search path for external ring3 ELF programs.
#[cfg(target_os = "none")]
const DEFAULT_PATH: &str = "/system:/bin";

/// Try to spawn `command` as an external ring3 ELF program.
///
/// Returns `Some(CmdResult)` if the command was found and spawned (the result
/// reflects the child's exit status), or `None` if no matching ELF was found.
///
/// Only functional on bare-metal (`target_os = "none"`); on host-side this
/// always returns `None` because ring3 ELFs cannot run in a host test context.
fn try_spawn_external(cwd: &str, command: &str, _argv: &[String]) -> Option<CmdResult> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (cwd, command, _argv);
        None
    }

    #[cfg(target_os = "none")]
    {
        let elf_path = resolve_external_command_path(cwd, command)?;

        // Load the ELF directly from the filesystem.
        let fs = crate::kernel::fs::global()?;
        let fs_guard = fs.lock_without_irq_disable();
        let loaded =
            match crate::user::program::loader::load_from_filesystem(&fs_guard, cwd, &elf_path) {
                Ok(l) => l,
                Err(_) => {
                    drop(fs_guard);
                    return None;
                }
            };
        drop(fs_guard);

        // Spawn as a user-mode process with guest privileges.
        let scheduler = crate::kernel::process::Scheduler::global()?;
        let launched = match crate::user::program::spawn::launch_loaded_program_with_security_token(
            scheduler,
            loaded,
            SecurityToken::guest(),
            false,
        ) {
            Ok(l) => l,
            Err(e) => {
                return Some(CmdResult::error(
                    126,
                    format!("shell: cannot spawn `{command}` — {e:?}\n"),
                ));
            }
        };

        // Block until the child process exits.
        launched.process.wait_for_termination();

        Some(CmdResult::success(String::new()))
    }
}

/// Resolve a command name to an absolute ELF path on the filesystem.
///
/// 1. If `command` looks like a path (`/…`, `./…`, `../…`), try it directly
///    (with and without `.elf` suffix).
/// 2. Otherwise perform a PATH lookup, searching each colon-separated directory
///    for `{command}` and `{command}.elf`.
#[cfg(target_os = "none")]
fn resolve_external_command_path(cwd: &str, command: &str) -> Option<String> {
    use crate::kernel::fs::path::normalize_path;

    // ── Direct path (absolute or relative to cwd) ──
    if command.starts_with('/') || command.starts_with("./") || command.starts_with("../") {
        let base = normalize_path(command, cwd).ok()?;
        if path_is_regular_file(&base) {
            return Some(base);
        }
        let with_elf = format!("{base}.elf");
        if path_is_regular_file(&with_elf) {
            return Some(with_elf);
        }
        return None;
    }

    // ── PATH lookup ──
    let path_var = {
        let env = ENV_VARS.lock();
        env.iter()
            .find(|(k, _)| k.as_str() == "PATH")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| String::from(DEFAULT_PATH))
    };

    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let dir = normalize_path(dir, cwd).ok()?;
        let candidate = format!("{dir}/{command}");
        if path_is_regular_file(&candidate) {
            return Some(candidate);
        }
        let with_elf = format!("{dir}/{command}.elf");
        if path_is_regular_file(&with_elf) {
            return Some(with_elf);
        }
    }

    None
}

/// Check whether `path` exists and is a regular file by probing with a
/// read-only open.  The fd is immediately closed on success.
#[cfg(target_os = "none")]
fn path_is_regular_file(path: &str) -> bool {
    match syscall::sys_open(path, OPEN_FLAG_READ) {
        Ok(fd) => {
            let _ = syscall::sys_close(fd);
            true
        }
        Err(_) => false,
    }
}
