//! src/user/program/shell/commands/user.rs
//!
//! User management commands (whoami, id, users, useradd, userdel, passwd,
//! login, su).

use super::super::entry::read_stdin_line;
use super::super::entry::read_stdin_secret;
use super::super::*;
use alloc::format;
use alloc::string::String;

use crate::kernel::user;

// ─── login / su ────────────────────────────────────────────────────────

pub(crate) fn cmd_login(cwd: &str, argv: &[String]) -> String {
    let username = if argv.len() > 1 && !argv[1].starts_with('-') {
        argv[1].to_string()
    } else {
        match read_stdin_line(6000) {
            Some(line) => line
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .trim()
                .to_string(),
            None => return String::from("login: error reading username\n"),
        }
    };

    if username.is_empty() {
        return String::from("login: username required\n");
    }

    authenticate_and_spawn_shell(cwd, &username)
}

pub(crate) fn cmd_su(cwd: &str, argv: &[String]) -> String {
    // Default to root if no username is given.
    let username = if argv.len() > 1 && !argv[1].starts_with('-') {
        argv[1].to_string()
    } else {
        String::from("root")
    };

    authenticate_and_spawn_shell(cwd, &username)
}

fn authenticate_and_spawn_shell(cwd: &str, username: &str) -> String {
    let password = match read_stdin_secret("Password: ") {
        Some(p) => p.trim_end_matches('\n').trim_end_matches('\r').to_string(),
        None => return String::from("Login incorrect\n"),
    };

    // Try authentication.
    let user_record = match user::authenticate_user(username, &password) {
        Some(rec) => rec,
        None => return String::from("Login incorrect\n"),
    };

    // Build an authenticated SecurityToken.
    use crate::kernel::process::IntegrityLevel;
    use crate::kernel::process::SecurityToken;
    let token = if user_record.uid == 0 {
        SecurityToken::new(user_record.uid, user_record.gid, IntegrityLevel::High)
            .with_elevation()
            .with_authentication()
    } else {
        SecurityToken::new(user_record.uid, user_record.gid, IntegrityLevel::Medium)
            .with_authentication()
    };

    // Spawn a new shell process with the authenticated token.
    let scheduler = match crate::kernel::process::Scheduler::global() {
        Some(s) => s,
        None => return String::from("login: scheduler not available\n"),
    };

    let result =
        crate::user::program::spawn_from_launch_reference_with_overrides_and_security_token(
            scheduler,
            cwd,
            crate::user::program::constants::SHELL_CURRENT_PATH,
            Default::default(),
            token,
        );

    match result {
        Ok(launched) => {
            LOGIN_EXIT_REQUESTED.store(true, core::sync::atomic::Ordering::Release);
            format!(
                "login: session started for `{username}` (pid={})\n",
                launched.process.pid()
            )
        }
        Err(e) => format!("login: failed to spawn shell: {}\n", e.as_str()),
    }
}
