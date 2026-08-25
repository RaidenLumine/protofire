//! src/user/shared/commands/fs.rs
//!
//! Filesystem commands: pwd, cd, ls, cat, mkdir, rm, touch, cp, mv.
//!
//! All commands use the syscall bridge (`crate::syscall`) for filesystem I/O
//! and return `CmdResult` so they work identically in ring0 and ring3.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::user::shared::abi::fs::DirectoryEntryRecord;
use crate::user::shared::abi::fs::FileStat;
use crate::user::shared::abi::fs::MountInfoRecord;
use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_SIZE;
use crate::user::shared::abi::fs::FILE_KIND_DEVICE;
use crate::user::shared::abi::fs::FILE_KIND_DIRECTORY;
use crate::user::shared::abi::fs::FILE_KIND_FILE;
use crate::user::shared::abi::fs::FILE_KIND_SYMLINK;
use crate::user::shared::abi::fs::FILE_STAT_SIZE;
use crate::user::shared::abi::io::OPEN_FLAG_READ;
use crate::user::shared::abi::io::OPEN_FLAG_WRITE_CREATE;
use crate::user::shared::path_util::resolve_path;
use crate::user::shared::syscall;
use crate::user::shared::types::CmdResult;

// ── Buffer size for file reads ─────────────────────────────────────────

const CAT_BUF_SIZE: usize = 4096;

// ── Error message helper ────────────────────────────────────────────────
// Error codes match crate::Error discriminant encoding (see syscall_bridge.rs):
//   InvalidArgument(0)→-1  NotFound(1)→-2  AlreadyExists(2)→-3
//   PermissionDenied(3)→-4  etc.

fn errno_msg(code: isize) -> &'static str {
    match code {
        -1 => "invalid argument",
        -2 => "not found",
        -3 => "already exists",
        -4 => "permission denied",
        -5 => "out of memory",
        -6 => "device error",
        -7 => "resource busy",
        -8 => "timed out",
        -9 => "unsupported",
        -10 => "not implemented",
        -11 => "internal error",
        -12 => "invalid credential",
        _ => "unknown error",
    }
}

/// Produce a hint string for common error scenarios.
fn hint_for(error_str: &str, command: &str) -> &'static str {
    match error_str {
        s if s.contains("not found") => match command {
            "cd" => "  hint: check that the path exists with `ls <parent>`\n",
            "cat" => "  hint: check that the file exists with `ls <dir>`\n",
            "rm" => "  hint: use `ls <dir>` to list files; use `rm -r <dir>` to remove directories\n",
            "cp" => "  hint: the source path does not exist; check with `ls`\n",
            "mv" => "  hint: the source path does not exist; check with `ls`\n",
            "mkdir" => {
                "  hint: parent directory must exist; use `mkdir -p` to create intermediate directories\n"
            }
            "touch" => "  hint: parent directory must exist; check with `ls`\n",
            _ => "",
        },
        s if s.contains("permission denied") => {
            "  hint: this operation requires administrator or recovery privileges\n"
        }
        s if s.contains("already exists") => match command {
            "rm" => "  hint: use `rm -r <path>` to remove directories recursively\n",
            _ => "",
        },
        s if s.contains("invalid argument") => match command {
            "cd" => "  hint: use a directory path, not a file path\n",
            _ => "",
        },
        _ => "",
    }
}

// ─── pwd ────────────────────────────────────────────────────────────────

/// `pwd` — print the current working directory.
pub fn cmd_pwd(cwd: &str) -> CmdResult {
    CmdResult::from_output(format!("{cwd}\n"))
}

// ─── cd ─────────────────────────────────────────────────────────────────

/// `cd` — change the current working directory.
///
/// `home_dir` provides the target for bare `cd` (no arguments) and `~`
/// expansion. If `None`, defaults to `/`.
pub fn cmd_cd(cwd: &mut String, argv: &[String], home_dir: Option<&str>) -> CmdResult {
    let raw_target = if argv.len() < 2 {
        home_dir.unwrap_or("/").to_string()
    } else {
        argv[1].clone()
    };

    // Expand ~ to the home directory.
    let target = if raw_target == "~" {
        home_dir.unwrap_or("/").to_string()
    } else if let Some(stripped) = raw_target.strip_prefix("~/") {
        match home_dir {
            Some(home) => format!("{home}/{}", stripped),
            None => format!("/{}", stripped),
        }
    } else {
        raw_target
    };

    let resolved = resolve_path(cwd, &target);

    // Verify the target exists and is a directory via syscall.
    let mut cd_stat_buf = [0u8; FILE_STAT_SIZE];
    match syscall::sys_stat(&resolved, &mut cd_stat_buf) {
        Ok(()) => {
            let cd_stat: &FileStat = unsafe { &*(cd_stat_buf.as_ptr() as *const FileStat) };
            if cd_stat.kind == FILE_KIND_DIRECTORY {
                *cwd = resolved;
                CmdResult::empty()
            } else {
                CmdResult::error(1, format!("cd: `{target}` is not a directory\n"))
            }
        }
        Err(e) => {
            let msg = errno_msg(e);
            CmdResult::error(
                1,
                format!("cd: `{target}` — {msg}\n{}", hint_for(msg, "cd")),
            )
        }
    }
}

// ─── ls ─────────────────────────────────────────────────────────────────

pub fn cmd_ls(cwd: &str, argv: &[String]) -> CmdResult {
    // Parse flags and target path.
    let mut show_all = false;
    let mut target: Option<&str> = None;

    for arg in &argv[1..] {
        if arg == "-a" || arg == "-la" || arg == "-al" {
            show_all = true;
        } else if !arg.starts_with('-') {
            target = Some(arg);
        }
    }

    let target = match target {
        Some(t) => resolve_path(cwd, t),
        None => cwd.to_string(),
    };

    // Stat first so we can distinguish "does not exist" from "empty directory".
    let mut ls_stat_buf = [0u8; FILE_STAT_SIZE];
    match syscall::sys_stat(&target, &mut ls_stat_buf) {
        Err(e) => {
            return CmdResult::error(
                1,
                format!("ls: cannot access `{target}` — {}\n", errno_msg(e)),
            );
        }
        Ok(()) => {
            let ls_stat: &FileStat = unsafe { &*(ls_stat_buf.as_ptr() as *const FileStat) };
            if ls_stat.kind != FILE_KIND_DIRECTORY {
                return CmdResult::error(1, format!("ls: `{target}` is not a directory\n"));
            }
        }
    }

    let mut out = String::new();
    let mut index = 0;
    let mut count = 0;
    let name_buf_len = DIRECTORY_ENTRY_RECORD_SIZE + 256;
    let mut name_buf: Vec<u8> = alloc::vec![0u8; name_buf_len];

    #[allow(clippy::while_let_loop)]
    loop {
        match syscall::sys_read_dir(&target, index, &mut name_buf) {
            Ok(()) => {
                let record: &DirectoryEntryRecord =
                    unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
                let name = core::str::from_utf8(
                    &name_buf[record.name_offset..record.name_offset + record.name_len],
                )
                .unwrap_or("");
                index += 1;

                // Hide dot-prefixed entries unless -a is given.
                if !show_all && name.starts_with('.') {
                    continue;
                }

                let kind_label = match record.kind {
                    FILE_KIND_DIRECTORY => "[dir] ",
                    FILE_KIND_FILE => "[file]",
                    FILE_KIND_DEVICE => "[dev] ",
                    FILE_KIND_SYMLINK => "[lnk] ",
                    _ => "[?]   ",
                };
                out.push_str(&format!("{kind_label} {name}\n"));
                count += 1;
            }
            Err(_) => break,
        }
    }

    if count == 0 {
        out.push_str("(empty)\n");
    }

    CmdResult::from_output(out)
}

// ─── cat ────────────────────────────────────────────────────────────────

pub fn cmd_cat(cwd: &str, argv: &[String], stdin: Option<&str>) -> CmdResult {
    if argv.len() < 2 && stdin.is_none() {
        return CmdResult::error(1, String::from("cat: missing path\n"));
    }

    let mut out = String::new();

    // With no file arguments, consume the pipeline/redirect stdin buffer.
    // Empty stdin produces no output (real `cat < emptyfile` prints nothing).
    if argv.len() < 2 {
        if let Some(content) = stdin {
            if !content.is_empty() {
                out.push_str(content);
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        return CmdResult::from_output(out);
    }

    for path_arg in &argv[1..] {
        let path = resolve_path(cwd, path_arg);

        let fd = match syscall::sys_open(&path, OPEN_FLAG_READ) {
            Ok(fd) => fd,
            Err(e) => {
                out.push_str(&format!(
                    "cat: cannot open `{path_arg}` — {}\n",
                    errno_msg(e)
                ));
                continue;
            }
        };

        let mut buf = [0u8; CAT_BUF_SIZE];
        loop {
            match syscall::sys_read(fd, &mut buf, 0) {
                Ok(0) => break,
                Ok(n) => match core::str::from_utf8(&buf[..n]) {
                    Ok(text) => out.push_str(text),
                    Err(_) => {
                        out.push_str(&format!("cat: `{path_arg}` is a binary file — skipped\n"));
                        break;
                    }
                },
                Err(e) => {
                    out.push_str(&format!(
                        "cat: read error `{path_arg}` — {}\n",
                        errno_msg(e)
                    ));
                    break;
                }
            }
        }

        let _ = syscall::sys_close(fd);

        if !out.ends_with('\n') {
            out.push('\n');
        }
    }

    CmdResult::from_output(out)
}

// ─── mkdir ──────────────────────────────────────────────────────────────

pub fn cmd_mkdir(cwd: &str, argv: &[String]) -> CmdResult {
    // Parse optional -p flag.
    let mut create_parents = false;
    let mut path_arg: Option<&str> = None;
    for arg in &argv[1..] {
        if arg == "-p" {
            create_parents = true;
        } else if !arg.starts_with('-') {
            path_arg = Some(arg);
        }
    }

    let Some(path_str) = path_arg else {
        return CmdResult::error(1, String::from("mkdir: missing path\n"));
    };

    let path = resolve_path(cwd, path_str);

    if create_parents {
        return cmd_mkdir_parents(path_str, &path);
    }

    match syscall::sys_make_dir(&path) {
        Ok(()) => CmdResult::empty(),
        Err(e) => {
            let msg = errno_msg(e);
            CmdResult::error(
                1,
                format!("mkdir: `{path_str}` — {msg}\n{}", hint_for(msg, "mkdir")),
            )
        }
    }
}

/// Create a directory and all intermediate parent directories (like `mkdir
/// -p`).
fn cmd_mkdir_parents(path_str: &str, full_path: &str) -> CmdResult {
    let segments: Vec<&str> = full_path.split('/').filter(|s| !s.is_empty()).collect();

    let mut partial = String::from("/");
    for (i, segment) in segments.iter().enumerate() {
        if i > 0 {
            partial.push('/');
        }
        partial.push_str(segment);

        let mut mkdir_stat_buf = [0u8; FILE_STAT_SIZE];
        match syscall::sys_stat(&partial, &mut mkdir_stat_buf) {
            Ok(()) => {
                let mkdir_stat: &FileStat =
                    unsafe { &*(mkdir_stat_buf.as_ptr() as *const FileStat) };
                if mkdir_stat.kind == FILE_KIND_DIRECTORY {
                    // Already exists — ok.
                    continue;
                } else {
                    return CmdResult::error(
                        1,
                        format!(
                            "mkdir: `{path_str}` — `{partial}` exists but is not a directory\n"
                        ),
                    );
                }
            }
            Err(_) => {
                // Doesn't exist — create it.
                if let Err(e) = syscall::sys_make_dir(&partial) {
                    return CmdResult::error(
                        1,
                        format!(
                            "mkdir: `{path_str}` — cannot create `{partial}`: {}\n",
                            errno_msg(e)
                        ),
                    );
                }
            }
        }
    }
    CmdResult::empty()
}

// ─── rm ─────────────────────────────────────────────────────────────────

pub fn cmd_rm(cwd: &str, argv: &[String]) -> CmdResult {
    // Parse optional -r flag.
    let mut recursive = false;
    let mut path_arg: Option<&str> = None;
    for arg in &argv[1..] {
        if arg == "-r" {
            recursive = true;
        } else if !arg.starts_with('-') {
            path_arg = Some(arg);
        }
    }

    let Some(path_str) = path_arg else {
        return CmdResult::error(1, String::from("rm: missing path\n"));
    };

    let path = resolve_path(cwd, path_str);

    // Check if target is a directory — if so, require -r.
    let mut rm_stat_buf = [0u8; FILE_STAT_SIZE];
    if syscall::sys_stat(&path, &mut rm_stat_buf).is_ok() {
        let rm_stat: &FileStat = unsafe { &*(rm_stat_buf.as_ptr() as *const FileStat) };
        if rm_stat.kind == FILE_KIND_DIRECTORY && !recursive {
            return CmdResult::error(
                1,
                format!("rm: `{path_str}` is a directory — use `rm -r` to remove directories\n"),
            );
        }
    }

    if recursive {
        match remove_recursive(&path) {
            Ok(()) => CmdResult::empty(),
            Err(e) => CmdResult::error(1, format!("rm: `{path_str}` — {}\n", errno_msg(e))),
        }
    } else {
        match syscall::sys_remove_path(&path) {
            Ok(()) => CmdResult::empty(),
            Err(e) => {
                let msg = errno_msg(e);
                CmdResult::error(
                    1,
                    format!("rm: `{path_str}` — {msg}\n{}", hint_for(msg, "rm")),
                )
            }
        }
    }
}

/// Recursively remove a directory and all its contents (uses syscalls).
fn remove_recursive(path: &str) -> Result<(), isize> {
    // First, recursively remove all children.
    let name_buf_len = DIRECTORY_ENTRY_RECORD_SIZE + 256;
    let mut name_buf: Vec<u8> = alloc::vec![0u8; name_buf_len];
    let mut index = 0;
    #[allow(clippy::while_let_loop)]
    loop {
        match syscall::sys_read_dir(path, index, &mut name_buf) {
            Ok(()) => {
                let record: &DirectoryEntryRecord =
                    unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
                let name = core::str::from_utf8(
                    &name_buf[record.name_offset..record.name_offset + record.name_len],
                )
                .unwrap_or("");
                let child = if path == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", path, name)
                };
                if record.kind == FILE_KIND_DIRECTORY {
                    remove_recursive(&child)?;
                } else {
                    syscall::sys_remove_path(&child)?;
                }
                // After removing, re-read from index 0 since entries may have shifted.
                index = 0;
            }
            Err(_) => break,
        }
    }

    // Then remove the (now empty) directory itself.
    syscall::sys_remove_path(path)?;
    Ok(())
}

// ─── touch ──────────────────────────────────────────────────────────────

pub fn cmd_touch(cwd: &str, argv: &[String]) -> CmdResult {
    if argv.len() < 2 {
        return CmdResult::error(1, String::from("touch: missing path\n"));
    }

    let path = resolve_path(cwd, &argv[1]);

    match syscall::sys_open(&path, OPEN_FLAG_WRITE_CREATE) {
        Ok(fd) => {
            let _ = syscall::sys_close(fd);
            CmdResult::empty()
        }
        Err(e) => {
            let msg = errno_msg(e);
            CmdResult::error(
                1,
                format!("touch: `{}` — {msg}\n{}", argv[1], hint_for(msg, "touch")),
            )
        }
    }
}

// ─── cp ─────────────────────────────────────────────────────────────────

pub fn cmd_cp(cwd: &str, argv: &[String]) -> CmdResult {
    // Parse optional -r flag.
    let mut recursive = false;
    let mut args: Vec<&str> = Vec::new();
    for arg in &argv[1..] {
        if arg == "-r" {
            recursive = true;
        } else if !arg.starts_with('-') {
            args.push(arg);
        }
    }

    if args.len() < 2 {
        return CmdResult::error(
            1,
            String::from("cp: usage: cp [-r] <source> <destination>\n"),
        );
    }
    let src_str = args[0];
    let dst_str = args[1];
    let src_path = resolve_path(cwd, src_str);
    let dst_path = resolve_path(cwd, dst_str);

    if src_path == dst_path {
        return CmdResult::error(
            1,
            format!("cp: `{src_str}` and `{dst_str}` are the same file\n"),
        );
    }

    // Stat source to determine if it's a directory.
    let mut cp_stat_buf = [0u8; FILE_STAT_SIZE];
    match syscall::sys_stat(&src_path, &mut cp_stat_buf) {
        Err(_) => CmdResult::error(
            1,
            format!(
                "cp: cannot access `{src_str}` — {}\n",
                hint_for("not found", "cp").trim_end()
            ),
        ),
        Ok(()) => {
            let cp_stat: &FileStat = unsafe { &*(cp_stat_buf.as_ptr() as *const FileStat) };
            if cp_stat.kind == FILE_KIND_DIRECTORY {
                if !recursive {
                    CmdResult::error(
                        1,
                        format!(
                            "cp: `{src_str}` is a directory — use `cp -r` to copy directories\n"
                        ),
                    )
                } else {
                    copy_recursive(&src_path, &dst_path, dst_str)
                }
            } else {
                // Copy a single file.
                copy_single_file(&src_path, &dst_path, src_str, dst_str)
            }
        }
    }
}

/// Copy a single file from src_path to dst_path (uses syscalls).
fn copy_single_file(src_path: &str, dst_path: &str, src_str: &str, dst_str: &str) -> CmdResult {
    // Open source file for reading.
    let src_fd = match syscall::sys_open(src_path, OPEN_FLAG_READ) {
        Ok(fd) => fd,
        Err(_) => return CmdResult::error(1, format!("cp: cannot open `{src_str}`\n")),
    };

    // Read all data from source.
    let mut data: Vec<u8> = Vec::new();
    let mut buf = [0u8; CAT_BUF_SIZE];
    let read_result = loop {
        match syscall::sys_read(src_fd, &mut buf, 0) {
            Ok(0) => break Ok(()),
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) => break Err(format!("cp: read error — {}\n", errno_msg(e))),
        }
    };
    let _ = syscall::sys_close(src_fd);

    if let Err(err_msg) = read_result {
        return CmdResult::error(1, err_msg);
    }

    // Create destination file and write data.
    let dst_fd = match syscall::sys_open(dst_path, OPEN_FLAG_WRITE_CREATE) {
        Ok(fd) => fd,
        Err(e) => {
            let msg = errno_msg(e);
            return CmdResult::error(
                1,
                format!(
                    "cp: cannot create `{dst_str}` — {msg}\n{}",
                    hint_for(msg, "cp")
                ),
            );
        }
    };

    if let Err(e) = syscall::sys_write(dst_fd, &data) {
        let _ = syscall::sys_close(dst_fd);
        return CmdResult::error(1, format!("cp: write error — {}\n", errno_msg(e)));
    }
    let _ = syscall::sys_close(dst_fd);
    CmdResult::empty()
}

/// Recursively copy a directory tree (uses syscalls).
fn copy_recursive(src_dir: &str, dst_dir: &str, dst_str: &str) -> CmdResult {
    // Create the destination directory.
    if let Err(e) = syscall::sys_make_dir(dst_dir) {
        let msg = errno_msg(e);
        if !msg.contains("already exists") {
            return CmdResult::error(
                1,
                format!(
                    "cp: cannot create directory `{dst_str}` — {msg}\n{}",
                    hint_for(msg, "cp")
                ),
            );
        }
    }

    // Iterate over source directory and copy each child.
    let mut index = 0;
    let name_buf_len = DIRECTORY_ENTRY_RECORD_SIZE + 256;
    let mut name_buf: Vec<u8> = alloc::vec![0u8; name_buf_len];
    #[allow(clippy::while_let_loop)]
    loop {
        match syscall::sys_read_dir(src_dir, index, &mut name_buf) {
            Ok(()) => {
                let record: &DirectoryEntryRecord =
                    unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
                let name = core::str::from_utf8(
                    &name_buf[record.name_offset..record.name_offset + record.name_len],
                )
                .unwrap_or("");
                let child_src = if src_dir == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", src_dir, name)
                };
                let child_dst = if dst_dir == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", dst_dir, name)
                };

                match record.kind {
                    FILE_KIND_DIRECTORY => {
                        let result = copy_recursive(&child_src, &child_dst, dst_str);
                        if !result.is_ok() {
                            return result;
                        }
                    }
                    FILE_KIND_FILE => {
                        let result = copy_single_file(&child_src, &child_dst, name, name);
                        if !result.is_ok() {
                            return result;
                        }
                    }
                    _ => {
                        // Skip device nodes and symlinks — cannot copy them.
                    }
                }
                index += 1;
            }
            Err(_) => break,
        }
    }
    CmdResult::empty()
}

// ─── mv ─────────────────────────────────────────────────────────────────

pub fn cmd_mv(cwd: &str, argv: &[String]) -> CmdResult {
    if argv.len() < 3 {
        return CmdResult::error(1, String::from("mv: usage: mv <source> <destination>\n"));
    }
    let src_path = resolve_path(cwd, &argv[1]);
    let dst_path = resolve_path(cwd, &argv[2]);

    if src_path == dst_path {
        return CmdResult::empty(); // no-op
    }

    match syscall::sys_rename(&src_path, &dst_path) {
        Ok(()) => CmdResult::empty(),
        Err(e) => {
            let msg = errno_msg(e);
            CmdResult::error(
                1,
                format!(
                    "mv: cannot move `{}` to `{}` — {msg}\n{}",
                    argv[1],
                    argv[2],
                    hint_for(msg, "mv")
                ),
            )
        }
    }
}

// ─── human_size ──────────────────────────────────────────────────────────

/// Format a byte count as a human-readable size string ("3.2M", "1.5K", "42B").
pub fn human_size(bytes: usize) -> String {
    const UNITS: &[(&str, usize)] = &[("G", 1024 * 1024 * 1024), ("M", 1024 * 1024), ("K", 1024)];
    for (unit, factor) in UNITS {
        if bytes >= *factor {
            let value = bytes as f64 / *factor as f64;
            return format!("{value:.1}{unit}");
        }
    }
    format!("{bytes}B")
}

/// Read the entry name from a `read_dir` result buffer.
fn read_entry_name<'a>(name_buf: &'a [u8], record: &DirectoryEntryRecord) -> &'a str {
    let end = (record.name_offset + record.name_len).min(name_buf.len());
    let start = record.name_offset.min(end);
    core::str::from_utf8(&name_buf[start..end]).unwrap_or("")
}

/// Read a NUL-terminated fixed-size string field.
fn cstr_field(field: &[u8]) -> &str {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    core::str::from_utf8(&field[..end]).unwrap_or("")
}

// ─── chmod ───────────────────────────────────────────────────────────────

pub fn cmd_chmod(cwd: &str, argv: &[String]) -> CmdResult {
    let mut recursive = false;
    let mut mode_str: Option<&str> = None;
    let mut path_str: Option<&str> = None;

    for arg in &argv[1..] {
        if arg == "-R" {
            recursive = true;
        } else if !arg.starts_with('-') {
            if mode_str.is_none() {
                mode_str = Some(arg);
            } else if path_str.is_none() {
                path_str = Some(arg);
            }
        } else {
            return CmdResult::error(1, format!("chmod: unknown flag `{arg}`\n"));
        }
    }

    let mode_str = match mode_str {
        Some(m) => m,
        None => {
            return CmdResult::error(
                1,
                String::from("chmod: missing mode\nusage: chmod [-R] <mode> <path>\n"),
            )
        }
    };
    let path = match path_str {
        Some(p) => p,
        None => {
            return CmdResult::error(
                1,
                String::from("chmod: missing path\nusage: chmod [-R] <mode> <path>\n"),
            )
        }
    };

    let mode = match u16::from_str_radix(mode_str, 8) {
        Ok(m) => m,
        Err(_) => {
            return CmdResult::error(
                1,
                format!("chmod: invalid mode `{mode_str}` (must be octal, e.g. 755)\n"),
            )
        }
    };

    let normalized = resolve_path(cwd, path);
    match syscall::sys_set_security_descriptor(&normalized, 0, mode, 0, 0) {
        Ok(()) => {
            if recursive {
                chmod_recursive(&normalized, mode);
            }
            CmdResult::empty()
        }
        Err(e) => CmdResult::error(1, format!("chmod: {path}: {}\n", errno_msg(e))),
    }
}

fn chmod_recursive(dir_path: &str, mode: u16) {
    let name_buf_len = DIRECTORY_ENTRY_RECORD_SIZE + 256;
    let mut name_buf = alloc::vec![0u8; name_buf_len];
    let mut index: usize = 0;
    #[allow(clippy::while_let_loop)]
    loop {
        match syscall::sys_read_dir(dir_path, index, &mut name_buf) {
            Ok(()) => {
                let record: &DirectoryEntryRecord =
                    unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
                let name = read_entry_name(&name_buf, record);
                if name != "." && name != ".." {
                    let child = if dir_path.ends_with('/') {
                        format!("{dir_path}{name}")
                    } else {
                        format!("{dir_path}/{name}")
                    };
                    let _ = syscall::sys_set_security_descriptor(&child, 0, mode, 0, 0);
                    if record.kind == FILE_KIND_DIRECTORY {
                        chmod_recursive(&child, mode);
                    }
                }
            }
            Err(_) => break,
        }
        index += 1;
    }
}

// ─── df ──────────────────────────────────────────────────────────────────

pub fn cmd_df(_argv: &[String]) -> CmdResult {
    let mut buf = [0u8; 8192];
    let written = match syscall::sys_list_mounts(&mut buf) {
        Ok(n) => n,
        Err(e) => return CmdResult::error(1, format!("df: {}\n", errno_msg(e))),
    };
    let record_size = core::mem::size_of::<MountInfoRecord>();
    let count = written / record_size;

    let mut out = String::from("Device         Size  Used  Avail Use% Mounted on\n");
    for i in 0..count {
        let rec = unsafe {
            (buf.as_ptr().add(i * record_size) as *const MountInfoRecord).read_unaligned()
        };
        let device = cstr_field(&rec.device);
        let fs_name = cstr_field(&rec.fs_name);
        let path = cstr_field(&rec.path);
        let _ = fs_name;
        out.push_str(&format!("{device:<14}  -     -     -    -   {path}\n"));
    }
    if count == 0 {
        out.push_str("(no mounted filesystems)\n");
    }
    CmdResult::from_output(out)
}

// ─── du ──────────────────────────────────────────────────────────────────

pub fn cmd_du(cwd: &str, argv: &[String]) -> CmdResult {
    let mut human = false;
    let mut target: Option<&str> = None;
    for arg in &argv[1..] {
        if arg == "-h" {
            human = true;
        } else if !arg.starts_with('-') {
            target = Some(arg);
        } else {
            return CmdResult::error(1, format!("du: unknown flag `{arg}`\n"));
        }
    }
    let target = match target {
        Some(t) => resolve_path(cwd, t),
        None => cwd.to_string(),
    };
    let total = match du_impl(&target) {
        Ok(t) => t,
        Err(e) => return CmdResult::error(1, format!("du: {target}: {}\n", errno_msg(e))),
    };
    let size_str = if human {
        human_size(total)
    } else {
        format!("{total}")
    };
    CmdResult::from_output(format!("{size_str}\t{target}\n"))
}

fn du_impl(path: &str) -> core::result::Result<usize, isize> {
    let mut stat_buf = [0u8; FILE_STAT_SIZE];
    syscall::sys_stat(path, &mut stat_buf)?;
    let stat = unsafe { &*(stat_buf.as_ptr() as *const FileStat) };
    let mut total = stat.size;
    if stat.kind == FILE_KIND_DIRECTORY {
        let name_buf_len = DIRECTORY_ENTRY_RECORD_SIZE + 256;
        let mut name_buf = alloc::vec![0u8; name_buf_len];
        let mut index: usize = 0;
        #[allow(clippy::while_let_loop)]
        loop {
            match syscall::sys_read_dir(path, index, &mut name_buf) {
                Ok(()) => {
                    let record: &DirectoryEntryRecord =
                        unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
                    let name = read_entry_name(&name_buf, record);
                    if name != "." && name != ".." {
                        let child = if path.ends_with('/') {
                            format!("{path}{name}")
                        } else {
                            format!("{path}/{name}")
                        };
                        total += du_impl(&child).unwrap_or(0);
                    }
                }
                Err(_) => break,
            }
            index += 1;
        }
    }
    Ok(total)
}
