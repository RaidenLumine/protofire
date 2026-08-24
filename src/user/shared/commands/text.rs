//! src/user/shared/commands/text.rs
//!
//! Text processing and editing commands (grep, find, head, tail, wc, sort,
//! uniq, diff, hexdump, edit).
//!
//! All commands use the syscall bridge (`crate::syscall`) for filesystem I/O
//! and return `CmdResult` so they work identically in ring0 and ring3.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::user::shared::abi::fs::{
    DirectoryEntryRecord, DIRECTORY_ENTRY_RECORD_SIZE, FILE_KIND_DEVICE, FILE_KIND_DIRECTORY,
    FILE_KIND_FILE, FILE_KIND_SYMLINK,
};
use crate::user::shared::abi::io::{OPEN_FLAG_READ, OPEN_FLAG_WRITE_CREATE};
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

// ── Shared helpers ──────────────────────────────────────────────────────

/// Read a file line-by-line via syscalls.
fn read_file_lines(path: &str) -> Result<Vec<String>, isize> {
    let fd = syscall::sys_open(path, OPEN_FLAG_READ)?;
    let mut buf = [0u8; 4096];
    let mut content = Vec::new();
    loop {
        match syscall::sys_read(fd, &mut buf, 0) {
            Ok(0) => break,
            Ok(n) => content.extend_from_slice(&buf[..n]),
            Err(e) => {
                let _ = syscall::sys_close(fd);
                return Err(e);
            }
        }
    }
    let _ = syscall::sys_close(fd);
    let text = core::str::from_utf8(&content).map_err(|_| -1_isize)?;
    Ok(text.lines().map(|l| l.into()).collect())
}

/// Write lines to a file via syscalls (create or overwrite).
fn write_file_lines(path: &str, lines: &[String]) -> Result<(), isize> {
    let fd = syscall::sys_open(path, OPEN_FLAG_WRITE_CREATE)?;
    let nl = *b"\n";
    for line in lines {
        syscall::sys_write(fd, line.as_bytes())?;
        syscall::sys_write(fd, &nl)?;
    }
    let _ = syscall::sys_close(fd);
    Ok(())
}

/// Read a command's full input.
///
/// An explicit file operand takes precedence over the pipeline/redirect
/// stdin buffer, matching standard shell semantics: `echo hi | grep hi
/// file.txt` searches `file.txt`, not the piped data.  stdin is consumed
/// only when no file operand was named.
fn read_input(cwd: &str, file: &str, stdin: Option<&str>) -> Result<String, String> {
    if !file.is_empty() {
        let path = resolve_path(cwd, file);
        let fd = syscall::sys_open(&path, OPEN_FLAG_READ)
            .map_err(|e| format!("cannot open `{file}` — {}", errno_msg(e)))?;
        let mut buf = [0u8; CAT_BUF_SIZE];
        let mut content: Vec<u8> = Vec::new();
        loop {
            match syscall::sys_read(fd, &mut buf, 0) {
                Ok(0) => break,
                Ok(n) => content.extend_from_slice(&buf[..n]),
                Err(e) => {
                    let _ = syscall::sys_close(fd);
                    return Err(format!("read error `{file}` — {}", errno_msg(e)));
                }
            }
        }
        let _ = syscall::sys_close(fd);
        return Ok(String::from_utf8_lossy(&content).into_owned());
    }
    if let Some(content) = stdin {
        return Ok(content.to_string());
    }
    Err(String::from("no input"))
}

/// Parse the `-n N` optional flag shared by head and tail.
/// Returns (line_count, Some(file_path)) or (0, None) on error.
pub fn parse_head_tail_args(argv: &[String]) -> (usize, Option<&str>) {
    let mut count: usize = 10;
    let mut path: Option<&str> = None;

    let mut i = 1;
    while i < argv.len() {
        if argv[i] == "-n" {
            if i + 1 < argv.len() {
                if let Ok(n) = argv[i + 1].parse::<usize>() {
                    count = n;
                    i += 2;
                    continue;
                }
            }
            return (0, None);
        } else if !argv[i].starts_with('-') {
            path = Some(argv[i].as_str());
            i += 1;
        } else {
            i += 1;
        }
    }

    if path.is_none() {
        return (0, None);
    }
    (count, path)
}

// ── grep ────────────────────────────────────────────────────────────────

pub fn cmd_grep(cwd: &str, argv: &[String], stdin: Option<&str>) -> CmdResult {
    let pattern = match argv.get(1) {
        Some(p) => p.as_str(),
        None => return CmdResult::error(1, String::from("grep: usage: grep <pattern> [file]\n")),
    };
    if stdin.is_none() && argv.len() < 3 {
        return CmdResult::error(1, String::from("grep: usage: grep <pattern> <file>\n"));
    }
    let file = argv.get(2).map(String::as_str).unwrap_or("");
    let content = match read_input(cwd, file, stdin) {
        Ok(c) => c,
        Err(msg) => return CmdResult::error(1, format!("grep: {msg}\n")),
    };

    let mut out = String::new();
    let mut remainder = String::new();
    remainder.push_str(&content);
    while let Some(pos) = remainder.find('\n') {
        let line = &remainder[..pos];
        if line.contains(pattern) {
            out.push_str(line);
            out.push('\n');
        }
        let rest = remainder[pos + 1..].to_string();
        remainder = rest;
    }
    if !remainder.is_empty() && remainder.contains(pattern) {
        out.push_str(&remainder);
        out.push('\n');
    }
    CmdResult::from_output(out)
}

// ── find ────────────────────────────────────────────────────────────────

/// Recursively collect entries whose name contains `pattern`.
fn find_recursive(dir: &str, pattern: &str, out: &mut String) {
    let mut index = 0;
    let name_buf_len = DIRECTORY_ENTRY_RECORD_SIZE + 256;
    let mut name_buf: Vec<u8> = alloc::vec![0u8; name_buf_len];
    #[allow(clippy::while_let_loop)]
    loop {
        match syscall::sys_read_dir(dir, index, &mut name_buf) {
            Ok(()) => {
                let record: &DirectoryEntryRecord =
                    unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
                let name = core::str::from_utf8(
                    &name_buf[record.name_offset..record.name_offset + record.name_len],
                )
                .unwrap_or("");

                let child = if dir == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", dir, name)
                };

                if record.kind == FILE_KIND_DIRECTORY {
                    find_recursive(&child, pattern, out);
                }

                if name.contains(pattern) {
                    let kind_label = match record.kind {
                        FILE_KIND_DIRECTORY => "[dir] ",
                        FILE_KIND_FILE => "[file]",
                        FILE_KIND_DEVICE => "[dev] ",
                        FILE_KIND_SYMLINK => "[lnk] ",
                        _ => "[?]   ",
                    };
                    out.push_str(&format!("{kind_label} {child}\n"));
                }

                index += 1;
            }
            Err(_) => break,
        }
    }
}

pub fn cmd_find(cwd: &str, argv: &[String]) -> CmdResult {
    if argv.len() < 3 {
        return CmdResult::error(1, String::from("find: usage: find <directory> <pattern>\n"));
    }
    let dir = resolve_path(cwd, &argv[1]);
    let pattern = &argv[2];

    let mut out = String::new();
    find_recursive(&dir, pattern, &mut out);
    if out.is_empty() {
        out.push_str("(no matches)\n");
    }
    CmdResult::from_output(out)
}

// ── head ────────────────────────────────────────────────────────────────

pub fn cmd_head(cwd: &str, argv: &[String], stdin: Option<&str>) -> CmdResult {
    let (count, path_arg) = parse_head_tail_args(argv);
    if stdin.is_none() && path_arg.is_none() {
        return CmdResult::error(1, String::from("head: usage: head [-n N] <file>\n"));
    }
    let file = path_arg.unwrap_or("");
    let content = match read_input(cwd, file, stdin) {
        Ok(c) => c,
        Err(msg) => return CmdResult::error(1, format!("head: {msg}\n")),
    };

    let mut out = String::new();
    for (idx, line) in content.lines().enumerate() {
        if idx >= count {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    CmdResult::from_output(out)
}

// ── tail ────────────────────────────────────────────────────────────────

pub fn cmd_tail(cwd: &str, argv: &[String], stdin: Option<&str>) -> CmdResult {
    let (count, path_arg) = parse_head_tail_args(argv);
    if stdin.is_none() && path_arg.is_none() {
        return CmdResult::error(1, String::from("tail: usage: tail [-n N] <file>\n"));
    }
    let file = path_arg.unwrap_or("");
    let content = match read_input(cwd, file, stdin) {
        Ok(c) => c,
        Err(msg) => return CmdResult::error(1, format!("tail: {msg}\n")),
    };

    let lines: Vec<&str> = content.lines().collect();
    let start = if lines.len() > count {
        lines.len() - count
    } else {
        0
    };
    let mut out = String::new();
    for line in &lines[start..] {
        out.push_str(line);
        out.push('\n');
    }
    CmdResult::from_output(out)
}

// ── wc ──────────────────────────────────────────────────────────────────

pub fn cmd_wc(cwd: &str, argv: &[String], stdin: Option<&str>) -> CmdResult {
    if stdin.is_none() && argv.len() < 2 {
        return CmdResult::error(1, String::from("wc: usage: wc <file>\n"));
    }
    let file = argv.get(1).map(String::as_str).unwrap_or("");
    let content = match read_input(cwd, file, stdin) {
        Ok(c) => c,
        Err(msg) => return CmdResult::error(1, format!("wc: {msg}\n")),
    };

    let mut lines = 0usize;
    let mut words = 0usize;
    let bytes = content.len();
    let mut in_word = false;
    for b in content.bytes() {
        match b {
            b'\n' => {
                lines += 1;
                in_word = false;
            }
            b' ' | b'\t' | b'\r' => {
                in_word = false;
            }
            _ => {
                if !in_word {
                    words += 1;
                    in_word = true;
                }
            }
        }
    }
    // Label reflects the actual input source: an explicit file operand takes
    // precedence over stdin (see read_input), so label by argv, not by the
    // presence of the stdin buffer.
    let name = if argv.len() >= 2 {
        argv[1].clone()
    } else {
        String::from("(stdin)")
    };
    CmdResult::from_output(format!("{lines:>6} {words:>6} {bytes:>6} {name}\n"))
}

// ── sort ────────────────────────────────────────────────────────────────

pub fn cmd_sort(cwd: &str, argv: &[String], stdin: Option<&str>) -> CmdResult {
    let mut reverse = false;
    let mut numeric = false;
    let mut unique = false;
    let mut file_arg: Option<&str> = None;

    for arg in &argv[1..] {
        match arg.as_str() {
            "-r" => reverse = true,
            "-n" => numeric = true,
            "-u" => unique = true,
            other if !other.starts_with('-') => {
                file_arg = Some(other);
            }
            _ => return CmdResult::error(1, format!("sort: unknown flag `{arg}`\n")),
        }
    }

    let mut lines: Vec<String> = if let Some(content) = stdin {
        // Pipeline / redirect stdin buffer
        content.lines().map(|l| l.to_string()).collect()
    } else if let Some(input) = file_arg {
        if input.contains('\n') {
            // Pipeline / inline data
            input.lines().map(|l| l.to_string()).collect()
        } else {
            let abs_path = resolve_path(cwd, input);
            read_file_lines(&abs_path).unwrap_or_default()
        }
    } else {
        return CmdResult::error(1, String::from("sort: usage: sort [-r] [-n] [-u] <file>\n"));
    };

    if numeric {
        lines.sort_unstable_by(|a, b| {
            let na = a.parse::<i64>().unwrap_or(0);
            let nb = b.parse::<i64>().unwrap_or(0);
            if reverse {
                nb.cmp(&na)
            } else {
                na.cmp(&nb)
            }
        });
    } else {
        lines.sort_unstable();
        if reverse {
            lines.reverse();
        }
    }

    if unique {
        let mut deduped: Vec<String> = Vec::with_capacity(lines.len());
        for line in lines {
            if deduped.last() != Some(&line) {
                deduped.push(line);
            }
        }
        lines = deduped;
    }

    let mut out = String::new();
    for line in &lines {
        out.push_str(line);
        out.push('\n');
    }
    CmdResult::from_output(out)
}

// ── uniq ────────────────────────────────────────────────────────────────

pub fn cmd_uniq(cwd: &str, argv: &[String], stdin: Option<&str>) -> CmdResult {
    let mut show_count = false;
    let mut duplicates_only = false;
    let mut uniques_only = false;
    let mut file_arg: Option<&str> = None;

    for arg in &argv[1..] {
        match arg.as_str() {
            "-c" => show_count = true,
            "-d" => duplicates_only = true,
            "-u" => uniques_only = true,
            other if !other.starts_with('-') => {
                file_arg = Some(other);
            }
            _ => return CmdResult::error(1, format!("uniq: unknown flag `{arg}`\n")),
        }
    }

    let lines: Vec<String> = if let Some(content) = stdin {
        // Pipeline / redirect stdin buffer
        content.lines().map(|l| l.to_string()).collect()
    } else if let Some(input) = file_arg {
        if input.contains('\n') {
            input.lines().map(|l| l.to_string()).collect()
        } else {
            let abs_path = resolve_path(cwd, input);
            read_file_lines(&abs_path).unwrap_or_default()
        }
    } else {
        return CmdResult::error(1, String::from("uniq: usage: uniq [-c] [-d] [-u] <file>\n"));
    };

    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let mut count = 1usize;
        while i + count < lines.len() && lines[i + count] == lines[i] {
            count += 1;
        }
        let is_duplicate = count > 1;
        let should_show = match (duplicates_only, uniques_only) {
            (true, false) => is_duplicate,
            (false, true) => !is_duplicate,
            _ => true,
        };
        if should_show {
            if show_count {
                out.push_str(&format!("{:>7} {}\n", count, lines[i]));
            } else {
                out.push_str(&lines[i]);
                out.push('\n');
            }
        }
        i += count;
    }
    CmdResult::from_output(out)
}

// ── diff ────────────────────────────────────────────────────────────────

/// Longest Common Subsequence — returns indices of matching lines in `a` and `b`.
fn compute_lcs(a: &[String], b: &[String]) -> Vec<(usize, usize)> {
    let m = a.len();
    let n = b.len();
    // Build the full DP table.
    let mut dp: Vec<Vec<usize>> = alloc::vec![alloc::vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    let mut matches: Vec<(usize, usize)> = Vec::new();
    let mut i = m;
    let mut j = n;
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            matches.push((i - 1, j - 1));
            i = i.wrapping_sub(1);
            j = j.wrapping_sub(1);
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i = i.wrapping_sub(1);
        } else {
            j = j.wrapping_sub(1);
        }
    }
    matches.reverse();
    matches
}

pub fn cmd_diff(cwd: &str, argv: &[String]) -> CmdResult {
    if argv.len() < 3 {
        return CmdResult::error(1, String::from("diff: usage: diff <file1> <file2>\n"));
    }

    let read_lines = |arg: &str| -> Vec<String> {
        if arg.contains('\n') {
            arg.lines().map(|l| l.to_string()).collect()
        } else {
            let abs_path = resolve_path(cwd, arg);
            read_file_lines(&abs_path).unwrap_or_default()
        }
    };

    let lines1 = read_lines(&argv[1]);
    let lines2 = read_lines(&argv[2]);

    let lcs = compute_lcs(&lines1, &lines2);
    let mut out = String::new();
    let mut i = 0usize;
    let mut j = 0usize;
    for &(li, lj) in &lcs {
        while i < li {
            out.push_str(&format!("< {}\n", lines1[i]));
            i += 1;
        }
        while j < lj {
            out.push_str(&format!("> {}\n", lines2[j]));
            j += 1;
        }
        out.push_str(&format!("  {}\n", lines1[li]));
        i = li + 1;
        j = lj + 1;
    }
    while i < lines1.len() {
        out.push_str(&format!("< {}\n", lines1[i]));
        i += 1;
    }
    while j < lines2.len() {
        out.push_str(&format!("> {}\n", lines2[j]));
        j += 1;
    }
    if out.is_empty() {
        out.push_str("(no differences)\n");
    }
    CmdResult::from_output(out)
}

// ── hexdump ─────────────────────────────────────────────────────────────

/// Display a file as hexadecimal bytes with an ASCII sidebar.
///
/// Usage: `hexdump [-n <count>] <file>`
///
/// Output format (classic `hexdump -C` style):
/// ```text
/// 00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 0a           |Hello World!.|
/// ```
pub fn cmd_hexdump(cwd: &str, argv: &[String]) -> CmdResult {
    let (max_bytes, path_arg) = parse_hexdump_args(argv);
    if path_arg.is_empty() {
        return CmdResult::error(
            1,
            String::from("hexdump: missing path (try `hexdump <file>`)\n"),
        );
    }

    let path = resolve_path(cwd, path_arg);
    let mut out = String::new();

    let fd = match syscall::sys_open(&path, OPEN_FLAG_READ) {
        Ok(fd) => fd,
        Err(e) => {
            return CmdResult::error(
                1,
                format!("hexdump: cannot open `{path_arg}` — {}\n", errno_msg(e)),
            );
        }
    };

    let mut buf = [0u8; 16];
    let mut offset: usize = 0;
    let mut remaining = max_bytes;

    loop {
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            break;
        }
        match syscall::sys_read(fd, &mut buf[..to_read], 0) {
            Ok(0) => break,
            Ok(n) => {
                remaining -= n;
                out.push_str(&format!("{offset:08x}  "));

                let data = &buf[..n];
                for (i, &byte) in data.iter().enumerate() {
                    if i == 8 {
                        out.push(' ');
                    }
                    out.push_str(&format!("{byte:02x} "));
                }

                if n < 16 {
                    for i in n..16 {
                        if i == 8 {
                            out.push(' ');
                        }
                        out.push_str("   ");
                    }
                }

                out.push_str(" |");
                for &byte in data {
                    if byte.is_ascii_graphic() || byte == b' ' {
                        out.push(byte as char);
                    } else {
                        out.push('.');
                    }
                }
                out.push_str("|\n");

                offset += n;
            }
            Err(e) => {
                out.push_str(&format!(
                    "hexdump: read error at offset {offset:#x} — {}\n",
                    errno_msg(e)
                ));
                break;
            }
        }
    }
    let _ = syscall::sys_close(fd);

    CmdResult::from_output(out)
}

/// Parse hexdump arguments: `[-n <count>] [<file>]`.
fn parse_hexdump_args(argv: &[String]) -> (usize, &str) {
    let mut max_bytes = usize::MAX;
    let mut path_arg = "";

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-n" => {
                if i + 1 < argv.len() {
                    max_bytes = argv[i + 1].parse().unwrap_or(usize::MAX);
                    i += 2;
                } else {
                    return (max_bytes, "");
                }
            }
            arg if !arg.starts_with('-') => {
                path_arg = arg;
                i += 1;
            }
            _ => i += 1,
        }
    }
    path_arg = path_arg.trim_start_matches(['\'', '"']);
    path_arg = path_arg.trim_end_matches(['\'', '"']);

    (max_bytes, path_arg)
}

// ── edit (minimal line editor) ──────────────────────────────────────────

/// Minimal line-oriented file editor.
///
/// Usage:
///   `edit <file>`                  — display file with line numbers
///   `edit -a "<line>" <file>`      — append a line to the file
///   `edit -d <N> <file>`           — delete line N (1-based)
///   `edit -s <N> "<line>" <file>`  — substitute line N with new text
pub fn cmd_edit(cwd: &str, argv: &[String]) -> CmdResult {
    let action = parse_edit_args(argv);
    if action.file.is_empty() {
        return CmdResult::error(
            1,
            String::from("edit: missing file (try `edit <file>` or `edit -a \"text\" <file>`)\n"),
        );
    }

    let path = resolve_path(cwd, &action.file);
    let mut out = String::new();

    // Read existing lines via syscall.
    let mut lines = match read_file_lines(&path) {
        Ok(lines) => lines,
        Err(_) => {
            // File doesn't exist — start empty if creating.
            if action.op == EditOp::Append || action.op == EditOp::View {
                Vec::new()
            } else {
                return CmdResult::error(1, format!("edit: cannot open `{}`\n", action.file));
            }
        }
    };

    match action.op {
        EditOp::View => {
            if lines.is_empty() {
                out.push_str(&format!("edit: `{}` is empty\n", action.file));
            } else {
                for (i, line) in lines.iter().enumerate() {
                    out.push_str(&format!("{:4}: {}\n", i + 1, line));
                }
            }
        }
        EditOp::Append => {
            lines.push(action.text.clone());
            let _ = write_file_lines(&path, &lines);
            out.push_str(&format!(
                "edit: appended line {} to `{}`\n",
                lines.len(),
                action.file
            ));
        }
        EditOp::Delete(n) => {
            let idx = (n as usize).saturating_sub(1);
            if idx >= lines.len() {
                out.push_str(&format!(
                    "edit: line {n} out of range (file has {} lines)\n",
                    lines.len()
                ));
            } else {
                let removed = lines.remove(idx);
                let _ = write_file_lines(&path, &lines);
                out.push_str(&format!(
                    "edit: deleted line {n} (`{removed}`) from `{}`\n",
                    action.file
                ));
            }
        }
        EditOp::Substitute(n) => {
            let idx = (n as usize).saturating_sub(1);
            if idx >= lines.len() {
                out.push_str(&format!(
                    "edit: line {n} out of range (file has {} lines)\n",
                    lines.len()
                ));
            } else {
                lines[idx] = action.text.clone();
                let _ = write_file_lines(&path, &lines);
                out.push_str(&format!("edit: set line {n} in `{}`\n", action.file));
            }
        }
    }

    CmdResult::from_output(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EditOp {
    View,
    Append,
    Delete(u32),
    Substitute(u32),
}

struct EditAction {
    op: EditOp,
    file: String,
    text: String,
}

fn parse_edit_args(argv: &[String]) -> EditAction {
    let mut op = EditOp::View;
    let mut file = String::new();
    let mut text = String::new();

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-a" => {
                op = EditOp::Append;
                if i + 1 < argv.len() {
                    text = argv[i + 1].trim_matches(['\'', '"']).to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-d" => {
                if i + 1 < argv.len() {
                    let line_num: u32 = argv[i + 1].parse().unwrap_or(0);
                    op = EditOp::Delete(line_num);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-s" => {
                if i + 2 < argv.len() {
                    let line_num: u32 = argv[i + 1].parse().unwrap_or(0);
                    text = argv[i + 2].trim_matches(['\'', '"']).to_string();
                    op = EditOp::Substitute(line_num);
                    i += 3;
                } else {
                    i += 1;
                }
            }
            arg if !arg.starts_with('-') => {
                file = arg.to_string();
                i += 1;
            }
            _ => i += 1,
        }
    }

    // Strip surrounding quotes.
    file = file.trim_matches(['\'', '"']).to_string();

    EditAction { op, file, text }
}
