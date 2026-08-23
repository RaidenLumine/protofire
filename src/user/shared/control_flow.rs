//! src/user/shared/control_flow.rs
//! Shell control flow: `if`/`for`/`while` parsing and execution.
//!
//! The executor functions accept callbacks for command execution, environment
//! expansion, and glob expansion so they work in both ring0 and ring3.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::user::shared::types::CmdResult;

// ─── Control flow types ───────────────────────────────────────────────

/// Keywords recognised by the control-flow parser.
#[derive(Clone, PartialEq, Debug)]
pub enum CFlowKeyword {
    If,
    Then,
    Else,
    Elif,
    Fi,
    For,
    In,
    Do,
    Done,
    While,
}

/// A segment of a control-flow block: either a keyword or a raw command
/// string (which may contain pipelines, redirects, and conditionals).
#[derive(Clone, Debug)]
pub enum CFlowSegment {
    Keyword(CFlowKeyword),
    Command(String),
}

/// Split a string on unquoted `;` characters (statement separator).
pub fn split_statements(line: &str) -> Vec<String> {
    let mut stmts = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for ch in line.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' => {
                current.push(ch);
                escape = true;
            }
            '\'' if !in_double => {
                current.push(ch);
                in_single = !in_single;
            }
            '"' if !in_single => {
                current.push(ch);
                in_double = !in_double;
            }
            ';' if !in_single && !in_double => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    stmts.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        stmts.push(trimmed);
    }
    stmts
}

/// Tokenise a control-flow block into keywords and command segments.
pub fn tokenize_control_flow(block: &str) -> Vec<CFlowSegment> {
    let stmts = split_statements(block);
    let mut segments = Vec::new();

    fn extract_keyword(s: &str) -> Option<(CFlowKeyword, &str)> {
        let keywords: &[(&str, CFlowKeyword)] = &[
            ("if", CFlowKeyword::If),
            ("then", CFlowKeyword::Then),
            ("else", CFlowKeyword::Else),
            ("elif", CFlowKeyword::Elif),
            ("fi", CFlowKeyword::Fi),
            ("for", CFlowKeyword::For),
            ("in", CFlowKeyword::In),
            ("do", CFlowKeyword::Do),
            ("done", CFlowKeyword::Done),
            ("while", CFlowKeyword::While),
        ];

        for (kw_str, kw) in keywords {
            if let Some(rest) = s.strip_prefix(kw_str) {
                if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') {
                    return Some((kw.clone(), rest.trim_start()));
                }
            }
        }
        None
    }

    for stmt in &stmts {
        let trimmed = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }

        match extract_keyword(trimmed) {
            Some((kw, rest)) => {
                segments.push(CFlowSegment::Keyword(kw));
                if !rest.is_empty() {
                    segments.push(CFlowSegment::Command(rest.to_string()));
                }
            }
            None => {
                segments.push(CFlowSegment::Command(trimmed.to_string()));
            }
        }
    }

    segments
}

/// Count occurrences of shell control-flow keywords outside of quotes.
pub fn count_keywords(line: &str, keywords: &[&str]) -> u32 {
    let mut count: u32 = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if escape {
            escape = false;
            i += 1;
            continue;
        }
        match ch {
            '\\' => {
                escape = true;
                i += 1;
            }
            '\'' if !in_double => {
                in_single = !in_single;
                i += 1;
            }
            '"' if !in_single => {
                in_double = !in_double;
                i += 1;
            }
            _ if !in_single && !in_double => {
                for kw in keywords {
                    let kw_chars: Vec<char> = kw.chars().collect();
                    if i + kw_chars.len() <= chars.len()
                        && chars[i..i + kw_chars.len()] == kw_chars[..]
                    {
                        let before = i == 0 || !chars[i - 1].is_alphanumeric();
                        let after = i + kw_chars.len() >= chars.len()
                            || !chars[i + kw_chars.len()].is_alphanumeric();
                        if before && after {
                            count += 1;
                            i += kw_chars.len();
                            continue;
                        }
                    }
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    count
}

/// Returns `true` if `line` starts a multi-line construct that is not
/// closed on the same line.
pub fn needs_continuation(line: &str) -> bool {
    let openers = count_keywords(line, &["if", "for", "while"]);
    let closers = count_keywords(line, &["fi", "done"]);
    openers > closers
}

// ─── Control flow executor ────────────────────────────────────────────

/// Execute a control-flow block (single-line or accumulated multi-line).
///
/// `exec_fn` is called for each command segment with the command line and cwd.
/// It should handle expansion, dispatch, and return a `CmdResult`.
pub fn execute_control_flow_block(
    block: &str,
    cwd: &mut String,
    mut exec_fn: impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    let segments = tokenize_control_flow(block);
    let mut pos: usize = 0;
    execute_cflow(&segments, &mut pos, cwd, &mut exec_fn)
}

/// Recursive-descent executor for control-flow segments.
fn execute_cflow(
    segments: &[CFlowSegment],
    pos: &mut usize,
    cwd: &mut String,
    exec_fn: &mut impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    let mut last_result = CmdResult::empty();

    while *pos < segments.len() {
        match &segments[*pos] {
            CFlowSegment::Keyword(CFlowKeyword::If) => {
                *pos += 1;
                last_result = execute_if(segments, pos, cwd, exec_fn);
            }
            CFlowSegment::Keyword(CFlowKeyword::For) => {
                *pos += 1;
                last_result = execute_for(segments, pos, cwd, exec_fn);
            }
            CFlowSegment::Keyword(CFlowKeyword::While) => {
                *pos += 1;
                last_result = execute_while(segments, pos, cwd, exec_fn);
            }
            CFlowSegment::Command(cmd) => {
                last_result = exec_fn(cmd, cwd);
                *pos += 1;
            }
            _ => {
                *pos += 1;
            }
        }
    }

    last_result
}

/// Execute `if condition; then body; [elif ...; else ...;] fi`.
fn execute_if(
    segments: &[CFlowSegment],
    pos: &mut usize,
    cwd: &mut String,
    exec_fn: &mut impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    let mut condition = String::new();
    while *pos < segments.len() {
        match &segments[*pos] {
            CFlowSegment::Keyword(CFlowKeyword::Then) => {
                *pos += 1;
                break;
            }
            CFlowSegment::Command(cmd) => {
                if !condition.is_empty() {
                    condition.push_str("; ");
                }
                condition.push_str(cmd);
                *pos += 1;
            }
            _ => {
                *pos += 1;
            }
        }
    }

    let cond_result = exec_fn(&condition, cwd);

    if cond_result.is_ok() {
        let body_result = execute_until(&["else", "elif", "fi"], segments, pos, cwd, exec_fn);
        skip_until(&["fi"], segments, pos);
        return body_result;
    }

    skip_until(&["else", "elif", "fi"], segments, pos);

    if *pos >= segments.len() {
        return CmdResult::empty();
    }

    match &segments[*pos] {
        CFlowSegment::Keyword(CFlowKeyword::Else) => {
            *pos += 1;
            let body = execute_until(&["fi"], segments, pos, cwd, exec_fn);
            if *pos < segments.len() {
                *pos += 1;
            }
            body
        }
        CFlowSegment::Keyword(CFlowKeyword::Elif) => {
            *pos += 1;
            execute_if(segments, pos, cwd, exec_fn)
        }
        CFlowSegment::Keyword(CFlowKeyword::Fi) => {
            *pos += 1;
            CmdResult::empty()
        }
        _ => CmdResult::empty(),
    }
}

/// Execute `for VAR in items; do body; done`.
fn execute_for(
    segments: &[CFlowSegment],
    pos: &mut usize,
    cwd: &mut String,
    exec_fn: &mut impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    let first_cmd = match segments.get(*pos) {
        Some(CFlowSegment::Command(cmd)) => cmd.clone(),
        _ => return CmdResult::error(1, "for: expected variable name\n".into()),
    };
    *pos += 1;

    let mut parts = first_cmd.split_whitespace();
    let var_name = match parts.next() {
        Some(v) => v.to_string(),
        None => return CmdResult::error(1, "for: expected variable name\n".into()),
    };

    let mut items: Vec<String> = Vec::new();
    let mut found_in = false;

    let remainder: Vec<&str> = parts.collect();
    let in_idx = remainder.iter().position(|&w| w == "in");
    if let Some(idx) = in_idx {
        found_in = true;
        for w in &remainder[idx + 1..] {
            items.push(w.to_string());
        }
    } else if matches!(
        segments.get(*pos),
        Some(CFlowSegment::Keyword(CFlowKeyword::In))
    ) {
        found_in = true;
        *pos += 1;
    }

    if found_in {
        while *pos < segments.len() {
            match &segments[*pos] {
                CFlowSegment::Keyword(CFlowKeyword::Do) => {
                    *pos += 1;
                    break;
                }
                CFlowSegment::Command(cmd) => {
                    for item in cmd.split_whitespace() {
                        items.push(item.to_string());
                    }
                    *pos += 1;
                }
                _ => {
                    *pos += 1;
                }
            }
        }
    } else {
        skip_until(&["do"], segments, pos);
        if *pos < segments.len() {
            *pos += 1;
        }
    }

    let body_start = *pos;
    skip_until(&["done"], segments, pos);
    let body_end = *pos;
    if *pos < segments.len() {
        *pos += 1;
    }

    let body_slice = &segments[body_start..body_end];
    let mut accumulated = CmdResult::empty();

    for item in &items {
        // Set the loop variable as an env-var-like side effect.
        // The caller is responsible for propagating this via the exec_fn result context.
        // For now, we pass the item name through via exec_fn — the kernel/ring3 wrappers
        // handle the actual set_env call.
        let iter_cmd = format!("ITER_VAR={var_name}={item}");
        let mut p: usize = 0;
        let iter_result = execute_cflow(body_slice, &mut p, cwd, exec_fn);
        if !iter_result.output.is_empty() {
            accumulated.output.push_str(&iter_result.output);
            if !accumulated.output.ends_with('\n') {
                accumulated.output.push('\n');
            }
        }
        accumulated.exit_code = iter_result.exit_code;

        // Allow exec_fn to process the loop variable assignment via the command string.
        let _ = exec_fn(&iter_cmd, cwd);
    }

    accumulated
}

/// Execute `while condition; do body; done`.
fn execute_while(
    segments: &[CFlowSegment],
    pos: &mut usize,
    cwd: &mut String,
    exec_fn: &mut impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    let cond_start = *pos;
    skip_until(&["do"], segments, pos);
    let cond_end = *pos;
    if *pos < segments.len() {
        *pos += 1;
    }

    let body_start = *pos;
    skip_until(&["done"], segments, pos);
    let body_end = *pos;
    if *pos < segments.len() {
        *pos += 1;
    }

    let cond_slice = &segments[cond_start..cond_end];
    let body_slice = &segments[body_start..body_end];
    let mut accumulated = CmdResult::empty();

    loop {
        let mut p: usize = 0;
        let cond = execute_cflow(cond_slice, &mut p, cwd, exec_fn);
        if !cond.is_ok() {
            break;
        }
        let mut p: usize = 0;
        let iter_result = execute_cflow(body_slice, &mut p, cwd, exec_fn);
        if !iter_result.output.is_empty() {
            accumulated.output.push_str(&iter_result.output);
            if !accumulated.output.ends_with('\n') {
                accumulated.output.push('\n');
            }
        }
        accumulated.exit_code = iter_result.exit_code;
    }

    accumulated
}

/// Execute commands until one of the given keywords is encountered.
fn execute_until(
    stop_kws: &[&str],
    segments: &[CFlowSegment],
    pos: &mut usize,
    cwd: &mut String,
    exec_fn: &mut impl FnMut(&str, &mut String) -> CmdResult,
) -> CmdResult {
    let stop_set: Vec<CFlowKeyword> = stop_kws
        .iter()
        .filter_map(|&kw| match kw {
            "else" => Some(CFlowKeyword::Else),
            "elif" => Some(CFlowKeyword::Elif),
            "fi" => Some(CFlowKeyword::Fi),
            "done" => Some(CFlowKeyword::Done),
            _ => None,
        })
        .collect();

    let mut last_result = CmdResult::empty();
    while *pos < segments.len() {
        match &segments[*pos] {
            CFlowSegment::Keyword(kw) if stop_set.contains(kw) => break,
            CFlowSegment::Command(cmd) => {
                last_result = exec_fn(cmd, cwd);
                *pos += 1;
            }
            _ => {
                *pos += 1;
            }
        }
    }
    last_result
}

/// Skip segments until one of the given keywords is encountered.
fn skip_until(stop_kws: &[&str], segments: &[CFlowSegment], pos: &mut usize) {
    let stop_set: Vec<CFlowKeyword> = stop_kws
        .iter()
        .filter_map(|&kw| match kw {
            "else" => Some(CFlowKeyword::Else),
            "elif" => Some(CFlowKeyword::Elif),
            "fi" => Some(CFlowKeyword::Fi),
            "done" => Some(CFlowKeyword::Done),
            "do" => Some(CFlowKeyword::Do),
            _ => None,
        })
        .collect();

    while *pos < segments.len() {
        match &segments[*pos] {
            CFlowSegment::Keyword(kw) if stop_set.contains(kw) => break,
            _ => *pos += 1,
        }
    }
}
