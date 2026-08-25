//! src/user/program/shell/control_flow.rs
//!
//! Shell control flow: `if`/`for`/`while` parsing and execution.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::dispatch::run_shell_command;
use super::expand::expand_env_vars;
use super::expand::set_env;
use super::glob::glob_match;
use super::glob::has_glob_chars;
use super::*;
use crate::user::shared::abi::fs::DirectoryEntryRecord;
use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_SIZE;
use crate::user::shared::syscall;

// ─── Keyword counting ─────────────────────────────────────────────────

/// Count the number of keyword occurrences in `line` that begin a command.
///
/// Used by the REPL to track multi-line continuation depth for `if`/`for`/
/// `while` blocks.  A keyword only opens a construct when it appears in a
/// command position: at the start of the line, after a separator (`;`,
/// `&&`, `||`, `|`), or right after `then`/`do`/`else`/`elif`.  This keeps
/// argument words like the `if` in `echo if` from being counted as openers.
#[allow(unused_assignments)]
pub(crate) fn count_keywords(line: &str, keywords: &[&str]) -> u32 {
    // Words that hand command position to the next token (the construct
    // bodies that follow the opener keywords).
    const BOUNDARY_WORDS: &[&str] = &["then", "do", "else", "elif"];

    let mut count = 0u32;
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    // Start-of-line is a command position.
    let mut at_command_start = true;

    // Flush the current word, counting it if it opens a construct, then
    // hand command position to the next token if it is a boundary word.
    macro_rules! flush_word {
        () => {
            if !current.is_empty() {
                let word = core::mem::take(&mut current);
                if at_command_start && keywords.contains(&word.as_str()) {
                    count += 1;
                }
                at_command_start = BOUNDARY_WORDS.contains(&word.as_str());
            }
        };
    }

    for ch in line.chars() {
        match ch {
            '\'' if !in_double => {
                current.push(ch);
                in_single = !in_single;
            }
            '"' if !in_single => {
                current.push(ch);
                in_double = !in_double;
            }
            ';' | '&' | '|' if !in_single && !in_double => {
                flush_word!();
                at_command_start = true;
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                flush_word!();
            }
            ch => current.push(ch),
        }
    }
    flush_word!();
    count
}

/// Return `true` when `line` begins a construct that needs continuation: a
/// trailing line-continuation backslash, or an `if`/`for`/`while` opener
/// whose `fi`/`done` closers do not balance.
pub(crate) fn needs_continuation(line: &str) -> bool {
    let line = line.trim_end();
    if line.ends_with('\\') {
        return true;
    }
    let openers = count_keywords(line, &["if", "for", "while"]);
    let closers = count_keywords(line, &["fi", "done"]);
    openers > closers
}

// ─── Control-flow execution ───────────────────────────────────────────

/// Execute a control-flow block (`if … fi`, `for … done`, `while … done`).
///
/// Each command inside the block is dispatched through the normal shell
/// command path so pipelines, redirects, and conditionals still work.
pub(crate) fn execute_control_flow_block(block: &str, cwd: &mut String) -> CmdResult {
    let block = block.trim();
    if let Some(parsed) = parse_if_block(block) {
        return execute_if(parsed, cwd);
    }
    if let Some(parsed) = parse_for_block(block) {
        return execute_for(parsed, cwd);
    }
    if let Some(parsed) = parse_while_block(block) {
        return execute_while(parsed, cwd);
    }
    CmdResult::error(2, format!("shell: unrecognized control flow: `{block}`\n"))
}

// ── if … then … [else …] fi ───────────────────────────────────────────

struct IfBlock {
    condition: String,
    then_body: String,
    else_body: Option<String>,
}

fn parse_if_block(block: &str) -> Option<IfBlock> {
    let tokens = tokenize(block);
    let if_pos = tokens.iter().position(|token| token == "if")?;
    let then_pos = tokens.iter().position(|token| token == "then")?;
    if then_pos <= if_pos {
        return None;
    }
    let fi_pos = tokens.iter().rposition(|token| token == "fi")?;
    if fi_pos <= then_pos {
        return None;
    }

    let condition = tokens[if_pos + 1..then_pos].join(" ");
    if condition.is_empty() {
        return None;
    }

    let body_tokens = &tokens[then_pos + 1..fi_pos];
    let (then_tokens, else_tokens) = match body_tokens.iter().position(|token| token == "else") {
        Some(else_pos) => (&body_tokens[..else_pos], Some(&body_tokens[else_pos + 1..])),
        None => (body_tokens, None),
    };
    let then_body = then_tokens.join(" ");
    if then_body.is_empty() {
        return None;
    }
    let else_body = else_tokens.map(|tokens| tokens.join(" "));

    Some(IfBlock {
        condition,
        then_body,
        else_body,
    })
}

fn execute_if(block: IfBlock, cwd: &mut String) -> CmdResult {
    let condition = expand_env_vars(&block.condition);
    let condition_result = run_shell_command(&condition, cwd);
    if condition_result.is_ok() {
        run_shell_command(&expand_env_vars(&block.then_body), cwd)
    } else if let Some(else_body) = block.else_body {
        run_shell_command(&expand_env_vars(&else_body), cwd)
    } else {
        CmdResult::empty()
    }
}

// ── for var [in words] do … done ──────────────────────────────────────

struct ForBlock {
    var: String,
    items: Vec<String>,
    body: String,
}

fn parse_for_block(block: &str) -> Option<ForBlock> {
    let tokens = tokenize(block);
    let for_pos = tokens.iter().position(|token| token == "for")?;
    let var = tokens.get(for_pos + 1)?.clone();
    if var.is_empty() || var == "in" || var == "do" {
        return None;
    }
    let do_pos = tokens.iter().position(|token| token == "do")?;
    if do_pos <= for_pos {
        return None;
    }
    let done_pos = tokens.iter().rposition(|token| token == "done")?;
    if done_pos <= do_pos {
        return None;
    }

    let body = tokens[do_pos + 1..done_pos].join(" ");
    if body.is_empty() {
        return None;
    }

    // Items sit between the loop variable and `do`, optionally introduced by
    // a literal `in` keyword.
    let mut item_tokens: Vec<&String> = tokens[for_pos + 2..do_pos].iter().collect();
    if item_tokens.first().map(|token| token.as_str()) == Some("in") {
        item_tokens.remove(0);
    }
    let items: Vec<String> = item_tokens.into_iter().cloned().collect();

    Some(ForBlock { var, items, body })
}

fn execute_for(block: ForBlock, cwd: &mut String) -> CmdResult {
    // Resolve the iteration list.  Glob patterns are expanded against the
    // filesystem; a bare `for var in` (no items) iterates the current
    // directory.
    let mut items = Vec::new();
    for item in &block.items {
        let item = expand_env_vars(item);
        if has_glob_chars(&item) {
            items.extend(glob_directory_items(cwd, &item));
        } else {
            items.push(item);
        }
    }
    if items.is_empty() && block.items.is_empty() {
        items = list_directory_items(cwd);
    }

    let mut output = String::new();
    for item in items {
        set_env(&block.var, &item);
        let result = run_shell_command(&expand_env_vars(&block.body), cwd);
        output.push_str(&result.output);
        if !result.is_ok() {
            return CmdResult::error(result.exit_code, output);
        }
    }
    CmdResult::success(output)
}

// ── while condition do … done ─────────────────────────────────────────

struct WhileBlock {
    condition: String,
    body: String,
}

fn parse_while_block(block: &str) -> Option<WhileBlock> {
    let tokens = tokenize(block);
    let while_pos = tokens.iter().position(|token| token == "while")?;
    let do_pos = tokens.iter().position(|token| token == "do")?;
    if do_pos <= while_pos {
        return None;
    }
    let done_pos = tokens.iter().rposition(|token| token == "done")?;
    if done_pos <= do_pos {
        return None;
    }

    let condition = tokens[while_pos + 1..do_pos].join(" ");
    if condition.is_empty() {
        return None;
    }
    let body = tokens[do_pos + 1..done_pos].join(" ");
    if body.is_empty() {
        return None;
    }

    Some(WhileBlock { condition, body })
}

fn execute_while(block: WhileBlock, cwd: &mut String) -> CmdResult {
    let mut output = String::new();
    let mut iterations = 0usize;
    loop {
        let condition = expand_env_vars(&block.condition);
        let condition_result = run_shell_command(&condition, cwd);
        if !condition_result.is_ok() {
            break;
        }
        let body_result = run_shell_command(&expand_env_vars(&block.body), cwd);
        output.push_str(&body_result.output);
        if !body_result.is_ok() {
            return CmdResult::error(body_result.exit_code, output);
        }
        iterations += 1;
        if iterations >= MAX_LOOP_ITERATIONS {
            return CmdResult::error(
                2,
                format!("{output}shell: while loop exceeded {MAX_LOOP_ITERATIONS} iterations\n"),
            );
        }
    }
    CmdResult::success(output)
}

/// Upper bound on loop iterations, guarding against a non-terminating
/// `while` body.
const MAX_LOOP_ITERATIONS: usize = 10_000;

// ── filesystem iteration helpers ──────────────────────────────────────

/// Expand a glob pattern (which may include a directory prefix) against the
/// filesystem, returning the matching names.
fn glob_directory_items(cwd: &str, pattern: &str) -> Vec<String> {
    let (dir, file_pattern) = split_glob_path(cwd, pattern);
    let mut matches = Vec::new();
    let mut name_buf = vec![0u8; DIRECTORY_ENTRY_RECORD_SIZE + 256];
    let mut index = 0;
    while let Ok(()) = syscall::sys_read_dir(&dir, index, &mut name_buf) {
        let record: &DirectoryEntryRecord =
            unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
        let name = core::str::from_utf8(
            &name_buf[record.name_offset..record.name_offset + record.name_len],
        )
        .unwrap_or("");
        if glob_match(&file_pattern, name) {
            matches.push(name.to_string());
        }
        index += 1;
    }
    matches.sort();
    matches
}

/// List the (non-hidden) entries of `cwd`.
fn list_directory_items(cwd: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut name_buf = vec![0u8; DIRECTORY_ENTRY_RECORD_SIZE + 256];
    let mut index = 0;
    while let Ok(()) = syscall::sys_read_dir(cwd, index, &mut name_buf) {
        let record: &DirectoryEntryRecord =
            unsafe { &*(name_buf.as_ptr() as *const DirectoryEntryRecord) };
        let name = core::str::from_utf8(
            &name_buf[record.name_offset..record.name_offset + record.name_len],
        )
        .unwrap_or("");
        if !name.starts_with('.') {
            items.push(name.to_string());
        }
        index += 1;
    }
    items.sort();
    items
}

/// Split a glob pattern into its directory prefix and file-name pattern.
fn split_glob_path(cwd: &str, pattern: &str) -> (String, String) {
    if let Some(last_slash) = pattern.rfind('/') {
        if last_slash == 0 {
            (String::from("/"), pattern[1..].to_string())
        } else if pattern.starts_with('/') {
            (
                pattern[..last_slash].to_string(),
                pattern[last_slash + 1..].to_string(),
            )
        } else {
            let mut dir = cwd.to_string();
            if !dir.ends_with('/') {
                dir.push('/');
            }
            dir.push_str(&pattern[..last_slash]);
            (dir, pattern[last_slash + 1..].to_string())
        }
    } else {
        (cwd.to_string(), pattern.to_string())
    }
}

// ── shell tokenizer ───────────────────────────────────────────────────

/// Split a line into tokens, honouring single/double quotes and treating
/// `;` as a token separator.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;

    for ch in line.chars() {
        match ch {
            '\'' if !in_double => {
                current.push(ch);
                in_single = !in_single;
            }
            '"' if !in_single => {
                current.push(ch);
                in_double = !in_double;
            }
            ';' if !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(core::mem::take(&mut current));
                }
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(core::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_openers_and_closers() {
        assert_eq!(
            count_keywords("if test -f /x; then echo hi; fi", &["if", "for", "while"]),
            1
        );
        assert_eq!(
            count_keywords("if a; then if b; then c; fi; fi", &["if", "for", "while"]),
            2
        );
        assert_eq!(
            count_keywords("for f in *.txt; do cat $f; done", &["if", "for", "while"]),
            1
        );
        assert_eq!(count_keywords("echo if", &["if"]), 0);
    }

    #[test]
    fn needs_continuation_for_unbalanced_if() {
        assert!(needs_continuation("if test -f /x; then"));
        assert!(!needs_continuation("if test -f /x; then echo y; fi"));
        assert!(needs_continuation("for f in *; do"));
        assert!(!needs_continuation("for f in *; do cat $f; done"));
    }

    #[test]
    fn tokenizer_keeps_quoted_words_together() {
        let tokens = tokenize("echo \"hello world\"; if 'then' x");
        assert_eq!(tokens, ["echo", "\"hello world\"", "if", "'then'", "x"]);
    }

    #[test]
    fn parse_if_block_extracts_parts() {
        let block = parse_if_block("if test -f /x; then echo yes; fi").expect("parse if");
        assert_eq!(block.condition, "test -f /x");
        assert_eq!(block.then_body, "echo yes");
        assert_eq!(block.else_body, None);
    }

    #[test]
    fn parse_if_block_with_else() {
        let block =
            parse_if_block("if test -f /x; then echo yes; else echo no; fi").expect("parse if");
        assert_eq!(block.condition, "test -f /x");
        assert_eq!(block.then_body, "echo yes");
        assert_eq!(block.else_body.as_deref(), Some("echo no"));
    }

    #[test]
    fn parse_for_block_extracts_items() {
        let block = parse_for_block("for f in a b c; do cat $f; done").expect("parse for");
        assert_eq!(block.var, "f");
        assert_eq!(block.items, ["a", "b", "c"]);
        assert_eq!(block.body, "cat $f");
    }

    #[test]
    fn parse_while_block_extracts_parts() {
        let block = parse_while_block("while test -f /x; do echo x; done").expect("parse while");
        assert_eq!(block.condition, "test -f /x");
        assert_eq!(block.body, "echo x");
    }
}
