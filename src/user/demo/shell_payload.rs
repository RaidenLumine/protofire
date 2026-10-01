//! src/user/demo/shell_payload.rs
//!
//! The shell program, as one macro that each architecture instantiates.
//!
//! A payload *is* its architecture: the section it is placed in is the program
//! image the ELF builder copies onto the demo disk, so the shell's code and
//! data have to be emitted once per target, with that target's syscall runtime
//! in scope.  What does *not* differ between targets is the program: the
//! banner, the prompt, the line reader, the tokenizer and the builtins are one
//! shell. This module holds that program once, and [`define_shell_payload!`]
//! emits a copy of it into a section.
//!
//! The invoking module supplies the three things that are genuinely per-target,
//! in this order:
//!
//! * `define_<arch>_payload_runtime!("<section>")` — the syscall stubs the body
//!   calls: `read_fd`, `write_fd`, `open_path`, `read_dir`, `close_fd`,
//!   `current_dir`, `chdir`, `exit_with_code`, `write_section_message`, and
//!   `payload_runtime_status_is_error`.
//! * `shell_address!(<static>)` — the address of one of the payload's own
//!   literals.  Taking that address is an architecture's own instruction (`lea
//!   rip+` on x86_64, `adrp`/`add` on AArch64), so that macro, and not this
//!   program, is where the difference lives.  It has to be defined before this
//!   macro is invoked; the write-side `shell_message!` above it is emitted
//!   here, in terms of it.
//! * the entry point — whatever the loader jumps to with, a stack pointer or
//!   three argument registers — which calls `shell_main`.
//!
//! Everything the macro emits is either a syscall trap or a function in the
//! same section, which is what lets the blob be copied to another address and
//! run there.  That property is checked per architecture: by name in
//! `scripts/check-payload-relocations.sh` for the x86_64 copy, and by the
//! branch-range test in [`crate::user::demo::shell_payload_aarch64`] for the
//! AArch64 one.

/// Emit the shell's program into one payload section.
///
/// See the module documentation for what the invoking module has to provide
/// first, and [`crate::user::demo::shell_payload_x86_64`] for a caller.
// A host that cannot carry a payload section — a COFF or Mach-O build, say —
// compiles this module and invokes nothing in it, which is not a defect to
// report: the macro is here for the two targets that have a shell payload.
#[allow(unused_macros)]
macro_rules! define_shell_payload {
    ($section:literal) => {
        /// Write one of the payload's own literals.
        macro_rules! shell_message {
            ($literal:path) => {
                write_section_message(shell_address!($literal), $literal.len())
            };
        }

use core::mem::size_of;
use core::mem::MaybeUninit;

use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_KIND_OFFSET;
use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET;
use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET;
use crate::user::shared::abi::fs::DIRECTORY_ENTRY_RECORD_SIZE;
use crate::user::shared::abi::fs::FILE_KIND_DIRECTORY;
use crate::user::shared::abi::io::OPEN_FLAG_READ;

/// Longest command line the shell accepts, in bytes.
const SHELL_LINE_CAPACITY: usize = 256;
/// Longest working directory the prompt will display.
const SHELL_CWD_CAPACITY: usize = 256;
/// Buffer one `read_dir` entry and its name are unpacked into.
const SHELL_LISTING_CAPACITY: usize = 1024;
/// Buffer `cat` reads a file through.
const SHELL_FILE_CAPACITY: usize = 512;
/// Longest command line the shell will split into words.
const SHELL_MAX_TOKENS: usize = 16;
/// Size of one token record: an `(address, length)` pair.
const SHELL_TOKEN_SIZE: usize = size_of::<usize>() * 2;
/// Window one console read blocks for, in ticks (milliseconds).  The in-kernel
/// shell uses the same six seconds (`READLINE_TIMEOUT`), so a prompt that a
/// user walks away from behaves the same in both.
const SHELL_READ_TIMEOUT_TICKS: usize = 6000;

#[link_section = $section]
static SHELL_BANNER: [u8; b"adastra ring3 shell \xe2\x80\x94 type 'help' for commands\n".len()] =
    *b"adastra ring3 shell \xe2\x80\x94 type 'help' for commands\n";

#[link_section = $section]
static SHELL_PROMPT_PREFIX: [u8; b"adastra:".len()] = *b"adastra:";

#[link_section = $section]
static SHELL_PROMPT_SUFFIX: [u8; b"$ ".len()] = *b"$ ";

#[link_section = $section]
static SHELL_NEWLINE: [u8; b"\n".len()] = *b"\n";

#[link_section = $section]
static SHELL_SPACE: [u8; b" ".len()] = *b" ";

#[link_section = $section]
static SHELL_DIRECTORY_MARK: [u8; b"/".len()] = *b"/";

#[link_section = $section]
static SHELL_ROOT_PATH: [u8; b"/".len()] = *b"/";

#[link_section = $section]
static SHELL_HELP: [u8; b"adastra shell (ring 3) builtins:\n  help           print this list\n  echo <words>   print the words\n  pwd            print the working directory\n  cd <path>      change the working directory\n  ls [path]      list a directory\n  cat <path>     print a file\n  exit           stop the shell\n"
    .len()] = *b"adastra shell (ring 3) builtins:\n  help           print this list\n  echo <words>   print the words\n  pwd            print the working directory\n  cd <path>      change the working directory\n  ls [path]      list a directory\n  cat <path>     print a file\n  exit           stop the shell\n";

#[link_section = $section]
static SHELL_UNKNOWN_PREFIX: [u8; b"shell: unknown command: ".len()] = *b"shell: unknown command: ";

#[link_section = $section]
static SHELL_CAT_USAGE: [u8; b"shell: cat needs a path\n".len()] = *b"shell: cat needs a path\n";

#[link_section = $section]
static SHELL_LIST_FAILED_PREFIX: [u8; b"shell: ls: cannot list '".len()] =
    *b"shell: ls: cannot list '";

#[link_section = $section]
static SHELL_OPEN_FAILED_PREFIX: [u8; b"shell: cat: cannot open '".len()] =
    *b"shell: cat: cannot open '";

#[link_section = $section]
static SHELL_CD_FAILED_PREFIX: [u8; b"shell: cd: cannot enter '".len()] =
    *b"shell: cd: cannot enter '";

#[link_section = $section]
static SHELL_READ_FAILED_PREFIX: [u8; b"shell: cat: cannot read '".len()] =
    *b"shell: cat: cannot read '";

#[link_section = $section]
static SHELL_QUOTE_SUFFIX: [u8; b"'\n".len()] = *b"'\n";

#[link_section = $section]
static SHELL_WORD_HELP: [u8; b"help".len()] = *b"help";

#[link_section = $section]
static SHELL_WORD_ECHO: [u8; b"echo".len()] = *b"echo";

#[link_section = $section]
static SHELL_WORD_PWD: [u8; b"pwd".len()] = *b"pwd";

#[link_section = $section]
static SHELL_WORD_CD: [u8; b"cd".len()] = *b"cd";

#[link_section = $section]
static SHELL_WORD_LS: [u8; b"ls".len()] = *b"ls";

#[link_section = $section]
static SHELL_WORD_CAT: [u8; b"cat".len()] = *b"cat";

#[link_section = $section]
static SHELL_WORD_EXIT: [u8; b"exit".len()] = *b"exit";

/// Write the prompt: the shell's name, the working directory, and `$ `.
#[inline(never)]
#[link_section = $section]
fn shell_write_prompt(cwd: usize, cwd_len: usize) {
    shell_message!(SHELL_PROMPT_PREFIX);
    write_section_message(cwd, cwd_len);
    shell_message!(SHELL_PROMPT_SUFFIX);
}

/// Report a path a builtin could not act on: `<prefix>'<path>'`.
///
/// A shell that says nothing when a command fails is worse than one that says
/// too much, and the reason is always the path the user named.
#[inline(never)]
#[link_section = $section]
fn shell_write_path_error(prefix: usize, prefix_len: usize, path: usize, path_len: usize) {
    write_section_message(prefix, prefix_len);
    write_section_message(path, path_len);
    shell_message!(SHELL_QUOTE_SUFFIX);
}

/// Ask the kernel for this process's working directory.
///
/// This is the real process state rather than a copy the shell maintains: the
/// shell changes it only through the `cd` syscall and reads it back
/// afterwards, so the prompt cannot drift from where relative paths resolve.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_load_cwd(buffer: usize, capacity: usize) -> usize {
    let length = current_dir(buffer, capacity);
    if payload_runtime_status_is_error(length) || length == 0 || length > capacity {
        // SAFETY: `buffer` names `capacity` writable bytes in the caller's
        // frame, and every caller here passes at least one byte.
        unsafe {
            core::ptr::write(buffer as *mut u8, b'/');
        }
        return 1;
    }
    length
}

/// Read one command line from the console (fd 0).
///
/// The console is a cooked line discipline: it echoes what is typed and hands
/// the reader a whole line, newline included, when the user presses return.
/// This loop therefore normally reads once and returns; it repeats only while
/// a line is longer than the buffer it is being read into.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_read_line(buffer: usize, capacity: usize) -> usize {
    let mut filled = 0;
    while filled < capacity {
        let status = read_fd(
            0,
            buffer.wrapping_add(filled),
            capacity.wrapping_sub(filled),
            SHELL_READ_TIMEOUT_TICKS,
        );
        if payload_runtime_status_is_error(status) {
            // A read that timed out with nothing in hand is an idle prompt; one
            // that timed out mid-line returns what the user typed rather than
            // blocking the shell forever.
            return filled;
        }
        if status == 0 {
            return filled;
        }

        let end = filled.wrapping_add(status);
        let mut index = filled;
        while index < end {
            // SAFETY: `index` is inside the `capacity` bytes the caller owns
            // and the read has just filled up to `end`.
            let byte = unsafe { core::ptr::read(buffer.wrapping_add(index) as *const u8) };
            if byte == b'\n' {
                return index.wrapping_add(1);
            }
            index = index.wrapping_add(1);
        }
        filled = end;
    }
    capacity
}

/// Split a line into whitespace-separated words.
///
/// Writes an `(address, length)` pair per word into `tokens` and returns how
/// many words were stored.  The address is the word's own address in the line
/// buffer rather than an offset into it, because every consumer — the
/// comparisons, `echo`, and the syscalls that take a path — wants to be handed
/// the bytes, not the arithmetic.  Words past `capacity` are dropped: the read
/// buffer already bounds the line, and a command with seventeen arguments is
/// not one this shell wants to guess at.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_tokenize(line: usize, line_len: usize, tokens: usize, capacity: usize) -> usize {
    let mut index = 0;
    let mut count = 0;
    while index < line_len && count < capacity {
        while index < line_len {
            // SAFETY: `index` is below the `line_len` bytes the caller filled.
            let byte = unsafe { core::ptr::read(line.wrapping_add(index) as *const u8) };
            if byte == b' ' || byte == b'\t' || byte == b'\r' || byte == b'\n' {
                index = index.wrapping_add(1);
            } else {
                break;
            }
        }
        if index >= line_len {
            break;
        }

        let start = index;
        while index < line_len {
            // SAFETY: as above — `index` is inside the line.
            let byte = unsafe { core::ptr::read(line.wrapping_add(index) as *const u8) };
            if byte == b' ' || byte == b'\t' || byte == b'\r' || byte == b'\n' {
                break;
            }
            index = index.wrapping_add(1);
        }

        let record = tokens.wrapping_add(count.wrapping_mul(SHELL_TOKEN_SIZE));
        // SAFETY: `record` is the `count`-th pair of a buffer holding
        // `capacity` pairs, and `count < capacity`, so both words are in
        // bounds of the caller's token buffer.
        unsafe {
            core::ptr::write(record as *mut usize, line.wrapping_add(start));
            core::ptr::write(
                record.wrapping_add(size_of::<usize>()) as *mut usize,
                index.wrapping_sub(start),
            );
        }
        count = count.wrapping_add(1);
    }
    count
}

/// The `index`-th word `shell_tokenize` stored.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_token(tokens: usize, index: usize) -> (usize, usize) {
    let record = tokens.wrapping_add(index.wrapping_mul(SHELL_TOKEN_SIZE));
    // SAFETY: the caller passes an index below the token count this buffer was
    // filled with, so both words of the pair hold what the tokenizer wrote.
    unsafe {
        (
            core::ptr::read(record as *const usize),
            core::ptr::read(record.wrapping_add(size_of::<usize>()) as *const usize),
        )
    }
}

/// Whether a word is exactly the bytes of one of the shell's literals.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_word_is(word: usize, word_len: usize, literal: usize, literal_len: usize) -> bool {
    if word_len != literal_len {
        return false;
    }
    let mut index = 0;
    while index < word_len {
        // SAFETY: both byte slices are `word_len` long, which is what the loop
        // bounds, and both are readable for that length.
        let (left, right) = unsafe {
            (
                core::ptr::read(word.wrapping_add(index) as *const u8),
                core::ptr::read(literal.wrapping_add(index) as *const u8),
            )
        };
        if left != right {
            return false;
        }
        index = index.wrapping_add(1);
    }
    true
}

/// Whether the word at `index` is `literal`.
#[inline(never)]
#[link_section = $section]
fn shell_word_at_is(tokens: usize, index: usize, literal: usize, literal_len: usize) -> bool {
    // SAFETY: forwarded to `shell_token`, which the caller reaches only with an
    // index below the token count.
    let (word, word_len) = unsafe { shell_token(tokens, index) };
    // SAFETY: forwarded with that word's own length.
    unsafe { shell_word_is(word, word_len, literal, literal_len) }
}

/// Read the three header fields of a `read_dir` entry the syscall just wrote.
///
/// The listing buffer is a byte array, so every field is read unaligned.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_listing_fields(listing: usize) -> (usize, usize, usize) {
    // SAFETY: the caller has established that the syscall wrote at least
    // `DIRECTORY_ENTRY_RECORD_SIZE` bytes of header at `listing`.
    unsafe {
        (
            core::ptr::read_unaligned(
                listing.wrapping_add(DIRECTORY_ENTRY_RECORD_KIND_OFFSET) as *const usize
            ),
            core::ptr::read_unaligned(
                listing.wrapping_add(DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET) as *const usize,
            ),
            core::ptr::read_unaligned(
                listing.wrapping_add(DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET) as *const usize
            ),
        )
    }
}

/// `ls`: list a directory, marking its subdirectories with a trailing slash.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_builtin_ls(path: usize, path_len: usize) {
    let mut listing = MaybeUninit::<[u8; SHELL_LISTING_CAPACITY]>::uninit();
    let listing_ptr = listing.as_mut_ptr() as usize;

    let mut index = 0;
    loop {
        let written = read_dir(path, path_len, index, listing_ptr, SHELL_LISTING_CAPACITY);
        if payload_runtime_status_is_error(written) {
            // Running off the end of the directory is how the listing ends;
            // failing on the first entry is how a path that cannot be read
            // announces itself.
            if index == 0 {
                shell_write_path_error(
                    shell_address!(SHELL_LIST_FAILED_PREFIX),
                    SHELL_LIST_FAILED_PREFIX.len(),
                    path,
                    path_len,
                );
            }
            return;
        }
        // A short read would mean the syscall reported fewer bytes than its own
        // header; there is nothing to print and nothing to trust.
        if written < DIRECTORY_ENTRY_RECORD_SIZE {
            return;
        }
        // SAFETY: the header is `DIRECTORY_ENTRY_RECORD_SIZE` bytes of the
        // `written` bytes the syscall just left in the listing buffer.
        let (kind, name_offset, name_len) = unsafe { shell_listing_fields(listing_ptr) };
        if name_offset >= written {
            return;
        }
        let name_end = name_offset.wrapping_add(name_len);
        let name_end = if name_end > written {
            written
        } else {
            name_end
        };
        write_section_message(
            listing_ptr.wrapping_add(name_offset),
            name_end.wrapping_sub(name_offset),
        );
        if kind == FILE_KIND_DIRECTORY {
            shell_message!(SHELL_DIRECTORY_MARK);
        }
        shell_message!(SHELL_NEWLINE);
        index = index.wrapping_add(1);
    }
}

/// `cat`: copy a file to stdout through the process's own descriptors.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_builtin_cat(path: usize, path_len: usize) {
    let fd = open_path(path, path_len, OPEN_FLAG_READ);
    if payload_runtime_status_is_error(fd) {
        shell_write_path_error(
            shell_address!(SHELL_OPEN_FAILED_PREFIX),
            SHELL_OPEN_FAILED_PREFIX.len(),
            path,
            path_len,
        );
        return;
    }

    let mut buffer = MaybeUninit::<[u8; SHELL_FILE_CAPACITY]>::uninit();
    let buffer_ptr = buffer.as_mut_ptr() as usize;
    let mut read_failed = false;
    loop {
        // A regular file ignores the timeout argument; end of file reads zero.
        let read = read_fd(fd, buffer_ptr, SHELL_FILE_CAPACITY, 0);
        if payload_runtime_status_is_error(read) {
            // An open that succeeded but a read that did not is what a
            // directory looks like from here, and silence would make it look
            // like an empty file.
            read_failed = true;
            break;
        }
        if read == 0 {
            break;
        }
        write_section_message(buffer_ptr, read);
    }
    let _ = close_fd(fd);
    if read_failed {
        shell_write_path_error(
            shell_address!(SHELL_READ_FAILED_PREFIX),
            SHELL_READ_FAILED_PREFIX.len(),
            path,
            path_len,
        );
    }
}

/// `cd`: hand the path to the kernel and re-read the directory it lands on.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_builtin_cd(cwd: usize, cwd_capacity: usize, path: usize, path_len: usize) -> usize {
    let status = chdir(path, path_len);
    if payload_runtime_status_is_error(status) {
        shell_write_path_error(
            shell_address!(SHELL_CD_FAILED_PREFIX),
            SHELL_CD_FAILED_PREFIX.len(),
            path,
            path_len,
        );
    }
    // SAFETY: the caller's buffer is still its own; re-reading it reports the
    // directory the shell is in, which on the failure path is where it was.
    unsafe { shell_load_cwd(cwd, cwd_capacity) }
}

/// `echo`: print the words after the command, space-separated.
#[inline(never)]
#[link_section = $section]
unsafe fn shell_builtin_echo(tokens: usize, token_count: usize) {
    let mut index = 1;
    while index < token_count {
        if index > 1 {
            shell_message!(SHELL_SPACE);
        }
        // SAFETY: `index` is below the token count.
        let (word, word_len) = unsafe { shell_token(tokens, index) };
        write_section_message(word, word_len);
        index = index.wrapping_add(1);
    }
    shell_message!(SHELL_NEWLINE);
}

#[inline(never)]
#[link_section = $section]
/// The shell's program.  It takes nothing: the loader has already left the
/// user stack in the stack pointer, which is where every buffer below lives,
/// and nothing else it hands over is something a shell reads.
extern "C" fn shell_main() -> ! {
    shell_message!(SHELL_BANNER);

    let mut cwd = MaybeUninit::<[u8; SHELL_CWD_CAPACITY]>::uninit();
    let cwd_ptr = cwd.as_mut_ptr() as usize;
    // SAFETY: `cwd_ptr` names SHELL_CWD_CAPACITY writable bytes in this frame.
    let mut cwd_len = unsafe { shell_load_cwd(cwd_ptr, SHELL_CWD_CAPACITY) };

    loop {
        shell_write_prompt(cwd_ptr, cwd_len);

        let mut line = MaybeUninit::<[u8; SHELL_LINE_CAPACITY]>::uninit();
        let line_ptr = line.as_mut_ptr() as usize;
        // SAFETY: `line_ptr` names SHELL_LINE_CAPACITY writable bytes.
        let line_len = unsafe { shell_read_line(line_ptr, SHELL_LINE_CAPACITY) };
        if line_len == 0 {
            // The read window closed with nothing typed; ask again.
            continue;
        }

        let mut tokens = MaybeUninit::<[(usize, usize); SHELL_MAX_TOKENS]>::uninit();
        let tokens_ptr = tokens.as_mut_ptr() as usize;
        // SAFETY: the token buffer holds SHELL_MAX_TOKENS pairs, and the line
        // window is the one the read just filled.
        let token_count = unsafe {
            shell_tokenize(line_ptr, line_len, tokens_ptr, SHELL_MAX_TOKENS)
        };
        if token_count == 0 {
            continue;
        }

        // Every comparison below asks the same question of token 0, so it is
        // spelled once per branch rather than hidden behind a closure: a
        // closure is its own function, and one the optimizer declines to
        // inline would land outside this section.
        if shell_word_at_is(
            tokens_ptr,
            0,
            shell_address!(SHELL_WORD_HELP),
            SHELL_WORD_HELP.len(),
        ) {
            shell_message!(SHELL_HELP);
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            shell_address!(SHELL_WORD_ECHO),
            SHELL_WORD_ECHO.len(),
        ) {
            // SAFETY: the token buffer and the count it was filled with.
            unsafe {
                shell_builtin_echo(tokens_ptr, token_count);
            }
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            shell_address!(SHELL_WORD_PWD),
            SHELL_WORD_PWD.len(),
        ) {
            write_section_message(cwd_ptr, cwd_len);
            shell_message!(SHELL_NEWLINE);
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            shell_address!(SHELL_WORD_CD),
            SHELL_WORD_CD.len(),
        ) {
            let root = shell_address!(SHELL_ROOT_PATH);
            // SAFETY: token 1 is present exactly when the count says so.
            let (path, path_len) = unsafe {
                if token_count > 1 {
                    shell_token(tokens_ptr, 1)
                } else {
                    (root, SHELL_ROOT_PATH.len())
                }
            };
            // SAFETY: the cwd buffer is this frame's; `path` points into the
            // line buffer for a length the tokenizer bounded.
            cwd_len = unsafe { shell_builtin_cd(cwd_ptr, SHELL_CWD_CAPACITY, path, path_len) };
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            shell_address!(SHELL_WORD_LS),
            SHELL_WORD_LS.len(),
        ) {
            // SAFETY: as above — token 1 is present when the count allows it,
            // and the fallback lists the directory the shell is already in.
            unsafe {
                if token_count > 1 {
                    let (path, path_len) = shell_token(tokens_ptr, 1);
                    shell_builtin_ls(path, path_len);
                } else {
                    shell_builtin_ls(cwd_ptr, cwd_len);
                }
            }
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            shell_address!(SHELL_WORD_CAT),
            SHELL_WORD_CAT.len(),
        ) {
            if token_count < 2 {
                shell_message!(SHELL_CAT_USAGE);
            } else {
                // SAFETY: token 1 exists, per the count check just made, and
                // the path window is the token the tokenizer bounded.
                unsafe {
                    let (path, path_len) = shell_token(tokens_ptr, 1);
                    shell_builtin_cat(path, path_len);
                }
            }
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            shell_address!(SHELL_WORD_EXIT),
            SHELL_WORD_EXIT.len(),
        ) {
            exit_with_code(0);
        } else {
            shell_message!(SHELL_UNKNOWN_PREFIX);
            // SAFETY: token 0 exists, because the token count is non-zero.
            let (word, word_len) = unsafe { shell_token(tokens_ptr, 0) };
            write_section_message(word, word_len);
            shell_message!(SHELL_NEWLINE);
        }
    }
}

    };
}

// Re-exported so the payload modules can reach it by path; see the note above.
#[allow(unused_imports)]
pub(crate) use define_shell_payload;
