//! src/user/demo/shell_payload_x86_64.rs
//!
//! The x86_64 ring-3 shell payload.
//!
//! `src/fs/demo/` writes this program into
//! `/apps/packages/shell/bin/shell.elf`, and the boot runs it: the prompt on
//! the console is this code in ring 3, not the in-kernel Rust shell
//! (`crate::user::program::shell`) that AArch64 and RISC-V still reach through
//! the `host_proxy` entry in their manifests.
//!
//! It is a payload in the same sense as the other demo programs: a
//! `#[link_section]`-placed blob of this target's machine code, copied out of
//! the kernel image by [`crate::user::demo::elf_builder`] and executed at
//! another address.  Everything it reaches is therefore either a syscall trap
//! or a function in this section, and `scripts/check-payload-relocations.sh`
//! reads the image's relocation table to hold that line.
//!
//! Two consequences of that show up below and read as style rather than as
//! requirement:
//!
//! * Buffers are locals, never `static mut`.  The section is mapped
//!   read-execute — it *is* the program image — so a writable static would
//!   fault on the first keystroke.
//! * Indexing goes through pointers and arithmetic that could overflow uses the
//!   wrapping forms.  A debug build's overflow or bounds check is a call to
//!   `core::panicking`, which lives outside this section, and a call out of the
//!   blob lands in the kernel image's copy of the callee rather than in the
//!   program that was copied onto the disk.
//!
//! This section used to hold a recovered assembly shell instead, with this Rust
//! module as the symbol bridge to it.  That blob printed a banner and a prompt
//! and then faulted on the first command: its `read_line` kept the typed line at
//! `[rsp]`, which is the return address the `call` had just pushed, so `ret`
//! jumped to the bytes of the command — `help` became the instruction-fetch
//! address `0x706c6568`, in unmapped memory.  A boot with no keyboard sees the
//! banner and the prompt and nothing else, so that shell looked healthy for as
//! long as nothing typed at it.

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

macro_rules! rip_relative_address {
    ($symbol:path) => {{
        let address: usize;
        // SAFETY: a RIP-relative `lea` against a symbol in this same payload;
        // the instruction computes an address and touches no memory.  Casting
        // the symbol instead would be an *absolute* address, which still names
        // the kernel image's copy of it after this blob is copied to a disk.
        unsafe {
            core::arch::asm!(
                "lea {address}, [rip + {symbol}]",
                address = lateout(reg) address,
                symbol = sym $symbol,
                options(nostack, preserves_flags),
            );
        }
        address
    }};
}

/// Write one of the payload's own literals.
macro_rules! shell_message {
    ($literal:path) => {
        write_section_message(rip_relative_address!($literal), $literal.len())
    };
}

#[link_section = "adastra_shell_payload"]
static SHELL_BANNER: [u8; b"adastra ring3 shell \xe2\x80\x94 type 'help' for commands\n".len()] =
    *b"adastra ring3 shell \xe2\x80\x94 type 'help' for commands\n";

#[link_section = "adastra_shell_payload"]
static SHELL_PROMPT_PREFIX: [u8; b"adastra:".len()] = *b"adastra:";

#[link_section = "adastra_shell_payload"]
static SHELL_PROMPT_SUFFIX: [u8; b"$ ".len()] = *b"$ ";

#[link_section = "adastra_shell_payload"]
static SHELL_NEWLINE: [u8; b"\n".len()] = *b"\n";

#[link_section = "adastra_shell_payload"]
static SHELL_SPACE: [u8; b" ".len()] = *b" ";

#[link_section = "adastra_shell_payload"]
static SHELL_DIRECTORY_MARK: [u8; b"/".len()] = *b"/";

#[link_section = "adastra_shell_payload"]
static SHELL_ROOT_PATH: [u8; b"/".len()] = *b"/";

#[link_section = "adastra_shell_payload"]
static SHELL_HELP: [u8; b"adastra shell (ring 3) builtins:\n  help           print this list\n  echo <words>   print the words\n  pwd            print the working directory\n  cd <path>      change the working directory\n  ls [path]      list a directory\n  cat <path>     print a file\n  exit           stop the shell\n"
    .len()] = *b"adastra shell (ring 3) builtins:\n  help           print this list\n  echo <words>   print the words\n  pwd            print the working directory\n  cd <path>      change the working directory\n  ls [path]      list a directory\n  cat <path>     print a file\n  exit           stop the shell\n";

#[link_section = "adastra_shell_payload"]
static SHELL_UNKNOWN_PREFIX: [u8; b"shell: unknown command: ".len()] = *b"shell: unknown command: ";

#[link_section = "adastra_shell_payload"]
static SHELL_CAT_USAGE: [u8; b"shell: cat needs a path\n".len()] = *b"shell: cat needs a path\n";

#[link_section = "adastra_shell_payload"]
static SHELL_LIST_FAILED_PREFIX: [u8; b"shell: ls: cannot list '".len()] =
    *b"shell: ls: cannot list '";

#[link_section = "adastra_shell_payload"]
static SHELL_OPEN_FAILED_PREFIX: [u8; b"shell: cat: cannot open '".len()] =
    *b"shell: cat: cannot open '";

#[link_section = "adastra_shell_payload"]
static SHELL_CD_FAILED_PREFIX: [u8; b"shell: cd: cannot enter '".len()] =
    *b"shell: cd: cannot enter '";

#[link_section = "adastra_shell_payload"]
static SHELL_READ_FAILED_PREFIX: [u8; b"shell: cat: cannot read '".len()] =
    *b"shell: cat: cannot read '";

#[link_section = "adastra_shell_payload"]
static SHELL_QUOTE_SUFFIX: [u8; b"'\n".len()] = *b"'\n";

#[link_section = "adastra_shell_payload"]
static SHELL_WORD_HELP: [u8; b"help".len()] = *b"help";

#[link_section = "adastra_shell_payload"]
static SHELL_WORD_ECHO: [u8; b"echo".len()] = *b"echo";

#[link_section = "adastra_shell_payload"]
static SHELL_WORD_PWD: [u8; b"pwd".len()] = *b"pwd";

#[link_section = "adastra_shell_payload"]
static SHELL_WORD_CD: [u8; b"cd".len()] = *b"cd";

#[link_section = "adastra_shell_payload"]
static SHELL_WORD_LS: [u8; b"ls".len()] = *b"ls";

#[link_section = "adastra_shell_payload"]
static SHELL_WORD_CAT: [u8; b"cat".len()] = *b"cat";

#[link_section = "adastra_shell_payload"]
static SHELL_WORD_EXIT: [u8; b"exit".len()] = *b"exit";

// The section's own symbols, read by the two accessors below.  With the
// `abi_frozen_payload` feature those answer with the frozen copy instead, so
// the declarations have no reader: the section is still compiled and still in
// the image, it is simply not the copy that ships.
#[cfg(not(feature = "abi_frozen_payload"))]
unsafe extern "C" {
    static adastra_shell_payload_entry: u8;

    #[link_name = "__start_adastra_shell_payload"]
    static ADASTRA_SHELL_PAYLOAD_SECTION_START: u8;
    #[link_name = "__stop_adastra_shell_payload"]
    static ADASTRA_SHELL_PAYLOAD_SECTION_END: u8;
}

crate::user::syscall::define_x86_64_payload_runtime!("adastra_shell_payload");

core::arch::global_asm!(
    r#"
.section adastra_shell_payload,"ax",@progbits
.global adastra_shell_payload_entry
.type adastra_shell_payload_entry,@function
adastra_shell_payload_entry:
    mov rdi, rsp
    jmp {main}
"#,
    main = sym adastra_shell_payload_main,
);

/// The payload's machine code and data, as it was on 2026-10-01.
///
/// With the `abi_frozen_payload` feature the ELF builder ships these bytes
/// instead of the section this build compiled, so the boot runs an x86_64 shell
/// that was *not* rebuilt.  It is the third such program on this architecture
/// and the only interactive one: the launchers announce what they are and exit,
/// while this one waits for a command and answers it, which is what lets the
/// gate exercise the console and directory syscalls against a frozen caller.
///
/// The bytes come out of the x86_64 kernel image, between the
/// `__start_`/`__stop_adastra_shell_payload` symbols:
///
/// ```text
/// cargo build --target x86_64-unknown-none --features demo-disk
/// objcopy -O binary --only-section=adastra_shell_payload \
///     target/x86_64-unknown-none/debug/protofire \
///     src/user/demo/fixtures/shell_payload_x86_64.bin
/// ```
///
/// Re-freezing is a deliberate act, not a build step: the payload carries the
/// ABI of the day it was built, and that is what makes the gate mean something.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD: &[u8] = include_bytes!("fixtures/shell_payload_x86_64.bin");

/// Where the frozen payload's entry point sits inside those bytes.
#[cfg(feature = "abi_frozen_payload")]
const FROZEN_PAYLOAD_ENTRY_OFFSET: usize = 0;

#[cfg(not(feature = "abi_frozen_payload"))]
pub fn payload_bytes() -> &'static [u8] {
    // SAFETY: the linker's own markers around this payload's section bound the
    // slice, which is live for the life of the image.
    unsafe {
        let start = core::ptr::addr_of!(ADASTRA_SHELL_PAYLOAD_SECTION_START);
        let end = core::ptr::addr_of!(ADASTRA_SHELL_PAYLOAD_SECTION_END);
        let start_addr = start as usize;
        let end_addr = end as usize;
        let len = end_addr
            .checked_sub(start_addr)
            .expect("x86_64 shell payload symbols must be ordered");

        core::slice::from_raw_parts(start, len)
    }
}

#[cfg(feature = "abi_frozen_payload")]
pub fn payload_bytes() -> &'static [u8] {
    FROZEN_PAYLOAD
}

/// Where the payload's entry point sits inside those bytes.
#[cfg(not(feature = "abi_frozen_payload"))]
pub fn payload_entry_offset() -> usize {
    let entry = core::ptr::addr_of!(adastra_shell_payload_entry) as usize;
    let start = core::ptr::addr_of!(ADASTRA_SHELL_PAYLOAD_SECTION_START) as usize;
    entry
        .checked_sub(start)
        .expect("x86_64 shell payload entry must follow the section start")
}

#[cfg(feature = "abi_frozen_payload")]
pub fn payload_entry_offset() -> usize {
    FROZEN_PAYLOAD_ENTRY_OFFSET
}

/// Which copy of the payload this build ships: `frozen` or `compiled`.
///
/// The runtime check asserts the boot line that quotes this, so a run of the
/// ABI gate cannot pass while quietly testing a freshly built payload.
pub const fn payload_source() -> &'static str {
    if cfg!(feature = "abi_frozen_payload") {
        "frozen"
    } else {
        "compiled"
    }
}

/// Write the prompt: the shell's name, the working directory, and `$ `.
#[inline(never)]
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
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
                    rip_relative_address!(SHELL_LIST_FAILED_PREFIX),
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
#[link_section = "adastra_shell_payload"]
unsafe fn shell_builtin_cat(path: usize, path_len: usize) {
    let fd = open_path(path, path_len, OPEN_FLAG_READ);
    if payload_runtime_status_is_error(fd) {
        shell_write_path_error(
            rip_relative_address!(SHELL_OPEN_FAILED_PREFIX),
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
            rip_relative_address!(SHELL_READ_FAILED_PREFIX),
            SHELL_READ_FAILED_PREFIX.len(),
            path,
            path_len,
        );
    }
}

/// `cd`: hand the path to the kernel and re-read the directory it lands on.
#[inline(never)]
#[link_section = "adastra_shell_payload"]
unsafe fn shell_builtin_cd(cwd: usize, cwd_capacity: usize, path: usize, path_len: usize) -> usize {
    let status = chdir(path, path_len);
    if payload_runtime_status_is_error(status) {
        shell_write_path_error(
            rip_relative_address!(SHELL_CD_FAILED_PREFIX),
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
#[link_section = "adastra_shell_payload"]
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
#[link_section = "adastra_shell_payload"]
extern "C" fn adastra_shell_payload_main(_initial_stack: usize) -> ! {
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
        let token_count =
            unsafe { shell_tokenize(line_ptr, line_len, tokens_ptr, SHELL_MAX_TOKENS) };
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
            rip_relative_address!(SHELL_WORD_HELP),
            SHELL_WORD_HELP.len(),
        ) {
            shell_message!(SHELL_HELP);
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            rip_relative_address!(SHELL_WORD_ECHO),
            SHELL_WORD_ECHO.len(),
        ) {
            // SAFETY: the token buffer and the count it was filled with.
            unsafe {
                shell_builtin_echo(tokens_ptr, token_count);
            }
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            rip_relative_address!(SHELL_WORD_PWD),
            SHELL_WORD_PWD.len(),
        ) {
            write_section_message(cwd_ptr, cwd_len);
            shell_message!(SHELL_NEWLINE);
        } else if shell_word_at_is(
            tokens_ptr,
            0,
            rip_relative_address!(SHELL_WORD_CD),
            SHELL_WORD_CD.len(),
        ) {
            let root = rip_relative_address!(SHELL_ROOT_PATH);
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
            rip_relative_address!(SHELL_WORD_LS),
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
            rip_relative_address!(SHELL_WORD_CAT),
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
            rip_relative_address!(SHELL_WORD_EXIT),
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

#[cfg(test)]
mod tests {
    use super::payload_bytes;
    use super::payload_entry_offset;
    use super::SHELL_BANNER;
    use super::SHELL_PROMPT_PREFIX;
    use super::SHELL_PROMPT_SUFFIX;

    #[test]
    fn shell_payload_is_a_non_empty_image_with_the_entry_inside_it() {
        let payload = payload_bytes();
        assert!(!payload.is_empty(), "the shell payload section is empty");
        assert!(
            payload_entry_offset() < payload.len(),
            "the shell payload entry is outside the section it is copied from"
        );
    }

    #[test]
    fn the_banner_and_prompt_are_the_lines_the_boot_gates_assert() {
        // `scripts/check-x8664-runtime.sh` requires these in the serial log.
        // A rename has to walk past this test instead of turning a boot gate
        // red in an unrelated change.
        assert!(SHELL_BANNER.starts_with(b"adastra ring3 shell"));
        assert_eq!(SHELL_PROMPT_PREFIX, *b"adastra:");
        assert_eq!(SHELL_PROMPT_SUFFIX, *b"$ ");
    }
}
