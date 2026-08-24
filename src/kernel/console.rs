//! src/kernel/console.rs
//!
//! Console subsystem for line buffering, byte reads, and waiter wakeups.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch;
use crate::kernel::process::Scheduler;
use crate::kernel::sync::{
    input_wait::{self, WaitStatsBookkeeping},
    Condvar, Mutex, WaitTimeoutCleanupRef,
};
use crate::util::debug;

const MAX_COOKED_BYTES: usize = 512;
const MAX_EDIT_LINE: usize = 256;
const TAB_ECHO_COLUMNS: usize = 4;
const MAX_ECHO_BYTES: usize = TAB_ECHO_COLUMNS * 3;

/// ANSI escape sequence parsing states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum EscapeState {
    /// Not inside an escape sequence.
    #[default]
    None,
    /// Received `\x1b` — expecting `[` next.
    SawEsc,
    /// Received `\x1b[` — collecting parameter bytes and the final byte.
    SawCsi { params: [u8; 4], param_len: u8 },
}

/// Callback type for history lookup: `fn(direction: i32) -> Option<String>`
/// where negative = go back in history, positive = go forward.
pub type HistoryCallback = fn(direction: i32, saved_line: Option<&str>) -> Option<String>;

/// Callback type for tab completion: `fn(prefix: &str, cwd: &str) -> Option<String>`.
pub type CompletionCallback = fn(prefix: &str, cwd: &str) -> Option<String>;

/// Registered history provider (set by the shell at startup).
static HISTORY_CALLBACK: Mutex<Option<HistoryCallback>> = Mutex::new(None);

/// Registered completion provider (set by the shell at startup).
static COMPLETION_CALLBACK: Mutex<Option<CompletionCallback>> = Mutex::new(None);

/// Signal-generating callbacks (set by the shell for Ctrl-C / Ctrl-Z).
pub type InterruptCallback = fn();
pub type StopCallback = fn();
static INTERRUPT_CALLBACK: Mutex<Option<InterruptCallback>> = Mutex::new(None);
static STOP_CALLBACK: Mutex<Option<StopCallback>> = Mutex::new(None);

/// Saved line buffer for history navigation (restore when moving past the
/// newest entry).
static SAVED_HISTORY_LINE: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// PID of the foreground process group, used to deliver Ctrl-C / Ctrl-Z
/// signals to the correct job.
static FOREGROUND_PID: Mutex<Option<u32>> = Mutex::new(None);

static CONSOLE_TTY: Mutex<Option<Arc<ConsoleTty>>> = Mutex::new(None);

#[derive(Default)]
struct ConsoleState {
    edit_line: Vec<u8>,
    edit_echo_widths: Vec<u8>,
    cooked: VecDeque<u8>,
    escape_state: EscapeState,
    history_index: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ConsoleFeedResult {
    cooked_bytes: usize,
    echoed: [u8; MAX_ECHO_BYTES],
    echoed_len: usize,
}

impl ConsoleFeedResult {
    fn echoed_bytes(&self) -> &[u8] {
        &self.echoed[..self.echoed_len]
    }

    fn with_echo(bytes: &[u8]) -> Self {
        let mut result = Self::default();
        result.echoed[..bytes.len()].copy_from_slice(bytes);
        result.echoed_len = bytes.len();
        result
    }

    fn with_backspace_echo(columns: usize) -> Self {
        let mut result = Self::default();
        for index in 0..columns {
            let start = index * 3;
            result.echoed[start..start + 3].copy_from_slice(b"\x08 \x08");
        }
        result.echoed_len = columns * 3;
        result
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConsoleWaitStats {
    pub waiter_peak: usize,
    pub wake_count: u64,
    pub timeout_count: u64,
}

impl ConsoleWaitStats {
    fn observe_waiter_peak(&mut self, predicted_waiters: usize) {
        if predicted_waiters > self.waiter_peak {
            self.waiter_peak = predicted_waiters;
        }
    }

    fn observe_wake(&mut self, woke: usize) {
        self.wake_count = self.wake_count.saturating_add(woke as u64);
    }

    fn observe_timeout(&mut self) {
        self.timeout_count = self.timeout_count.saturating_add(1);
    }
}

impl WaitStatsBookkeeping<()> for ConsoleWaitStats {
    fn observe_waiter_peak(&mut self, _kind: (), predicted_waiters: usize) {
        self.observe_waiter_peak(predicted_waiters);
    }

    fn observe_wake(&mut self, _kind: (), woke: usize) {
        self.observe_wake(woke);
    }

    fn observe_timeout(&mut self, _kind: ()) {
        self.observe_timeout();
    }
}

pub struct ConsoleTty {
    state: Mutex<ConsoleState>,
    ready: Condvar,
    stats: Arc<Mutex<ConsoleWaitStats>>,
    timeout_observer: WaitTimeoutCleanupRef,
}

impl Default for ConsoleTty {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleState {
    fn push_cooked_byte(&mut self, byte: u8) {
        if self.cooked.len() == MAX_COOKED_BYTES {
            self.cooked.pop_front();
        }
        self.cooked.push_back(byte);
    }

    fn feed_char(&mut self, character: char) -> ConsoleFeedResult {
        let byte = character as u32 as u8;

        // ── ANSI escape sequence parsing ──
        match self.escape_state {
            EscapeState::SawEsc => {
                if character == '[' {
                    self.escape_state = EscapeState::SawCsi {
                        params: [0; 4],
                        param_len: 0,
                    };
                } else {
                    // Unknown escape — reset.
                    self.escape_state = EscapeState::None;
                }
                return ConsoleFeedResult::default();
            }
            EscapeState::SawCsi {
                mut params,
                param_len,
            } => {
                if character.is_ascii_digit() || character == ';' {
                    if (param_len as usize) < params.len() {
                        params[param_len as usize] = byte;
                        self.escape_state = EscapeState::SawCsi {
                            params,
                            param_len: param_len + 1,
                        };
                    }
                    return ConsoleFeedResult::default();
                }
                // Final byte of the CSI sequence.
                self.escape_state = EscapeState::None;
                return self.handle_csi_final(character, params, param_len);
            }
            EscapeState::None => {}
        }

        // ── Start of an escape sequence ──
        if character == '\x1b' {
            self.escape_state = EscapeState::SawEsc;
            return ConsoleFeedResult::default();
        }

        match character {
            '\x03' => {
                // Ctrl-C — invoke interrupt callback.
                if let Some(cb) = *INTERRUPT_CALLBACK.lock() {
                    cb();
                }
                crate::println!("^C");
                ConsoleFeedResult::default()
            }
            '\x1a' => {
                // Ctrl-Z — invoke stop callback.
                if let Some(cb) = *STOP_CALLBACK.lock() {
                    cb();
                }
                crate::println!("^Z");
                ConsoleFeedResult::default()
            }
            '\r' | '\n' => {
                // Commit current edit line into cooked queue as a full line.
                let bytes = self.edit_line.clone();
                let flushed = bytes.len() + 1;
                for byte in bytes {
                    self.push_cooked_byte(byte);
                }
                self.push_cooked_byte(b'\n');
                self.edit_line.clear();
                self.edit_echo_widths.clear();
                self.history_index = 0;
                let mut result = ConsoleFeedResult::with_echo(b"\r\n");
                result.cooked_bytes = flushed;
                result
            }
            '\u{0008}' | '\u{007f}' => {
                // Backspace/delete edits only the pending line, never cooked bytes.
                if self.edit_line.pop().is_some() {
                    let columns = self.edit_echo_widths.pop().unwrap_or(1) as usize;
                    ConsoleFeedResult::with_backspace_echo(columns)
                } else {
                    ConsoleFeedResult::default()
                }
            }
            '\t' => {
                // Invoke the completion callback if registered.
                if let Some(cb) = *COMPLETION_CALLBACK.lock() {
                    let line_str = core::str::from_utf8(&self.edit_line).unwrap_or("");
                    let prefix = match line_str.rfind(|c: char| c.is_whitespace()) {
                        Some(pos) => &line_str[pos + 1..],
                        None => line_str,
                    };
                    if let Some(completed) = cb(prefix, "") {
                        let prefix_end = match line_str.rfind(|c: char| c.is_whitespace()) {
                            Some(pos) => pos + 1,
                            None => 0,
                        };
                        let completion_bytes = completed.as_bytes();
                        self.edit_line.truncate(prefix_end);
                        self.edit_echo_widths.truncate(prefix_end);
                        for &b in completion_bytes {
                            if self.edit_line.len() < MAX_EDIT_LINE {
                                self.edit_line.push(b);
                                self.edit_echo_widths.push(1);
                            }
                        }
                        return self.redraw_line();
                    }
                    // Callback returned None — bell.
                    return ConsoleFeedResult::with_echo(b"\x07");
                }

                // No completion callback — fall back to inserting tab stops.
                if self.edit_line.len() < MAX_EDIT_LINE {
                    self.edit_line.push(b'\t');
                    self.edit_echo_widths.push(TAB_ECHO_COLUMNS as u8);
                    let mut result = ConsoleFeedResult::default();
                    result.echoed[..TAB_ECHO_COLUMNS].fill(b' ');
                    result.echoed_len = TAB_ECHO_COLUMNS;
                    result
                } else {
                    ConsoleFeedResult::default()
                }
            }
            character if character.is_ascii_graphic() || character == ' ' => {
                if self.edit_line.len() < MAX_EDIT_LINE {
                    self.edit_line.push(character as u8);
                    self.edit_echo_widths.push(1);
                    ConsoleFeedResult::with_echo(&[character as u8])
                } else {
                    ConsoleFeedResult::default()
                }
            }
            _ => ConsoleFeedResult::default(),
        }
    }

    fn try_pop_byte(&mut self) -> Option<u8> {
        self.cooked.pop_front()
    }

    fn try_pop_line(&mut self) -> Option<String> {
        if self.cooked.is_empty() {
            return None;
        }

        let mut line = String::new();
        while let Some(byte) = self.cooked.pop_front() {
            line.push(byte as char);
            if byte == b'\n' {
                return Some(line);
            }
        }

        None
    }

    /// Handle the final byte of a CSI sequence (`\x1b[...<final>`).
    fn handle_csi_final(
        &mut self,
        final_byte: char,
        _params: [u8; 4],
        _param_len: u8,
    ) -> ConsoleFeedResult {
        match final_byte {
            'A' => {
                // UP arrow — go back in history.
                self.history_navigate(-1)
            }
            'B' => {
                // DOWN arrow — go forward in history.
                self.history_navigate(1)
            }
            'C' | 'D' => {
                // RIGHT / LEFT arrow — silently consume for now.
                ConsoleFeedResult::default()
            }
            'H' | 'F' => {
                // Home / End — silently consume.
                ConsoleFeedResult::default()
            }
            '~' => {
                // Delete / Insert / PageUp / PageDown — silently consume.
                ConsoleFeedResult::default()
            }
            _ => ConsoleFeedResult::default(),
        }
    }

    /// Navigate through history: `direction` = -1 for back, 1 for forward.
    fn history_navigate(&mut self, direction: i32) -> ConsoleFeedResult {
        // Save the current line if this is the first history navigation.
        if self.history_index == 0 {
            let mut saved = SAVED_HISTORY_LINE.lock();
            *saved = Some(self.edit_line.clone());
        }

        let callback = HISTORY_CALLBACK.lock();
        let saved_line = SAVED_HISTORY_LINE.lock();
        let saved_str = saved_line
            .as_ref()
            .and_then(|v| core::str::from_utf8(v).ok());

        let replacement = callback.and_then(|cb| cb(direction, saved_str));

        if let Some(new_line) = replacement {
            self.history_index += direction;
            self.replace_edit_line(new_line.as_bytes())
        } else {
            // No more history entries — restore saved line when going
            // forward past the newest entry.
            if direction > 0 && self.history_index + direction >= 0 {
                if let Some(ref saved) = *saved_line {
                    self.history_index = 0;
                    let mut saved_clone = saved.clone();
                    core::mem::swap(&mut self.edit_line, &mut saved_clone);
                    return self.redraw_line();
                }
            }
            ConsoleFeedResult::default()
        }
    }

    /// Replace the current edit line and redraw.
    fn replace_edit_line(&mut self, new_bytes: &[u8]) -> ConsoleFeedResult {
        // Clear the displayed line.
        let old_len = self.edit_line.len();
        self.edit_line.clear();
        self.edit_echo_widths.clear();

        // Build the new line.
        for &b in new_bytes {
            if self.edit_line.len() < MAX_EDIT_LINE {
                self.edit_line.push(b);
                self.edit_echo_widths.push(1);
            }
        }

        // Erase old line: backspace through each character, then overwrite
        // with spaces, then backspace again.
        let mut result = ConsoleFeedResult::default();
        let clear_len = old_len.max(self.edit_line.len());
        let mut echo_idx = 0;

        // Erase old displayed characters.
        for _ in 0..clear_len {
            result.echoed[echo_idx] = b'\x08';
            echo_idx += 1;
            if echo_idx >= MAX_ECHO_BYTES {
                break;
            }
            result.echoed[echo_idx] = b' ';
            echo_idx += 1;
            if echo_idx >= MAX_ECHO_BYTES {
                break;
            }
            result.echoed[echo_idx] = b'\x08';
            echo_idx += 1;
            if echo_idx >= MAX_ECHO_BYTES {
                break;
            }
        }

        // Write new characters.
        for &b in new_bytes {
            if echo_idx < MAX_ECHO_BYTES {
                result.echoed[echo_idx] = b;
                echo_idx += 1;
            }
        }
        result.echoed_len = echo_idx;
        result
    }

    /// Redraw the current edit line in-place.
    fn redraw_line(&mut self) -> ConsoleFeedResult {
        self.replace_edit_line(&self.edit_line.clone())
    }
}

impl ConsoleTty {
    pub fn new() -> Self {
        let stats = Arc::new(Mutex::new(ConsoleWaitStats::default()));
        let timeout_observer = input_wait::timeout_observer(stats.clone(), ());

        Self {
            state: Mutex::new(ConsoleState::default()),
            ready: Condvar::new(),
            stats,
            timeout_observer,
        }
    }

    pub fn wait_stats(&self) -> ConsoleWaitStats {
        *self.stats.lock()
    }

    pub fn reset_wait_stats(&self) {
        *self.stats.lock() = ConsoleWaitStats::default();
    }

    pub fn pending_byte_count(&self) -> usize {
        self.state.lock().cooked.len()
    }

    pub fn waiter_count(&self) -> usize {
        self.ready.waiter_count()
    }

    pub fn try_read_byte(&self) -> Option<u8> {
        self.state.lock().try_pop_byte()
    }

    pub fn try_read_line(&self) -> Option<String> {
        self.state.lock().try_pop_line()
    }

    pub fn wait_for_input(&self) -> bool {
        input_wait::wait_until_ready(
            || !self.state.lock().cooked.is_empty(),
            || {
                let state = self.state.lock();
                if !state.cooked.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(&self.stats, self.ready.waiter_count(), ());
                self.ready.wait(state).blocked()
            },
        )
    }

    pub fn wait_for_input_timeout(&self, timeout_ticks: u64) -> bool {
        input_wait::wait_until_ready_timeout(
            timeout_ticks,
            || !self.state.lock().cooked.is_empty(),
            |remaining| {
                let state = self.state.lock();
                if !state.cooked.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(&self.stats, self.ready.waiter_count(), ());
                self.ready
                    .wait_timeout_observed(state, remaining, self.timeout_observer.clone())
                    .blocked()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(&self.stats, (), false);
            },
        )
    }

    pub fn read_byte(&self) -> Option<u8> {
        if !arch::supports_context_switch() {
            return input_wait::probe_then_wait_then_probe(
                || self.try_read_byte(),
                || {
                    let _ = self.wait_for_input();
                },
            );
        }

        if Scheduler::global().is_none() {
            return self.try_read_byte();
        }

        loop {
            if let Some(byte) = input_wait::probe_then_wait_then_probe(
                || self.try_read_byte(),
                || {
                    let state = self.state.lock();
                    if !state.cooked.is_empty() {
                        input_wait::mark_current_wait_completed();
                        return;
                    }

                    input_wait::record_wait_registration(
                        &self.stats,
                        self.ready.waiter_count(),
                        (),
                    );
                    let _ = self.ready.wait(state);
                },
            ) {
                return Some(byte);
            }
        }
    }

    pub fn read_byte_timeout(&self, timeout_ticks: u64) -> Option<u8> {
        if !arch::supports_context_switch() {
            return input_wait::probe_then_wait_then_probe(
                || self.try_read_byte(),
                || {
                    let _ = self.wait_for_input_timeout(timeout_ticks);
                },
            );
        }

        input_wait::probe_then_timed_wait_loop(
            timeout_ticks,
            || self.try_read_byte(),
            |remaining| {
                let state = self.state.lock();
                if !state.cooked.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(&self.stats, self.ready.waiter_count(), ());
                self.ready
                    .wait_timeout_observed(state, remaining, self.timeout_observer.clone())
                    .timed_out()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(&self.stats, (), None::<u8>);
            },
        )
    }

    pub fn read_bytes_timeout(&self, buffer: &mut [u8], timeout_ticks: u64) -> Option<usize> {
        if buffer.is_empty() {
            return Some(0);
        }

        let first = self.read_byte_timeout(timeout_ticks)?;
        buffer[0] = first;

        let mut count = 1;
        while count < buffer.len() {
            let Some(byte) = self.try_read_byte() else {
                break;
            };

            buffer[count] = byte;
            count += 1;
        }

        Some(count)
    }

    pub fn read_line_timeout(&self, timeout_ticks: u64) -> Option<String> {
        if !arch::supports_context_switch() {
            return input_wait::probe_then_wait_then_probe(
                || self.try_read_line(),
                || {
                    let _ = self.wait_for_input_timeout(timeout_ticks);
                },
            );
        }

        input_wait::probe_then_timed_wait_loop(
            timeout_ticks,
            || self.try_read_line(),
            |remaining| {
                let state = self.state.lock();
                if !state.cooked.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(&self.stats, self.ready.waiter_count(), ());
                self.ready
                    .wait_timeout_observed(state, remaining, self.timeout_observer.clone())
                    .timed_out()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(&self.stats, (), None::<String>);
            },
        )
    }

    pub fn write_bytes(&self, bytes: &[u8]) -> usize {
        if bytes.is_empty() {
            return 0;
        }

        debug::write_bytes(bytes);
        bytes.len()
    }

    pub fn feed_input_char(&self, character: char) -> usize {
        let feed = {
            let mut state = self.state.lock();
            state.feed_char(character)
        };

        if !feed.echoed_bytes().is_empty() {
            let _ = self.write_bytes(feed.echoed_bytes());
        }

        if feed.cooked_bytes == 0 {
            return 0;
        }

        let woke = self.ready.notify_all();
        input_wait::record_wake_count(&self.stats, (), woke);
        woke
    }

    pub fn clear(&self) {
        let mut state = self.state.lock();
        state.cooked.clear();
        state.edit_line.clear();
        state.edit_echo_widths.clear();
        state.escape_state = EscapeState::None;
        state.history_index = 0;
    }
}

pub fn init_global() -> Arc<ConsoleTty> {
    let mut slot = CONSOLE_TTY.lock();
    if let Some(console) = slot.as_ref() {
        return console.clone();
    }

    let console = Arc::new(ConsoleTty::new());
    *slot = Some(console.clone());
    console
}

/// Register a history provider callback for arrow-key history navigation.
///
/// `callback(direction, saved_line)` is called when the user presses UP
/// (direction = -1) or DOWN (direction = 1).  It should return the
/// replacement line, or `None` if there are no more entries in that
/// direction.
pub fn set_history_callback(callback: HistoryCallback) {
    *HISTORY_CALLBACK.lock() = Some(callback);
}

/// Register a tab-completion callback.
///
/// `callback(prefix, cwd)` receives the word prefix under the cursor and
/// the current working directory.  It should return the completed string
/// (replacing the prefix), or `None` if no completion is available.
pub fn set_completion_callback(callback: CompletionCallback) {
    *COMPLETION_CALLBACK.lock() = Some(callback);
}

/// Register a callback invoked on Ctrl-C (SIGINT).
pub fn set_interrupt_callback(callback: InterruptCallback) {
    *INTERRUPT_CALLBACK.lock() = Some(callback);
}

/// Register a callback invoked on Ctrl-Z (SIGTSTP).
pub fn set_stop_callback(callback: StopCallback) {
    *STOP_CALLBACK.lock() = Some(callback);
}

/// Set the foreground process PID, so Ctrl-C sends SIGINT to it.
pub fn set_foreground_pid(pid: u32) {
    *FOREGROUND_PID.lock() = Some(pid);
}

/// Clear the foreground process PID.
pub fn clear_foreground_pid() {
    *FOREGROUND_PID.lock() = None;
}

pub fn global() -> Option<Arc<ConsoleTty>> {
    CONSOLE_TTY.lock().clone()
}

pub fn handle_input_char(character: char) {
    if let Some(console) = global() {
        let _ = console.feed_input_char(character);
    }
}

/// Feed a raw byte (e.g. from a serial port) into the console TTY.
///
/// Only bytes that correspond to recognised console characters (printable
/// ASCII, whitespace, backspace, tab) are forwarded; all other byte values
/// are silently dropped.  This keeps the path safe to call from hardware
/// polling contexts such as the serial RX poll in the timer tick.
pub fn handle_input_byte(byte: u8) {
    // Forward bytes that the console line discipline knows how to
    // interpret — feed_char already silently ignores unrecognised chars.
    // \x1b (escape) is forwarded so the console can parse ANSI sequences
    // for arrow keys and other terminal control codes.
    if byte.is_ascii_graphic()
        || byte == b' '
        || byte == b'\r'
        || byte == b'\n'
        || byte == b'\t'
        || byte == 0x08
        || byte == 0x7f
        || byte == 0x1b
    {
        handle_input_char(byte as char);
    }
}

pub fn try_read_byte() -> Option<u8> {
    global().and_then(|console| console.try_read_byte())
}

pub fn read_byte_timeout(timeout_ticks: u64) -> Option<u8> {
    global().and_then(|console| console.read_byte_timeout(timeout_ticks))
}

pub fn read_line_timeout(timeout_ticks: u64) -> Option<String> {
    global().and_then(|console| console.read_line_timeout(timeout_ticks))
}

pub fn write_bytes(bytes: &[u8]) -> usize {
    init_global().write_bytes(bytes)
}
