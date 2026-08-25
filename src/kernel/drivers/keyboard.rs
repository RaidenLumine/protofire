//! src/kernel/drivers/keyboard.rs
//!
//! PS/2 keyboard input driver.
//! Keyboard driver: PS/2 scancode buffering/decoding, USB-HID injection,
//! and input wait semantics.
//!
//! The PS/2 IRQ handler feeds raw scancodes via [`handle_scancode`]; the
//! USB-HID driver feeds PS/2 set-1 codes via [`inject_scancode`].  Both
//! paths buffer the raw byte, decode it into a character (when printable),
//! and bridge that character to the console TTY so the Ring 3 shell can
//! receive keystrokes from fd 0 → /system/dev/console.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch;
use crate::kernel::console;
use crate::kernel::sync::input_wait::WaitStatsBookkeeping;
use crate::kernel::sync::input_wait::{self};
use crate::kernel::sync::Condvar;
use crate::kernel::sync::Mutex;
use crate::kernel::sync::WaitTimeoutCleanupRef;
use crate::Result;

use super::Driver;
use super::DriverCategory;

const MAX_BUFFERED_SCANCODES: usize = 64;
const MAX_BUFFERED_EVENTS: usize = 256;
const MAX_BUFFERED_CHARS: usize = 256;

/// Global keyboard core, created lazily by `init_device()` (called from the
/// driver's `init`).  Never removed once installed.
static KEYBOARD_CORE: Mutex<Option<Arc<KeyboardCore>>> = Mutex::new(None);

// ─── PS/2 scancode set 1 decode tables ─────────────────────────────────
//
// `SCANCODE_BASE[i]` is the unshifted character for make code `i`;
// `SCANCODE_SHIFT[i]` is the shifted character.  `0` means "no printable
// character" (modifier, function key, or unmapped).

const SCANCODE_BASE: [u8; 0x3B] = [
    0, // 0x00
    0, // 0x01 Esc
    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', // 0x02-0x0B
    b'-', b'=', 0x08, 0x09, // 0x0C-0x0F  '-', '=', Backspace, Tab
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', // 0x10-0x19
    b'[', b']', b'\n', 0, // 0x1A-0x1D  '[', ']', Enter, LCtrl
    b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', // 0x1E-0x26
    b';', b'\'', b'`', 0, // 0x27-0x2A  ';', '\'', '`', LShift
    b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm', // 0x2B-0x32
    b',', b'.', b'/', 0, b'*', 0, // 0x33-0x38  ',', '.', '/', RShift, numpad *, LAlt
    b' ', 0, // 0x39-0x3A  Space, CapsLock
];

const SCANCODE_SHIFT: [u8; 0x3B] = [
    0, // 0x00
    0, // 0x01 Esc
    b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', // 0x02-0x0B
    b'_', b'+', 0x08, 0x09, // 0x0C-0x0F
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', // 0x10-0x19
    b'{', b'}', b'\n', 0, // 0x1A-0x1D
    b'A', b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L', // 0x1E-0x26
    b':', b'"', b'~', 0, // 0x27-0x2A
    b'|', b'Z', b'X', b'C', b'V', b'B', b'N', b'M', // 0x2B-0x32
    b'<', b'>', b'?', 0, b'*', 0, // 0x33-0x38
    b' ', 0, // 0x39-0x3A
];

/// Set-1 make codes for modifier keys.
const MOD_LEFT_SHIFT: u8 = 0x2A;
const MOD_RIGHT_SHIFT: u8 = 0x36;
const MOD_LEFT_CTRL: u8 = 0x1D;
const MOD_LEFT_ALT: u8 = 0x38;
const MOD_CAPS_LOCK: u8 = 0x3A;
/// Set-1 break prefix (break code = make | 0x80).
const BREAK_BIT: u8 = 0x80;
/// Extended (two-byte) scancode prefix.
const EXTENDED_PREFIX: u8 = 0xE0;

// ─── Key event types ───────────────────────────────────────────────────

/// A key identity from PS/2 scancode set 1 (plus the E0-extended keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    Esc,
    D1,
    D2,
    D3,
    D4,
    D5,
    D6,
    D7,
    D8,
    D9,
    D0,
    Minus,
    Equals,
    Backspace,
    Tab,
    Q,
    W,
    E,
    R,
    T,
    Y,
    U,
    I,
    O,
    P,
    LBracket,
    RBracket,
    Enter,
    LeftCtrl,
    A,
    S,
    D,
    F,
    G,
    H,
    J,
    K,
    L,
    Semicolon,
    Apostrophe,
    Backtick,
    LeftShift,
    Backslash,
    Z,
    X,
    C,
    V,
    B,
    N,
    M,
    Comma,
    Period,
    Slash,
    RightShift,
    NumpadMultiply,
    LeftAlt,
    Space,
    CapsLock,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    /// Any make code without a named mapping.
    Other(u8),
}

/// Modifier state captured on a key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyModifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub caps_lock: bool,
}

/// A decoded key press or release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub code: KeyCode,
    pub pressed: bool,
    pub character: Option<char>,
    pub modifiers: KeyModifiers,
}

// ─── Wait stats ────────────────────────────────────────────────────────

/// Which input queue a wait/stats observation applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitKind {
    Scancode,
    Event,
    Char,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyboardWaitStats {
    pub scancode_waiter_peak: usize,
    pub event_waiter_peak: usize,
    pub char_waiter_peak: usize,
    pub scancode_wake_count: u64,
    pub event_wake_count: u64,
    pub char_wake_count: u64,
    pub scancode_timeout_count: u64,
    pub event_timeout_count: u64,
    pub char_timeout_count: u64,
}

impl WaitStatsBookkeeping<WaitKind> for KeyboardWaitStats {
    fn observe_waiter_peak(&mut self, kind: WaitKind, predicted_waiters: usize) {
        match kind {
            WaitKind::Scancode => {
                self.scancode_waiter_peak = self.scancode_waiter_peak.max(predicted_waiters)
            }
            WaitKind::Event => {
                self.event_waiter_peak = self.event_waiter_peak.max(predicted_waiters)
            }
            WaitKind::Char => self.char_waiter_peak = self.char_waiter_peak.max(predicted_waiters),
        }
    }

    fn observe_wake(&mut self, kind: WaitKind, woke: usize) {
        let woke = woke as u64;
        match kind {
            WaitKind::Scancode => {
                self.scancode_wake_count = self.scancode_wake_count.saturating_add(woke)
            }
            WaitKind::Event => self.event_wake_count = self.event_wake_count.saturating_add(woke),
            WaitKind::Char => self.char_wake_count = self.char_wake_count.saturating_add(woke),
        }
    }

    fn observe_timeout(&mut self, kind: WaitKind) {
        match kind {
            WaitKind::Scancode => {
                self.scancode_timeout_count = self.scancode_timeout_count.saturating_add(1)
            }
            WaitKind::Event => {
                self.event_timeout_count = self.event_timeout_count.saturating_add(1)
            }
            WaitKind::Char => self.char_timeout_count = self.char_timeout_count.saturating_add(1),
        }
    }
}

// ─── Decode state ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default)]
struct DecodeState {
    shift: bool,
    ctrl: bool,
    alt: bool,
    caps: bool,
    /// Set while consuming an E0-prefixed (extended) scancode sequence.
    e0_pending: bool,
}

// ─── Scancode → KeyCode mapping ────────────────────────────────────────

/// Map a PS/2 set-1 make code (break bit stripped) to a [`KeyCode`].
fn keycode_for(code: u8) -> KeyCode {
    match code {
        0x01 => KeyCode::Esc,
        0x02 => KeyCode::D1,
        0x03 => KeyCode::D2,
        0x04 => KeyCode::D3,
        0x05 => KeyCode::D4,
        0x06 => KeyCode::D5,
        0x07 => KeyCode::D6,
        0x08 => KeyCode::D7,
        0x09 => KeyCode::D8,
        0x0A => KeyCode::D9,
        0x0B => KeyCode::D0,
        0x0C => KeyCode::Minus,
        0x0D => KeyCode::Equals,
        0x0E => KeyCode::Backspace,
        0x0F => KeyCode::Tab,
        0x10 => KeyCode::Q,
        0x11 => KeyCode::W,
        0x12 => KeyCode::E,
        0x13 => KeyCode::R,
        0x14 => KeyCode::T,
        0x15 => KeyCode::Y,
        0x16 => KeyCode::U,
        0x17 => KeyCode::I,
        0x18 => KeyCode::O,
        0x19 => KeyCode::P,
        0x1A => KeyCode::LBracket,
        0x1B => KeyCode::RBracket,
        0x1C => KeyCode::Enter,
        0x1D => KeyCode::LeftCtrl,
        0x1E => KeyCode::A,
        0x1F => KeyCode::S,
        0x20 => KeyCode::D,
        0x21 => KeyCode::F,
        0x22 => KeyCode::G,
        0x23 => KeyCode::H,
        0x24 => KeyCode::J,
        0x25 => KeyCode::K,
        0x26 => KeyCode::L,
        0x27 => KeyCode::Semicolon,
        0x28 => KeyCode::Apostrophe,
        0x29 => KeyCode::Backtick,
        0x2A => KeyCode::LeftShift,
        0x2B => KeyCode::Backslash,
        0x2C => KeyCode::Z,
        0x2D => KeyCode::X,
        0x2E => KeyCode::C,
        0x2F => KeyCode::V,
        0x30 => KeyCode::B,
        0x31 => KeyCode::N,
        0x32 => KeyCode::M,
        0x33 => KeyCode::Comma,
        0x34 => KeyCode::Period,
        0x35 => KeyCode::Slash,
        0x36 => KeyCode::RightShift,
        0x37 => KeyCode::NumpadMultiply,
        0x38 => KeyCode::LeftAlt,
        0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock,
        0x3B => KeyCode::F1,
        0x3C => KeyCode::F2,
        0x3D => KeyCode::F3,
        0x3E => KeyCode::F4,
        0x3F => KeyCode::F5,
        0x40 => KeyCode::F6,
        0x41 => KeyCode::F7,
        0x42 => KeyCode::F8,
        0x43 => KeyCode::F9,
        0x44 => KeyCode::F10,
        0x57 => KeyCode::F11,
        0x58 => KeyCode::F12,
        other => KeyCode::Other(other),
    }
}

/// Map an E0-prefixed (extended) scancode — make or break — to a [`KeyCode`].
/// Returns `None` for unhandled extended codes (e.g. E0 Ctrl/Alt), which still
/// get buffered as raw scancodes but produce no key event.
fn keycode_for_extended(code: u8) -> Option<KeyCode> {
    let base = code & !BREAK_BIT;
    Some(match base {
        0x48 => KeyCode::ArrowUp,
        0x50 => KeyCode::ArrowDown,
        0x4B => KeyCode::ArrowLeft,
        0x4D => KeyCode::ArrowRight,
        0x47 => KeyCode::Home,
        0x4F => KeyCode::End,
        0x49 => KeyCode::PageUp,
        0x51 => KeyCode::PageDown,
        0x52 => KeyCode::Insert,
        0x53 => KeyCode::Delete,
        _ => return None,
    })
}

fn modifiers_from(decode: &DecodeState) -> KeyModifiers {
    KeyModifiers {
        shift: decode.shift,
        ctrl: decode.ctrl,
        alt: decode.alt,
        caps_lock: decode.caps,
    }
}

// ─── Keyboard core ─────────────────────────────────────────────────────

pub struct KeyboardCore {
    /// Raw PS/2 set-1 scancodes (for the keyboard-raw device).
    scancodes: Mutex<VecDeque<u8>>,
    /// Decoded key events (one per meaningful make/break), for the keyboard
    /// event device.
    events: Mutex<VecDeque<KeyEvent>>,
    /// Decoded ASCII characters (for the keyboard device).
    chars: Mutex<VecDeque<char>>,
    /// Keyboard decoder state (modifier keys, extended-scancode tracking).
    decode: Mutex<DecodeState>,
    scancode_ready: Condvar,
    event_ready: Condvar,
    char_ready: Condvar,
    stats: Arc<Mutex<KeyboardWaitStats>>,
    scancode_timeout_observer: WaitTimeoutCleanupRef,
    event_timeout_observer: WaitTimeoutCleanupRef,
    char_timeout_observer: WaitTimeoutCleanupRef,
}

impl Default for KeyboardCore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyboardCore {
    pub fn new() -> Self {
        let stats = Arc::new(Mutex::new(KeyboardWaitStats::default()));
        Self {
            scancodes: Mutex::new(VecDeque::new()),
            events: Mutex::new(VecDeque::new()),
            chars: Mutex::new(VecDeque::new()),
            decode: Mutex::new(DecodeState::default()),
            scancode_ready: Condvar::new(),
            event_ready: Condvar::new(),
            char_ready: Condvar::new(),
            scancode_timeout_observer: input_wait::timeout_observer(
                stats.clone(),
                WaitKind::Scancode,
            ),
            event_timeout_observer: input_wait::timeout_observer(stats.clone(), WaitKind::Event),
            char_timeout_observer: input_wait::timeout_observer(stats.clone(), WaitKind::Char),
            stats,
        }
    }

    /// Drop any buffered input and reset the decoder, so host tests start
    /// from a known-empty keyboard state (mirrors `serial::clear`).
    pub fn clear(&self) {
        self.scancodes.lock().clear();
        self.events.lock().clear();
        self.chars.lock().clear();
        *self.decode.lock() = DecodeState::default();
    }

    pub fn wait_stats(&self) -> KeyboardWaitStats {
        *self.stats.lock()
    }

    pub fn reset_wait_stats(&self) {
        *self.stats.lock() = KeyboardWaitStats::default();
    }

    /// Number of threads waiting on the raw-scancode queue.
    pub fn waiter_count(&self) -> usize {
        self.scancode_ready.waiter_count()
    }

    /// Number of threads waiting on the decoded-event queue.
    pub fn event_waiter_count(&self) -> usize {
        self.event_ready.waiter_count()
    }

    /// Number of threads waiting on the decoded-character queue.
    pub fn char_waiter_count(&self) -> usize {
        self.char_ready.waiter_count()
    }

    /// Raw scancodes currently buffered.
    pub fn pending_count(&self) -> usize {
        self.scancodes.lock().len()
    }

    pub fn pending_scancode_count(&self) -> usize {
        self.scancodes.lock().len()
    }

    pub fn pending_event_count(&self) -> usize {
        self.events.lock().len()
    }

    pub fn pending_char_count(&self) -> usize {
        self.chars.lock().len()
    }

    /// Feed one raw PS/2 set-1 scancode from hardware (PS/2 IRQ or USB-HID).
    ///
    /// Every scancode is buffered raw; each meaningful make/break is
    /// additionally decoded into a [`KeyEvent`] (and a character, when
    /// printable).  All three queues (raw, event, character) wake their
    /// waiters.
    pub fn feed_scancode(&self, scancode: u8) {
        // Always buffer the raw scancode (bounded, dropping the oldest).
        {
            let mut scancodes = self.scancodes.lock();
            if scancodes.len() >= MAX_BUFFERED_SCANCODES {
                scancodes.pop_front();
            }
            scancodes.push_back(scancode);
        }

        let mut produced = Vec::with_capacity(4);
        let mut event: Option<KeyEvent> = None;

        {
            let mut decode = self.decode.lock();

            if decode.e0_pending {
                // Consume an E0-prefixed (extended) sequence.
                decode.e0_pending = false;
                if let Some(code) = keycode_for_extended(scancode) {
                    event = Some(KeyEvent {
                        code,
                        pressed: scancode & BREAK_BIT == 0,
                        character: None,
                        modifiers: modifiers_from(&decode),
                    });
                }
            } else if scancode == EXTENDED_PREFIX {
                decode.e0_pending = true;
            } else if scancode & BREAK_BIT != 0 {
                // Break codes release modifiers, then emit a press-release event
                // with the already-updated modifier state.
                let code = scancode & !BREAK_BIT;
                match code {
                    MOD_LEFT_SHIFT | MOD_RIGHT_SHIFT => decode.shift = false,
                    MOD_LEFT_CTRL => decode.ctrl = false,
                    MOD_LEFT_ALT => decode.alt = false,
                    MOD_CAPS_LOCK => {}
                    _ => {}
                }
                event = Some(KeyEvent {
                    code: keycode_for(code),
                    pressed: false,
                    character: None,
                    modifiers: modifiers_from(&decode),
                });
            } else {
                // Make codes toggle modifiers first, then emit the event.
                match scancode {
                    MOD_LEFT_SHIFT | MOD_RIGHT_SHIFT => decode.shift = true,
                    MOD_CAPS_LOCK => decode.caps = !decode.caps,
                    MOD_LEFT_CTRL => decode.ctrl = true,
                    MOD_LEFT_ALT => decode.alt = true,
                    _ => {}
                }
                let character = {
                    let shifted = decode.shift ^ decode.caps;
                    let table = if shifted {
                        &SCANCODE_SHIFT
                    } else {
                        &SCANCODE_BASE
                    };
                    match table.get(scancode as usize) {
                        Some(&0) | None => None,
                        Some(&code) => {
                            let ch = code as char;
                            {
                                let mut chars = self.chars.lock();
                                if chars.len() < MAX_BUFFERED_CHARS {
                                    chars.push_back(ch);
                                }
                            }
                            produced.push(ch as u8);
                            Some(ch)
                        }
                    }
                };
                event = Some(KeyEvent {
                    code: keycode_for(scancode),
                    pressed: true,
                    character,
                    modifiers: modifiers_from(&decode),
                });
            }
        }

        if let Some(event) = event {
            let mut events = self.events.lock();
            if events.len() < MAX_BUFFERED_EVENTS {
                events.push_back(event);
            }
        }

        // Bridge decoded characters to the console TTY (Ring 3 shell stdin).
        for &byte in &produced {
            console::handle_input_byte(byte);
        }

        // Wake all three input queues; record per-queue wake counts.
        let scancode_woke = self.scancode_ready.notify_all();
        input_wait::record_wake_count(&self.stats, WaitKind::Scancode, scancode_woke);
        let event_woke = self.event_ready.notify_all();
        input_wait::record_wake_count(&self.stats, WaitKind::Event, event_woke);
        let char_woke = self.char_ready.notify_all();
        input_wait::record_wake_count(&self.stats, WaitKind::Char, char_woke);
    }

    pub fn try_read_char(&self) -> Option<char> {
        if let Some(ch) = self.chars.lock().pop_front() {
            input_wait::mark_current_wait_completed();
            return Some(ch);
        }
        None
    }

    pub fn try_read_scancode(&self) -> Option<u8> {
        if let Some(sc) = self.scancodes.lock().pop_front() {
            input_wait::mark_current_wait_completed();
            return Some(sc);
        }
        None
    }

    pub fn try_read_event(&self) -> Option<KeyEvent> {
        if let Some(event) = self.events.lock().pop_front() {
            input_wait::mark_current_wait_completed();
            return Some(event);
        }
        None
    }

    pub fn read_char_timeout(&self, timeout_ticks: u64) -> Option<char> {
        if !arch::supports_context_switch() {
            return input_wait::probe_then_wait_then_probe(
                || self.try_read_char(),
                || {
                    let _ = self.wait_for_char_timeout(timeout_ticks);
                },
            );
        }

        input_wait::probe_then_timed_wait_loop(
            timeout_ticks,
            || self.try_read_char(),
            |remaining| {
                let chars = self.chars.lock();
                if !chars.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(
                    &self.stats,
                    self.char_ready.waiter_count(),
                    WaitKind::Char,
                );
                self.char_ready
                    .wait_timeout_observed(chars, remaining, self.char_timeout_observer.clone())
                    .timed_out()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(
                    &self.stats,
                    WaitKind::Char,
                    None::<char>,
                );
            },
        )
    }

    pub fn read_scancode_timeout(&self, timeout_ticks: u64) -> Option<u8> {
        if !arch::supports_context_switch() {
            return input_wait::probe_then_wait_then_probe(
                || self.try_read_scancode(),
                || {
                    let _ = self.wait_for_scancode_timeout(timeout_ticks);
                },
            );
        }

        input_wait::probe_then_timed_wait_loop(
            timeout_ticks,
            || self.try_read_scancode(),
            |remaining| {
                let scancodes = self.scancodes.lock();
                if !scancodes.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(
                    &self.stats,
                    self.scancode_ready.waiter_count(),
                    WaitKind::Scancode,
                );
                self.scancode_ready
                    .wait_timeout_observed(
                        scancodes,
                        remaining,
                        self.scancode_timeout_observer.clone(),
                    )
                    .timed_out()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(
                    &self.stats,
                    WaitKind::Scancode,
                    None::<u8>,
                );
            },
        )
    }

    pub fn read_event_timeout(&self, timeout_ticks: u64) -> Option<KeyEvent> {
        if !arch::supports_context_switch() {
            return input_wait::probe_then_wait_then_probe(
                || self.try_read_event(),
                || {
                    let _ = self.wait_for_event_timeout(timeout_ticks);
                },
            );
        }

        input_wait::probe_then_timed_wait_loop(
            timeout_ticks,
            || self.try_read_event(),
            |remaining| {
                let events = self.events.lock();
                if !events.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(
                    &self.stats,
                    self.event_ready.waiter_count(),
                    WaitKind::Event,
                );
                self.event_ready
                    .wait_timeout_observed(events, remaining, self.event_timeout_observer.clone())
                    .timed_out()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(
                    &self.stats,
                    WaitKind::Event,
                    None::<KeyEvent>,
                );
            },
        )
    }

    /// Wait until a character is available or `timeout_ticks` elapse.  Returns
    /// `true` when a real deadline wait was armed (whether it ended by wake or
    /// timeout); `false` for zero-timeout / no-scheduler / already-ready.
    pub fn wait_for_char_timeout(&self, timeout_ticks: u64) -> bool {
        input_wait::wait_until_ready_timeout(
            timeout_ticks,
            || !self.chars.lock().is_empty(),
            |remaining| {
                let chars = self.chars.lock();
                if !chars.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(
                    &self.stats,
                    self.char_ready.waiter_count(),
                    WaitKind::Char,
                );
                self.char_ready
                    .wait_timeout_observed(chars, remaining, self.char_timeout_observer.clone())
                    .blocked()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(&self.stats, WaitKind::Char, false);
            },
        )
    }

    /// Wait until a raw scancode is available or `timeout_ticks` elapse.
    /// Return semantics match [`Self::wait_for_char_timeout`].
    pub fn wait_for_scancode_timeout(&self, timeout_ticks: u64) -> bool {
        input_wait::wait_until_ready_timeout(
            timeout_ticks,
            || !self.scancodes.lock().is_empty(),
            |remaining| {
                let scancodes = self.scancodes.lock();
                if !scancodes.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(
                    &self.stats,
                    self.scancode_ready.waiter_count(),
                    WaitKind::Scancode,
                );
                self.scancode_ready
                    .wait_timeout_observed(
                        scancodes,
                        remaining,
                        self.scancode_timeout_observer.clone(),
                    )
                    .blocked()
            },
            || {
                let _ =
                    input_wait::finish_unobserved_timeout(&self.stats, WaitKind::Scancode, false);
            },
        )
    }

    /// Wait until a decoded key event is available or `timeout_ticks` elapse.
    /// Return semantics match [`Self::wait_for_char_timeout`].
    pub fn wait_for_event_timeout(&self, timeout_ticks: u64) -> bool {
        input_wait::wait_until_ready_timeout(
            timeout_ticks,
            || !self.events.lock().is_empty(),
            |remaining| {
                let events = self.events.lock();
                if !events.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(
                    &self.stats,
                    self.event_ready.waiter_count(),
                    WaitKind::Event,
                );
                self.event_ready
                    .wait_timeout_observed(events, remaining, self.event_timeout_observer.clone())
                    .blocked()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(&self.stats, WaitKind::Event, false);
            },
        )
    }
}

// ─── Driver ─────────────────────────────────────────────────────────────

struct KeyboardDriver;

impl Driver for KeyboardDriver {
    fn name(&self) -> &'static str {
        "keyboard"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Input
    }

    fn init(&self) -> Result<()> {
        let _ = init_device();
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(KeyboardDriver)
}

pub fn init_device() -> Arc<KeyboardCore> {
    let mut slot = KEYBOARD_CORE.lock();
    if let Some(core) = slot.as_ref() {
        return core.clone();
    }

    let core = Arc::new(KeyboardCore::new());
    *slot = Some(core.clone());
    core
}

fn core() -> Arc<KeyboardCore> {
    init_device()
}

// ─── Public API used by the PS/2 IRQ handler, USB-HID, and device layer ─

/// Feed a raw scancode from the PS/2 keyboard IRQ handler.
pub fn handle_scancode(scancode: u8) {
    core().feed_scancode(scancode);
}

/// Feed a PS/2 set-1 scancode from the USB-HID keyboard driver.
pub fn inject_scancode(scancode: u8) {
    core().feed_scancode(scancode);
}

pub fn try_read_char() -> Option<char> {
    core().try_read_char()
}

pub fn read_char_timeout(timeout_ticks: u64) -> Option<char> {
    core().read_char_timeout(timeout_ticks)
}

pub fn try_read_scancode() -> Option<u8> {
    core().try_read_scancode()
}

pub fn read_scancode_timeout(timeout_ticks: u64) -> Option<u8> {
    core().read_scancode_timeout(timeout_ticks)
}

pub fn try_read_event() -> Option<KeyEvent> {
    core().try_read_event()
}

pub fn read_event_timeout(timeout_ticks: u64) -> Option<KeyEvent> {
    core().read_event_timeout(timeout_ticks)
}
