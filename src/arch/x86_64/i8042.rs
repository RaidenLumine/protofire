//! src/arch/x86_64/i8042.rs
//!
//! PS/2 (8042) keyboard-controller programming.
//!
//! Enables the keyboard interface and its IRQ1 so legacy PS/2 keystrokes
//! (the QEMU default on q35, and the source that HMP `sendkey` and the
//! GTK/VGA window drive) reach `interrupts::handle_irq`.  A SeaBIOS
//! multiboot payload does not guarantee the controller left the keyboard
//! interrupt armed, so the kernel must enable it itself.

use super::port::Port;

const STATUS_PORT: u16 = 0x64;
const DATA_PORT: u16 = 0x60;

/// 8042 status-register bits.
const STATUS_OUTPUT_FULL: u8 = 0x01;
const STATUS_INPUT_FULL: u8 = 0x02;

/// 8042 commands (written to the status/command port).
const CMD_READ_CMD_BYTE: u8 = 0x20;
const CMD_WRITE_CMD_BYTE: u8 = 0x60;
const CMD_DISABLE_KEYBOARD: u8 = 0xAD;
const CMD_ENABLE_KEYBOARD: u8 = 0xAE;

/// Keyboard (not controller) commands, written to the data port.  These are
/// forwarded to the PS/2 keyboard itself.
const KBD_CMD_ENABLE_SCANNING: u8 = 0xF4;

/// Controller command-byte bits.
const CFG_KEYBOARD_IRQ: u8 = 1 << 0; // Raise IRQ1 when keyboard data is ready.
const CFG_DISABLE_MOUSE: u8 = 1 << 4;
const CFG_DISABLE_KEYBOARD: u8 = 1 << 5;
const CFG_TRANSLATE: u8 = 1 << 6; // Translate scancode set 2 → set 1.

/// Bound on controller busy-wait loops, so a missing/broken controller
/// cannot hang early boot indefinitely.
const MAX_POLL: u32 = 0x1_0000;

/// Wait until the controller input buffer is empty (a command can be sent).
fn wait_input_empty() {
    let mut status = Port::<u8>::new(STATUS_PORT);
    for _ in 0..MAX_POLL {
        // Safety: reading the 8042 status register is always safe on x86.
        let st = unsafe { status.read() };
        if st & STATUS_INPUT_FULL == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Wait until the controller output buffer holds a byte (data can be read).
fn wait_output_full() {
    let mut status = Port::<u8>::new(STATUS_PORT);
    for _ in 0..MAX_POLL {
        // Safety: reading the 8042 status register is always safe on x86.
        let st = unsafe { status.read() };
        if st & STATUS_OUTPUT_FULL != 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Enable the keyboard interface, its IRQ1, and the keyboard's own scanning.
///
/// Called once interrupt routing (IOAPIC IRQ1 → vector 33) is finalised so
/// the controller only starts raising IRQ1 once the kernel is ready to
/// service it.  Idempotent in effect.
///
/// The 8042 command byte gets the keyboard-IRQ (bit 0) and translate
/// (bit 6, scancode set 2 → set 1) bits, and both interfaces stay enabled.
/// Finally the keyboard itself is told to enable scanning (0xF4); until it
/// receives that it does not report key presses to the controller, so
/// without it the IRQ1 line stays silent for real keystrokes and `sendkey`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn init() {
    let mut status = Port::<u8>::new(STATUS_PORT);
    let mut data = Port::<u8>::new(DATA_PORT);

    // Disable the keyboard interface first so the keyboard cannot push a
    // scancode into the output buffer while we read the command byte.
    // Safety: writing a controller command to the command port.
    unsafe { status.write(CMD_DISABLE_KEYBOARD) };
    wait_input_empty();

    // Drop any scancodes that accumulated while the interface was idle so
    // the input path starts clean.
    loop {
        // Safety: reading the 8042 status register is always safe on x86.
        let st = unsafe { status.read() };
        if st & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        // Safety: reading the data port when the output buffer is full is the
        // prescribed way to clear a scancode.
        let _ = unsafe { data.read() };
    }

    // Read the current command byte, then set keyboard IRQ + translation on
    // while keeping the keyboard (and mouse) interfaces enabled.
    // Safety: 0x20 asks the controller to put its command byte in the data
    // port output buffer.
    unsafe { status.write(CMD_READ_CMD_BYTE) };
    wait_output_full();
    // Safety: reading the data port once the output buffer is full returns
    // the requested command byte.
    let current = unsafe { data.read() };

    // Safety: 0x60 tells the controller the next data-port byte is the new
    // command byte.
    unsafe { status.write(CMD_WRITE_CMD_BYTE) };
    wait_input_empty();
    let next =
        (current | CFG_KEYBOARD_IRQ | CFG_TRANSLATE) & !(CFG_DISABLE_KEYBOARD | CFG_DISABLE_MOUSE);
    // Safety: writing the command byte to the data port as instructed.
    unsafe { data.write(next) };
    wait_input_empty();

    // Re-enable the keyboard interface so it can assert IRQ1.
    // Safety: writing the enable-keyboard command to the command port.
    unsafe { status.write(CMD_ENABLE_KEYBOARD) };
    wait_input_empty();

    // Put the keyboard into scanning mode.  0xF4 is a *keyboard* command, so
    // it is written to the data port (the controller forwards it).  The
    // keyboard acknowledges with 0xFA on the output buffer.
    // Safety: writing a keyboard command to the data port.
    unsafe { data.write(KBD_CMD_ENABLE_SCANNING) };
    wait_output_full();
    // Safety: reading the data port when the output buffer is full drains the
    // keyboard's ACK byte.
    let _ack = unsafe { data.read() };
    wait_input_empty();
}

/// Host / non-bare-metal builds: nothing to program.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn init() {}
