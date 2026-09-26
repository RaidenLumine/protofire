//! src/drivers/pcspkr.rs
//!
//! PC speaker (PC beeper) driver, on the machines that have one.
//!
//! Hardware interface:
//! - PIT channel 2 at IO port 0x42, command port 0x43
//! - PC speaker gate at IO port 0x61 (bit 0 = PIT gate, bit 1 = speaker gate)
//!
//! The driver registers a `/system/dev/pcspkr` device node.  Ring-3 programs
//! write a 4-byte little-endian u32 frequency value; 0 stops the tone.
//!
//! The ports are PC hardware, so this file is compiled where they exist; a
//! machine without them answers under the same module name from
//! `pcspkr_absent.rs`.

use alloc::sync::Arc;

use crate::Result;

use super::Driver;
use super::DriverCategory;

// ── IO port constants ──────────────────────────────────────────────────────

/// PIT command register (mode/command).
const PIT_COMMAND: u16 = 0x43;
/// PIT channel 2 data port.
const PIT_CHANNEL2: u16 = 0x42;
/// PIT base frequency (1.193182 MHz).
const PIT_BASE_FREQUENCY: u32 = 1_193_182;
/// PC speaker / PIT channel 2 gate control port.
const SPEAKER_PORT: u16 = 0x61;
/// PIT command: channel 2, mode 3 (square wave generator), LSB then MSB.
const PIT_CMD_CHANNEL2_MODE3: u8 = 0xB6;

// ── Driver struct ──────────────────────────────────────────────────────────

struct PcspkrDriver;

impl Driver for PcspkrDriver {
    fn name(&self) -> &'static str {
        "pcspkr"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Audio
    }

    fn init(&self) -> Result<()> {
        // Ensure the speaker is off at boot.
        stop_inner();
        crate::println!("[driver] pcspkr initialized");
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(PcspkrDriver)
}

// ── Hardware control ───────────────────────────────────────────────────────

/// Play a tone at the given frequency (in Hz) using PIT channel 2.
///
/// Passing 0 is equivalent to calling [`stop`].
pub fn play_tone(freq_hz: u32) {
    if freq_hz == 0 {
        stop_inner();
        return;
    }

    // The PIT divisor must be in [1, 65535].
    let divisor = (PIT_BASE_FREQUENCY / freq_hz).clamp(1, 65535) as u16;

    // SAFETY: these are standard motherboard IO ports; writing well-known
    // command sequences is safe at any time.
    unsafe {
        let mut command = crate::arch::x86_64::port::Port::<u8>::new(PIT_COMMAND);
        command.write(PIT_CMD_CHANNEL2_MODE3);

        let mut channel2 = crate::arch::x86_64::port::Port::<u8>::new(PIT_CHANNEL2);
        channel2.write((divisor & 0xFF) as u8);
        channel2.write((divisor >> 8) as u8);

        // Enable the speaker gate (bit 1) and the PIT channel 2 gate (bit 0).
        let mut speaker = crate::arch::x86_64::port::Port::<u8>::new(SPEAKER_PORT);
        let value = speaker.read();
        speaker.write(value | 0x03);
    }
}

/// Disable the PC speaker tone by clearing the speaker gate bits.
pub fn stop() {
    stop_inner();
}

fn stop_inner() {
    // SAFETY: port 0x61 is the standard PS/2 controller + speaker port;
    // clearing bits 0 and 1 is always safe.
    unsafe {
        let mut speaker = crate::arch::x86_64::port::Port::<u8>::new(SPEAKER_PORT);
        let value = speaker.read();
        speaker.write(value & !0x03);
    }
}

// ── Device node handlers ───────────────────────────────────────────────────

/// Device-node read handler for `/system/dev/pcspkr`.
///
/// Reading from the PC speaker is not supported.
pub fn device_read(_buffer: &mut [u8], _timeout_ticks: u64) -> Result<usize> {
    Err(crate::Error::Unsupported)
}

/// Device-node write handler for `/system/dev/pcspkr`.
///
/// Expects exactly 4 bytes encoding a little-endian `u32` frequency in Hz.
/// A value of 0 stops the tone.
pub fn device_write(buffer: &[u8]) -> Result<usize> {
    if buffer.len() < 4 {
        return Err(crate::Error::InvalidArgument);
    }

    let freq = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    play_tone(freq);
    Ok(4)
}
