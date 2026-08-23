//! src/kernel/drivers/pcspkr.rs
//! PC speaker driver using PIT channel 2.
//!
//! Hardware interface (x86_64 only):
//! - PIT channel 2 at IO port 0x42, command port 0x43
//! - PC speaker gate at IO port 0x61 (bit 0 = PIT gate, bit 1 = speaker gate)
//!
//! The driver registers a `/system/dev/pcspkr` device node.  Ring-3 programs
//! write a 4-byte little-endian u32 frequency value; 0 stops the tone.
//!
//! On non-x86 targets the device node still appears but returns
//! [`Error::Unsupported`] on any write.

use alloc::sync::Arc;

use crate::Result;

use super::{Driver, DriverCategory};

// ── IO port constants (x86_64 only) ────────────────────────────────────────

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
/// PIT command register (mode/command).
const PIT_COMMAND: u16 = 0x43;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
/// PIT channel 2 data port.
const PIT_CHANNEL2: u16 = 0x42;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
/// PIT base frequency (1.193182 MHz).
const PIT_BASE_FREQUENCY: u32 = 1_193_182;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
/// PC speaker / PIT channel 2 gate control port.
const SPEAKER_PORT: u16 = 0x61;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
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
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            // Ensure the speaker is off at boot.
            stop_inner();
            crate::println!("[driver] pcspkr initialized");
        }
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(PcspkrDriver)
}

// ── Hardware control (x86_64 only) ──────────────────────────────────────────

/// Play a tone at the given frequency (in Hz) using PIT channel 2.
///
/// On non-x86 targets this is a no-op.
/// Passing 0 is equivalent to calling [`stop`].
pub fn play_tone(freq_hz: u32) {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
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

    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    let _ = freq_hz;
}

/// Disable the PC speaker tone by clearing the speaker gate bits.
///
/// On non-x86 targets this is a no-op.
pub fn stop() {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    stop_inner();
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
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
///
/// On non-x86 targets this always returns [`Error::Unsupported`].
pub fn device_write(buffer: &[u8]) -> Result<usize> {
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        let _ = buffer;
        Err(crate::Error::Unsupported)
    }

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        if buffer.len() < 4 {
            return Err(crate::Error::InvalidArgument);
        }

        let freq = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        play_tone(freq);
        Ok(4)
    }
}
