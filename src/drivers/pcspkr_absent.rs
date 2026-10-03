//! src/drivers/pcspkr_absent.rs
//!
//! The PC speaker on a machine that has no PC speaker.
//!
//! The device node still exists — a `/system/dev` entry that is missing would
//! be a lie about the machine — and every operation on it reports that the
//! hardware is not there, which is what a write's error return is for.

use alloc::sync::Arc;

use crate::Result;

use crate::drivers::Driver;
use crate::drivers::DriverCategory;

struct PcspkrDriver;

impl Driver for PcspkrDriver {
    fn name(&self) -> &'static str {
        "pcspkr"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Audio
    }

    fn init(&self) -> Result<()> {
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(PcspkrDriver)
}

/// Nothing to play a tone on.
pub fn play_tone(_freq_hz: u32) {}

/// Nothing is sounding.
pub fn stop() {}

/// Reading a speaker that is not there is not supported.
pub fn device_read(_buffer: &mut [u8], _timeout_ticks: u64) -> Result<usize> {
    Err(crate::Error::Unsupported)
}

/// Writing to a speaker that is not there is not supported.
pub fn device_write(_buffer: &[u8]) -> Result<usize> {
    Err(crate::Error::Unsupported)
}
