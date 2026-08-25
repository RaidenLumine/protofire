//! src/arch/x86_64/timer.rs
//!
//! x86_64 PIT timer initialization and tick accounting.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

static TICKS: AtomicU64 = AtomicU64::new(0);

const PIT_COMMAND: u16 = 0x43;
const PIT_CHANNEL0: u16 = 0x40;
const PIT_BASE_FREQUENCY: u32 = 1_193_182;
const PIT_TICK_HZ: u32 = 100;

pub fn init() {
    let divisor = (PIT_BASE_FREQUENCY / PIT_TICK_HZ) as u16;
    let mut command = super::port::Port::<u8>::new(PIT_COMMAND);
    let mut channel0 = super::port::Port::<u8>::new(PIT_CHANNEL0);

    unsafe {
        command.write(0x36);
        channel0.write((divisor & 0x00FF) as u8);
        channel0.write((divisor >> 8) as u8);
    }
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Busy-wait for at least `n` PIT ticks (1 tick ≈ 10 ms at 100 Hz).
pub fn wait_ticks(n: u64) {
    let start = ticks();
    loop {
        if ticks().wrapping_sub(start) >= n {
            break;
        }
        core::hint::spin_loop();
    }
}

pub(crate) fn acknowledge_tick() -> u64 {
    TICKS.fetch_add(1, Ordering::Relaxed) + 1
}
