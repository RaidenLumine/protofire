//! src/kernel/drivers/mouse.rs
//!
//! Boot-protocol mouse input core.
//!
//! The kernel has no pointer/display-cursor subsystem yet, so the mouse
//! core exposes a bounded stream of relative-motion reports that device
//! nodes (and, later, a GUI) can consume.  A USB HID boot-protocol mouse
//! injects into this core the same way the USB HID keyboard injects
//! scancodes into the PS/2 keyboard core.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use crate::kernel::sync::Condvar;
use crate::kernel::sync::Mutex;

/// Number of bytes in a serialised boot-protocol mouse motion report.
pub const MOUSE_REPORT_LEN: usize = 4;

/// Maximum number of buffered motion reports before the oldest is dropped.
const MAX_BUFFERED_MOTIONS: usize = 16;

/// A boot-protocol mouse motion report: buttons, X/Y deltas, wheel.
///
/// Deltas are relative and signed; `0` means "no movement".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MouseMotion {
    /// Button bitfield (bit 0 = left, bit 1 = right, bit 2 = middle).
    pub buttons: u8,
    /// Horizontal delta (positive = right).
    pub dx: i8,
    /// Vertical delta (positive = down in screen coordinates).
    pub dy: i8,
    /// Wheel delta (positive = scroll up).
    pub wheel: i8,
}

impl MouseMotion {
    pub const fn new(buttons: u8, dx: i8, dy: i8, wheel: i8) -> Self {
        Self {
            buttons,
            dx,
            dy,
            wheel,
        }
    }

    /// Serialise as the boot-protocol byte stream (buttons, dx, dy, wheel).
    pub const fn to_bytes(self) -> [u8; MOUSE_REPORT_LEN] {
        [self.buttons, self.dx as u8, self.dy as u8, self.wheel as u8]
    }
}

// ============================================================================
// Mouse core
// ============================================================================

/// The canonical mouse input source: a bounded motion-report queue.
pub struct MouseCore {
    motions: Mutex<VecDeque<MouseMotion>>,
    motion_ready: Condvar,
}

impl Default for MouseCore {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseCore {
    pub fn new() -> Self {
        Self {
            motions: Mutex::new(VecDeque::new()),
            motion_ready: Condvar::new(),
        }
    }

    /// Drop any buffered motion so host tests start from a known-empty state.
    pub fn clear(&self) {
        self.motions.lock().clear();
    }

    /// Number of buffered motion reports.
    pub fn pending_count(&self) -> usize {
        self.motions.lock().len()
    }

    /// Buffer one relative-motion report (bounded, dropping the oldest).
    pub fn inject_motion(&self, buttons: u8, dx: i8, dy: i8, wheel: i8) {
        {
            let mut motions = self.motions.lock();
            if motions.len() >= MAX_BUFFERED_MOTIONS {
                motions.pop_front();
            }
            motions.push_back(MouseMotion::new(buttons, dx, dy, wheel));
        }
        self.motion_ready.notify_one();
    }

    /// Read one buffered motion report without blocking.
    pub fn try_read_motion(&self) -> Option<MouseMotion> {
        self.motions.lock().pop_front()
    }

    /// Read one motion report, blocking up to `timeout_ticks`.
    pub fn read_motion_timeout(&self, timeout_ticks: u64) -> Option<MouseMotion> {
        if !crate::arch::supports_context_switch() {
            return crate::kernel::sync::input_wait::probe_then_wait_then_probe(
                || self.try_read_motion(),
                || {
                    let _ = self.wait_for_motion_timeout(timeout_ticks);
                },
            );
        }

        crate::kernel::sync::input_wait::probe_then_timed_wait_loop(
            timeout_ticks,
            || self.try_read_motion(),
            |remaining| {
                let motions = self.motions.lock();
                if !motions.is_empty() {
                    crate::kernel::sync::input_wait::mark_current_wait_completed();
                    return false;
                }
                self.motion_ready
                    .wait_timeout(motions, remaining)
                    .timed_out()
            },
            || {},
        )
    }

    fn wait_for_motion_timeout(&self, timeout_ticks: u64) -> bool {
        let motions = self.motions.lock();
        if !motions.is_empty() {
            return false;
        }
        self.motion_ready
            .wait_timeout(motions, timeout_ticks)
            .timed_out()
    }
}

// ============================================================================
// Global mouse core
// ============================================================================

static MOUSE_CORE: Mutex<Option<Arc<MouseCore>>> = Mutex::new(None);

/// Return the global mouse core, creating it on first use.
pub fn init_global() -> Arc<MouseCore> {
    let mut slot = MOUSE_CORE.lock();
    if let Some(ref core) = *slot {
        return core.clone();
    }
    let core = Arc::new(MouseCore::new());
    *slot = Some(core.clone());
    core
}

/// Clear the global mouse core (host tests).
pub fn clear_global() {
    init_global().clear();
}

/// Inject a relative-motion report into the global mouse core.
pub fn inject_motion(buttons: u8, dx: i8, dy: i8, wheel: i8) {
    init_global().inject_motion(buttons, dx, dy, wheel);
}

/// Read one buffered motion report without blocking.
pub fn try_read_motion() -> Option<MouseMotion> {
    init_global().try_read_motion()
}

/// Read one motion report, blocking up to `timeout_ticks`.
pub fn read_motion_timeout(timeout_ticks: u64) -> Option<MouseMotion> {
    init_global().read_motion_timeout(timeout_ticks)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motion_round_trips_through_bytes() {
        let motion = MouseMotion::new(0x01, -3, 7, 1);
        assert_eq!(motion.to_bytes(), [0x01, 0xFD, 0x07, 0x01]);
        assert_eq!(
            MouseMotion::new(0x00, 0, 0, 0).to_bytes(),
            [0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn inject_then_read_returns_fifo() {
        let core = MouseCore::new();
        core.inject_motion(0x01, 1, 0, 0);
        core.inject_motion(0x00, -1, 2, 0);
        assert_eq!(
            core.try_read_motion(),
            Some(MouseMotion::new(0x01, 1, 0, 0))
        );
        assert_eq!(
            core.try_read_motion(),
            Some(MouseMotion::new(0x00, -1, 2, 0))
        );
        assert_eq!(core.try_read_motion(), None);
    }

    #[test]
    fn read_drops_oldest_when_full() {
        let core = MouseCore::new();
        for i in 0..(MAX_BUFFERED_MOTIONS + 4) {
            core.inject_motion(0, i as i8, 0, 0);
        }
        // The oldest four reports were dropped, so the first remaining is 4.
        assert_eq!(core.try_read_motion(), Some(MouseMotion::new(0, 4, 0, 0)));
        assert_eq!(core.pending_count(), MAX_BUFFERED_MOTIONS - 1);
    }

    #[test]
    fn clear_resets_pending() {
        let core = MouseCore::new();
        core.inject_motion(0x02, 5, 5, 0);
        core.clear();
        assert_eq!(core.pending_count(), 0);
        assert_eq!(core.try_read_motion(), None);
    }
}
