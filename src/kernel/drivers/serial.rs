//! src/kernel/drivers/serial.rs
//! Serial device wrapper that turns the architecture UART backend into a kernel device.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch;
use crate::kernel::console;
use crate::kernel::sync::{
    input_wait::{self, WaitStatsBookkeeping},
    Condvar, Mutex, WaitTimeoutCleanupRef,
};
use crate::Result;

use super::{Driver, DriverCategory};

const MAX_BUFFERED_RX_BYTES: usize = 512;
const MAX_CAPTURED_TX_BYTES: usize = 4096;

static SERIAL_DEVICE: Mutex<Option<Arc<SerialDevice>>> = Mutex::new(None);

struct SerialDriver;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SerialWaitStats {
    pub waiter_peak: usize,
    pub wake_count: u64,
    pub timeout_count: u64,
}

impl SerialWaitStats {
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

impl WaitStatsBookkeeping<()> for SerialWaitStats {
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

pub struct SerialDevice {
    rx: Mutex<VecDeque<u8>>,
    rx_ready: Condvar,
    tx_capture: Mutex<VecDeque<u8>>,
    stats: Arc<Mutex<SerialWaitStats>>,
    timeout_observer: WaitTimeoutCleanupRef,
}

impl Default for SerialDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialDevice {
    pub fn new() -> Self {
        let stats = Arc::new(Mutex::new(SerialWaitStats::default()));
        let timeout_observer = input_wait::timeout_observer(stats.clone(), ());

        Self {
            rx: Mutex::new(VecDeque::new()),
            rx_ready: Condvar::new(),
            tx_capture: Mutex::new(VecDeque::new()),
            stats,
            timeout_observer,
        }
    }

    pub fn clear(&self) {
        self.rx.lock().clear();
        self.tx_capture.lock().clear();
    }

    pub fn captured_tx_bytes(&self) -> Vec<u8> {
        self.tx_capture.lock().iter().copied().collect()
    }

    pub fn wait_stats(&self) -> SerialWaitStats {
        *self.stats.lock()
    }

    pub fn reset_wait_stats(&self) {
        *self.stats.lock() = SerialWaitStats::default();
    }

    pub fn waiter_count(&self) -> usize {
        self.rx_ready.waiter_count()
    }

    pub fn inject_rx_bytes(&self, bytes: &[u8]) -> usize {
        if bytes.is_empty() {
            return 0;
        }

        {
            let mut rx = self.rx.lock();
            for &byte in bytes {
                push_bounded(&mut rx, MAX_BUFFERED_RX_BYTES, byte);
            }
        }

        let woke = self.rx_ready.notify_all();
        input_wait::record_wake_count(&self.stats, (), woke);
        woke
    }

    pub fn try_read_byte(&self) -> Option<u8> {
        if let Some(byte) = self.rx.lock().pop_front() {
            input_wait::mark_current_wait_completed();
            return Some(byte);
        }

        let _ = self.poll_hardware_rx();
        if let Some(byte) = self.rx.lock().pop_front() {
            input_wait::mark_current_wait_completed();
            return Some(byte);
        }

        None
    }

    pub fn read_byte_timeout(&self, timeout_ticks: u64) -> Option<u8> {
        if !arch::supports_context_switch() {
            return input_wait::probe_then_wait_then_probe(
                || self.try_read_byte(),
                || {
                    let _ = self.wait_for_rx_timeout(timeout_ticks);
                },
            );
        }

        input_wait::probe_then_timed_wait_loop(
            timeout_ticks,
            || self.try_read_byte(),
            |remaining| {
                let _ = self.poll_hardware_rx();
                let rx = self.rx.lock();
                if !rx.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(&self.stats, self.rx_ready.waiter_count(), ());
                self.rx_ready
                    .wait_timeout_observed(rx, remaining, self.timeout_observer.clone())
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

    pub fn write_bytes(&self, bytes: &[u8]) -> usize {
        if bytes.is_empty() {
            return 0;
        }

        {
            let mut tx_capture = self.tx_capture.lock();
            for &byte in bytes {
                push_bounded(&mut tx_capture, MAX_CAPTURED_TX_BYTES, byte);
            }
        }

        // Keep the capture queue lock out of the hardware write path so test
        // observability does not serialise unrelated UART polling/spins.
        for &byte in bytes {
            arch::serial::write_byte(byte);
        }

        bytes.len()
    }

    pub fn poll_hardware_rx(&self) -> usize {
        let mut received = 0;
        // Collect console-bound bytes outside the rx lock so we can feed the
        // console TTY without holding a serial-internal mutex, avoiding a
        // potential deadlock with the keyboard → console → serial path.
        let mut console_bytes = Vec::with_capacity(16);
        {
            let mut rx = self.rx.lock();
            while let Some(byte) = arch::serial::try_read_byte() {
                push_bounded(&mut rx, MAX_BUFFERED_RX_BYTES, byte);
                received += 1;
                console_bytes.push(byte);
            }
        }

        // Bridge serial input to the console TTY so that the Ring 3 shell
        // (which reads from fd 0 → /system/dev/console) can receive keystrokes
        // when there is no PS/2 keyboard hardware, e.g. QEMU with -display none
        // and -serial stdio.
        for &byte in &console_bytes {
            console::handle_input_byte(byte);
        }

        if received != 0 {
            let woke = self.rx_ready.notify_all();
            input_wait::record_wake_count(&self.stats, (), woke);
        }

        received
    }

    fn wait_for_rx_timeout(&self, timeout_ticks: u64) -> bool {
        input_wait::wait_until_ready_timeout(
            timeout_ticks,
            || {
                let _ = self.poll_hardware_rx();
                !self.rx.lock().is_empty()
            },
            |remaining| {
                let _ = self.poll_hardware_rx();
                let rx = self.rx.lock();
                if !rx.is_empty() {
                    input_wait::mark_current_wait_completed();
                    return false;
                }

                input_wait::record_wait_registration(&self.stats, self.rx_ready.waiter_count(), ());
                self.rx_ready
                    .wait_timeout_observed(rx, remaining, self.timeout_observer.clone())
                    .blocked()
            },
            || {
                let _ = input_wait::finish_unobserved_timeout(&self.stats, (), false);
            },
        )
    }
}

impl Driver for SerialDriver {
    fn name(&self) -> &'static str {
        "serial"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Console
    }

    fn init(&self) -> Result<()> {
        arch::serial::init();
        let _ = init_device();
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(SerialDriver)
}

pub fn init_device() -> Arc<SerialDevice> {
    let mut slot = SERIAL_DEVICE.lock();
    if let Some(device) = slot.as_ref() {
        return device.clone();
    }

    let device = Arc::new(SerialDevice::new());
    *slot = Some(device.clone());
    device
}

pub fn global_device() -> Option<Arc<SerialDevice>> {
    SERIAL_DEVICE.lock().clone()
}

pub fn poll_hardware_rx() -> usize {
    global_device()
        .map(|device| device.poll_hardware_rx())
        .unwrap_or(0)
}

pub fn inject_rx_bytes(bytes: &[u8]) -> usize {
    init_device().inject_rx_bytes(bytes)
}

pub fn write_bytes(bytes: &[u8]) -> usize {
    init_device().write_bytes(bytes)
}

pub fn try_read_byte() -> Option<u8> {
    init_device().try_read_byte()
}

pub fn read_byte_timeout(timeout_ticks: u64) -> Option<u8> {
    init_device().read_byte_timeout(timeout_ticks)
}

pub fn read_bytes_timeout(buffer: &mut [u8], timeout_ticks: u64) -> Option<usize> {
    init_device().read_bytes_timeout(buffer, timeout_ticks)
}

fn push_bounded(queue: &mut VecDeque<u8>, max_len: usize, byte: u8) {
    if queue.len() >= max_len {
        queue.pop_front();
    }
    queue.push_back(byte);
}

#[cfg(test)]
mod tests {
    use super::{SerialDevice, MAX_BUFFERED_RX_BYTES};
    use crate::kernel::process::{Scheduler, ThreadWaitOutcome};
    use alloc::vec::Vec;
    use std::sync::{Mutex, OnceLock};

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn serial_rx_burst_drops_oldest_bytes() {
        let _guard = test_lock();
        let serial = SerialDevice::new();
        serial.clear();

        let burst: Vec<u8> = (0..=MAX_BUFFERED_RX_BYTES)
            .map(|index| index as u8)
            .collect();
        assert_eq!(serial.inject_rx_bytes(&burst), 0);

        let mut buffer = [0_u8; MAX_BUFFERED_RX_BYTES];
        assert_eq!(
            serial.read_bytes_timeout(&mut buffer, 0),
            Some(MAX_BUFFERED_RX_BYTES)
        );
        assert_eq!(buffer.as_slice(), &burst[1..]);
        assert_eq!(serial.try_read_byte(), None);
    }

    #[test]
    fn serial_wait_stats_track_waiter_peak_and_wake_count() {
        let _guard = test_lock();
        let serial = SerialDevice::new();
        serial.clear();
        serial.reset_wait_stats();

        let scheduler = Scheduler::new();
        let first = scheduler.spawn_named("serial-reader-a", 0x1000);
        let second = scheduler.spawn_named("serial-reader-b", 0x2000);
        let third = scheduler.spawn_named("serial-producer", 0x3000);

        unsafe {
            scheduler.install_global_unchecked();
        }
        scheduler.schedule();
        assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
        assert!(serial.wait_for_rx_timeout(5));

        assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
        assert!(serial.wait_for_rx_timeout(5));
        assert_eq!(serial.wait_stats().waiter_peak, 2);

        assert_eq!(scheduler.current_thread_id(), Some(third.tid()));
        assert_eq!(serial.inject_rx_bytes(b"xy"), 2);

        let stats = serial.wait_stats();
        assert_eq!(stats.waiter_peak, 2);
        assert_eq!(stats.wake_count, 2);
        assert_eq!(stats.timeout_count, 0);
    }

    #[test]
    fn serial_wait_stats_track_timeout_counts_and_zero_timeout_probe() {
        let _guard = test_lock();
        let serial = SerialDevice::new();
        serial.clear();
        serial.reset_wait_stats();

        let scheduler = Scheduler::new();
        let first = scheduler.spawn_named("serial-reader", 0x1000);
        let _second = scheduler.spawn_named("serial-worker", 0x2000);

        unsafe {
            scheduler.install_global_unchecked();
        }
        scheduler.schedule();
        assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

        assert_eq!(serial.read_byte_timeout(0), None);
        assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
        assert_eq!(serial.wait_stats().timeout_count, 1);
        assert_eq!(serial.wait_stats().waiter_peak, 0);

        assert!(serial.wait_for_rx_timeout(3));
        assert_eq!(
            serial.wait_stats().timeout_count,
            1,
            "observed timeout should only count when the timer callback fires"
        );
        scheduler.handle_timer_tick(3);

        let stats = serial.wait_stats();
        assert_eq!(stats.waiter_peak, 1);
        assert_eq!(stats.timeout_count, 2);
        assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
        assert_eq!(serial.waiter_count(), 0);
    }

    #[test]
    fn serial_immediate_timeout_read_consumes_buffered_rx_without_wait_registration() {
        let _guard = test_lock();
        let serial = SerialDevice::new();
        serial.clear();
        serial.reset_wait_stats();

        let scheduler = Scheduler::new();
        let first = scheduler.spawn_named("serial-reader", 0x1000);

        unsafe {
            scheduler.install_global_unchecked();
        }
        scheduler.schedule();
        assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

        assert_eq!(serial.inject_rx_bytes(b"rx"), 0);

        let mut buffer = [0_u8; 4];
        assert_eq!(serial.read_bytes_timeout(&mut buffer, 5), Some(2));
        assert_eq!(&buffer[..2], b"rx");
        assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
        assert_eq!(serial.waiter_count(), 0);

        let stats = serial.wait_stats();
        assert_eq!(stats.waiter_peak, 0);
        assert_eq!(stats.wake_count, 0);
        assert_eq!(stats.timeout_count, 0);
    }
}
