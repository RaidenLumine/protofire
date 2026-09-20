//! src/arch/x86_64/serial.rs
//!
//! x86_64 COM1 serial backend used by early logging.

use core::fmt::Write;
use core::fmt::{self};

use crate::kernel::sync::SpinLock;

use super::port::Port;

const COM1: u16 = 0x3F8;

/// Bytes dropped because the transmitter never reported ready.
///
/// Counted rather than printed at the point of failure: this runs inside the
/// console write path, so printing here would recurse.  A caller above the
/// UART reads it and announces it once — see
/// `util::debug::report_transmit_timeouts`.  Without that, a transmitter that
/// times out is invisible: the symptom is a log that stops, which is
/// indistinguishable from the CPU having stopped for an unrelated reason.
static TRANSMIT_TIMEOUTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Return how many bytes the console has dropped.
pub fn transmit_timeout_count() -> u64 {
    TRANSMIT_TIMEOUTS.load(core::sync::atomic::Ordering::Relaxed)
}

/// How long to wait for the UART's transmitter to report ready.
///
/// The wait is bounded on purpose.  This is the kernel's only diagnostic
/// channel, and it runs on whatever CPU happens to be printing — including the
/// BSP in the middle of bringing up an AP, with the other APs printing too.
/// An unbounded wait here means a transmitter that never reports ready stops
/// that CPU for good, and the log simply ends with no explanation: the last
/// line is the one printed *before* the stuck write, so a stalled console
/// looks exactly like a stall in the code between two prints.
///
/// Dropping the byte keeps the kernel running so the failure can be reported.
/// The bound is generous — a working UART clears the bit within a few spins, so
/// reaching it means something is wrong rather than merely slow.
const TRANSMIT_READY_SPIN_LIMIT: u32 = 1_000_000;

pub struct SerialPort {
    data: Port<u8>,
    interrupt_enable: Port<u8>,
    fifo_control: Port<u8>,
    line_control: Port<u8>,
    modem_control: Port<u8>,
    line_status: Port<u8>,
    initialized: bool,
}

impl SerialPort {
    pub const fn new(base: u16) -> Self {
        Self {
            data: Port::new(base),
            interrupt_enable: Port::new(base + 1),
            fifo_control: Port::new(base + 2),
            line_control: Port::new(base + 3),
            modem_control: Port::new(base + 4),
            line_status: Port::new(base + 5),
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        unsafe {
            self.interrupt_enable.write(0x00);
            self.line_control.write(0x80);
            self.data.write(0x03);
            self.interrupt_enable.write(0x00);
            self.line_control.write(0x03);
            self.fifo_control.write(0xC7);
            self.modem_control.write(0x0B);
        }

        self.initialized = true;
    }

    fn can_transmit(&mut self) -> bool {
        unsafe { self.line_status.read() & 0x20 != 0 }
    }

    fn can_receive(&mut self) -> bool {
        unsafe { self.line_status.read() & 0x01 != 0 }
    }

    fn write_byte(&mut self, byte: u8) {
        if !self.initialized {
            self.init();
        }

        let mut spins: u32 = 0;
        while !self.can_transmit() {
            spins += 1;
            if spins >= TRANSMIT_READY_SPIN_LIMIT {
                // Give up on this byte rather than the machine.  See the note
                // on `TRANSMIT_READY_SPIN_LIMIT`.
                TRANSMIT_TIMEOUTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return;
            }
            core::hint::spin_loop();
        }

        unsafe {
            self.data.write(byte);
        }
    }

    fn try_read_byte(&mut self) -> Option<u8> {
        if !self.initialized {
            self.init();
        }

        if !self.can_receive() {
            return None;
        }

        Some(unsafe { self.data.read() })
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, message: &str) -> fmt::Result {
        for byte in message.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }

            self.write_byte(byte);
        }

        Ok(())
    }
}

static SERIAL1: SpinLock<SerialPort> = SpinLock::new(SerialPort::new(COM1));

pub fn init() {
    SERIAL1.lock().init();
}

pub fn write_str(message: &str) {
    let _ = SERIAL1.lock().write_str(message);
}

pub fn write_byte(byte: u8) {
    SERIAL1.lock().write_byte(byte);
}

pub fn try_read_byte() -> Option<u8> {
    SERIAL1.lock().try_read_byte()
}

pub fn write_fmt(args: fmt::Arguments<'_>) -> fmt::Result {
    let mut serial = SERIAL1.lock();
    serial.write_fmt(args)
}
