//! src/arch/x86_64/serial.rs
//!
//! x86_64 COM1 serial backend used by early logging.

use core::fmt::Write;
use core::fmt::{self};

use crate::kernel::sync::SpinLock;

use super::port::Port;

const COM1: u16 = 0x3F8;

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

        while !self.can_transmit() {}

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
