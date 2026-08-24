//! src/util/logger.rs
//!
//! Structured logging and panic output helpers.

use core::alloc::Layout;
use core::panic::PanicInfo;

use crate::println;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO ",
            Self::Warn => "WARN ",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }
}

pub fn log(level: LogLevel, message: &str) {
    println!("[{}] {}", level.as_str(), message);
}

pub fn panic(info: &PanicInfo<'_>) -> ! {
    println!("[FATAL] kernel panic");

    if let Some(location) = info.location() {
        println!(
            "[FATAL] at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }

    println!("[FATAL] {}", info.message());

    crate::arch::interrupts::disable();
    loop {
        crate::arch::instructions::hlt();
    }
}

pub fn alloc_error(layout: Layout) -> ! {
    println!(
        "[FATAL] allocation failed: size={}, align={}",
        layout.size(),
        layout.align()
    );

    crate::arch::interrupts::disable();
    loop {
        crate::arch::instructions::hlt();
    }
}
