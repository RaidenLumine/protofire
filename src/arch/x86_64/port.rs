//! src/arch/x86_64/port.rs
//! x86_64 I/O port access helpers.

use core::arch::asm;
use core::marker::PhantomData;

pub trait PortValue: Copy {
    /// # Safety
    ///
    /// The caller must ensure that reading from `port` is valid for the
    /// current platform and will not violate device or CPU requirements.
    unsafe fn read(port: u16) -> Self;

    /// # Safety
    ///
    /// The caller must ensure that writing `value` to `port` is valid for the
    /// current platform and will not violate device or CPU requirements.
    unsafe fn write(port: u16, value: Self);
}

pub struct Port<T> {
    port: u16,
    _marker: PhantomData<T>,
}

impl<T> Port<T> {
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _marker: PhantomData,
        }
    }
}

impl<T: PortValue> Port<T> {
    /// # Safety
    ///
    /// The caller must ensure the wrapped port can be read as `T`.
    pub unsafe fn read(&mut self) -> T {
        T::read(self.port)
    }

    /// # Safety
    ///
    /// The caller must ensure the wrapped port can be written as `T`.
    pub unsafe fn write(&mut self, value: T) {
        T::write(self.port, value);
    }
}

impl PortValue for u8 {
    unsafe fn read(port: u16) -> Self {
        let value: u8;
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }

    unsafe fn write(port: u16, value: Self) {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

impl PortValue for u16 {
    unsafe fn read(port: u16) -> Self {
        let value: u16;
        asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }

    unsafe fn write(port: u16, value: Self) {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags));
    }
}

impl PortValue for u32 {
    unsafe fn read(port: u16) -> Self {
        let value: u32;
        asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }

    unsafe fn write(port: u16, value: Self) {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }
}
