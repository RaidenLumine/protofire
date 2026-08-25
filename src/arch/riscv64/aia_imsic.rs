//! src/arch/riscv64/aia_imsic.rs
//!
//! RISC-V AIA IMSIC implementation for MSI/MSI-X support

#![allow(dead_code)] // experimental driver: wired for compilation, no consumer yet

use alloc::format;
use alloc::vec::Vec;

use super::read_volatile;
use super::write_volatile;
use crate::kernel::sync::SpinLock;
use crate::util::logger::log;
use crate::util::logger::LogLevel;
use crate::Error;

// AIA IMSIC constants
const AIA_IMSIC_BASE: usize = 0x2000000;
const AIA_IMSIC_SIZE: usize = 0x100000;
const AIA_IMSIC_CONTEXT_SIZE: usize = 0x8000;
const IMSIC_SEI: u64 = 1 << 63; // Supervisor External Interrupt Enable
const IMSIC_UEI: u64 = 1 << 62; // User External Interrupt Enable
const IMSIC_SGEI: u64 = 1 << 61; // Supervisor Guest External Interrupt Enable
const IMSIC_UGEI: u64 = 1 << 60; // User Guest External Interrupt Enable
const IMSIC_VSEI: u64 = 1 << 59; // Virtual Supervisor External Interrupt Enable
const IMSIC_VUEI: u64 = 1 << 58; // Virtual User External Interrupt Enable
const IMSIC_EIE: u64 = 1 << 63; // External Interrupt Enable
const IMSIC_VSIE: u64 = 1 << 62; // Virtual Supervisor Interrupt Enable

// MSI-X table entry structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MsiXEntry {
    msg_addr: u64,
    msg_data: u32,
    vector_control: u32,
}

pub struct AiaImsicController {
    base: usize,
    context_id: u32,
    msi_enabled: bool,
    msix_enabled: bool,
    msix_table: Option<Vec<MsiXEntry>>,
}

impl AiaImsicController {
    pub fn new(base: usize, context_id: u32) -> Self {
        Self {
            base,
            context_id,
            msi_enabled: false,
            msix_enabled: false,
            msix_table: None,
        }
    }

    fn read(&self, offset: u32) -> u64 {
        unsafe { read_volatile((self.base + offset as usize) as *mut u64) }
    }

    fn write(&self, offset: u32, value: u64) {
        unsafe { write_volatile((self.base + offset as usize) as *mut u64, value) }
    }

    /// Enable external interrupts in the IMSIC
    fn enable_external_interrupts(&self) {
        let sei_reg = self.read(0);
        self.write(0, sei_reg | IMSIC_SEI);
        log(LogLevel::Info, "AIA IMSIC: External interrupts enabled");
    }

    /// Disable external interrupts in the IMSIC
    fn disable_external_interrupts(&self) {
        let sei_reg = self.read(0);
        self.write(0, sei_reg & !IMSIC_SEI);
        log(LogLevel::Info, "AIA IMSIC: External interrupts disabled");
    }

    /// Configure MSI for a device
    pub fn configure_msi(&mut self, device_id: u32, vector: u32, data: u32) -> Result<u32, Error> {
        // Validate parameters
        if device_id >= 32 {
            return Err(Error::InvalidArgument);
        }
        if vector >= 32 {
            return Err(Error::InvalidArgument);
        }
        if data > 0xffff {
            return Err(Error::InvalidArgument);
        }

        let irq = device_id * 32 + vector;
        if irq >= 1024 {
            return Err(Error::InvalidArgument);
        }

        // Enable the interrupt in the IMSIC
        let reg_offset = (irq / 64) * 8;
        let bit = 1 << (irq % 64);
        let current = self.read(reg_offset);
        self.write(reg_offset, current | bit);

        self.msi_enabled = true;
        log(
            LogLevel::Info,
            &format!(
                "AIA IMSIC: MSI configured for device={}, vector={}, irq={}",
                device_id, vector, irq
            ),
        );

        Ok(irq)
    }

    /// Configure MSI-X for a device
    pub fn configure_msix(
        &mut self,
        device_id: u32,
        vector_count: u32,
        msi_addr: u64,
        msi_data: u64,
    ) -> Result<(u32, u32), Error> {
        // Validate parameters
        if device_id >= 32 {
            return Err(Error::InvalidArgument);
        }
        if vector_count == 0 || vector_count > 32 {
            return Err(Error::InvalidArgument);
        }
        if (msi_addr & 0xfffffffc) != msi_addr {
            return Err(Error::InvalidArgument);
        }
        if msi_data > 0xffffffff {
            return Err(Error::InvalidArgument);
        }

        let base_vector = device_id * 32;
        if base_vector + vector_count >= 1024 {
            return Err(Error::InvalidArgument);
        }

        // Allocate MSI-X table if not already allocated
        if self.msix_table.is_none() {
            let mut table = Vec::with_capacity(vector_count as usize);
            for i in 0..vector_count {
                table.push(MsiXEntry {
                    msg_addr: msi_addr,
                    msg_data: ((msi_data as u32) & 0xffff) | ((i as u32) << 16),
                    vector_control: 0, // Interrupt enabled
                });
            }
            self.msix_table = Some(table);
        } else {
            // Update existing MSI-X table
            let table = self.msix_table.as_mut().unwrap();
            for i in 0..vector_count.min(table.len() as u32) {
                table[i as usize].msg_addr = msi_addr;
                table[i as usize].msg_data = ((msi_data as u32) & 0xffff) | ((i as u32) << 16);
                table[i as usize].vector_control = 0; // Interrupt enabled
            }
        }

        // Enable interrupts in the IMSIC
        for i in 0..vector_count {
            let irq = base_vector + i;
            let reg_offset = (irq / 64) * 8;
            let bit = 1 << (irq % 64);
            let current = self.read(reg_offset);
            self.write(reg_offset, current | bit);
        }

        self.msix_enabled = true;
        log(
            LogLevel::Info,
            &format!(
                "AIA IMSIC: MSI-X configured for device={}, vectors={}, base_vector={}",
                device_id, vector_count, base_vector
            ),
        );

        Ok((base_vector, vector_count))
    }

    /// Get MSI-X table entry
    pub fn get_msix_entry(&self, vector: u32) -> Option<&MsiXEntry> {
        if !self.msix_enabled {
            return None;
        }
        if let Some(table) = &self.msix_table {
            if vector < table.len() as u32 {
                return Some(&table[vector as usize]);
            }
        }
        None
    }

    /// Mask/unmask a specific interrupt
    pub fn set_interrupt_mask(&mut self, irq: u32, masked: bool) -> Result<(), Error> {
        if irq >= 1024 {
            return Err(Error::InvalidArgument);
        }

        let reg_offset = (irq / 64) * 8 + 4; // Mask register is at +4 offset
        let bit = 1 << (irq % 64);

        let current = self.read(reg_offset);
        if masked {
            self.write(reg_offset, current | bit);
        } else {
            self.write(reg_offset, current & !bit);
        }

        log(
            LogLevel::Info,
            &format!(
                "AIA IMSIC: Interrupt {} {}",
                irq,
                if masked { "masked" } else { "unmasked" }
            ),
        );
        Ok(())
    }

    /// Clear pending interrupt
    pub fn clear_interrupt(&self, irq: u32) -> Result<(), Error> {
        if irq >= 1024 {
            return Err(Error::InvalidArgument);
        }

        let reg_offset = (irq / 64) * 8 + 8; // EOI register is at +8 offset
        let bit = 1 << (irq % 64);
        let current = self.read(reg_offset);
        self.write(reg_offset, current | bit);

        log(
            LogLevel::Info,
            &format!("AIA IMSIC: Interrupt {} cleared", irq),
        );
        Ok(())
    }

    /// Check if an interrupt is pending
    pub fn is_interrupt_pending(&self, irq: u32) -> bool {
        if irq >= 1024 {
            return false;
        }

        let reg_offset = (irq / 64) * 8 + 8; // Pending register is at +8 offset
        let bit = 1 << (irq % 64);
        (self.read(reg_offset) & bit) != 0
    }

    /// Get controller status
    pub fn get_status(&self) -> (bool, bool) {
        (self.msi_enabled, self.msix_enabled)
    }
}

static AIA_IMSIC_CONTROLLER: SpinLock<Option<AiaImsicController>> = SpinLock::new(None);

pub fn init_aia_imsic(base: usize, context_id: u32) {
    let mut controller = AIA_IMSIC_CONTROLLER.lock();
    *controller = Some(AiaImsicController::new(base, context_id));
    log(
        LogLevel::Info,
        &format!(
            "AIA IMSIC initialized at base={:#x}, context={}",
            base, context_id
        ),
    );
}

pub fn has_aia_imsic() -> bool {
    AIA_IMSIC_CONTROLLER.lock().is_some()
}

pub fn configure_msi(device_id: u32, vector: u32, data: u32) -> Result<u32, Error> {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_mut() {
        controller.configure_msi(device_id, vector, data)
    } else {
        log(LogLevel::Error, "AIA IMSIC not initialized");
        Err(Error::NotImplemented)
    }
}

pub fn configure_msix(
    device_id: u32,
    vector_count: u32,
    msi_addr: u64,
    msi_data: u64,
) -> Result<(u32, u32), Error> {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_mut() {
        controller.configure_msix(device_id, vector_count, msi_addr, msi_data)
    } else {
        log(LogLevel::Error, "AIA IMSIC not initialized");
        Err(Error::NotImplemented)
    }
}

// Additional public functions for interrupt management
pub fn set_interrupt_mask(irq: u32, masked: bool) -> Result<(), Error> {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_mut() {
        controller.set_interrupt_mask(irq, masked)
    } else {
        Err(Error::NotImplemented)
    }
}

pub fn clear_interrupt(irq: u32) -> Result<(), Error> {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_ref() {
        controller.clear_interrupt(irq)
    } else {
        Err(Error::NotImplemented)
    }
}

pub fn is_interrupt_pending(irq: u32) -> bool {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_ref() {
        controller.is_interrupt_pending(irq)
    } else {
        false
    }
}

pub fn get_msix_entry(vector: u32) -> Option<MsiXEntry> {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_ref() {
        controller.get_msix_entry(vector).copied()
    } else {
        None
    }
}

pub fn get_controller_status() -> (bool, bool) {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_ref() {
        controller.get_status()
    } else {
        (false, false)
    }
}

// Initialize external interrupts
pub fn init_external_interrupts() {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_mut() {
        controller.enable_external_interrupts();
    }
}

pub fn disable_external_interrupts() {
    if let Some(controller) = AIA_IMSIC_CONTROLLER.lock().as_mut() {
        controller.disable_external_interrupts();
    }
}
