//! src/kernel/process/process/address_space.rs
//!
//! Process address-space management: install, translate, activate.

#[cfg(all(
    any(target_arch = "aarch64", target_arch = "riscv64"),
    target_os = "none"
))]
use crate::arch::mmu::PreparedTranslation;
#[cfg(all(target_arch = "x86_64", any(target_os = "none", test)))]
use crate::arch::mmu::PreparedUserTranslation;

use super::types::*;
use super::Process;

impl Process {
    pub(crate) fn install_user_address_space(&self, address_space: ProcessUserAddressSpace) {
        *self.user_address_space.lock() = Some(address_space);
    }

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    pub(crate) fn translate_user_address(&self, address: usize) -> Option<PreparedUserTranslation> {
        self.user_address_space
            .lock()
            .as_ref()
            .and_then(|address_space| address_space.translate(address))
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(crate) fn translate_user_address(&self, address: usize) -> Option<PreparedTranslation> {
        self.user_address_space
            .lock()
            .as_ref()
            .and_then(|address_space| address_space.translate(address))
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    pub(crate) fn translate_user_address(&self, address: usize) -> Option<PreparedTranslation> {
        self.user_address_space
            .lock()
            .as_ref()
            .and_then(|address_space| address_space.translate(address))
    }

    #[cfg(all(target_arch = "x86_64", test))]
    pub(crate) fn translate_user_address(&self, address: usize) -> Option<PreparedUserTranslation> {
        self.user_address_space
            .lock()
            .as_ref()
            .and_then(|address_space| address_space.translate(address))
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    ))]
    pub(crate) fn activate_address_space_for_thread(&self) -> bool {
        if let Some(address_space) = self.user_address_space.lock().as_ref() {
            #[cfg(target_arch = "x86_64")]
            if address_space.activate_process_root().is_some() {
                return true;
            }

            #[cfg(target_arch = "aarch64")]
            if address_space.activate_process_root() {
                return true;
            }
        }

        // Kernel-only threads or host configurations fall back to the prepared
        // runtime kernel page tables.
        crate::arch::mmu::activate_prepared_runtime_kernel_page_tables().is_some()
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    #[cfg_attr(target_arch = "riscv64", allow(dead_code))]
    pub(crate) fn activate_address_space_for_thread(&self) -> bool {
        // The RISC-V process page tables clone the kernel PGD/PMD, so the
        // kernel remains mapped under the process `satp` — a trap can run the
        // full kernel handler with the process table still active and `sret`
        // returns to U-mode on the same table.  Kernel-only threads fall back
        // to the prepared runtime kernel page tables.
        if let Some(address_space) = self.user_address_space.lock().as_ref() {
            if address_space.activate_process_root() {
                return true;
            }
        }

        crate::arch::mmu::activate_prepared_runtime_kernel_page_tables().is_some()
    }
}
