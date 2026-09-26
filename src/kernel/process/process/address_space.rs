//! src/kernel/process/process/address_space.rs
//!
//! Process address-space management: install, translate, activate.
//!
//! The architecture owns what an address space *is* (see
//! [`crate::arch::mmu::ProcessAddressSpace`]); this file is the process's side
//! of it, and asks the same questions of every architecture: which page a user
//! address reaches, and how to make this process's root the active one.

use super::types::ProcessUserAddressSpace;
use super::Process;
use crate::arch::mmu::UserTranslation;

impl Process {
    pub(crate) fn install_user_address_space(&self, address_space: ProcessUserAddressSpace) {
        *self.user_address_space.lock() = Some(address_space);
    }

    // The user-memory validation and the dispatch path are bare-metal; a host
    // has no live user mapping to translate or activation to perform, so the
    // wrappers have no callers there.
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub(crate) fn translate_user_address(&self, address: usize) -> Option<UserTranslation> {
        self.user_address_space
            .lock()
            .as_ref()
            .and_then(|address_space| address_space.translate(address))
    }

    /// Make this process's address space the one the caller runs on.
    ///
    /// A kernel-only thread has no process root, so both this and a process
    /// whose activation was refused fall back to the prepared runtime kernel
    /// page tables — which is also what a target with no process roots at all
    /// answers with.  Refusing is the process root's job: it is the
    /// architecture that knows whether the hierarchy it prepared can be the
    /// active one.
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub(crate) fn activate_address_space_for_thread(&self) -> bool {
        if let Some(address_space) = self.user_address_space.lock().as_ref() {
            if address_space.activate_process_root() {
                return true;
            }
        }

        crate::arch::mmu::activate_prepared_runtime_kernel_page_tables().is_some()
    }
}
