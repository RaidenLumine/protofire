//! src/arch/aarch64/mmu/process_address_space.rs
//!
//! What an AArch64 process address space is, as the process layer sees it.
//!
//! The hierarchy itself is [`PreparedProcessAddressSpace`]; this is its uniform
//! face — the questions the process layer asks, answered in the kernel's
//! vocabulary — so that the layer above holds one type and asks once instead of
//! carrying a `#[cfg]` ladder per method.
//!
//! The summary's x86_64-shaped fields (the PML4 and page-directory counts) have
//! no counterpart here and are reported as zero rather than invented: a reader
//! who wants to know how many tables AArch64 built should read the counts that
//! do exist.

use super::PreparedProcessAddressSpace;
use super::PreparedTranslation;
use crate::arch::mmu::UserTranslation;
use crate::kernel::process::ProcessAddressSpaceSummary;
use crate::kernel::process::UserAddressSpaceSummary;
use crate::kernel::process::UserThreadStart;

/// One process's prepared address space.
pub struct ProcessAddressSpace(PreparedProcessAddressSpace);

impl ProcessAddressSpace {
    /// Wrap the hierarchy this architecture prepared.
    pub fn from_prepared_process(prepared: PreparedProcessAddressSpace) -> Self {
        Self(prepared)
    }

    /// The user half's summary, in the shape the kernel reports.
    pub fn user_summary(&self) -> UserAddressSpaceSummary {
        let prepared = &self.0;
        UserAddressSpaceSummary {
            root_table_address: prepared.root_table_address(),
            mapped_page_count: prepared.user_page_count(),
            image_page_count: prepared.image_page_count(),
            stack_page_count: prepared.stack_page_count(),
            table_page_count: prepared.table_page_count(),
            pml4_entry_count: prepared.root_entry_count(),
            pdpt_count: prepared.second_level_entry_count(),
            page_directory_count: 0,
            page_table_count: prepared.leaf_table_count(),
        }
    }

    /// The whole hierarchy's summary: AArch64 prepares one root for both
    /// halves, so the kernel and the user mappings are counted together.
    pub fn process_summary(&self) -> Option<ProcessAddressSpaceSummary> {
        let prepared = &self.0;
        Some(ProcessAddressSpaceSummary {
            root_table_address: prepared.root_table_address(),
            mapped_page_count: prepared.mapped_page_count(),
            kernel_page_count: prepared.kernel_page_count(),
            user_page_count: prepared.user_page_count(),
            table_page_count: prepared.table_page_count(),
            pml4_entry_count: prepared.root_entry_count(),
            pdpt_count: prepared.second_level_entry_count(),
            page_directory_count: 0,
            page_table_count: prepared.leaf_table_count(),
        })
    }

    /// The virtual range `(start, end_exclusive)` covering the user pages.
    pub fn user_page_va_range(&self) -> Option<(usize, usize)> {
        self.0.user_page_va_range()
    }

    /// The entry point and stack the prepared slot pins for the user program.
    pub fn user_thread_start(&self) -> Option<UserThreadStart> {
        Some(self.0.user_thread_start())
    }

    /// Does the prepared slot agree with this thread start?
    ///
    /// The demo-slot loader rebases the image into a fixed runtime window, so
    /// the addresses the ELF header names are not the ones the program runs at;
    /// this is where that rebasing is checked.
    pub fn matches_user_thread_start(&self, start: UserThreadStart) -> Option<bool> {
        let prepared = self.0.user_thread_start();
        Some(
            start.instruction_pointer == prepared.instruction_pointer
                && start.stack_pointer == prepared.stack_pointer
                && start.exception_stack_pointer == prepared.exception_stack_pointer,
        )
    }

    /// Translate one user address into the page the kernel would reach.
    pub fn translate_user(&self, address: usize) -> Option<UserTranslation> {
        self.0.translate_user(address).map(Into::into)
    }

    /// Make this hierarchy the active one, and say whether it worked.
    pub fn activate(&self) -> bool {
        self.0.activate().is_some()
    }

    /// The mutable hierarchy, for the operations that edit it (fork).
    pub fn process_mut(&mut self) -> Option<&mut PreparedProcessAddressSpace> {
        Some(&mut self.0)
    }
}

impl From<PreparedTranslation> for UserTranslation {
    fn from(translation: PreparedTranslation) -> Self {
        Self {
            physical_address: translation.physical_address,
            permissions: translation.permissions,
        }
    }
}
