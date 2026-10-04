//! src/memory/diagnostics.rs
//!
//! Page-fault diagnostic types — layered translation snapshots and
//! kernel-region classification for fault insight reporting.

use super::paging::MappingKind;
use super::paging::PagePermissions;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressTranslation {
    pub physical_address: usize,
    pub permissions: PagePermissions,
    pub kind: MappingKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapTranslation {
    pub physical_address: usize,
    pub page_size: usize,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedTranslation {
    pub physical_address: usize,
    pub permissions: PagePermissions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannedKernelRegionKind {
    KernelText,
    KernelRodata,
    KernelData,
    KernelBss,
    KernelHeap,
}

impl PlannedKernelRegionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelText => "kernel-text",
            Self::KernelRodata => "kernel-rodata",
            Self::KernelData => "kernel-data",
            Self::KernelBss => "kernel-bss",
            Self::KernelHeap => "kernel-heap",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedKernelRegion {
    pub permissions: PagePermissions,
    pub kind: PlannedKernelRegionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFaultInsight {
    pub in_kernel_heap: bool,
    pub translation: Option<AddressTranslation>,
    pub bootstrap_translation: Option<BootstrapTranslation>,
    pub prepared_active: bool,
    pub prepared_translation: Option<PreparedTranslation>,
    pub planned_region: Option<PlannedKernelRegion>,
}

impl PageFaultInsight {
    pub const fn software_state(self) -> &'static str {
        match (self.in_kernel_heap, self.translation) {
            (_, Some(translation)) => translation.kind.as_str(),
            (true, None) => "unmapped-kernel-heap",
            (false, None) => "unmapped",
        }
    }

    pub const fn bootstrap_state(self) -> &'static str {
        if self.bootstrap_translation.is_some() {
            "bootstrap-identity-map"
        } else {
            "bootstrap-unmapped"
        }
    }

    pub const fn prepared_state(self) -> &'static str {
        match (self.prepared_active, self.prepared_translation) {
            (true, Some(_)) => "prepared-kernel-page-table-active",
            (false, Some(_)) => "prepared-kernel-page-table",
            (true, None) => "prepared-active-unmapped",
            (false, None) => "prepared-unmapped",
        }
    }

    pub const fn planned_state(self) -> &'static str {
        match self.planned_region {
            Some(region) => region.kind.as_str(),
            None => "outside-kernel-plan",
        }
    }
}
