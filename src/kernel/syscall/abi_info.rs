//! src/kernel/syscall/abi_info.rs
//! Runtime ABI identity syscall used by user space to detect supported execution features.

use crate::abi::runtime as runtime_abi;
use crate::arch::ArchitectureCapabilityInventory;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeUserModeAbiCandidates {
    supports_user_mode_runtime: bool,
    supports_user_exception_delivery: bool,
    supports_lower_el_user_exception_delivery: bool,
}

impl RuntimeUserModeAbiCandidates {
    const fn from_inventory(inventory: ArchitectureCapabilityInventory) -> Self {
        Self {
            supports_user_mode_runtime: inventory.supports_user_mode_runtime,
            supports_user_exception_delivery: inventory.supports_user_exception_delivery,
            supports_lower_el_user_exception_delivery: inventory
                .supports_lower_el_user_exception_delivery,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeExceptionRecoveryAbiCandidates {
    supports_kernel_page_fault_recovery_hook: bool,
}

impl RuntimeExceptionRecoveryAbiCandidates {
    const fn from_inventory(inventory: ArchitectureCapabilityInventory) -> Self {
        Self {
            supports_kernel_page_fault_recovery_hook: inventory
                .supports_kernel_page_fault_recovery_hook,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeMultiprocessorAbiCandidates {
    supports_smp_bootstrap: bool,
}

impl RuntimeMultiprocessorAbiCandidates {
    const fn from_inventory(inventory: ArchitectureCapabilityInventory) -> Self {
        Self {
            supports_smp_bootstrap: inventory.supports_smp_bootstrap,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeAbiFeaturePromotionCandidates {
    user_mode: RuntimeUserModeAbiCandidates,
    exception_recovery: RuntimeExceptionRecoveryAbiCandidates,
    multiprocessor: RuntimeMultiprocessorAbiCandidates,
}

impl RuntimeAbiFeaturePromotionCandidates {
    const fn from_inventory(inventory: ArchitectureCapabilityInventory) -> Self {
        Self {
            user_mode: RuntimeUserModeAbiCandidates::from_inventory(inventory),
            exception_recovery: RuntimeExceptionRecoveryAbiCandidates::from_inventory(inventory),
            multiprocessor: RuntimeMultiprocessorAbiCandidates::from_inventory(inventory),
        }
    }

    const fn current_public_feature_contribution(self) -> u64 {
        let _ = self;
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeAbiExposureBoundary {
    architecture_inventory: ArchitectureCapabilityInventory,
    feature_promotion_candidates: RuntimeAbiFeaturePromotionCandidates,
    public_feature_flags: u64,
}

impl RuntimeAbiExposureBoundary {
    const fn current() -> Self {
        let architecture_inventory = ArchitectureCapabilityInventory::current();
        let feature_promotion_candidates =
            RuntimeAbiFeaturePromotionCandidates::from_inventory(architecture_inventory);
        Self {
            architecture_inventory,
            feature_promotion_candidates,
            public_feature_flags: runtime_abi::stable_runtime_abi_feature_flags()
                | feature_promotion_candidates.current_public_feature_contribution(),
        }
    }

    const fn public_record(self) -> runtime_abi::RuntimeAbiInfo {
        runtime_abi::RuntimeAbiInfo::new(
            self.public_feature_flags,
            super::PUBLIC_SYSCALL_COUNT,
            crate::user::shared::abi::syscall::SYSCALL_ABI_VERSION_MAJOR,
            crate::user::shared::abi::syscall::SYSCALL_ABI_VERSION_MINOR,
        )
    }
}

pub(super) fn query(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 2)?;
    let record_buffer =
        super::user_memory::fixed_output_buffer_arg::<runtime_abi::RuntimeAbiInfo>(context, 0, 1)?;

    // `abi_info` only reports stable user-visible runtime ABI promises. More
    // granular architecture inventory remains internal until intentionally
    // promoted into the public contract.
    record_buffer.copy_value(&RuntimeAbiExposureBoundary::current().public_record())
}

#[cfg(test)]
mod tests {
    use super::RuntimeAbiExposureBoundary;
    use crate::abi::runtime;

    #[test]
    fn runtime_abi_exposure_boundary_keeps_public_flags_stable() {
        let boundary = RuntimeAbiExposureBoundary::current();
        assert_eq!(
            boundary.public_feature_flags,
            runtime::stable_runtime_abi_feature_flags()
        );
        assert_eq!(
            boundary.public_record().feature_flags,
            runtime::stable_runtime_abi_feature_flags()
        );
    }

    #[test]
    fn runtime_abi_exposure_boundary_reports_shared_syscall_count() {
        let boundary = RuntimeAbiExposureBoundary::current();

        assert_eq!(
            boundary.public_record().syscall_count,
            super::super::PUBLIC_SYSCALL_COUNT
        );
    }

    #[test]
    fn runtime_abi_exposure_boundary_tracks_internal_candidates_separately() {
        let boundary = RuntimeAbiExposureBoundary::current();
        let candidates = boundary.feature_promotion_candidates;
        let inventory = boundary.architecture_inventory;

        assert_eq!(
            candidates.user_mode.supports_user_mode_runtime,
            inventory.supports_user_mode_runtime
        );
        assert_eq!(
            candidates.user_mode.supports_user_exception_delivery,
            inventory.supports_user_exception_delivery
        );
        assert_eq!(
            candidates
                .user_mode
                .supports_lower_el_user_exception_delivery,
            inventory.supports_lower_el_user_exception_delivery
        );
        assert_eq!(
            candidates
                .exception_recovery
                .supports_kernel_page_fault_recovery_hook,
            inventory.supports_kernel_page_fault_recovery_hook
        );
        assert_eq!(
            candidates.multiprocessor.supports_smp_bootstrap,
            inventory.supports_smp_bootstrap
        );
    }

    #[test]
    fn runtime_abi_exposure_boundary_groups_candidates_by_concern() {
        let candidates = RuntimeAbiExposureBoundary::current().feature_promotion_candidates;

        let _ = candidates.user_mode;
        let _ = candidates.exception_recovery;
        let _ = candidates.multiprocessor;
    }

    #[test]
    fn runtime_abi_exposure_boundary_keeps_candidate_contribution_internal() {
        let boundary = RuntimeAbiExposureBoundary::current();
        assert_eq!(
            boundary
                .feature_promotion_candidates
                .current_public_feature_contribution(),
            0
        );
        assert_eq!(
            boundary.public_feature_flags,
            runtime::stable_runtime_abi_feature_flags()
        );
    }
}
