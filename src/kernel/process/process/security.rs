//! src/kernel/process/process/security.rs
//! Process security token: integrity levels, permission checks, MAC type.
use super::constants::*;
use crate::kernel::process::mac::{MacType, MAC_TYPE_SYSTEM, MAC_TYPE_UNTRUSTED, MAC_TYPE_USER};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    System,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityToken {
    pub user_id: UserId,
    pub primary_group_id: GroupId,
    pub integrity: IntegrityLevel,
    elevated: bool,
    pub recovery: bool,
    /// Supplementary group memberships consulted during
    /// discretionary access checks (in addition to `primary_group_id`).
    pub supplementary_group_ids: &'static [GroupId],
    /// Set to `true` only after password-based authentication (login/su).
    /// Kernel-internal system tokens bypass this check.
    authenticated: bool,
    /// MAC type-enforcement subject label.
    pub mac_type: MacType,
}

impl SecurityToken {
    pub const fn new(
        user_id: UserId,
        primary_group_id: GroupId,
        integrity: IntegrityLevel,
    ) -> Self {
        Self {
            user_id,
            primary_group_id,
            integrity,
            elevated: false,
            recovery: false,
            supplementary_group_ids: &[],
            authenticated: false,
            mac_type: MAC_TYPE_USER,
        }
    }

    pub const fn root() -> Self {
        Self::new(ROOT_USER_ID, ROOT_GROUP_ID, IntegrityLevel::High)
            .with_elevation()
            .with_supplementary_groups(&[ROOT_GROUP_ID])
            .with_mac_type(MAC_TYPE_SYSTEM)
    }

    pub const fn guest() -> Self {
        Self::new(
            DEFAULT_GUEST_USER_ID,
            DEFAULT_GUEST_GROUP_ID,
            IntegrityLevel::Medium,
        )
        .with_mac_type(MAC_TYPE_UNTRUSTED)
    }

    pub const fn system() -> Self {
        Self {
            user_id: ROOT_USER_ID,
            primary_group_id: ROOT_GROUP_ID,
            integrity: IntegrityLevel::System,
            elevated: true,
            recovery: false,
            supplementary_group_ids: &[ROOT_GROUP_ID],
            authenticated: false,
            mac_type: MAC_TYPE_SYSTEM,
        }
    }

    /// Return the MAC subject type.
    pub const fn mac_type(self) -> MacType {
        self.mac_type
    }

    /// Return a copy of this token with `mac_type` set (used at creation and
    /// by exec domain transitions).
    pub const fn with_mac_type(mut self, mac_type: MacType) -> Self {
        self.mac_type = mac_type;
        self
    }

    pub const fn with_elevation(mut self) -> Self {
        self.elevated = true;
        self
    }

    pub const fn with_recovery(mut self) -> Self {
        self.elevated = true;
        self.recovery = true;
        self
    }

    /// Mark this token as having been obtained through password-based
    /// authentication (login/su).  Only authenticated non-system tokens
    /// receive full privilege.
    pub const fn with_authentication(mut self) -> Self {
        self.authenticated = true;
        self
    }

    /// Returns `true` when this token was produced by a successful
    /// password-based authentication flow.
    pub const fn is_authenticated(self) -> bool {
        self.authenticated
    }

    pub const fn with_supplementary_groups(mut self, groups: &'static [GroupId]) -> Self {
        self.supplementary_group_ids = groups;
        self
    }

    pub const fn is_superuser(self) -> bool {
        self.user_id == ROOT_USER_ID
    }

    pub const fn is_system(self) -> bool {
        self.user_id == ROOT_USER_ID && matches!(self.integrity, IntegrityLevel::System)
    }

    /// Returns `true` when `self.integrity` dominates `other` (`System` is
    /// highest, `Low` is lowest).
    pub const fn dominates_integrity(self, other: IntegrityLevel) -> bool {
        self.integrity as u8 <= other as u8
    }

    pub const fn is_elevated(self) -> bool {
        self.elevated
    }

    pub const fn is_admin_mode(self) -> bool {
        self.elevated || self.is_system()
    }

    /// Shorthand for admin-mode checks used by the OOM killer and audit path.
    pub const fn is_admin(self) -> bool {
        self.is_admin_mode()
    }

    pub const fn is_recovery_mode(self) -> bool {
        self.recovery
    }

    pub const fn belongs_to_primary_group(self, group_id: GroupId) -> bool {
        self.primary_group_id == group_id
    }

    pub const fn belongs_to_group(self, group_id: GroupId) -> bool {
        if self.primary_group_id == group_id {
            return true;
        }
        let mut i = 0;
        while i < self.supplementary_group_ids.len() {
            if self.supplementary_group_ids[i] == group_id {
                return true;
            }
            i += 1;
        }
        false
    }

    pub const fn may_manage_system_tree(self) -> bool {
        // Recovery is modeled as a privileged admin subset, so the admin-mode
        // gate already covers both elevated maintenance and recovery shells.
        self.is_admin_mode()
    }

    pub const fn may_bypass_discretionary_permissions(self) -> bool {
        // Kernel-internal system threads always bypass, no auth required.
        if self.is_system() {
            return true;
        }
        // User-facing admin/superuser tokens must be authenticated.
        (self.is_superuser() || self.is_admin_mode()) && self.authenticated
    }

    // Read-only mount bypass is intentionally narrower than general admin
    // powers so maintenance shells do not silently widen ordinary write scope.
    pub const fn may_bypass_read_only_mounts(self) -> bool {
        self.is_recovery_mode()
    }
}
