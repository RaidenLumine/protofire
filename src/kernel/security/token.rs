//! src/kernel/security/token.rs
//!
//! The security token: who a request runs as, what it may do, and the MAC
//! subject label it carries.
//!
//! This lives below `process` and below `fs` because both need it and neither
//! owns it.  A filesystem asks the token whether a path may be read; the
//! process layer asks it whether an operation is privileged; and the two must
//! be able to hold the same answer without one depending on the other.

use super::mac::MacType;
use super::mac::MAC_TYPE_SYSTEM;
use super::mac::MAC_TYPE_UNTRUSTED;
use super::mac::MAC_TYPE_USER;

// ── Identities ──────────────────────────────────────────────────────────

pub type UserId = u32;
pub type GroupId = u32;

pub const ROOT_USER_ID: UserId = 0;
pub const ROOT_GROUP_ID: GroupId = 0;
pub const DEFAULT_GUEST_USER_ID: UserId = 1000;
pub const DEFAULT_GUEST_GROUP_ID: GroupId = 1000;

// The rights a handle may carry are a bottom-level concept shared with the
// device and audit layers, not something this layer owns.  Re-exported here
// because the token is what a caller usually has in hand when checking them.
pub use crate::kernel::handle_rights::HANDLE_RIGHT_READ;
pub use crate::kernel::handle_rights::HANDLE_RIGHT_WRITE;

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
    /// Set to `true` when the kernel built this token from a definition it
    /// trusts rather than from itself.  It is the difference between an
    /// identity the kernel *is* and one it merely *resolved*: see
    /// [`SecurityToken::is_kernel_token`].
    provisioned: bool,
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
            provisioned: false,
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
            provisioned: false,
            mac_type: MAC_TYPE_SYSTEM,
        }
    }

    /// The token for a service the kernel started itself, from a definition it
    /// trusts and an account it resolved.
    ///
    /// A service has nobody to ask for a password, so this is the kernel
    /// establishing an identity rather than a secret proving one, and the two
    /// flags that describe provenance both stay clear: `authenticated` because
    /// no password was verified, and `provisioned` because the token is not the
    /// kernel itself.  Between them they keep the discretionary bypass
    /// reachable only from the two places allowed to have it.
    pub const fn provisioned(uid: UserId, gid: GroupId, integrity: IntegrityLevel) -> Self {
        Self::new(uid, gid, integrity)
            .with_elevation()
            .with_mac_type(MAC_TYPE_SYSTEM)
            .with_provisioning()
    }

    /// Mark this token as built from a service definition rather than from the
    /// kernel's own identity.
    pub const fn with_provisioning(mut self) -> Self {
        self.provisioned = true;
        self
    }

    /// Return `true` when this token is the kernel speaking for itself.
    ///
    /// The raw [`SecurityToken::system`] token is, and a token built for a
    /// service is not, however it was declared: a config file can ask for the
    /// kernel's *trust level* but not for the kernel's *identity*.  Callers
    /// that treat "is this the kernel" as a shortcut — the discretionary
    /// bypass, unconditional security-descriptor changes, the per-process
    /// `is_kernel` report — ask this, not [`SecurityToken::is_system`].
    pub const fn is_kernel_token(self) -> bool {
        self.is_system() && !self.provisioned
    }

    /// Return `true` when the kernel built this token from a service
    /// definition rather than from itself.
    pub const fn is_provisioned(self) -> bool {
        self.provisioned
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
    /// authentication (login/su).
    ///
    /// This is the only flag that opens the discretionary bypass for a token
    /// that is not the kernel's own, so a privilege arriving any other way — a
    /// service definition, say — cannot set it by accident.
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
        // The kernel's own threads always bypass, no auth required.  A token
        // built for a service is not one of them: it carries an identity the
        // kernel resolved, so it faces the same standard as any other caller —
        // a password, or nothing.
        if self.is_kernel_token() {
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
