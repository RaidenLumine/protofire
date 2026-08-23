//! src/kernel/fs/vfs/tests.rs
//! Regression tests for the pure VFS type layer: security descriptors,
//! metadata records, directory entries, and volume-check reporting.

use super::*;
use crate::abi::fs::{FILE_KIND_DIRECTORY, FILE_KIND_FILE};
use crate::kernel::process::{IntegrityLevel, SecurityToken};
use crate::Error;

#[test]
fn security_descriptor_mode_bits_are_extracted_per_class() {
    // 0755: owner rwx, group r-x, other r-x.
    let descriptor = SecurityDescriptor::root(0o755);
    assert_eq!(descriptor.owner_mode_bits(), 0o7);
    assert_eq!(descriptor.group_mode_bits(), 0o5);
    assert_eq!(descriptor.other_mode_bits(), 0o5);

    // 0644: owner rw-, group r--, other r--.
    let descriptor = SecurityDescriptor::root(0o644);
    assert_eq!(descriptor.owner_mode_bits(), 0o6);
    assert_eq!(descriptor.group_mode_bits(), 0o4);
    assert_eq!(descriptor.other_mode_bits(), 0o4);
}

#[test]
fn root_token_bypasses_discretionary_permissions() {
    let descriptor = SecurityDescriptor::root(0o000);
    // A superuser token only gains full bypass after authentication (the
    // `may_bypass_discretionary_permissions` gate requires it).
    let token = SecurityToken::root().with_authentication();
    let access = descriptor.access_query_for(
        ACCESS_READ_BIT | ACCESS_WRITE_BIT | ACCESS_EXECUTE_BIT,
        token,
    );
    assert!(access.allowed);
    assert!(access.bypasses_discretionary_permissions);
    assert_eq!(access.granted_mode_bits, 0o7);
}

#[test]
fn guest_token_respects_other_bits() {
    // Root-owned 0600 gives the guest (other class) no access.
    let descriptor = SecurityDescriptor::root(0o600);
    let access = descriptor.access_query_for(ACCESS_READ_BIT, SecurityToken::guest());
    assert!(!access.allowed);
    assert!(!access.bypasses_discretionary_permissions);

    // Root-owned 0644 grants read to the guest.
    let descriptor = SecurityDescriptor::root(0o644);
    let access = descriptor.access_query_for(ACCESS_READ_BIT, SecurityToken::guest());
    assert!(access.allowed);
    assert!(!access.can_write);
}

#[test]
fn low_integrity_token_loses_write() {
    let descriptor = SecurityDescriptor::root(0o777);
    let mut token = SecurityToken::guest();
    token.integrity = IntegrityLevel::Low;
    let access = descriptor.access_query_for(ACCESS_WRITE_BIT, token);
    assert!(
        !access.allowed,
        "low-integrity guest must not gain write access"
    );
    assert!(access.can_read);
}

#[test]
fn owner_class_is_checked_before_group_class() {
    // Owner root, group root; a guest token is not the owner and not in the group.
    let descriptor = SecurityDescriptor::root(0o750);
    let access = descriptor.access_query_for(ACCESS_EXECUTE_BIT, SecurityToken::guest());
    assert!(!access.allowed, "other class has no execute bit on 0750");
}

#[test]
fn security_descriptor_update_applies_fields() {
    let base = SecurityDescriptor::root(0o755);
    let updated = base
        .apply_update(SecurityDescriptorUpdate::default().mode(0o700))
        .expect("apply mode update");
    assert_eq!(updated.owner_uid, base.owner_uid);
    assert_eq!(updated.owner_gid, base.owner_gid);
    assert_eq!(updated.mode, 0o700);

    let invalid = base.apply_update(SecurityDescriptorUpdate::default().mode(0o1000));
    assert!(matches!(invalid, Err(Error::InvalidArgument)));
}

#[test]
fn metadata_defaults_use_root_per_kind() {
    let file = Metadata::new(NodeKind::File, 42);
    assert_eq!(file.kind, NodeKind::File);
    assert_eq!(file.size, 42);
    assert_eq!(file.security.mode, 0o644);
    assert_eq!(file.created, 0);

    let directory = Metadata::new(NodeKind::Directory, 0);
    assert_eq!(directory.security.mode, 0o755);
}

#[test]
fn metadata_public_stat_record_maps_kind() {
    let file = Metadata::new(NodeKind::File, 7);
    let record = file.public_stat_record();
    assert_eq!(record.kind, FILE_KIND_FILE);
    assert_eq!(record.size, 7);

    let directory = Metadata::new(NodeKind::Directory, 3);
    assert_eq!(directory.public_stat_record().kind, FILE_KIND_DIRECTORY);
}

#[test]
fn directory_entry_public_record_embeds_name_length() {
    let entry = DirectoryEntry::new(NodeKind::File, 16, alloc::string::String::from("init"));
    let record = entry.public_record();
    assert_eq!(record.kind, FILE_KIND_FILE);
    assert_eq!(record.size, 16);
    assert_eq!(record.name_len, 4);
    assert_eq!(
        record.name_offset,
        crate::abi::fs::DIRECTORY_ENTRY_RECORD_SIZE
    );
}

#[test]
fn directory_entry_permission_metadata_matches_security() {
    let entry = DirectoryEntry::new(NodeKind::File, 0, alloc::string::String::from("a"))
        .with_security(SecurityDescriptor::root(0o640));
    let record = entry.permission_metadata_record();
    assert_eq!(record.owner_uid, 0);
    assert_eq!(record.owner_gid, 0);
    assert_eq!(record.mode, 0o640);
}

#[test]
fn node_kind_abi_kinds_are_stable() {
    assert_eq!(NodeKind::Directory.public_abi_kind(), FILE_KIND_DIRECTORY);
    assert_eq!(NodeKind::File.public_abi_kind(), FILE_KIND_FILE);
    assert_eq!(NodeKind::Device.public_abi_kind(), 3);
    assert_eq!(NodeKind::Symlink.public_abi_kind(), 4);
}

#[test]
fn default_modes_follow_kind() {
    assert_eq!(default_mode_for_kind(NodeKind::Directory), 0o755);
    assert_eq!(default_mode_for_kind(NodeKind::File), 0o644);
    assert_eq!(default_mode_for_kind(NodeKind::Device), 0o660);
    assert_eq!(default_mode_for_kind(NodeKind::Symlink), 0o777);
}

#[test]
fn volume_check_report_flags_are_derived() {
    let clean = VolumeCheckReport {
        issues_detected: 0,
        repairs_applied: 0,
        orphan_data_blocks: 0,
        checksum_failures: 0,
        staging_orphans_cleaned: 0,
        orphan_blocks_cleaned: 0,
        interrupted_commits: 0,
    };
    assert!(clean.is_clean());
    assert!(!clean.repaired());

    let repaired = VolumeCheckReport {
        issues_detected: 1,
        repairs_applied: 2,
        orphan_data_blocks: 1,
        checksum_failures: 0,
        staging_orphans_cleaned: 0,
        orphan_blocks_cleaned: 1,
        interrupted_commits: 1,
    };
    assert!(!repaired.is_clean());
    assert!(repaired.repaired());
}

#[test]
fn mutation_support_capabilities() {
    assert!(SecurityDescriptorMutationSupport::Persistent.supports_persistent_updates());
    assert!(!SecurityDescriptorMutationSupport::LayoutDerivedOnly.supports_persistent_updates());
    assert!(!SecurityDescriptorMutationSupport::LayoutDerivedOnly.provides_persistent_metadata());
}
