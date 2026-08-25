//! src/kernel/fs/simplefs/format_io.rs
//!
//! On-disk format I/O: superblock, inode/dirent tables, image building.
//!
//! Low-level helpers (byte I/O, kind encoding, test utilities) are in
//! [`super::free_fns`].

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::unicode;
use crate::Error;
use crate::Result;

use super::super::block::BlockDevice;
use super::super::block::BLOCK_SIZE;
use super::super::vfs::NodeKind;

use super::constants::*;
use super::free_fns::*;
use super::types::*;
use super::ImageEntry;

pub(crate) fn read_inodes(
    device: &dyn BlockDevice,
    format_version: SimpleFsFormatVersion,
    table_block: usize,
    count: usize,
) -> Result<Vec<OnDiskInode>> {
    let inode_bytes = format_version.inode_table_bytes(count)?;
    let mut buffer = vec![0_u8; blocks_for(inode_bytes) * BLOCK_SIZE];
    device.read_blocks(table_block as u64, &mut buffer)?;

    let mut inodes = Vec::with_capacity(count);
    for index in 0..count {
        let base = format_version.inode_table_entry_offset(0, index)?;
        let kind = *buffer
            .get(base + format_version.inode_kind_offset())
            .ok_or(Error::InvalidArgument)?;
        let deleted = *buffer
            .get(base + format_version.inode_flags_offset())
            .ok_or(Error::InvalidArgument)?
            & INODE_FLAG_DELETED
            != 0;
        let data_checksum = match format_version.data_checksum_offset() {
            Some(offset) => read_u32(&buffer, base + offset)?,
            None => 0,
        };
        inodes.push(OnDiskInode {
            kind: decode_kind(kind)?,
            deleted,
            entry_start: read_u32(&buffer, base + format_version.inode_entry_start_offset())?,
            entry_count: read_u32(&buffer, base + format_version.inode_entry_count_offset())?,
            data_block: read_u32(&buffer, base + format_version.inode_data_block_offset())?,
            block_count: read_u32(&buffer, base + format_version.inode_block_count_offset())?,
            size: read_u32(&buffer, base + format_version.inode_size_field_offset())?,
            persistent_security: read_inode_persistent_security_descriptor(
                &buffer,
                format_version,
                base,
            )?,
            data_checksum,
            compressed: buffer
                .get(base + format_version.inode_flags_offset())
                .ok_or(Error::InvalidArgument)?
                & INODE_FLAG_COMPRESSED
                != 0,
            deduped: buffer
                .get(base + format_version.inode_flags_offset())
                .ok_or(Error::InvalidArgument)?
                & INODE_FLAG_DEDUPED
                != 0,
        });
    }

    Ok(inodes)
}

pub(crate) fn read_inode_persistent_security_descriptor(
    bytes: &[u8],
    format_version: SimpleFsFormatVersion,
    base: usize,
) -> Result<Option<OnDiskPersistentSecurityDescriptor>> {
    let Some(layout) = format_version.persistent_security_descriptor_layout() else {
        return Ok(None);
    };

    Ok(Some(OnDiskPersistentSecurityDescriptor {
        owner_uid: read_u32(bytes, base + layout.owner_uid_offset)?,
        owner_gid: read_u32(bytes, base + layout.owner_gid_offset)?,
        mode: read_u16(bytes, base + layout.mode_offset)?,
    }))
}

pub(crate) fn read_dir_entries(
    device: &dyn BlockDevice,
    format_version: SimpleFsFormatVersion,
    table_block: usize,
    count: usize,
) -> Result<Vec<OnDiskDirEntry>> {
    let dirent_bytes = format_version.dirent_table_bytes(count)?;
    let mut buffer = vec![0_u8; blocks_for(dirent_bytes) * BLOCK_SIZE];
    device.read_blocks(table_block as u64, &mut buffer)?;

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let base = format_version.dirent_table_entry_offset(0, index)?;
        let inode_index = read_u32(&buffer, base + format_version.dirent_inode_index_offset())?;
        let kind = decode_kind(
            *buffer
                .get(base + format_version.dirent_kind_offset())
                .ok_or(Error::InvalidArgument)?,
        )?;
        let name_len = *buffer
            .get(base + format_version.dirent_name_len_offset())
            .ok_or(Error::InvalidArgument)? as usize;
        if name_len > format_version.dirent_name_max_len() {
            return Err(Error::InvalidArgument);
        }
        let name_start = base + format_version.dirent_name_offset();
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(Error::InvalidArgument)?;
        let name = buffer
            .get(name_start..name_end)
            .ok_or(Error::InvalidArgument)?;
        entries.push(OnDiskDirEntry {
            inode_index,
            kind,
            // NOTE(utf-8): SimpleFs stores filenames as opaque bytes on disk.
            // `from_utf8_lossy` replaces invalid UTF-8 sequences with U+FFFD
            // (replacement character).  This means a filename containing raw
            // bytes that survive a read→write→read round-trip will be
            // *permanently corrupted* — the replacement characters cannot be
            // mapped back to the original bytes.  This is a known limitation
            // of the macOS-style "UTF-8 only" path model.  A future WTF-8 or
            // byte-string VFS layer would be required for lossless round-trips.
            //
            // Store the filename as-is — the kernel treats names as
            // opaque UTF-8 byte sequences (Linux / HarmonyOS semantics).
            name: String::from_utf8_lossy(name).into_owned(),
        });
    }

    Ok(entries)
}

pub(crate) fn build_nodes<'a>(files: &[ImageEntry<'a>]) -> Result<Vec<BuilderNode<'a>>> {
    let mut nodes = vec![BuilderNode {
        name: "/".to_string(),
        kind: NodeKind::Directory,
        data: b"",
        children: Vec::new(),
    }];
    let mut index_by_path = BTreeMap::new();
    index_by_path.insert("/".to_string(), 0_usize);

    for entry in files {
        // Materialize any implicit parent directories so image construction can
        // accept flat file lists instead of requiring explicit directory nodes.
        let normalized = normalize_image_path(entry.path)?;
        for parent in parent_paths(&normalized) {
            ensure_node(
                &mut nodes,
                &mut index_by_path,
                &parent,
                NodeKind::Directory,
                b"",
            )?;
        }

        ensure_node(
            &mut nodes,
            &mut index_by_path,
            &normalized,
            NodeKind::File,
            entry.data,
        )?;
    }

    let names: Vec<String> = nodes.iter().map(|node| node.name.clone()).collect();
    for node in &mut nodes {
        node.children
            // Tiebreaker on index guarantees a total order even if two
            // children share the same name (which shouldn't happen, but
            // Rust 1.81+ debug-asserts the comparator is a total order).
            .sort_by(|left, right| {
                names[*left]
                    .cmp(&names[*right])
                    .then_with(|| left.cmp(right))
            });
    }

    Ok(nodes)
}

pub(crate) fn ensure_node<'a>(
    nodes: &mut Vec<BuilderNode<'a>>,
    index_by_path: &mut BTreeMap<String, usize>,
    path: &str,
    kind: NodeKind,
    data: &'a [u8],
) -> Result<usize> {
    if let Some(index) = index_by_path.get(path).copied() {
        return Ok(index);
    }

    let parent = parent_path(path);
    let name = base_name(path);
    validate_dir_entry_name_for_format(name, SimpleFsFormatVersion::V2)?;
    let index = nodes.len();
    nodes.push(BuilderNode {
        name: name.to_string(),
        kind,
        data,
        children: Vec::new(),
    });
    index_by_path.insert(path.to_string(), index);

    if let Some(parent_path) = parent {
        let parent_index =
            ensure_node(nodes, index_by_path, &parent_path, NodeKind::Directory, b"")?;
        nodes[parent_index].children.push(index);
    }

    Ok(index)
}

pub(crate) fn depth_first_order(nodes: &[BuilderNode<'_>]) -> Vec<usize> {
    fn walk(index: usize, nodes: &[BuilderNode<'_>], order: &mut Vec<usize>) {
        order.push(index);
        for child in &nodes[index].children {
            walk(*child, nodes, order);
        }
    }

    let mut order = Vec::with_capacity(nodes.len());
    // Emit parents before children so directory slices can point only forward
    // into the generated dir-entry table and inode array.
    walk(0, nodes, &mut order);
    order
}

pub(crate) fn normalize_image_path(path: &str) -> Result<String> {
    let normalized = path.trim();
    if normalized.contains('\\') {
        return Err(Error::InvalidArgument);
    }
    if normalized.starts_with('/') {
        Ok(normalized.to_string())
    } else {
        let mut absolute = String::from("/");
        absolute.push_str(normalized.trim_start_matches('/'));
        Ok(absolute)
    }
}

pub(crate) fn parent_paths(path: &str) -> Vec<String> {
    let mut current = parent_path(path);
    let mut parents = Vec::new();

    while let Some(parent) = current {
        parents.push(parent.clone());
        current = parent_path(&parent);
    }

    parents.reverse();
    parents
}

pub(crate) fn parent_path(path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }

    let trimmed = path.trim_end_matches('/');
    let parent = trimmed
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("/");
    if parent.is_empty() {
        Some("/".to_string())
    } else {
        Some(parent.to_string())
    }
}

pub(crate) fn base_name(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("/")
}

pub(crate) fn names_match(left: &str, right: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        left == right
    } else {
        unicode::eq_unicode_insensitive(left, right)
    }
}

pub(crate) fn blocks_for(byte_len: usize) -> usize {
    if byte_len == 0 {
        0
    } else {
        byte_len.div_ceil(BLOCK_SIZE)
    }
}

pub(crate) fn validate_dir_entry_name_for_format(
    name: &str,
    format_version: SimpleFsFormatVersion,
) -> Result<()> {
    if name.is_empty()
        || name == "/"
        || name.contains('/')
        || name.len() > format_version.dirent_name_max_len()
    {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

pub(crate) fn load_current_runtime_state(
    device: &dyn BlockDevice,
    case_sensitive: bool,
    mount_policy: SimpleFsRuntimeMountPolicy,
) -> Result<(
    String,
    ParsedSuperblock,
    Vec<OnDiskInode>,
    Vec<OnDiskDirEntry>,
)> {
    let mut candidates = readable_superblock_candidates(device);
    candidates.sort_by_key(|entry| core::cmp::Reverse(entry.1.record.generation));
    let mut saw_runtime_unsupported_candidate = false;

    for (label, parsed_superblock) in candidates {
        match load_runtime_state_from_superblock(
            device,
            parsed_superblock,
            case_sensitive,
            mount_policy,
        ) {
            Ok((inodes, dir_entries)) => {
                return Ok((label, parsed_superblock, inodes, dir_entries));
            }
            Err(Error::Unsupported) => {
                saw_runtime_unsupported_candidate = true;
            }
            Err(_) => {}
        }
    }

    if saw_runtime_unsupported_candidate {
        Err(Error::Unsupported)
    } else {
        Err(Error::InvalidArgument)
    }
}

pub(crate) fn readable_superblock_candidates(
    device: &dyn BlockDevice,
) -> Vec<(String, ParsedSuperblock)> {
    let mut candidates = Vec::with_capacity(2);
    if let Ok(primary) = read_superblock_record(device, PRIMARY_SUPERBLOCK_BLOCK) {
        candidates.push(primary);
    }
    if let Ok(secondary) = read_superblock_record(device, SECONDARY_SUPERBLOCK_BLOCK) {
        candidates.push(secondary);
    }
    candidates
}

pub(crate) fn load_runtime_state_from_superblock(
    device: &dyn BlockDevice,
    parsed_superblock: ParsedSuperblock,
    case_sensitive: bool,
    mount_policy: SimpleFsRuntimeMountPolicy,
) -> Result<(Vec<OnDiskInode>, Vec<OnDiskDirEntry>)> {
    let format_version = parsed_superblock.format_version;
    format_version.ensure_runtime_mount_supported(device.is_read_only(), mount_policy)?;
    let superblock = parsed_superblock.record;
    let inode_capacity = format_version.inode_capacity(superblock.inode_table_blocks);
    let dirent_capacity = format_version.dirent_capacity(superblock.dirent_table_blocks);
    if superblock.inode_count > inode_capacity || superblock.dirent_count > dirent_capacity {
        return Err(Error::InvalidArgument);
    }

    let inodes = read_inodes(
        device,
        format_version,
        superblock.active_inode_table_block,
        superblock.inode_count,
    )?;
    let dir_entries = read_dir_entries(
        device,
        format_version,
        superblock.active_dirent_table_block,
        superblock.dirent_count,
    )?;

    // Reject malformed or inconsistent metadata before exposing the volume.
    validate_loaded_metadata(
        &inodes,
        &dir_entries,
        format_version,
        superblock.data_block_start,
        device.block_count() as usize,
        case_sensitive,
    )?;

    Ok((inodes, dir_entries))
}

pub(crate) fn read_superblock_record(
    device: &dyn BlockDevice,
    block_index: usize,
) -> Result<(String, ParsedSuperblock)> {
    let mut superblock = [0_u8; BLOCK_SIZE];
    device.read_blocks(block_index as u64, &mut superblock)?;
    parse_superblock(&superblock)
}

pub(crate) fn parse_supported_format_version(raw: u32) -> Result<SimpleFsFormatVersion> {
    SimpleFsFormatVersion::parse_supported(raw)
}

pub(crate) fn parse_superblock(superblock: &[u8]) -> Result<(String, ParsedSuperblock)> {
    if &superblock[..8] != MAGIC {
        return Err(Error::InvalidArgument);
    }

    let format_version = parse_supported_format_version(read_u32(superblock, 8)?)?;

    if read_u32(superblock, 12)? as usize != BLOCK_SIZE {
        return Err(Error::Unsupported);
    }

    let stored_checksum = read_u32(superblock, SUPERBLOCK_CHECKSUM_OFFSET)?;
    if stored_checksum != superblock_checksum(superblock) {
        return Err(Error::InvalidArgument);
    }

    let record = SuperblockRecord {
        inode_count: read_u32(superblock, 16)? as usize,
        dirent_count: read_u32(superblock, 20)? as usize,
        active_inode_table_block: read_u32(superblock, SUPERBLOCK_ACTIVE_INODE_TABLE_OFFSET)?
            as usize,
        active_dirent_table_block: read_u32(superblock, SUPERBLOCK_ACTIVE_DIRENT_TABLE_OFFSET)?
            as usize,
        data_block_start: read_u32(superblock, SUPERBLOCK_DATA_BLOCK_START_OFFSET)? as usize,
        shadow_inode_table_block: read_u32(superblock, SUPERBLOCK_SHADOW_INODE_TABLE_OFFSET)?
            as usize,
        shadow_dirent_table_block: read_u32(superblock, SUPERBLOCK_SHADOW_DIRENT_TABLE_OFFSET)?
            as usize,
        inode_table_blocks: read_u32(superblock, SUPERBLOCK_INODE_TABLE_BLOCKS_OFFSET)? as usize,
        dirent_table_blocks: read_u32(superblock, SUPERBLOCK_DIRENT_TABLE_BLOCKS_OFFSET)? as usize,
        generation: read_u32(superblock, SUPERBLOCK_GENERATION_OFFSET)?,
        pending_commit: if format_version
            .persistent_security_descriptor_layout()
            .is_some()
        {
            read_u32(superblock, SUPERBLOCK_PENDING_COMMIT_OFFSET)?
        } else {
            0
        },
        active_xattr_table_block: read_u32(superblock, SUPERBLOCK_ACTIVE_XATTR_TABLE_OFFSET)?
            as usize,
        shadow_xattr_table_block: read_u32(superblock, SUPERBLOCK_SHADOW_XATTR_TABLE_OFFSET)?
            as usize,
        xattr_table_blocks: read_u32(superblock, SUPERBLOCK_XATTR_TABLE_BLOCKS_OFFSET)? as usize,
        xattr_count: read_u32(superblock, SUPERBLOCK_XATTR_COUNT_OFFSET)? as usize,
    };
    validate_superblock_record(record)?;
    Ok((
        parse_label(superblock),
        ParsedSuperblock {
            format_version,
            record,
        },
    ))
}

pub(crate) fn validate_superblock_record(record: SuperblockRecord) -> Result<()> {
    if record.inode_table_blocks == 0 {
        return Err(Error::InvalidArgument);
    }

    let active_inode_end = record
        .active_inode_table_block
        .checked_add(record.inode_table_blocks)
        .ok_or(Error::InvalidArgument)?;
    let active_dirent_end = record
        .active_dirent_table_block
        .checked_add(record.dirent_table_blocks)
        .ok_or(Error::InvalidArgument)?;
    let shadow_inode_end = record
        .shadow_inode_table_block
        .checked_add(record.inode_table_blocks)
        .ok_or(Error::InvalidArgument)?;
    let shadow_dirent_end = record
        .shadow_dirent_table_block
        .checked_add(record.dirent_table_blocks)
        .ok_or(Error::InvalidArgument)?;

    if record.active_inode_table_block <= SECONDARY_SUPERBLOCK_BLOCK
        || record.active_dirent_table_block != active_inode_end
        || record.shadow_inode_table_block <= SECONDARY_SUPERBLOCK_BLOCK
        || record.shadow_dirent_table_block != shadow_inode_end
    {
        return Err(Error::InvalidArgument);
    }

    let active_range = record.active_inode_table_block..active_dirent_end;
    let shadow_range = record.shadow_inode_table_block..shadow_dirent_end;
    if active_range.start >= active_range.end || shadow_range.start >= shadow_range.end {
        return Err(Error::InvalidArgument);
    }
    if active_range.start < shadow_range.end && shadow_range.start < active_range.end {
        return Err(Error::InvalidArgument);
    }
    if record.data_block_start < active_range.end || record.data_block_start < shadow_range.end {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

pub(crate) fn write_superblock(
    block: &mut [u8],
    label: &str,
    format_version: SimpleFsFormatVersion,
    record: SuperblockRecord,
) {
    block.fill(0);
    block[..8].copy_from_slice(MAGIC);
    write_u32(block, 8, format_version.on_disk_value());
    write_u32(block, 12, BLOCK_SIZE as u32);
    write_u32(block, 16, record.inode_count as u32);
    write_u32(block, 20, record.dirent_count as u32);
    write_u32(
        block,
        SUPERBLOCK_ACTIVE_INODE_TABLE_OFFSET,
        record.active_inode_table_block as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_ACTIVE_DIRENT_TABLE_OFFSET,
        record.active_dirent_table_block as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_DATA_BLOCK_START_OFFSET,
        record.data_block_start as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_SHADOW_INODE_TABLE_OFFSET,
        record.shadow_inode_table_block as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_SHADOW_DIRENT_TABLE_OFFSET,
        record.shadow_dirent_table_block as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_INODE_TABLE_BLOCKS_OFFSET,
        record.inode_table_blocks as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_DIRENT_TABLE_BLOCKS_OFFSET,
        record.dirent_table_blocks as u32,
    );
    // V4+: the xattr table slots and per-slot size.  Written unconditionally —
    // V2/V3 records carry 0 for these fields, which is exactly what the
    // read path (format_io::parse_superblock) recovers for those formats.
    write_u32(
        block,
        SUPERBLOCK_ACTIVE_XATTR_TABLE_OFFSET,
        record.active_xattr_table_block as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_SHADOW_XATTR_TABLE_OFFSET,
        record.shadow_xattr_table_block as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_XATTR_TABLE_BLOCKS_OFFSET,
        record.xattr_table_blocks as u32,
    );
    write_u32(
        block,
        SUPERBLOCK_XATTR_COUNT_OFFSET,
        record.xattr_count as u32,
    );
    write_u32(block, SUPERBLOCK_GENERATION_OFFSET, record.generation);

    // Pending-commit marker: only written for V3+ formats.
    if format_version
        .persistent_security_descriptor_layout()
        .is_some()
    {
        write_u32(
            block,
            SUPERBLOCK_PENDING_COMMIT_OFFSET,
            record.pending_commit,
        );
    }

    let label_bytes = label.as_bytes();
    let label_len = label_bytes.len().min(SUPERBLOCK_LABEL_LEN);
    block[SUPERBLOCK_LABEL_OFFSET..SUPERBLOCK_LABEL_OFFSET + label_len]
        .copy_from_slice(&label_bytes[..label_len]);
    write_u32(
        block,
        SUPERBLOCK_CHECKSUM_OFFSET,
        superblock_checksum(block),
    );
}

pub(crate) fn superblock_checksum(block: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for (index, byte) in block.iter().enumerate() {
        if (SUPERBLOCK_CHECKSUM_OFFSET..SUPERBLOCK_CHECKSUM_OFFSET + 4).contains(&index) {
            continue;
        }

        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

pub(crate) fn write_inode_table(
    image: &mut [u8],
    format_version: SimpleFsFormatVersion,
    table_block: usize,
    inodes: &[BuilderInode],
) -> Result<()> {
    for (index, inode) in inodes.iter().enumerate() {
        let base = format_version.inode_table_entry_offset(table_block, index)?;
        image[base + format_version.inode_kind_offset()] = inode.kind;
        image[base + format_version.inode_flags_offset()] = 0;
        write_u32(
            image,
            base + format_version.inode_entry_start_offset(),
            inode.entry_start,
        );
        write_u32(
            image,
            base + format_version.inode_entry_count_offset(),
            inode.entry_count,
        );
        write_u32(
            image,
            base + format_version.inode_data_block_offset(),
            inode.data_block,
        );
        write_u32(
            image,
            base + format_version.inode_block_count_offset(),
            inode.block_count,
        );
        write_u32(
            image,
            base + format_version.inode_size_field_offset(),
            inode.size,
        );
    }

    Ok(())
}

pub(crate) fn write_dir_entry_table(
    image: &mut [u8],
    format_version: SimpleFsFormatVersion,
    table_block: usize,
    dir_entries: &[BuilderDirEntry],
) -> Result<()> {
    for (index, entry) in dir_entries.iter().enumerate() {
        let base = format_version.dirent_table_entry_offset(table_block, index)?;
        write_u32(
            image,
            base + format_version.dirent_inode_index_offset(),
            entry.inode_index,
        );
        image[base + format_version.dirent_kind_offset()] = entry.kind;
        image[base + format_version.dirent_name_len_offset()] = entry.name.len() as u8;
        let name_start = base + format_version.dirent_name_offset();
        let name_end = name_start + entry.name.len();
        image[name_start..name_end].copy_from_slice(entry.name.as_bytes());
    }

    Ok(())
}

pub(crate) fn write_runtime_inode_table(
    image: &mut [u8],
    format_version: SimpleFsFormatVersion,
    table_block: usize,
    inodes: &[OnDiskInode],
) -> Result<()> {
    for (index, inode) in inodes.iter().enumerate() {
        let base = format_version.inode_table_entry_offset(table_block, index)?;
        image[base + format_version.inode_kind_offset()] = encode_kind(inode.kind);
        image[base + format_version.inode_flags_offset()] =
            if inode.deleted { INODE_FLAG_DELETED } else { 0 };
        write_u32(
            image,
            base + format_version.inode_entry_start_offset(),
            inode.entry_start,
        );
        write_u32(
            image,
            base + format_version.inode_entry_count_offset(),
            inode.entry_count,
        );
        write_u32(
            image,
            base + format_version.inode_data_block_offset(),
            inode.data_block,
        );
        write_u32(
            image,
            base + format_version.inode_block_count_offset(),
            inode.block_count,
        );
        write_u32(
            image,
            base + format_version.inode_size_field_offset(),
            inode.size,
        );
        let inode_end = base
            .checked_add(format_version.inode_size())
            .ok_or(Error::InvalidArgument)?;
        let inode_bytes = image
            .get_mut(base..inode_end)
            .ok_or(Error::InvalidArgument)?;
        write_inode_persistent_security_descriptor(
            inode_bytes,
            format_version,
            inode.persistent_security,
        )?;
        if let Some(offset) = format_version.data_checksum_offset() {
            write_u32(inode_bytes, offset, inode.data_checksum);
        }
    }

    Ok(())
}

pub(crate) fn write_runtime_dir_entry_table(
    image: &mut [u8],
    format_version: SimpleFsFormatVersion,
    table_block: usize,
    dir_entries: &[OnDiskDirEntry],
) -> Result<()> {
    for (index, entry) in dir_entries.iter().enumerate() {
        let base = format_version.dirent_table_entry_offset(table_block, index)?;
        write_u32(
            image,
            base + format_version.dirent_inode_index_offset(),
            entry.inode_index,
        );
        image[base + format_version.dirent_kind_offset()] = encode_kind(entry.kind);
        image[base + format_version.dirent_name_len_offset()] = entry.name.len() as u8;
        let name_start = base + format_version.dirent_name_offset();
        let name_end = name_start + entry.name.len();
        image[name_start..name_end].copy_from_slice(entry.name.as_bytes());
    }

    Ok(())
}

/// Serialize a runtime xattr table into `image` for `format_version`'s V4+
/// shadow-slot geometry.
///
/// Each fixed-size record is written at `xattr_table_entry_offset`, laid out
/// as `{inode_index:u32, name_len:u32, value_len:u32, status:u32,
/// name:[u8;XATTR_NAME_MAX], value:[u8;XATTR_VALUE_MAX]}` — the mirror image
/// of the parser in `xattr.rs`.
pub(crate) fn write_runtime_xattr_table(
    image: &mut [u8],
    format_version: SimpleFsFormatVersion,
    table_block: usize,
    xattrs: &[XattrRecord],
) -> Result<()> {
    for (index, record) in xattrs.iter().enumerate() {
        let base = format_version.xattr_table_entry_offset(table_block, index)?;
        let end = base
            .checked_add(XATTR_RECORD_SIZE)
            .ok_or(Error::InvalidArgument)?;
        let slot = image.get_mut(base..end).ok_or(Error::InvalidArgument)?;

        slot[0..4].copy_from_slice(&record.inode_index.to_le_bytes());
        slot[4..8].copy_from_slice(&record.name_len.to_le_bytes());
        slot[8..12].copy_from_slice(&record.value_len.to_le_bytes());
        slot[12..16].copy_from_slice(&record.status.to_le_bytes());
        let name_start = 16;
        let name_end = name_start + XATTR_NAME_MAX;
        slot[name_start..name_end].copy_from_slice(&record.name);
        let value_start = name_end;
        let value_end = value_start + XATTR_VALUE_MAX;
        slot[value_start..value_end].copy_from_slice(&record.value);
    }

    Ok(())
}

pub(crate) fn parse_label(superblock: &[u8]) -> String {
    let bytes =
        &superblock[SUPERBLOCK_LABEL_OFFSET..SUPERBLOCK_LABEL_OFFSET + SUPERBLOCK_LABEL_LEN];
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    // NOTE(utf-8): same lossy-round-trip caveat as directory entry names above.
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

pub(crate) fn validate_loaded_metadata(
    inodes: &[OnDiskInode],
    dir_entries: &[OnDiskDirEntry],
    format_version: SimpleFsFormatVersion,
    data_block_start: usize,
    device_block_count: usize,
    case_sensitive: bool,
) -> Result<()> {
    // Reject any on-disk image that does not describe a rooted tree with
    // bounded extents, valid directory slices, and exactly one live parent for
    // every non-root inode.
    let root = inodes.first().ok_or(Error::InvalidArgument)?;
    if root.deleted || root.kind != NodeKind::Directory {
        return Err(Error::InvalidArgument);
    }

    let mut live_file_extents = Vec::new();
    let mut live_dir_entry_coverage = vec![0_usize; dir_entries.len()];

    for inode in inodes {
        if inode.kind == NodeKind::Directory {
            let entry_start = inode.entry_start as usize;
            let entry_count = inode.entry_count as usize;
            let entry_end = entry_start
                .checked_add(entry_count)
                .ok_or(Error::InvalidArgument)?;
            if entry_end > dir_entries.len() {
                return Err(Error::InvalidArgument);
            }

            if inode.deleted {
                continue;
            }

            let entries = &dir_entries[entry_start..entry_end];
            for left in 0..entries.len() {
                for right in (left + 1)..entries.len() {
                    if names_match(
                        entries[left].name.as_str(),
                        entries[right].name.as_str(),
                        case_sensitive,
                    ) {
                        return Err(Error::InvalidArgument);
                    }
                }
            }
            for slot in &mut live_dir_entry_coverage[entry_start..entry_end] {
                *slot = slot.checked_add(1).ok_or(Error::InvalidArgument)?;
            }
            continue;
        }

        let size = inode.size as usize;
        let block_count = inode.block_count as usize;
        if block_count == 0 {
            // Symlinks may store their target inline in the inode fields
            // (entry_start + entry_count + data_block) with block_count == 0
            // and a non-zero size indicating the target length.
            if !inode.deleted && size != 0 && inode.kind != NodeKind::Symlink {
                return Err(Error::InvalidArgument);
            }
            continue;
        }

        if !inode.deleted {
            let data_block = inode.data_block as usize;
            if data_block < data_block_start {
                return Err(Error::InvalidArgument);
            }

            let data_end = data_block
                .checked_add(block_count)
                .ok_or(Error::InvalidArgument)?;
            if data_end > device_block_count {
                return Err(Error::InvalidArgument);
            }

            let capacity = block_count
                .checked_mul(BLOCK_SIZE)
                .ok_or(Error::InvalidArgument)?;
            if size > capacity {
                return Err(Error::InvalidArgument);
            }

            live_file_extents.push((data_block, data_end));
        }
    }

    live_file_extents.sort_unstable_by_key(|(start, _)| *start);
    for pair in live_file_extents.windows(2) {
        let previous_end = pair[0].1;
        let next_start = pair[1].0;
        if previous_end > next_start {
            return Err(Error::InvalidArgument);
        }
    }

    if live_dir_entry_coverage.iter().any(|count| *count != 1) {
        return Err(Error::InvalidArgument);
    }

    let mut parent_ref_counts = vec![0_usize; inodes.len()];
    for entry in dir_entries {
        validate_dir_entry_name_for_format(entry.name.as_str(), format_version)?;
        let child_index = entry.inode_index as usize;
        if child_index == 0 {
            return Err(Error::InvalidArgument);
        }

        let child = inodes.get(child_index).ok_or(Error::InvalidArgument)?;
        if child.deleted {
            return Err(Error::InvalidArgument);
        }
        if entry.kind != child.kind {
            return Err(Error::InvalidArgument);
        }

        let count = parent_ref_counts
            .get_mut(child_index)
            .ok_or(Error::InvalidArgument)?;
        *count = count.checked_add(1).ok_or(Error::InvalidArgument)?;
    }

    for (index, inode) in inodes.iter().enumerate().skip(1) {
        if inode.deleted {
            continue;
        }

        if parent_ref_counts[index] != 1 {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_inode_persistent_security_descriptor(
    inode: &mut [u8],
    format_version: SimpleFsFormatVersion,
    persistent_security: Option<OnDiskPersistentSecurityDescriptor>,
) -> Result<()> {
    let Some(layout) = format_version.persistent_security_descriptor_layout() else {
        return Ok(());
    };

    let mode = persistent_security.map_or(0, |security| security.mode);
    let owner_uid = persistent_security.map_or(0, |security| security.owner_uid);
    let owner_gid = persistent_security.map_or(0, |security| security.owner_gid);

    let mode_end = layout
        .mode_offset
        .checked_add(2)
        .ok_or(Error::InvalidArgument)?;
    let owner_uid_end = layout
        .owner_uid_offset
        .checked_add(4)
        .ok_or(Error::InvalidArgument)?;
    let owner_gid_end = layout
        .owner_gid_offset
        .checked_add(4)
        .ok_or(Error::InvalidArgument)?;
    inode
        .get_mut(layout.mode_offset..mode_end)
        .ok_or(Error::InvalidArgument)?;
    inode
        .get_mut(layout.owner_uid_offset..owner_uid_end)
        .ok_or(Error::InvalidArgument)?;
    inode
        .get_mut(layout.owner_gid_offset..owner_gid_end)
        .ok_or(Error::InvalidArgument)?;

    write_u16(inode, layout.mode_offset, mode);
    write_u32(inode, layout.owner_uid_offset, owner_uid);
    write_u32(inode, layout.owner_gid_offset, owner_gid);
    Ok(())
}

pub(crate) fn count_unreferenced_data_blocks(
    data_start: usize,
    total_blocks: usize,
    inodes: &[OnDiskInode],
) -> usize {
    let max_referenced = inodes
        .iter()
        .filter(|inode| !inode.deleted && inode.block_count > 0)
        .map(|inode| (inode.data_block as usize).saturating_add(inode.block_count as usize))
        .max()
        .unwrap_or(data_start);

    if max_referenced <= data_start {
        return 0;
    }

    let scan_blocks = max_referenced.saturating_sub(data_start);
    let mut referenced = alloc::vec![false; scan_blocks];

    for inode in inodes {
        if inode.deleted || inode.block_count == 0 {
            continue;
        }
        let start = inode.data_block as usize;
        let end = start.saturating_add(inode.block_count as usize);
        if start < data_start || end > total_blocks {
            continue;
        }
        let rel_start = start.saturating_sub(data_start);
        let rel_end = end.saturating_sub(data_start).min(scan_blocks);
        for slot in referenced.iter_mut().take(rel_end).skip(rel_start) {
            *slot = true;
        }
    }

    referenced.iter().filter(|&&r| !r).count()
}
