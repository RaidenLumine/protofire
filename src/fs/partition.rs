//! src/fs/partition.rs
//!
//! Partition table parsing and writing helpers: MBR, which is the table this
//! kernel's own disks carry, and GPT, which is the table a machine's disk
//! carries ([RFC
//! 0018](../../docs/rfcs/0018-read-a-disk-whose-table-is-gpt.md)).

use alloc::vec;
use alloc::vec::Vec;

use super::block::BlockDevice;
use super::block::BLOCK_SIZE;
use super::layout::StorageZone;
use super::vfs::crc32;
use crate::Error;
use crate::Result;

pub const MBR_PARTITION_COUNT: usize = 4;

/// The MBR slots the two system volumes live in.  A is the slot the layout has
/// always used, so a disk built before the pair existed is a disk with only A,
/// and B is the fourth slot — the one a second system volume was given.
pub const MBR_SYSTEM_SLOT_A: usize = 0;
pub const MBR_SYSTEM_SLOT_B: usize = 3;

const MBR_PARTITION_TABLE_OFFSET: usize = 446;
const MBR_PARTITION_ENTRY_SIZE: usize = 16;
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xaa];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartitionEntry {
    pub bootable: bool,
    pub partition_type: u8,
    pub start_block: u64,
    pub block_count: u64,
}

impl MbrPartitionEntry {
    pub const fn new(
        bootable: bool,
        partition_type: u8,
        start_block: u64,
        block_count: u64,
    ) -> Self {
        Self {
            bootable,
            partition_type,
            start_block,
            block_count,
        }
    }
}

pub type MbrPartitionTable = [Option<MbrPartitionEntry>; MBR_PARTITION_COUNT];

pub fn read_mbr_partitions(device: &dyn BlockDevice) -> Result<Option<MbrPartitionTable>> {
    if device.block_size() != BLOCK_SIZE || device.block_count() == 0 {
        return Ok(None);
    }

    let mut sector = [0_u8; BLOCK_SIZE];
    device.read_blocks(0, &mut sector)?;

    if sector[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + MBR_SIGNATURE.len()] != MBR_SIGNATURE {
        return Ok(None);
    }

    let mut table: MbrPartitionTable = [None; MBR_PARTITION_COUNT];
    #[allow(clippy::needless_range_loop)]
    for index in 0..MBR_PARTITION_COUNT {
        let offset = MBR_PARTITION_TABLE_OFFSET + index * MBR_PARTITION_ENTRY_SIZE;
        let entry = &sector[offset..offset + MBR_PARTITION_ENTRY_SIZE];

        // An entry is present when either the boot flag or the type byte is
        // non-zero; an all-zero entry is unused.
        if entry[0] == 0 && entry[4] == 0 {
            continue;
        }

        let start_block = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
        let block_count = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as u64;
        table[index] = Some(MbrPartitionEntry {
            bootable: entry[0] == 0x80,
            partition_type: entry[4],
            start_block,
            block_count,
        });
    }

    Ok(Some(table))
}

pub fn write_mbr_partitions(sector: &mut [u8], partitions: &MbrPartitionTable) -> Result<()> {
    if sector.len() < BLOCK_SIZE {
        return Err(Error::InvalidArgument);
    }

    sector[..BLOCK_SIZE].fill(0);

    for (index, partition) in partitions.iter().enumerate() {
        let Some(partition) = partition else {
            continue;
        };

        let start_block =
            u32::try_from(partition.start_block).map_err(|_| Error::InvalidArgument)?;
        let block_count =
            u32::try_from(partition.block_count).map_err(|_| Error::InvalidArgument)?;

        let offset = MBR_PARTITION_TABLE_OFFSET + index * MBR_PARTITION_ENTRY_SIZE;
        let entry = &mut sector[offset..offset + MBR_PARTITION_ENTRY_SIZE];
        entry[0] = if partition.bootable { 0x80 } else { 0x00 };
        entry[4] = partition.partition_type;
        entry[8..12].copy_from_slice(&start_block.to_le_bytes());
        entry[12..16].copy_from_slice(&block_count.to_le_bytes());
    }

    sector[MBR_SIGNATURE_OFFSET] = MBR_SIGNATURE[0];
    sector[MBR_SIGNATURE_OFFSET + 1] = MBR_SIGNATURE[1];
    Ok(())
}

// ── GPT ─────────────────────────────────────────────────────────────────

/// The type byte a protective MBR's first entry carries: "the real table is the
/// GPT, and this entry describes the whole disk so that a reader which knows
/// only MBR leaves it alone".
const MBR_PROTECTIVE_TYPE: u8 = 0xEE;

/// The GPT header's signature, at the header's own first byte.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// Where the primary GPT header is: LBA 1, and the backup is looked for in
/// neither this file nor any other yet.
const GPT_HEADER_LBA: u64 = 1;

/// The header's own fields, at the offsets the format gives them.
const GPT_HEADER_SIZE_OFFSET: usize = 12;
const GPT_HEADER_CRC_OFFSET: usize = 16;
const GPT_ENTRIES_LBA_OFFSET: usize = 72;
const GPT_ENTRY_COUNT_OFFSET: usize = 80;
const GPT_ENTRY_SIZE_OFFSET: usize = 84;
const GPT_ENTRIES_CRC_OFFSET: usize = 88;

/// How long a header may say it is.  The format's own header is 92 bytes; the
/// bound keeps a disk's claim from making the reader index past the sector it
/// read.
const GPT_HEADER_SIZE_MIN: usize = 92;

/// The smallest entry the format defines.  A table may use a larger one — the
/// format says a power of two times this — and the stride is what is read.
const GPT_ENTRY_SIZE_MIN: usize = 128;

/// The largest entry the format's readers accept, so the bound below is about
/// the disk rather than about this kernel's arithmetic.
const GPT_ENTRY_SIZE_MAX: usize = 4096;

/// How many entries the images this tree writes carry: the format's usual
/// table.
const GPT_ENTRY_COUNT: usize = 128;

/// The blocks a GPT reserves at each end of a disk: the header and the entry
/// array, whose usual array is 32 blocks.  A disk whose zones reach its last
/// block cannot hold the backup copy, which is a size the writer has to plan
/// for rather than a check to fail.
pub const GPT_RESERVED_BLOCKS: u64 = 33;

/// How much of a table a boot will read.  The usual table is 128 entries of
/// 128 bytes — 16 KiB — and this bound is four times that, so no disk's own
/// header can make the boot read a volume's worth of entries.
const GPT_ENTRIES_MAX_BYTES: usize = 64 * 1024;

/// A GPT partition, as one entry of its array describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPartitionEntry {
    /// The type GUID, in the bytes the entry holds.
    pub type_guid: [u8; 16],
    /// The partition's first and last block, inclusive.
    pub first_lba: u64,
    pub last_lba: u64,
    /// The entry's attribute bits, carried because they are the entry's: bit 0
    /// is "required", which is what a reader of a machine's own table wants.
    pub attributes: u64,
}

impl GptPartitionEntry {
    /// Whether nothing is here: an entry whose type GUID is all zero is unused.
    pub fn is_unused(&self) -> bool {
        self.type_guid == [0_u8; 16]
    }

    /// How many blocks the partition covers.
    pub const fn block_count(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

/// One partition, whichever table described it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    pub start_block: u64,
    pub block_count: u64,
    pub kind: PartitionKind,
}

/// What a table says a partition *is*, in that table's own vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionKind {
    Mbr {
        partition_type: u8,
        bootable: bool,
    },
    Gpt {
        type_guid: [u8; 16],
        attributes: u64,
    },
}

/// The partition table a disk carries, in the shape that read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionTable {
    Mbr(MbrPartitionTable),
    Gpt(Vec<GptPartitionEntry>),
}

impl PartitionTable {
    /// The name of the table, for a boot's own line about what it mounted.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Mbr(_) => "MBR",
            Self::Gpt(_) => "GPT",
        }
    }

    /// The partitions of `zone`, in the order the table holds them.
    ///
    /// The two tables answer this differently because the two tables *are*
    /// different.  MBR identifies a zone by the slot its
    /// [`partition_slot`](../layout/struct.StorageZone.html) names — the
    /// convention the disk's own builder wrote — and the system pair is the
    /// two slots [`MBR_SYSTEM_SLOT_A`]/[`MBR_SYSTEM_SLOT_B`].  GPT identifies a
    /// zone by its **type GUID**, because a GPT is the table a *foreign*
    /// machine's disk carries and an index on such a disk is the machine's
    /// choice rather than this kernel's: the system pair is the first two
    /// entries of the system zone's type, in order.
    pub fn zone_partitions(&self, zone: StorageZone) -> Vec<(usize, Partition)> {
        match self {
            Self::Mbr(table) => {
                let slots: &[usize] = if zone == StorageZone::System {
                    &[MBR_SYSTEM_SLOT_A, MBR_SYSTEM_SLOT_B]
                } else {
                    &[]
                };
                if !slots.is_empty() {
                    let mut found = Vec::new();
                    for &slot in slots {
                        if let Some(partition) = table.get(slot).and_then(|entry| *entry) {
                            found.push((slot, mbr_partition(partition)));
                        }
                    }
                    return found;
                }
                let slot = zone.partition_slot();
                table
                    .get(slot)
                    .and_then(|entry| *entry)
                    .map(|partition| (slot, mbr_partition(partition)))
                    .into_iter()
                    .collect()
            }
            Self::Gpt(entries) => {
                let wanted = zone.gpt_type_guid();
                let mut found = Vec::new();
                for (slot, entry) in entries.iter().enumerate() {
                    if entry.is_unused() || entry.type_guid != wanted {
                        continue;
                    }
                    found.push((
                        slot,
                        Partition {
                            start_block: entry.first_lba,
                            block_count: entry.block_count(),
                            kind: PartitionKind::Gpt {
                                type_guid: entry.type_guid,
                                attributes: entry.attributes,
                            },
                        },
                    ));
                    // The system zone is a pair and every other zone is one
                    // partition; a third of the system's type is a partition
                    // this kernel has no name for.
                    if zone != StorageZone::System {
                        break;
                    }
                    if found.len() == 2 {
                        break;
                    }
                }
                found
            }
        }
    }

    /// The system pair, in slot order.
    pub fn system_partitions(&self) -> Vec<(usize, Partition)> {
        self.zone_partitions(StorageZone::System)
    }
}

fn mbr_partition(partition: MbrPartitionEntry) -> Partition {
    Partition {
        start_block: partition.start_block,
        block_count: partition.block_count,
        kind: PartitionKind::Mbr {
            partition_type: partition.partition_type,
            bootable: partition.bootable,
        },
    }
}

/// The partition table `device` carries, or `None` when it carries none this
/// kernel reads.
///
/// A **protective** MBR is the case worth naming: its one entry is a promise
/// that the real table is the GPT, not a description of a partition, so a disk
/// whose GPT cannot be read answers `None` rather than "one partition, the
/// whole disk" — the answer that used to become a system slot
/// ([RFC 0018](../../docs/rfcs/0018-read-a-disk-whose-table-is-gpt.md)).
pub fn read_partitions(device: &dyn BlockDevice) -> Result<Option<PartitionTable>> {
    if protective_mbr(device)? {
        return Ok(read_gpt_partitions(device)?.map(PartitionTable::Gpt));
    }
    Ok(read_mbr_partitions(device)?.map(PartitionTable::Mbr))
}

/// Whether LBA 0 is a protective MBR: the format's signature, and a first
/// entry that is the protective type and starts where the GPT's header lives.
fn protective_mbr(device: &dyn BlockDevice) -> Result<bool> {
    if device.block_size() != BLOCK_SIZE || device.block_count() == 0 {
        return Ok(false);
    }

    let mut sector = [0_u8; BLOCK_SIZE];
    device.read_blocks(0, &mut sector)?;

    let signature = &sector[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + MBR_SIGNATURE.len()];
    let entry = &sector[MBR_PARTITION_TABLE_OFFSET..MBR_PARTITION_TABLE_OFFSET + 16];
    let first_lba = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
    Ok(signature == MBR_SIGNATURE.as_slice()
        && entry[4] == MBR_PROTECTIVE_TYPE
        && first_lba == GPT_HEADER_LBA)
}

/// The GPT `device` carries, or `None` when there is none to read.
///
/// Both of the format's checksums are verified — the header's over the header
/// with its own CRC field taken as zero, and the array's over the entries as
/// they lie — because the alternative is handing a caller offsets out of bytes
/// nobody vouched for, and a volume mounted at the wrong offset is the one
/// failure a filesystem cannot report.
pub fn read_gpt_partitions(device: &dyn BlockDevice) -> Result<Option<Vec<GptPartitionEntry>>> {
    if device.block_size() != BLOCK_SIZE || device.block_count() <= GPT_HEADER_LBA {
        return Ok(None);
    }

    let mut header = [0_u8; BLOCK_SIZE];
    device.read_blocks(GPT_HEADER_LBA, &mut header)?;
    if &header[..GPT_SIGNATURE.len()] != GPT_SIGNATURE {
        return Ok(None);
    }

    let header_size = u32::from_le_bytes(
        header[GPT_HEADER_SIZE_OFFSET..GPT_HEADER_SIZE_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if !(GPT_HEADER_SIZE_MIN..=BLOCK_SIZE).contains(&header_size) {
        return Ok(None);
    }

    let stated_crc = u32::from_le_bytes(
        header[GPT_HEADER_CRC_OFFSET..GPT_HEADER_CRC_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let mut checked = header;
    checked[GPT_HEADER_CRC_OFFSET..GPT_HEADER_CRC_OFFSET + 4].fill(0);
    if crc32(&checked[..header_size]) != stated_crc {
        return Ok(None);
    }

    let entries_lba = u64::from_le_bytes(
        header[GPT_ENTRIES_LBA_OFFSET..GPT_ENTRIES_LBA_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let count = u32::from_le_bytes(
        header[GPT_ENTRY_COUNT_OFFSET..GPT_ENTRY_COUNT_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let entry_size = u32::from_le_bytes(
        header[GPT_ENTRY_SIZE_OFFSET..GPT_ENTRY_SIZE_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let stated_crc = u32::from_le_bytes(
        header[GPT_ENTRIES_CRC_OFFSET..GPT_ENTRIES_CRC_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    if count == 0 || !(GPT_ENTRY_SIZE_MIN..=GPT_ENTRY_SIZE_MAX).contains(&entry_size) {
        return Ok(None);
    }
    let array_bytes = count * entry_size;
    if array_bytes > GPT_ENTRIES_MAX_BYTES {
        return Ok(None);
    }

    // The array is read in whole blocks, since that is what a device answers;
    // the checksum covers the entries and not the padding after them.
    let blocks = array_bytes.div_ceil(BLOCK_SIZE);
    let mut raw = vec![0_u8; blocks * BLOCK_SIZE];
    device.read_blocks(entries_lba, &mut raw)?;
    if crc32(&raw[..array_bytes]) != stated_crc {
        return Ok(None);
    }

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let at = index * entry_size;
        let entry = &raw[at..at + entry_size];
        let mut type_guid = [0_u8; 16];
        type_guid.copy_from_slice(&entry[..16]);
        entries.push(GptPartitionEntry {
            type_guid,
            first_lba: u64::from_le_bytes(entry[32..40].try_into().unwrap()),
            last_lba: u64::from_le_bytes(entry[40..48].try_into().unwrap()),
            attributes: u64::from_le_bytes(entry[48..56].try_into().unwrap()),
        });
    }

    Ok(Some(entries))
}

/// Write a GPT over `disk`, with the partitions given as
/// `(slot, type GUID, first block, block count)`.
///
/// This is the **host tool's** half of RFC 0018 — the kernel reads a table, and
/// the thing that makes a disk bootable is the tool that wrote its GUIDs — so
/// it writes what a reader checks: the protective MBR, the entry array and its
/// checksum in both copies, the primary header at LBA 1 and the backup at the
/// last block, each with its own checksum over itself.
pub fn write_gpt_partitions(
    disk: &mut [u8],
    partitions: &[(usize, [u8; 16], u64, u64)],
) -> Result<()> {
    if disk.len() < BLOCK_SIZE {
        return Err(Error::InvalidArgument);
    }

    let total_blocks = (disk.len() / BLOCK_SIZE) as u64;
    // The format's own minimum: a header and an entry array at each end.
    if total_blocks < 2 * GPT_RESERVED_BLOCKS + 1 {
        return Err(Error::InvalidArgument);
    }
    let last_block = total_blocks - 1;

    // The protective MBR: the format's signature, and one entry of the
    // protective type covering the disk from the header's own LBA.  The rest of
    // the sector is zeroed, because a boot sector that keeps an old table is a
    // boot sector a reader may believe.
    disk[..BLOCK_SIZE].fill(0);
    disk[MBR_SIGNATURE_OFFSET] = MBR_SIGNATURE[0];
    disk[MBR_SIGNATURE_OFFSET + 1] = MBR_SIGNATURE[1];
    let covered = u32::try_from(last_block.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
    let protective = &mut disk[MBR_PARTITION_TABLE_OFFSET..MBR_PARTITION_TABLE_OFFSET + 16];
    protective[4] = MBR_PROTECTIVE_TYPE;
    protective[8..12].copy_from_slice(&(GPT_HEADER_LBA as u32).to_le_bytes());
    protective[12..16].copy_from_slice(&covered.to_le_bytes());

    // The entry array, in the block after the header.
    let entries_lba = GPT_HEADER_LBA + 1;
    let array_bytes = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE_MIN;
    let array_blocks = array_bytes / BLOCK_SIZE;
    let backup_entries_lba = last_block - array_blocks as u64;

    let mut array = vec![0_u8; array_bytes];
    for &(slot, type_guid, first_block, block_count) in partitions {
        if slot >= GPT_ENTRY_COUNT || block_count == 0 {
            return Err(Error::InvalidArgument);
        }
        let last = first_block + block_count - 1;
        if last > backup_entries_lba {
            return Err(Error::InvalidArgument);
        }
        let at = slot * GPT_ENTRY_SIZE_MIN;
        array[at..at + 16].copy_from_slice(&type_guid);
        array[at + 32..at + 40].copy_from_slice(&first_block.to_le_bytes());
        array[at + 40..at + 48].copy_from_slice(&last.to_le_bytes());
    }
    let array_crc = crc32(&array);

    let primary_at = entries_lba as usize * BLOCK_SIZE;
    disk[primary_at..primary_at + array_bytes].copy_from_slice(&array);
    let backup_at = backup_entries_lba as usize * BLOCK_SIZE;
    disk[backup_at..backup_at + array_bytes].copy_from_slice(&array);

    let last_usable_lba = backup_entries_lba - 1;
    let header = gpt_header(
        GPT_HEADER_LBA,
        last_block,
        entries_lba,
        array_crc,
        last_usable_lba,
    );
    let at = GPT_HEADER_LBA as usize * BLOCK_SIZE;
    disk[at..at + BLOCK_SIZE].copy_from_slice(&header);
    let backup = gpt_header(
        last_block,
        GPT_HEADER_LBA,
        backup_entries_lba,
        array_crc,
        last_usable_lba,
    );
    let at = last_block as usize * BLOCK_SIZE;
    disk[at..at + BLOCK_SIZE].copy_from_slice(&backup);

    Ok(())
}

/// One GPT header, checksummed the way [`read_gpt_partitions`] verifies it: the
/// CRC covers the header with its own CRC field taken as zero.
fn gpt_header(
    my_lba: u64,
    alternate_lba: u64,
    entries_lba: u64,
    entries_crc: u32,
    last_usable_lba: u64,
) -> [u8; BLOCK_SIZE] {
    let mut header = [0_u8; BLOCK_SIZE];
    header[..GPT_SIGNATURE.len()].copy_from_slice(GPT_SIGNATURE);
    // Revision 1.0, and the 92-byte header the format defines.
    header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
    header[12..16].copy_from_slice(&(GPT_HEADER_SIZE_MIN as u32).to_le_bytes());
    header[24..32].copy_from_slice(&my_lba.to_le_bytes());
    header[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    // What a partition may use: everything between the two reserved ends, which
    // is the same span in both copies of the header.
    header[40..48].copy_from_slice(&(GPT_RESERVED_BLOCKS + 1).to_le_bytes());
    header[48..56].copy_from_slice(&last_usable_lba.to_le_bytes());
    // A disk GUID of this tree's own; nothing prints it, and the format only
    // wants it to be a GUID.
    header[56..72].copy_from_slice(&[
        0x50, 0x52, 0x54, 0x4f, 0x46, 0x49, 0x52, 0x45, 0x00, 0x00, 0x44, 0x69, 0x73, 0x6b, 0x00,
        0x00,
    ]);
    header[GPT_ENTRIES_LBA_OFFSET..GPT_ENTRIES_LBA_OFFSET + 8]
        .copy_from_slice(&entries_lba.to_le_bytes());
    header[GPT_ENTRY_COUNT_OFFSET..GPT_ENTRY_COUNT_OFFSET + 4]
        .copy_from_slice(&(GPT_ENTRY_COUNT as u32).to_le_bytes());
    header[GPT_ENTRY_SIZE_OFFSET..GPT_ENTRY_SIZE_OFFSET + 4]
        .copy_from_slice(&(GPT_ENTRY_SIZE_MIN as u32).to_le_bytes());
    header[GPT_ENTRIES_CRC_OFFSET..GPT_ENTRIES_CRC_OFFSET + 4]
        .copy_from_slice(&entries_crc.to_le_bytes());

    let crc = crc32(&header[..GPT_HEADER_SIZE_MIN]);
    header[GPT_HEADER_CRC_OFFSET..GPT_HEADER_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
    header
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::crc32;
    use super::read_mbr_partitions;
    use super::read_partitions;
    use super::write_mbr_partitions;
    use super::MbrPartitionEntry;
    use super::MbrPartitionTable;
    use super::PartitionTable;
    use super::BLOCK_SIZE;
    use super::GPT_ENTRIES_CRC_OFFSET;
    use super::GPT_ENTRIES_LBA_OFFSET;
    use super::GPT_ENTRY_COUNT_OFFSET;
    use super::GPT_ENTRY_SIZE_OFFSET;
    use super::GPT_HEADER_CRC_OFFSET;
    use super::GPT_HEADER_LBA;
    use super::GPT_SIGNATURE;
    use super::MBR_PARTITION_TABLE_OFFSET;
    use super::MBR_PROTECTIVE_TYPE;
    use super::MBR_SIGNATURE_OFFSET;
    use crate::fs::block::MemoryBlockDevice;
    use crate::fs::layout::StorageZone;
    use crate::Error;

    /// How many blocks a test image has.  The format's usual minimum is 34 —
    /// the protective MBR, the header, and 32 blocks of entries — and this
    /// leaves room for the backup header a real tool would write.
    const IMAGE_BLOCKS: usize = 40;
    /// Where a test's entry array starts, in blocks.
    const ENTRIES_LBA: u64 = 2;
    /// The format's usual table: 128 entries of 128 bytes.
    const ENTRIES: usize = 128;
    const ENTRY_SIZE: usize = 128;

    /// A GPT image built byte by byte, with both checksums computed the way the
    /// format says: the header's over the header with its own CRC field zero,
    /// the array's over the entries as they lie.
    fn gpt_image(partitions: &[(usize, [u8; 16], u64, u64)]) -> Vec<u8> {
        let mut image = vec![0_u8; IMAGE_BLOCKS * BLOCK_SIZE];

        // The protective MBR: the format's signature and one entry of the
        // protective type covering the disk from the header's own LBA.
        image[MBR_SIGNATURE_OFFSET] = 0x55;
        image[MBR_SIGNATURE_OFFSET + 1] = 0xaa;
        let entry = &mut image[MBR_PARTITION_TABLE_OFFSET..MBR_PARTITION_TABLE_OFFSET + 16];
        entry[4] = MBR_PROTECTIVE_TYPE;
        entry[8..12].copy_from_slice(&(GPT_HEADER_LBA as u32).to_le_bytes());
        entry[12..16].copy_from_slice(&((IMAGE_BLOCKS - 1) as u32).to_le_bytes());

        // The entries.
        let mut array = vec![0_u8; ENTRIES * ENTRY_SIZE];
        let mut highest = 0_u64;
        for &(slot, type_guid, first_lba, last_lba) in partitions {
            let at = slot * ENTRY_SIZE;
            array[at..at + 16].copy_from_slice(&type_guid);
            array[at + 32..at + 40].copy_from_slice(&first_lba.to_le_bytes());
            array[at + 40..at + 48].copy_from_slice(&last_lba.to_le_bytes());
            highest = highest.max(last_lba);
        }
        let array_crc = crc32(&array);
        let array_blocks = array.len() / BLOCK_SIZE;
        let array_at = ENTRIES_LBA as usize * BLOCK_SIZE;
        image[array_at..array_at + array.len()].copy_from_slice(&array);

        // The header.
        let mut header = [0_u8; BLOCK_SIZE];
        header[..GPT_SIGNATURE.len()].copy_from_slice(GPT_SIGNATURE);
        header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
        header[12..16].copy_from_slice(&92_u32.to_le_bytes());
        header[24..32].copy_from_slice(&GPT_HEADER_LBA.to_le_bytes());
        header[32..40].copy_from_slice(&((IMAGE_BLOCKS - 1) as u64).to_le_bytes());
        header[40..48].copy_from_slice(&(ENTRIES_LBA + array_blocks as u64).to_le_bytes());
        header[48..56].copy_from_slice(&highest.to_le_bytes());
        header[GPT_ENTRIES_LBA_OFFSET..GPT_ENTRIES_LBA_OFFSET + 8]
            .copy_from_slice(&ENTRIES_LBA.to_le_bytes());
        header[GPT_ENTRY_COUNT_OFFSET..GPT_ENTRY_COUNT_OFFSET + 4]
            .copy_from_slice(&(ENTRIES as u32).to_le_bytes());
        header[GPT_ENTRY_SIZE_OFFSET..GPT_ENTRY_SIZE_OFFSET + 4]
            .copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
        header[GPT_ENTRIES_CRC_OFFSET..GPT_ENTRIES_CRC_OFFSET + 4]
            .copy_from_slice(&array_crc.to_le_bytes());
        let header_crc = crc32(&header[..92]);
        header[GPT_HEADER_CRC_OFFSET..GPT_HEADER_CRC_OFFSET + 4]
            .copy_from_slice(&header_crc.to_le_bytes());
        image[BLOCK_SIZE..2 * BLOCK_SIZE].copy_from_slice(&header);

        image
    }

    fn gpt_device(partitions: &[(usize, [u8; 16], u64, u64)]) -> Arc<MemoryBlockDevice> {
        MemoryBlockDevice::new("test-gpt", gpt_image(partitions), true)
    }

    /// The zones of a GPT disk are found by their **type GUID**, in the array's
    /// own order — never by index, which on a machine's disk belongs to the
    /// machine.
    #[test]
    fn a_gpt_disk_answers_its_zones_by_type_guid() {
        let device = gpt_device(&[
            (1, StorageZone::Apps.gpt_type_guid(), 2048, 4095),
            (4, StorageZone::Data.gpt_type_guid(), 8192, 12287),
            (7, StorageZone::System.gpt_type_guid(), 4096, 8191),
        ]);

        let table = read_partitions(device.as_ref()).unwrap().expect("a GPT");
        assert_eq!(table.label(), "GPT");

        let system = table.system_partitions();
        assert_eq!(system.len(), 1, "one system volume on this disk");
        assert_eq!(system[0].0, 7, "at the slot the array put it in");
        assert_eq!(system[0].1.start_block, 4096);
        assert_eq!(system[0].1.block_count, 4096);

        let apps = table.zone_partitions(StorageZone::Apps);
        assert_eq!(apps.len(), 1);
        assert_eq!((apps[0].0, apps[0].1.start_block), (1, 2048));
        let data = table.zone_partitions(StorageZone::Data);
        assert_eq!((data[0].0, data[0].1.start_block), (4, 8192));

        // The entry's own words come through: the type GUID it declared, and
        // the attributes beside it.
        assert!(matches!(
            apps[0].1.kind,
            super::PartitionKind::Gpt { type_guid, .. }
                if type_guid == StorageZone::Apps.gpt_type_guid()
        ));

        // And a zone whose GUID is not on the disk is not on the disk: the
        // parse answers what it read rather than what it expected.
        assert!(table.zone_partitions(StorageZone::Data).len() == 1);
    }

    /// A GPT whose pairs are somewhere else entirely: the two system volumes
    /// are the first two of the system type, in the array's order.
    #[test]
    fn a_gpt_system_pair_is_the_two_of_its_type_in_order() {
        let device = gpt_device(&[
            (2, StorageZone::System.gpt_type_guid(), 4096, 8191),
            (9, StorageZone::System.gpt_type_guid(), 8192, 12287),
        ]);

        let table = read_partitions(device.as_ref()).unwrap().expect("a GPT");
        let system = table.system_partitions();
        assert_eq!(system.len(), 2);
        assert_eq!(system[0].0, 2);
        assert_eq!(system[1].0, 9);
    }

    /// A partition the type GUID does not name is not a zone, whatever its type
    /// is: the disk is read as what it says it is.
    #[test]
    fn a_foreign_type_guid_is_no_zone() {
        let device = gpt_device(&[(
            0,
            [
                0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e,
                0xc9, 0x3b,
            ],
            2048,
            4095,
        )]);

        let table = read_partitions(device.as_ref()).unwrap().expect("a GPT");
        assert_eq!(table.label(), "GPT");
        for zone in [StorageZone::System, StorageZone::Apps, StorageZone::Data] {
            assert!(
                table.zone_partitions(zone).is_empty(),
                "an EFI system partition is not a zone of this kernel's"
            );
        }
    }

    /// Every way a GPT can be unreadable answers "no table" — and never the MBR
    /// view, whose only entry is the whole disk.
    #[test]
    fn a_protective_mbr_that_leads_nowhere_is_not_a_partition() {
        // A protective MBR over zeros: there is no header at all.
        let mut image = vec![0_u8; IMAGE_BLOCKS * BLOCK_SIZE];
        image[MBR_SIGNATURE_OFFSET] = 0x55;
        image[MBR_SIGNATURE_OFFSET + 1] = 0xaa;
        let entry = &mut image[MBR_PARTITION_TABLE_OFFSET..MBR_PARTITION_TABLE_OFFSET + 16];
        entry[4] = MBR_PROTECTIVE_TYPE;
        entry[8..12].copy_from_slice(&1u32.to_le_bytes());
        entry[12..16].copy_from_slice(&((IMAGE_BLOCKS - 1) as u32).to_le_bytes());
        let bare = MemoryBlockDevice::new("test-bare-protective", image.clone(), true);
        assert_eq!(read_partitions(bare.as_ref()).unwrap(), None);

        // A header whose signature is wrong.
        let mut broken = gpt_image(&[]);
        broken[BLOCK_SIZE] = b'X';
        let device = MemoryBlockDevice::new("test-bad-signature", broken, true);
        assert_eq!(read_partitions(device.as_ref()).unwrap(), None);

        // A header whose own checksum does not hold.
        let mut broken = gpt_image(&[]);
        let crc = u32::from_le_bytes(
            broken[BLOCK_SIZE + GPT_HEADER_CRC_OFFSET..BLOCK_SIZE + GPT_HEADER_CRC_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        broken[BLOCK_SIZE + GPT_HEADER_CRC_OFFSET..BLOCK_SIZE + GPT_HEADER_CRC_OFFSET + 4]
            .copy_from_slice(&crc.wrapping_add(1).to_le_bytes());
        let device = MemoryBlockDevice::new("test-bad-header-crc", broken, true);
        assert_eq!(read_partitions(device.as_ref()).unwrap(), None);

        // And one whose entries do not.
        let mut broken = gpt_image(&[(0, StorageZone::Data.gpt_type_guid(), 2048, 4095)]);
        let at = ENTRIES_LBA as usize * BLOCK_SIZE + 32;
        broken[at] ^= 0xff;
        let device = MemoryBlockDevice::new("test-bad-array-crc", broken, true);
        assert_eq!(read_partitions(device.as_ref()).unwrap(), None);

        // An entry size the format does not define.
        let mut broken = gpt_image(&[]);
        broken[BLOCK_SIZE + GPT_ENTRY_SIZE_OFFSET..BLOCK_SIZE + GPT_ENTRY_SIZE_OFFSET + 4]
            .copy_from_slice(&64_u32.to_le_bytes());
        let device = MemoryBlockDevice::new("test-small-entries", broken, true);
        assert_eq!(read_partitions(device.as_ref()).unwrap(), None);

        // A table bigger than a boot will read: 4096 entries of 4096 bytes.
        let mut broken = gpt_image(&[]);
        broken[BLOCK_SIZE + GPT_ENTRY_COUNT_OFFSET..BLOCK_SIZE + GPT_ENTRY_COUNT_OFFSET + 4]
            .copy_from_slice(&4096_u32.to_le_bytes());
        broken[BLOCK_SIZE + GPT_ENTRY_SIZE_OFFSET..BLOCK_SIZE + GPT_ENTRY_SIZE_OFFSET + 4]
            .copy_from_slice(&4096_u32.to_le_bytes());
        let device = MemoryBlockDevice::new("test-huge-table", broken, true);
        assert_eq!(read_partitions(device.as_ref()).unwrap(), None);
    }

    /// The writer and the reader are held to each other: a GPT this tree writes
    /// is a GPT this tree reads, with the zones it was given.
    #[test]
    fn a_written_gpt_reads_back_as_the_zones_it_was_given() {
        let mut image = vec![0_u8; 200 * BLOCK_SIZE];
        let given = [
            (0, StorageZone::System.gpt_type_guid(), 34, 100),
            (1, StorageZone::Apps.gpt_type_guid(), 140, 20),
            (2, StorageZone::Data.gpt_type_guid(), 160, 6),
        ];
        super::write_gpt_partitions(&mut image, &given).unwrap();

        let device = MemoryBlockDevice::new("written-gpt", image, true);
        let table = read_partitions(device.as_ref())
            .unwrap()
            .expect("a GPT this tree wrote is one it reads");
        assert_eq!(table.label(), "GPT");

        let system = table.system_partitions();
        assert_eq!(system.len(), 1, "one system volume was written");
        assert_eq!(
            (system[0].1.start_block, system[0].1.block_count),
            (34, 100)
        );
        let apps = table.zone_partitions(StorageZone::Apps);
        assert_eq!((apps[0].1.start_block, apps[0].1.block_count), (140, 20));
        let data = table.zone_partitions(StorageZone::Data);
        assert_eq!((data[0].1.start_block, data[0].1.block_count), (160, 6));

        // A disk too small to carry the two reserved ends is refused rather
        // than written half a table.
        let mut small = vec![0_u8; 16 * BLOCK_SIZE];
        assert_eq!(
            super::write_gpt_partitions(&mut small, &[]),
            Err(Error::InvalidArgument)
        );
    }

    /// An MBR disk is read exactly as it was: the same entries, and the same
    /// slots the zones have always been found at.
    #[test]
    fn an_mbr_disk_is_unaffected_by_the_table_that_is_not_there() {
        let partitions: MbrPartitionTable = [
            Some(MbrPartitionEntry::new(true, 0xa1, 2048, 100_000)),
            Some(MbrPartitionEntry::new(false, 0xa2, 102_048, 16_384)),
            Some(MbrPartitionEntry::new(false, 0xa3, 118_432, 16_384)),
            Some(MbrPartitionEntry::new(false, 0xa1, 134_816, 16_384)),
        ];
        let mut sector = [0_u8; BLOCK_SIZE];
        write_mbr_partitions(&mut sector, &partitions).unwrap();
        let device = MemoryBlockDevice::new("test-mbr", sector.to_vec(), false);

        let table = read_partitions(device.as_ref()).unwrap().expect("an MBR");
        assert_eq!(table.label(), "MBR");
        assert_eq!(table, PartitionTable::Mbr(partitions));

        // The system pair is the two slots it has always been, and the other
        // zones are their own single slots.
        let system = table.system_partitions();
        assert_eq!(
            system.iter().map(|(slot, _)| *slot).collect::<Vec<_>>(),
            vec![0, 3]
        );
        assert_eq!(
            table.zone_partitions(StorageZone::Apps)[0].0,
            StorageZone::Apps.partition_slot()
        );
        assert_eq!(
            table.zone_partitions(StorageZone::Data)[0].0,
            StorageZone::Data.partition_slot()
        );
    }

    #[test]
    fn write_mbr_rejects_short_sector_buffer() {
        let mut short_sector = [0_u8; BLOCK_SIZE - 1];
        let partitions: MbrPartitionTable = [None; 4];
        assert_eq!(
            write_mbr_partitions(&mut short_sector, &partitions),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn write_then_read_mbr_round_trips_partitions() {
        let partitions: MbrPartitionTable = [
            Some(MbrPartitionEntry::new(true, 0x83, 2048, 100_000)),
            Some(MbrPartitionEntry::new(false, 0x82, 102_048, 16_384)),
            None,
            None,
        ];

        let mut sector = [0_u8; BLOCK_SIZE];
        write_mbr_partitions(&mut sector, &partitions).unwrap();

        assert_eq!(
            &sector[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2],
            &[0x55, 0xaa]
        );

        let device = MemoryBlockDevice::new("test-mbr", sector.to_vec(), false);
        let parsed = read_mbr_partitions(device.as_ref()).unwrap().unwrap();
        assert_eq!(parsed, partitions);
    }

    #[test]
    fn read_mbr_returns_none_on_missing_signature() {
        let sector = [0_u8; BLOCK_SIZE];
        let device = MemoryBlockDevice::new("test-mbr", sector.to_vec(), false);
        assert_eq!(read_mbr_partitions(device.as_ref()).unwrap(), None);
    }

    #[test]
    fn read_mbr_skips_all_zero_entries() {
        let mut sector = [0_u8; BLOCK_SIZE];
        sector[MBR_SIGNATURE_OFFSET] = 0x55;
        sector[MBR_SIGNATURE_OFFSET + 1] = 0xaa;
        let device = MemoryBlockDevice::new("test-mbr", sector.to_vec(), false);
        let parsed = read_mbr_partitions(device.as_ref()).unwrap();
        assert_eq!(parsed, Some([None; 4]));
    }
}
