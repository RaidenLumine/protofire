//! src/kernel/fs/partition.rs
//!
//! Partition table parsing and writing helpers, including MBR support.

use super::block::{BlockDevice, BLOCK_SIZE};
use crate::{Error, Result};

pub const MBR_PARTITION_COUNT: usize = 4;

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

#[cfg(test)]
mod tests {
    use super::{
        read_mbr_partitions, write_mbr_partitions, MbrPartitionEntry, MbrPartitionTable,
        MBR_SIGNATURE_OFFSET,
    };
    use crate::kernel::fs::block::{MemoryBlockDevice, BLOCK_SIZE};
    use crate::Error;

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
