//! src/user/elf.rs
//!
//! Minimal ELF64 parsing helpers used by the user program loader.

use alloc::vec::Vec;

use crate::{Error, Result};

const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LSB: u8 = 1;
const ELF_IDENT_VERSION_CURRENT: u8 = 1;
const ELF_HEADER_VERSION_CURRENT: u32 = 1;
const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF_PROGRAM_HEADER_LOAD: u32 = 1;
const ELF_SEGMENT_EXECUTE: u32 = 1 << 0;
const ELF_SEGMENT_WRITE: u32 = 1 << 1;
const ELF_SEGMENT_READ: u32 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfSegmentFlags(u32);

impl ElfSegmentFlags {
    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn readable(self) -> bool {
        self.0 & ELF_SEGMENT_READ != 0
    }

    pub const fn writable(self) -> bool {
        self.0 & ELF_SEGMENT_WRITE != 0
    }

    pub const fn executable(self) -> bool {
        self.0 & ELF_SEGMENT_EXECUTE != 0
    }

    pub const fn as_rwx(self) -> &'static str {
        match (self.readable(), self.writable(), self.executable()) {
            (false, false, false) => "---",
            (true, false, false) => "r--",
            (false, true, false) => "-w-",
            (true, true, false) => "rw-",
            (false, false, true) => "--x",
            (true, false, true) => "r-x",
            (false, true, true) => "-wx",
            (true, true, true) => "rwx",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfLoadSegment {
    pub virtual_address: usize,
    pub file_offset: usize,
    pub file_size: usize,
    pub memory_size: usize,
    pub alignment: usize,
    pub flags: ElfSegmentFlags,
}

impl ElfLoadSegment {
    pub const fn contains(self, address: usize) -> bool {
        address >= self.virtual_address
            && address < self.virtual_address.saturating_add(self.memory_size)
    }
}

pub struct ElfImage<'a> {
    pub entry_point: usize,
    pub machine: u16,
    pub image: &'a [u8],
    program_header_offset: usize,
    program_header_entry_size: usize,
    program_header_count: usize,
}

impl<'a> ElfImage<'a> {
    pub fn load_segments(&self) -> Result<Vec<ElfLoadSegment>> {
        if self.program_header_count == 0 {
            return Ok(Vec::new());
        }

        let mut segments = Vec::new();

        for index in 0..self.program_header_count {
            let header_offset = self
                .program_header_offset
                .checked_add(
                    index
                        .checked_mul(self.program_header_entry_size)
                        .ok_or(Error::InvalidArgument)?,
                )
                .ok_or(Error::InvalidArgument)?;

            if read_u32(self.image, header_offset)? != ELF_PROGRAM_HEADER_LOAD {
                continue;
            }

            let flags = ElfSegmentFlags(read_u32(self.image, header_offset + 4)?);
            let file_offset = read_u64(self.image, header_offset + 8)? as usize;
            let virtual_address = read_u64(self.image, header_offset + 16)? as usize;
            let file_size = read_u64(self.image, header_offset + 32)? as usize;
            let memory_size = read_u64(self.image, header_offset + 40)? as usize;
            let alignment = read_u64(self.image, header_offset + 48)? as usize;

            if file_size > memory_size {
                return Err(Error::InvalidArgument);
            }

            if alignment != 0 && !alignment.is_power_of_two() {
                return Err(Error::InvalidArgument);
            }

            let file_end = file_offset
                .checked_add(file_size)
                .ok_or(Error::InvalidArgument)?;
            if file_end > self.image.len() {
                return Err(Error::InvalidArgument);
            }

            segments.push(ElfLoadSegment {
                virtual_address,
                file_offset,
                file_size,
                memory_size,
                alignment,
                flags,
            });
        }

        Ok(segments)
    }

    pub fn load_segment_count(&self) -> Result<usize> {
        Ok(self.load_segments()?.len())
    }

    pub fn entry_in_load_segment(&self) -> Result<bool> {
        Ok(self
            .load_segments()?
            .into_iter()
            .any(|segment| segment.contains(self.entry_point)))
    }
}

pub fn parse_elf64(image: &[u8]) -> Result<ElfImage<'_>> {
    if image.len() < ELF64_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    if &image[0..4] != ELF_MAGIC {
        return Err(Error::InvalidArgument);
    }

    if image[4] != ELF_CLASS_64 {
        return Err(Error::Unsupported);
    }

    if image[5] != ELF_DATA_LSB || image[6] != ELF_IDENT_VERSION_CURRENT {
        return Err(Error::Unsupported);
    }

    if read_u32(image, 20)? != ELF_HEADER_VERSION_CURRENT {
        return Err(Error::Unsupported);
    }

    let machine = read_u16(image, 18)?;
    let entry = read_u64(image, 24)? as usize;
    let program_header_offset = read_u64(image, 32)? as usize;
    let program_header_entry_size = read_u16(image, 54)? as usize;
    let program_header_count = read_u16(image, 56)? as usize;

    if read_u16(image, 52)? as usize != ELF64_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    if program_header_count > 0 {
        if program_header_entry_size < ELF64_PROGRAM_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }

        let table_size = program_header_entry_size
            .checked_mul(program_header_count)
            .ok_or(Error::InvalidArgument)?;
        let table_end = program_header_offset
            .checked_add(table_size)
            .ok_or(Error::InvalidArgument)?;
        if program_header_offset < ELF64_HEADER_SIZE || table_end > image.len() {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(ElfImage {
        entry_point: entry,
        machine,
        image,
        program_header_offset,
        program_header_entry_size,
        program_header_count,
    })
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16> {
    let bytes = read_array::<2>(image, offset)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32> {
    let bytes = read_array::<4>(image, offset)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(image: &[u8], offset: usize) -> Result<u64> {
    let bytes = read_array::<8>(image, offset)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_array<const N: usize>(image: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Error::InvalidArgument)?;
    let bytes = image.get(offset..end).ok_or(Error::InvalidArgument)?;
    let mut value = [0_u8; N];
    value.copy_from_slice(bytes);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{read_array, Error};

    #[test]
    fn read_array_rejects_short_slices() {
        assert_eq!(read_array::<4>(b"abc", 0), Err(Error::InvalidArgument));
        assert_eq!(read_array::<8>(b"abcdefg", 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn read_array_reads_little_endian_bytes() {
        assert_eq!(
            read_array::<4>(b"\x01\x02\x03\x04", 0).unwrap(),
            [1, 2, 3, 4]
        );
    }
}
