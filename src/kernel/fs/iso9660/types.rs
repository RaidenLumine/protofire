//! src/kernel/fs/iso9660/types.rs
//!
//! On-disk data structures for ISO 9660 (ECMA-119) and Rock Ridge (RRIP-1.12).
//!
//! Reference: ECMA-119 (ISO 9660), SUSP 1.12, RRIP 1.12.

use alloc::string::String;
use alloc::vec::Vec;

// ── Sizes ──

/// ISO 9660 logical sector size (always 2048 for data tracks).
pub const SECTOR_SIZE: usize = 2048;

/// Offset of the Primary Volume Descriptor (sector 16, 0-indexed).
pub const PVD_SECTOR: u64 = 16;

/// Offset of the Joliet Supplementary Volume Descriptor (sector 17).
pub const SVD_SECTOR: u64 = 17;

// ── Volume Descriptor ──

/// Primary Volume Descriptor (ECMA-119 §7.4).
///
/// Located at sector 16 on the medium. Contains the root directory record.
#[repr(C, packed)]
pub struct Pvd {
    pub desc_type: u8,
    pub std_identifier: [u8; 5], // "CD001"
    pub desc_version: u8,
    _unused1: u8,
    pub system_id: [u8; 32],
    pub volume_id: [u8; 32],
    _unused2: [u8; 8],
    pub volume_space_size: [u8; 8], // LE+BE u32
    _unused3: [u8; 32],
    pub volume_set_size: [u8; 4],    // LE+BE u16
    pub volume_seq_num: [u8; 4],     // LE+BE u16
    pub logical_block_size: [u8; 4], // LE+BE u16
    pub path_table_size: [u8; 8],    // LE+BE u32
    pub l_path_table_loc: u32,       // LE
    pub opt_l_path_table_loc: u32,   // LE
    pub m_path_table_loc: u32,       // BE
    pub opt_m_path_table_loc: u32,   // BE
    pub root_dir_record: [u8; 34],   // embedded DirectoryRecord
    pub volume_set_id: [u8; 128],
    pub publisher_id: [u8; 128],
    pub data_preparer_id: [u8; 128],
    pub application_id: [u8; 128],
    pub copyright_file_id: [u8; 37],
    pub abstract_file_id: [u8; 37],
    pub bibliographic_file_id: [u8; 37],
    pub creation_date: [u8; 17],
    pub modification_date: [u8; 17],
    pub expiration_date: [u8; 17],
    pub effective_date: [u8; 17],
    pub file_structure_version: u8,
    _reserved: u8,
    pub application_used: [u8; 512],
    _reserved2: [u8; 653],
}

impl Pvd {
    /// Validate magic bytes: type=0x01, id="CD001", version=0x01.
    pub fn is_valid(&self) -> bool {
        self.desc_type == 0x01 && &self.std_identifier == b"CD001" && self.desc_version == 0x01
    }

    /// Read the LE u16 logical block size.
    pub fn block_size(&self) -> u16 {
        u16::from_le_bytes([self.logical_block_size[0], self.logical_block_size[1]])
    }
}

// ── Directory Record ──

/// A parsed ISO 9660 directory record.
#[derive(Clone)]
pub struct DirRecord {
    /// Extent start location in logical blocks.
    pub extent_location: u32,
    /// Extent size in bytes.
    pub extent_size: u32,
    /// File flags (0x02 = directory).
    pub flags: u8,
    /// ISO 9660 file identifier (raw bytes).
    pub identifier: Vec<u8>,

    // ── Rock Ridge extensions ──
    /// POSIX alternative name (from NM entry).
    pub rr_name: Option<String>,
    /// POSIX attributes: (mode, links, uid, gid).
    pub rr_posix: Option<(u32, u32, u32, u32)>,
    /// Symlink components (from SL entries).
    pub rr_symlink: Option<Vec<u8>>,
    /// Whether this record came from a Joliet (UCS-2BE) directory.
    pub joliet: bool,
}

impl DirRecord {
    /// Parse an ISO 9660 directory record (ASCII filenames).
    pub fn parse(sector_data: &[u8], offset: usize) -> Option<(Self, usize)> {
        Self::parse_inner(sector_data, offset, false)
    }

    /// Parse a Joliet directory record (UCS-2BE filenames).
    pub fn parse_joliet(sector_data: &[u8], offset: usize) -> Option<(Self, usize)> {
        Self::parse_inner(sector_data, offset, true)
    }

    /// Parse a directory record from raw bytes at `offset` within `sector`.
    ///
    /// Returns `(record, next_offset)` on success. Returns `None` when the
    /// record length is 0 (end of directory).
    fn parse_inner(sector_data: &[u8], offset: usize, joliet: bool) -> Option<(Self, usize)> {
        let dr_len = *sector_data.get(offset)?;
        if dr_len == 0 {
            return None; // end of directory
        }
        if dr_len as usize > sector_data.len() - offset {
            return None;
        }

        let rec = &sector_data[offset..][..dr_len as usize];

        let extent_location = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]);
        let extent_size = u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]);
        let flags = rec[25];
        let fi_len = rec[32] as usize;

        let identifier = if fi_len > 0 && 33 + fi_len <= dr_len as usize {
            rec[33..33 + fi_len].to_vec()
        } else {
            Vec::new()
        };

        // Parse Rock Ridge extensions from the System Use area.
        let su_start = if fi_len == 0 {
            33
        } else {
            // File identifier is at offset 33, length fi_len.
            // If fi_len is odd, there's a padding byte.
            let pad = if fi_len.is_multiple_of(2) { 0 } else { 1 };
            33 + fi_len + pad
        };

        let mut rr_name = None;
        let mut rr_posix = None;
        let mut rr_symlink: Option<Vec<u8>> = None;

        if su_start < dr_len as usize {
            let su = &rec[su_start..];
            parse_susp_entries(su, &mut rr_name, &mut rr_posix, &mut rr_symlink);
        }

        let next = offset + dr_len as usize;
        Some((
            DirRecord {
                extent_location,
                extent_size,
                flags,
                identifier,
                rr_name,
                rr_posix,
                rr_symlink,
                joliet,
            },
            next,
        ))
    }

    /// Return the "best" name: Rock Ridge name if available, then
    /// Joliet UCS-2BE decoding if applicable, otherwise ISO 9660 ASCII.
    pub fn best_name(&self) -> String {
        if let Some(ref nm) = self.rr_name {
            return nm.clone();
        }
        if self.joliet {
            decode_joliet_filename(&self.identifier)
        } else {
            decode_iso_filename(&self.identifier)
        }
    }

    /// Whether this record represents a directory.
    pub fn is_dir(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

// ── SUSP / Rock Ridge parsing ──

/// Parse SUSP continuation entries in the System Use area.
fn parse_susp_entries(
    mut data: &[u8],
    rr_name: &mut Option<String>,
    rr_posix: &mut Option<(u32, u32, u32, u32)>,
    rr_symlink: &mut Option<Vec<u8>>,
) {
    while data.len() >= 4 {
        let sig = [data[0], data[1]];
        let len = data[2] as usize;
        let _version = data[3];

        if len < 4 || len > data.len() {
            break;
        }

        let body = &data[4..len];

        match &sig {
            b"PX" => {
                // POSIX attributes: mode(u32 LE), links(u32 LE), uid(u32 LE), gid(u32 LE).
                if body.len() >= 16 {
                    let mode = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    let nlink = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                    let uid = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
                    let gid = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
                    *rr_posix = Some((mode, nlink, uid, gid));
                }
            }
            b"NM" => {
                // Alternative name: flags(1) + name bytes.
                if body.len() >= 2 {
                    let _flags = body[0];
                    let name_bytes = &body[1..];
                    let nm = String::from_utf8_lossy(name_bytes).into_owned();
                    // CONTINUE flag (0x01) would mean concatenation; we overwrite for simplicity.
                    *rr_name = Some(nm);
                }
            }
            b"SL" => {
                // Symlink: flags(1) + component list.
                // Each component: flags(1) + comp_len(1) + data(comp_len).
                if let Some(ref mut link_data) = rr_symlink {
                    let mut comps = &body[1..];
                    while comps.len() >= 2 {
                        let comp_flags = comps[0];
                        let comp_len = comps[1] as usize;
                        if 2 + comp_len > comps.len() {
                            break;
                        }
                        let comp_data = &comps[2..2 + comp_len];

                        if comp_flags & 0x08 != 0 {
                            // ROOT
                            link_data.push(b'/');
                        } else if comp_flags & 0x04 != 0 {
                            // PARENT
                            link_data.extend_from_slice(b"..");
                        } else if comp_flags & 0x02 != 0 {
                            // CURRENT
                            link_data.push(b'.');
                        } else {
                            link_data.extend_from_slice(comp_data);
                            link_data.push(b'/');
                        }

                        if comp_flags & 0x01 == 0 {
                            // No CONTINUE — remove trailing slash for last component.
                            if !matches!(link_data.last(), Some(b'/') if comp_flags & 0x08 == 0) {
                                // keep trailing slash except for non-ROOT
                                // non-CONTINUE
                            }
                        }

                        comps = &comps[2 + comp_len..];
                    }
                    // Fix up trailing slash if last component wasn't CONTINUE.
                    if body[0] & 0x01 == 0 && link_data.last() == Some(&b'/') {
                        link_data.pop();
                    }
                } else {
                    // Initialize symlink from first SL entry.
                    let mut link = Vec::new();
                    let mut comps = &body[1..];
                    while comps.len() >= 2 {
                        let comp_flags = comps[0];
                        let comp_len = comps[1] as usize;
                        if 2 + comp_len > comps.len() {
                            break;
                        }
                        let comp_data = &comps[2..2 + comp_len];

                        if comp_flags & 0x08 != 0 {
                            link.push(b'/');
                        } else if comp_flags & 0x04 != 0 {
                            link.extend_from_slice(b"..");
                        } else if comp_flags & 0x02 != 0 {
                            link.push(b'.');
                        } else {
                            link.extend_from_slice(comp_data);
                            link.push(b'/');
                        }

                        if comp_flags & 0x01 == 0 {
                            break;
                        }
                        comps = &comps[2 + comp_len..];
                    }
                    if link.last() == Some(&b'/') {
                        link.pop();
                    }
                    *rr_symlink = Some(link);
                }
            }
            b"ST" => {
                // System Use Terminator.
                break;
            }
            _ => {}
        }

        data = &data[len..];
    }
}

// ── Filename decoding ──

/// Decode an ISO 9660 file identifier to a human-readable name.
fn decode_iso_filename(raw: &[u8]) -> String {
    // Strip ";1" version suffix if present.
    let without_version = if let Some(pos) = raw.iter().rposition(|&b| b == b';') {
        &raw[..pos]
    } else {
        raw
    };
    // Trim trailing spaces.
    let end = without_version
        .iter()
        .rposition(|&b| b != b' ')
        .map(|i| i + 1)
        .unwrap_or(0);
    let trimmed = &without_version[..end];
    // Convert to lowercase ASCII.
    let lowered: Vec<u8> = trimmed.iter().map(|b| b.to_ascii_lowercase()).collect();
    String::from_utf8_lossy(&lowered).into_owned()
}

/// Decode a Joliet (UCS-2BE) file identifier to a human-readable name.
fn decode_joliet_filename(raw: &[u8]) -> String {
    // Convert UCS-2BE bytes to UTF-16 code units.
    let mut utf16 = Vec::with_capacity(raw.len() / 2);
    let mut i = 0;
    while i + 1 < raw.len() {
        let cu = u16::from_be_bytes([raw[i], raw[i + 1]]);
        utf16.push(cu);
        i += 2;
    }

    // Strip ";1" version suffix.
    let without_version =
        if utf16.len() >= 2 && utf16[utf16.len() - 2] == 0x003B && utf16[utf16.len() - 1] == 0x0031
        {
            &utf16[..utf16.len() - 2]
        } else {
            &utf16
        };

    // Strip trailing spaces (U+0020).
    let end = without_version
        .iter()
        .rposition(|&c| c != 0x0020)
        .map(|i| i + 1)
        .unwrap_or(0);
    let trimmed = &without_version[..end];

    String::from_utf16_lossy(trimmed)
}

// ── El Torito Boot Catalog ───────────────────────────────────────────────────

/// Parsed El Torito boot catalog entry.
#[derive(Debug, Clone)]
pub struct BootEntry {
    /// Whether this entry is bootable (0x88 flag).
    pub bootable: bool,
    /// Media type: 0 = no emulation, 1-4 = floppy/hard disk emulation.
    pub media_type: u8,
    /// x86 real-mode load segment address.
    pub load_segment: u16,
    /// Number of virtual/emulated sectors.
    pub sector_count: u16,
    /// Starting sector (LBA) of the boot image.
    pub load_rba: u32,
}

/// Parse an El Torito Boot Catalog from a 2048-byte sector.
///
/// Returns `Vec<BootEntry>` containing all initial/default and section entries.
/// Returns empty vec if the catalog header (validation entry) is missing.
pub fn parse_boot_catalog(sector: &[u8]) -> Vec<BootEntry> {
    if sector.len() < 64 {
        return Vec::new();
    }

    // Validation entry must be at offset 0 with header_id=0x01.
    if sector[0] != 0x01 {
        return Vec::new();
    }

    // Check key bytes (0x55, 0xAA) at offset 30-31.
    if sector[30] != 0x55 || sector[31] != 0xAA {
        return Vec::new();
    }

    let mut entries = Vec::new();
    let mut pos = 32usize; // Start after validation entry (32 bytes).

    while pos + 32 <= sector.len() {
        let entry_type = sector[pos];
        if entry_type == 0 {
            pos += 32;
            continue;
        }

        if entry_type == 0x90 || entry_type == 0x91 {
            // Section header — skip.
            pos += 32;
            continue;
        }

        let bootable = entry_type == 0x88;
        let media_type = sector[pos + 1];
        let load_segment = u16::from_le_bytes([sector[pos + 2], sector[pos + 3]]);
        let sector_count = u16::from_le_bytes([sector[pos + 6], sector[pos + 7]]);
        let load_rba = u32::from_le_bytes([
            sector[pos + 8],
            sector[pos + 9],
            sector[pos + 10],
            sector[pos + 11],
        ]);

        entries.push(BootEntry {
            bootable,
            media_type,
            load_segment,
            sector_count,
            load_rba,
        });

        pos += 32;
    }

    entries
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn build_pvd_bytes(desc_type: u8, magic: &[u8; 5], bs: u16) -> [u8; SECTOR_SIZE] {
        let mut buf = [0u8; SECTOR_SIZE];
        buf[0] = desc_type;
        buf[1..6].copy_from_slice(magic);
        buf[6] = 0x01; // desc_version
        buf[128..130].copy_from_slice(&bs.to_le_bytes());
        buf[881] = 0x01; // file_structure_version
        buf
    }

    #[test]
    fn pvd_valid() {
        let buf = build_pvd_bytes(0x01, b"CD001", 2048);
        let pvd = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) };
        assert!(pvd.is_valid());
    }

    #[test]
    fn pvd_block_size() {
        let buf = build_pvd_bytes(0x01, b"CD001", 2048);
        let pvd = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) };
        assert_eq!(pvd.block_size(), 2048);
    }

    #[test]
    fn pvd_invalid_type() {
        let buf = build_pvd_bytes(0x02, b"CD001", 2048);
        let pvd = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) };
        assert!(!pvd.is_valid());
    }

    #[test]
    fn pvd_invalid_magic() {
        let buf = build_pvd_bytes(0x01, b"WRONG", 2048);
        let pvd = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) };
        assert!(!pvd.is_valid());
    }

    fn make_dir_record_raw(extent_loc: u32, extent_size: u32, flags: u8, name: &[u8]) -> Vec<u8> {
        let fi_len = name.len() as u8;
        let pad = if fi_len.is_multiple_of(2) { 0u8 } else { 1u8 };
        let dr_len = 33 + fi_len + pad;
        let mut rec = vec![0u8; dr_len as usize];
        rec[0] = dr_len;
        rec[2..6].copy_from_slice(&extent_loc.to_le_bytes());
        rec[10..14].copy_from_slice(&extent_size.to_le_bytes());
        rec[25] = flags;
        rec[32] = fi_len;
        rec[33..33 + name.len()].copy_from_slice(name);
        rec
    }

    #[test]
    fn dir_record_root_dir() {
        let rec = make_dir_record_raw(20, 2048, 0x02, b"\x00");
        let (parsed, _) = DirRecord::parse(&rec, 0).expect("parse root dir");
        assert!(parsed.is_dir());
        assert_eq!(parsed.extent_location, 20);
        assert_eq!(parsed.extent_size, 2048);
    }

    #[test]
    fn dir_record_file() {
        let rec = make_dir_record_raw(30, 100, 0x00, b"HELLO.TXT;1");
        let (parsed, _) = DirRecord::parse(&rec, 0).expect("parse file");
        assert!(!parsed.is_dir());
        assert_eq!(parsed.extent_location, 30);
        assert_eq!(parsed.extent_size, 100);
        assert_eq!(parsed.identifier, b"HELLO.TXT;1");
    }

    #[test]
    fn dir_record_padding() {
        // Name with odd length should get a padding byte.
        let rec = make_dir_record_raw(10, 50, 0x00, b"ODD"); // 3 bytes → pad
        let (parsed, next) = DirRecord::parse(&rec, 0).expect("parse odd name");
        assert_eq!(parsed.identifier, b"ODD");
        // next should account for padding: 33 + 3 + 1 = 37
        assert_eq!(next, 37);
    }

    #[test]
    fn dir_record_end() {
        let rec = [0u8];
        assert!(DirRecord::parse(&rec, 0).is_none());
    }

    #[test]
    fn susp_px_entry() {
        // Build a SUSP PX entry: sig="PX", len=20, ver=1, mode=0o755, nlink=2,
        // uid=1000, gid=1000
        let mut data = vec![0u8; 20];
        data[0] = b'P';
        data[1] = b'X';
        data[2] = 20;
        data[3] = 1;
        data[4..8].copy_from_slice(&0o755u32.to_le_bytes());
        data[8..12].copy_from_slice(&2u32.to_le_bytes());
        data[12..16].copy_from_slice(&1000u32.to_le_bytes());
        data[16..20].copy_from_slice(&1000u32.to_le_bytes());

        let mut name = None;
        let mut posix = None;
        let mut link = None;
        parse_susp_entries(&data, &mut name, &mut posix, &mut link);
        assert!(posix.is_some());
        let (mode, nlink, uid, gid) = posix.unwrap();
        assert_eq!(mode, 0o755);
        assert_eq!(nlink, 2);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1000);
    }

    #[test]
    fn susp_nm_entry() {
        // Build NM: sig="NM", len=14, ver=1, flags=0, name="hello.txt"
        let mut data = vec![0u8; 14];
        data[0] = b'N';
        data[1] = b'M';
        data[2] = 14;
        data[3] = 1;
        data[4] = 0; // flags
        data[5..14].copy_from_slice(b"hello.txt");

        let mut name = None;
        let mut posix = None;
        let mut link = None;
        parse_susp_entries(&data, &mut name, &mut posix, &mut link);
        assert_eq!(name, Some("hello.txt".into()));
    }

    #[test]
    fn susp_sl_entry() {
        // Build SL: sig="SL", len fits, ver=1, flags=0 (no CONTINUE), component: "/usr"
        let comp = b"usr";
        let body_len = 1 + 2 + comp.len(); // flags(1) + comp_flags(1)+comp_len(1)+data(3)
        let mut data = vec![0u8; 4 + body_len];
        data[0] = b'S';
        data[1] = b'L';
        data[2] = (4 + body_len) as u8;
        data[3] = 1;
        data[4] = 0; // flags (no CONTINUE)
        data[5] = 0; // comp_flags (0 = normal component)
        data[6] = comp.len() as u8;
        data[7..7 + comp.len()].copy_from_slice(comp);

        let mut name = None;
        let mut posix = None;
        let mut link = None;
        parse_susp_entries(&data, &mut name, &mut posix, &mut link);
        assert!(link.is_some());
        assert_eq!(link.unwrap(), b"usr");
    }

    #[test]
    fn susp_st_terminator() {
        let mut data = vec![0u8; 4];
        data[0] = b'S';
        data[1] = b'T';
        data[2] = 4;
        data[3] = 1;
        // Add some junk after ST to verify parsing stops.
        data.extend_from_slice(&[b'X', b'X', 4, 1]);

        let mut name = Some("should_keep".into());
        let mut posix = None;
        let mut link = None;
        parse_susp_entries(&data, &mut name, &mut posix, &mut link);
        // name should still be "should_keep" since ST stops before XX
        assert_eq!(name, Some("should_keep".into()));
    }

    #[test]
    fn decode_filename_with_version() {
        assert_eq!(decode_iso_filename(b"HELLO.TXT;1"), "hello.txt");
    }

    #[test]
    fn decode_filename_no_version() {
        assert_eq!(decode_iso_filename(b"README"), "readme");
    }

    #[test]
    fn decode_filename_trailing_spaces() {
        assert_eq!(decode_iso_filename(b"FILE    ;1"), "file");
    }
}
