//! src/fs/iso9660/types.rs
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

/// Byte offset of the root directory's record inside the PVD.
///
/// The root's record is a field of the descriptor rather than a record in some
/// directory, and a root that grows or shrinks rewrites its length there.
pub const PVD_ROOT_RECORD_OFFSET: usize = 156;

/// Byte offset of a directory record's data-length field.
///
/// The field is the file's length, stored twice — little-endian then
/// big-endian — and a reader may check either, so anything that rewrites the
/// length rewrites both halves.
pub const DIR_RECORD_DATA_LENGTH_OFFSET: usize = 10;

/// Byte offset of a directory record's extent-location field.
///
/// The file's first logical block, stored twice — little-endian then
/// big-endian — and rewritten with the length when a file moves to new space.
pub const DIR_RECORD_EXTENT_LOCATION_OFFSET: usize = 2;

/// A System Use entry as SUSP defines it.
///
/// The header is a two-byte signature, a length that *includes* the header,
/// and a version.  Everything after it is the entry's own body, which is what
/// makes one builder enough for all of them.
fn susp_entry(signature: &[u8; 2], body: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(4 + body.len());
    entry.extend_from_slice(signature);
    entry.push((4 + body.len()) as u8);
    entry.push(1); // SUSP version 1
    entry.extend_from_slice(body);
    entry
}

/// The `NM` entry: the name a Rock Ridge reader uses instead of the identifier.
///
/// One entry holds 250 bytes of name, and a longer name continues in the next
/// entry with the CONTINUE flag set — the flag is what tells a reader to join
/// them rather than to replace what it has.
pub fn susp_name(name: &[u8]) -> Vec<u8> {
    const PER_ENTRY: usize = 250;

    let mut out = Vec::new();
    let mut rest = name;
    loop {
        let chunk = core::cmp::min(rest.len(), PER_ENTRY);
        let (head, tail) = rest.split_at(chunk);

        let mut body = Vec::with_capacity(1 + head.len());
        body.push(if tail.is_empty() { 0x00 } else { 0x01 });
        body.extend_from_slice(head);
        out.extend_from_slice(&susp_entry(b"NM", &body));

        if tail.is_empty() {
            return out;
        }
        rest = tail;
    }
}

/// The `PX` entry: POSIX attributes, each stored twice.
pub fn susp_posix(mode: u32, links: u32, uid: u32, gid: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(32);
    for value in [mode, links, uid, gid] {
        body.extend_from_slice(&value.to_le_bytes());
        body.extend_from_slice(&value.to_be_bytes());
    }
    susp_entry(b"PX", &body)
}

/// The `ST` entry: four bytes, and the last one in a record's System Use area.
pub fn susp_terminator() -> Vec<u8> {
    susp_entry(b"ST", &[])
}

/// The `SP` entry: the marker that says a record's System Use area is SUSP's.
///
/// SUSP puts it first, and only in the root directory's own "." record: it is
/// what tells a reader that the entries after it are the protocol's rather
/// than a format of the volume's own.  The two magic bytes are the standard's,
/// and the last field is how far into the area a reader should start — zero,
/// because the entries here begin where the record says they do.
pub fn susp_sharing_protocol() -> Vec<u8> {
    susp_entry(b"SP", &[0xBE, 0xEF, 0x00])
}

/// The `CE` entry: where the entries that did not fit continue.
///
/// A directory record's length is a single byte, so an area with more in it
/// than that continues in a block of its own, named here by logical block,
/// byte offset and length — each stored twice, the way the format stores every
/// number a reader might check.
pub fn susp_continuation(block: u32, offset: u32, size: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    for value in [block, offset, size] {
        body.extend_from_slice(&value.to_le_bytes());
        body.extend_from_slice(&value.to_be_bytes());
    }
    susp_entry(b"CE", &body)
}

/// The `ER` entry: the extension a volume's System Use areas belong to.
///
/// It names `RRIP_1991A`, the standard whose `NM`, `PX` and `SL` entries this
/// driver writes and reads, and it is the entry a reader looks for before it
/// believes any of the others.  Its own description and source text are the
/// ones the standard fixes, which is what makes it 237 bytes and too long for
/// a directory record: the record holds a `CE` pointing at where this goes.
pub fn susp_extensions_reference() -> Vec<u8> {
    const ID: &[u8] = b"RRIP_1991A";
    const DESCRIPTION: &[u8] =
        b"THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS";
    const SOURCE: &[u8] = b"PLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE.  SEE PUBLISHER IDENTIFIER IN PRIMARY VOLUME DESCRIPTOR FOR CONTACT INFORMATION.";

    let mut body = Vec::with_capacity(4 + ID.len() + DESCRIPTION.len() + SOURCE.len());
    body.push(ID.len() as u8);
    body.push(DESCRIPTION.len() as u8);
    body.push(SOURCE.len() as u8);
    body.push(1); // extension version
    body.extend_from_slice(ID);
    body.extend_from_slice(DESCRIPTION);
    body.extend_from_slice(SOURCE);
    susp_entry(b"ER", &body)
}

/// Whether an area names the extension its entries belong to.
///
/// The `ER` entry may be in the area itself or — because it is 237 bytes and a
/// directory record's length is one byte — in the continuation area a `CE`
/// entry names, which is where a writer that has one puts it.  One level of
/// continuation is as far as this follows, and the bytes of a continuation are
/// the caller's to fetch, since only it knows what a block number means.
pub fn susp_names_extension(
    system_use: &[u8],
    mut continuation: impl FnMut(u32, u32, u32) -> Option<Vec<u8>>,
) -> bool {
    let mut rest = system_use;
    while rest.len() >= 4 {
        let len = rest[2] as usize;
        if len < 4 || len > rest.len() {
            break;
        }
        let (entry, tail) = rest.split_at(len);
        let signature = &entry[..2];
        let body = &entry[4..];

        if signature == b"ER" {
            return true;
        }
        if signature == b"CE" && body.len() >= 24 {
            // Each of the three numbers is stored twice, little-endian first,
            // so the little half is the one to read.
            let number =
                |at: usize| u32::from_le_bytes(body[at..at + 4].try_into().unwrap_or_default());
            if continuation(number(0), number(8), number(16))
                .is_some_and(|bytes| has_extension_reference(&bytes))
            {
                return true;
            }
        }
        rest = tail;
    }
    false
}

/// Whether an area holds the `ER` entry itself.
fn has_extension_reference(system_use: &[u8]) -> bool {
    let mut rest = system_use;
    while rest.len() >= 4 {
        let len = rest[2] as usize;
        if len < 4 || len > rest.len() {
            break;
        }
        if &rest[..2] == b"ER" {
            return true;
        }
        rest = &rest[len..];
    }
    false
}

/// The same System Use area with the name entries replaced.
///
/// Every other entry is copied **verbatim**, because a record can carry
/// entries this driver does not parse — a symlink's target, a timestamp — and
/// re-serialising them from parsed fields would store what the parse could
/// hold and lose the rest.  The `NM` entries are the ones a rename changes,
/// and the terminator goes last, as SUSP requires.
pub fn susp_with_name(system_use: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(system_use.len() + name.len() + 8);
    let mut rest = system_use;
    while rest.len() >= 4 {
        let len = rest[2] as usize;
        if len < 4 || len > rest.len() {
            break;
        }
        let (entry, tail) = rest.split_at(len);
        let signature = &entry[..2];
        if signature != b"NM" && signature != b"ST" {
            out.extend_from_slice(entry);
        }
        rest = tail;
    }
    out.extend_from_slice(&susp_name(name));
    out.extend_from_slice(&susp_terminator());
    out
}

/// A parsed ISO 9660 directory record.
#[derive(Clone)]
pub struct DirRecord {
    /// Extent start location in logical blocks.
    pub extent_location: u32,
    /// Extent size in bytes.
    pub extent_size: u32,
    /// The blocks of extended attributes that precede the file's data.
    ///
    /// A record may name an Extended Attribute Record in front of its data,
    /// and this driver does not read them (`XA attributes are ignored`), so a
    /// volume that has any is one whose data it could not read correctly —
    /// which is what the block map refuses to hand blocks out of.
    pub extended_attribute_blocks: u8,
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
    /// The record's System Use area, byte for byte, as the volume has it.
    ///
    /// The parsed entries above are what this driver understands of it; a
    /// record can also carry entries it does not (`SL` components beyond the
    /// first, `TF` timestamps), and a rename has to keep them, so the bytes
    /// themselves are kept rather than rebuilt from the parse.
    pub system_use: Vec<u8>,
    /// Whether this record came from a Joliet (UCS-2BE) directory.
    pub joliet: bool,
    /// How long this record is, in bytes, as its first byte says.
    ///
    /// A record is variable-length and the length is the only thing that finds
    /// the next one, so removing a record means knowing this.
    pub record_len: usize,
    /// Where this record itself sits, as a byte offset into the buffer it was
    /// parsed from.
    ///
    /// The record says where a file's *extent* is; this says where the record
    /// is, which is what a resize rewrites.  The parser knows it because it
    /// walks the extent, and the mount keeps it so a node can change the
    /// length the record carries without walking the path again
    /// ([RFC 0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md)).
    pub source_offset: usize,
}

impl DirRecord {
    /// Serialise a directory record for a regular file.
    ///
    /// The two fields that say where a file is and how long it is are each
    /// stored twice — little-endian then big-endian — because a reader is free
    /// to check either, and the recording date is left as all-zero, which the
    /// standard reads as "not specified" and this driver does not use.
    pub fn new_file(identifier: &[u8], extent_location: u32, extent_size: u32) -> Vec<u8> {
        let fi_len = identifier.len();
        // A record's length is even: the identifier is followed by one pad byte
        // when it has to be.
        let dr_len = {
            let base = 33 + fi_len;
            if base.is_multiple_of(2) {
                base
            } else {
                base + 1
            }
        };
        let mut rec = alloc::vec![0u8; dr_len];
        rec[0] = dr_len as u8;
        rec[DIR_RECORD_EXTENT_LOCATION_OFFSET..][..4]
            .copy_from_slice(&extent_location.to_le_bytes());
        rec[DIR_RECORD_EXTENT_LOCATION_OFFSET + 4..][..4]
            .copy_from_slice(&extent_location.to_be_bytes());
        rec[DIR_RECORD_DATA_LENGTH_OFFSET..][..4].copy_from_slice(&extent_size.to_le_bytes());
        rec[DIR_RECORD_DATA_LENGTH_OFFSET + 4..][..4].copy_from_slice(&extent_size.to_be_bytes());
        // A regular file: not a directory, not associated, not multi-extent.
        rec[25] = 0x00;
        // The volume sequence number, stored twice, is the volume this record
        // belongs to — the first and only one this driver writes.
        rec[28..30].copy_from_slice(&1u16.to_le_bytes());
        rec[30..32].copy_from_slice(&1u16.to_be_bytes());
        rec[32] = fi_len as u8;
        rec[33..33 + fi_len].copy_from_slice(identifier);
        rec
    }

    /// The same record, marked as a directory.
    pub fn new_directory(identifier: &[u8], extent_location: u32, extent_size: u32) -> Vec<u8> {
        let mut rec = Self::new_file(identifier, extent_location, extent_size);
        rec[25] = 0x02; // directory
        rec
    }

    /// The same record for an entry that may be either.
    pub fn new_entry(
        identifier: &[u8],
        extent_location: u32,
        extent_size: u32,
        directory: bool,
    ) -> Vec<u8> {
        let mut rec = Self::new_file(identifier, extent_location, extent_size);
        if directory {
            rec[25] = 0x02;
        }
        rec
    }

    /// The same record, carrying a System Use area after its identifier.
    ///
    /// The area starts where the identifier's own padding ends, and the record
    /// grows to hold it and is padded to an even length like every other.
    pub fn new_entry_with(
        identifier: &[u8],
        extent_location: u32,
        extent_size: u32,
        directory: bool,
        system_use: &[u8],
    ) -> Vec<u8> {
        let mut rec = Self::new_entry(identifier, extent_location, extent_size, directory);
        rec.extend_from_slice(system_use);
        if !rec.len().is_multiple_of(2) {
            rec.push(0);
        }
        rec[0] = rec.len() as u8;
        rec
    }

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
        // The fixed part of a record is 33 bytes — everything up to the
        // identifier's length — and nothing below reads past this.
        if dr_len < 33 {
            return None;
        }

        let rec = &sector_data[offset..][..dr_len as usize];

        let location_at = DIR_RECORD_EXTENT_LOCATION_OFFSET;
        let extent_location = u32::from_le_bytes([
            rec[location_at],
            rec[location_at + 1],
            rec[location_at + 2],
            rec[location_at + 3],
        ]);
        let length_at = DIR_RECORD_DATA_LENGTH_OFFSET;
        let extent_size = u32::from_le_bytes([
            rec[length_at],
            rec[length_at + 1],
            rec[length_at + 2],
            rec[length_at + 3],
        ]);
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
            // The identifier is at offset 33 and is followed by one padding
            // byte **when its length is even**, which is what makes the
            // System Use area begin at an even offset from the record's own
            // start: 33 + odd is even, and 33 + even takes the byte back.
            let pad = if fi_len.is_multiple_of(2) { 1 } else { 0 };
            33 + fi_len + pad
        };

        let mut rr_name = None;
        let mut rr_posix = None;
        let mut rr_symlink: Option<Vec<u8>> = None;
        let mut system_use = Vec::new();

        if su_start < dr_len as usize {
            let su = &rec[su_start..];
            parse_susp_entries(su, &mut rr_name, &mut rr_posix, &mut rr_symlink);
            system_use.extend_from_slice(su);
        }

        let next = offset + dr_len as usize;
        Some((
            DirRecord {
                extent_location,
                extent_size,
                extended_attribute_blocks: rec[1],
                flags,
                identifier,
                rr_name,
                rr_posix,
                rr_symlink,
                system_use,
                joliet,
                source_offset: offset,
                record_len: dr_len as usize,
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
    // Whether the entry before this one said its name continues into the next
    // `NM`: a name longer than one entry's 250 bytes is written as several.
    let mut name_continues = false;

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
                if !body.is_empty() {
                    let flags = body[0];
                    let piece = String::from_utf8_lossy(&body[1..]).into_owned();
                    let name = if name_continues {
                        let mut held = rr_name.take().unwrap_or_default();
                        held.push_str(&piece);
                        held
                    } else {
                        piece
                    };
                    *rr_name = Some(name);
                    name_continues = flags & 0x01 != 0;
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

        // Only a name continues a name: the flag means something of its own on
        // any other entry, and SUSP puts a continued one next to what it
        // continues.
        if sig != *b"NM" {
            name_continues = false;
        }

        data = &data[len..];
    }
}

// ── Filename decoding ──

/// Decode an ISO 9660 file identifier to a human-readable name.
pub(crate) fn decode_iso_filename(raw: &[u8]) -> String {
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
        // SAFETY: `buf` is a test-built sector and `Pvd` is a packed descriptor that
        // starts at its beginning, so the unaligned copy needs no alignment.
        let pvd = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) };
        assert!(pvd.is_valid());
    }

    #[test]
    fn pvd_block_size() {
        let buf = build_pvd_bytes(0x01, b"CD001", 2048);
        // SAFETY: as above — the same test-built sector, read as a descriptor.
        let pvd = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) };
        assert_eq!(pvd.block_size(), 2048);
    }

    #[test]
    fn pvd_invalid_type() {
        let buf = build_pvd_bytes(0x02, b"CD001", 2048);
        // SAFETY: as above — the same construction with a wrong type byte.
        let pvd = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) };
        assert!(!pvd.is_valid());
    }

    #[test]
    fn pvd_invalid_magic() {
        let buf = build_pvd_bytes(0x01, b"WRONG", 2048);
        // SAFETY: as above — the same construction with a wrong identifier.
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
    fn dir_record_shorter_than_its_fixed_part_is_not_one() {
        // A record's own length is the first byte, and everything a reader
        // reads from it is behind that: one that says it is shorter than the
        // length it claims is a record nobody can read, not a short one to
        // read past the end of.
        for length in 1..33u8 {
            let rec = vec![length; SECTOR_SIZE];
            assert!(
                DirRecord::parse(&rec, 0).is_none(),
                "a {length}-byte record is not a record"
            );
        }
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
    fn a_records_system_use_area_starts_after_the_identifier_padding() {
        // The padding byte is there when the identifier's length is *even*,
        // which is what makes 33 + fi_len + pad even either way.  Reading the
        // area one byte off is how a `PX` entry gets mistaken for its own
        // length byte, and the two identifiers below take the two paths.
        for identifier in [&b"ODD;1"[..], &b"EVEN;1"[..]] {
            let area = susp_name(b"a name");
            let record = DirRecord::new_entry_with(identifier, 7, 9, false, &area);

            let (parsed, next) = DirRecord::parse(&record, 0).expect("parse");
            assert_eq!(next, record.len());
            assert_eq!(parsed.rr_name.as_deref(), Some("a name"));
            assert!(parsed.system_use.starts_with(&area));
        }
    }

    #[test]
    fn a_name_longer_than_one_name_entry_is_carried_in_several() {
        // One entry holds 250 bytes and says it continues; the rest goes in
        // the next, which says it does not.  A parser that replaced rather
        // than joined would answer with the tail alone.
        let long = vec![b'x'; 300];
        let area = susp_name(&long);
        assert_eq!(area.len(), 4 + 1 + 250 + 4 + 1 + 50);

        let mut name = None;
        let mut posix = None;
        let mut link = None;
        parse_susp_entries(&area, &mut name, &mut posix, &mut link);
        assert_eq!(name.expect("name").as_bytes(), long.as_slice());
    }

    #[test]
    fn the_extensions_reference_is_the_size_the_standard_gives_it() {
        let reference = susp_extensions_reference();
        // Signature, length and version, then the three length bytes and the
        // extension's version: 4 + 4, and the text the standard fixes.
        assert_eq!(&reference[..2], b"ER");
        assert_eq!(reference[2] as usize, reference.len());
        assert_eq!(reference.len(), 4 + 4 + 10 + 84 + 135);
        assert_eq!(reference[4], 10);
        assert_eq!(&reference[8..18], b"RRIP_1991A");
    }

    #[test]
    fn an_extension_reference_is_found_in_the_area_or_in_its_continuation() {
        let reference = susp_extensions_reference();

        // In the area itself.
        assert!(susp_names_extension(&reference, |_, _, _| None));

        // Or where the area's `CE` says it continues, which is where a writer
        // that cannot fit it in a record puts it.
        let mut area = susp_sharing_protocol();
        area.extend_from_slice(&susp_continuation(42, 0, reference.len() as u32));
        area.extend_from_slice(&susp_terminator());
        let mut asked = None;
        let found = susp_names_extension(&area, |block, offset, size| {
            asked = Some((block, offset, size));
            Some(reference.clone())
        });
        assert!(found);
        assert_eq!(asked, Some((42, 0, reference.len() as u32)));

        // An area with no reference in either place is one.
        let mut names_only = susp_name(b"a name");
        names_only.extend_from_slice(&susp_terminator());
        assert!(!susp_names_extension(&names_only, |_, _, _| None));
        let mut area = susp_sharing_protocol();
        area.extend_from_slice(&susp_continuation(42, 0, 4));
        assert!(!susp_names_extension(&area, |_, _, _| {
            Some(susp_terminator())
        }));
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
