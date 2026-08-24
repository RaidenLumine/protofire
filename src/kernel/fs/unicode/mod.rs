//! src/kernel/fs/unicode/mod.rs
//!
//! Unicode conversion and normalisation helpers shared by the filesystem
//! drivers (FAT32, exFAT, SimpleFs).
//!
//! Sub-modules:
//!
//! - [`oem`] — OEM code-page ↔ Unicode (CP437/CP850) for 8.3 short names.
//! - [`utf16`] — UTF-8 ↔ UTF-16LE for FAT32 LFN and exFAT name entries.
//! - [`casefold`] — case-insensitive filename comparison.
//! - [`casefold_tables`] — generated full Unicode case-folding table.
//! - [`normalize`] / [`normalize_tables`] — NFD/NFC normalisation.
//! - [`gb18030`] — GB18030/GBK (simplified Chinese) conversion.
//! - [`validate`] — UTF-8 validation and sanitisation.

pub mod casefold;
pub mod casefold_tables;
pub mod gb18030;
pub mod normalize;
pub mod normalize_tables;
pub mod oem;
pub mod utf16;
pub mod validate;

pub use casefold::eq_unicode_insensitive;
pub use oem::{char_to_oem_byte, oem_byte_to_char, utf8_to_oem, OemCodePage};
pub use utf16::{utf16le_code_unit_to_char, utf16le_to_utf8, utf8_to_utf16le, write_utf16le_chars};
