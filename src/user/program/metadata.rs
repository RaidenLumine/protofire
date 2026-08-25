//! src/user/program/metadata.rs
//!
//! Catalog and manifest parsing, rendering, and launch-budget validation
//! helpers.

// `format!` is only used by the renderers, which are gated to demo/test builds.
#[cfg(any(test, feature = "demo-disk"))]
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::Error;
use crate::Result;

use super::catalog::CatalogEntry;
use super::catalog::LaunchManifest;
use super::integrity::validate_optional_sha256_hex;

// ── launch metadata budget limits ─────────────────────────────────────
//
// These bound the argv/environment/working-dir metadata carried inside
// launch manifests before it is copied into a user process image.  The
// bounds are deliberately generous (a manifest is a small text file) while
// still preventing a corrupted or hostile manifest from requesting a huge
// argument area.

/// Maximum number of arguments accepted from launch metadata.
pub(crate) const MAX_METADATA_ARGUMENTS: usize = 64;
/// Maximum number of environment entries accepted from launch metadata.
pub(crate) const MAX_METADATA_ENVIRONMENT: usize = 64;
/// Maximum length (in bytes) of any single argument or environment entry.
pub(crate) const MAX_METADATA_ENTRY_BYTES: usize = 4096;
/// Maximum total length (in bytes) of all arguments combined.
pub(crate) const MAX_METADATA_ARGUMENTS_TOTAL_BYTES: usize = 64 * 1024;
/// Maximum total length (in bytes) of all environment entries combined.
pub(crate) const MAX_METADATA_ENVIRONMENT_TOTAL_BYTES: usize = 64 * 1024;
/// Maximum length (in bytes) of the launch working directory.
pub(crate) const MAX_METADATA_WORKING_DIR_BYTES: usize = 4096;

// ── catalog entry parsing ──────────────────────────────────────────────
//
// Catalog records use a small key = "value" format:
//
//   # catalog alias (redirects to a versioned catalog record)
//   id = "shell"
//   version = "0.1.0"
//   catalog = "./shell@0.1.0.toml"
//
//   # versioned catalog record (points directly at a launch manifest)
//   id = "shell"
//   version = "0.1.0"
//   manifest = "/apps/packages/shell/manifest.toml"
//   manifest_sha256 = "…"          # optional
//   manifest_signature = "…"       # optional
//   source_reference = "…"         # optional

pub(crate) fn parse_catalog_entry(text: &str) -> Result<CatalogEntry> {
    let id = parse_string_field(text, "id")?;
    let version = parse_optional_string_field(text, "version")?;
    let manifest_path = parse_optional_string_field(text, "manifest")?;
    let catalog_path = parse_optional_string_field(text, "catalog")?;
    let manifest_sha256 = parse_optional_string_field(text, "manifest_sha256")?;
    let manifest_signature = parse_optional_string_field(text, "manifest_signature")?;
    let source_reference = parse_optional_string_field(text, "source_reference")?;

    validate_optional_sha256_hex(manifest_sha256.as_deref())?;

    if id.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if manifest_path.is_none() && catalog_path.is_none() {
        // A catalog record that neither redirects nor points at a manifest
        // cannot be launched.
        return Err(Error::InvalidArgument);
    }

    Ok(CatalogEntry {
        id,
        version,
        manifest_path,
        catalog_path,
        manifest_sha256,
        manifest_signature,
        source_reference,
    })
}

// ── launch manifest parsing ───────────────────────────────────────────
//
//   name = "shell"
//   version = "0.1.0"
//   format = "elf64-x86_64-user"
//   entry = "/apps/packages/shell/bin/shell.elf"
//   entry_sha256 = "…"             # optional
//   entry_signature = "…"          # optional
//   working_dir = "/apps/packages/shell"
//   argv = ["shell", "-i"]         # optional
//   env = ["TERM=vt100"]           # optional
//   host_proxy = "shell"           # optional (host-resident proxy program)

pub(crate) fn parse_launch_manifest(text: &str) -> Result<LaunchManifest> {
    let name = parse_string_field(text, "name")?;
    let version = parse_string_field(text, "version")?;
    let format = parse_string_field(text, "format")?;
    let entry_path = parse_string_field(text, "entry")?;
    let entry_sha256 = parse_optional_string_field(text, "entry_sha256")?;
    let entry_signature = parse_optional_string_field(text, "entry_signature")?;
    let working_dir = parse_string_field(text, "working_dir")?;
    let arguments = parse_string_list_field(text, "argv")?;
    let environment = parse_string_list_field(text, "env")?;
    let host_proxy = parse_optional_string_field(text, "host_proxy")?;

    validate_optional_sha256_hex(entry_sha256.as_deref())?;

    if name.is_empty() || entry_path.is_empty() || working_dir.is_empty() {
        return Err(Error::InvalidArgument);
    }

    Ok(LaunchManifest {
        name,
        version,
        format,
        entry_path,
        entry_sha256,
        entry_signature,
        working_dir,
        arguments,
        environment,
        host_proxy,
    })
}

// ── launch metadata budget validation ─────────────────────────────────

/// Validate that launch metadata (arguments, environment, and working
/// directory) stays within the enforced budgets.
pub(crate) fn validate_launch_metadata_budget(
    arguments: &[String],
    environment: &[String],
    working_dir: &str,
) -> Result<()> {
    if arguments.len() > MAX_METADATA_ARGUMENTS {
        return Err(Error::InvalidArgument);
    }
    if environment.len() > MAX_METADATA_ENVIRONMENT {
        return Err(Error::InvalidArgument);
    }
    if working_dir.len() > MAX_METADATA_WORKING_DIR_BYTES {
        return Err(Error::InvalidArgument);
    }

    let mut argument_bytes = 0usize;
    for argument in arguments {
        if argument.len() > MAX_METADATA_ENTRY_BYTES {
            return Err(Error::InvalidArgument);
        }
        argument_bytes = argument_bytes.saturating_add(argument.len());
    }
    if argument_bytes > MAX_METADATA_ARGUMENTS_TOTAL_BYTES {
        return Err(Error::InvalidArgument);
    }

    let mut environment_bytes = 0usize;
    for entry in environment {
        if entry.len() > MAX_METADATA_ENTRY_BYTES {
            return Err(Error::InvalidArgument);
        }
        environment_bytes = environment_bytes.saturating_add(entry.len());
    }
    if environment_bytes > MAX_METADATA_ENVIRONMENT_TOTAL_BYTES {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

// ── string literal rendering ──────────────────────────────────────────

/// Render `value` as a double-quoted TOML-style string literal.
///
/// Used only by the appctl/lumina CLI surface (demo disk / tests), so it is
/// gated with that module.
#[cfg(any(test, feature = "demo-disk"))]
pub(crate) fn render_string_literal(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for ch in value.chars() {
        match ch {
            '"' => rendered.push_str("\\\""),
            '\\' => rendered.push_str("\\\\"),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            '\0' => rendered.push_str("\\0"),
            ch if (ch as u32) < 0x20 => rendered.push_str(&format!("\\x{:02x}", ch as u32)),
            ch => rendered.push(ch),
        }
    }
    rendered.push('"');
    rendered
}

/// Render a list of strings as a TOML-style array of string literals.
///
/// Used only by the `render_list_round_trip` unit test, so it is gated to
/// test builds.
#[cfg(test)]
pub(crate) fn render_string_list_literal(values: &[String]) -> String {
    let mut rendered = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            rendered.push_str(", ");
        }
        rendered.push_str(&render_string_literal(value));
    }
    rendered.push(']');
    rendered
}

// ── string literal parsing ────────────────────────────────────────────

/// Parse a double-quoted TOML-style string literal (starting at the opening
/// quote).  Supported escapes: `\"`, `\\`, `\n`, `\r`, `\t`, `\0`, `\xHH`.
///
/// The input must be exactly one string literal: the text after the closing
/// quote (if any) must be whitespace.
pub(crate) fn parse_string_literal(text: &str) -> Result<String> {
    let text = text.trim_start();
    let mut chars = text.chars();

    let Some(first) = chars.next() else {
        return Err(Error::InvalidArgument);
    };
    if first != '"' {
        return Err(Error::InvalidArgument);
    }

    let mut parsed = String::new();
    let mut closed = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                closed = true;
                break;
            }
            '\\' => {
                let escaped = chars.next().ok_or(Error::InvalidArgument)?;
                match escaped {
                    'n' => parsed.push('\n'),
                    'r' => parsed.push('\r'),
                    't' => parsed.push('\t'),
                    '0' => parsed.push('\0'),
                    '"' => parsed.push('"'),
                    '\\' => parsed.push('\\'),
                    'x' => {
                        let high = chars.next().ok_or(Error::InvalidArgument)?;
                        let low = chars.next().ok_or(Error::InvalidArgument)?;
                        let byte = (hex_digit_value(high)? << 4) | hex_digit_value(low)?;
                        parsed.push(char::from(byte));
                    }
                    _ => return Err(Error::InvalidArgument),
                }
            }
            ch => parsed.push(ch),
        }
    }

    if !closed {
        return Err(Error::InvalidArgument);
    }
    // Only trailing whitespace is permitted after the closing quote.
    if chars.any(|ch| !ch.is_whitespace()) {
        return Err(Error::InvalidArgument);
    }

    Ok(parsed)
}

/// Parse a TOML-style array of string literals, e.g. `["a", "b"]`.
pub(crate) fn parse_string_list_literal(text: &str) -> Result<Vec<String>> {
    let text = text.trim();
    let Some(rest) = text.strip_prefix('[') else {
        return Err(Error::InvalidArgument);
    };
    let Some(rest) = rest.strip_suffix(']') else {
        return Err(Error::InvalidArgument);
    };

    let mut items = Vec::new();
    for item in split_list_items(rest) {
        items.push(parse_string_literal(&item)?);
    }
    Ok(items)
}

// ── field lookup helpers ──────────────────────────────────────────────

/// Find the `field = ` assignment in `text` and return the trimmed value
/// (the text after `=`), or `None` when the field is absent.
fn find_field_value<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(field) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        return Some(rest.trim());
    }
    None
}

/// Parse a required `field = "…"` string field.
pub(crate) fn parse_string_field(text: &str, field: &str) -> Result<String> {
    let value = find_field_value(text, field).ok_or(Error::InvalidArgument)?;
    parse_string_literal(value)
}

/// Parse an optional `field = "…"` string field, returning `Ok(None)` when
/// the field is absent.
pub(crate) fn parse_optional_string_field(text: &str, field: &str) -> Result<Option<String>> {
    let Some(value) = find_field_value(text, field) else {
        return Ok(None);
    };
    parse_string_literal(value).map(Some)
}

/// Parse an optional `field = ["…", …]` list field, returning an empty list
/// when the field is absent.
pub(crate) fn parse_string_list_field(text: &str, field: &str) -> Result<Vec<String>> {
    let Some(value) = find_field_value(text, field) else {
        return Ok(Vec::new());
    };
    parse_string_list_literal(value)
}

// ── list splitting ────────────────────────────────────────────────────

/// Split a TOML array body on top-level commas, keeping quoted strings
/// intact (escaped quotes are preserved as literal pairs).
fn split_list_items(text: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_string = false;

    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                // Keep the escape sequence together so `\"` does not toggle
                // in_string.
                current.push(ch);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '"' => {
                in_string = !in_string;
                current.push(ch);
            }
            ',' if !in_string => {
                let item = current.trim().to_string();
                if !item.is_empty() {
                    items.push(item);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let last = current.trim().to_string();
    if !last.is_empty() {
        items.push(last);
    }
    items
}

/// Decode a single hex nibble character.
fn hex_digit_value(ch: char) -> Result<u8> {
    match ch {
        '0'..='9' => Ok(ch as u8 - b'0'),
        'a'..='f' => Ok(ch as u8 - b'a' + 10),
        'A'..='F' => Ok(ch as u8 - b'A' + 10),
        _ => Err(Error::InvalidArgument),
    }
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn catalog_entry_text() -> &'static str {
        "id = \"shell\"\nversion = \"0.1.0\"\ncatalog = \"./shell@0.1.0.toml\"\n"
    }

    fn manifest_text() -> &'static str {
        "name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\n\
         entry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\n\
         argv = [\"shell\", \"-i\"]\nenv = [\"TERM=vt100\"]\n"
    }

    #[test]
    fn parse_catalog_entry_parses_alias() {
        let entry = parse_catalog_entry(catalog_entry_text()).expect("parse catalog");
        assert_eq!(entry.id, "shell");
        assert_eq!(entry.version.as_deref(), Some("0.1.0"));
        assert_eq!(entry.catalog_path.as_deref(), Some("./shell@0.1.0.toml"));
        assert_eq!(entry.manifest_path, None);
    }

    #[test]
    fn parse_catalog_entry_parses_versioned() {
        let text = "id = \"shell\"\nmanifest = \"/apps/packages/shell/manifest.toml\"\n\
                    manifest_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";
        let entry = parse_catalog_entry(text).expect("parse catalog");
        assert_eq!(entry.id, "shell");
        assert_eq!(
            entry.manifest_path.as_deref(),
            Some("/apps/packages/shell/manifest.toml")
        );
        assert!(entry.manifest_sha256.is_some());
    }

    #[test]
    fn parse_catalog_entry_rejects_missing_target() {
        assert_eq!(
            parse_catalog_entry("id = \"shell\"\n"),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn parse_catalog_entry_rejects_bad_sha256() {
        let text = "id = \"shell\"\nmanifest = \"/apps/m.toml\"\nmanifest_sha256 = \"xyz\"\n";
        assert_eq!(parse_catalog_entry(text), Err(Error::InvalidArgument));
    }

    #[test]
    fn parse_launch_manifest_parses_fields() {
        let manifest = parse_launch_manifest(manifest_text()).expect("parse manifest");
        assert_eq!(manifest.name, "shell");
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.format, "elf64-x86_64-user");
        assert_eq!(manifest.entry_path, "/apps/packages/shell/bin/shell.elf");
        assert_eq!(manifest.working_dir, "/apps/packages/shell");
        assert_eq!(manifest.arguments, ["shell", "-i"]);
        assert_eq!(manifest.environment, ["TERM=vt100"]);
        assert_eq!(manifest.host_proxy, None);
    }

    #[test]
    fn parse_launch_manifest_rejects_missing_entry() {
        assert_eq!(
            parse_launch_manifest(
                "name = \"x\"\nversion = \"1\"\nformat = \"elf\"\nworking_dir = \"/\"\n"
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn string_literal_round_trip() {
        for value in [
            "plain",
            "with \"quotes\" and \\ backslashes",
            "line\nbreak\tand\rreturns",
            "",
        ] {
            let rendered = render_string_literal(value);
            assert_eq!(parse_string_literal(&rendered).expect("parse"), value);
        }
    }

    #[test]
    fn render_list_round_trip() {
        let values = vec![String::from("a"), String::from("b c"), String::from("d,e")];
        let rendered = render_string_list_literal(&values);
        assert_eq!(parse_string_list_literal(&rendered).expect("parse"), values);
    }

    #[test]
    fn string_field_lookup_is_exact() {
        let text = "name = \"x\"\nname_suffix = \"y\"\n";
        assert_eq!(parse_string_field(text, "name").expect("name"), "x");
        assert_eq!(
            parse_optional_string_field(text, "name_suffix").expect("suffix"),
            Some(String::from("y"))
        );
        assert_eq!(parse_optional_string_field(text, "absent"), Ok(None));
    }

    #[test]
    fn launch_metadata_budget_accepts_reasonable_input() {
        let arguments = vec![String::from("app"), String::from("--flag")];
        let environment = vec![String::from("TERM=xterm")];
        assert_eq!(
            validate_launch_metadata_budget(&arguments, &environment, "/apps/packages/app"),
            Ok(())
        );
    }

    #[test]
    fn launch_metadata_budget_rejects_oversized_argument() {
        let arguments = vec!["a".repeat(MAX_METADATA_ENTRY_BYTES + 1)];
        assert_eq!(
            validate_launch_metadata_budget(&arguments, &[], "/"),
            Err(Error::InvalidArgument)
        );
    }
}
