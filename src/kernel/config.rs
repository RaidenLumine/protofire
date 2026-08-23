//! src/kernel/config.rs
//! Minimal TOML-subset parser for kernel configuration files.
//!
//! Supports the subset needed by service definitions and kernel config:
//! - Top-level `key = "value"` pairs (string, integer, boolean)
//! - `[section]` headers for named tables
//! - `[[array]]` headers for arrays of tables
//! - `#` line comments (outside quoted strings)
//! - String escape sequences (\", \\, \n, \r, \t, \0, \u{...})
//!
//! This is intentionally NOT a full TOML parser — it handles only the
//! constructs used by kernel and distribution configuration files.

use alloc::string::String;
use alloc::vec::Vec;

// ── Error type ───────────────────────────────────────────────────────────────

/// Lightweight config parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A required key or section was not found.
    NotFound,
    /// The value could not be parsed (wrong type, malformed escape, etc.).
    InvalidValue,
    /// A section header syntax error (e.g. `[unclosed`).
    MalformedSection,
}

impl ConfigError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfigError::NotFound => "config key not found",
            ConfigError::InvalidValue => "invalid config value",
            ConfigError::MalformedSection => "malformed section header",
        }
    }
}

// ── Parsed config representation ─────────────────────────────────────────────

/// A single key-value pair from a TOML-like config file.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    StringList(Vec<String>),
}

/// One section: either a top-level key-value collection or a named `[section]`.
#[derive(Debug, Clone)]
pub struct ConfigSection {
    pub name: Option<String>, // None = top-level (before any [section])
    pub entries: Vec<(String, ConfigValue)>,
}

/// One element of an `[[array]]` — identical to a section but tagged with the
/// array name.
#[derive(Debug, Clone)]
pub struct ConfigArrayElement {
    pub array_name: String,
    pub entries: Vec<(String, ConfigValue)>,
}

/// Parsed configuration document.
#[derive(Debug, Clone, Default)]
pub struct ConfigDocument {
    /// Top-level key-value pairs (before any `[section]`).
    pub root: Vec<(String, ConfigValue)>,
    /// Named sections: `[name]`.
    pub sections: Vec<ConfigSection>,
    /// Array-of-tables elements: `[[name]]`.
    pub arrays: Vec<ConfigArrayElement>,
}

impl ConfigDocument {
    /// Look up a top-level string value by key.
    pub fn get_str(&self, key: &str) -> Result<&str, ConfigError> {
        for (k, v) in &self.root {
            if k == key {
                return match v {
                    ConfigValue::String(s) => Ok(s.as_str()),
                    _ => Err(ConfigError::InvalidValue),
                };
            }
        }
        Err(ConfigError::NotFound)
    }

    /// Look up a top-level string value, returning `default` if absent.
    pub fn get_str_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get_str(key).unwrap_or(default)
    }

    /// Look up a top-level boolean value by key.
    pub fn get_bool(&self, key: &str) -> Result<bool, ConfigError> {
        for (k, v) in &self.root {
            if k == key {
                return match v {
                    ConfigValue::Boolean(b) => Ok(*b),
                    _ => Err(ConfigError::InvalidValue),
                };
            }
        }
        Err(ConfigError::NotFound)
    }

    /// Look up a top-level boolean, returning `default` if absent.
    pub fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    /// Find a named section by its `[name]`.
    pub fn section(&self, name: &str) -> Option<&ConfigSection> {
        self.sections
            .iter()
            .find(|s| s.name.as_deref() == Some(name))
    }

    /// Return all elements of an `[[array]]` with the given name.
    pub fn array_elements(&self, array_name: &str) -> Vec<&ConfigArrayElement> {
        self.arrays
            .iter()
            .filter(|e| e.array_name == array_name)
            .collect()
    }
}

// ── Section helpers (shared lookup logic for sections and array elements) ───

/// Trait for anything that holds key-value pairs.
pub trait ConfigEntryLookup {
    fn entries(&self) -> &[(String, ConfigValue)];

    fn get_str(&self, key: &str) -> Result<&str, ConfigError> {
        for (k, v) in self.entries() {
            if k == key {
                return match v {
                    ConfigValue::String(s) => Ok(s.as_str()),
                    _ => Err(ConfigError::InvalidValue),
                };
            }
        }
        Err(ConfigError::NotFound)
    }

    fn get_str_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get_str(key).unwrap_or(default)
    }

    fn get_bool(&self, key: &str) -> Result<bool, ConfigError> {
        for (k, v) in self.entries() {
            if k == key {
                return match v {
                    ConfigValue::Boolean(b) => Ok(*b),
                    _ => Err(ConfigError::InvalidValue),
                };
            }
        }
        Err(ConfigError::NotFound)
    }

    fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    fn get_i64(&self, key: &str) -> Result<i64, ConfigError> {
        for (k, v) in self.entries() {
            if k == key {
                return match v {
                    ConfigValue::Integer(i) => Ok(*i),
                    _ => Err(ConfigError::InvalidValue),
                };
            }
        }
        Err(ConfigError::NotFound)
    }

    fn get_string_list(&self, key: &str) -> Result<Vec<String>, ConfigError> {
        for (k, v) in self.entries() {
            if k == key {
                return match v {
                    ConfigValue::StringList(list) => Ok(list.clone()),
                    _ => Err(ConfigError::InvalidValue),
                };
            }
        }
        Ok(Vec::new()) // missing list = empty
    }
}

impl ConfigEntryLookup for ConfigSection {
    fn entries(&self) -> &[(String, ConfigValue)] {
        &self.entries
    }
}

impl ConfigEntryLookup for ConfigArrayElement {
    fn entries(&self) -> &[(String, ConfigValue)] {
        &self.entries
    }
}

// ── Parser ───────────────────────────────────────────────────────────────────

/// Parse a TOML-subset config document from text.
pub fn parse_config(text: &str) -> Result<ConfigDocument, ConfigError> {
    let mut doc = ConfigDocument::default();
    let mut current_section: Option<String> = None; // None = root
    let mut current_entries: Vec<(String, ConfigValue)> = Vec::new();

    // Flush entries to the right destination:
    // - section=None  → doc.root (root-level key-value pairs)
    // - section=Some  → doc.sections (named [section])
    //
    // Named sections are always pushed — even when empty — so that
    // `doc.section("name")` can find a section with no keys.
    let flush_current = |section: &mut Option<String>,
                         entries: &mut Vec<(String, ConfigValue)>,
                         doc: &mut ConfigDocument| {
        let name = section.take();
        if let Some(section_name) = name {
            doc.sections.push(ConfigSection {
                name: Some(section_name),
                entries: core::mem::take(entries),
            });
        } else if !entries.is_empty() {
            // Root entries — append to doc.root.
            doc.root.append(entries);
        }
    };

    // When true, key-value pairs go into the last array element instead
    // of current_entries.  Reset when a [section] header appears.
    let mut in_array = false;

    for raw_line in text.lines() {
        let line = String::from(strip_line_comment(raw_line).trim());
        if line.is_empty() {
            continue;
        }

        // ── Section headers ──────────────────────────────────────────
        if line.starts_with("[[") && line.ends_with("]]") {
            // Array-of-tables: [[name]]
            flush_current(&mut current_section, &mut current_entries, &mut doc);
            let name = line[2..line.len() - 2].trim();
            if name.is_empty() {
                return Err(ConfigError::MalformedSection);
            }
            current_section = None;
            in_array = true;
            doc.arrays.push(ConfigArrayElement {
                array_name: String::from(name),
                entries: Vec::new(),
            });
            continue;
        }

        if line.starts_with('[') && !line.starts_with("[[") {
            // Must be a named section: [name].
            if !line.ends_with(']') {
                return Err(ConfigError::MalformedSection);
            }
            in_array = false;
            flush_current(&mut current_section, &mut current_entries, &mut doc);
            let name = line[1..line.len() - 1].trim();
            if name.is_empty() {
                return Err(ConfigError::MalformedSection);
            }
            current_section = Some(String::from(name));
            continue;
        }

        // A line starting with '[' that didn't match any section pattern
        // (e.g. `[unclosed` without `]`, or malformed `[[` header) is
        // always an error.
        if line.starts_with('[') {
            return Err(ConfigError::MalformedSection);
        }

        // ── Key = value ─────────────────────────────────────────────
        let Some((key, raw_value)) = line.split_once('=') else {
            // Lines without '=' inside a section/array element are
            // silently skipped (could be blank after comment strip).
            continue;
        };

        let key: String = String::from(key.trim());
        let raw_value: &str = raw_value.trim();
        if key.is_empty() {
            continue;
        }

        let value = parse_value(raw_value)?;

        // Place the entry in the right collection.
        if in_array {
            if let Some(last_array) = doc.arrays.last_mut() {
                last_array.entries.push((key, value));
            }
        } else {
            current_entries.push((key, value));
        }
    }

    // Flush any remaining entries (only flushes if section is named).
    flush_current(&mut current_section, &mut current_entries, &mut doc);

    // Root-level key-value pairs remain in current_entries.
    if !current_entries.is_empty() {
        doc.root = current_entries;
    }

    Ok(doc)
}

fn parse_value(raw: &str) -> Result<ConfigValue, ConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ConfigError::InvalidValue);
    }

    // Boolean
    if raw == "true" {
        return Ok(ConfigValue::Boolean(true));
    }
    if raw == "false" {
        return Ok(ConfigValue::Boolean(false));
    }

    // Integer (signed 64-bit)
    if let Ok(i) = raw.parse::<i64>() {
        return Ok(ConfigValue::Integer(i));
    }

    // String list: ["a", "b"]
    if raw.starts_with('[') && raw.ends_with(']') {
        return parse_string_list_literal(raw).map(ConfigValue::StringList);
    }

    // String: "value"
    if raw.starts_with('"') {
        return parse_string_literal(raw).map(ConfigValue::String);
    }

    // Bare string (unquoted single word)
    // For simplicity, treat any unrecognized value as a bare string.
    Ok(ConfigValue::String(String::from(raw)))
}

// ── String literal parsing (reuses metadata.rs patterns) ────────────────────

fn parse_string_literal(value: &str) -> Result<String, ConfigError> {
    let (parsed, rest) = parse_string_literal_prefix(value)?;
    if !rest.trim().is_empty() {
        return Err(ConfigError::InvalidValue);
    }
    Ok(parsed)
}

fn parse_string_list_literal(value: &str) -> Result<Vec<String>, ConfigError> {
    let inner = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .ok_or(ConfigError::InvalidValue)?;
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }

    let mut rest = inner;
    let mut items = Vec::new();
    while !rest.is_empty() {
        let (item, next) = parse_string_literal_prefix(rest)?;
        items.push(item);
        rest = next.trim_start();
        if rest.is_empty() {
            break;
        }
        let Some(after_comma) = rest.strip_prefix(',') else {
            return Err(ConfigError::InvalidValue);
        };
        rest = after_comma.trim_start();
    }
    Ok(items)
}

fn parse_string_literal_prefix(value: &str) -> Result<(String, &str), ConfigError> {
    let Some(rest) = value.strip_prefix('"') else {
        return Err(ConfigError::InvalidValue);
    };
    let mut cursor = 0usize;
    let bytes = rest.as_bytes();
    let mut parsed = String::new();

    while cursor < bytes.len() {
        let ch = bytes[cursor];
        cursor += 1;
        match ch {
            b'"' => return Ok((parsed, &rest[cursor..])),
            b'\\' => {
                if cursor >= bytes.len() {
                    return Err(ConfigError::InvalidValue);
                }
                let escaped = bytes[cursor];
                cursor += 1;
                match escaped {
                    b'"' => parsed.push('"'),
                    b'\\' => parsed.push('\\'),
                    b'n' => parsed.push('\n'),
                    b'r' => parsed.push('\r'),
                    b't' => parsed.push('\t'),
                    b'0' => parsed.push('\0'),
                    b'u' => {
                        // \u{XXXX}
                        if cursor >= bytes.len() || bytes[cursor] != b'{' {
                            return Err(ConfigError::InvalidValue);
                        }
                        cursor += 1;
                        let hex_start = cursor;
                        while cursor < bytes.len() && bytes[cursor] != b'}' {
                            if !bytes[cursor].is_ascii_hexdigit() {
                                return Err(ConfigError::InvalidValue);
                            }
                            cursor += 1;
                        }
                        if cursor >= bytes.len() || cursor == hex_start {
                            return Err(ConfigError::InvalidValue);
                        }
                        let hex_str = core::str::from_utf8(&bytes[hex_start..cursor])
                            .map_err(|_| ConfigError::InvalidValue)?;
                        let scalar = u32::from_str_radix(hex_str, 16)
                            .map_err(|_| ConfigError::InvalidValue)?;
                        let ch = char::from_u32(scalar).ok_or(ConfigError::InvalidValue)?;
                        parsed.push(ch);
                        cursor += 1; // skip '}'
                    }
                    _ => return Err(ConfigError::InvalidValue),
                }
            }
            b'\n' | b'\r' => return Err(ConfigError::InvalidValue),
            _ => parsed.push(ch as char),
        }
    }

    Err(ConfigError::InvalidValue)
}

// ── Comment stripping ────────────────────────────────────────────────────────

fn strip_line_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escape = false;

    for (index, ch) in line.char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            match ch {
                '\\' => escape = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '#' => return &line[..index],
            _ => {}
        }
    }
    line
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parse_empty_document() {
        let doc = parse_config("").expect("parse empty");
        assert!(doc.root.is_empty());
        assert!(doc.sections.is_empty());
        assert!(doc.arrays.is_empty());
    }

    #[test]
    fn parse_top_level_string() {
        let doc = parse_config("name = \"hello\"\n").expect("parse");
        assert_eq!(doc.get_str("name"), Ok("hello"));
    }

    #[test]
    fn parse_top_level_bool() {
        let doc = parse_config("enabled = true\nverbose = false\n").expect("parse");
        assert!(doc.get_bool("enabled").unwrap());
        assert!(!doc.get_bool("verbose").unwrap());
    }

    #[test]
    fn parse_top_level_integer() {
        let doc = parse_config("port = 8080\ncount = -1\n").expect("parse");
        let port = doc.root.iter().find(|(k, _)| k == "port").unwrap();
        assert_eq!(port.1, ConfigValue::Integer(8080));
    }

    #[test]
    fn parse_string_list() {
        let doc = parse_config("args = [\"--help\", \"--verbose\"]\n").expect("parse");
        let (_, val) = doc.root.iter().find(|(k, _)| k == "args").unwrap();
        assert_eq!(
            val,
            &ConfigValue::StringList(vec![String::from("--help"), String::from("--verbose")])
        );
    }

    #[test]
    fn parse_empty_string_list() {
        let doc = parse_config("args = []\n").expect("parse");
        let (_, val) = doc.root.iter().find(|(k, _)| k == "args").unwrap();
        assert_eq!(val, &ConfigValue::StringList(Vec::new()));
    }

    #[test]
    fn parse_with_comments() {
        let doc = parse_config(
            "# comment\nname = \"hello\" # inline\n# another comment\nversion = \"1\"\n",
        )
        .expect("parse");
        assert_eq!(doc.get_str("name"), Ok("hello"));
        assert_eq!(doc.get_str("version"), Ok("1"));
    }

    #[test]
    fn parse_named_section() {
        let text = "top = \"root\"\n[network]\nhost = \"localhost\"\nport = 8080\n";
        let doc = parse_config(text).expect("parse");
        assert_eq!(doc.get_str("top"), Ok("root"));

        let net = doc.section("network").expect("section exists");
        assert_eq!(net.get_str("host"), Ok("localhost"));
        assert_eq!(net.get_i64("port"), Ok(8080));
    }

    #[test]
    fn parse_array_of_tables() {
        let text = "format = \"1\"\n[[service]]\nname = \"a\"\n[[service]]\nname = \"b\"\n";
        let doc = parse_config(text).expect("parse");
        assert_eq!(doc.get_str("format"), Ok("1"));

        let services = doc.array_elements("service");
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].get_str("name"), Ok("a"));
        assert_eq!(services[1].get_str("name"), Ok("b"));
    }

    #[test]
    fn parse_array_of_tables_with_multiple_fields() {
        let text = "[[service]]\nname = \"shell\"\nkind = \"user_program\"\npath = \"/system/shell.elf\"\nauto_restart = false\n";
        let doc = parse_config(text).expect("parse");
        let svc = &doc.array_elements("service")[0];
        assert_eq!(svc.get_str("name"), Ok("shell"));
        assert_eq!(svc.get_str("kind"), Ok("user_program"));
        assert_eq!(svc.get_str("path"), Ok("/system/shell.elf"));
        assert!(!svc.get_bool("auto_restart").unwrap());
    }

    #[test]
    fn parse_section_then_array() {
        let text =
            "[global]\nkey = \"val\"\n[[worker]]\nname = \"w1\"\n[[worker]]\nname = \"w2\"\n";
        let doc = parse_config(text).expect("parse");

        let global = doc.section("global").expect("global section");
        assert_eq!(global.get_str("key"), Ok("val"));

        let workers = doc.array_elements("worker");
        assert_eq!(workers.len(), 2);
    }

    #[test]
    fn parse_array_then_section() {
        let text = "[[program]]\npath = \"/bin/a\"\n[[program]]\npath = \"/bin/b\"\n[meta]\nversion = \"1\"\n";
        let doc = parse_config(text).expect("parse");

        let progs = doc.array_elements("program");
        assert_eq!(progs.len(), 2);
        assert_eq!(progs[0].get_str("path"), Ok("/bin/a"));
        assert_eq!(progs[1].get_str("path"), Ok("/bin/b"));

        let meta = doc.section("meta").expect("meta section");
        assert_eq!(meta.get_str("version"), Ok("1"));
    }

    #[test]
    fn string_literal_escapes() {
        let val = parse_string_literal("\"hello\\nworld\\ttab\"").expect("parse");
        assert_eq!(val, "hello\nworld\ttab");
    }

    #[test]
    fn string_literal_unicode_escape() {
        let val = parse_string_literal("\"\\u{4e2d}\\u{6587}\"").expect("parse");
        assert_eq!(val, "中文");
    }

    #[test]
    fn parse_bare_string_fallback() {
        let doc = parse_config("kind = user_program\n").expect("parse");
        assert_eq!(doc.get_str("kind"), Ok("user_program"));
    }

    #[test]
    fn get_str_or_default() {
        let doc = parse_config("name = \"test\"\n").expect("parse");
        assert_eq!(doc.get_str_or("name", "default"), "test");
        assert_eq!(doc.get_str_or("missing", "default"), "default");
    }

    #[test]
    fn get_bool_or_default() {
        let doc = parse_config("").expect("parse");
        assert!(doc.get_bool_or("auto_restart", true));
        assert!(!doc.get_bool_or("auto_restart", false));
    }

    #[test]
    fn parse_rejects_empty_array_of_tables_name() {
        // "[[]]" has an empty name between [[ and ]].
        assert!(parse_config("[[]]\n").is_err());
    }

    #[test]
    fn parse_rejects_unclosed_section_header() {
        // "[unclosed" without closing bracket.
        assert!(parse_config("[unclosed\n").is_err());
    }

    #[test]
    fn parse_rejects_malformed_string_escape() {
        // Invalid escape sequence inside string.
        assert!(parse_config("key = \"bad\\xescape\"\n").is_err());
    }

    #[test]
    fn parse_comment_inside_string_is_part_of_value() {
        // "#" inside a quoted string is not a comment start.
        let doc = parse_config("value = \"hello # world\"\n").expect("parse");
        assert_eq!(doc.get_str("value"), Ok("hello # world"));
    }

    #[test]
    fn parse_string_with_embedded_equals() {
        // "=" inside a quoted string shouldn't cause parsing issues.
        let doc = parse_config("formula = \"1 + 2 = 3\"\n").expect("parse");
        assert_eq!(doc.get_str("formula"), Ok("1 + 2 = 3"));
    }

    #[test]
    fn parse_section_with_no_entries() {
        let text = "[empty]\n[different]\nkey = \"val\"\n";
        let doc = parse_config(text).expect("parse");
        assert!(doc.section("empty").is_some());
        assert_eq!(doc.section("different").unwrap().get_str("key"), Ok("val"));
    }

    #[test]
    fn parse_section_after_array_stops_inline_array_mode() {
        // A [section] after [[array]] should close the array context.
        let text = "[[arr]]\nk = \"v1\"\n[[arr]]\nk = \"v2\"\n[sec]\nkey = \"val\"\n";
        let doc = parse_config(text).expect("parse");
        assert_eq!(doc.array_elements("arr").len(), 2);
        assert_eq!(doc.section("sec").unwrap().get_str("key"), Ok("val"));
    }

    #[test]
    fn parse_array_element_boolean_and_string_list() {
        let text = "[[item]]\nactive = true\nargs = [\"a\", \"b\"]\n";
        let doc = parse_config(text).expect("parse");
        let items = doc.array_elements("item");
        assert_eq!(items.len(), 1);
        assert!(items[0].get_bool("active").unwrap());
        assert_eq!(
            items[0].get_string_list("args"),
            Ok(alloc::vec![String::from("a"), String::from("b")])
        );
    }

    #[test]
    fn section_get_str_or_default() {
        let text = "[s]\nname = \"hello\"\n";
        let doc = parse_config(text).expect("parse");
        let sec = doc.section("s").unwrap();
        assert_eq!(sec.get_str_or("name", "default"), "hello");
        assert_eq!(sec.get_str_or("missing", "default"), "default");
    }

    #[test]
    fn section_get_bool_or_default() {
        let text = "[s]\n";
        let doc = parse_config(text).expect("parse");
        let sec = doc.section("s").unwrap();
        assert!(sec.get_bool_or("enabled", true));
        assert!(!sec.get_bool_or("enabled", false));
    }

    #[test]
    fn parse_root_keys_between_arrays() {
        // Root-level keys alongside array-of-tables entries.
        let text = "version = \"1\"\n[[entry]]\nname = \"a\"\ncount = 3\n[[entry]]\nname = \"b\"\n";
        let doc = parse_config(text).expect("parse");
        assert_eq!(doc.get_str("version"), Ok("1"));
        // "count = 3" appears after "name" in the first array element,
        // so it lands in that element, not a new one.
        let entries = doc.array_elements("entry");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].get_str("name"), Ok("a"));
        assert_eq!(entries[0].get_i64("count"), Ok(3));
        assert_eq!(entries[1].get_str("name"), Ok("b"));
    }
}
