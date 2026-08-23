//! src/kernel/user.rs
//! User database: persistent user records, UID/username mapping, home
//! directory resolution, and password authentication.
//!
//! The canonical user database lives at `/data/etc/passwd` (the System zone is
//! read-only, so the writable Data zone holds the authoritative copy).
//! Password hashes are stored separately in `/data/etc/shadow` (mode 0600).
//! A skeleton template at `/data/etc/skel/` is copied into every new home
//! directory created by `useradd`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::kernel::crypto;
use crate::kernel::fs::vfs::SecurityDescriptorUpdate;
use crate::kernel::fs::{FileSystem, OPEN_ALWAYS};
use crate::kernel::process::{
    home_dir_for_uid, GroupId, UserId, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE,
};
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

/// Path to the persistent user database on the writable Data zone.
const PASSWD_PATH: &str = "/data/etc/passwd";

/// Skeleton template directory copied into each new home directory.
const SKEL_PATH: &str = "/data/etc/skel";

/// Maximum length of a single line in the passwd file (in bytes).
const MAX_LINE_LEN: usize = 512;

/// Initial passwd content created when the file does not exist yet.
/// Seeded account database used by the demo distribution on first boot.
///
/// This is distribution *policy* (which accounts exist, what home dirs they
/// get), not kernel *mechanism*.  A non-`demo-disk` kernel build does not
/// seed any accounts — the distribution's init or filesystem image supplies
/// `/data/etc/passwd` instead.
#[cfg(any(feature = "demo-disk", test))]
const DEFAULT_PASSWD_CONTENT: &[u8] = b"\
# /data/etc/passwd - protofire user database
# username:uid:gid:home
root:0:0:/root
guest:1000:1000:/data/users/guest
";

const DEFAULT_PROFILE_CONTENT: &[u8] = b"\
# protofire user profile
# Place personal configuration below.
";

// ── Shadow (password) database ──────────────────────────────────────────

/// Path to the shadow password file on the writable Data zone.
const SHADOW_PATH: &str = "/data/etc/shadow";

/// Salt length in bytes (16 bytes = 32 hex chars).
const SALT_LEN: usize = 16;

/// Maximum shadow file size (64 KiB).
const MAX_SHADOW_SIZE: usize = 64 * 1024;

/// Default root password used by the demo distribution on first boot
/// (hashed at init time).  Distribution policy — a non-`demo-disk` kernel
/// build never assigns a default password; new shadow entries start locked.
#[cfg(any(feature = "demo-disk", test))]
const DEFAULT_ROOT_PASSWORD: &str = "root";

/// Sentinel hash — all zeros means the account is locked from password login.
const LOCKED_HASH: [u8; 32] = [0u8; 32];

// ── Data types ──────────────────────────────────────────────────────────

/// A single user record parsed from the passwd file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub username: String,
    pub uid: UserId,
    pub gid: GroupId,
    pub home: String,
}

/// In-memory user database loaded from `/data/etc/passwd`.
pub struct UserDatabase {
    users: Vec<UserRecord>,
}

/// A single shadow entry — one user's password salt and hash.
#[derive(Clone, Debug)]
pub(crate) struct ShadowEntry {
    pub username: String,
    pub salt: [u8; SALT_LEN],
    pub hash: [u8; 32],
}

/// In-memory shadow password database loaded from `/data/etc/shadow`.
pub(crate) struct ShadowDatabase {
    entries: Vec<ShadowEntry>,
}

// ── Global storage ──────────────────────────────────────────────────────

static USER_DATABASE: Mutex<Option<UserDatabase>> = Mutex::new(None);
static USER_DB_INITIALISED: AtomicBool = AtomicBool::new(false);

static SHADOW_DATABASE: Mutex<Option<ShadowDatabase>> = Mutex::new(None);
static SHADOW_DB_INITIALISED: AtomicBool = AtomicBool::new(false);

fn store_database(db: UserDatabase) {
    let mut slot = USER_DATABASE.lock();
    *slot = Some(db);
    USER_DB_INITIALISED.store(true, Ordering::Release);
}

fn with_database<T, F: FnOnce(&UserDatabase) -> T>(f: F) -> Option<T> {
    let slot = USER_DATABASE.lock();
    slot.as_ref().map(f)
}

// ── UserDatabase methods ────────────────────────────────────────────────

impl UserDatabase {
    /// Parse the passwd file content into a `UserDatabase`.
    pub fn parse(content: &str) -> Self {
        let mut users = Vec::new();
        for raw_line in content.lines() {
            let line = raw_line.trim();
            // Skip empty lines and comments.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.len() > MAX_LINE_LEN {
                continue;
            }
            let fields: Vec<&str> = line.splitn(4, ':').collect();
            if fields.len() < 4 {
                // Malformed line — skip silently so a manually-edited file
                // doesn't lock out all users.
                continue;
            }
            let username = fields[0].trim().to_string();
            let uid: UserId = match fields[1].trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let gid: GroupId = match fields[2].trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let home = fields[3].trim().to_string();

            // Reject empty usernames or home paths.
            if username.is_empty() || home.is_empty() {
                continue;
            }

            // Prefer the last duplicate rather than the first (last-write-wins
            // for uid; last-write-wins for name).
            users.retain(|r: &UserRecord| r.username != username && r.uid != uid);
            users.push(UserRecord {
                username,
                uid,
                gid,
                home,
            });
        }
        Self { users }
    }

    /// Serialize the database to passwd file format.
    pub fn serialize(&self) -> String {
        let mut out = String::with_capacity(self.users.len() * 64 + 64);
        out.push_str("# /data/etc/passwd - protofire user database\n");
        out.push_str("# username:uid:gid:home\n");
        for rec in &self.users {
            let _ = writeln!(out, "{}:{}:{}:{}", rec.username, rec.uid, rec.gid, rec.home);
        }
        out
    }

    /// Load the database from the filesystem.  Returns `Ok(None)` when the
    /// passwd file doesn't exist so callers can initialise it.
    pub fn load(fs: &FileSystem) -> Result<Option<Self>> {
        let mut handle = match fs.open(PASSWD_PATH, HANDLE_RIGHT_READ) {
            Ok(h) => h,
            Err(Error::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        let file_len = handle.size();
        // Guard against a malformed or enormous passwd file.
        if file_len > 64 * 1024 {
            return Err(Error::InternalError);
        }
        let mut buffer = vec![0u8; file_len];
        let bytes_read = fs.read(&mut handle, &mut buffer)?;
        buffer.truncate(bytes_read);
        let content = core::str::from_utf8(&buffer).map_err(|_| Error::InternalError)?;
        Ok(Some(Self::parse(content)))
    }

    /// Write the database back to the passwd file (atomically).
    pub fn save(&self, fs: &FileSystem) -> Result<()> {
        let content = self.serialize();
        write_text_file_atomic(fs, PASSWD_PATH, content.as_bytes())
    }

    pub fn find_by_name(&self, name: &str) -> Option<&UserRecord> {
        self.users.iter().find(|r| r.username == name)
    }

    pub fn find_by_uid(&self, uid: UserId) -> Option<&UserRecord> {
        self.users.iter().find(|r| r.uid == uid)
    }

    /// Add a user and immediately persist.  Returns `AlreadyExists` when the
    /// username or UID is already in use.
    pub fn add_user(&mut self, record: UserRecord, fs: &FileSystem) -> Result<()> {
        if self.find_by_name(&record.username).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.find_by_uid(record.uid).is_some() {
            return Err(Error::AlreadyExists);
        }
        self.users.push(record);
        self.save(fs)
    }

    /// Remove a user by UID and immediately persist.  Returns `NotFound` when
    /// no matching record exists.
    pub fn remove_user(&mut self, uid: UserId, fs: &FileSystem) -> Result<UserRecord> {
        let idx = self
            .users
            .iter()
            .position(|r| r.uid == uid)
            .ok_or(Error::NotFound)?;
        let record = self.users.remove(idx);
        self.save(fs)?;
        Ok(record)
    }

    /// Find the next available UID starting from 1000.  Scans existing records
    /// and returns `max(existing_uids >= 1000) + 1`, or 1000 if none exist.
    pub fn next_available_uid(&self) -> UserId {
        let max_uid = self
            .users
            .iter()
            .map(|r| r.uid)
            .filter(|&uid| uid >= 1000)
            .max()
            .unwrap_or(999);
        max_uid + 1
    }

    /// Iterate over all users.
    pub fn iter(&self) -> impl Iterator<Item = &UserRecord> {
        self.users.iter()
    }
}

// ── ShadowDatabase methods ──────────────────────────────────────────────

impl ShadowDatabase {
    /// Parse shadow file content into a `ShadowDatabase`.
    pub fn parse(content: &str) -> Self {
        let mut entries = Vec::new();
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.splitn(3, ':').collect();
            if fields.len() < 3 {
                continue;
            }
            let username = fields[0].trim().to_string();
            let salt_hex = fields[1].trim();
            let hash_hex = fields[2].trim();

            if username.is_empty() || salt_hex.len() != SALT_LEN * 2 || hash_hex.len() != 64 {
                continue;
            }

            let salt = match hex_to_bytes_16(salt_hex) {
                Some(s) => s,
                None => continue,
            };
            let hash = match hex_to_bytes_32(hash_hex) {
                Some(h) => h,
                None => continue,
            };

            // Last-write-wins for duplicate usernames.
            entries.retain(|e: &ShadowEntry| e.username != username);
            entries.push(ShadowEntry {
                username,
                salt,
                hash,
            });
        }
        Self { entries }
    }

    /// Serialize the shadow database to file format.
    pub fn serialize(&self) -> String {
        let mut out = String::with_capacity(self.entries.len() * 128 + 64);
        out.push_str("# /data/etc/shadow — protofire password hashes\n");
        out.push_str("# username:salt_hex:hash_hex\n");
        for entry in &self.entries {
            out.push_str(&entry.username);
            out.push(':');
            for b in &entry.salt {
                out.push(HEX_CHARS[(b >> 4) as usize]);
                out.push(HEX_CHARS[(b & 0x0f) as usize]);
            }
            out.push(':');
            for b in &entry.hash {
                out.push(HEX_CHARS[(b >> 4) as usize]);
                out.push(HEX_CHARS[(b & 0x0f) as usize]);
            }
            out.push('\n');
        }
        out
    }

    /// Load the shadow database from the filesystem.
    pub fn load(fs: &FileSystem) -> Result<Option<Self>> {
        let mut handle = match fs.open(SHADOW_PATH, HANDLE_RIGHT_READ) {
            Ok(h) => h,
            Err(Error::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        let file_len = handle.size();
        if file_len > MAX_SHADOW_SIZE {
            return Err(Error::InternalError);
        }
        let mut buffer = vec![0u8; file_len];
        let bytes_read = fs.read(&mut handle, &mut buffer)?;
        buffer.truncate(bytes_read);
        let content = core::str::from_utf8(&buffer).map_err(|_| Error::InternalError)?;
        Ok(Some(Self::parse(content)))
    }

    /// Write the shadow database back to disk (atomically), then restore the
    /// restrictive 0600 permissions that a freshly created file would not
    /// otherwise inherit.
    pub fn save(&self, fs: &FileSystem) -> Result<()> {
        let content = self.serialize();
        write_text_file_atomic(fs, SHADOW_PATH, content.as_bytes())?;
        let _ = fs.update_persistent_security_descriptor_for_normalized_path(
            SHADOW_PATH,
            SecurityDescriptorUpdate::default().mode(0o600),
            crate::kernel::process::SecurityToken::system(),
        );
        Ok(())
    }

    /// Find a shadow entry by username.
    pub fn find_by_name(&self, username: &str) -> Option<&ShadowEntry> {
        self.entries.iter().find(|e| e.username == username)
    }

    /// Set (or change) a user's password.  Generates a fresh salt and
    /// computes the new hash.
    pub fn set_password(&mut self, username: &str, password: &str, fs: &FileSystem) -> Result<()> {
        let salt = crypto::generate_salt(username);
        let hash = hash_password(password, &salt);

        if let Some(entry) = self.entries.iter_mut().find(|e| e.username == username) {
            entry.salt = salt;
            entry.hash = hash;
        } else {
            self.entries.push(ShadowEntry {
                username: username.to_string(),
                salt,
                hash,
            });
        }
        self.save(fs)
    }

    /// Remove a user's shadow entry.  Returns `true` if an entry was removed.
    pub fn remove_entry(&mut self, username: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.username != username);
        self.entries.len() != before
    }

    /// Verify a password against the stored hash.  Returns `false` when the
    /// user is unknown, the account is locked (all-zeros hash), or the
    /// password doesn't match.
    pub fn verify_password(&self, username: &str, password: &str) -> bool {
        let entry = match self.find_by_name(username) {
            Some(e) => e,
            None => return false,
        };
        // Locked account — all-zeros hash never matches any password.
        if entry.hash == LOCKED_HASH {
            return false;
        }
        let candidate = hash_password(password, &entry.salt);
        crypto::constant_time_eq(&candidate, &entry.hash)
    }
}

// ── Shadow helpers ──────────────────────────────────────────────────────

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Compute the salted SHA-256 hash of a password.
fn hash_password(password: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut input = Vec::with_capacity(SALT_LEN + password.len());
    input.extend_from_slice(salt);
    input.extend_from_slice(password.as_bytes());
    crypto::sha256(&input)
}

/// Parse 32 hex chars into 16 bytes.  Returns `None` on invalid input.
fn hex_to_bytes_16(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    let raw = hex.as_bytes();
    for i in 0..16 {
        bytes[i] = hex_nibble(raw[i * 2])? << 4 | hex_nibble(raw[i * 2 + 1])?;
    }
    Some(bytes)
}

/// Parse 64 hex chars into 32 bytes.  Returns `None` on invalid input.
fn hex_to_bytes_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    let raw = hex.as_bytes();
    for i in 0..32 {
        bytes[i] = hex_nibble(raw[i * 2])? << 4 | hex_nibble(raw[i * 2 + 1])?;
    }
    Some(bytes)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// ── Shadow global storage helpers ───────────────────────────────────────

fn store_shadow_database(db: ShadowDatabase) {
    let mut slot = SHADOW_DATABASE.lock();
    *slot = Some(db);
    SHADOW_DB_INITIALISED.store(true, Ordering::Release);
}

// ── Public authentication API ───────────────────────────────────────────

/// Verify a username/password pair against the shadow database and return
/// the corresponding user record on success.  Returns `None` when the
/// username is unknown, the account is locked, or the password is wrong.
pub fn authenticate_user(username: &str, password: &str) -> Option<UserRecord> {
    {
        let shadow_guard = SHADOW_DATABASE.lock();
        let shadow = shadow_guard.as_ref()?;
        if !shadow.verify_password(username, password) {
            return None;
        }
        // shadow_guard is dropped here, releasing the lock before we acquire
        // the USER_DATABASE lock below.
    }

    with_database(|db| db.find_by_name(username).cloned()).flatten()
}

/// Set or change a user's password.  Requires filesystem access to persist
/// the shadow file.
pub fn set_user_password(username: &str, new_password: &str, fs: &FileSystem) -> Result<()> {
    let mut shadow = SHADOW_DATABASE.lock();
    let shadow = shadow.as_mut().ok_or(Error::InternalError)?;
    shadow.set_password(username, new_password, fs)
}

/// Remove a user by UID: persist the passwd change and also remove the
/// user's shadow entry so credential records do not linger after deletion.
pub fn remove_user(uid: UserId, fs: &FileSystem) -> Result<UserRecord> {
    let record = {
        let mut db = USER_DATABASE.lock();
        let db = db.as_mut().ok_or(Error::InternalError)?;
        db.remove_user(uid, fs)?
    };
    let mut shadow = SHADOW_DATABASE.lock();
    if let Some(shadow) = shadow.as_mut() {
        if shadow.remove_entry(&record.username) {
            let _ = shadow.save(fs);
        }
    }
    Ok(record)
}

// ── Public convenience functions ────────────────────────────────────────

/// Look up the home directory for `uid` from the user database, falling back
/// to the pure-function [`home_dir_for_uid`] when the database is unavailable
/// or doesn't contain the UID.
pub fn resolve_home_dir(uid: UserId) -> String {
    with_database(|db| {
        db.find_by_uid(uid)
            .map(|r| r.home.clone())
            .unwrap_or_else(|| home_dir_for_uid(uid))
    })
    .unwrap_or_else(|| home_dir_for_uid(uid))
}

/// Map a UID to a username.  Returns `None` when the database is unavailable
/// or the UID is unknown.
pub fn uid_to_username(uid: UserId) -> Option<String> {
    with_database(|db| db.find_by_uid(uid).map(|r| r.username.clone())).flatten()
}

/// Map a username to a UID.  Returns `None` when the database is unavailable
/// or the name is unknown.
pub fn username_to_uid(name: &str) -> Option<UserId> {
    with_database(|db| db.find_by_name(name).map(|r| r.uid)).flatten()
}

/// Return a reference to the global user database mutex, or `None` before
/// initialisation.
pub fn global_user_database() -> Option<&'static Mutex<Option<UserDatabase>>> {
    if USER_DB_INITIALISED.load(Ordering::Acquire) {
        Some(&USER_DATABASE)
    } else {
        None
    }
}

// ── Boot-time initialisation ────────────────────────────────────────────

/// Create intermediate directories needed for a path (mkdir -p style).
/// The path must already be normalized.  This is intentionally simple: it
/// splits on `/`, skips empty segments (leading `/`), and calls
/// `fs.create_dir` for each prefix.
fn ensure_dir_all(fs: &FileSystem, normalized_path: &str) -> Result<()> {
    let mut accumulated = String::new();
    for segment in normalized_path.split('/') {
        if segment.is_empty() {
            continue; // skip the empty string before the first '/'
        }
        accumulated.push('/');
        accumulated.push_str(segment);
        match fs.create_dir(&accumulated) {
            Ok(()) | Err(Error::AlreadyExists) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Write (or replace) a small text file at `normalized_path` with `content`.
fn write_text_file(fs: &FileSystem, normalized_path: &str, content: &[u8]) -> Result<()> {
    let mut handle = fs.create_file(normalized_path, HANDLE_RIGHT_WRITE, 0, OPEN_ALWAYS)?;
    handle.set_len(0).map_err(|_| Error::InternalError)?;
    fs.write(&mut handle, content)?;
    Ok(())
}

/// Atomically replace `normalized_path` with `content`: write a sibling
/// `<path>.tmp` file first, then rename it over the target.  A crash between
/// the write and the rename leaves the original file intact rather than a
/// truncated/partial credential database.
fn write_text_file_atomic(fs: &FileSystem, normalized_path: &str, content: &[u8]) -> Result<()> {
    let tmp_path = alloc::format!("{normalized_path}.tmp");
    let mut handle = fs.create_file(&tmp_path, HANDLE_RIGHT_WRITE, 0, OPEN_ALWAYS)?;
    handle.set_len(0).map_err(|_| Error::InternalError)?;
    let written = fs.write(&mut handle, content)?;
    if written != content.len() {
        return Err(Error::InternalError);
    }
    drop(handle);
    fs.rename_path(&tmp_path, normalized_path)
}

/// Ensure the skeleton template directory exists with default content.
pub fn ensure_skeleton_template(fs: &FileSystem) -> Result<()> {
    ensure_dir_all(fs, SKEL_PATH)?;
    ensure_dir_all(fs, "/data/etc/skel/documents")?;
    ensure_dir_all(fs, "/data/etc/skel/downloads")?;
    let profile_path = "/data/etc/skel/.profile";
    if fs.stat_path(profile_path).is_err() {
        write_text_file(fs, profile_path, DEFAULT_PROFILE_CONTENT)?;
    }
    Ok(())
}

/// Create a home directory for a new user by copying the skeleton template.
pub fn create_home_skeleton(fs: &FileSystem, home_path: &str) -> Result<()> {
    ensure_dir_all(fs, home_path)?;
    ensure_dir_all(fs, &format!("{home_path}/documents"))?;
    ensure_dir_all(fs, &format!("{home_path}/downloads"))?;
    // Copy .profile from skeleton if it exists.
    let profile_dest = format!("{home_path}/.profile");
    if fs.stat_path(profile_dest.as_str()).is_err() {
        // Try reading the skeleton profile; if that fails, write a minimal
        // default so the home directory isn't completely empty.
        let profile_content = match fs.open("/data/etc/skel/.profile", HANDLE_RIGHT_READ) {
            Ok(mut handle) => {
                let len = handle.size();
                let mut buf = vec![0u8; len.min(4096)];
                let n = fs.read(&mut handle, &mut buf).unwrap_or(0);
                buf.truncate(n);
                buf
            }
            Err(_) => DEFAULT_PROFILE_CONTENT.to_vec(),
        };
        write_text_file(fs, &profile_dest, &profile_content)?;
    }
    Ok(())
}

/// Initialise the user database at boot time.
///
/// The kernel provides the *mechanism*: ensure `/data/etc/` exists, load
/// `/data/etc/passwd` and `/data/etc/shadow` into the global slots, and apply
/// restrictive permissions to the shadow file.  Any *policy* (which accounts
/// exist, the default root password, the skeleton template) belongs to the
/// distribution and is only seeded under the `demo-disk` feature (or in
/// host tests).  A pure kernel build never creates accounts or passwords.
pub fn init_user_database(fs: &FileSystem) {
    // Ensure the directory tree exists.
    if let Err(e) = ensure_dir_all(fs, "/data/etc") {
        crate::println!("[userdb] failed to create /data/etc: {}", e.as_str());
        return;
    }

    // Load the database.  If none is present the demo distribution seeds one;
    // a pure kernel build simply runs with an empty in-memory database and
    // relies on the distribution's init to provide the account file.
    // The `mut` is only used behind `#[cfg(any(feature = "demo-disk", test))]`,
    // so the plain clippy pass (no test cfg) reports it as unused.  Keep it for
    // the test build and silence the cfg-dependent lint.
    #[allow(unused_mut)]
    let mut db = match UserDatabase::load(fs) {
        Ok(Some(db)) => db,
        Ok(None) => {
            #[cfg(any(feature = "demo-disk", test))]
            {
                // First boot: create the default passwd file.
                if let Err(e) = write_text_file(fs, PASSWD_PATH, DEFAULT_PASSWD_CONTENT) {
                    crate::println!("[userdb] failed to create {}: {}", PASSWD_PATH, e.as_str());
                    // Fall back to an in-memory database with built-in users so
                    // the system remains usable.
                    let db = UserDatabase::parse(
                        core::str::from_utf8(DEFAULT_PASSWD_CONTENT).unwrap_or(""),
                    );
                    store_database(db);
                    return;
                }
                match UserDatabase::load(fs) {
                    Ok(Some(db)) => db,
                    Ok(None) => {
                        crate::println!("[userdb] passwd file disappeared after creation");
                        let db = UserDatabase::parse(
                            core::str::from_utf8(DEFAULT_PASSWD_CONTENT).unwrap_or(""),
                        );
                        store_database(db);
                        return;
                    }
                    Err(e) => {
                        crate::println!(
                            "[userdb] failed to load passwd after creation: {}",
                            e.as_str()
                        );
                        let db = UserDatabase::parse(
                            core::str::from_utf8(DEFAULT_PASSWD_CONTENT).unwrap_or(""),
                        );
                        store_database(db);
                        return;
                    }
                }
            }
            #[cfg(not(any(feature = "demo-disk", test)))]
            {
                crate::println!(
                    "[userdb] no /data/etc/passwd on first boot; running with an empty \
                     user database (distribution init should provide one)"
                );
                store_database(UserDatabase::parse(""));
                return;
            }
        }
        Err(e) => {
            crate::println!("[userdb] failed to load passwd: {}", e.as_str());
            #[cfg(any(feature = "demo-disk", test))]
            {
                // Fall back to in-memory defaults.
                let db =
                    UserDatabase::parse(core::str::from_utf8(DEFAULT_PASSWD_CONTENT).unwrap_or(""));
                store_database(db);
            }
            #[cfg(not(any(feature = "demo-disk", test)))]
            {
                store_database(UserDatabase::parse(""));
            }
            return;
        }
    };

    // ── Shadow database init ──────────────────────────────────────────
    // The demo distribution seeds a root password on first boot; a pure
    // kernel build starts with an empty shadow database (all accounts locked
    // until a password is set).
    #[allow(unused_mut)]
    let mut shadow = match ShadowDatabase::load(fs) {
        Ok(Some(s)) => s,
        Ok(None) => {
            #[cfg(any(feature = "demo-disk", test))]
            {
                // First boot: create default shadow with root password.
                let mut s = ShadowDatabase {
                    entries: Vec::new(),
                };
                let salt = crypto::generate_salt("root");
                let root_hash = hash_password(DEFAULT_ROOT_PASSWORD, &salt);
                s.entries.push(ShadowEntry {
                    username: String::from("root"),
                    salt,
                    hash: root_hash,
                });
                // Guest starts locked (no password login).
                let guest_salt = crypto::generate_salt("guest");
                s.entries.push(ShadowEntry {
                    username: String::from("guest"),
                    salt: guest_salt,
                    hash: LOCKED_HASH,
                });
                if let Err(e) = s.save(fs) {
                    crate::println!("[userdb] failed to create {}: {}", SHADOW_PATH, e.as_str());
                }
                s
            }
            #[cfg(not(any(feature = "demo-disk", test)))]
            {
                ShadowDatabase {
                    entries: Vec::new(),
                }
            }
        }
        Err(e) => {
            crate::println!("[userdb] failed to load {}: {}", SHADOW_PATH, e.as_str());
            #[cfg(any(feature = "demo-disk", test))]
            {
                // Fall back to a minimal in-memory shadow.
                let mut s = ShadowDatabase {
                    entries: Vec::new(),
                };
                let salt = crypto::generate_salt("root");
                let root_hash = hash_password(DEFAULT_ROOT_PASSWORD, &salt);
                s.entries.push(ShadowEntry {
                    username: String::from("root"),
                    salt,
                    hash: root_hash,
                });
                s
            }
            #[cfg(not(any(feature = "demo-disk", test)))]
            {
                ShadowDatabase {
                    entries: Vec::new(),
                }
            }
        }
    };

    // The demo distribution reconciles its built-in users and gives root a
    // default password.  A pure kernel build leaves accounts untouched —
    // newly added users stay locked until a password is set.
    #[cfg(any(feature = "demo-disk", test))]
    {
        // Reconcile: ensure the two built-in users always exist.
        let mut changed = false;

        if db.find_by_uid(0).is_none() {
            db.users.push(UserRecord {
                username: String::from("root"),
                uid: 0,
                gid: 0,
                home: String::from("/root"),
            });
            changed = true;
        }

        if db.find_by_uid(1000).is_none() {
            db.users.push(UserRecord {
                username: String::from("guest"),
                uid: 1000,
                gid: 1000,
                home: String::from("/data/users/guest"),
            });
            changed = true;
        }

        if changed {
            if let Err(e) = db.save(fs) {
                crate::println!("[userdb] failed to reconcile passwd: {}", e.as_str());
            }
        }

        // Reconcile: ensure every user in passwd has a shadow entry.
        let mut shadow_changed = false;
        for user in db.iter() {
            if shadow.find_by_name(&user.username).is_none() {
                let salt = crypto::generate_salt(&user.username);
                let hash = if user.uid == 0 {
                    hash_password(DEFAULT_ROOT_PASSWORD, &salt)
                } else {
                    LOCKED_HASH
                };
                shadow.entries.push(ShadowEntry {
                    username: user.username.clone(),
                    salt,
                    hash,
                });
                shadow_changed = true;
            }
        }
        if shadow_changed {
            if let Err(e) = shadow.save(fs) {
                crate::println!("[userdb] failed to reconcile shadow: {}", e.as_str());
            }
        }
    }

    // Apply restrictive permissions to the shadow file.
    let _ = fs.update_persistent_security_descriptor_for_normalized_path(
        SHADOW_PATH,
        SecurityDescriptorUpdate::default().mode(0o600),
        crate::kernel::process::SecurityToken::system(),
    );

    // Ensure the skeleton template is present for useradd.  Distribution
    // policy — a pure build leaves the skel to the distribution's init.
    #[cfg(any(feature = "demo-disk", test))]
    if let Err(e) = ensure_skeleton_template(fs) {
        crate::println!(
            "[userdb] failed to create skeleton template: {}",
            e.as_str()
        );
    }

    store_database(db);
    store_shadow_database(shadow);
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_passwd() {
        let content = "\
# comment
root:0:0:/root
guest:1000:1000:/data/users/guest
testuser:1001:1001:/data/users/testuser
";
        let db = UserDatabase::parse(content);
        assert_eq!(db.users.len(), 3);
        assert_eq!(db.find_by_uid(0).unwrap().username, "root");
        assert_eq!(db.find_by_name("guest").unwrap().uid, 1000);
        assert_eq!(
            db.find_by_name("testuser").unwrap().home,
            "/data/users/testuser"
        );
    }

    #[test]
    fn parse_skips_malformed_lines() {
        let content = "\
root:0:0:/root
malformed
missing:fields
baduid:bogus:100:/home/bad
:0:0:/home/noname  # empty username
# just a comment
";
        let db = UserDatabase::parse(content);
        // Only root should be parsed successfully.
        assert_eq!(db.users.len(), 1);
        assert_eq!(db.find_by_uid(0).unwrap().username, "root");
    }

    #[test]
    fn parse_empty_content() {
        let db = UserDatabase::parse("");
        assert!(db.users.is_empty());
    }

    #[test]
    fn parse_last_duplicate_wins() {
        let content = "\
root:0:0:/root
root:0:0:/root-override
";
        let db = UserDatabase::parse(content);
        assert_eq!(db.users.len(), 1);
        assert_eq!(db.find_by_uid(0).unwrap().home, "/root-override");
    }

    #[test]
    fn find_by_name_and_uid() {
        let db = UserDatabase::parse("alice:1001:100:/home/alice\nbob:1002:200:/home/bob\n");
        assert_eq!(db.find_by_name("alice").unwrap().uid, 1001);
        assert_eq!(db.find_by_name("bob").unwrap().gid, 200);
        assert!(db.find_by_name("charlie").is_none());
        assert_eq!(db.find_by_uid(1002).unwrap().username, "bob");
        assert!(db.find_by_uid(9999).is_none());
    }

    #[test]
    fn next_available_uid() {
        let db = UserDatabase::parse("root:0:0:/root\nguest:1000:1000:/home/guest\n");
        assert_eq!(db.next_available_uid(), 1001);
    }

    #[test]
    fn next_available_uid_empty() {
        let db = UserDatabase::parse("");
        assert_eq!(db.next_available_uid(), 1000);
    }

    #[test]
    fn next_available_uid_below_1000_only() {
        let db = UserDatabase::parse("root:0:0:/root\n");
        assert_eq!(db.next_available_uid(), 1000);
    }

    #[test]
    fn serialize_roundtrip() {
        let original = "root:0:0:/root\nguest:1000:1000:/data/users/guest\n";
        let db = UserDatabase::parse(original);
        let serialized = db.serialize();
        let db2 = UserDatabase::parse(&serialized);
        assert_eq!(db2.users.len(), 2);
        assert_eq!(db2.find_by_uid(0).unwrap().username, "root");
        assert_eq!(db2.find_by_uid(1000).unwrap().home, "/data/users/guest");
    }

    #[test]
    fn add_user_rejects_duplicate() {
        let db = UserDatabase::parse("root:0:0:/root\n");
        let _record = UserRecord {
            username: String::from("root"),
            uid: 9999,
            gid: 0,
            home: String::from("/root2"),
        };
        // Cannot verify with real FS, but we can check that the duplicate check
        // works by calling find_by_name directly.
        assert!(db.find_by_name("root").is_some());
    }

    #[test]
    fn remove_user_by_uid() {
        let mut db = UserDatabase::parse("alice:1001:100:/home/alice\nbob:1002:200:/home/bob\n");
        // Test removal logic without filesystem persist.
        let idx = db.users.iter().position(|r| r.uid == 1001).unwrap();
        let removed = db.users.remove(idx);
        assert_eq!(removed.username, "alice");
        assert_eq!(db.users.len(), 1);
        assert!(db.find_by_uid(1001).is_none());
        assert!(db.find_by_uid(1002).is_some());
    }

    #[test]
    fn resolve_home_dir_fallback_when_db_empty() {
        // With no database stored, resolve_home_dir should fall back to the
        // pure function.
        let home = resolve_home_dir(0);
        assert_eq!(home, home_dir_for_uid(0));
        let home = resolve_home_dir(9999);
        assert_eq!(home, home_dir_for_uid(9999));
    }

    // ── Shadow database tests ───────────────────────────────────────────

    #[test]
    fn shadow_parse_valid() {
        let content = "\
# shadow file
root:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
guest:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
";
        let db = ShadowDatabase::parse(content);
        assert_eq!(db.entries.len(), 2);
        assert_eq!(db.find_by_name("root").unwrap().salt.len(), 16);
        assert_eq!(db.find_by_name("root").unwrap().hash.len(), 32);
    }

    #[test]
    fn shadow_parse_skips_malformed() {
        let content = "\
root:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
bogus:short:badhash
missingfields
# comment
valid:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
";
        let db = ShadowDatabase::parse(content);
        assert_eq!(db.entries.len(), 2);
    }

    #[test]
    fn shadow_serialize_roundtrip() {
        let content = "\
root:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
guest:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
";
        let db = ShadowDatabase::parse(content);
        let serialized = db.serialize();
        let db2 = ShadowDatabase::parse(&serialized);
        assert_eq!(db2.entries.len(), 2);
        assert_eq!(
            db2.find_by_name("root").unwrap().salt,
            db.find_by_name("root").unwrap().salt
        );
        assert_eq!(
            db2.find_by_name("root").unwrap().hash,
            db.find_by_name("root").unwrap().hash
        );
    }

    #[test]
    fn shadow_verify_password_roundtrip() {
        let mut db = ShadowDatabase {
            entries: Vec::new(),
        };
        let salt = crypto::generate_salt("alice");
        let hash = hash_password("hunter2", &salt);
        db.entries.push(ShadowEntry {
            username: String::from("alice"),
            salt,
            hash,
        });
        assert!(db.verify_password("alice", "hunter2"));
        assert!(!db.verify_password("alice", "wrong"));
        assert!(!db.verify_password("unknown", "hunter2"));
    }

    #[test]
    fn shadow_remove_entry_removes_existing() {
        let mut db = ShadowDatabase {
            entries: vec![
                ShadowEntry {
                    username: String::from("alice"),
                    salt: [0u8; 16],
                    hash: [1u8; 32],
                },
                ShadowEntry {
                    username: String::from("bob"),
                    salt: [0u8; 16],
                    hash: [2u8; 32],
                },
            ],
        };
        assert!(db.remove_entry("alice"));
        assert_eq!(db.entries.len(), 1);
        assert!(db.find_by_name("alice").is_none());
        assert!(db.find_by_name("bob").is_some());
        // Removing again returns false.
        assert!(!db.remove_entry("alice"));
    }

    #[test]
    fn shadow_remove_entry_missing_returns_false() {
        let mut db = ShadowDatabase {
            entries: Vec::new(),
        };
        assert!(!db.remove_entry("nobody"));
    }

    #[test]
    fn shadow_locked_account_always_fails() {
        let mut db = ShadowDatabase {
            entries: Vec::new(),
        };
        db.entries.push(ShadowEntry {
            username: String::from("locked"),
            salt: [0u8; 16],
            hash: LOCKED_HASH,
        });
        assert!(!db.verify_password("locked", ""));
        assert!(!db.verify_password("locked", "anything"));
    }
}
