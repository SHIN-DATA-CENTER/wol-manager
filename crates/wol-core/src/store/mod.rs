//! Reading and writing `config.toml` safely from several processes (GUI and CLI at once).
//!
//! [`Store::update`]:
//! 1. creates the folder, takes `config.lock` with `File::try_lock` (every 50 ms, up to 5 s);
//! 2. re-reads and parses `config.toml` (missing = defaults); a parse error aborts without
//!    writing anything; a newer `schema_version` aborts with [`Error::NewerSchema`];
//! 3. applies the closure, then validates (only problems *introduced* by the change abort);
//! 4. writes nothing when nothing changed, and nothing when the new text would not parse
//!    again ([`Config::to_toml_checked`]);
//! 5. copies the old file to `config.toml.bak`, writes `config.toml.tmp` + `sync_all`, and
//!    renames it over `config.toml`, retrying up to 6 times on errors 5 / 32 / 33
//!    (antivirus scanners, sync clients).
//!
//! [`Store::poll_changed`] compares a hash of the whole file (FAT32 has 2 s mtime granularity).
//!
//! Host ids that reading had to assign (a hand-edited file without `id`s) exist only in
//! memory until a write; [`Store::persist_assigned_ids`] writes them before anything lasting
//! (a stored password) is keyed by a host id.

pub mod location;
pub mod portable;

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

pub use location::{ConfigLocation, ConfigSource, ResolveInputs, resolve, resolve_with};

use crate::error::{Error, Result};
use crate::model::{Config, ConfigIssue, HostId, ParseNote, SCHEMA_VERSION, line_col};
use crate::sys;

/// How long [`Store::update`] waits for `config.lock`.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// Interval between lock attempts.
pub const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(50);
/// Back-off between rename retries (6 retries).
const RENAME_BACKOFF_MS: [u64; 6] = [25, 50, 100, 200, 400, 800];

/// Why a loaded config must not be written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReadOnlyReason {
    /// Written by a newer version.
    NewerSchema {
        /// Version in the file.
        found: u32,
        /// Supported version.
        supported: u32,
    },
    /// The folder is not writable (read-only media, ACLs).
    NotWritable {
        /// The folder.
        dir: PathBuf,
    },
}

/// Something worth telling the user after loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LoadWarning {
    /// Observation from parsing (ids assigned / replaced).
    Parse(ParseNote),
    /// A portable marker was ignored because this is an installed copy.
    MarkerIgnored {
        /// The marker file.
        marker: PathBuf,
    },
    /// A validation problem in the file (fix with the editor or `wolm edit`).
    Issue(ConfigIssue),
}

/// Result of [`Store::load`] / [`Store::poll_changed`].
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    /// The parsed settings (defaults when the file does not exist).
    pub config: Config,
    /// Writes will fail; see `read_only_reason`.
    pub read_only: bool,
    /// Why it is read-only.
    pub read_only_reason: Option<ReadOnlyReason>,
    /// Notes for the user.
    pub warnings: Vec<LoadWarning>,
    /// `config.toml` exists.
    pub exists: bool,
}

/// Result of [`Store::update`].
#[derive(Debug, Clone, PartialEq)]
pub struct Updated<R> {
    /// The closure's return value.
    pub value: R,
    /// The config after the update (what is on disk now, including other processes' changes
    /// since the last load / poll).
    pub config: Config,
    /// `false` when nothing changed and the file was not touched. External changes contained
    /// in `config` are then still reported by the next [`Store::poll_changed`].
    pub written: bool,
}

/// Value of [`Store::persist_assigned_ids`]: are the host ids in `config.toml`?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostIdsState {
    /// Every host's id is in the file: it already was, or it was written now
    /// ([`Updated::written`]). A missing file counts as saved (it has no hosts).
    Saved,
    /// Reading assigned `ids` (hosts without `id`, or repeating another host's id), but the
    /// file is not written by this build (`reason`: newer `schema_version`, or a folder that
    /// is not writable). Those ids are deterministic but change when the file changes (hosts
    /// reordered / renamed): do not key lasting data (passwords) by them. The other hosts'
    /// ids are in the file.
    Unsaved {
        /// Why the file is not written.
        reason: ReadOnlyReason,
        /// The ids that exist only in memory.
        ids: Vec<HostId>,
    },
}

impl HostIdsState {
    /// `true` when `id` is in the file, i.e. not one of the [`HostIdsState::Unsaved`] ids.
    pub fn is_saved(&self, id: HostId) -> bool {
        match self {
            HostIdsState::Saved => true,
            HostIdsState::Unsaved { ids, .. } => !ids.contains(&id),
        }
    }
}

/// Handle on one settings location. `Send + Sync`; cheap to create.
#[derive(Debug)]
pub struct Store {
    loc: ConfigLocation,
    last_hash: Mutex<Option<u64>>,
}

fn hash_content(bytes: Option<&[u8]>) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

fn is_not_writable(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied
        || e.kind() == io::ErrorKind::ReadOnlyFilesystem
        || matches!(e.raw_os_error(), Some(5 | 19))
}

fn is_transient(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

/// Holds `config.lock`; unlocked on drop (the OS also releases it when the process exits).
struct LockGuard(File);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn lock_dir(dir: &Path, lock_path: &Path) -> Result<LockGuard> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|e| write_error("open lock", dir, lock_path, e))?;
    let start = Instant::now();
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(LockGuard(f)),
            Err(TryLockError::WouldBlock) => {
                if start.elapsed() >= LOCK_TIMEOUT {
                    return Err(Error::LockTimeout {
                        path: lock_path.to_path_buf(),
                    });
                }
                std::thread::sleep(LOCK_RETRY_INTERVAL);
            }
            Err(TryLockError::Error(e)) => {
                return Err(Error::io("lock", lock_path.to_path_buf(), e));
            }
        }
    }
}

fn write_error(op: &'static str, dir: &Path, path: &Path, e: io::Error) -> Error {
    if is_not_writable(&e) {
        Error::PortableNotWritable {
            dir: dir.to_path_buf(),
        }
    } else {
        Error::io(op, path.to_path_buf(), e)
    }
}

/// Writes `bytes` to `path` atomically: `<path>.tmp` + `sync_all`, then rename over `path`
/// with up to 6 retries on errors 5 / 32 / 33. For the app's own files (`config.toml`,
/// `gui-state.toml`): a stale `<path>.tmp` is replaced. Files the user names (exports) go
/// through [`write_output_file`]. Does not lock and does not create folders.
///
/// Errors: [`Error::PortableNotWritable`] when the folder is read-only, [`Error::Io`]
/// (`op = "replace"`, with a hint) when the rename keeps failing.
pub fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    let _ = fs::remove_file(&tmp);
    let write = || -> io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(write_error("write", dir, &tmp, e));
    }
    rename_into_place(&tmp, path)
}

/// Writes a file the user chose (an export) atomically. Unlike [`write_file_atomic`], the
/// temporary file gets a new, unique name next to `path` (an existing `<name>.tmp` is left
/// alone), and errors name `path` itself ([`Error::Io`], also for access denied: the folder
/// is the user's choice, not the settings folder).
pub fn write_output_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new(""));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let fail = |e: io::Error| Error::io("write", path.to_path_buf(), e);
    let mut n = 0u32;
    let (tmp, mut file) = loop {
        let tmp = dir.join(format!(".{name}.{}-{n}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < 100 => n += 1,
            Err(e) => return Err(fail(e)),
        }
    };
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(fail(e));
    }
    drop(file);
    rename_into_place(&tmp, path)
}

/// Renames `tmp` over `path`, retrying on errors 5 / 32 / 33; removes `tmp` on failure.
fn rename_into_place(tmp: &Path, path: &Path) -> Result<()> {
    let mut attempt = 0;
    loop {
        match fs::rename(tmp, path) {
            Ok(()) => return Ok(()),
            Err(e) if is_transient(&e) && attempt < RENAME_BACKOFF_MS.len() => {
                std::thread::sleep(Duration::from_millis(RENAME_BACKOFF_MS[attempt]));
                attempt += 1;
            }
            Err(e) => {
                let _ = fs::remove_file(tmp);
                return Err(Error::Io {
                    op: "replace",
                    path: Some(path.to_path_buf()),
                    source: e,
                    hint: Some(
                        "the file may be locked by antivirus, a sync client or Controlled Folder Access",
                    ),
                });
            }
        }
    }
}

/// Reads a text file: `Ok(None)` when missing; strips a UTF-8 BOM.
/// Errors: [`Error::ConfigParse`] for invalid UTF-8, [`Error::Io`] otherwise.
fn read_text(path: &Path) -> Result<Option<String>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io("read", path.to_path_buf(), e)),
    };
    decode_text(path, bytes).map(Some)
}

fn decode_text(path: &Path, bytes: Vec<u8>) -> Result<String> {
    match String::from_utf8(bytes) {
        Ok(s) => Ok(match s.strip_prefix('\u{FEFF}') {
            Some(rest) => rest.to_owned(),
            None => s,
        }),
        Err(e) => {
            let valid = e.utf8_error().valid_up_to();
            let prefix = String::from_utf8_lossy(&e.as_bytes()[..valid]).into_owned();
            let (line, column) = line_col(&prefix, prefix.len());
            Err(Error::ConfigParse {
                path: Some(path.to_path_buf()),
                line: Some(line),
                column: Some(column),
                message: "the file is not valid UTF-8".to_owned(),
            })
        }
    }
}

fn with_path<T>(path: &Path, r: Result<T>) -> Result<T> {
    r.map_err(|e| match e {
        Error::ConfigParse {
            line,
            column,
            message,
            ..
        } => Error::ConfigParse {
            path: Some(path.to_path_buf()),
            line,
            column,
            message,
        },
        other => other,
    })
}

fn parse_at(path: &Path, text: &str) -> Result<(Config, Vec<ParseNote>)> {
    with_path(path, Config::from_toml(text))
}

/// [`parse_at`] (the same config) plus the ids [`Config::assign_missing_ids`] gave hosts
/// that have none, or a repeated one, in the file: they exist only in memory.
fn parse_assigned_ids(path: &Path, text: &str) -> Result<(Config, Vec<HostId>)> {
    let (mut cfg, _) = with_path(path, Config::from_toml_keeping_ids(text))?;
    let in_file: Vec<HostId> = cfg.hosts.iter().map(|h| h.id).collect();
    cfg.assign_missing_ids();
    let assigned = cfg
        .hosts
        .iter()
        .zip(in_file)
        .filter(|(h, id)| h.id != *id)
        .map(|(h, _)| h.id)
        .collect();
    Ok((cfg, assigned))
}

/// Identity of an issue for "did the update introduce it?" (ignores names / values).
fn issue_key(i: &ConfigIssue) -> (Option<HostId>, String) {
    match i {
        ConfigIssue::Host {
            id, field, issue, ..
        } => (Some(*id), format!("{field:?}/{issue:?}")),
        ConfigIssue::Setting { key, .. } => (None, (*key).to_owned()),
    }
}

impl Store {
    /// Store for a resolved location. Touches nothing.
    pub fn new(location: ConfigLocation) -> Store {
        Store {
            loc: location,
            last_hash: Mutex::new(None),
        }
    }

    /// Resolves the location ([`location::resolve`]) and creates a store.
    pub fn open(flag: Option<&Path>) -> Result<Store> {
        Ok(Store::new(location::resolve(flag)?))
    }

    /// The location.
    pub fn location(&self) -> &ConfigLocation {
        &self.loc
    }

    /// Path of `config.toml`.
    pub fn config_path(&self) -> PathBuf {
        self.loc.config_file()
    }

    /// `config.toml` exists.
    pub fn exists(&self) -> bool {
        self.config_path().is_file()
    }

    /// Raw file text (BOM stripped) for `wolm config show`; `None` when missing.
    pub fn read_raw(&self) -> Result<Option<String>> {
        read_text(&self.config_path())
    }

    fn set_hash(&self, h: u64) {
        *self.last_hash.lock().unwrap_or_else(|p| p.into_inner()) = Some(h);
    }

    fn writable(&self) -> bool {
        let dir = &self.loc.dir;
        if dir.is_dir() {
            return sys::dir_is_writable(dir);
        }
        // Not created yet: AppData is assumed writable; for portable / custom folders test
        // the nearest existing parent.
        if self.loc.source == ConfigSource::AppData {
            return true;
        }
        match dir.ancestors().skip(1).find(|p| p.is_dir()) {
            Some(parent) => sys::dir_is_writable(parent),
            None => false,
        }
    }

    /// Why `config` (as read from this location) must not be written, if it must not.
    fn read_only_reason(&self, config: &Config) -> Option<ReadOnlyReason> {
        if config.is_newer_schema() {
            Some(ReadOnlyReason::NewerSchema {
                found: config.schema_version,
                supported: SCHEMA_VERSION,
            })
        } else if !self.writable() {
            Some(ReadOnlyReason::NotWritable {
                dir: self.loc.dir.clone(),
            })
        } else {
            None
        }
    }

    fn build_loaded(&self, text: Option<&str>) -> Result<Loaded> {
        let path = self.config_path();
        let (config, notes) = match text {
            Some(t) => parse_at(&path, t)?,
            None => (Config::default(), Vec::new()),
        };
        let mut warnings: Vec<LoadWarning> = notes.into_iter().map(LoadWarning::Parse).collect();
        if self.loc.marker_ignored
            && let Some(m) = &self.loc.marker_path
        {
            warnings.push(LoadWarning::MarkerIgnored { marker: m.clone() });
        }
        warnings.extend(config.validate().into_iter().map(LoadWarning::Issue));
        let read_only_reason = self.read_only_reason(&config);
        Ok(Loaded {
            config,
            read_only: read_only_reason.is_some(),
            read_only_reason,
            warnings,
            exists: text.is_some(),
        })
    }

    /// Reads and parses `config.toml` without locking. A missing file gives defaults; the
    /// folder is never created. **Blocking** (small file I/O; a write test in the folder).
    ///
    /// Errors: [`Error::ConfigParse`] (with path and line), [`Error::Io`].
    pub fn load(&self) -> Result<Loaded> {
        let path = self.config_path();
        let bytes = match fs::read(&path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::io("read", path, e)),
        };
        self.set_hash(hash_content(bytes.as_deref()));
        let text = bytes.map(|b| decode_text(&path, b)).transpose()?;
        self.build_loaded(text.as_deref())
    }

    /// Returns `Some(Loaded)` when the file content differs from what this store last loaded,
    /// wrote or polled (the first call always returns `Some`). An [`Store::update`] that wrote
    /// nothing does not count. A parse error is returned once
    /// per distinct content; the next polls return `Ok(None)` until the file changes again.
    /// The GUI calls this every 2 s on its store thread. **Blocking** (reads the file).
    pub fn poll_changed(&self) -> Result<Option<Loaded>> {
        let path = self.config_path();
        let bytes = match fs::read(&path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::io("read", path, e)),
        };
        let h = hash_content(bytes.as_deref());
        {
            let mut last = self.last_hash.lock().unwrap_or_else(|p| p.into_inner());
            if *last == Some(h) {
                return Ok(None);
            }
            *last = Some(h);
        }
        let text = bytes.map(|b| decode_text(&path, b)).transpose()?;
        self.build_loaded(text.as_deref()).map(Some)
    }

    /// Locked read-modify-write (see the module docs).
    ///
    /// The closure may fail (e.g. [`Error::HostIdNotFound`], [`Error::InvalidFields`]); then
    /// nothing is written. **Blocking**: up to 5 s for the lock plus file I/O (and up to
    /// ~1.6 s of rename retries). Never call it on the GUI thread.
    ///
    /// [`Updated::config`] is always the file's current content, including changes other
    /// processes made since this store last loaded or polled. After a write, those changes
    /// count as seen by [`Store::poll_changed`] (reconcile with `Updated::config`). When
    /// nothing was written the poll baseline is left alone, so the next `poll_changed` still
    /// reports such external changes.
    ///
    /// Errors: [`Error::LockTimeout`], [`Error::ConfigParse`], [`Error::NewerSchema`],
    /// [`Error::Validation`], [`Error::PortableNotWritable`], [`Error::Io`], or the closure's.
    pub fn update<R>(&self, f: impl FnOnce(&mut Config) -> Result<R>) -> Result<Updated<R>> {
        self.update_inner(false, f)
    }

    /// Writes `config.toml` when reading it had to assign host ids, and only then: hosts
    /// without `id` in a hand-edited file, or repeating another host's id
    /// ([`ParseNote::AssignedIds`] / [`ParseNote::DuplicateIdReplaced`]). Those ids are
    /// deterministic, but they live only in memory until a write, and [`Store::update`] writes
    /// nothing when nothing else changed. Call this before keying lasting data by a host id
    /// (storing a password, [`crate::secret`]); afterwards the ids in [`Updated::config`] are
    /// the ones in the file.
    ///
    /// * Nothing to write (every host has its own id, or no file): `value` =
    ///   [`HostIdsState::Saved`], `written == false`; the file is only read (no lock).
    /// * Otherwise the write follows the [`Store::update`] rules: lock, re-read and parse,
    ///   `config.toml.bak`, atomic replace, never an unreadable result, poll baseline moved.
    ///   `value` = `Saved`, `written == true` (`false` if another process wrote the ids
    ///   meanwhile).
    /// * A file this build does not write (newer `schema_version`, folder not writable) is left
    ///   alone: `value` = [`HostIdsState::Unsaved`] with the in-memory ids, `written == false`.
    ///
    /// [`Updated::config`] is the file's current content (with the ids). **Blocking** (like
    /// `update`; never on the GUI thread).
    ///
    /// Errors: [`Error::ConfigParse`], [`Error::LockTimeout`], [`Error::PortableNotWritable`]
    /// / [`Error::NewerSchema`] (only when the folder or file changed between the check and
    /// the write), [`Error::Io`].
    pub fn persist_assigned_ids(&self) -> Result<Updated<HostIdsState>> {
        let path = self.config_path();
        let Some(text) = read_text(&path)? else {
            return Ok(Updated {
                value: HostIdsState::Saved,
                config: Config::default(),
                written: false,
            });
        };
        let (config, assigned) = parse_assigned_ids(&path, &text)?;
        if assigned.is_empty() {
            return Ok(Updated {
                value: HostIdsState::Saved,
                config,
                written: false,
            });
        }
        if let Some(reason) = self.read_only_reason(&config) {
            return Ok(Updated {
                value: HostIdsState::Unsaved {
                    reason,
                    ids: assigned,
                },
                config,
                written: false,
            });
        }
        let up = self.update_inner(true, |_| Ok(()))?;
        Ok(Updated {
            value: HostIdsState::Saved,
            config: up.config,
            written: up.written,
        })
    }

    /// [`Store::update`]; with `save_ids` it also writes when the only change is the ids that
    /// reading assigned ([`Store::persist_assigned_ids`]).
    fn update_inner<R>(
        &self,
        save_ids: bool,
        f: impl FnOnce(&mut Config) -> Result<R>,
    ) -> Result<Updated<R>> {
        let dir = self.loc.dir.clone();
        fs::create_dir_all(&dir).map_err(|e| write_error("create folder", &dir, &dir, e))?;
        let _lock = lock_dir(&dir, &self.loc.lock_file())?;

        let path = self.config_path();
        let old_bytes = match fs::read(&path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::io("read", path, e)),
        };
        let old_text = old_bytes.map(|b| decode_text(&path, b)).transpose()?;
        let (mut cfg, assigned) = match &old_text {
            Some(t) => parse_assigned_ids(&path, t)?,
            None => (Config::default(), Vec::new()),
        };
        let force = save_ids && !assigned.is_empty();
        if cfg.is_newer_schema() {
            return Err(Error::NewerSchema {
                found: cfg.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        let before = cfg.clone();
        let issues_before: HashSet<(Option<HostId>, String)> =
            before.validate().iter().map(issue_key).collect();

        let value = f(&mut cfg)?;

        // No-op updates leave the poll baseline alone: if another process changed the file
        // since the last load / poll, `poll_changed` must still report it.
        if cfg == before && !force {
            return Ok(Updated {
                value,
                config: cfg,
                written: false,
            });
        }
        let new_issues: Vec<ConfigIssue> = cfg
            .validate()
            .into_iter()
            .filter(|i| !issues_before.contains(&issue_key(i)))
            .collect();
        if !new_issues.is_empty() {
            return Err(Error::Validation(new_issues));
        }
        // Never write a file that the next load could not parse: every later command (and
        // every later update, which re-reads it first) would fail until it is fixed by hand.
        let new_text = cfg.to_toml_checked()?;
        if old_text.as_deref() == Some(new_text.as_str()) {
            return Ok(Updated {
                value,
                config: cfg,
                written: false,
            });
        }
        if old_text.is_some()
            && let Err(e) = fs::copy(&path, self.loc.backup_file())
        {
            log::warn!("cannot write {}: {e}", self.loc.backup_file().display());
        }
        write_file_atomic(&path, new_text.as_bytes())?;
        self.set_hash(hash_content(Some(new_text.as_bytes())));
        Ok(Updated {
            value,
            config: cfg,
            written: true,
        })
    }
}

#[cfg(test)]
mod tests;
