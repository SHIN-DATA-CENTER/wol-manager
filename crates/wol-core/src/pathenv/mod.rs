//! Adding / removing a folder (normally `<install>\bin`) to / from the user or machine PATH.
//!
//! Used by `wolm path add|remove|status` (which the installer calls) and by the GUI's
//! "add wolm to my PATH" switch. The registry is edited directly (never via NSIS, whose
//! 1024-character strings corrupt long PATHs):
//!
//! * the value type is preserved (`REG_EXPAND_SZ` stays `REG_EXPAND_SZ`); a missing value is
//!   created as `REG_EXPAND_SZ`;
//! * entries are compared whole, after normalization ([`normalize_entry`]: trim, strip
//!   quotes, expand `%VAR%`, `/` → `\`, strip trailing `\`, case-insensitive);
//! * adding only appends and is idempotent; other entries (order, empty entries) are kept;
//! * directories containing `;` and results longer than 32767 UTF-16 units are refused;
//! * after a change `WM_SETTINGCHANGE("Environment")` is broadcast (1 s per window, abort if
//!   hung). Already-open terminals do not see the change.
//!
//! Tests use [`MemBackend`], never the real registry. Debug builds also honour
//! `WOL_MANAGER_PATH_BACKEND_FILE` (a JSON file, see [`FileBackend`]) for CLI tests.

mod registry;

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

pub use registry::{RegistryBackend, broadcast_environment_change};

use crate::error::{Error, Result};
use crate::sys;

/// Maximum length of an environment variable value (UTF-16 units).
pub const MAX_VALUE_LEN: usize = 32767;

/// Which PATH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// `HKCU\Environment\Path` (no elevation needed).
    User,
    /// `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path` (writing
    /// needs elevation; reading does not).
    Machine,
}

impl Scope {
    /// `"user"` / `"machine"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Machine => "machine",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scope {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "user" | "currentuser" | "current-user" => Ok(Scope::User),
            "machine" | "system" | "allusers" | "all-users" => Ok(Scope::Machine),
            _ => Err("expected user | machine".to_owned()),
        }
    }
}

/// Registry type of the PATH value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    /// `REG_EXPAND_SZ` (normal, and used when creating the value).
    ExpandString,
    /// `REG_SZ`.
    String,
}

/// Raw PATH value of one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathValue {
    /// Unexpanded value.
    pub value: String,
    /// Registry type.
    pub kind: ValueKind,
}

/// Storage of the PATH values (registry, memory, or a JSON file in debug builds).
pub trait EnvBackend: Send + Sync {
    /// Reads the raw value; `Ok(None)` when it does not exist.
    fn read(&self, scope: Scope) -> Result<Option<PathValue>>;
    /// Writes the raw value. Errors: [`Error::ElevationRequired`] on access denied.
    fn write(&self, scope: Scope, value: &PathValue) -> Result<()>;
    /// Tells running programs that the environment changed. Returns `false` on failure
    /// (callers only log it).
    fn broadcast(&self) -> bool;
    /// Environment variable lookup used to expand `%VAR%` for comparisons.
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Result of [`add`] / [`remove`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathChange {
    /// The folder was appended.
    Added,
    /// It was already there (nothing written).
    AlreadyPresent,
    /// Matching entries were removed.
    Removed,
    /// It was not there (nothing written).
    NotPresent,
}

impl PathChange {
    /// `true` when the registry was written.
    pub fn changed(self) -> bool {
        matches!(self, PathChange::Added | PathChange::Removed)
    }
}

/// Result of [`status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathStatus {
    /// Scope.
    pub scope: Scope,
    /// The folder as it would be written.
    pub dir: String,
    /// At least one entry matches.
    pub present: bool,
    /// Matching entries as written in PATH.
    pub matching_entries: Vec<String>,
    /// Registry type (`None` when the value does not exist).
    pub value_kind: Option<ValueKind>,
    /// Current length in UTF-16 units.
    pub length: usize,
}

/// Length in UTF-16 code units.
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Expands `%NAME%` references with `lookup`; unknown names and lone `%` stay as they are.
pub fn expand_vars(s: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => {
                let name = &after[..end];
                match lookup(name) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Comparison form of a PATH entry: trimmed, quotes removed, `%VAR%` expanded, `\\?\`
/// removed, `/` → `\`, trailing `\` removed, lower case. Used for comparison only; entries
/// are never rewritten.
pub fn normalize_entry(entry: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let t = entry.trim().replace('"', "");
    let t = expand_vars(t.trim(), lookup).replace('/', "\\");
    let t = t.strip_prefix(r"\\?\").unwrap_or(&t);
    t.trim_end_matches('\\').to_lowercase()
}

/// Splits a PATH value on `;` (empty entries included, as they are).
pub fn split_entries(value: &str) -> Vec<&str> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split(';').collect()
    }
}

/// Entries of `value` equal to `dir` after normalization.
pub fn find_entries(
    value: &str,
    dir: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Vec<String> {
    let want = normalize_entry(dir, lookup);
    if want.is_empty() {
        return Vec::new();
    }
    split_entries(value)
        .into_iter()
        .filter(|e| !e.trim().is_empty() && normalize_entry(e, lookup) == want)
        .map(str::to_owned)
        .collect()
}

/// Appends `dir` unless an equal entry exists (`Ok(None)`). Pure.
/// Errors: [`Error::PathTooLong`].
pub fn append_entry(
    value: &str,
    dir: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<String>> {
    if !find_entries(value, dir, lookup).is_empty() {
        return Ok(None);
    }
    // A trailing `;` is kept after the new entry, so that `remove_entries` restores the
    // original value byte for byte ("a;b;" -> "a;b;dir;" -> "a;b;").
    let new = if value.is_empty() {
        dir.to_owned()
    } else if value.ends_with(';') {
        format!("{value}{dir};")
    } else {
        format!("{value};{dir}")
    };
    let len = utf16_len(&new);
    if len > MAX_VALUE_LEN {
        return Err(Error::PathTooLong {
            len,
            max: MAX_VALUE_LEN,
        });
    }
    Ok(Some(new))
}

/// Removes every entry equal to `dir`; `None` when there is none. Pure.
pub fn remove_entries(
    value: &str,
    dir: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let want = normalize_entry(dir, lookup);
    let entries = split_entries(value);
    let kept: Vec<&str> = entries
        .iter()
        .copied()
        .filter(|e| e.trim().is_empty() || normalize_entry(e, lookup) != want)
        .collect();
    (kept.len() != entries.len()).then(|| kept.join(";"))
}

/// Turns a directory into the PATH entry to write: absolute, no `\\?\` prefix, no trailing
/// `\` (except for a drive root). Errors: [`Error::InvalidPathEntry`] for empty input or a
/// `;` / `"` in the path.
pub fn prepare_dir(dir: &Path) -> Result<String> {
    let raw = dir.to_string_lossy();
    if raw.trim().is_empty() {
        return Err(Error::InvalidPathEntry {
            dir: raw.into_owned(),
            reason: "empty",
        });
    }
    if raw.contains(';') {
        return Err(Error::InvalidPathEntry {
            dir: raw.into_owned(),
            reason: "contains ';'",
        });
    }
    if raw.contains('"') {
        return Err(Error::InvalidPathEntry {
            dir: raw.into_owned(),
            reason: "contains '\"'",
        });
    }
    let abs = std::path::absolute(dir).map_err(|e| Error::io("absolute", dir.to_path_buf(), e))?;
    let s = sys::strip_verbatim(&abs).to_string_lossy().into_owned();
    let trimmed = s.trim_end_matches('\\');
    Ok(if trimmed.len() == 2 && trimmed.ends_with(':') {
        format!("{trimmed}\\")
    } else {
        trimmed.to_owned()
    })
}

/// Folder of the running exe: the default for `wolm path add` (`<install>\bin`).
pub fn default_dir() -> Result<PathBuf> {
    sys::exe_dir().map_err(|e| Error::io("current_exe", None, e))
}

/// The folder that holds `wolm.exe` for a given exe: its own folder for `wolm.exe`, otherwise
/// `<exe folder>\bin` (what the GUI's "add wolm to my PATH" switch registers).
pub fn cli_dir_for(exe_path: &Path) -> PathBuf {
    let dir = exe_path.parent().unwrap_or(Path::new("")).to_path_buf();
    let is_cli = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case(crate::consts::CLI_EXE));
    if is_cli {
        dir
    } else {
        dir.join(crate::consts::CLI_SUBDIR)
    }
}

/// Adds `dir` to the PATH of `scope`. **Blocking** (registry, and the broadcast can take
/// about 1 s per hung window).
///
/// Errors: [`Error::InvalidPathEntry`], [`Error::PathTooLong`], [`Error::ElevationRequired`],
/// [`Error::Registry`].
pub fn add(backend: &dyn EnvBackend, scope: Scope, dir: &Path) -> Result<PathChange> {
    let dir = prepare_dir(dir)?;
    let lookup = |n: &str| backend.var(n);
    let cur = backend.read(scope)?;
    let (value, kind) = match cur {
        Some(v) => (v.value, v.kind),
        None => (String::new(), ValueKind::ExpandString),
    };
    match append_entry(&value, &dir, &lookup)? {
        None => Ok(PathChange::AlreadyPresent),
        Some(new) => {
            backend.write(scope, &PathValue { value: new, kind })?;
            if !backend.broadcast() {
                log::warn!("WM_SETTINGCHANGE broadcast failed");
            }
            Ok(PathChange::Added)
        }
    }
}

/// Removes every entry equal to `dir` from the PATH of `scope`. **Blocking** like [`add`].
///
/// Errors: [`Error::InvalidPathEntry`], [`Error::ElevationRequired`], [`Error::Registry`].
pub fn remove(backend: &dyn EnvBackend, scope: Scope, dir: &Path) -> Result<PathChange> {
    let dir = prepare_dir(dir)?;
    let lookup = |n: &str| backend.var(n);
    let Some(cur) = backend.read(scope)? else {
        return Ok(PathChange::NotPresent);
    };
    match remove_entries(&cur.value, &dir, &lookup) {
        None => Ok(PathChange::NotPresent),
        Some(new) => {
            backend.write(
                scope,
                &PathValue {
                    value: new,
                    kind: cur.kind,
                },
            )?;
            if !backend.broadcast() {
                log::warn!("WM_SETTINGCHANGE broadcast failed");
            }
            Ok(PathChange::Removed)
        }
    }
}

/// Whether `dir` is on the PATH of `scope`. Reading needs no elevation.
pub fn status(backend: &dyn EnvBackend, scope: Scope, dir: &Path) -> Result<PathStatus> {
    let dir = prepare_dir(dir)?;
    let lookup = |n: &str| backend.var(n);
    let cur = backend.read(scope)?;
    let (value, kind) = match &cur {
        Some(v) => (v.value.as_str(), Some(v.kind)),
        None => ("", None),
    };
    let matching_entries = find_entries(value, &dir, &lookup);
    Ok(PathStatus {
        scope,
        present: !matching_entries.is_empty(),
        matching_entries,
        value_kind: kind,
        length: utf16_len(value),
        dir,
    })
}

/// In-memory backend for tests. Variables for `%VAR%` expansion are explicit.
#[derive(Debug, Default)]
pub struct MemBackend {
    user: Mutex<Option<PathValue>>,
    machine: Mutex<Option<PathValue>>,
    vars: Mutex<Vec<(String, String)>>,
    deny_machine_write: bool,
    broadcasts: AtomicUsize,
}

impl MemBackend {
    /// Both values missing.
    pub fn new() -> MemBackend {
        MemBackend::default()
    }

    /// Starts with the given values.
    pub fn with(user: Option<PathValue>, machine: Option<PathValue>) -> MemBackend {
        MemBackend {
            user: Mutex::new(user),
            machine: Mutex::new(machine),
            ..MemBackend::default()
        }
    }

    /// Makes machine writes fail with [`Error::ElevationRequired`].
    pub fn deny_machine_writes(mut self) -> MemBackend {
        self.deny_machine_write = true;
        self
    }

    /// Defines a variable for `%VAR%` expansion (case-insensitive).
    pub fn set_var(&self, name: &str, value: &str) {
        self.vars
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((name.to_owned(), value.to_owned()));
    }

    /// Current value of a scope.
    pub fn get(&self, scope: Scope) -> Option<PathValue> {
        self.slot(scope)
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Number of broadcasts so far.
    pub fn broadcast_count(&self) -> usize {
        self.broadcasts.load(Ordering::Relaxed)
    }

    fn slot(&self, scope: Scope) -> &Mutex<Option<PathValue>> {
        match scope {
            Scope::User => &self.user,
            Scope::Machine => &self.machine,
        }
    }
}

impl EnvBackend for MemBackend {
    fn read(&self, scope: Scope) -> Result<Option<PathValue>> {
        Ok(self.get(scope))
    }

    fn write(&self, scope: Scope, value: &PathValue) -> Result<()> {
        if scope == Scope::Machine && self.deny_machine_write {
            return Err(Error::ElevationRequired);
        }
        *self.slot(scope).lock().unwrap_or_else(|p| p.into_inner()) = Some(value.clone());
        Ok(())
    }

    fn broadcast(&self) -> bool {
        self.broadcasts.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn var(&self, name: &str) -> Option<String> {
        self.vars
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .rev()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}

/// Debug-only JSON file backend, selected by `WOL_MANAGER_PATH_BACKEND_FILE` so CLI tests
/// never touch the registry. File format (missing file = both values missing):
///
/// ```json
/// {"user": {"value": "C:\\a;C:\\b", "kind": "expand_string"},
///  "machine": null,
///  "machine_requires_elevation": true,
///  "broadcasts": 0}
/// ```
#[cfg(debug_assertions)]
#[derive(Debug, Clone)]
pub struct FileBackend {
    path: PathBuf,
}

#[cfg(debug_assertions)]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct FileDoc {
    user: Option<PathValue>,
    machine: Option<PathValue>,
    machine_requires_elevation: bool,
    broadcasts: u64,
}

#[cfg(debug_assertions)]
impl FileBackend {
    /// Backend on a JSON file.
    pub fn new(path: impl Into<PathBuf>) -> FileBackend {
        FileBackend { path: path.into() }
    }

    fn load(&self) -> Result<FileDoc> {
        match std::fs::read(&self.path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| Error::ConfigParse {
                path: Some(self.path.clone()),
                line: Some(e.line()),
                column: Some(e.column()),
                message: e.to_string(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileDoc::default()),
            Err(e) => Err(Error::io("read", self.path.clone(), e)),
        }
    }

    fn save(&self, doc: &FileDoc) -> Result<()> {
        let text =
            serde_json::to_string_pretty(doc).map_err(|e| Error::Serialize(e.to_string()))?;
        std::fs::write(&self.path, text).map_err(|e| Error::io("write", self.path.clone(), e))
    }
}

#[cfg(debug_assertions)]
impl EnvBackend for FileBackend {
    fn read(&self, scope: Scope) -> Result<Option<PathValue>> {
        let d = self.load()?;
        Ok(match scope {
            Scope::User => d.user,
            Scope::Machine => d.machine,
        })
    }

    fn write(&self, scope: Scope, value: &PathValue) -> Result<()> {
        let mut d = self.load()?;
        match scope {
            Scope::User => d.user = Some(value.clone()),
            Scope::Machine => {
                if d.machine_requires_elevation {
                    return Err(Error::ElevationRequired);
                }
                d.machine = Some(value.clone());
            }
        }
        self.save(&d)
    }

    fn broadcast(&self) -> bool {
        match self.load() {
            Ok(mut d) => {
                d.broadcasts += 1;
                self.save(&d).is_ok()
            }
            Err(_) => false,
        }
    }
}

/// The backend the CLI and GUI should use: [`RegistryBackend`], or in debug builds a
/// [`FileBackend`] when `WOL_MANAGER_PATH_BACKEND_FILE` is set (non-empty).
pub fn backend_from_env() -> Box<dyn EnvBackend> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os(crate::consts::ENV_PATH_BACKEND_FILE)
        && !p.is_empty()
    {
        return Box::new(FileBackend::new(PathBuf::from(p)));
    }
    Box::new(RegistryBackend)
}

#[cfg(test)]
mod tests;
