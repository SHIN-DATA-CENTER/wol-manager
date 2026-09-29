//! Error type shared by the whole crate, plus the per-field validation results used by the
//! host editor (GUI) and by `wolm add/edit` (CLI).
//!
//! [`Error`]'s `Display` is English and meant for logs. User-facing text comes from
//! [`crate::i18n::describe_error`]. Consumers branch on [`Error::kind`] (for exit codes) or
//! match the dedicated variants they need to handle specially.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::Serialize;

use crate::model::{ConfigIssue, HostId};

/// Result alias using [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Coarse classification of an [`Error`].
///
/// Suggested `wolm` exit codes: `InvalidInput`/`Ambiguous` → 2, `NotFound` → 3, `Timeout` → 4,
/// `Network` → 5, `Config`/`Io` → 6, `Permission`/`Unsupported` → 7 (not permitted here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Bad user input (field validation, unknown setting key, bad import row...).
    InvalidInput,
    /// A host, interface or ARP entry does not exist.
    NotFound,
    /// A query matched more than one host.
    Ambiguous,
    /// Name resolution or sending failed, or there was nothing to send to.
    Network,
    /// Waiting for something timed out.
    Timeout,
    /// The settings file is broken or cannot be used (parse error, newer schema).
    Config,
    /// File system or registry failure.
    Io,
    /// Access denied, elevation required, or the settings folder is not writable.
    Permission,
    /// The operation is not available in this situation (e.g. portable mode on an installed copy).
    Unsupported,
}

/// Which input field a [`FieldError`] refers to.
///
/// Mirrors the fields of [`crate::model::HostDraft`]. The GUI maps it 1:1 to a Slint enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// Host name.
    Name,
    /// MAC address.
    Mac,
    /// IPv4 address or host name used for status checks and unicast.
    Address,
    /// Group name.
    Group,
    /// Free-form notes.
    Notes,
    /// UDP port.
    Port,
    /// SecureOn password.
    SecureOn,
    /// Extra send targets (`host[:port]` list).
    Targets,
    /// Pinned network interfaces.
    Interfaces,
    /// Probe method.
    Probe,
    /// TCP ports used by the TCP probe.
    TcpPorts,
}

/// What is wrong with a field. The GUI maps it 1:1 to a Slint enum and translates it with
/// `@tr`; the CLI uses [`crate::i18n::Msg::FieldIssue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldIssue {
    /// The field is required but empty.
    Required,
    /// Not a MAC address.
    InvalidMac,
    /// A well-formed MAC address that no network adapter has (all-zero, broadcast or
    /// multicast: the group bit of the first byte is set), so it can never be woken.
    MacNotUnicast,
    /// Not an IPv4 address or a valid host name.
    InvalidAddress,
    /// Not a port number in 1..=65535.
    InvalidPort,
    /// A comma separated port list contains an invalid entry.
    InvalidPortList,
    /// A port list has more than [`crate::model::limits::TCP_PORTS_MAX`] entries.
    TooManyPorts,
    /// Not a 6-byte SecureOn password (`AA:BB:CC:DD:EE:FF` form).
    InvalidSecureOn,
    /// A `host[:port]` target is malformed.
    InvalidTarget,
    /// Another host already uses this name (compared width-folded and case-insensitively).
    DuplicateName,
    /// The name parses as a MAC address, which would make `wolm wake <MAC>` ambiguous.
    NameLooksLikeMac,
    /// The name is longer than [`crate::model::NAME_MAX_CHARS`] characters.
    NameTooLong,
    /// Kana / CJK characters in a technical field: the IME is probably on.
    ImeKana,
}

/// A validation failure for one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct FieldError {
    /// The field.
    pub field: Field,
    /// What is wrong with it.
    pub issue: FieldIssue,
}

impl FieldError {
    /// Creates a field error.
    pub const fn new(field: Field, issue: FieldIssue) -> Self {
        Self { field, issue }
    }
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {:?}", self.field, self.issue)
    }
}

fn join_fields(errors: &[FieldError]) -> String {
    errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_issues(issues: &[ConfigIssue]) -> String {
    issues
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

fn fmt_parse(
    path: &Option<PathBuf>,
    line: &Option<usize>,
    column: &Option<usize>,
    message: &str,
) -> String {
    let mut s = String::from("cannot parse ");
    match path {
        Some(p) => s.push_str(&p.display().to_string()),
        None => s.push_str("settings"),
    }
    if let Some(l) = line {
        s.push_str(&format!(" at line {l}"));
        if let Some(c) = column {
            s.push_str(&format!(", column {c}"));
        }
    }
    s.push_str(": ");
    s.push_str(message.trim());
    s
}

/// The crate-wide error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// One or more fields of a host failed validation.
    #[error("invalid input: {}", join_fields(.0))]
    InvalidFields(Vec<FieldError>),

    /// A single value (typically a CLI flag such as `--mac`) failed to parse.
    #[error("invalid {field:?} value {input:?}: {issue:?}")]
    InvalidValue {
        /// Which kind of value.
        field: Field,
        /// Why it was rejected.
        issue: FieldIssue,
        /// The rejected input, as typed.
        input: String,
    },

    /// `Settings::set_key` / `get_key` was given a key that does not exist.
    #[error("unknown setting key {0:?}")]
    UnknownSettingKey(String),

    /// `Settings::set_key` was given a value of the wrong type or out of range.
    #[error("invalid value {value:?} for {key}: expected {expected}")]
    InvalidSetting {
        /// Dotted key, e.g. `wake.repeat`.
        key: String,
        /// The rejected value.
        value: String,
        /// Human readable description of the accepted values (English, e.g. `1..=10`).
        expected: String,
    },

    /// A change made in `Store::update` introduced new validation problems.
    #[error("the change would make the settings invalid: {}", join_issues(.0))]
    Validation(Vec<ConfigIssue>),

    /// No host matches the query (name, id, id prefix or MAC).
    #[error("host not found: {0}")]
    HostNotFound(String),

    /// The host being edited no longer exists (deleted by another process).
    #[error("host {0} no longer exists")]
    HostIdNotFound(HostId),

    /// No host belongs to the group.
    #[error("group not found or empty: {0}")]
    GroupNotFound(String),

    /// The query matched several hosts.
    #[error("{query:?} matches several hosts: {}", .candidates.join(", "))]
    AmbiguousHost {
        /// The query.
        query: String,
        /// Names of the matching hosts.
        candidates: Vec<String>,
    },

    /// `config.lock` could not be acquired within 5 seconds.
    #[error("timed out waiting for the settings lock {}", .path.display())]
    LockTimeout {
        /// The lock file.
        path: PathBuf,
    },

    /// `--wait` style timeout, for consumers that want to return it as an error.
    #[error("{label} did not respond within {secs} s")]
    WaitTimeout {
        /// Host label.
        label: String,
        /// Timeout in seconds.
        secs: u64,
    },

    /// `config.toml` (or an imported TOML/JSON file) could not be parsed.
    #[error("{}", fmt_parse(.path, .line, .column, .message))]
    ConfigParse {
        /// File that failed, when known.
        path: Option<PathBuf>,
        /// 1-based line, when known.
        line: Option<usize>,
        /// 1-based column, when known.
        column: Option<usize>,
        /// Parser message (English).
        message: String,
    },

    /// The file was written by a newer version; it is opened read-only.
    #[error(
        "settings schema version {found} is newer than the supported version {supported}; opened read-only"
    )]
    NewerSchema {
        /// `schema_version` in the file.
        found: u32,
        /// Highest version this build understands.
        supported: u32,
    },

    /// The settings folder cannot be written (read-only media, ACLs). Raised on the first
    /// write; loading still works. Named after the typical portable case but used for every
    /// location. The app never falls back to AppData silently.
    #[error("the settings folder {} is not writable", .dir.display())]
    PortableNotWritable {
        /// The folder.
        dir: PathBuf,
    },

    /// Writing the machine PATH (HKLM) requires an elevated process.
    #[error("administrator rights are required")]
    ElevationRequired,

    /// Adding the entry would make PATH longer than Windows allows.
    #[error("PATH would be {len} characters long (maximum {max})")]
    PathTooLong {
        /// Resulting length in UTF-16 units.
        len: usize,
        /// Maximum length.
        max: usize,
    },

    /// A directory cannot be put on PATH (contains `;`, is empty or not absolute).
    #[error("cannot put {dir:?} on PATH: {reason}")]
    InvalidPathEntry {
        /// The rejected directory.
        dir: String,
        /// English reason.
        reason: &'static str,
    },

    /// Nothing to send to: no usable interface, no target.
    #[error("no usable network interface or target to send to")]
    NoDestinations,

    /// Portable mode was requested for an installed copy (`uninstall.exe` next to the exe).
    #[error("{} is an installed copy; portable mode is not available", .root.display())]
    InstalledCopyRefusesPortable {
        /// Install folder.
        root: PathBuf,
    },

    /// ARP lookup refused: the IP is not inside a subnet of a selected non-virtual interface.
    #[error("{ip} is not on a local subnet")]
    NotOnLocalSubnet {
        /// The address.
        ip: Ipv4Addr,
    },

    /// ARP got no answer.
    #[error("no ARP reply from {ip}")]
    ArpNoReply {
        /// The address.
        ip: Ipv4Addr,
    },

    /// A host name could not be resolved to an IPv4 address.
    #[error("cannot resolve {name}: {message}")]
    Resolve {
        /// The name.
        name: String,
        /// OS message.
        message: String,
    },

    /// A network operation failed.
    #[error("network error during {op}: {source}")]
    Network {
        /// Operation, e.g. `"send"`, `"arp"`.
        op: &'static str,
        /// Underlying error.
        #[source]
        source: io::Error,
    },

    /// A file operation failed.
    #[error("{op} failed{}: {source}{}", .path.as_ref().map(|p| format!(" for {}", p.display())).unwrap_or_default(), .hint.map(|h| format!(" ({h})")).unwrap_or_default())]
    Io {
        /// Operation, e.g. `"read"`, `"replace"`.
        op: &'static str,
        /// File involved, when known.
        path: Option<PathBuf>,
        /// Underlying error.
        #[source]
        source: io::Error,
        /// Optional English hint (e.g. antivirus / Controlled Folder Access for `replace`).
        hint: Option<&'static str>,
    },

    /// A registry operation failed.
    #[error("registry {op} failed: {source}")]
    Registry {
        /// Operation.
        op: &'static str,
        /// Underlying error.
        #[source]
        source: io::Error,
    },

    /// An import file is malformed (row / record level).
    #[error("import error{}: {message}", .location.as_ref().map(|l| format!(" at {l}")).unwrap_or_default())]
    Import {
        /// Where, e.g. `"row 3"` or `"hosts[2]"`.
        location: Option<String>,
        /// English message.
        message: String,
    },

    /// Serialization failed (internal).
    #[error("serialization failed: {0}")]
    Serialize(String),

    /// No per-user settings folder could be determined.
    #[error("cannot determine the AppData folder")]
    NoConfigDir,

    /// Operation not supported here.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The GUI already runs (single instance) with another settings folder: starting it for
    /// `requested` would only bring up the window that uses `running`.
    #[error("WoL Manager is already running with the settings in {}", .running.display())]
    AppRunningWithOtherSettings {
        /// Settings folder of the running app.
        running: PathBuf,
        /// Settings folder this start asked for.
        requested: PathBuf,
    },
}

impl Error {
    /// Coarse classification, used for exit codes and generic UI handling.
    pub fn kind(&self) -> ErrorKind {
        use Error::*;
        match self {
            InvalidFields(_)
            | InvalidValue { .. }
            | UnknownSettingKey(_)
            | InvalidSetting { .. }
            | Validation(_)
            | InvalidPathEntry { .. }
            | Import { .. } => ErrorKind::InvalidInput,
            HostNotFound(_)
            | HostIdNotFound(_)
            | GroupNotFound(_)
            | NotOnLocalSubnet { .. }
            | ArpNoReply { .. } => ErrorKind::NotFound,
            AmbiguousHost { .. } => ErrorKind::Ambiguous,
            NoDestinations | Resolve { .. } | Network { .. } => ErrorKind::Network,
            WaitTimeout { .. } => ErrorKind::Timeout,
            ConfigParse { .. } | NewerSchema { .. } | NoConfigDir | Serialize(_) => {
                ErrorKind::Config
            }
            LockTimeout { .. } | PathTooLong { .. } => ErrorKind::Io,
            PortableNotWritable { .. } | ElevationRequired => ErrorKind::Permission,
            Io { source, .. } | Registry { source, .. } => {
                if source.kind() == io::ErrorKind::PermissionDenied {
                    ErrorKind::Permission
                } else {
                    ErrorKind::Io
                }
            }
            InstalledCopyRefusesPortable { .. }
            | Unsupported(_)
            | AppRunningWithOtherSettings { .. } => ErrorKind::Unsupported,
        }
    }

    /// Field errors carried by [`Error::InvalidFields`] / [`Error::InvalidValue`], if any.
    pub fn field_errors(&self) -> Vec<FieldError> {
        match self {
            Error::InvalidFields(v) => v.clone(),
            Error::InvalidValue { field, issue, .. } => vec![FieldError::new(*field, *issue)],
            _ => Vec::new(),
        }
    }

    /// Shorthand for [`Error::InvalidValue`].
    pub fn invalid(field: Field, issue: FieldIssue, input: impl Into<String>) -> Self {
        Error::InvalidValue {
            field,
            issue,
            input: input.into(),
        }
    }

    /// Shorthand for [`Error::Io`] without hint.
    pub fn io(op: &'static str, path: impl Into<Option<PathBuf>>, source: io::Error) -> Self {
        Error::Io {
            op,
            path: path.into(),
            source,
            hint: None,
        }
    }
}

impl From<Vec<FieldError>> for Error {
    fn from(v: Vec<FieldError>) -> Self {
        Error::InvalidFields(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(Error::NoDestinations.kind(), ErrorKind::Network);
        assert_eq!(Error::ElevationRequired.kind(), ErrorKind::Permission);
        assert_eq!(
            Error::io(
                "read",
                None,
                io::Error::from(io::ErrorKind::PermissionDenied)
            )
            .kind(),
            ErrorKind::Permission
        );
        assert_eq!(
            Error::io("read", None, io::Error::from(io::ErrorKind::NotFound)).kind(),
            ErrorKind::Io
        );
        assert_eq!(
            Error::AmbiguousHost {
                query: "a".into(),
                candidates: vec![]
            }
            .kind(),
            ErrorKind::Ambiguous
        );
    }

    #[test]
    fn parse_error_display_has_line() {
        let e = Error::ConfigParse {
            path: Some(PathBuf::from(r"C:\x\config.toml")),
            line: Some(3),
            column: Some(5),
            message: "expected `=`".into(),
        };
        let s = e.to_string();
        assert!(s.contains("line 3"), "{s}");
        assert!(s.contains("config.toml"), "{s}");
    }
}
