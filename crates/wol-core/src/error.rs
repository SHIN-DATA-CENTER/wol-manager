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

use crate::model::{ConfigIssue, HostId, RemoteKind};
use crate::remote::{PowerAction, RemoteError, RemoteOp};

/// Result alias using [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Coarse classification of an [`Error`].
///
/// Suggested `wolm` exit codes: `InvalidInput`/`Ambiguous` → 2, `NotFound` → 3, `Timeout` → 4,
/// `Network` → 5, `Config`/`Io` → 6, `Permission`/`Unsupported` → 7 (not permitted here),
/// `Remote` → 1 (the remote host reported a failure).
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
    /// The remote host reported a failure (a command failed, a shutdown is already in
    /// progress, unexpected output...). Suggested `wolm` exit code 1.
    Remote,
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
    /// Remote management kind (`[hosts.remote]` present or not).
    RemoteKind,
    /// Remote management user (Windows account / SSH login).
    RemoteUser,
    /// Management address (when different from the address).
    RemoteAddress,
    /// SSH port.
    SshPort,
    /// SSH private key file.
    SshKeyFile,
    /// Pinned SSH host key.
    SshHostKey,
    /// How an SSH host gets root rights (sudo mode).
    SshSudo,
    /// SSH reboot command override.
    RebootCommand,
    /// SSH power-off command override.
    ShutdownCommand,
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
    /// A remote user name contains characters the account system does not allow.
    InvalidUser,
    /// A power command override contains a disallowed character or is too long.
    InvalidCommand,
    /// Not an OpenSSH public-key line (`ssh-ed25519 AAAA...`).
    InvalidHostKey,
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

fn fmt_mismatch(p: &HostKeyProblem) -> String {
    let pinned = p.expected_fingerprint.as_deref().unwrap_or("?");
    if p.fingerprint.is_empty() {
        format!(
            "SSH host {} no longer offers a {} host key (pinned {pinned})",
            p.host,
            if p.algorithm.is_empty() {
                "pinned-type"
            } else {
                &p.algorithm
            }
        )
    } else {
        format!(
            "SSH host key of {} changed: pinned {pinned}, presented {}",
            p.host, p.fingerprint
        )
    }
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

    /// Remote management is not set up for the host (no `[hosts.remote]` table).
    #[error("remote management is not set up for {host}")]
    RemoteNotConfigured {
        /// Host name.
        host: String,
    },

    /// The host has remote management but neither a management address nor an address.
    #[error("{host} has no address for remote management")]
    RemoteNoAddress {
        /// Host name.
        host: String,
    },

    /// The operation is not available for this kind of remote management (cancelling a
    /// shutdown over SSH).
    #[error("{op:?} is not supported for {kind} hosts ({host})")]
    RemoteUnsupported {
        /// Host name.
        host: String,
        /// Remote management kind of the host.
        kind: RemoteKind,
        /// The operation.
        op: RemoteOp,
    },

    /// First contact with an SSH host: its host key is not pinned yet. Show
    /// [`HostKeyProblem::fingerprint`]; when the user trusts it, pin
    /// [`HostKeyProblem::openssh_line`] (`remote::trust_host_key`) and retry.
    #[error("the SSH host key of {} is not trusted yet ({})", .0.host, .0.fingerprint)]
    UnknownHostKey(Box<HostKeyProblem>),

    /// The SSH host presented a different key than the pinned one (or no longer offers the
    /// pinned key type). Never replaced automatically; offer "forget host key".
    #[error("{}", fmt_mismatch(.0))]
    HostKeyMismatch(Box<HostKeyProblem>),

    /// A host key was not pinned because the host's remote management changed after the key
    /// was read and shown (another management address / SSH port, or another key pinned
    /// meanwhile). Connect again and check the key (`remote::trust_host_key`).
    #[error(
        "the remote management of {host} changed while its SSH host key was being checked; nothing was pinned"
    )]
    RemoteChanged {
        /// Host name.
        host: String,
    },

    /// A remote management operation failed.
    #[error("{0}")]
    Remote(Box<RemoteError>),

    /// "MAC from IP" for an address ARP cannot reach (off-link, VPN) and no remote management
    /// is set up for the host.
    #[error("the MAC address of {ip} cannot be read by ARP{}; set up remote management for the host", if *.via_vpn { " (VPN)" } else { "" })]
    MacNeedsRemote {
        /// The address.
        ip: Ipv4Addr,
        /// The address is routed through a VPN / tunnel adapter or lies in 100.64.0.0/10.
        via_vpn: bool,
    },

    /// A restart / shutdown was accepted but not confirmed before the deadline (`--wait`).
    #[error("{label}: {action:?} not confirmed within {secs} s")]
    VerifyTimeout {
        /// Host label.
        label: String,
        /// The requested action.
        action: PowerAction,
        /// Timeout in seconds.
        secs: u64,
    },

    /// Windows Credential Manager could not be used.
    #[error("Credential Manager: {detail}")]
    SecretStore {
        /// Classification.
        failure: SecretStoreFailure,
        /// English detail for logs (never contains a secret).
        detail: String,
    },
}

/// Details of [`Error::UnknownHostKey`] / [`Error::HostKeyMismatch`] (boxed to keep [`Error`]
/// small). Everything here is public data, never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostKeyProblem {
    /// Host name (label).
    pub host: String,
    /// Management address that was contacted.
    pub address: String,
    /// SSH port.
    pub port: u16,
    /// Key algorithm, e.g. `ssh-ed25519`: unknown key → the received key's; mismatch → the
    /// pinned key's type (the server presented a different key of that type, or no longer
    /// offers that type). `""` only when the pinned key could not be read.
    pub algorithm: String,
    /// `SHA256:...` fingerprint of the received key (`""` when the server no longer offers
    /// the pinned key type).
    pub fingerprint: String,
    /// The received key as an OpenSSH line without comment: pin this on "trust". `""` for a
    /// mismatch (a changed key can never be trusted directly).
    pub openssh_line: String,
    /// Mismatch: fingerprint of the pinned key.
    pub expected_fingerprint: Option<String>,
    /// Unknown key: the same key is already in the user's `~/.ssh/known_hosts` (OpenSSH
    /// trusts it), so pinning it silently (with a notice) is reasonable.
    pub in_known_hosts: bool,
}

/// Why Windows Credential Manager failed ([`Error::SecretStore`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStoreFailure {
    /// Not available in this logon session (e.g. a network / SSH logon on this PC, error 1312).
    Unavailable,
    /// The secret (or user name) is longer than Credential Manager allows.
    TooLong,
    /// Any other failure (see the detail).
    Other,
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
            // "Not set up" and "not available for this kind" are usage problems (exit 2).
            RemoteNotConfigured { .. } | RemoteNoAddress { .. } | RemoteUnsupported { .. } => {
                ErrorKind::InvalidInput
            }
            UnknownHostKey(_) | HostKeyMismatch(_) | RemoteChanged { .. } => ErrorKind::Permission,
            Remote(e) => e.kind(),
            MacNeedsRemote { .. } => ErrorKind::NotFound,
            VerifyTimeout { .. } => ErrorKind::Timeout,
            SecretStore { failure, .. } => match failure {
                SecretStoreFailure::Unavailable => ErrorKind::Permission,
                SecretStoreFailure::TooLong => ErrorKind::InvalidInput,
                SecretStoreFailure::Other => ErrorKind::Io,
            },
        }
    }

    /// The remote failure, for [`Error::Remote`].
    pub fn remote(&self) -> Option<&RemoteError> {
        match self {
            Error::Remote(e) => Some(e),
            _ => None,
        }
    }

    /// Host key details of [`Error::UnknownHostKey`] (offer "trust") or
    /// [`Error::HostKeyMismatch`] (offer "forget").
    pub fn host_key_problem(&self) -> Option<&HostKeyProblem> {
        match self {
            Error::UnknownHostKey(p) | Error::HostKeyMismatch(p) => Some(p),
            _ => None,
        }
    }

    /// `true` for network-class failures of remote operations (unreachable, timeout,
    /// connection lost): the host may just be down or booting. Verification loops keep
    /// polling on these.
    pub fn is_remote_transient(&self) -> bool {
        match self {
            Error::Remote(e) => e.kind() == ErrorKind::Network,
            Error::Resolve { .. } | Error::Network { .. } => true,
            _ => false,
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
