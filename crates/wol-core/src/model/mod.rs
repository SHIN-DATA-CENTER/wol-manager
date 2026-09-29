//! The `config.toml` schema (version 1) and operations on it.
//!
//! ```toml
//! schema_version = 1
//! [settings]
//! language = "auto"
//! [settings.wake]
//! port = 9
//! # ...
//! [[hosts]]
//! id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
//! name = "NAS"
//! mac = "00:11:22:33:44:55"
//! address = "192.168.1.10"
//! ```
//!
//! Every struct keeps unknown keys in a flattened `extra` table so files written by newer
//! versions survive a round trip. Hosts without `id` get a deterministic UUIDv5 at parse
//! time (same id on every load), which is written on the next save.

/// Declares a lower-case string enum (config spelling) with `ALL`, `as_str`, `Display`,
/// `FromStr` (full-width input accepted) and serde support. Used by `settings` and `remote`.
macro_rules! str_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $text:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// All values, in display order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The lower-case name used in `config.toml` and on the command line.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $name::$variant => $text, )+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = String;
            fn from_str(s: &str) -> std::result::Result<Self, String> {
                let t = normalize::normalize_input(s).trim().to_ascii_lowercase();
                match t.as_str() {
                    $( $text => Ok($name::$variant), )+
                    _ => Err(format!(
                        "expected one of: {}",
                        [$($text),+].join(" | ")
                    )),
                }
            }
        }
    };
}

mod draft;
mod remote;
mod settings;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::error::{Field, FieldError, FieldIssue};
pub use draft::{EditBase, HostDraft, RemoteDraft, check_field, check_remote_field};
pub use remote::{
    COMMAND_MAX_BYTES, DEFAULT_SSH_PORT, DEFAULT_SSH_USER, RemoteConfig, RemoteKind, SudoMode,
    check_host_key, check_management_address, check_power_command, check_remote_user,
    check_ssh_port, clean_key_file,
};
pub use settings::{
    GuiSettings, KEY_INFO, KeyInfo, ProbeMethod, ProbeSettings, RemoteSettings, Renderer, Settings,
    Theme, ValueType, WakeSettings, limits,
};

use crate::addr::{HostAddr, Target};
use crate::error::{Error, Result};
use crate::mac::{self, MacAddr, SecureOn};
use crate::normalize;

/// Host identifier (UUID; v4 for new hosts, v5 for hosts that had no id in the file).
pub type HostId = Uuid;

/// Schema version written by this build. Files with a higher version open read-only (and
/// are parsed leniently, see [`Config::from_toml`]). Files of this version are parsed
/// strictly, so a future build that adds an enum value (probe method, theme, renderer,
/// language) or a new address form must raise the version.
pub const SCHEMA_VERSION: u32 = 1;

/// Maximum host name length in characters.
pub const NAME_MAX_CHARS: usize = 64;

/// Minimum length of an id prefix accepted by [`Config::find`].
pub const ID_PREFIX_MIN: usize = 8;

/// Namespace for deterministic host ids (`Uuid::new_v5(HOST_ID_NAMESPACE, "<index>:<name>:<mac>")`).
pub const HOST_ID_NAMESPACE: Uuid = Uuid::from_u128(0x6f1d_3a52_9c0e_4b7a_8e21_5d4c_9b0a_7e13);

/// Header comment written at the top of `config.toml`.
pub const FILE_HEADER: &str =
    "# WoL Manager settings (managed by WoL Manager / wolm; comments are not preserved)\n";

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

/// One `[[hosts]]` entry.
///
/// Serialization goes through a private mirror with the same layout, which drops a
/// preserved unsupported `remote` table from `extra` once `remote` is set (see
/// [`Host::unsupported_remote`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, into = "HostOut")]
pub struct Host {
    /// Stable id. `nil` right after deserialization means "missing"; [`Config::from_toml`]
    /// replaces it with a deterministic v5 id.
    pub id: HostId,
    /// Display name, unique (width-folded, case-insensitive), 1..=64 characters.
    pub name: String,
    /// Target MAC.
    pub mac: MacAddr,
    /// IPv4 address or host name, used for status checks and on-link unicast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<HostAddr>,
    /// Group (one per host).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Free text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// UDP port override (default: `settings.wake.port`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SecureOn password (plain text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secureon: Option<SecureOn>,
    /// Extra explicit targets (`host[:port]`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<Target>,
    /// Send the directed broadcast of every selected subnet (default `true`).
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub broadcast: bool,
    /// Pinned adapters for this host (GUIDs preferred). Empty = use the settings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// Probe method override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeMethod>,
    /// TCP ports override for the TCP probe. Empty = use the settings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tcp_ports: Vec<u16>,
    /// Remote management (v0.2.0): restart, shutdown, boot time, MAC via the host. `None` =
    /// not managed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteConfig>,
    /// Unknown keys, preserved.
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// What a [`Host`] serializes to: the same fields in the same order. A `remote` table kept in
/// `extra` (written by a newer version, see [`Host::unsupported_remote`]) is only written
/// while this build has no `remote` of its own for the host.
#[derive(Serialize)]
struct HostOut {
    id: HostId,
    name: String,
    mac: MacAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<HostAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secureon: Option<SecureOn>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    targets: Vec<Target>,
    #[serde(skip_serializing_if = "is_true")]
    broadcast: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe: Option<ProbeMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tcp_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<RemoteConfig>,
    #[serde(flatten)]
    extra: toml::Table,
}

impl From<Host> for HostOut {
    fn from(h: Host) -> HostOut {
        let Host {
            id,
            name,
            mac,
            address,
            group,
            notes,
            port,
            secureon,
            targets,
            broadcast,
            interfaces,
            probe,
            tcp_ports,
            remote,
            mut extra,
        } = h;
        if remote.is_some() {
            extra.remove("remote");
        }
        HostOut {
            id,
            name,
            mac,
            address,
            group,
            notes,
            port,
            secureon,
            targets,
            broadcast,
            interfaces,
            probe,
            tcp_ports,
            remote,
            extra,
        }
    }
}

impl Default for Host {
    fn default() -> Self {
        Host {
            id: Uuid::nil(),
            name: String::new(),
            mac: MacAddr::default(),
            address: None,
            group: None,
            notes: None,
            port: None,
            secureon: None,
            targets: Vec::new(),
            broadcast: true,
            interfaces: Vec::new(),
            probe: None,
            tcp_ports: Vec::new(),
            remote: None,
            extra: toml::Table::new(),
        }
    }
}

impl Host {
    /// A new host with a fresh v4 id and default options.
    pub fn new(name: impl Into<String>, mac: MacAddr) -> Host {
        Host {
            id: Uuid::new_v4(),
            name: name.into(),
            mac,
            ..Host::default()
        }
    }

    /// Effective UDP port: the host's override, else `settings.wake`'s port. A hand-edited
    /// `port = 0` (reported by [`Config::validate`]) counts as "no override".
    pub fn effective_port(&self, settings: &Settings) -> u16 {
        match self.port {
            Some(p) if p != 0 => p,
            _ => settings.wake.effective_port(),
        }
    }

    /// Effective probe method.
    pub fn effective_probe(&self, settings: &Settings) -> ProbeMethod {
        self.probe.unwrap_or(settings.probe.method)
    }

    /// Effective TCP probe ports.
    pub fn effective_tcp_ports<'a>(&'a self, settings: &'a Settings) -> &'a [u16] {
        if self.tcp_ports.is_empty() {
            &settings.probe.tcp_ports
        } else {
            &self.tcp_ports
        }
    }

    /// Remote management kind, `None` when the host is not managed.
    pub fn remote_kind(&self) -> Option<RemoteKind> {
        self.remote.as_ref().map(|r| r.kind)
    }

    /// Address used for remote management: `remote.address`, else `address`. `None` when
    /// neither is set (or the host is not managed).
    pub fn management_address(&self) -> Option<&HostAddr> {
        let r = self.remote.as_ref()?;
        r.address.as_ref().or(self.address.as_ref())
    }

    /// A `[hosts.remote]` table this build cannot use (a newer version's `kind` or `sudo`
    /// value, or, in a newer-schema file, a key it cannot read). It is kept as it is (in
    /// `extra`, written back on save) and the host counts as **not managed** here
    /// (`remote` is `None`; `ParseNote::UnsupportedRemote` was reported). Setting up remote
    /// management for the host in this version replaces it.
    pub fn unsupported_remote(&self) -> Option<&toml::Table> {
        if self.remote.is_some() {
            return None;
        }
        self.extra.get("remote").and_then(toml::Value::as_table)
    }

    /// `true` when the query text matches this host for GUI search: name, group, notes,
    /// address and MAC (with or without separators), width-folded and case-insensitive.
    pub fn matches_search(&self, query: &str) -> bool {
        let q = normalize::search_key(query);
        let q = q.trim();
        if q.is_empty() {
            return true;
        }
        let compact_q: String = q
            .chars()
            .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
            .collect();
        let fields = [
            Some(self.name.as_str()),
            self.group.as_deref(),
            self.notes.as_deref(),
        ];
        fields
            .iter()
            .flatten()
            .any(|f| normalize::search_key(f).contains(q))
            || self
                .address
                .as_ref()
                .is_some_and(|a| a.to_string().to_lowercase().contains(q))
            || self.mac.to_string().to_lowercase().contains(q)
            || (!compact_q.is_empty() && self.mac.to_compact().contains(&compact_q))
    }
}

/// A validation problem found by [`Config::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConfigIssue {
    /// A host field is invalid.
    Host {
        /// Host id.
        id: HostId,
        /// Host name (as stored).
        name: String,
        /// Field.
        field: Field,
        /// Problem.
        issue: FieldIssue,
    },
    /// A setting is out of range.
    Setting {
        /// Dotted key.
        key: &'static str,
        /// Current value.
        value: String,
        /// Accepted values (English).
        expected: &'static str,
    },
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigIssue::Host {
                name, field, issue, ..
            } => write!(f, "host {name:?}: {field:?} {issue:?}"),
            ConfigIssue::Setting {
                key,
                value,
                expected,
            } => write!(f, "{key} = {value} (expected {expected})"),
        }
    }
}

/// Non-fatal observations made while parsing a settings file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParseNote {
    /// Hosts without `id` received deterministic ids (written on the next save that changes
    /// something, or by `Store::persist_assigned_ids` before data is keyed by a host id).
    AssignedIds {
        /// How many.
        count: usize,
    },
    /// A host repeated another host's id; it received a deterministic new id.
    DuplicateIdReplaced {
        /// Host name.
        name: String,
        /// The duplicated id.
        old: HostId,
        /// The replacement.
        new: HostId,
    },
    /// A host's `[hosts.remote]` table has a value this version does not know (written by a
    /// newer version, e.g. `kind = "ipmi"`): the host is treated as not managed and the table
    /// is kept unchanged ([`Host::unsupported_remote`]).
    UnsupportedRemote {
        /// Host name.
        name: String,
        /// The value, e.g. `kind = "ipmi"` (for the log / message).
        value: String,
    },
}

/// The whole settings file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// File format version (this build writes [`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// `[settings]`.
    pub settings: Settings,
    /// `[[hosts]]`, in file order.
    pub hosts: Vec<Host>,
    /// Unknown top-level keys, preserved.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema_version: SCHEMA_VERSION,
            settings: Settings::default(),
            hosts: Vec::new(),
            extra: toml::Table::new(),
        }
    }
}

/// Removes the keys of `tbl` whose value does not deserialize as the field of `T` it belongs
/// to. Every field of `T` has a default and unknown keys go to `extra`, so deserializing a
/// one-key table tests exactly that key. Removed keys are appended to `dropped` (prefixed).
fn drop_invalid_keys<T: serde::de::DeserializeOwned>(
    tbl: &mut toml::Table,
    prefix: &str,
    dropped: &mut Vec<String>,
) {
    let bad: Vec<String> = tbl
        .iter()
        .filter(|(k, v)| {
            let mut one = toml::Table::new();
            one.insert((*k).clone(), (*v).clone());
            T::deserialize(toml::Value::Table(one)).is_err()
        })
        .map(|(k, _)| k.clone())
        .collect();
    for k in bad {
        tbl.remove(&k);
        dropped.push(format!("{prefix}{k}"));
    }
}

/// Newer-schema files: `Some(description)` when this build cannot use a `[hosts.remote]`
/// table as a whole: its `kind` is missing or unknown, or any other key does not read (tested
/// together with the kind). Dropping single keys would silently fall back to defaults for
/// security-relevant values (address → host address, port → 22, user → root), so the whole
/// table is kept aside instead and the host is not managed in the read-only view.
fn unusable_newer_remote(tbl: &toml::Table) -> Option<String> {
    let Some(kind) = tbl.get("kind").cloned() else {
        return Some("kind missing".to_owned());
    };
    if RemoteKind::deserialize(kind.clone()).is_err() {
        return Some(format!("kind = {kind}"));
    }
    tbl.iter()
        .find(|(k, v)| {
            let mut one = toml::Table::new();
            one.insert("kind".to_owned(), kind.clone());
            one.insert((*k).clone(), (*v).clone());
            RemoteConfig::deserialize(toml::Value::Table(one)).is_err()
        })
        .map(|(k, v)| format!("{k} = {v}"))
}

/// Current-schema files: `Some(description)` when a `[hosts.remote]` table carries an enum
/// value a newer version may add (`kind` or `sudo` that is an unknown word, not a mistyped
/// known one). Everything else stays a parse error with its position. Imports use the same
/// rule (`transfer`), so a table kept from a file is one the next load keeps as well.
pub(crate) fn unsupported_remote_value(tbl: &toml::Table) -> Option<String> {
    let unknown_word = |key: &str, known: &dyn Fn(&str) -> bool| match tbl.get(key) {
        Some(toml::Value::String(s)) if !known(s) => Some(format!("{key} = {s:?}")),
        _ => None,
    };
    unknown_word("kind", &|s| s.parse::<RemoteKind>().is_ok())
        .or_else(|| unknown_word("sudo", &|s| s.parse::<SudoMode>().is_ok()))
}

/// Takes the `remote` tables `unusable` rejects out of the host tables of `tbl` (`hosts` array),
/// returning `(index, table, description)`.
fn take_remote_tables(
    tbl: &mut toml::Table,
    unusable: &dyn Fn(&toml::Table) -> Option<String>,
) -> Vec<(usize, toml::Value, String, String)> {
    let mut out = Vec::new();
    if let Some(toml::Value::Array(hosts)) = tbl.get_mut("hosts") {
        for (i, h) in hosts.iter_mut().enumerate() {
            let toml::Value::Table(t) = h else { continue };
            let Some(what) = t
                .get("remote")
                .and_then(toml::Value::as_table)
                .and_then(unusable)
            else {
                continue;
            };
            let name = t
                .get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if let Some(v) = t.remove("remote") {
                out.push((i, v, name, what));
            }
        }
    }
    out
}

/// Puts the tables of [`take_remote_tables`] back into the hosts' `extra` and describes them.
fn restore_remote_tables(
    cfg: &mut Config,
    taken: Vec<(usize, toml::Value, String, String)>,
) -> Vec<ParseNote> {
    let mut notes = Vec::new();
    for (i, v, name, value) in taken {
        if let Some(h) = cfg.hosts.get_mut(i) {
            log::warn!(
                "host {name:?}: remote management ({value}) is not supported by this version; kept unchanged, host not managed"
            );
            h.extra.insert("remote".to_owned(), v);
            notes.push(ParseNote::UnsupportedRemote { name, value });
        }
    }
    notes
}

/// Converts a byte offset into 1-based (line, column).
pub(crate) fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let col = before
        .rfind('\n')
        .map(|i| before[i + 1..].chars().count())
        .unwrap_or_else(|| before.chars().count())
        + 1;
    (line, col)
}

impl Config {
    /// Parses TOML text (a UTF-8 BOM is tolerated), assigns deterministic ids to hosts that
    /// have none (and to later duplicates of an id), and returns notes about that.
    ///
    /// A file with a newer `schema_version` (opened read-only) is parsed leniently: values
    /// this build does not understand (a new probe method or renderer, an IPv6 address...)
    /// are ignored and the defaults used, instead of failing the whole file. Files of the
    /// current version are strict, so typos are reported with their position.
    ///
    /// Errors: [`Error::ConfigParse`] with line/column (path `None`; the store fills it in).
    pub fn from_toml(text: &str) -> Result<(Config, Vec<ParseNote>)> {
        let (mut cfg, remote_notes) = Self::from_toml_keeping_ids(text)?;
        let mut notes = cfg.assign_missing_ids();
        notes.extend(remote_notes);
        Ok((cfg, notes))
    }

    /// [`Config::from_toml`] without [`Config::assign_missing_ids`]: hosts without `id` keep a
    /// nil id and repeated ids stay repeated. For the store, which must know which ids exist
    /// only in memory (`Store::persist_assigned_ids`).
    pub(crate) fn from_toml_keeping_ids(text: &str) -> Result<(Config, Vec<ParseNote>)> {
        let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
        let (cfg, remote_notes): (Config, Vec<ParseNote>) = match toml::from_str(text) {
            Ok(cfg) => (cfg, Vec::new()),
            Err(e) => match Self::from_newer_toml(text)
                .or_else(|| Self::from_toml_keeping_unsupported_remote(text))
            {
                Some(parsed) => parsed,
                None => {
                    let (line, column) = match e.span() {
                        Some(span) => {
                            let (l, c) = line_col(text, span.start);
                            (Some(l), Some(c))
                        }
                        None => (None, None),
                    };
                    return Err(Error::ConfigParse {
                        path: None,
                        line,
                        column,
                        message: e.message().to_owned(),
                    });
                }
            },
        };
        Ok((cfg, remote_notes))
    }

    /// Current-schema file that failed the strict parse: when the only problems are
    /// `[hosts.remote]` tables with a `kind` / `sudo` word of a newer version (the schema
    /// stays 1 for additive remote-management changes), those tables are kept aside
    /// ([`Host::unsupported_remote`]) and the rest is parsed strictly. `None` otherwise (the
    /// caller reports the original error with its position).
    fn from_toml_keeping_unsupported_remote(text: &str) -> Option<(Config, Vec<ParseNote>)> {
        let mut tbl: toml::Table = toml::from_str(text).ok()?;
        if tbl
            .get("schema_version")
            .and_then(toml::Value::as_integer)
            .is_some_and(|v| v > i64::from(SCHEMA_VERSION))
        {
            return None;
        }
        let taken = take_remote_tables(&mut tbl, &unsupported_remote_value);
        if taken.is_empty() {
            return None;
        }
        let mut cfg = Config::deserialize(toml::Value::Table(tbl)).ok()?;
        let notes = restore_remote_tables(&mut cfg, taken);
        Some((cfg, notes))
    }

    /// Lenient parse of a file whose `schema_version` is newer than [`SCHEMA_VERSION`]: every
    /// value that does not deserialize is dropped (so the default applies), except in
    /// `[hosts.remote]`, which is kept aside as a whole when anything in it does not read
    /// (the host is then not managed in this view). `None` when the text is not TOML or the
    /// version is not newer. The result is only ever shown read-only, so nothing dropped here
    /// can be lost by a later save.
    fn from_newer_toml(text: &str) -> Option<(Config, Vec<ParseNote>)> {
        let mut tbl: toml::Table = toml::from_str(text).ok()?;
        let found = tbl.get("schema_version")?.as_integer()?;
        if found <= i64::from(SCHEMA_VERSION) {
            return None;
        }
        let mut dropped = Vec::new();
        if let Some(toml::Value::Table(settings)) = tbl.get_mut("settings") {
            if let Some(toml::Value::Table(t)) = settings.get_mut("wake") {
                drop_invalid_keys::<WakeSettings>(t, "settings.wake.", &mut dropped);
            }
            if let Some(toml::Value::Table(t)) = settings.get_mut("probe") {
                drop_invalid_keys::<ProbeSettings>(t, "settings.probe.", &mut dropped);
            }
            if let Some(toml::Value::Table(t)) = settings.get_mut("gui") {
                drop_invalid_keys::<GuiSettings>(t, "settings.gui.", &mut dropped);
            }
            if let Some(toml::Value::Table(t)) = settings.get_mut("remote") {
                drop_invalid_keys::<RemoteSettings>(t, "settings.remote.", &mut dropped);
            }
            drop_invalid_keys::<Settings>(settings, "settings.", &mut dropped);
        }
        if let Some(toml::Value::Array(hosts)) = tbl.get_mut("hosts") {
            let before = hosts.len();
            hosts.retain(toml::Value::is_table);
            if hosts.len() != before {
                dropped.push("hosts[]".to_owned());
            }
        }
        let taken = take_remote_tables(&mut tbl, &unusable_newer_remote);
        if let Some(toml::Value::Array(hosts)) = tbl.get_mut("hosts") {
            for (i, h) in hosts.iter_mut().enumerate() {
                if let toml::Value::Table(t) = h {
                    drop_invalid_keys::<Host>(t, &format!("hosts[{i}]."), &mut dropped);
                }
            }
        }
        drop_invalid_keys::<Config>(&mut tbl, "", &mut dropped);
        let mut cfg = Config::deserialize(toml::Value::Table(tbl)).ok()?;
        cfg.schema_version = u32::try_from(found).unwrap_or(u32::MAX);
        if !dropped.is_empty() {
            log::warn!(
                "settings file schema_version {found}: ignoring values this version does not understand: {}",
                dropped.join(", ")
            );
        }
        let notes = restore_remote_tables(&mut cfg, taken);
        Some((cfg, notes))
    }

    /// Serializes to TOML with the [`FILE_HEADER`] comment.
    pub fn to_toml(&self) -> Result<String> {
        let body = toml::to_string(self).map_err(|e| Error::Serialize(e.to_string()))?;
        Ok(format!("{FILE_HEADER}{body}"))
    }

    /// [`Config::to_toml`], then parses the text again: what is saved must be readable by
    /// the next load (values kept from an import, e.g. unknown keys, may nest deeper than
    /// the TOML parser accepts). Errors: [`Error::Serialize`] when it is not.
    pub fn to_toml_checked(&self) -> Result<String> {
        let text = self.to_toml()?;
        match Self::from_toml(&text) {
            Ok(_) => Ok(text),
            Err(e) => Err(Error::Serialize(format!(
                "the result could not be read back ({e})"
            ))),
        }
    }

    /// `true` when the file was written by a newer version (open read-only).
    pub fn is_newer_schema(&self) -> bool {
        self.schema_version > SCHEMA_VERSION
    }

    /// Deterministic id for a host at `index` without id.
    pub fn deterministic_id(index: usize, name: &str, mac: &MacAddr) -> HostId {
        Uuid::new_v5(
            &HOST_ID_NAMESPACE,
            format!("{index}:{name}:{mac}").as_bytes(),
        )
    }

    /// Gives every host with a nil id a deterministic v5 id and replaces duplicated ids
    /// (second and later occurrences). Called by [`Config::from_toml`].
    pub fn assign_missing_ids(&mut self) -> Vec<ParseNote> {
        let mut notes = Vec::new();
        let mut assigned = 0;
        for (i, h) in self.hosts.iter_mut().enumerate() {
            if h.id.is_nil() {
                h.id = Self::deterministic_id(i, &h.name, &h.mac);
                assigned += 1;
            }
        }
        if assigned > 0 {
            notes.push(ParseNote::AssignedIds { count: assigned });
        }
        let mut seen: HashMap<HostId, usize> = HashMap::new();
        for i in 0..self.hosts.len() {
            let id = self.hosts[i].id;
            if seen.contains_key(&id) {
                let h = &self.hosts[i];
                let mut new = Uuid::new_v5(
                    &HOST_ID_NAMESPACE,
                    format!("dup:{i}:{}:{}:{}", h.id, h.name, h.mac).as_bytes(),
                );
                while seen.contains_key(&new) {
                    new = Uuid::new_v5(&HOST_ID_NAMESPACE, new.as_bytes());
                }
                notes.push(ParseNote::DuplicateIdReplaced {
                    name: h.name.clone(),
                    old: id,
                    new,
                });
                self.hosts[i].id = new;
                seen.insert(new, i);
            } else {
                seen.insert(id, i);
            }
        }
        notes
    }

    /// Host by id.
    pub fn get(&self, id: HostId) -> Option<&Host> {
        self.hosts.iter().find(|h| h.id == id)
    }

    /// Mutable host by id.
    pub fn get_mut(&mut self, id: HostId) -> Option<&mut Host> {
        self.hosts.iter_mut().find(|h| h.id == id)
    }

    /// Index of a host by id.
    pub fn position(&self, id: HostId) -> Option<usize> {
        self.hosts.iter().position(|h| h.id == id)
    }

    /// Finds one host by query, in this order:
    /// 1. exact id (any UUID notation),
    /// 2. name (width-folded, case-insensitive),
    /// 3. id prefix of at least 8 hex characters (hyphens optional),
    /// 4. MAC address (any accepted notation).
    ///
    /// Errors: [`Error::HostNotFound`], [`Error::AmbiguousHost`] (several matches at the first
    /// step that matches anything).
    pub fn find(&self, query: &str) -> Result<&Host> {
        let q = query.trim();
        let ambiguous = |hits: Vec<&Host>| Error::AmbiguousHost {
            query: q.to_owned(),
            candidates: hits.iter().map(|h| h.name.clone()).collect(),
        };
        if let Ok(id) = Uuid::parse_str(q)
            && let Some(h) = self.get(id)
        {
            return Ok(h);
        }
        let key = normalize::name_key(q);
        let hits: Vec<&Host> = self
            .hosts
            .iter()
            .filter(|h| normalize::name_key(&h.name) == key)
            .collect();
        match hits.len() {
            1 => return Ok(hits[0]),
            0 => {}
            _ => return Err(ambiguous(hits)),
        }
        let compact: String = normalize::normalize_input(q)
            .to_ascii_lowercase()
            .chars()
            .filter(|c| *c != '-')
            .collect();
        if compact.len() >= ID_PREFIX_MIN && compact.chars().all(|c| c.is_ascii_hexdigit()) {
            let hits: Vec<&Host> = self
                .hosts
                .iter()
                .filter(|h| h.id.simple().to_string().starts_with(&compact))
                .collect();
            match hits.len() {
                1 => return Ok(hits[0]),
                0 => {}
                _ => return Err(ambiguous(hits)),
            }
        }
        if let Ok(mac) = MacAddr::parse(q) {
            let hits: Vec<&Host> = self.hosts.iter().filter(|h| h.mac == mac).collect();
            match hits.len() {
                1 => return Ok(hits[0]),
                0 => {}
                _ => return Err(ambiguous(hits)),
            }
        }
        Err(Error::HostNotFound(q.to_owned()))
    }

    /// Distinct group names, sorted case-insensitively (first spelling wins).
    pub fn groups(&self) -> Vec<String> {
        let mut seen: HashMap<String, String> = HashMap::new();
        for h in &self.hosts {
            if let Some(g) = h.group.as_deref() {
                let g = g.trim();
                if !g.is_empty() {
                    seen.entry(normalize::name_key(g))
                        .or_insert_with(|| g.to_owned());
                }
            }
        }
        let mut v: Vec<(String, String)> = seen.into_iter().collect();
        v.sort();
        v.into_iter().map(|(_, g)| g).collect()
    }

    /// Hosts of a group (width-folded, case-insensitive), in file order.
    pub fn hosts_in_group(&self, group: &str) -> Vec<&Host> {
        let key = normalize::name_key(group);
        self.hosts
            .iter()
            .filter(|h| {
                h.group
                    .as_deref()
                    .is_some_and(|g| normalize::name_key(g) == key)
            })
            .collect()
    }

    /// Checks a candidate host name against the rules: 1..=64 characters after trimming,
    /// not parseable as a MAC, unique (ignoring the host being edited).
    pub fn check_name(&self, name: &str, editing: Option<HostId>) -> Result<(), FieldIssue> {
        let name = normalize::clean_single_line(name);
        if name.is_empty() {
            return Err(FieldIssue::Required);
        }
        if name.chars().count() > NAME_MAX_CHARS {
            return Err(FieldIssue::NameTooLong);
        }
        if mac::looks_like_mac(&name) {
            return Err(FieldIssue::NameLooksLikeMac);
        }
        let key = normalize::name_key(&name);
        if self
            .hosts
            .iter()
            .any(|h| Some(h.id) != editing && normalize::name_key(&h.name) == key)
        {
            return Err(FieldIssue::DuplicateName);
        }
        Ok(())
    }

    /// Adds a new host after checking its name and id. The name is stored cleaned (control
    /// characters → spaces, trimmed), as the rules check it. Errors: [`Error::InvalidFields`].
    pub fn insert_host(&mut self, mut host: Host) -> Result<HostId> {
        if host.id.is_nil() || self.get(host.id).is_some() {
            host.id = Uuid::new_v4();
        }
        host.name = normalize::clean_single_line(&host.name);
        self.check_name(&host.name, None)
            .map_err(|i| Error::InvalidFields(vec![FieldError::new(Field::Name, i)]))?;
        let id = host.id;
        self.hosts.push(host);
        Ok(id)
    }

    /// Replaces the host with the same id, keeping its position. The name is stored cleaned
    /// like [`Config::insert_host`] does.
    /// Errors: [`Error::HostIdNotFound`], [`Error::InvalidFields`] (duplicate name).
    pub fn replace_host(&mut self, mut host: Host) -> Result<()> {
        let pos = self
            .position(host.id)
            .ok_or(Error::HostIdNotFound(host.id))?;
        host.name = normalize::clean_single_line(&host.name);
        self.check_name(&host.name, Some(host.id))
            .map_err(|i| Error::InvalidFields(vec![FieldError::new(Field::Name, i)]))?;
        self.hosts[pos] = host;
        Ok(())
    }

    /// Removes a host by id. Errors: [`Error::HostIdNotFound`].
    pub fn remove_host(&mut self, id: HostId) -> Result<Host> {
        let pos = self.position(id).ok_or(Error::HostIdNotFound(id))?;
        Ok(self.hosts.remove(pos))
    }

    /// Validates `draft` and saves it: updates the host `editing.id` with the fields the user
    /// changed relative to `editing.draft` (keeping fields the draft does not show, `extra`,
    /// and concurrent changes to untouched fields; see [`HostDraft::build`]), or inserts a new
    /// host when `editing` is `None`. Call it inside [`crate::store::Store::update`].
    ///
    /// Errors: [`Error::InvalidFields`], [`Error::HostIdNotFound`] when the host being edited
    /// was deleted meanwhile (the GUI then offers "save as new host" = `editing = None`).
    pub fn save_draft(&mut self, draft: &HostDraft, editing: Option<&EditBase>) -> Result<HostId> {
        if let Some(b) = editing
            && self.get(b.id).is_none()
        {
            return Err(Error::HostIdNotFound(b.id));
        }
        let host = draft.build(self, editing).map_err(Error::InvalidFields)?;
        let id = host.id;
        match editing {
            Some(_) => self.replace_host(host)?,
            None => {
                self.hosts.push(host);
            }
        }
        Ok(id)
    }

    /// Returns `base` (cleaned, cut to 64 characters) if it is a valid free name, otherwise
    /// `base (2)`, `base (3)`... Use with `Msg::CopyOf` when duplicating a host.
    pub fn unique_name(&self, base: &str) -> String {
        let base = normalize::clean_single_line(base);
        let base: String = base.chars().take(NAME_MAX_CHARS).collect();
        if self.check_name(&base, None).is_ok() {
            return base;
        }
        for n in 2.. {
            let suffix = format!(" ({n})");
            let keep = NAME_MAX_CHARS.saturating_sub(suffix.chars().count());
            let cand: String = base.chars().take(keep).collect::<String>() + &suffix;
            if self.check_name(&cand, None).is_ok() {
                return cand;
            }
        }
        unreachable!()
    }

    /// Lists all problems: host field issues (name rules, duplicate names, unusable MAC) and
    /// out-of-range settings. An empty list means the file is clean.
    pub fn validate(&self) -> Vec<ConfigIssue> {
        let mut issues = Vec::new();
        let mut names: HashMap<String, usize> = HashMap::new();
        for h in &self.hosts {
            *names.entry(normalize::name_key(&h.name)).or_default() += 1;
        }
        for h in &self.hosts {
            let mut push = |field, issue| {
                issues.push(ConfigIssue::Host {
                    id: h.id,
                    name: h.name.clone(),
                    field,
                    issue,
                })
            };
            let name = normalize::clean_single_line(&h.name);
            if name.is_empty() {
                push(Field::Name, FieldIssue::Required);
            } else if name.chars().count() > NAME_MAX_CHARS {
                push(Field::Name, FieldIssue::NameTooLong);
            } else if mac::looks_like_mac(&name) {
                push(Field::Name, FieldIssue::NameLooksLikeMac);
            }
            if !name.is_empty() && names.get(&normalize::name_key(&h.name)).copied() > Some(1) {
                push(Field::Name, FieldIssue::DuplicateName);
            }
            if !h.mac.is_usable() {
                push(Field::Mac, FieldIssue::MacNotUnicast);
            }
            if h.port == Some(0) {
                push(Field::Port, FieldIssue::InvalidPort);
            }
            if let Err(i) = crate::addr::check_port_list(&h.tcp_ports) {
                push(Field::TcpPorts, i);
            }
            if let Some(r) = &h.remote {
                for e in r.check() {
                    push(e.field, e.issue);
                }
            }
        }
        for (key, value, expected) in self.settings.out_of_range() {
            issues.push(ConfigIssue::Setting {
                key,
                value,
                expected,
            });
        }
        issues
    }
}

#[cfg(test)]
mod tests;
