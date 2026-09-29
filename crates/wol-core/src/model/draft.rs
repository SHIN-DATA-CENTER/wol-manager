//! Host editing with text fields as typed by users (GUI editor, `wolm add/edit`).
//!
//! Editing is a three-way merge. [`EditBase`] records what the editor showed when it was
//! opened. [`HostDraft::build`] starts from a clone of the host as it is in the config *now*
//! (re-read under the store lock) and overwrites only the fields whose text the user changed
//! relative to that base. Fields the UI does not show, the exact stored representation of
//! untouched fields, `extra`, and fields another process changed while the editor was open
//! are all kept.

use serde::Serialize;
use uuid::Uuid;

use super::{Config, Host, HostId, NAME_MAX_CHARS, ProbeMethod};
use crate::addr::{self, HostAddr};
use crate::error::{Field, FieldError, FieldIssue};
use crate::mac::{self, MacAddr, SecureOn};
use crate::normalize;

/// Editable text form of a [`Host`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostDraft {
    /// Name (required).
    pub name: String,
    /// MAC (required).
    pub mac: String,
    /// IPv4 address or host name (optional).
    pub address: String,
    /// Group (optional).
    pub group: String,
    /// Notes (optional).
    pub notes: String,
    /// Port override (empty = default).
    pub port: String,
    /// SecureOn password (empty = none).
    pub secureon: String,
    /// Extra targets, one per line (commas and spaces also separate).
    pub targets: String,
    /// Directed broadcast on every selected subnet.
    pub broadcast: bool,
    /// Pinned adapter GUIDs (the GUI keeps the list untouched unless the user changes it).
    pub interfaces: Vec<String>,
    /// Probe method override (`None` = settings default).
    pub probe: Option<ProbeMethod>,
    /// TCP ports override, comma separated (empty = settings default).
    pub tcp_ports: String,
}

impl Default for HostDraft {
    /// Empty draft for a new host (`broadcast = true`, everything else empty).
    fn default() -> Self {
        HostDraft::from_host(&Host::default())
    }
}

/// The host an editor was opened on: its id and the draft shown at that moment.
///
/// Take it when the editor opens (GUI) or when the host is looked up (`wolm edit`), keep it
/// unchanged while the user edits a clone of `draft`, and pass it to [`HostDraft::build`] /
/// [`Config::save_draft`] inside [`crate::store::Store::update`]. Only fields whose text differs
/// from `draft` are applied to the host as it is on disk at save time, so a change another
/// process made meanwhile to a field the user did not touch survives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EditBase {
    /// Id of the edited host.
    pub id: HostId,
    /// [`HostDraft::from_host`] of the host when editing started.
    pub draft: HostDraft,
}

impl EditBase {
    /// Snapshot of `host` for editing.
    pub fn of(host: &Host) -> EditBase {
        EditBase {
            id: host.id,
            draft: HostDraft::from_host(host),
        }
    }
}

impl HostDraft {
    /// Text form of an existing host (what the editor shows).
    pub fn from_host(h: &Host) -> HostDraft {
        HostDraft {
            name: h.name.clone(),
            mac: if h.mac.is_zero() {
                String::new()
            } else {
                h.mac.to_string()
            },
            address: h
                .address
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            group: h.group.clone().unwrap_or_default(),
            notes: h.notes.clone().unwrap_or_default(),
            port: h.port.map(|p| p.to_string()).unwrap_or_default(),
            secureon: h.secureon.map(|s| s.to_string()).unwrap_or_default(),
            targets: addr::format_target_list(&h.targets),
            broadcast: h.broadcast,
            interfaces: h.interfaces.clone(),
            probe: h.probe,
            tcp_ports: addr::format_port_list(&h.tcp_ports),
        }
    }

    /// Validates the draft and produces the host to store.
    ///
    /// * `editing = Some(base)` and `base.id` exists in `cfg`: the result is a clone of the
    ///   host *as it is in `cfg`* with only the fields whose text differs from `base.draft`
    ///   re-parsed and overwritten (same id, `extra` kept). Fields the user left alone keep
    ///   the value in `cfg`, even if another process changed them after `base` was taken.
    /// * `editing = None` (or `base.id` no longer exists): a new host built from every field
    ///   of the draft; the id is a fresh v4 (or `base.id`). Use [`Config::save_draft`] to get
    ///   [`crate::Error::HostIdNotFound`] instead when the edited host vanished.
    ///
    /// The resulting name is always checked (another host may have taken it meanwhile). All
    /// field problems are returned together, in field order.
    pub fn build(&self, cfg: &Config, editing: Option<&EditBase>) -> Result<Host, Vec<FieldError>> {
        match editing.and_then(|b| cfg.get(b.id).map(|h| (b, h))) {
            Some((base, current)) => {
                self.build_from(cfg, current.clone(), &base.draft, Some(base.id))
            }
            None => {
                let h = Host {
                    id: editing.map_or_else(Uuid::new_v4, |b| b.id),
                    ..Host::default()
                };
                self.build_from(cfg, h, &HostDraft::default(), None)
            }
        }
    }

    /// Like [`HostDraft::build`] for "duplicate host": the result is a new host (fresh id)
    /// based on `template`, keeping the template's hidden fields and `extra`.
    pub fn build_copy(&self, cfg: &Config, template: &Host) -> Result<Host, Vec<FieldError>> {
        let h = Host {
            id: Uuid::new_v4(),
            ..template.clone()
        };
        self.build_from(cfg, h, &HostDraft::from_host(template), None)
    }

    /// Applies the fields of `self` that differ from `base` onto `h`.
    fn build_from(
        &self,
        cfg: &Config,
        mut h: Host,
        base: &HostDraft,
        editing: Option<HostId>,
    ) -> Result<Host, Vec<FieldError>> {
        let mut errs = Vec::new();
        let mut err = |field, issue| errs.push(FieldError::new(field, issue));

        // Name: the resulting name is always checked (another host may have taken it).
        let name_changed = self.name != base.name;
        let name = if name_changed { &self.name } else { &h.name };
        match cfg.check_name(name, editing) {
            Ok(()) => {
                if name_changed {
                    h.name = normalize::clean_single_line(&self.name);
                }
            }
            Err(i) => err(Field::Name, i),
        }

        if self.mac != base.mac {
            match MacAddr::parse_usable(&self.mac) {
                Ok(m) => h.mac = m,
                Err(i) => err(Field::Mac, i),
            }
        } else if !h.mac.is_usable() {
            err(
                Field::Mac,
                if h.mac.is_zero() {
                    FieldIssue::Required
                } else {
                    FieldIssue::MacNotUnicast
                },
            );
        }

        if self.address != base.address {
            match optional(&self.address, HostAddr::parse) {
                Ok(a) => h.address = a,
                Err(i) => err(Field::Address, i),
            }
        }

        if self.group != base.group {
            let g = normalize::clean_single_line(&self.group);
            h.group = (!g.is_empty()).then_some(g);
        }

        if self.notes != base.notes {
            let n = normalize::clean_notes(&self.notes);
            h.notes = (!n.trim().is_empty()).then_some(n);
        }

        if self.port != base.port {
            match optional(&self.port, addr::parse_port) {
                Ok(p) => h.port = p,
                Err(i) => err(Field::Port, i),
            }
        }

        if self.secureon != base.secureon {
            match optional(&self.secureon, SecureOn::parse) {
                Ok(s) => h.secureon = s,
                Err(i) => err(Field::SecureOn, i),
            }
        }

        if self.targets != base.targets {
            match addr::parse_target_list(&self.targets) {
                Ok(t) => h.targets = t,
                Err(i) => err(Field::Targets, i),
            }
        }

        if self.broadcast != base.broadcast {
            h.broadcast = self.broadcast;
        }

        if self.interfaces != base.interfaces {
            let mut v: Vec<String> = Vec::new();
            for s in &self.interfaces {
                let s = s.trim();
                if !s.is_empty() && !v.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                    v.push(s.to_owned());
                }
            }
            h.interfaces = v;
        }

        if self.probe != base.probe {
            h.probe = self.probe;
        }

        if self.tcp_ports != base.tcp_ports {
            match addr::parse_port_list(&self.tcp_ports) {
                Ok(p) => h.tcp_ports = p,
                Err(i) => err(Field::TcpPorts, i),
            }
        }

        if errs.is_empty() { Ok(h) } else { Err(errs) }
    }
}

/// Empty (after normalization) → `Ok(None)`, else parse.
fn optional<T>(
    s: &str,
    parse: impl Fn(&str) -> Result<T, FieldIssue>,
) -> Result<Option<T>, FieldIssue> {
    if normalize::normalize_input(s).trim().is_empty() {
        Ok(None)
    } else {
        parse(s).map(Some)
    }
}

/// Stateless check of one field's text, for the GUI's live validation (pure callback).
///
/// Optional fields accept empty input. The name check here does not look for duplicates;
/// use [`Config::check_name`] for that.
pub fn check_field(field: Field, input: &str) -> Result<(), FieldIssue> {
    match field {
        Field::Name => {
            let n = normalize::clean_single_line(input);
            if n.is_empty() {
                Err(FieldIssue::Required)
            } else if n.chars().count() > NAME_MAX_CHARS {
                Err(FieldIssue::NameTooLong)
            } else if mac::looks_like_mac(&n) {
                Err(FieldIssue::NameLooksLikeMac)
            } else {
                Ok(())
            }
        }
        Field::Mac => MacAddr::parse_usable(input).map(|_| ()),
        Field::Address => optional(input, HostAddr::parse).map(|_| ()),
        Field::Port => optional(input, addr::parse_port).map(|_| ()),
        Field::SecureOn => optional(input, SecureOn::parse).map(|_| ()),
        Field::Targets => addr::parse_target_list(input).map(|_| ()),
        Field::TcpPorts => addr::parse_port_list(input).map(|_| ()),
        Field::Group | Field::Notes | Field::Interfaces | Field::Probe => Ok(()),
    }
}
