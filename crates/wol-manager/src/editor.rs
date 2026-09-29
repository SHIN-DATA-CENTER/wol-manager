//! Host editor: `EditorState` ⇄ `HostDraft` (with `EditBase` for the three-way merge),
//! the adapter pinning rule (−1 / −2 / index), the `Validator` pure callbacks and the
//! mapping of `wol_core` field errors to the `*-issue` properties (contract §3, §4).

use slint::{ComponentHandle, Model, SharedString};
use wol_core::addr;
use wol_core::i18n::{Lang, Msg};
use wol_core::model::{Field, FieldError, ProbeMethod, check_field};
use wol_core::netif::NetInterface;
use wol_core::{Config, EditBase, Host, HostDraft, HostId};

use crate::app::{App, Pending};
use crate::persist::{Op, SaveKind, apply_op};
use crate::texts::{GuiText, Text};
use crate::{
    AppState, AppWindow, ArpStatus, ConfirmKind, ConfirmRequest, EditorMode, EditorState,
    FieldIssue, InterfaceOption, OverlayKind, ToastKind,
};

/// `interface-index` meaning "automatic".
pub const IFACE_AUTO: i32 = -1;
/// `interface-index` meaning "keep the host's existing pinning unchanged".
pub const IFACE_KEEP: i32 = -2;

/// wol-core issue → Slint enum (1:1).
pub fn issue(i: wol_core::FieldIssue) -> FieldIssue {
    use wol_core::FieldIssue as C;
    match i {
        C::Required => FieldIssue::Required,
        C::InvalidMac => FieldIssue::InvalidMac,
        C::MacNotUnicast => FieldIssue::MacNotUnicast,
        C::InvalidAddress => FieldIssue::InvalidAddress,
        C::InvalidPort => FieldIssue::InvalidPort,
        C::InvalidPortList => FieldIssue::InvalidPortList,
        C::TooManyPorts => FieldIssue::TooManyPorts,
        C::InvalidSecureOn => FieldIssue::InvalidSecureOn,
        C::InvalidTarget => FieldIssue::InvalidTarget,
        C::DuplicateName => FieldIssue::DuplicateName,
        C::NameLooksLikeMac => FieldIssue::NameLooksLikeMac,
        C::NameTooLong => FieldIssue::NameTooLong,
        C::ImeKana => FieldIssue::ImeKana,
    }
}

fn check(field: Field, text: &str) -> FieldIssue {
    match check_field(field, text) {
        Ok(()) => FieldIssue::None,
        Err(e) => issue(e),
    }
}

/// `Validator.check-name`.
pub fn check_name(cfg: &Config, name: &str, host_id: &str) -> FieldIssue {
    let editing = HostId::parse_str(host_id.trim()).ok();
    match cfg.check_name(name, editing) {
        Ok(()) => FieldIssue::None,
        Err(e) => issue(e),
    }
}

/// `Validator.check-mac`.
pub fn check_mac(text: &str) -> FieldIssue {
    check(Field::Mac, text)
}
/// `Validator.check-address`.
pub fn check_address(text: &str) -> FieldIssue {
    check(Field::Address, text)
}
/// `Validator.check-port`.
pub fn check_port(text: &str) -> FieldIssue {
    check(Field::Port, text)
}
/// `Validator.check-targets`.
pub fn check_targets(text: &str) -> FieldIssue {
    check(Field::Targets, text)
}
/// `Validator.check-secureon`.
pub fn check_secureon(text: &str) -> FieldIssue {
    check(Field::SecureOn, text)
}
/// `Validator.check-tcp-ports`.
pub fn check_tcp_ports(text: &str) -> FieldIssue {
    check(Field::TcpPorts, text)
}
/// `Validator.port-value`: the normalized port, 0 when invalid.
pub fn port_value(text: &str) -> i32 {
    addr::parse_port(text).map(i32::from).unwrap_or(0)
}
/// `Validator.is-ipv4`.
pub fn is_ipv4(text: &str) -> bool {
    addr::parse_ipv4(text).is_ok()
}

/// `probe-index` for a host override.
pub fn probe_index(p: Option<ProbeMethod>) -> i32 {
    match p {
        None => 0,
        Some(ProbeMethod::Auto) => 1,
        Some(ProbeMethod::Icmp) => 2,
        Some(ProbeMethod::Tcp) => 3,
        Some(ProbeMethod::None) => 4,
    }
}

/// Host override for a `probe-index`.
pub fn probe_from_index(i: i32) -> Option<ProbeMethod> {
    match i {
        1 => Some(ProbeMethod::Auto),
        2 => Some(ProbeMethod::Icmp),
        3 => Some(ProbeMethod::Tcp),
        4 => Some(ProbeMethod::None),
        _ => None,
    }
}

/// One adapter entry of the editor's picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceOption {
    /// GUID (stored in the config).
    pub id: String,
    /// Adapter name.
    pub label: String,
    /// "192.168.1.20/24".
    pub detail: String,
}

/// Adapters offered for pinning: everything except loopback that is up or has IPv4.
pub fn interface_options(ifaces: &[NetInterface]) -> Vec<IfaceOption> {
    ifaces
        .iter()
        .filter(|i| !i.is_loopback() && (i.oper_up || !i.ipv4.is_empty()))
        .map(|i| IfaceOption {
            id: i.guid.clone(),
            label: i.display_name().to_owned(),
            detail: i
                .ipv4
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        })
        .collect()
}

/// Initial adapter state of the editor for a host's pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaceChoice {
    /// `interface-index`.
    pub index: i32,
    /// `interface-pinned-count`.
    pub pinned_count: i32,
    /// `interface-missing`.
    pub missing: bool,
}

/// The adapter rule (contract §3): no pins → −1; exactly one pin whose adapter is present →
/// its index; anything else (several pins, or any pinned adapter missing) → −2 (keep).
pub fn interface_choice(
    pins: &[String],
    options: &[IfaceOption],
    ifaces: &[NetInterface],
) -> IfaceChoice {
    let find = |pin: &str| -> Option<usize> {
        let iface = ifaces.iter().find(|i| i.matches_pin(pin))?;
        options.iter().position(|o| o.id == iface.guid)
    };
    let missing = pins.iter().any(|p| find(p).is_none());
    let index = match pins {
        [] => IFACE_AUTO,
        [only] => match find(only) {
            Some(i) => i as i32,
            None => IFACE_KEEP,
        },
        _ => IFACE_KEEP,
    };
    IfaceChoice {
        index,
        pinned_count: i32::try_from(pins.len()).unwrap_or(i32::MAX),
        missing,
    }
}

/// The editor's values (mirror of `EditorState`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EditorFields {
    /// Name.
    pub name: String,
    /// MAC.
    pub mac: String,
    /// Address.
    pub address: String,
    /// Group.
    pub group: String,
    /// Notes.
    pub notes: String,
    /// Directed broadcast.
    pub broadcast: bool,
    /// Targets, one per line.
    pub targets: String,
    /// Port override.
    pub port: String,
    /// −1 auto, −2 keep, ≥0 pin `options[i]`.
    pub interface_index: i32,
    /// SecureOn.
    pub secureon: String,
    /// 0 default, 1 auto, 2 icmp, 3 tcp, 4 none.
    pub probe_index: i32,
    /// TCP ports override.
    pub tcp_ports: String,
}

/// What the editor was opened on.
#[derive(Debug, Clone)]
pub struct EditorSession {
    /// Add / edit / duplicate.
    pub mode: EditorMode,
    /// Snapshot for the three-way merge (edit mode).
    pub base: Option<EditBase>,
    /// Host being duplicated (duplicate mode; keeps hidden fields and `extra`).
    pub template: Option<Host>,
    /// Pins of the host when the editor opened.
    pub pins: Vec<String>,
    /// `interface-index` set when the editor opened.
    pub initial_index: i32,
    /// Adapter list behind `EditorState.interfaces`.
    pub options: Vec<IfaceOption>,
    /// Name pre-filled for a duplicate (to re-translate it on a language switch).
    pub copy_name: Option<String>,
    /// Id used when a new host is saved.
    pub new_id: HostId,
    /// Changes whenever the editor is (re)opened or closed; stale ARP results are dropped.
    pub token: u64,
}

/// Editor fields for a draft.
pub fn fields_from_draft(d: &HostDraft, choice: IfaceChoice) -> EditorFields {
    EditorFields {
        name: d.name.clone(),
        mac: d.mac.clone(),
        address: d.address.clone(),
        group: d.group.clone(),
        notes: d.notes.clone(),
        broadcast: d.broadcast,
        targets: d.targets.clone(),
        port: d.port.clone(),
        interface_index: choice.index,
        secureon: d.secureon.clone(),
        probe_index: probe_index(d.probe),
        tcp_ports: d.tcp_ports.clone(),
    }
}

/// The pins to save for the editor's adapter choice.
pub fn pins_for(f: &EditorFields, s: &EditorSession) -> Vec<String> {
    let i = f.interface_index;
    if i == IFACE_KEEP || (i >= 0 && i == s.initial_index) {
        // Unchanged: keep the exact stored representation.
        return s.pins.clone();
    }
    match usize::try_from(i).ok().and_then(|i| s.options.get(i)) {
        Some(o) => vec![o.id.clone()],
        None => Vec::new(),
    }
}

/// Draft from the editor's fields.
pub fn draft_from_fields(f: &EditorFields, s: &EditorSession) -> HostDraft {
    HostDraft {
        name: f.name.clone(),
        mac: f.mac.clone(),
        address: f.address.clone(),
        group: f.group.clone(),
        notes: f.notes.clone(),
        port: f.port.clone(),
        secureon: f.secureon.clone(),
        targets: f.targets.clone(),
        broadcast: f.broadcast,
        interfaces: pins_for(f, s),
        probe: probe_from_index(f.probe_index),
        tcp_ports: f.tcp_ports.clone(),
    }
}

/// Issues per editor property, from `HostDraft::build` / `save_draft` errors.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Issues {
    /// name-issue.
    pub name: FieldIssue,
    /// mac-issue.
    pub mac: FieldIssue,
    /// address-issue.
    pub address: FieldIssue,
    /// targets-issue.
    pub targets: FieldIssue,
    /// port-issue.
    pub port: FieldIssue,
    /// secureon-issue.
    pub secureon: FieldIssue,
    /// tcp-ports-issue.
    pub tcp_ports: FieldIssue,
}

impl Issues {
    /// An advanced field failed (open the "Advanced" section).
    pub fn advanced(&self) -> bool {
        [self.targets, self.port, self.secureon, self.tcp_ports]
            .iter()
            .any(|i| *i != FieldIssue::None)
    }

    /// Nothing to show.
    pub fn is_empty(&self) -> bool {
        *self == Issues::default()
    }
}

/// Maps field errors to the editor properties (first error per field wins).
pub fn issues_from(errors: &[FieldError]) -> Issues {
    let mut out = Issues::default();
    for e in errors {
        let slot = match e.field {
            Field::Name => &mut out.name,
            Field::Mac => &mut out.mac,
            Field::Address => &mut out.address,
            Field::Targets => &mut out.targets,
            Field::Port => &mut out.port,
            Field::SecureOn => &mut out.secureon,
            Field::TcpPorts => &mut out.tcp_ports,
            Field::Group | Field::Notes | Field::Interfaces | Field::Probe => continue,
        };
        if *slot == FieldIssue::None {
            *slot = issue(e.issue);
        }
    }
    out
}

/// Field errors inside an error from the store (`InvalidFields`, `InvalidValue`, or
/// `Validation` issues of `host`).
pub fn field_errors_of(e: &wol_core::Error, host: Option<HostId>) -> Vec<FieldError> {
    let mut v = e.field_errors();
    if let wol_core::Error::Validation(issues) = e {
        for i in issues {
            if let wol_core::model::ConfigIssue::Host {
                id, field, issue, ..
            } = i
                && (host.is_none() || host == Some(*id))
            {
                v.push(FieldError::new(*field, *issue));
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------------------------
// UI glue (App methods for the editor overlay)

/// Reads the editor's fields.
pub fn read_fields(ui: &AppWindow) -> EditorFields {
    let e = ui.global::<EditorState>();
    EditorFields {
        name: e.get_name().into(),
        mac: e.get_mac().into(),
        address: e.get_address().into(),
        group: e.get_group().into(),
        notes: e.get_notes().into(),
        broadcast: e.get_broadcast(),
        targets: e.get_targets().into(),
        port: e.get_port().into(),
        interface_index: e.get_interface_index(),
        secureon: e.get_secureon().into(),
        probe_index: e.get_probe_index(),
        tcp_ports: e.get_tcp_ports().into(),
    }
}

/// Writes every editor field.
pub fn push_fields(ui: &AppWindow, f: &EditorFields) {
    let e = ui.global::<EditorState>();
    e.set_name(f.name.as_str().into());
    e.set_mac(f.mac.as_str().into());
    e.set_address(f.address.as_str().into());
    e.set_group(f.group.as_str().into());
    e.set_notes(f.notes.as_str().into());
    e.set_broadcast(f.broadcast);
    e.set_targets(f.targets.as_str().into());
    e.set_port(f.port.as_str().into());
    e.set_interface_index(f.interface_index);
    e.set_secureon(f.secureon.as_str().into());
    e.set_probe_index(f.probe_index);
    e.set_tcp_ports(f.tcp_ports.as_str().into());
}

/// Writes every `*-issue` property.
pub fn push_issues(ui: &AppWindow, i: &Issues) {
    let e = ui.global::<EditorState>();
    e.set_name_issue(i.name);
    e.set_mac_issue(i.mac);
    e.set_address_issue(i.address);
    e.set_targets_issue(i.targets);
    e.set_port_issue(i.port);
    e.set_secureon_issue(i.secureon);
    e.set_tcp_ports_issue(i.tcp_ports);
    if i.advanced() {
        e.set_advanced_open(true);
    }
}

/// The host has values in the "Advanced" section (open it).
pub fn has_advanced(d: &HostDraft) -> bool {
    !d.targets.trim().is_empty()
        || !d.port.trim().is_empty()
        || !d.secureon.trim().is_empty()
        || !d.broadcast
        || !d.interfaces.is_empty()
        || d.probe.is_some()
        || !d.tcp_ports.trim().is_empty()
}

impl App {
    fn host_clone(&self, id: &str) -> Option<Host> {
        let hid = HostId::parse_str(id.trim()).ok()?;
        self.cfg.borrow().get(hid).cloned()
    }

    /// Toolbar / File > New host.
    pub fn add_host(&self) {
        if self.idle() {
            self.open_editor(EditorMode::Add, None);
        }
    }

    /// Double click / Enter / menu.
    pub fn edit_host(&self, id: &str) {
        if !self.idle() {
            return;
        }
        if let Some(h) = self.host_clone(id) {
            self.open_editor(EditorMode::Edit, Some(h));
        }
    }

    /// Host > Duplicate: an editor pre-filled with "Copy of …"; nothing is saved until Save.
    pub fn duplicate_host(&self, id: &str) {
        if !self.idle() {
            return;
        }
        if let Some(h) = self.host_clone(id) {
            self.open_editor(EditorMode::Duplicate, Some(h));
        }
    }

    fn open_editor(&self, mode: EditorMode, host: Option<Host>) {
        let token = self.next_token();
        let lang = self.lang.get();
        let (draft, base, template, pins, copy_name, new_id) = match (mode, host) {
            (EditorMode::Edit, Some(h)) => {
                let base = EditBase::of(&h);
                (
                    base.draft.clone(),
                    Some(base),
                    None,
                    h.interfaces.clone(),
                    None,
                    h.id,
                )
            }
            (EditorMode::Duplicate, Some(h)) => {
                let mut d = HostDraft::from_host(&h);
                let name = self.cfg.borrow().unique_name(
                    &Msg::CopyOf {
                        name: h.name.clone(),
                    }
                    .text(lang),
                );
                d.name = name.clone();
                let pins = h.interfaces.clone();
                (d, None, Some(h), pins, Some(name), HostId::new_v4())
            }
            _ => (
                HostDraft::default(),
                None,
                None,
                Vec::new(),
                None,
                HostId::new_v4(),
            ),
        };
        let (options, choice) = {
            let ifaces = self.ifaces.borrow();
            let options = interface_options(&ifaces);
            let choice = interface_choice(&pins, &options, &ifaces);
            (options, choice)
        };
        let fields = fields_from_draft(&draft, choice);
        self.set_interface_model(&options);
        let e = self.ui.global::<EditorState>();
        e.set_mode(mode);
        e.set_host_id(
            base.as_ref()
                .map(|b| b.id.to_string())
                .unwrap_or_default()
                .into(),
        );
        push_fields(&self.ui, &fields);
        e.set_interface_pinned_count(choice.pinned_count);
        e.set_interface_missing(choice.missing);
        e.set_advanced_open(has_advanced(&draft));
        push_issues(&self.ui, &Issues::default());
        e.set_arp_status(ArpStatus::Idle);
        e.set_saving(false);
        *self.editor.borrow_mut() = Some(EditorSession {
            mode,
            base,
            template,
            pins,
            initial_index: choice.index,
            options,
            copy_name,
            new_id,
            token,
        });
        self.ui
            .global::<AppState>()
            .set_overlay(OverlayKind::Editor);
        // Adapters may have changed since the last look.
        self.refresh_interfaces();
    }

    fn set_interface_model(&self, options: &[IfaceOption]) {
        let v: Vec<InterfaceOption> = options
            .iter()
            .map(|o| InterfaceOption {
                id: o.id.as_str().into(),
                label: o.label.as_str().into(),
                detail: o.detail.as_str().into(),
            })
            .collect();
        if self.ifaces_model.iter().ne(v.iter().cloned()) {
            self.ifaces_model.set_vec(v);
        }
    }

    /// A fresh adapter list arrived: update the open editor while its picker is untouched.
    pub(crate) fn editor_interfaces_updated(&self) {
        let e = self.ui.global::<EditorState>();
        let update = {
            let mut ed = self.editor.borrow_mut();
            let Some(s) = ed.as_mut() else {
                return;
            };
            if e.get_interface_index() != s.initial_index {
                return;
            }
            let ifaces = self.ifaces.borrow();
            let options = interface_options(&ifaces);
            if options == s.options {
                return;
            }
            let choice = interface_choice(&s.pins, &options, &ifaces);
            s.options = options.clone();
            s.initial_index = choice.index;
            (options, choice)
        };
        let (options, choice) = update;
        self.set_interface_model(&options);
        e.set_interface_index(choice.index);
        e.set_interface_pinned_count(choice.pinned_count);
        e.set_interface_missing(choice.missing);
    }

    /// The user closed the editor (pending ARP results are dropped).
    pub(crate) fn discard_editor(&self) {
        self.editor.borrow_mut().take();
        self.ui
            .global::<EditorState>()
            .set_arp_status(ArpStatus::Idle);
    }

    /// Editor > Save.
    pub fn save_editor(&self) {
        let e = self.ui.global::<EditorState>();
        if e.get_saving() {
            return;
        }
        let Some(s) = self.editor.borrow().clone() else {
            return;
        };
        let fields = read_fields(&self.ui);
        let draft = draft_from_fields(&fields, &s);
        let kind = match s.mode {
            EditorMode::Edit => match &s.base {
                Some(b) if self.cfg.borrow().get(b.id).is_some() => SaveKind::Edit(b.clone()),
                Some(b) => {
                    // Deleted by another program meanwhile.
                    e.set_saving(true);
                    self.confirm(ConfirmRequest {
                        kind: ConfirmKind::SaveAsNew,
                        host_id: b.id.to_string().into(),
                        subject: fields.name.trim().into(),
                        ..ConfirmRequest::default()
                    });
                    return;
                }
                None => SaveKind::New { id: s.new_id },
            },
            EditorMode::Duplicate => match &s.template {
                Some(t) => SaveKind::Copy {
                    template: Box::new(t.clone()),
                    id: s.new_id,
                },
                None => SaveKind::New { id: s.new_id },
            },
            EditorMode::Add => SaveKind::New { id: s.new_id },
        };
        let id = match &kind {
            SaveKind::Edit(b) => b.id,
            SaveKind::New { id } | SaveKind::Copy { id, .. } => *id,
        };
        self.submit_save(s.token, s.mode, id, Op::SaveHost { draft, kind });
    }

    fn submit_save(&self, token: u64, mode: EditorMode, id: HostId, op: Op) {
        let e = self.ui.global::<EditorState>();
        // Same rules as on the store thread, against what this window knows now.
        let mut local = self.cfg.borrow().clone();
        if let Err(err) = apply_op(&mut local, &op) {
            let issues = issues_from(&field_errors_of(&err, Some(id)));
            if issues.is_empty() {
                self.toast(ToastKind::Error, GuiText::SaveFailed, Text::error(&err));
            } else {
                push_issues(&self.ui, &issues);
            }
            e.set_saving(false);
            return;
        }
        let name = local.get(id).map(|h| h.name.clone()).unwrap_or_default();
        e.set_saving(true);
        // Optimistic: the list shows the change at once; the store result reconciles it.
        self.reconcile_from(local);
        self.submit(
            op,
            Pending::Save {
                token,
                mode,
                name,
                id,
            },
        );
    }

    /// "Save as new" after the edited host was deleted elsewhere.
    pub(crate) fn save_as_new(&self, req: &ConfirmRequest) {
        let Some(s) = self.editor.borrow().clone() else {
            return;
        };
        self.ui.global::<EditorState>().set_saving(false);
        let id = HostId::parse_str(req.host_id.trim()).unwrap_or(s.new_id);
        let draft = draft_from_fields(&read_fields(&self.ui), &s);
        self.submit_save(
            s.token,
            EditorMode::Add,
            id,
            Op::SaveHost {
                draft,
                kind: SaveKind::New { id },
            },
        );
    }

    /// The store saved the host: close the editor it came from.
    pub(crate) fn close_editor_after_save(&self, token: u64) {
        let same = self
            .editor
            .borrow()
            .as_ref()
            .is_some_and(|s| s.token == token);
        if !same {
            return;
        }
        self.editor.borrow_mut().take();
        self.ui.global::<EditorState>().set_saving(false);
        let st = self.ui.global::<AppState>();
        if st.get_overlay() == OverlayKind::Editor {
            st.set_overlay(OverlayKind::None);
        }
    }

    /// The store refused the save.
    pub(crate) fn editor_save_failed(&self, token: u64, id: HostId, err: &wol_core::Error) {
        let open = self
            .editor
            .borrow()
            .as_ref()
            .is_some_and(|s| s.token == token)
            && self.ui.global::<AppState>().get_overlay() == OverlayKind::Editor;
        if !open {
            self.toast(ToastKind::Error, GuiText::SaveFailed, Text::error(err));
            return;
        }
        let e = self.ui.global::<EditorState>();
        e.set_saving(false);
        if let wol_core::Error::HostIdNotFound(gone) = err {
            e.set_saving(true);
            let name = e.get_name();
            self.confirm(ConfirmRequest {
                kind: ConfirmKind::SaveAsNew,
                host_id: gone.to_string().into(),
                subject: name.trim().into(),
                ..ConfirmRequest::default()
            });
            return;
        }
        let issues = issues_from(&field_errors_of(err, Some(id)));
        if issues.is_empty() {
            self.toast(ToastKind::Error, GuiText::SaveFailed, Text::error(err));
        } else {
            push_issues(&self.ui, &issues);
        }
    }

    /// "Get from IP": ARP on the io pool.
    pub fn lookup_mac(&self, address: &str) {
        let Some(token) = self.editor.borrow().as_ref().map(|s| s.token) else {
            return;
        };
        let e = self.ui.global::<EditorState>();
        let Ok(ip) = wol_core::addr::parse_ipv4(address) else {
            e.set_arp_status(ArpStatus::Failed);
            return;
        };
        e.set_arp_status(ArpStatus::Busy);
        self.io_pool.spawn(move || {
            let r = wol_core::arp::mac_from_ip(ip);
            crate::workers::post_ui(move |app| app.on_arp_done(token, r));
        });
    }

    fn on_arp_done(&self, token: u64, r: wol_core::Result<wol_core::MacAddr>) {
        let current = self.editor.borrow().as_ref().map(|s| s.token);
        if current != Some(token) {
            return;
        }
        let e = self.ui.global::<EditorState>();
        match r {
            Ok(mac) => {
                e.set_mac(mac.to_string().into());
                e.set_mac_issue(FieldIssue::None);
                e.set_arp_status(ArpStatus::Found);
            }
            Err(wol_core::Error::NotOnLocalSubnet { .. }) => e.set_arp_status(ArpStatus::NotLocal),
            Err(wol_core::Error::ArpNoReply { .. }) => e.set_arp_status(ArpStatus::NotFound),
            Err(err) => {
                log::info!("ARP failed: {err}");
                e.set_arp_status(ArpStatus::Failed);
            }
        }
    }

    /// Language switch: a duplicate's untouched "Copy of …" name follows the language.
    pub(crate) fn retranslate_editor(&self, _old: Lang) {
        let lang = self.lang.get();
        let e = self.ui.global::<EditorState>();
        let new_name = {
            let mut ed = self.editor.borrow_mut();
            let Some(s) = ed.as_mut() else {
                return;
            };
            let (Some(old_name), Some(t)) = (s.copy_name.clone(), s.template.as_ref()) else {
                return;
            };
            if e.get_name() != old_name.as_str() {
                return;
            }
            let name = self.cfg.borrow().unique_name(
                &Msg::CopyOf {
                    name: t.name.clone(),
                }
                .text(lang),
            );
            s.copy_name = Some(name.clone());
            name
        };
        e.set_name(SharedString::from(new_name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::{Op, SaveKind, apply_op};
    use wol_core::netif::Ipv4Subnet;
    use wol_core::{HostAddr, MacAddr, SecureOn, Target};

    fn nic(index: u32, guid: &str, name: &str, ip: &str) -> NetInterface {
        NetInterface::new(
            index,
            guid,
            name,
            format!("{name} adapter"),
            6,
            true,
            None,
            vec![ip.parse::<Ipv4Subnet>().unwrap()],
        )
    }

    fn full_host() -> Host {
        let mut h = Host::new("NAS", MacAddr::parse("00:11:22:33:44:55").unwrap());
        h.address = Some(HostAddr::parse("nas.lan").unwrap());
        h.group = Some("Home".into());
        h.notes = Some("line1\nline2".into());
        h.port = Some(7);
        h.secureon = Some(SecureOn::parse("01:02:03:04:05:06").unwrap());
        h.targets = vec![
            Target::parse("10.0.20.255").unwrap(),
            Target::parse("relay.lan:9").unwrap(),
        ];
        h.broadcast = false;
        h.interfaces = vec!["Ethernet 2".into()];
        h.probe = Some(ProbeMethod::Tcp);
        h.tcp_ports = vec![3389, 22];
        h.extra
            .insert("future_key".into(), toml::Value::String("kept".into()));
        h
    }

    fn session_for(h: &Host, ifaces: &[NetInterface]) -> (EditorSession, EditorFields) {
        let base = EditBase::of(h);
        let options = interface_options(ifaces);
        let choice = interface_choice(&h.interfaces, &options, ifaces);
        let fields = fields_from_draft(&base.draft, choice);
        let s = EditorSession {
            mode: EditorMode::Edit,
            pins: h.interfaces.clone(),
            initial_index: choice.index,
            options,
            base: Some(base),
            template: None,
            copy_name: None,
            new_id: HostId::new_v4(),
            token: 1,
        };
        (s, fields)
    }

    #[test]
    fn editor_round_trip_keeps_every_field_and_extra() {
        let h = full_host();
        let mut cfg = Config::default();
        cfg.hosts.push(h.clone());
        cfg.extra.insert("top".into(), toml::Value::Boolean(true));
        let ifaces = vec![
            nic(3, "{AAAA}", "Ethernet", "192.168.1.20/24"),
            nic(4, "{BBBB}", "Ethernet 2", "10.0.0.2/24"),
        ];
        let (s, f) = session_for(&h, &ifaces);
        // Pinned by friendly name; the adapter is present -> its index.
        assert_eq!(f.interface_index, 1);
        let draft = draft_from_fields(&f, &s);
        assert_eq!(
            draft.interfaces,
            vec!["Ethernet 2".to_string()],
            "representation kept"
        );
        let op = Op::SaveHost {
            draft,
            kind: SaveKind::Edit(s.base.clone().unwrap()),
        };
        let before = cfg.clone();
        apply_op(&mut cfg, &op).unwrap();
        assert_eq!(cfg, before, "an unchanged editor must not change anything");

        // Rename only: every other field (and extra) survives.
        let mut f2 = f.clone();
        f2.name = "NAS-2".into();
        let op = Op::SaveHost {
            draft: draft_from_fields(&f2, &s),
            kind: SaveKind::Edit(s.base.clone().unwrap()),
        };
        apply_op(&mut cfg, &op).unwrap();
        let saved = cfg.get(h.id).unwrap();
        let mut expected = h.clone();
        expected.name = "NAS-2".into();
        assert_eq!(*saved, expected);
        assert_eq!(cfg.extra.get("top"), Some(&toml::Value::Boolean(true)));
    }

    #[test]
    fn duplicate_and_new_hosts() {
        let h = full_host();
        let mut cfg = Config::default();
        cfg.hosts.push(h.clone());
        let base = EditBase::of(&h);
        let mut draft = base.draft.clone();
        draft.name = "NAS copy".into();
        let id = HostId::new_v4();
        apply_op(
            &mut cfg,
            &Op::SaveHost {
                draft,
                kind: SaveKind::Copy {
                    template: Box::new(h.clone()),
                    id,
                },
            },
        )
        .unwrap();
        let copy = cfg.get(id).expect("copy saved with the chosen id");
        assert_eq!(copy.extra, h.extra);
        assert_eq!(copy.targets, h.targets);
        assert_eq!(copy.name, "NAS copy");

        let d = HostDraft {
            name: "New".into(),
            mac: "aabbccddeeff".into(),
            ..HostDraft::default()
        };
        let nid = HostId::new_v4();
        apply_op(
            &mut cfg,
            &Op::SaveHost {
                draft: d,
                kind: SaveKind::New { id: nid },
            },
        )
        .unwrap();
        assert_eq!(cfg.get(nid).unwrap().mac.to_string(), "AA:BB:CC:DD:EE:FF");

        // Duplicate name -> field error.
        let d = HostDraft {
            name: "new".into(),
            mac: "aabbccddee00".into(),
            ..HostDraft::default()
        };
        let e = apply_op(
            &mut cfg,
            &Op::SaveHost {
                draft: d,
                kind: SaveKind::New {
                    id: HostId::new_v4(),
                },
            },
        )
        .unwrap_err();
        let iss = issues_from(&field_errors_of(&e, None));
        assert_eq!(iss.name, FieldIssue::DuplicateName);
        assert!(!iss.advanced());
    }

    #[test]
    fn interface_rule() {
        let ifaces = vec![
            nic(3, "{AAAA}", "Ethernet", "192.168.1.20/24"),
            nic(4, "{BBBB}", "Wi-Fi", "192.168.2.20/24"),
        ];
        let opts = interface_options(&ifaces);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].detail, "192.168.1.20/24");
        let c = interface_choice(&[], &opts, &ifaces);
        assert_eq!((c.index, c.pinned_count, c.missing), (IFACE_AUTO, 0, false));
        let c = interface_choice(&["{bbbb}".into()], &opts, &ifaces);
        assert_eq!((c.index, c.pinned_count, c.missing), (1, 1, false));
        // Single pin, adapter unplugged -> keep (-2).
        let c = interface_choice(&["{CCCC}".into()], &opts, &ifaces);
        assert_eq!((c.index, c.pinned_count, c.missing), (IFACE_KEEP, 1, true));
        // Several pins -> keep.
        let c = interface_choice(&["{AAAA}".into(), "{BBBB}".into()], &opts, &ifaces);
        assert_eq!((c.index, c.pinned_count, c.missing), (IFACE_KEEP, 2, false));
    }

    #[test]
    fn keep_rule_preserves_pins_and_changes_apply() {
        let ifaces = vec![nic(3, "{AAAA}", "Ethernet", "192.168.1.20/24")];
        let mut h = full_host();
        h.interfaces = vec!["{GONE}".into(), "{AAAA}".into()];
        let (s, mut f) = session_for(&h, &ifaces);
        assert_eq!(f.interface_index, IFACE_KEEP);
        assert_eq!(pins_for(&f, &s), h.interfaces);
        f.interface_index = 0;
        assert_eq!(pins_for(&f, &s), vec!["{AAAA}".to_string()]);
        f.interface_index = IFACE_AUTO;
        assert!(pins_for(&f, &s).is_empty());
    }

    #[test]
    fn probe_index_mapping() {
        for p in [
            None,
            Some(ProbeMethod::Auto),
            Some(ProbeMethod::Icmp),
            Some(ProbeMethod::Tcp),
            Some(ProbeMethod::None),
        ] {
            assert_eq!(probe_from_index(probe_index(p)), p);
        }
    }

    #[test]
    fn validators() {
        let mut cfg = Config::default();
        let h = Host::new("PC", MacAddr::parse("00:11:22:33:44:55").unwrap());
        let id = h.id.to_string();
        cfg.hosts.push(h);
        assert_eq!(check_name(&cfg, "", ""), FieldIssue::Required);
        assert_eq!(check_name(&cfg, "ｐｃ", ""), FieldIssue::DuplicateName);
        assert_eq!(check_name(&cfg, "pc", &id), FieldIssue::None);
        assert_eq!(
            check_name(&cfg, "00:11:22:33:44:66", ""),
            FieldIssue::NameLooksLikeMac
        );
        assert_eq!(
            check_name(&cfg, &"x".repeat(65), ""),
            FieldIssue::NameTooLong
        );
        assert_eq!(check_name(&cfg, "書斎の PC", ""), FieldIssue::None);
        assert_eq!(check_mac(""), FieldIssue::Required);
        assert_eq!(
            check_mac("ＡＡ－ＢＢ－ＣＣ－ＤＤ－ＥＥ－ＦＦ"),
            FieldIssue::None
        );
        assert_eq!(check_mac("zz"), FieldIssue::InvalidMac);
        assert_eq!(check_mac("11-22-33-44-55-66"), FieldIssue::MacNotUnicast);
        assert_eq!(check_mac("あ"), FieldIssue::ImeKana);
        assert_eq!(check_address(""), FieldIssue::None);
        assert_eq!(check_address("１９２．１６８．１．１"), FieldIssue::None);
        assert_eq!(check_address("999.1.1.1"), FieldIssue::InvalidAddress);
        assert_eq!(check_port(""), FieldIssue::None);
        assert_eq!(check_port("0"), FieldIssue::InvalidPort);
        assert_eq!(port_value("７"), 7);
        assert_eq!(port_value("x"), 0);
        assert_eq!(check_targets("a.lan:9\n10.0.0.255"), FieldIssue::None);
        assert_eq!(check_targets("a:b:c"), FieldIssue::InvalidTarget);
        assert_eq!(check_secureon("01:02:03:04:05:06"), FieldIssue::None);
        assert_eq!(check_secureon("01"), FieldIssue::InvalidSecureOn);
        assert_eq!(check_tcp_ports("22, ８０"), FieldIssue::None);
        assert_eq!(check_tcp_ports("22,x"), FieldIssue::InvalidPortList);
        assert_eq!(
            check_tcp_ports("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17"),
            FieldIssue::TooManyPorts
        );
        assert!(is_ipv4("１０．０．０．１"));
        assert!(!is_ipv4("nas.lan"));
    }

    #[test]
    fn issues_mapping_opens_advanced() {
        let errs = vec![
            FieldError::new(Field::Mac, wol_core::FieldIssue::InvalidMac),
            FieldError::new(Field::Port, wol_core::FieldIssue::InvalidPort),
            FieldError::new(Field::Mac, wol_core::FieldIssue::Required),
        ];
        let i = issues_from(&errs);
        assert_eq!(i.mac, FieldIssue::InvalidMac);
        assert_eq!(i.port, FieldIssue::InvalidPort);
        assert!(i.advanced());
        assert!(!i.is_empty());
        assert!(issues_from(&[]).is_empty());
    }
}
