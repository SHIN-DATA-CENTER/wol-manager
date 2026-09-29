//! Host editor: `EditorState` ⇄ `HostDraft` (with `EditBase` for the three-way merge),
//! the adapter pinning rule (−1 / −2 / index), the `Validator` pure callbacks and the
//! mapping of `wol_core` field errors to the `*-issue` properties (contract §3, §4).
//!
//! v0.2.0 "Remote management" section (contract §10.4 / §10.5): the remote fields are part of
//! the draft (merged like the others); secrets never are — the editor turns the password boxes
//! into [`SecretOverrides`] ("typed → write", "delete flag → delete", "empty → unchanged"),
//! which are written to Credential Manager on a worker **after** the host was saved, and used
//! as they are for "Test connection" / "Get from IP" before saving. No stored secret is ever
//! sent back to Slint; the boxes are cleared whenever the editor opens or closes.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use wol_core::i18n::{Lang, Msg};
use wol_core::macfind::{self, MacFound, MacQuery, SystemMacEnv};
use wol_core::model::{
    Field, FieldError, ProbeMethod, RemoteDraft, SudoMode as CoreSudo, check_field,
    check_remote_field,
};
use wol_core::netif::NetInterface;
use wol_core::remote::{
    BootInfo, ConnInfo, KeyFileIssue, MacCandidate, NicKind, RemoteClient, SecretOverride,
    SecretOverrides,
};
use wol_core::secret::{self, SecretBinding, SecretKind, SecretState, SecretStatus, SecretStore};
use wol_core::{Config, EditBase, Error, Host, HostAddr, HostDraft, HostId, addr, normalize};

use crate::app::{App, Pending};
use crate::persist::{Op, OpOutput, SaveKind, StoreEvent, apply_op};
use crate::remote::{KeyStep, Origin, Retry, TopDialog, key_step};
use crate::texts::{GuiText, Text};
use crate::workers::{SECRET_WAIT, SerialQueue, post_ui};
use crate::{
    AppState, AppWindow, ArpStatus, ConfirmKind, ConfirmRequest, EditorMode, EditorState,
    FieldIssue, HostKeyPrompt, InterfaceOption, MacCandidateRow, MacKind, OverlayKind, RemoteKind,
    SudoMode, TestStatus, ToastKind,
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
        C::InvalidUser => FieldIssue::InvalidUser,
        C::InvalidCommand => FieldIssue::InvalidCommand,
        C::InvalidHostKey => FieldIssue::InvalidHostKey,
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
/// `Validator.check-remote-user`: the user-name rules of `kind` (none for kind None).
pub fn check_remote_user(text: &str, kind: RemoteKind) -> FieldIssue {
    match kind_to_core(kind) {
        None => FieldIssue::None,
        Some(k) => match check_remote_field(Field::RemoteUser, k, text) {
            Ok(()) => FieldIssue::None,
            Err(e) => issue(e),
        },
    }
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

/// Slint `RemoteKind` → wol-core (`None` = not managed).
pub fn kind_to_core(k: RemoteKind) -> Option<wol_core::RemoteKind> {
    match k {
        RemoteKind::None => None,
        RemoteKind::Windows => Some(wol_core::RemoteKind::Windows),
        RemoteKind::Ssh => Some(wol_core::RemoteKind::Ssh),
    }
}

/// wol-core → Slint `RemoteKind`.
pub fn kind_from_core(k: Option<wol_core::RemoteKind>) -> RemoteKind {
    match k {
        None => RemoteKind::None,
        Some(wol_core::RemoteKind::Windows) => RemoteKind::Windows,
        Some(wol_core::RemoteKind::Ssh) => RemoteKind::Ssh,
    }
}

/// Slint `SudoMode` → config (1:1; `separate` is a config value with its own secret).
pub fn sudo_to_core(m: SudoMode) -> CoreSudo {
    match m {
        SudoMode::Auto => CoreSudo::Auto,
        SudoMode::Root => CoreSudo::Root,
        SudoMode::Nopasswd => CoreSudo::NoPasswd,
        SudoMode::Password => CoreSudo::Password,
        SudoMode::Separate => CoreSudo::Separate,
    }
}

/// Config → Slint `SudoMode`.
pub fn sudo_from_core(m: CoreSudo) -> SudoMode {
    match m {
        CoreSudo::Auto => SudoMode::Auto,
        CoreSudo::Root => SudoMode::Root,
        CoreSudo::NoPasswd => SudoMode::Nopasswd,
        CoreSudo::Password => SudoMode::Password,
        CoreSudo::Separate => SudoMode::Separate,
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

/// The editor's remote-management fields (mirror of `EditorState`, secrets excluded).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RemoteFields {
    /// None / Windows / SSH.
    pub kind: RemoteKind,
    /// Management address ("" = the host's address).
    pub address: String,
    /// User name.
    pub user: String,
    /// SSH port.
    pub port: String,
    /// SSH key file.
    pub key_file: String,
    /// SSH sudo method.
    pub sudo: SudoMode,
    /// "Forget" the pinned host key on save.
    pub host_key_forget: bool,
    /// "Use the defaults": remove the SSH power command overrides on save.
    pub commands_reset: bool,
}

/// The editor's values (mirror of `EditorState`).
#[derive(Debug, Clone, PartialEq, Default)]
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
    /// Remote management section.
    pub remote: RemoteFields,
}

/// Rust texts of the "Test connection" result (re-rendered after a language switch).
#[derive(Debug, Clone)]
pub enum TestShown {
    /// Connected.
    Ok {
        /// Boot of the host.
        boot: BootInfo,
        /// Remark ("not an administrator").
        note: Text,
    },
    /// Failed.
    Failed(Text),
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
    /// Remote section as the editor opened it (the merge base of `[hosts.remote]`).
    pub remote_base: RemoteDraft,
    /// The host as the editor opened it (edit mode): its passwords follow only an endpoint
    /// change made in this editor (review S3).
    pub opened: Option<Host>,
    /// Pinned SSH host key of the draft (a key trusted during "Test connection" replaces it).
    pub host_key_line: String,
    /// Number of the latest "Test connection" (older results are dropped).
    pub test_seq: u64,
    /// Number of the latest "Get from IP".
    pub lookup_seq: u64,
    /// Test result texts on screen.
    pub test_shown: Option<TestShown>,
    /// `arp-message` on screen.
    pub arp_text: Text,
    /// The candidates behind the MAC picker.
    pub mac_candidates: Vec<MacCandidate>,
}

/// Remote fields for a draft.
pub fn remote_fields_from(d: &RemoteDraft) -> RemoteFields {
    RemoteFields {
        kind: kind_from_core(d.kind),
        address: d.address.clone(),
        user: d.user.clone(),
        port: d.port.clone(),
        key_file: d.key_file.clone(),
        sudo: sudo_from_core(d.sudo),
        host_key_forget: false,
        commands_reset: false,
    }
}

/// The remote draft of the editor's fields. Kind None keeps the base's text (only the kind
/// decides: an untouched section of an unmanaged host stays untouched, a managed one loses
/// its table). The host key is the draft's pinned line ("" when forgotten); the command
/// overrides cannot be edited in the GUI (shown read-only): they stay as they were, or are
/// removed with "Use the defaults" (cross review X1).
pub fn remote_draft(rf: &RemoteFields, host_key_line: &str, base: &RemoteDraft) -> RemoteDraft {
    let command = |c: &String| {
        if rf.commands_reset {
            String::new()
        } else {
            c.clone()
        }
    };
    match kind_to_core(rf.kind) {
        None => RemoteDraft {
            kind: None,
            ..base.clone()
        },
        Some(kind) => RemoteDraft {
            kind: Some(kind),
            user: rf.user.clone(),
            address: rf.address.clone(),
            port: rf.port.clone(),
            key_file: rf.key_file.clone(),
            host_key: if rf.host_key_forget {
                String::new()
            } else {
                host_key_line.to_owned()
            },
            sudo: sudo_to_core(rf.sudo),
            reboot_command: command(&base.reboot_command),
            shutdown_command: command(&base.shutdown_command),
        },
    }
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
        remote: remote_fields_from(&d.remote),
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
        remote: remote_draft(&f.remote, &s.host_key_line, &s.remote_base),
    }
}

/// The editor's key file when it is on a network (UNC) path, which is never used (pure: no
/// file access on the UI thread).
pub fn network_key_file(text: &str) -> Option<String> {
    let cleaned = wol_core::model::clean_key_file(text);
    wol_core::remote::is_network_path(std::path::Path::new(&cleaned)).then_some(cleaned)
}

/// `host-key-type` / `host-key-fingerprint` for a pinned line ("" = none). A line that does
/// not parse (hand-edited config) is shown as it is, so that it can be forgotten.
pub fn host_key_display(line: &str) -> (String, String) {
    let t = line.trim();
    if t.is_empty() {
        return (String::new(), String::new());
    }
    match wol_core::remote::parse_host_key(t) {
        Ok(k) => (k.algorithm, k.fingerprint),
        Err(_) => (
            t.split_whitespace().next().unwrap_or("").to_owned(),
            t.to_owned(),
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Secrets

/// A password box of the editor: text as typed and its "delete saved" flag (the UI never
/// lets both be set).
#[derive(Debug, Clone, Copy)]
pub struct SecretInput<'a> {
    /// Typed text ("" = keep).
    pub typed: &'a str,
    /// "Delete saved …" was clicked.
    pub delete: bool,
}

fn typed_or_flag(i: SecretInput<'_>) -> SecretOverride {
    if i.delete {
        SecretOverride::Absent
    } else if !i.typed.is_empty() {
        SecretOverride::Value(i.typed.to_owned().into())
    } else {
        SecretOverride::Stored
    }
}

fn flag_only(i: SecretInput<'_>) -> SecretOverride {
    if i.delete {
        SecretOverride::Absent
    } else {
        SecretOverride::Stored
    }
}

/// What the password boxes mean (contract §10.4): typed → write (`Value`), delete flag →
/// delete (`Absent`), empty → unchanged (`Stored`). Boxes the kind does not show only count
/// with their delete flag. The separate sudo password: written / deleted with sudo method
/// `separate`; kept for `auto` (it uses a stored one); deleted for the methods that never use
/// it (root, NOPASSWD, login password). Kind None: everything goes (the table is removed).
/// The same values serve as overrides for "Test connection" / "Get from IP".
pub fn secret_intents(
    kind: RemoteKind,
    sudo: SudoMode,
    login: SecretInput<'_>,
    passphrase: SecretInput<'_>,
    sudo_password: SecretInput<'_>,
) -> SecretOverrides {
    match kind {
        RemoteKind::None => SecretOverrides {
            login: SecretOverride::Absent,
            key_passphrase: SecretOverride::Absent,
            sudo: SecretOverride::Absent,
        },
        RemoteKind::Windows => SecretOverrides {
            login: typed_or_flag(login),
            key_passphrase: flag_only(passphrase),
            sudo: flag_only(sudo_password),
        },
        RemoteKind::Ssh => SecretOverrides {
            login: typed_or_flag(login),
            key_passphrase: typed_or_flag(passphrase),
            sudo: match sudo {
                SudoMode::Separate => typed_or_flag(sudo_password),
                SudoMode::Auto => flag_only(sudo_password),
                SudoMode::Root | SudoMode::Nopasswd | SudoMode::Password => SecretOverride::Absent,
            },
        },
    }
}

/// Credential Manager changes of a save, applied after the config was written.
#[derive(Debug, Clone, Default)]
pub struct SavePlan {
    /// Per-secret changes (`None`: the section is off, nothing to write).
    pub intents: Option<SecretOverrides>,
    /// The user switched a managed host to "None": delete its secrets when the saved host
    /// ends up without remote management (the editor says so).
    pub forget_if_unmanaged: bool,
    /// The host as the editor opened it (edit mode): its usable passwords follow a management
    /// address / SSH port the user changed in this editor, for the same account
    /// (`SecretStore::rebind`, only after an explicit user edit).
    pub before: Option<Host>,
    /// The management endpoint the editor showed when the user saved (kind, management
    /// address, SSH port of its fields). The saved host is merged with config.toml as it is
    /// then, so an import or another program may have re-pointed it meanwhile: passwords
    /// follow, and the current Windows sign-in is confirmed, only when the host was saved
    /// with this endpoint (review S2 / S3).
    pub shown: Option<SecretBinding>,
}

impl SavePlan {
    /// The host was saved with the endpoint the editor showed.
    fn saved_as_shown(&self, host: &Host) -> bool {
        self.shown.is_some() && SecretBinding::for_host(host) == self.shown
    }

    /// The user changed the endpoint in this editor (the one shown differs from the host as
    /// the editor opened it).
    fn endpoint_edited(&self) -> bool {
        self.before
            .as_ref()
            .is_some_and(|b| SecretBinding::for_host(b) != self.shown)
    }
}

fn intent(o: &SecretOverrides, kind: SecretKind) -> &SecretOverride {
    match kind {
        SecretKind::Login => &o.login,
        SecretKind::KeyPassphrase => &o.key_passphrase,
        SecretKind::Sudo => &o.sudo,
    }
}

impl SavePlan {
    fn is_noop(&self, managed_after: bool) -> bool {
        if !managed_after {
            return !self.forget_if_unmanaged;
        }
        let writes = self.intents.as_ref().is_some_and(|o| {
            SecretKind::ALL
                .iter()
                .any(|k| !matches!(intent(o, *k), SecretOverride::Stored))
        });
        let was_managed = self.before.as_ref().is_some_and(|h| h.remote.is_some());
        !writes && !was_managed
    }
}

/// What applying a [`SavePlan`] found.
#[derive(Debug, Default)]
pub struct SecretOutcome {
    /// Credential Manager failures.
    pub errors: Vec<Error>,
    /// Passwords that stay saved but belong to another connection (kind / account changed):
    /// the user has to enter them again (kind, what they were saved for).
    pub stale: Vec<(SecretKind, String)>,
}

/// Stale passwords worth telling the user about: the login password, and the separate sudo
/// password while sudo method `separate` uses it (`auto` falls back to the login password).
fn stale_secrets(
    store: &SecretStore,
    host: &Host,
    skip: impl Fn(SecretKind) -> bool,
) -> Vec<(SecretKind, String)> {
    let Some(r) = host.remote.as_ref() else {
        return Vec::new();
    };
    let mut v = Vec::new();
    for kind in [SecretKind::Login, SecretKind::Sudo] {
        if skip(kind) || (kind == SecretKind::Sudo && r.sudo != CoreSudo::Separate) {
            continue;
        }
        match store.state(host, kind) {
            Ok(SecretState::Stale { stored_for }) => v.push((kind, stored_for)),
            Ok(_) => {}
            Err(e) => log::warn!("{}: {kind}: {e}", host.name),
        }
    }
    v
}

/// Applies a [`SavePlan`] to the host as it was saved. Blocking (Credential Manager): worker
/// only. Typed passwords are stored bound to the saved host's kind, management address, SSH
/// port and account (`set_for_host`); a user edit of the address / port moves the usable
/// ones first (`rebind`); a host switched to "None" loses all of them.
pub fn apply_save_plan(store: &SecretStore, host: Option<&Host>, plan: &SavePlan) -> SecretOutcome {
    let mut out = SecretOutcome::default();
    let Some(host) = host else {
        return out;
    };
    if host.remote.is_none() {
        if plan.forget_if_unmanaged {
            let n = secret::forget_host(store, host.id);
            log::info!("{}: {n} saved secret(s) deleted", host.name);
        }
        return out;
    }
    // Only a change the user made here, and only to where it was saved (never an address an
    // import or another program wrote meanwhile; review S3).
    if let Some(before) = plan.before.as_ref().filter(|b| b.remote.is_some())
        && plan.endpoint_edited()
    {
        if plan.saved_as_shown(host) {
            match store.rebind(before, host) {
                Ok(0) => {}
                Ok(n) => log::info!("{}: {n} saved secret(s) follow the new address", host.name),
                Err(e) => out.errors.push(e),
            }
        } else {
            log::info!(
                "{}: saved with another address than the editor showed (changed meanwhile); \
                 saved passwords not moved",
                host.name
            );
        }
    }
    let intents = plan.intents.clone().unwrap_or_default();
    for kind in SecretKind::ALL {
        let res = match intent(&intents, kind) {
            SecretOverride::Stored => continue,
            SecretOverride::Value(v) => store
                .set_for_host(host, kind, "", v.as_str())
                .map(|account| log::info!("{}: {kind} saved for {account}", host.name)),
            SecretOverride::Absent => store.delete(host.id, kind).map(|existed| {
                if existed {
                    log::info!("{}: {kind} deleted", host.name);
                }
            }),
        };
        if let Err(e) = res {
            log::warn!("{}: {kind}: {e}", host.name);
            out.errors.push(e);
        }
    }
    // Kept (not typed or deleted now) but no longer for this connection: say so.
    out.stale = stale_secrets(store, host, |k| {
        !matches!(intent(&intents, k), SecretOverride::Stored)
    });
    out
}

/// The editor's save is the user's confirmation that a Windows host without a saved password
/// may use the current Windows sign-in at its management address (cross review X2). `true`
/// when it was recorded now. Blocking (Credential Manager): worker only.
pub fn confirm_after_save(client: &RemoteClient, host: &Host) -> bool {
    match client.confirm_sign_in(host) {
        Ok(account) => account.is_some(),
        Err(e) => {
            log::warn!(
                "{}: the sign-in confirmation was not recorded: {e}",
                host.name
            );
            false
        }
    }
}

/// Credential Manager work that belongs to a store operation: an editor save (its typed
/// passwords, a rebind, the sign-in confirmation) or a deleted host (its passwords). The store
/// thread queues it on the secret queue as soon as the operation is written
/// ([`queue_secret_job`]), not when the UI thread sees the result: at exit or session end the
/// UI no longer processes results, but the store flush and the secret-queue flush still run
/// it (review C2).
pub enum SecretJob {
    /// After an editor save.
    Save {
        /// Host name (log / toasts).
        name: String,
        /// The id the save was submitted for.
        pending: HostId,
        /// What to write.
        plan: Box<SavePlan>,
    },
    /// After a host was deleted.
    Delete {
        /// The deleted host.
        id: HostId,
    },
}

/// The store sink's part (store thread): takes the job of an `Updated` event and queues it
/// when the operation was written (a failed one just drops it: nothing was saved).
pub fn hand_off_secret_job(
    jobs: &Mutex<HashMap<u64, SecretJob>>,
    queue: &SerialQueue,
    client: &RemoteClient,
    ev: &StoreEvent,
) {
    if let StoreEvent::Updated { tag, result } = ev {
        let job = jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(tag);
        if let (Some(job), Ok(updated)) = (job, result) {
            queue_secret_job(queue, client, job, &updated.value, &updated.config);
        }
    }
}

/// Store thread: queues `job` for its written operation (`out`, `cfg` = the saved config).
pub fn queue_secret_job(
    queue: &SerialQueue,
    client: &RemoteClient,
    job: SecretJob,
    out: &OpOutput,
    cfg: &Config,
) {
    match job {
        SecretJob::Save {
            name,
            pending,
            plan,
        } => {
            let saved_id = match out {
                OpOutput::Saved(i) => *i,
                _ => pending,
            };
            let host = cfg.get(saved_id).cloned();
            queue_save_secrets(queue, client.clone(), name, pending, host, *plan);
        }
        SecretJob::Delete { id } => {
            let store = client.secrets().clone();
            queue.spawn(move || {
                let n = secret::forget_host(&store, id);
                if n > 0 {
                    log::info!("{n} saved secret(s) of the deleted host {id} removed");
                }
            });
        }
    }
}

/// After the host was saved (`pending` = the id the save was submitted for), on the secret
/// queue: writes / deletes / rebinds its secrets, records that a Windows host without a saved
/// password may use the current sign-in (the editor's save is the user's confirmation, cross
/// review X2; only for the endpoint the editor showed, review S2), checks the key file, then
/// reports failures, passwords that no longer fit the connection and key file problems, and
/// lets the automatic boot-time fetch run (cross review m2).
fn queue_save_secrets(
    queue: &SerialQueue,
    client: RemoteClient,
    name: String,
    pending: HostId,
    host: Option<Host>,
    plan: SavePlan,
) {
    let managed = host.as_ref().is_some_and(|h| h.remote.is_some());
    if !managed && plan.is_noop(false) {
        post_ui(move |app| app.secrets_applied(pending));
        return;
    }
    queue.spawn(move || {
        let store = client.secrets();
        let out = if plan.is_noop(managed) {
            SecretOutcome::default()
        } else {
            apply_save_plan(store, host.as_ref(), &plan)
        };
        let (confirmed, key_issue) = match host.as_ref().filter(|h| h.remote.is_some()) {
            Some(h) => {
                let confirmed = if plan.saved_as_shown(h) {
                    confirm_after_save(&client, h)
                } else {
                    // Re-pointed after the editor showed it (import, another program): not
                    // confirmed by this save; the next operation the user starts asks.
                    log::info!(
                        "{name}: saved with another address than the editor showed; the Windows \
                         sign-in is not confirmed by this save"
                    );
                    false
                };
                (confirmed, key_file_problem(h))
            }
            None => (false, None),
        };
        post_ui(move |app| {
            if let Some(e) = out.errors.first() {
                log::warn!("{name}: secrets not saved: {e}");
                app.toast(ToastKind::Error, GuiText::SecretSaveFailed, Text::error(e));
            }
            for (kind, stored_for) in out.stale {
                app.toast(
                    ToastKind::Warning,
                    GuiText::SecretStale {
                        kind,
                        stored_for,
                        in_editor: false,
                    },
                    Text::Empty,
                );
            }
            if let Some(t) = key_issue {
                app.toast(ToastKind::Warning, t, Text::Empty);
            }
            if confirmed {
                log::info!("{name}: the Windows sign-in is confirmed for this host");
            }
            app.secrets_applied(pending);
        });
    });
}

/// A warning about the saved host's SSH key file: `.pub`, missing, or a network path (cross
/// review m3). Reads the file's metadata: worker only.
pub fn key_file_problem(host: &Host) -> Option<GuiText> {
    let r = host
        .remote
        .as_ref()
        .filter(|r| r.kind == wol_core::RemoteKind::Ssh)?;
    let path = r.key_file.as_ref()?;
    let shown = path.display().to_string();
    Some(match wol_core::remote::key_file_issue(path)? {
        KeyFileIssue::NetworkPath => GuiText::KeyFileOnNetwork(shown),
        KeyFileIssue::PublicKey => GuiText::KeyFileIsPublic(shown),
        KeyFileIssue::Missing => GuiText::KeyFileMissing(shown),
    })
}

/// The editor's view of a host's secrets: which ones are usable for the host as it is now
/// ("saved" markers) and which ones are saved for another connection.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SecretView {
    /// Usable secrets.
    pub usable: SecretStatus,
    /// Saved for another connection (kind, what for).
    pub stale: Vec<(SecretKind, String)>,
}

/// Reads [`SecretView`] for `host`. Blocking (Credential Manager): worker only.
pub fn secret_view(store: &SecretStore, host: &Host) -> wol_core::Result<SecretView> {
    let exists = store.status(host.id)?;
    let mut usable = SecretStatus::default();
    for kind in SecretKind::ALL {
        if exists.has(kind) && store.state(host, kind)? == SecretState::Usable {
            match kind {
                SecretKind::Login => usable.login = true,
                SecretKind::KeyPassphrase => usable.key_passphrase = true,
                SecretKind::Sudo => usable.sudo = true,
            }
        }
    }
    Ok(SecretView {
        usable,
        stale: stale_secrets(store, host, |k| !exists.has(k)),
    })
}

// ---------------------------------------------------------------------------------------------
// Issues

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
    /// remote-user-issue.
    pub remote_user: FieldIssue,
    /// remote-address-issue.
    pub remote_address: FieldIssue,
    /// ssh-port-issue.
    pub ssh_port: FieldIssue,
    /// A remote field without an editor slot (host key, command overrides of a hand-edited
    /// config): shown as a toast.
    pub other: Option<FieldError>,
}

impl Issues {
    /// An advanced field failed (open the "Advanced" section).
    pub fn advanced(&self) -> bool {
        [self.targets, self.port, self.secureon, self.tcp_ports]
            .iter()
            .any(|i| *i != FieldIssue::None)
    }

    /// A remote field failed (open the "Remote management" section).
    pub fn remote(&self) -> bool {
        [self.remote_user, self.remote_address, self.ssh_port]
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
            Field::RemoteUser => &mut out.remote_user,
            Field::RemoteAddress => &mut out.remote_address,
            Field::SshPort => &mut out.ssh_port,
            Field::Group | Field::Notes | Field::Interfaces | Field::Probe => continue,
            Field::RemoteKind
            | Field::SshKeyFile
            | Field::SshHostKey
            | Field::SshSudo
            | Field::RebootCommand
            | Field::ShutdownCommand => {
                out.other.get_or_insert(*e);
                continue;
            }
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

/// MAC picker rows (best first, as the host ranked them).
pub fn candidate_rows(c: &[MacCandidate]) -> Vec<MacCandidateRow> {
    c.iter()
        .map(|c| {
            let mut detail: Vec<String> = Vec::new();
            if let Some(s) = &c.lan_ipv4 {
                detail.push(s.to_string());
            }
            if let Some(v) = c.via.as_deref().filter(|v| *v != c.iface) {
                detail.push(v.to_owned());
            }
            MacCandidateRow {
                iface: c.iface.as_str().into(),
                mac: c.mac.to_string().into(),
                detail: detail.join(" · ").into(),
                kind: match c.kind {
                    NicKind::Physical => MacKind::Physical,
                    NicKind::Wifi => MacKind::Wifi,
                    NicKind::Other => MacKind::Other,
                },
                default_route: c.on_default_route,
                link_up: c.link_up,
                score: c.score,
            }
        })
        .collect()
}

/// Note under a successful test: not an administrator, WMI refused the account (UAC remote
/// restrictions), WMI not reachable (firewall), or unknown; nothing for this PC (review R3).
pub fn test_note(info: &ConnInfo) -> Text {
    match info.admin_check.note() {
        Some((_, msg)) => Text::msg(msg),
        None => Text::Empty,
    }
}

// ---------------------------------------------------------------------------------------------
// UI glue (App methods for the editor overlay)

/// Reads the remote fields.
pub fn read_remote(ui: &AppWindow) -> RemoteFields {
    let e = ui.global::<EditorState>();
    RemoteFields {
        kind: e.get_remote_kind(),
        address: e.get_remote_address().into(),
        user: e.get_remote_user().into(),
        port: e.get_ssh_port().into(),
        key_file: e.get_ssh_key_file().into(),
        sudo: e.get_ssh_sudo(),
        host_key_forget: e.get_host_key_forget(),
        commands_reset: e.get_power_commands_reset(),
    }
}

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
        remote: read_remote(ui),
    }
}

/// The password boxes as [`SecretOverrides`] for the current kind / sudo method.
pub fn read_secret_intents(ui: &AppWindow, rf: &RemoteFields) -> SecretOverrides {
    let e = ui.global::<EditorState>();
    let (pw, pp, sp) = (
        e.get_remote_password(),
        e.get_ssh_key_passphrase(),
        e.get_ssh_sudo_password(),
    );
    secret_intents(
        rf.kind,
        rf.sudo,
        SecretInput {
            typed: &pw,
            delete: e.get_remote_password_delete(),
        },
        SecretInput {
            typed: &pp,
            delete: e.get_ssh_key_passphrase_delete(),
        },
        SecretInput {
            typed: &sp,
            delete: e.get_ssh_sudo_password_delete(),
        },
    )
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
    let r = &f.remote;
    e.set_remote_kind(r.kind);
    e.set_remote_address(r.address.as_str().into());
    e.set_remote_user(r.user.as_str().into());
    e.set_ssh_port(r.port.as_str().into());
    e.set_ssh_key_file(r.key_file.as_str().into());
    e.set_ssh_sudo(r.sudo);
    e.set_host_key_forget(r.host_key_forget);
    e.set_power_commands_reset(r.commands_reset);
}

/// Empties the password boxes and their flags (never leave typed secrets in the UI).
pub fn clear_secret_fields(ui: &AppWindow) {
    let e = ui.global::<EditorState>();
    e.set_remote_password(SharedString::default());
    e.set_remote_password_delete(false);
    e.set_ssh_key_passphrase(SharedString::default());
    e.set_ssh_key_passphrase_delete(false);
    e.set_ssh_sudo_password(SharedString::default());
    e.set_ssh_sudo_password_delete(false);
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
    e.set_remote_user_issue(i.remote_user);
    e.set_remote_address_issue(i.remote_address);
    e.set_ssh_port_issue(i.ssh_port);
    if i.advanced() {
        e.set_advanced_open(true);
    }
    if i.remote() {
        e.set_remote_open(true);
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
            self.open_editor(EditorMode::Add, None, false);
        }
    }

    /// Double click / Enter / menu.
    pub fn edit_host(&self, id: &str) {
        if !self.idle() {
            return;
        }
        if let Some(h) = self.host_clone(id) {
            self.open_editor(EditorMode::Edit, Some(h), false);
        }
    }

    /// "Set up remote management…": the editor with the remote section expanded (kind None
    /// for an unmanaged host, so that the UI scrolls to the section and focuses its header).
    pub fn setup_remote(&self, id: &str) {
        if !self.idle() {
            return;
        }
        if let Some(h) = self.host_clone(id) {
            self.open_editor(EditorMode::Edit, Some(h), true);
        }
    }

    /// Host > Duplicate: an editor pre-filled with "Copy of …"; nothing is saved until Save.
    pub fn duplicate_host(&self, id: &str) {
        if !self.idle() {
            return;
        }
        if let Some(h) = self.host_clone(id) {
            self.open_editor(EditorMode::Duplicate, Some(h), false);
        }
    }

    fn open_editor(&self, mode: EditorMode, host: Option<Host>, reveal_remote: bool) {
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
        // An earlier editor's "Get from IP" / "Test connection" may still run (a filtered host
        // can take minutes): its button stays busy until it ended (review C5).
        e.set_arp_status(if self.editor_lookup_running.get() {
            ArpStatus::Busy
        } else {
            ArpStatus::Idle
        });
        e.set_saving(false);
        // Remote management: every property (the UI keeps nothing between openings).
        let host_key_line = draft.remote.host_key.clone();
        let (key_type, key_fp) = host_key_display(&host_key_line);
        e.set_host_key_type(key_type.into());
        e.set_host_key_fingerprint(key_fp.into());
        // The SSH power command overrides run as root: always shown (read-only, X1).
        e.set_reboot_command(draft.remote.reboot_command.trim().into());
        e.set_shutdown_command(draft.remote.shutdown_command.trim().into());
        clear_secret_fields(&self.ui);
        // Secrets are keyed by the host id: a copy has none.
        e.set_remote_password_saved(false);
        e.set_ssh_key_passphrase_saved(false);
        e.set_ssh_sudo_password_saved(false);
        e.set_test_status(if self.editor_test_running.get() {
            TestStatus::Busy
        } else {
            TestStatus::Idle
        });
        e.set_test_os(SharedString::default());
        e.set_test_boot(SharedString::default());
        e.set_test_note(SharedString::default());
        e.set_test_error(SharedString::default());
        e.set_arp_message(SharedString::default());
        e.set_mac_candidates(ModelRc::default());
        e.set_mac_picker_open(false);
        e.set_mac_picker_host(SharedString::default());
        e.set_remote_open(reveal_remote || draft.remote.kind.is_some());
        let edit_host = base
            .as_ref()
            .and_then(|b| self.cfg.borrow().get(b.id).cloned());
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
            remote_base: draft.remote.clone(),
            opened: edit_host.clone(),
            host_key_line,
            test_seq: 0,
            lookup_seq: 0,
            test_shown: None,
            arp_text: Text::Empty,
            mac_candidates: Vec::new(),
        });
        self.ui
            .global::<AppState>()
            .set_overlay(OverlayKind::Editor);
        // Adapters may have changed since the last look.
        self.refresh_interfaces();
        if let Some(h) = edit_host {
            if h.unsupported_remote().is_some() {
                // Kept in the file, but "None" here: say why before it gets replaced.
                self.toast(
                    ToastKind::Warning,
                    GuiText::RemoteFromNewerVersion,
                    Text::Empty,
                );
            }
            self.load_secret_view(token, h);
        }
    }

    /// Reads the host's secrets ("saved" markers, stale ones) on the secret queue (after any
    /// change queued before).
    fn load_secret_view(&self, token: u64, host: Host) {
        let store = self.client.secrets().clone();
        self.secret_queue.spawn(move || {
            let r = secret_view(&store, &host);
            post_ui(move |app| app.on_secret_view(token, r));
        });
    }

    fn on_secret_view(&self, token: u64, r: wol_core::Result<SecretView>) {
        let v = match r {
            Ok(v) => v,
            Err(e) => {
                log::warn!("cannot read the saved passwords: {e}");
                return;
            }
        };
        if self.editor.borrow().as_ref().map(|s| s.token) != Some(token) {
            return;
        }
        // "Saved" = usable for this connection; a password saved for another one is shown as
        // not saved (typing replaces it) and explained once.
        let e = self.ui.global::<EditorState>();
        e.set_remote_password_saved(v.usable.login);
        e.set_ssh_key_passphrase_saved(v.usable.key_passphrase);
        e.set_ssh_sudo_password_saved(v.usable.sudo);
        for (kind, stored_for) in v.stale {
            self.toast(
                ToastKind::Warning,
                GuiText::SecretStale {
                    kind,
                    stored_for,
                    in_editor: true,
                },
                Text::Empty,
            );
        }
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

    fn reset_editor_transients(&self) {
        let e = self.ui.global::<EditorState>();
        clear_secret_fields(&self.ui);
        e.set_arp_status(ArpStatus::Idle);
        e.set_mac_picker_open(false);
        e.set_mac_candidates(ModelRc::default());
        e.set_test_status(TestStatus::Idle);
    }

    /// The user closed the editor (pending ARP / test results are dropped, typed passwords
    /// discarded).
    pub(crate) fn discard_editor(&self) {
        self.editor.borrow_mut().take();
        self.reset_editor_transients();
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
        // A key file on a network path is never read (reading it would log on to that server
        // with this user's credentials): not saved (cross review m3 / m4, like `wolm remote
        // set`). A `.pub` / missing file is only a warning after the save.
        if fields.remote.kind == RemoteKind::Ssh
            && let Some(path) = network_key_file(&fields.remote.key_file)
        {
            e.set_remote_open(true);
            self.toast(
                ToastKind::Error,
                GuiText::SaveFailed,
                GuiText::KeyFileOnNetwork(path).into(),
            );
            return;
        }
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
        let plan = self.save_plan(&s, &fields);
        self.submit_save(s.token, s.mode, id, Op::SaveHost { draft, kind }, plan);
    }

    /// Credential Manager changes of the current editor state.
    fn save_plan(&self, s: &EditorSession, f: &EditorFields) -> SavePlan {
        SavePlan {
            intents: (f.remote.kind != RemoteKind::None)
                .then(|| read_secret_intents(&self.ui, &f.remote)),
            forget_if_unmanaged: s.remote_base.kind.is_some(),
            // The host as the editor showed it, not as the app knows it now: a change made
            // meanwhile by an import or another program is not the user's (review S3).
            before: s.opened.clone(),
            shown: self
                .draft_host(s, f)
                .ok()
                .as_ref()
                .and_then(SecretBinding::for_host),
        }
    }

    /// Shows save errors: inline issues (opening the sections), else a toast.
    fn show_save_errors(&self, issues: &Issues, err: &wol_core::Error) {
        if issues.is_empty() {
            self.toast(ToastKind::Error, GuiText::SaveFailed, Text::error(err));
            return;
        }
        push_issues(&self.ui, issues);
        if let Some(fe) = issues.other {
            self.toast(
                ToastKind::Error,
                GuiText::SaveFailed,
                Text::msg(Msg::FieldError(fe)),
            );
        }
    }

    fn submit_save(&self, token: u64, mode: EditorMode, id: HostId, op: Op, plan: SavePlan) {
        let e = self.ui.global::<EditorState>();
        // Same rules as on the store thread, against what this window knows now.
        let mut local = self.cfg.borrow().clone();
        if let Err(err) = apply_op(&mut local, &op) {
            let issues = issues_from(&field_errors_of(&err, Some(id)));
            self.show_save_errors(&issues, &err);
            e.set_saving(false);
            return;
        }
        let name = local.get(id).map(|h| h.name.clone()).unwrap_or_default();
        e.set_saving(true);
        // No automatic boot-time fetch for this host until its passwords are stored (a fetch
        // started by the optimistic update below would run without them; cross review m2).
        self.secrets_pending.borrow_mut().insert(id);
        // Optimistic: the list shows the change at once; the store result reconciles it.
        self.reconcile_from(local);
        self.submit_with_secrets(
            op,
            Pending::Save {
                token,
                mode,
                name: name.clone(),
                id,
            },
            SecretJob::Save {
                name,
                pending: id,
                plan: Box::new(plan),
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
        let fields = read_fields(&self.ui);
        let draft = draft_from_fields(&fields, &s);
        let plan = self.save_plan(&s, &fields);
        self.submit_save(
            s.token,
            EditorMode::Add,
            id,
            Op::SaveHost {
                draft,
                kind: SaveKind::New { id },
            },
            plan,
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
        self.reset_editor_transients();
        self.ui.global::<EditorState>().set_saving(false);
        let st = self.ui.global::<AppState>();
        if st.get_overlay() == OverlayKind::Editor {
            st.set_overlay(OverlayKind::None);
        }
    }

    /// The store refused the save.
    pub(crate) fn editor_save_failed(&self, token: u64, id: HostId, err: &wol_core::Error) {
        // Nothing to store: automatic fetches may run again (the reload restores the host).
        self.secrets_pending.borrow_mut().remove(&id);
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
        self.show_save_errors(&issues, err);
    }

    /// The draft as a host for "Test connection" / "Get from IP": the saved host (or the
    /// duplicated one, or a new one) with the editor's address, adapter pins and remote
    /// section. An invalid address counts as none (the management address may be enough).
    fn draft_host(&self, s: &EditorSession, f: &EditorFields) -> Result<Host, FieldError> {
        let mut h = {
            let cfg = self.cfg.borrow();
            match (&s.base, &s.template) {
                (Some(b), _) => cfg.get(b.id).cloned().unwrap_or_else(|| Host {
                    id: b.id,
                    ..Host::default()
                }),
                (None, Some(t)) => Host {
                    id: s.new_id,
                    ..t.clone()
                },
                (None, None) => Host {
                    id: s.new_id,
                    ..Host::default()
                },
            }
        };
        h.address = HostAddr::parse(&f.address).ok();
        let name = normalize::clean_single_line(&f.name);
        if !name.is_empty() {
            h.name = name;
        } else if let Some(a) = h.address.as_ref().or(h.management_address()) {
            h.name = a.to_string();
        }
        h.interfaces = pins_for(f, s);
        match remote_draft(&f.remote, &s.host_key_line, &s.remote_base).build() {
            Ok(r) => h.remote = r,
            Err(v) => {
                return Err(v.first().copied().unwrap_or(FieldError::new(
                    Field::RemoteKind,
                    wol_core::FieldIssue::Required,
                )));
            }
        }
        Ok(h)
    }

    /// Pushes the test result texts in the current language.
    fn push_test_shown(&self) {
        let shown = self
            .editor
            .borrow()
            .as_ref()
            .and_then(|s| s.test_shown.clone());
        let Some(shown) = shown else {
            return;
        };
        let lang = self.lang.get();
        let e = self.ui.global::<EditorState>();
        match shown {
            TestShown::Ok { boot, note } => {
                e.set_test_boot(crate::remote::boot_text(lang, &boot, SystemTime::now()).into());
                e.set_test_note(note.render(lang).into());
            }
            TestShown::Failed(t) => e.set_test_error(t.render(lang).into()),
        }
    }

    fn set_test_shown(&self, token: u64, shown: TestShown) {
        {
            let mut ed = self.editor.borrow_mut();
            let Some(s) = ed.as_mut().filter(|s| s.token == token) else {
                return;
            };
            s.test_shown = Some(shown);
        }
        self.push_test_shown();
    }

    fn set_arp_text(&self, token: u64, t: Text) {
        {
            let mut ed = self.editor.borrow_mut();
            let Some(s) = ed.as_mut().filter(|s| s.token == token) else {
                return;
            };
            s.arp_text = t.clone();
        }
        self.ui
            .global::<EditorState>()
            .set_arp_message(t.render(self.lang.get()).into());
    }

    /// "Test connection" with the draft (typed secrets, else the saved ones unless deleted).
    pub fn test_connection(&self) {
        let e = self.ui.global::<EditorState>();
        if e.get_test_status() == TestStatus::Busy || self.editor_test_running.get() {
            return;
        }
        let Some(s) = self.editor.borrow().clone() else {
            return;
        };
        let f = read_fields(&self.ui);
        if f.remote.kind == RemoteKind::None {
            return;
        }
        let token = s.token;
        let host = match self.draft_host(&s, &f) {
            Ok(h) => h,
            Err(fe) => {
                e.set_test_status(TestStatus::Failed);
                self.set_test_shown(token, TestShown::Failed(Text::msg(Msg::FieldError(fe))));
                return;
            }
        };
        let seq = {
            let mut ed = self.editor.borrow_mut();
            let Some(s) = ed.as_mut().filter(|s| s.token == token) else {
                return;
            };
            s.test_seq += 1;
            s.test_shown = None;
            s.test_seq
        };
        let client = self
            .client
            .clone()
            .with_overrides(read_secret_intents(&self.ui, &f.remote));
        let settings = self.cfg.borrow().settings.clone();
        let secrets = self.secret_queue.barrier();
        // A test of the saved host's own endpoint confirms the current Windows sign-in for it
        // (cross review X2); a draft that points elsewhere is confirmed by its save.
        let confirm = self.saved_endpoint(&host);
        e.set_test_status(TestStatus::Busy);
        self.editor_test_running.set(true);
        log::info!("{}: connection test", host.name);
        self.remote_pool.spawn(move || {
            secrets.wait(SECRET_WAIT);
            if confirm {
                confirm_after_save(&client, &host);
            }
            let r = client.test_connection(&host, &settings);
            post_ui(move |app| app.on_test_done(token, seq, host, r));
        });
    }

    fn on_test_done(&self, token: u64, seq: u64, host: Host, r: wol_core::Result<ConnInfo>) {
        self.editor_test_running.set(false);
        let e = self.ui.global::<EditorState>();
        let current = self
            .editor
            .borrow()
            .as_ref()
            .is_some_and(|s| s.token == token && s.test_seq == seq);
        if !current {
            // An earlier editor's test: the open editor's button waited for it (review C5).
            if e.get_test_status() == TestStatus::Busy {
                e.set_test_status(TestStatus::Idle);
            }
            return;
        }
        match r {
            Ok(info) => {
                log::info!("{}: connection test ok ({:?})", host.name, info.os);
                e.set_test_os(info.os.clone().unwrap_or_default().into());
                e.set_test_error(SharedString::default());
                self.set_test_shown(
                    token,
                    TestShown::Ok {
                        boot: info.boot.clone(),
                        note: test_note(&info),
                    },
                );
                e.set_test_status(TestStatus::Ok);
                self.learn_boot_from_test(&host, info.boot);
            }
            Err(err) => {
                log::info!("{}: connection test failed: {err}", host.name);
                let host_id = e.get_host_id().to_string();
                match key_step(Origin::User, &err, &host_id) {
                    KeyStep::Ask(p) => {
                        e.set_test_status(TestStatus::Idle);
                        self.show_top(TopDialog::HostKey(p, Retry::Test { token }));
                    }
                    KeyStep::TrustKnown(p) => {
                        e.set_test_status(TestStatus::Idle);
                        self.editor_trust_key(&p, Retry::Test { token }, true);
                    }
                    KeyStep::Mismatch(p) => {
                        self.set_test_shown(token, TestShown::Failed(Text::error(&err)));
                        e.set_test_status(TestStatus::Failed);
                        self.show_top(TopDialog::HostKey(p, Retry::Test { token }));
                    }
                    KeyStep::NotKey | KeyStep::Quiet => {
                        self.set_test_shown(token, TestShown::Failed(Text::error(&err)));
                        e.set_test_status(TestStatus::Failed);
                    }
                }
            }
        }
    }

    /// `true` when the editor's draft points at the saved host's own endpoint (same host id,
    /// kind, management address and SSH port).
    fn saved_endpoint(&self, draft: &Host) -> bool {
        let cfg = self.cfg.borrow();
        cfg.get(draft.id).is_some_and(|h| {
            h.remote.is_some() && crate::remote::remote_key(h) == crate::remote::remote_key(draft)
        })
    }

    /// A test of the saved host's own endpoint also tells the row its boot time.
    fn learn_boot_from_test(&self, draft: &Host, boot: BootInfo) {
        if self.saved_endpoint(draft) {
            self.remote.borrow_mut().set_boot(draft.id, boot);
            self.refresh_remote_row(draft.id);
        }
    }

    /// "Get from IP": `wol_core::macfind` with the draft (ARP on the LAN, else the host's
    /// remote management with the typed secrets) on the remote pool.
    pub fn lookup_mac(&self, address: &str) {
        // One at a time, also across editor sessions (review C5).
        if self.editor_lookup_running.get() {
            return;
        }
        let Some(s) = self.editor.borrow().clone() else {
            return;
        };
        let token = s.token;
        let e = self.ui.global::<EditorState>();
        let f = read_fields(&self.ui);
        let managed = f.remote.kind != RemoteKind::None;
        let typed = address.trim();
        let query = if typed.is_empty() {
            None
        } else {
            HostAddr::parse(typed).ok()
        };
        if query.is_none() && !managed {
            e.set_arp_status(ArpStatus::Failed);
            self.set_arp_text(token, Text::Empty);
            return;
        }
        let host = match self.draft_host(&s, &f) {
            Ok(h) => h,
            Err(fe) => {
                e.set_arp_status(ArpStatus::Failed);
                self.set_arp_text(token, Text::msg(Msg::FieldError(fe)));
                return;
            }
        };
        let seq = {
            let mut ed = self.editor.borrow_mut();
            let Some(s) = ed.as_mut().filter(|s| s.token == token) else {
                return;
            };
            s.lookup_seq += 1;
            s.lookup_seq
        };
        let client = self
            .client
            .clone()
            .with_overrides(read_secret_intents(&self.ui, &f.remote));
        let settings = self.cfg.borrow().settings.clone();
        let label = if f.name.trim().is_empty() {
            typed.to_owned()
        } else {
            f.name.trim().to_owned()
        };
        let address = typed.to_owned();
        let secrets = self.secret_queue.barrier();
        let confirm = managed && self.saved_endpoint(&host);
        e.set_arp_status(ArpStatus::Busy);
        self.editor_lookup_running.set(true);
        self.set_arp_text(token, Text::Empty);
        self.remote_pool.spawn(move || {
            secrets.wait(SECRET_WAIT);
            if confirm {
                confirm_after_save(&client, &host);
            }
            let q = MacQuery {
                address: query.as_ref(),
                host: Some(&host),
            };
            let r = macfind::find_mac_with(&q, &settings, &client, &SystemMacEnv);
            post_ui(move |app| app.on_lookup_done(token, seq, address, label, r));
        });
    }

    fn on_lookup_done(
        &self,
        token: u64,
        seq: u64,
        address: String,
        label: String,
        r: wol_core::Result<MacFound>,
    ) {
        self.editor_lookup_running.set(false);
        let e = self.ui.global::<EditorState>();
        let current = self
            .editor
            .borrow()
            .as_ref()
            .is_some_and(|s| s.token == token && s.lookup_seq == seq);
        if !current {
            // An earlier editor's lookup: the open editor's button waited for it (review C5).
            if e.get_arp_status() == ArpStatus::Busy {
                e.set_arp_status(ArpStatus::Idle);
            }
            return;
        }
        match r {
            Ok(found) => {
                let candidates = found.candidates().to_vec();
                if let Some(s) = self.editor.borrow_mut().as_mut() {
                    s.mac_candidates = candidates.clone();
                }
                match found.unique() {
                    Some(mac) => self.mac_found(&mac.to_string()),
                    None => {
                        log::info!("{label}: {} MAC candidates", candidates.len());
                        let rows = candidate_rows(&candidates);
                        e.set_mac_candidates(ModelRc::new(VecModel::from(rows)));
                        e.set_mac_picker_host(label.into());
                        e.set_arp_status(ArpStatus::Idle);
                        self.show_top(TopDialog::MacPicker { token });
                    }
                }
            }
            Err(Error::NotOnLocalSubnet { .. }) => e.set_arp_status(ArpStatus::NotLocal),
            Err(Error::ArpNoReply { .. }) => e.set_arp_status(ArpStatus::NotFound),
            Err(err @ Error::MacNeedsRemote { .. }) => {
                self.set_arp_text(token, Text::error(&err));
                e.set_arp_status(ArpStatus::NeedsRemote);
            }
            Err(err) => {
                log::info!("MAC lookup failed: {err}");
                let host_id = e.get_host_id().to_string();
                let retry = Retry::Mac { token, address };
                match key_step(Origin::User, &err, &host_id) {
                    KeyStep::Ask(p) => {
                        e.set_arp_status(ArpStatus::Idle);
                        self.show_top(TopDialog::HostKey(p, retry));
                    }
                    KeyStep::TrustKnown(p) => {
                        e.set_arp_status(ArpStatus::Idle);
                        self.editor_trust_key(&p, retry, true);
                    }
                    KeyStep::Mismatch(p) => {
                        self.set_arp_text(token, Text::error(&err));
                        e.set_arp_status(ArpStatus::Failed);
                        self.show_top(TopDialog::HostKey(p, retry));
                    }
                    KeyStep::NotKey | KeyStep::Quiet => {
                        self.set_arp_text(token, Text::error(&err));
                        e.set_arp_status(ArpStatus::Failed);
                    }
                }
            }
        }
    }

    /// A MAC was found (unique result or picked): warn when the host reported WoL as
    /// disabled on that adapter.
    fn mac_found(&self, mac: &str) {
        let e = self.ui.global::<EditorState>();
        e.set_mac(mac.into());
        e.set_mac_issue(FieldIssue::None);
        e.set_arp_status(ArpStatus::Found);
        let disabled = self.editor.borrow().as_ref().and_then(|s| {
            s.mac_candidates
                .iter()
                .find(|c| c.mac.to_string() == mac && c.wol_enabled == Some(false))
                .map(|c| c.iface.clone())
        });
        if let Some(iface) = disabled {
            self.toast(
                ToastKind::Warning,
                Msg::WolDisabledOn { iface },
                Text::Empty,
            );
        }
    }

    /// MAC picker: "Select" (the UI already wrote `mac` and closed the picker).
    pub fn mac_picked(&self, c: MacCandidateRow) {
        if self.editor.borrow().is_some() {
            self.mac_found(&c.mac);
        }
        self.pump_top();
    }

    /// A key trusted in the host-key dialog during an editor operation goes into the draft
    /// (saved with the host); the operation runs again.
    pub(crate) fn editor_trust_key(&self, p: &HostKeyPrompt, retry: Retry, known: bool) {
        let Some(token) = retry.editor_token() else {
            return;
        };
        {
            let mut ed = self.editor.borrow_mut();
            let Some(s) = ed.as_mut().filter(|s| s.token == token) else {
                return;
            };
            s.host_key_line = p.key_line.to_string();
        }
        let e = self.ui.global::<EditorState>();
        e.set_host_key_type(p.key_type.clone());
        e.set_host_key_fingerprint(p.fingerprint.clone());
        e.set_host_key_forget(false);
        if known {
            self.toast(
                ToastKind::Info,
                Msg::HostKeyFromKnownHosts {
                    label: p.host_name.to_string(),
                    fingerprint: p.fingerprint.to_string(),
                },
                Text::Empty,
            );
        }
        match retry {
            Retry::Test { .. } => self.test_connection(),
            Retry::Mac { address, .. } => self.lookup_mac(&address),
            Retry::BootTime(_) | Retry::Power(_) => {}
        }
    }

    /// Mismatch during an editor operation, "Forget…": the pinned key is the draft's, so
    /// this only sets the draft flag (nothing happens until Save).
    pub(crate) fn editor_forget_key(&self, retry: &Retry) {
        let Some(token) = retry.editor_token() else {
            return;
        };
        if self.editor.borrow().as_ref().map(|s| s.token) != Some(token) {
            return;
        }
        let e = self.ui.global::<EditorState>();
        e.set_host_key_forget(true);
        match retry {
            Retry::Test { .. } => e.set_test_status(TestStatus::Idle),
            Retry::Mac { .. } => e.set_arp_status(ArpStatus::Idle),
            Retry::BootTime(_) | Retry::Power(_) => {}
        }
    }

    /// The host-key dialog of an editor operation was cancelled: nothing keeps running.
    pub(crate) fn editor_retry_abandoned(&self, retry: &Retry) {
        let Some(token) = retry.editor_token() else {
            return;
        };
        if self.editor.borrow().as_ref().map(|s| s.token) != Some(token) {
            return;
        }
        let e = self.ui.global::<EditorState>();
        if e.get_test_status() == TestStatus::Busy {
            e.set_test_status(TestStatus::Idle);
        }
        if e.get_arp_status() == ArpStatus::Busy {
            e.set_arp_status(ArpStatus::Idle);
        }
    }

    /// Language switch: a duplicate's untouched "Copy of …" name follows the language, and so
    /// do the Rust texts of the remote section.
    pub(crate) fn retranslate_editor(&self, _old: Lang) {
        let lang = self.lang.get();
        let e = self.ui.global::<EditorState>();
        self.push_test_shown();
        let arp = self.editor.borrow().as_ref().map(|s| s.arp_text.clone());
        if let Some(t) = arp {
            e.set_arp_message(t.render(lang).into());
        }
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
    use wol_core::remote::AdminCheck;
    use wol_core::{HostAddr, MacAddr, RemoteConfig, SecureOn, Target};

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

    /// GitHub's published ed25519 host key (public data; a syntactically valid key line).
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    fn ssh_host() -> Host {
        let mut h = full_host();
        let mut r = RemoteConfig::new(wol_core::RemoteKind::Ssh);
        r.user = Some("admin".into());
        r.address = Some(HostAddr::parse("100.105.1.2").unwrap());
        r.port = Some(2222);
        r.key_file = Some("C:\\keys\\id_ed25519".into());
        r.host_key = Some(KEY.into());
        r.sudo = CoreSudo::Separate;
        r.reboot_command = Some("/sbin/reboot".into());
        r.extra
            .insert("future".into(), toml::Value::String("kept".into()));
        h.remote = Some(r);
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
            remote_base: base.draft.remote.clone(),
            opened: Some(h.clone()),
            host_key_line: base.draft.remote.host_key.clone(),
            base: Some(base),
            template: None,
            copy_name: None,
            new_id: HostId::new_v4(),
            token: 1,
            test_seq: 0,
            lookup_seq: 0,
            test_shown: None,
            arp_text: Text::Empty,
            mac_candidates: Vec::new(),
        };
        (s, fields)
    }

    fn save(cfg: &mut Config, s: &EditorSession, f: &EditorFields) -> wol_core::Result<()> {
        apply_op(
            cfg,
            &Op::SaveHost {
                draft: draft_from_fields(f, s),
                kind: SaveKind::Edit(s.base.clone().unwrap()),
            },
        )
        .map(|_| ())
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
    fn remote_draft_round_trip_and_merge() {
        let h = ssh_host();
        let mut cfg = Config::default();
        cfg.hosts.push(h.clone());
        let (s, f) = session_for(&h, &[]);
        // Fields as the editor shows them.
        assert_eq!(f.remote.kind, RemoteKind::Ssh);
        assert_eq!(f.remote.user, "admin");
        assert_eq!(f.remote.address, "100.105.1.2");
        assert_eq!(f.remote.port, "2222");
        assert_eq!(f.remote.key_file, "C:\\keys\\id_ed25519");
        assert_eq!(
            f.remote.sudo,
            SudoMode::Separate,
            "separate is a config value"
        );
        assert!(!f.remote.host_key_forget);
        let (kt, fp) = host_key_display(&s.host_key_line);
        assert_eq!(kt, "ssh-ed25519");
        assert!(fp.starts_with("SHA256:"), "{fp}");
        // Untouched: the whole table (incl. commands and unknown keys) stays.
        let before = cfg.clone();
        save(&mut cfg, &s, &f).unwrap();
        assert_eq!(cfg, before);

        // Change the user and the sudo method only.
        let mut f2 = f.clone();
        f2.remote.user = "ops".into();
        f2.remote.sudo = SudoMode::Nopasswd;
        save(&mut cfg, &s, &f2).unwrap();
        let r = cfg.get(h.id).unwrap().remote.clone().unwrap();
        assert_eq!(r.user.as_deref(), Some("ops"));
        assert_eq!(r.sudo, CoreSudo::NoPasswd);
        assert_eq!(r.reboot_command.as_deref(), Some("/sbin/reboot"));
        assert_eq!(r.host_key.as_deref(), Some(KEY));
        assert_eq!(
            r.extra.get("future"),
            Some(&toml::Value::String("kept".into()))
        );

        // Forget the pinned key.
        let mut cfg2 = before.clone();
        let mut f3 = f.clone();
        f3.remote.host_key_forget = true;
        save(&mut cfg2, &s, &f3).unwrap();
        assert_eq!(
            cfg2.get(h.id).unwrap().remote.as_ref().unwrap().host_key,
            None
        );

        // Cross review X1: the command overrides are shown read-only; "Use the defaults"
        // removes them on save, nothing else can change them.
        assert!(!f.remote.commands_reset);
        let mut cfg5 = before.clone();
        let mut f6 = f.clone();
        f6.remote.commands_reset = true;
        save(&mut cfg5, &s, &f6).unwrap();
        let r = cfg5.get(h.id).unwrap().remote.clone().unwrap();
        assert_eq!((r.reboot_command, r.shutdown_command), (None, None));
        assert_eq!(r.host_key.as_deref(), Some(KEY), "only the commands");

        // A key trusted during "Test connection" is part of the draft.
        let mut plain = h.clone();
        plain.remote.as_mut().unwrap().host_key = None;
        let mut cfg3 = Config::default();
        cfg3.hosts.push(plain.clone());
        let (mut s3, f4) = session_for(&plain, &[]);
        assert_eq!(
            host_key_display(&s3.host_key_line),
            (String::new(), String::new())
        );
        s3.host_key_line = KEY.into();
        save(&mut cfg3, &s3, &f4).unwrap();
        assert_eq!(
            cfg3.get(h.id)
                .unwrap()
                .remote
                .as_ref()
                .unwrap()
                .host_key
                .as_deref(),
            Some(KEY)
        );

        // Kind None removes the table.
        let mut cfg4 = before.clone();
        let mut f5 = f.clone();
        f5.remote.kind = RemoteKind::None;
        save(&mut cfg4, &s, &f5).unwrap();
        assert!(cfg4.get(h.id).unwrap().remote.is_none());

        // An unmanaged host with an untouched section stays unmanaged, whatever the hidden
        // fields say; choosing Windows creates a table from the fields.
        let bare = full_host();
        let mut cfg5 = Config::default();
        cfg5.hosts.push(bare.clone());
        let (s5, mut f6) = session_for(&bare, &[]);
        assert_eq!(f6.remote, RemoteFields::default());
        f6.remote.user = "typed-then-switched-off".into();
        save(&mut cfg5, &s5, &f6).unwrap();
        assert!(cfg5.get(bare.id).unwrap().remote.is_none());
        f6.remote.kind = RemoteKind::Windows;
        f6.remote.user = "PC\\admin".into();
        save(&mut cfg5, &s5, &f6).unwrap();
        let r = cfg5.get(bare.id).unwrap().remote.clone().unwrap();
        assert_eq!(r.kind, wol_core::RemoteKind::Windows);
        assert_eq!(r.user.as_deref(), Some("PC\\admin"));

        // Remote field errors go to their slots and open the section.
        let mut f7 = f.clone();
        f7.remote.user = "bad user".into();
        f7.remote.port = "0".into();
        let e = save(&mut cfg.clone(), &s, &f7).unwrap_err();
        let iss = issues_from(&field_errors_of(&e, Some(h.id)));
        assert_eq!(iss.remote_user, FieldIssue::InvalidUser);
        assert_eq!(iss.ssh_port, FieldIssue::InvalidPort);
        assert!(iss.remote() && !iss.advanced());
    }

    #[test]
    fn secret_intents_typed_delete_unchanged() {
        let tag = |o: &SecretOverride| match o {
            SecretOverride::Stored => "keep".to_owned(),
            SecretOverride::Absent => "delete".to_owned(),
            SecretOverride::Value(v) => format!("write:{}", v.as_str()),
        };
        let tags = |o: &SecretOverrides| [tag(&o.login), tag(&o.key_passphrase), tag(&o.sudo)];
        let none = SecretInput {
            typed: "",
            delete: false,
        };
        let typed = |t| SecretInput {
            typed: t,
            delete: false,
        };
        let del = SecretInput {
            typed: "",
            delete: true,
        };
        // Windows: the login password only; hidden boxes count with their delete flag only.
        let o = secret_intents(
            RemoteKind::Windows,
            SudoMode::Auto,
            typed(" pa ss "),
            typed("ignored"),
            del,
        );
        assert_eq!(tags(&o), ["write: pa ss ", "keep", "delete"], "not trimmed");
        let o = secret_intents(RemoteKind::Windows, SudoMode::Auto, del, none, none);
        assert_eq!(tags(&o), ["delete", "keep", "keep"]);
        // SSH, separate sudo password.
        let o = secret_intents(
            RemoteKind::Ssh,
            SudoMode::Separate,
            none,
            typed("pp"),
            typed("sudo!"),
        );
        assert_eq!(tags(&o), ["keep", "write:pp", "write:sudo!"]);
        let o = secret_intents(RemoteKind::Ssh, SudoMode::Separate, none, del, del);
        assert_eq!(tags(&o), ["keep", "delete", "delete"]);
        // Auto keeps a stored sudo password (it uses one) and ignores the hidden box.
        let o = secret_intents(RemoteKind::Ssh, SudoMode::Auto, none, none, typed("x"));
        assert_eq!(tags(&o), ["keep", "keep", "keep"]);
        // Methods that never use it delete it.
        for m in [SudoMode::Root, SudoMode::Nopasswd, SudoMode::Password] {
            let o = secret_intents(RemoteKind::Ssh, m, typed("pw"), none, typed("x"));
            assert_eq!(tags(&o), ["write:pw", "keep", "delete"], "{m:?}");
        }
        // Kind None: everything goes.
        let o = secret_intents(RemoteKind::None, SudoMode::Auto, typed("pw"), none, none);
        assert_eq!(tags(&o), ["delete", "delete", "delete"]);
    }

    const KEEP: SecretInput<'static> = SecretInput {
        typed: "",
        delete: false,
    };

    fn typed(t: &str) -> SecretInput<'_> {
        SecretInput {
            typed: t,
            delete: false,
        }
    }

    /// A plan for an SSH host; `shown` = the host as the editor showed it when saving.
    fn ssh_plan(login: SecretInput<'_>, before: Option<Host>, shown: &Host) -> SavePlan {
        SavePlan {
            intents: Some(secret_intents(
                RemoteKind::Ssh,
                SudoMode::Nopasswd,
                login,
                KEEP,
                KEEP,
            )),
            forget_if_unmanaged: true,
            before,
            shown: SecretBinding::for_host(shown),
        }
    }

    #[test]
    fn save_plan_binds_rebinds_and_reports_stale() {
        let store = SecretStore::in_memory();
        let mut h = ssh_host();
        let id = h.id;
        store
            .set_for_host(&h, SecretKind::KeyPassphrase, "", "old")
            .unwrap();
        store
            .set_for_host(&h, SecretKind::Sudo, "", "sudo-old")
            .unwrap();
        // Saved with NOPASSWD and a typed login password.
        h.remote.as_mut().unwrap().sudo = CoreSudo::NoPasswd;
        let plan = ssh_plan(typed("login!"), Some(h.clone()), &h);
        assert!(!plan.is_noop(true));
        let out = apply_save_plan(&store, Some(&h), &plan);
        assert!(out.errors.is_empty() && out.stale.is_empty(), "{out:?}");
        let login = store.get(id, SecretKind::Login).unwrap().unwrap();
        assert_eq!(login.user, "admin", "SSH: the login user");
        assert_eq!(login.secret.as_str(), "login!");
        assert_eq!(
            store.state(&h, SecretKind::Login).unwrap(),
            SecretState::Usable,
            "bound to the saved host"
        );
        assert!(store.has(id, SecretKind::KeyPassphrase).unwrap(), "kept");
        assert!(
            !store.has(id, SecretKind::Sudo).unwrap(),
            "NOPASSWD deletes it"
        );

        // The user moved the host to another management address: the password follows.
        let mut moved = h.clone();
        moved.remote.as_mut().unwrap().address = Some(HostAddr::parse("100.105.1.3").unwrap());
        assert!(matches!(
            store.state(&moved, SecretKind::Login).unwrap(),
            SecretState::Stale { .. }
        ));
        // Review S3: an import re-pointed it while the editor showed the old address: the
        // password does NOT follow (the user did not change the address), and nothing is
        // confirmed for the new one.
        let untouched = ssh_plan(KEEP, Some(h.clone()), &h);
        assert!(!untouched.saved_as_shown(&moved));
        let out = apply_save_plan(&store, Some(&moved), &untouched);
        assert!(out.errors.is_empty(), "{out:?}");
        assert!(matches!(
            store.state(&moved, SecretKind::Login).unwrap(),
            SecretState::Stale { .. }
        ));
        // Edited in the editor, but saved with yet another address (changed meanwhile): not
        // moved either.
        let mut elsewhere = moved.clone();
        elsewhere.remote.as_mut().unwrap().address = Some(HostAddr::parse("100.105.1.4").unwrap());
        let out = apply_save_plan(
            &store,
            Some(&elsewhere),
            &ssh_plan(KEEP, Some(h.clone()), &moved),
        );
        assert!(out.errors.is_empty(), "{out:?}");
        assert!(matches!(
            store.state(&elsewhere, SecretKind::Login).unwrap(),
            SecretState::Stale { .. }
        ));
        // The user changed it in the editor and it was saved so: the password follows.
        let keep = ssh_plan(KEEP, Some(h.clone()), &moved);
        assert!(!keep.is_noop(true), "a managed host is always checked");
        assert!(keep.saved_as_shown(&moved) && keep.endpoint_edited());
        let out = apply_save_plan(&store, Some(&moved), &keep);
        assert!(out.errors.is_empty() && out.stale.is_empty(), "{out:?}");
        assert_eq!(
            store.state(&moved, SecretKind::Login).unwrap(),
            SecretState::Usable
        );

        // Another login user: not moved; the user is told to enter it again.
        let mut other = moved.clone();
        other.remote.as_mut().unwrap().user = Some("root".into());
        let out = apply_save_plan(
            &store,
            Some(&other),
            &ssh_plan(KEEP, Some(moved.clone()), &other),
        );
        assert_eq!(out.stale.len(), 1, "{out:?}");
        assert_eq!(out.stale[0].0, SecretKind::Login);
        assert!(out.stale[0].1.contains("admin"), "{}", out.stale[0].1);
        // Typing it again binds it to the new account.
        let out = apply_save_plan(
            &store,
            Some(&other),
            &ssh_plan(typed("root-pw"), Some(moved), &other),
        );
        assert!(out.stale.is_empty());
        assert_eq!(
            store.state(&other, SecretKind::Login).unwrap(),
            SecretState::Usable
        );
        assert_eq!(
            store.get(id, SecretKind::Login).unwrap().unwrap().user,
            "root"
        );

        // Windows without a user: the account is derived (current sign-in).
        let mut w = full_host();
        w.remote = Some(RemoteConfig::new(wol_core::RemoteKind::Windows));
        let wplan = SavePlan {
            intents: Some(secret_intents(
                RemoteKind::Windows,
                SudoMode::Auto,
                typed("pw"),
                KEEP,
                KEEP,
            )),
            forget_if_unmanaged: false,
            before: None,
            shown: SecretBinding::for_host(&w),
        };
        let out = apply_save_plan(&store, Some(&w), &wplan);
        assert!(out.errors.is_empty() && out.stale.is_empty(), "{out:?}");
        assert_eq!(
            store.get(w.id, SecretKind::Login).unwrap().unwrap().user,
            wol_core::remote::current_windows_account().unwrap_or_default()
        );
        assert_eq!(
            store.state(&w, SecretKind::Login).unwrap(),
            SecretState::Usable
        );

        // Switched to "None" by the user: every secret goes.
        let mut off = other.clone();
        off.remote = None;
        let removal = SavePlan {
            intents: None,
            forget_if_unmanaged: true,
            before: Some(other.clone()),
            shown: None,
        };
        assert!(!removal.is_noop(false));
        apply_save_plan(&store, Some(&off), &removal);
        assert_eq!(store.status(id).unwrap(), SecretStatus::default());
        // An unmanaged host that was not switched off keeps whatever is stored.
        store
            .set_for_host(&other, SecretKind::Login, "", "x")
            .unwrap();
        assert!(SavePlan::default().is_noop(false));
        apply_save_plan(&store, Some(&off), &SavePlan::default());
        assert!(store.has(id, SecretKind::Login).unwrap());
        // A host that is gone: nothing (never delete by accident).
        apply_save_plan(&store, None, &removal);
        assert!(store.has(id, SecretKind::Login).unwrap());
        // Unmanaged before and after, nothing typed: nothing to do.
        let nothing = SavePlan {
            intents: Some(SecretOverrides::default()),
            forget_if_unmanaged: false,
            before: Some(full_host()),
            shown: None,
        };
        assert!(nothing.is_noop(true) && nothing.is_noop(false));
    }

    /// Cross review X2 / m3: the editor's save confirms the current Windows sign-in for a
    /// Windows host without a password (never with a saved one, never for SSH), and key file
    /// problems are found (network paths refuse the save, `.pub` / missing files warn).
    #[test]
    fn save_confirms_the_sign_in_and_checks_the_key_file() {
        use wol_core::remote::{SystemSsh, SystemWindows};
        let store = SecretStore::in_memory();
        let client = RemoteClient::new(
            store.clone(),
            std::sync::Arc::new(SystemWindows),
            std::sync::Arc::new(SystemSsh),
        );
        let mut w = Host::new("PC", MacAddr::parse("02:00:00:00:00:01").unwrap());
        w.address = Some(HostAddr::parse("192.0.2.10").unwrap());
        w.remote = Some(RemoteConfig::new(wol_core::RemoteKind::Windows));
        assert!(confirm_after_save(&client, &w));
        assert!(!confirm_after_save(&client, &w), "once");
        assert!(store.sign_in_confirmed(&w).unwrap());
        let mut with_pw = w.clone();
        with_pw.id = HostId::new_v4();
        store
            .set_for_host(&with_pw, SecretKind::Login, r"PC\admin", "pw")
            .unwrap();
        assert!(!confirm_after_save(&client, &with_pw));
        assert!(!store.sign_in_confirmed(&with_pw).unwrap());
        assert!(!confirm_after_save(&client, &ssh_host()));

        assert_eq!(
            network_key_file(r#" "\\srv\keys\id" "#).as_deref(),
            Some(r"\\srv\keys\id")
        );
        assert_eq!(network_key_file(r"C:\keys\id"), None);
        assert_eq!(network_key_file(""), None);
        let mut k = ssh_host();
        k.remote.as_mut().unwrap().key_file = Some(r"C:\no\such\folder\id_ed25519".into());
        assert!(matches!(
            key_file_problem(&k),
            Some(GuiText::KeyFileMissing(_))
        ));
        k.remote.as_mut().unwrap().key_file = Some(r"C:\no\such\folder\id_ed25519.pub".into());
        assert!(matches!(
            key_file_problem(&k),
            Some(GuiText::KeyFileIsPublic(_))
        ));
        k.remote.as_mut().unwrap().key_file = None;
        assert_eq!(key_file_problem(&k), None);
        assert_eq!(key_file_problem(&w), None, "Windows hosts have no key file");
    }

    /// Review C2: the Credential Manager work of a store operation is queued by the store
    /// thread when the operation is written, so it also runs when the UI never sees the
    /// result (quit or logoff right after a delete / save): the exit's store flush and
    /// secret-queue flush are enough. A failed operation drops its work.
    #[test]
    fn secret_work_is_queued_by_the_store_thread() {
        use crate::persist::StoreHandle;
        use crate::workers::SerialQueue;
        use std::sync::Arc;
        use std::time::Duration;
        use wol_core::remote::{SystemSsh, SystemWindows};
        use wol_core::store::{ConfigLocation, Store};

        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(ConfigLocation::custom(dir.path()));
        let mut h = Host::new("PC", MacAddr::parse("02:00:00:00:00:01").unwrap());
        h.address = Some(HostAddr::parse("192.0.2.40").unwrap());
        h.remote = Some(RemoteConfig::new(wol_core::RemoteKind::Ssh));
        store.update(|c| c.insert_host(h.clone())).unwrap();
        let secrets = SecretStore::in_memory();
        secrets
            .set_for_host(&h, SecretKind::Login, "", "pw")
            .unwrap();
        let client = RemoteClient::new(
            secrets.clone(),
            Arc::new(SystemWindows),
            Arc::new(SystemSsh),
        );
        let queue = Arc::new(SerialQueue::new("secrets-c2"));
        let jobs: Arc<Mutex<HashMap<u64, SecretJob>>> = Arc::default();
        let handle = {
            let (q, j, c) = (queue.clone(), jobs.clone(), client.clone());
            StoreHandle::start(store, None, move |ev| hand_off_secret_job(&j, &q, &c, &ev))
        };
        // A failed operation (unknown host): its work is dropped, nothing deleted.
        jobs.lock()
            .unwrap()
            .insert(1, SecretJob::Delete { id: h.id });
        handle.update(
            1,
            Op::DeleteHost {
                id: HostId::new_v4(),
            },
        );
        assert!(handle.flush(Duration::from_secs(10)));
        assert!(queue.flush(Duration::from_secs(10)));
        assert!(jobs.lock().unwrap().is_empty(), "taken and dropped");
        assert!(secrets.has(h.id, SecretKind::Login).unwrap());
        // The delete of the host: its passwords go although nobody handles the result.
        jobs.lock()
            .unwrap()
            .insert(2, SecretJob::Delete { id: h.id });
        handle.update(2, Op::DeleteHost { id: h.id });
        assert!(handle.shutdown(Duration::from_secs(10)));
        assert!(queue.flush(Duration::from_secs(10)));
        assert!(jobs.lock().unwrap().is_empty());
        assert!(!secrets.has(h.id, SecretKind::Login).unwrap());
        assert!(queue.is_idle());
    }

    #[test]
    fn secret_view_marks_usable_and_stale() {
        let store = SecretStore::in_memory();
        let h = ssh_host();
        assert_eq!(secret_view(&store, &h).unwrap(), SecretView::default());
        for (kind, s) in [
            (SecretKind::Login, "pw"),
            (SecretKind::KeyPassphrase, "pp"),
            (SecretKind::Sudo, "sudo"),
        ] {
            store.set_for_host(&h, kind, "", s).unwrap();
        }
        let v = secret_view(&store, &h).unwrap();
        assert!(v.usable.login && v.usable.key_passphrase && v.usable.sudo);
        assert!(v.stale.is_empty());
        // The host now points at a Windows PC (e.g. after an import): the passwords are not
        // used any more; the key passphrase (local only) still is.
        let mut w = h.clone();
        w.remote = Some(RemoteConfig::new(wol_core::RemoteKind::Windows));
        let v = secret_view(&store, &w).unwrap();
        assert!(!v.usable.login && v.usable.key_passphrase && !v.usable.sudo);
        let kinds: Vec<SecretKind> = v.stale.iter().map(|s| s.0).collect();
        assert_eq!(
            kinds,
            vec![SecretKind::Login],
            "sudo only matters for `separate`"
        );
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
    fn duplicate_keeps_the_remote_table_but_no_secrets() {
        let h = ssh_host();
        let mut cfg = Config::default();
        cfg.hosts.push(h.clone());
        let tmpl = HostDraft::from_host(&h);
        let mut f = fields_from_draft(
            &tmpl,
            IfaceChoice {
                index: IFACE_KEEP,
                pinned_count: 1,
                missing: true,
            },
        );
        f.name = "NAS copy".into();
        let s = EditorSession {
            mode: EditorMode::Duplicate,
            base: None,
            template: Some(h.clone()),
            pins: h.interfaces.clone(),
            initial_index: IFACE_KEEP,
            options: Vec::new(),
            copy_name: None,
            new_id: HostId::new_v4(),
            token: 1,
            remote_base: tmpl.remote.clone(),
            opened: None,
            host_key_line: tmpl.remote.host_key.clone(),
            test_seq: 0,
            lookup_seq: 0,
            test_shown: None,
            arp_text: Text::Empty,
            mac_candidates: Vec::new(),
        };
        apply_op(
            &mut cfg,
            &Op::SaveHost {
                draft: draft_from_fields(&f, &s),
                kind: SaveKind::Copy {
                    template: Box::new(h.clone()),
                    id: s.new_id,
                },
            },
        )
        .unwrap();
        let copy = cfg.get(s.new_id).unwrap();
        assert_eq!(
            copy.remote, h.remote,
            "public remote settings (incl. key) copied"
        );
        // Secrets are keyed by the host id: the copy's store entries are empty.
        let store = SecretStore::in_memory();
        store.set_for_host(&h, SecretKind::Login, "", "pw").unwrap();
        assert_eq!(store.status(s.new_id).unwrap(), SecretStatus::default());
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
        for m in [
            CoreSudo::Auto,
            CoreSudo::Root,
            CoreSudo::NoPasswd,
            CoreSudo::Password,
            CoreSudo::Separate,
        ] {
            assert_eq!(sudo_to_core(sudo_from_core(m)), m);
        }
        for k in [
            None,
            Some(wol_core::RemoteKind::Windows),
            Some(wol_core::RemoteKind::Ssh),
        ] {
            assert_eq!(kind_to_core(kind_from_core(k)), k);
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
        // Remote user names depend on the kind; kind None never complains.
        assert_eq!(check_remote_user("", RemoteKind::Windows), FieldIssue::None);
        assert_eq!(
            check_remote_user("DESKTOP-1\\admin", RemoteKind::Windows),
            FieldIssue::None
        );
        assert_eq!(
            check_remote_user("山田", RemoteKind::Windows),
            FieldIssue::None
        );
        assert_eq!(
            check_remote_user("a:b", RemoteKind::Windows),
            FieldIssue::InvalidUser
        );
        assert_eq!(
            check_remote_user("two words", RemoteKind::Ssh),
            FieldIssue::InvalidUser
        );
        assert_eq!(
            check_remote_user("あ", RemoteKind::Ssh),
            FieldIssue::ImeKana
        );
        assert_eq!(check_remote_user("a:b", RemoteKind::None), FieldIssue::None);
    }

    #[test]
    fn issues_mapping_opens_sections() {
        let errs = vec![
            FieldError::new(Field::Mac, wol_core::FieldIssue::InvalidMac),
            FieldError::new(Field::Port, wol_core::FieldIssue::InvalidPort),
            FieldError::new(Field::Mac, wol_core::FieldIssue::Required),
        ];
        let i = issues_from(&errs);
        assert_eq!(i.mac, FieldIssue::InvalidMac);
        assert_eq!(i.port, FieldIssue::InvalidPort);
        assert!(i.advanced());
        assert!(!i.remote());
        assert!(!i.is_empty());
        assert!(issues_from(&[]).is_empty());
        // Remote fields: their slots; fields without a slot become a toast.
        let errs = vec![
            FieldError::new(Field::RemoteAddress, wol_core::FieldIssue::InvalidAddress),
            FieldError::new(Field::SshHostKey, wol_core::FieldIssue::InvalidHostKey),
            FieldError::new(Field::RebootCommand, wol_core::FieldIssue::InvalidCommand),
        ];
        let i = issues_from(&errs);
        assert_eq!(i.remote_address, FieldIssue::InvalidAddress);
        assert!(i.remote());
        assert_eq!(
            i.other,
            Some(FieldError::new(
                Field::SshHostKey,
                wol_core::FieldIssue::InvalidHostKey
            ))
        );
        let only_other = issues_from(&[FieldError::new(
            Field::ShutdownCommand,
            wol_core::FieldIssue::InvalidCommand,
        )]);
        assert!(!only_other.is_empty() && !only_other.remote());
        // The v0.2 issues map 1:1.
        assert_eq!(
            issue(wol_core::FieldIssue::InvalidCommand),
            FieldIssue::InvalidCommand
        );
        assert_eq!(
            issue(wol_core::FieldIssue::InvalidHostKey),
            FieldIssue::InvalidHostKey
        );
        assert_eq!(
            issue(wol_core::FieldIssue::InvalidUser),
            FieldIssue::InvalidUser
        );
    }

    #[test]
    fn mac_candidate_rows_and_test_notes() {
        let c = |iface: &str, mac: &str, score: i32| MacCandidate {
            iface: iface.into(),
            mac: MacAddr::parse(mac).unwrap(),
            permanent_mac: None,
            current_mac: None,
            kind: NicKind::Physical,
            on_default_route: false,
            via: None,
            link_up: true,
            wol_enabled: None,
            lan_ipv4: None,
            score,
        };
        let mut a = c("enp3s0", "00:11:22:33:44:01", 90);
        a.lan_ipv4 = Some("192.168.1.20/24".parse().unwrap());
        a.via = Some("vmbr0".into());
        a.on_default_route = true;
        let mut b = c("wlan0", "00:11:22:33:44:02", 90);
        b.kind = NicKind::Wifi;
        b.link_up = false;
        let rows = candidate_rows(&[a, b]);
        assert_eq!(rows[0].iface, "enp3s0");
        assert_eq!(rows[0].mac, "00:11:22:33:44:01");
        assert_eq!(rows[0].detail, "192.168.1.20/24 · vmbr0");
        assert!(rows[0].default_route && rows[0].link_up);
        assert_eq!(rows[1].kind, MacKind::Wifi);
        assert_eq!(rows[1].detail, "");
        assert!(!rows[1].link_up);
        assert_eq!(rows[1].score, 90);

        let now = SystemTime::now();
        let info = |check: AdminCheck| ConnInfo {
            os: Some("Windows 11 Pro".into()),
            boot: BootInfo {
                boot_time: now,
                uptime: std::time::Duration::ZERO,
                source: "t".into(),
                approximate: false,
                boot_id: None,
            },
            admin_hint: None,
            admin_check: check,
            user: None,
            kernel: None,
        };
        let note = |check| match test_note(&info(check)) {
            Text::Msg(m) => Some(*m),
            _ => None,
        };
        assert_eq!(note(AdminCheck::NotAdmin), Some(Msg::RemoteNotAdmin));
        // Review R3: UAC-filtered token, firewall and unknown are told apart.
        assert_eq!(note(AdminCheck::WmiDenied), Some(Msg::RemoteWmiDenied));
        assert_eq!(
            note(AdminCheck::WmiUnreachable),
            Some(Msg::RemoteWmiUnreachable)
        );
        assert_eq!(note(AdminCheck::Unknown), Some(Msg::RemoteAdminUnknown));
        assert_eq!(test_note(&info(AdminCheck::Admin)), Text::Empty);
        assert_eq!(
            test_note(&info(AdminCheck::NotChecked)),
            Text::Empty,
            "this PC"
        );
        // Invalid pinned lines are still shown (so that they can be forgotten).
        assert_eq!(
            host_key_display("ssh-rsa garbage"),
            ("ssh-rsa".to_owned(), "ssh-rsa garbage".to_owned())
        );
    }
}
