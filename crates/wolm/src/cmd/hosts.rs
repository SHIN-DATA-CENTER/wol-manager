//! `list`, `show`, `add`, `edit`, `remove`.

use serde::Serialize;
use wol_core::i18n::{Header, Msg};
use wol_core::secret;
use wol_core::{EditBase, Error, Field, FieldIssue, Host, HostAddr, HostDraft, HostId, Settings};

use super::mac;
use super::remote::RemoteView;
use crate::backend;
use crate::cli::{AddArgs, EditArgs, HostFields, ListArgs, RemoveArgs, ShowArgs};
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::output::table::{Cell, key_values};
use crate::output::{self, Table};
use crate::text::Text;
use crate::util;

/// JSON view of a host. The SecureOn password is never printed, only whether it is set.
#[derive(Debug, Serialize)]
pub struct HostView<'a> {
    id: HostId,
    name: &'a str,
    mac: String,
    address: Option<String>,
    group: Option<&'a str>,
    notes: Option<&'a str>,
    port: Option<u16>,
    effective_port: u16,
    secureon: bool,
    targets: Vec<String>,
    broadcast: bool,
    interfaces: &'a [String],
    probe: Option<&'static str>,
    effective_probe: &'static str,
    tcp_ports: &'a [u16],
    effective_tcp_ports: &'a [u16],
    /// Remote management (`null` when not set up). Passwords are never part of it.
    remote: Option<RemoteView<'a>>,
}

impl<'a> HostView<'a> {
    pub fn new(h: &'a Host, s: &'a Settings) -> HostView<'a> {
        HostView {
            id: h.id,
            name: &h.name,
            mac: h.mac.to_string(),
            address: h.address.as_ref().map(ToString::to_string),
            group: h.group.as_deref(),
            notes: h.notes.as_deref(),
            port: h.port,
            effective_port: h.effective_port(s),
            secureon: h.secureon.is_some(),
            targets: h.targets.iter().map(ToString::to_string).collect(),
            broadcast: h.broadcast,
            interfaces: &h.interfaces,
            probe: h.probe.map(|p| p.as_str()),
            effective_probe: h.effective_probe(s).as_str(),
            tcp_ports: &h.tcp_ports,
            effective_tcp_ports: h.effective_tcp_ports(s),
            remote: RemoteView::of(h),
        }
    }
}

fn dash(s: Option<&str>) -> String {
    match s {
        Some(v) if !v.trim().is_empty() => v.to_owned(),
        _ => "-".to_owned(),
    }
}

/// First line of a multi-line text (notes in tables).
fn first_line(s: Option<&str>) -> String {
    let s = dash(s);
    match s.lines().next() {
        Some(l) if s.lines().count() > 1 => format!("{l} ..."),
        Some(l) => l.to_owned(),
        None => s,
    }
}

pub fn list(ctx: &mut Ctx, a: &ListArgs) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let hosts: Vec<&Host> = match &a.group {
        Some(g) => {
            let v = cfg.hosts_in_group(g);
            if v.is_empty() {
                return Err(Error::GroupNotFound(g.clone()).into());
            }
            v
        }
        None => cfg.hosts.iter().collect(),
    };
    if ctx.json() {
        let v: Vec<HostView> = hosts
            .iter()
            .map(|h| HostView::new(h, &cfg.settings))
            .collect();
        ctx.print_json(&v);
        return Ok(exit::OK);
    }
    if hosts.is_empty() {
        ctx.info(&ctx.t(Msg::NoHosts));
        return Ok(exit::OK);
    }
    let h = |x| ctx.t(Msg::Header(x));
    let mut headers = vec![
        h(Header::Name),
        h(Header::Mac),
        h(Header::Address),
        h(Header::Group),
    ];
    let verbose = ctx.verbose() > 0;
    if verbose {
        headers.push(h(Header::Notes));
        headers.push(h(Header::Id));
    }
    let mut t = Table::new(headers);
    for host in hosts {
        let mut row = vec![
            Cell::styled(host.name.clone(), output::BOLD),
            Cell::plain(host.mac.to_string()),
            Cell::plain(dash(
                host.address.as_ref().map(ToString::to_string).as_deref(),
            )),
            Cell::plain(dash(host.group.as_deref())),
        ];
        if verbose {
            row.push(Cell::plain(first_line(host.notes.as_deref())));
            row.push(Cell::styled(host.id.to_string(), output::DIM));
        }
        t.row(row);
    }
    for l in t.lines() {
        ctx.out(&l);
    }
    Ok(exit::OK)
}

pub fn show(ctx: &mut Ctx, a: &ShowArgs) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let host = cfg.find(&a.host)?;
    if ctx.json() {
        ctx.print_json(&HostView::new(host, &cfg.settings));
        return Ok(exit::OK);
    }
    for l in describe(ctx, host, &cfg.settings) {
        ctx.out(&l);
    }
    Ok(exit::OK)
}

fn describe(ctx: &Ctx, host: &Host, s: &Settings) -> Vec<String> {
    let f = |x| ctx.t(Msg::Field(x));
    let default = ctx.tx(Text::Default);
    let with_default = |set: bool, v: String| {
        if set { v } else { format!("{v}{default}") }
    };
    let join = |v: Vec<String>| {
        if v.is_empty() {
            "-".to_owned()
        } else {
            v.join(", ")
        }
    };
    let tcp: Vec<String> = host
        .effective_tcp_ports(s)
        .iter()
        .map(u16::to_string)
        .collect();
    let pairs = vec![
        (ctx.t(Msg::Header(Header::Id)), host.id.to_string()),
        (f(Field::Name), host.name.clone()),
        (f(Field::Mac), host.mac.to_string()),
        (
            f(Field::Address),
            dash(host.address.as_ref().map(ToString::to_string).as_deref()),
        ),
        (f(Field::Group), dash(host.group.as_deref())),
        (
            f(Field::Port),
            with_default(host.port.is_some(), host.effective_port(s).to_string()),
        ),
        (
            f(Field::SecureOn),
            ctx.t(if host.secureon.is_some() {
                Msg::SecureOnSet
            } else {
                Msg::NotSet
            }),
        ),
        (
            f(Field::Targets),
            join(host.targets.iter().map(ToString::to_string).collect()),
        ),
        (
            ctx.tx(Text::Broadcast),
            ctx.t(if host.broadcast { Msg::Yes } else { Msg::No }),
        ),
        (f(Field::Interfaces), join(host.interfaces.clone())),
        (
            f(Field::Probe),
            with_default(
                host.probe.is_some(),
                host.effective_probe(s).as_str().to_owned(),
            ),
        ),
        (
            f(Field::TcpPorts),
            with_default(!host.tcp_ports.is_empty(), join(tcp)),
        ),
        (
            f(Field::RemoteKind),
            match host.remote_kind() {
                Some(k) => ctx.t(Msg::RemoteKindName(k)),
                None => ctx.t(Msg::RemoteNone),
            },
        ),
    ];
    let mut lines = key_values(&pairs, 0);
    if let Some(n) = host.notes.as_deref().filter(|n| !n.trim().is_empty()) {
        let mut it = n.lines();
        let label = f(Field::Notes);
        let first = it.next().unwrap_or_default();
        let w = pairs
            .iter()
            .map(|(k, _)| output::table::width(k))
            .max()
            .unwrap_or(0);
        lines.push(format!(
            "{}{}  {first}",
            output::paint(output::BOLD, &label),
            " ".repeat(w.saturating_sub(output::table::width(&label)))
        ));
        for more in it {
            lines.push(format!("{}  {more}", " ".repeat(w)));
        }
    }
    lines
}

/// Copies the given flags into `d`. `existing` is the host being edited: its address is used
/// by `--arp` without `--address`, and its remote management when ARP cannot reach it.
fn apply_fields(
    ctx: &Ctx,
    d: &mut HostDraft,
    f: &HostFields,
    settings: &Settings,
    existing: Option<&Host>,
) -> Result<(), Failure> {
    if let Some(v) = &f.address {
        d.address = v.clone();
    }
    if f.arp {
        let current = existing.and_then(|h| h.address.as_ref().map(ToString::to_string));
        let text = f.address.as_deref().or(current.as_deref()).unwrap_or("");
        let addr = HostAddr::parse(text).map_err(|i| Error::invalid(Field::Address, i, text))?;
        // ARP on the local network, else the host's remote management (VPN peers), else an
        // explanation of why the MAC cannot be read, with the steps that work from here
        // (review R1: `add` has no remote management yet).
        d.mac = match mac::mac_for_draft(ctx, &addr, existing, settings) {
            Ok(m) => m.to_string(),
            Err(Failure::Core(e @ Error::MacNeedsRemote { .. })) => {
                let name = crate::exit::shell_arg(match existing {
                    Some(h) => &h.name,
                    None if d.name.trim().is_empty() => "NAME",
                    None => d.name.trim(),
                });
                let hint = match existing {
                    None => ctx.tx(Text::AddVpnHostSteps {
                        name: &name,
                        address: text.trim(),
                    }),
                    Some(_) => ctx.tx(Text::EditVpnHostSteps { name: &name }),
                };
                return Err(Failure::WithHint(Box::new(Failure::Core(e)), hint));
            }
            Err(f) => return Err(f),
        };
    }
    if let Some(v) = &f.mac {
        d.mac = v.clone();
    }
    if let Some(v) = &f.group {
        d.group = v.clone();
    }
    if let Some(v) = &f.notes {
        d.notes = v.clone();
    }
    if let Some(v) = &f.port {
        d.port = v.clone();
    }
    if let Some(v) = &f.secureon {
        d.secureon = v.clone();
    }
    if !f.to.is_empty() {
        d.targets = f.to.join("\n");
    }
    if !f.interface.is_empty() {
        d.interfaces = f.interface.clone();
    }
    if let Some(v) = &f.probe {
        d.probe = Some(util::parse_probe("--probe", v)?);
    }
    if !f.tcp_port.is_empty() {
        d.tcp_ports = f.tcp_port.join(", ");
    }
    Ok(())
}

pub fn add(ctx: &mut Ctx, a: &AddArgs) -> CmdResult {
    let (store, loaded) = ctx.load()?;
    let mut d = HostDraft {
        name: a.name.clone(),
        ..HostDraft::default()
    };
    if a.fields.arp && a.fields.address.is_none() {
        return Err(Error::invalid(Field::Address, FieldIssue::Required, "").into());
    }
    apply_fields(ctx, &mut d, &a.fields, &loaded.config.settings, None)?;
    if a.no_broadcast {
        d.broadcast = false;
    }
    let up = store.update(|c| c.save_draft(&d, None))?;
    let host = up
        .config
        .get(up.value)
        .ok_or(Error::HostIdNotFound(up.value))?;
    if ctx.json() {
        ctx.print_json(&HostView::new(host, &up.config.settings));
    } else {
        ctx.info(&ctx.t(Msg::HostAdded {
            name: host.name.clone(),
        }));
    }
    Ok(exit::OK)
}

pub fn edit(ctx: &mut Ctx, a: &EditArgs) -> CmdResult {
    let (store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let host = cfg.find(&a.host)?;
    let base = EditBase::of(host);
    let mut d = base.draft.clone();
    if let Some(n) = &a.name {
        d.name = n.clone();
    }
    apply_fields(ctx, &mut d, &a.fields, &cfg.settings, Some(host))?;
    if a.broadcast {
        d.broadcast = true;
    }
    if a.no_broadcast {
        d.broadcast = false;
    }
    let clears: [(bool, &mut String); 7] = [
        (a.clear_address, &mut d.address),
        (a.clear_group, &mut d.group),
        (a.clear_notes, &mut d.notes),
        (a.clear_port, &mut d.port),
        (a.clear_secureon, &mut d.secureon),
        (a.clear_targets, &mut d.targets),
        (a.clear_tcp_ports, &mut d.tcp_ports),
    ];
    for (clear, field) in clears {
        if clear {
            field.clear();
        }
    }
    if a.clear_interfaces {
        d.interfaces.clear();
    }
    if a.clear_probe {
        d.probe = None;
    }

    let unchanged = |ctx: &Ctx, cfg: &wol_core::Config, id: HostId| {
        if ctx.json() {
            if let Some(h) = cfg.get(id) {
                #[derive(Serialize)]
                struct Doc<'a> {
                    changed: bool,
                    host: HostView<'a>,
                }
                ctx.print_json(&Doc {
                    changed: false,
                    host: HostView::new(h, &cfg.settings),
                });
            }
        } else {
            ctx.info(&ctx.t(Msg::NoChanges));
        }
        Ok(exit::NEGATIVE)
    };
    if d == base.draft {
        return unchanged(ctx, cfg, base.id);
    }
    let up = store.update(|c| c.save_draft(&d, Some(&base)))?;
    if !up.written {
        return unchanged(ctx, &up.config, base.id);
    }
    let before = cfg.get(base.id);
    let host = up
        .config
        .get(up.value)
        .ok_or(Error::HostIdNotFound(up.value))?;
    if let Some(before) = before {
        // The user pointed the host at another management address: that address is confirmed
        // for the current Windows sign-in like with `remote set` (other edits confirm nothing).
        let moved = before.management_address() != host.management_address();
        super::remote::after_connection_edit(ctx, before, host, moved);
    }
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc<'a> {
            changed: bool,
            host: HostView<'a>,
        }
        ctx.print_json(&Doc {
            changed: true,
            host: HostView::new(host, &up.config.settings),
        });
    } else {
        ctx.info(&ctx.t(Msg::HostUpdated {
            name: host.name.clone(),
        }));
    }
    Ok(exit::OK)
}

pub fn remove(ctx: &mut Ctx, a: &RemoveArgs) -> CmdResult {
    let (store, loaded) = ctx.load()?;
    let mut ids: Vec<HostId> = Vec::new();
    for q in &a.hosts {
        let h = loaded.config.find(q)?;
        if !ids.contains(&h.id) {
            ids.push(h.id);
        }
    }
    let up = store.update(|c| {
        let mut removed: Vec<Host> = Vec::new();
        for id in &ids {
            match c.remove_host(*id) {
                Ok(h) => removed.push(h),
                Err(Error::HostIdNotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        if removed.is_empty() {
            return Err(Error::HostNotFound(a.hosts.join(", ")));
        }
        Ok(removed)
    })?;
    // The passwords of a removed host are useless and must not linger (after the save, so
    // a failed save keeps them).
    let secrets = backend::secret_store();
    let secrets_deleted: usize = up
        .value
        .iter()
        .map(|h| secret::forget_host(&secrets, h.id))
        .sum();
    if ctx.json() {
        #[derive(Serialize)]
        struct Removed<'a> {
            id: HostId,
            name: &'a str,
        }
        #[derive(Serialize)]
        struct Doc<'a> {
            removed: Vec<Removed<'a>>,
            secrets_deleted: usize,
        }
        ctx.print_json(&Doc {
            removed: up
                .value
                .iter()
                .map(|h| Removed {
                    id: h.id,
                    name: &h.name,
                })
                .collect(),
            secrets_deleted,
        });
    } else {
        for h in &up.value {
            ctx.info(&ctx.t(Msg::HostRemoved {
                name: h.name.clone(),
            }));
        }
        if secrets_deleted > 0 {
            ctx.info(&ctx.tx(Text::SecretsDeleted {
                count: secrets_deleted,
            }));
        }
    }
    Ok(exit::OK)
}
