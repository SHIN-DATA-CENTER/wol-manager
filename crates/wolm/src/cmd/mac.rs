//! `mac`: the MAC address of a host or an address (ARP on the LAN, else the host's remote
//! management), optionally stored in the host.

use std::net::Ipv4Addr;

use serde::Serialize;
use wol_core::i18n::{Header, Msg};
use wol_core::macfind::{MacFound, MacQuery};
use wol_core::netif::Ipv4Subnet;
use wol_core::remote::{MacCandidate, NicKind};
use wol_core::{Config, EditBase, Error, Host, HostAddr, HostId, MacAddr};

use super::remote::confirm_sign_in;
use crate::backend::Remote;
use crate::cli::MacArgs;
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::output::table::Cell;
use crate::output::{self, Table};
use crate::text::{MacCaveat, Text};
use crate::{prompt, util};

/// What `wolm mac` looks up: a registered host (maybe found by its address), and / or a
/// typed address.
fn target<'c>(cfg: &'c Config, q: &str) -> Result<(Option<&'c Host>, Option<HostAddr>), Error> {
    let not_found = match cfg.find(q) {
        Ok(h) => return Ok((Some(h), None)),
        Err(e @ Error::HostNotFound(_)) => e,
        Err(e) => return Err(e),
    };
    // An IPv4 address, or a DNS name with a dot. A single word is a mistyped host name
    // rather than something to resolve.
    let Ok(addr) = HostAddr::parse(q) else {
        return Err(not_found);
    };
    if addr.as_ipv4().is_none() && !q.contains('.') {
        return Err(not_found);
    }
    let matches: Vec<&Host> = cfg
        .hosts
        .iter()
        .filter(|h| {
            h.address.as_ref() == Some(&addr)
                || h.remote.as_ref().and_then(|r| r.address.as_ref()) == Some(&addr)
        })
        .collect();
    match matches.as_slice() {
        [] => Ok((None, Some(addr))),
        [h] => Ok((Some(h), Some(addr))),
        many => Err(Error::AmbiguousHost {
            query: q.trim().to_owned(),
            candidates: many.iter().map(|h| h.name.clone()).collect(),
        }),
    }
}

/// The MAC of candidate `n` (1-based); ARP has exactly one.
fn nth(found: &MacFound, n: usize) -> Option<MacAddr> {
    match found {
        MacFound::Arp { mac, .. } => (n == 1).then_some(*mac),
        MacFound::Remote { candidates } => candidates.get(n.checked_sub(1)?).map(|c| c.mac),
    }
}

fn count(found: &MacFound) -> usize {
    match found {
        MacFound::Arp { .. } => 1,
        MacFound::Remote { candidates } => candidates.len(),
    }
}

/// Why a candidate is not chosen automatically / may not wake the host (the most important
/// reason; `None` for a connected physical adapter with Wake-on-LAN not reported disabled).
fn caveat(c: &MacCandidate) -> Option<MacCaveat> {
    if c.wol_enabled == Some(false) {
        Some(MacCaveat::WolDisabled)
    } else if c.kind == NicKind::Wifi {
        Some(MacCaveat::Wifi)
    } else if !c.link_up {
        Some(MacCaveat::LinkDown)
    } else if c.kind != NicKind::Physical {
        Some(MacCaveat::NotPhysical)
    } else {
        None
    }
}

/// The message when no candidate is chosen automatically: the only candidate and why
/// (`host`: the `edit --arp` hint), or several and why the best one is not taken (cross
/// review m5 / n9: never "1 candidates").
fn pick_needed(ctx: &Ctx, found: &MacFound, host: Option<&str>) -> String {
    let candidates = found.candidates();
    let count = count(found);
    if let [only] = candidates
        && let Some(caveat) = caveat(only)
    {
        return ctx.tx(Text::MacSingleNeedsPick {
            iface: &only.iface,
            caveat,
            host,
        });
    }
    let caveat = candidates
        .first()
        .filter(|c| !wol_core::remote::auto_pickable(c))
        .and_then(caveat);
    match host {
        Some(host) => ctx.tx(Text::ArpSeveralAdapters {
            count,
            host,
            caveat,
        }),
        None => ctx.tx(Text::MacPickNeeded { count, caveat }),
    }
}

#[derive(Serialize)]
struct CandidateView<'a> {
    index: usize,
    iface: &'a str,
    mac: MacAddr,
    permanent_mac: Option<MacAddr>,
    current_mac: Option<MacAddr>,
    kind: NicKind,
    on_default_route: bool,
    via: Option<&'a str>,
    link_up: bool,
    wol_enabled: Option<bool>,
    lan_ipv4: Option<Ipv4Subnet>,
    recommended: bool,
}

#[derive(Serialize)]
struct MacDoc<'a> {
    host: Option<&'a str>,
    id: Option<HostId>,
    /// `arp` or `remote`.
    source: &'static str,
    /// ARP: the address that answered.
    ip: Option<Ipv4Addr>,
    /// ARP: its MAC.
    mac: Option<MacAddr>,
    /// Remote: the host's adapters, best first.
    candidates: Vec<CandidateView<'a>>,
    /// The MAC chosen (`--pick`, or the unambiguous best), else `null`.
    selected: Option<MacAddr>,
    saved: bool,
    changed: bool,
}

pub fn run(ctx: &mut Ctx, a: &MacArgs) -> CmdResult {
    let pick = a
        .pick
        .as_deref()
        .map(|v| util::parse_uint("--pick", v, 1..=999).map(|n| n as usize))
        .transpose()?;
    let (store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let (host, addr) = target(cfg, &a.target)?;
    if a.save && host.is_none() {
        return Err(Failure::Usage(ctx.tx(Text::MacSaveNeedsHost)));
    }
    let remote = Remote::new()?;
    if let Some(h) = host.filter(|h| h.remote.is_some()) {
        // The user asked for this host: it may use the current Windows sign-in (X2).
        confirm_sign_in(ctx, remote.client(), &[h]);
    }
    let found = remote.find_mac(
        &MacQuery {
            address: addr.as_ref(),
            host,
        },
        &cfg.settings,
    )?;
    let n = count(&found);
    let best = found.unique();
    let mut chosen = match pick {
        Some(p) if p > n => {
            return Err(Failure::Usage(
                ctx.tx(Text::MacPickOutOfRange { n: p, count: n }),
            ));
        }
        Some(p) => nth(&found, p),
        None => best,
    };
    let label = host
        .map(|h| h.name.clone())
        .unwrap_or_else(|| a.target.trim().to_owned());
    if !ctx.json() {
        print_found(ctx, &label, &found, best);
    }
    for c in found.candidates() {
        if c.wol_enabled == Some(false) {
            ctx.warn(&ctx.t(Msg::WolDisabledOn {
                iface: c.iface.clone(),
            }));
        }
    }

    let mut changed = false;
    if a.save {
        let h = host.expect("checked above");
        let mac = match chosen {
            Some(m) => m,
            None if ctx.interactive() => {
                match prompt::ask_number(&ctx.tx(Text::MacPickPrompt { count: n }), n)
                    .and_then(|i| nth(&found, i))
                {
                    Some(m) => m,
                    None => {
                        ctx.warn(&ctx.tx(Text::Declined));
                        return Ok(exit::NEGATIVE);
                    }
                }
            }
            None => return Err(Failure::Usage(pick_needed(ctx, &found, None))),
        };
        chosen = Some(mac);
        // Wi-Fi / not connected / not physical: say so (WoL disabled was said above).
        if let Some((c, cv)) = found
            .candidates()
            .iter()
            .find(|c| c.mac == mac)
            .and_then(|c| caveat(c).map(|cv| (c, cv)))
            .filter(|(_, cv)| *cv != MacCaveat::WolDisabled)
        {
            ctx.warn(&ctx.tx(Text::MacChosenCaveat {
                iface: &c.iface,
                caveat: cv,
            }));
        }
        let base = EditBase::of(h);
        let mut d = base.draft.clone();
        d.mac = mac.to_string();
        if d != base.draft {
            let up = store.update(|c| c.save_draft(&d, Some(&base)))?;
            changed = up.written;
        }
        if !ctx.json() {
            if changed {
                ctx.info(&ctx.t(Msg::HostUpdated {
                    name: h.name.clone(),
                }));
            } else {
                ctx.info(&ctx.t(Msg::NoChanges));
            }
        }
    }

    if ctx.json() {
        let (source, ip, mac) = match &found {
            MacFound::Arp { ip, mac } => ("arp", Some(*ip), Some(*mac)),
            MacFound::Remote { .. } => ("remote", None, None),
        };
        let candidates = found
            .candidates()
            .iter()
            .enumerate()
            .map(|(i, c)| candidate_view(i, c, best))
            .collect();
        ctx.print_json(&MacDoc {
            host: host.map(|h| h.name.as_str()),
            id: host.map(|h| h.id),
            source,
            ip,
            mac,
            candidates,
            selected: chosen,
            saved: a.save,
            changed,
        });
    }
    Ok(exit::OK)
}

fn candidate_view<'a>(i: usize, c: &'a MacCandidate, best: Option<MacAddr>) -> CandidateView<'a> {
    CandidateView {
        index: i + 1,
        iface: &c.iface,
        mac: c.mac,
        permanent_mac: c.permanent_mac,
        current_mac: c.current_mac,
        kind: c.kind,
        on_default_route: c.on_default_route,
        via: c.via.as_deref(),
        link_up: c.link_up,
        wol_enabled: c.wol_enabled,
        lan_ipv4: c.lan_ipv4,
        recommended: i == 0 && best == Some(c.mac),
    }
}

fn print_found(ctx: &Ctx, label: &str, found: &MacFound, best: Option<MacAddr>) {
    let candidates = match found {
        MacFound::Arp { ip, mac } => {
            ctx.out(&ctx.t(Msg::ArpFound {
                ip: *ip,
                mac: mac.to_string(),
            }));
            return;
        }
        MacFound::Remote { candidates } => candidates,
    };
    if best.is_none() {
        ctx.info(&ctx.t(Msg::MacCandidatesFound {
            label: label.to_owned(),
            count: candidates.len(),
        }));
    }
    let hd = |x| ctx.t(Msg::Header(x));
    let mut t = Table::new(vec![
        "#".to_owned(),
        hd(Header::Interface),
        hd(Header::Mac),
        hd(Header::Kind),
        hd(Header::Ipv4),
        String::new(),
    ]);
    for (i, c) in candidates.iter().enumerate() {
        let mut badges: Vec<String> = Vec::new();
        if i == 0 && best == Some(c.mac) {
            badges.push(ctx.t(Msg::MacRecommended));
        }
        if c.on_default_route {
            badges.push(ctx.t(Msg::MacDefaultRoute));
        }
        if !c.link_up {
            badges.push(ctx.t(Msg::MacLinkDown));
        }
        let mut name = c.iface.clone();
        if let Some(v) = c.via.as_deref().filter(|v| *v != c.iface) {
            name = format!("{name} ({v})");
        }
        let mac = match c.current_mac {
            Some(cur) if ctx.verbose() > 0 => format!("{} [{cur}]", c.mac),
            _ => c.mac.to_string(),
        };
        t.row(vec![
            Cell::plain((i + 1).to_string()),
            Cell::styled(name, output::BOLD),
            Cell::plain(mac),
            Cell::plain(ctx.t(Msg::NicKindName(c.kind))),
            Cell::plain(
                c.lan_ipv4
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
            ),
            Cell::styled(badges.join(", "), output::DIM),
        ]);
    }
    for l in t.lines() {
        ctx.out(&l);
    }
}

/// `add --arp` / `edit --arp`: one MAC for `addr` (ARP, or the host's unambiguous best
/// adapter). Several equally good adapters: exit 2 with a pointer to `wolm mac`.
pub fn mac_for_draft(
    ctx: &Ctx,
    addr: &HostAddr,
    host: Option<&Host>,
    settings: &wol_core::Settings,
) -> Result<MacAddr, Failure> {
    let remote = Remote::new()?;
    if let Some(h) = host.filter(|h| h.remote.is_some()) {
        // `edit HOST --arp`: the user asked for this host (X2).
        confirm_sign_in(ctx, remote.client(), &[h]);
    }
    let found = remote.find_mac(
        &MacQuery {
            address: Some(addr),
            host,
        },
        settings,
    )?;
    match found.unique() {
        Some(m) => Ok(m),
        None => {
            let arg = crate::exit::shell_arg(host.map_or("HOST", |h| h.name.as_str()));
            Err(Failure::Usage(pick_needed(ctx, &found, Some(&arg))))
        }
    }
}
