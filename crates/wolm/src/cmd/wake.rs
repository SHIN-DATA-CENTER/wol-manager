//! `wake`: magic packets, `--dry-run` plan, `--wait` verification.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Serialize;
use wol_core::i18n::{Header, Msg};
use wol_core::probe::{self, HostState, ProbeSpec, WaitOutcome};
use wol_core::send::{self, PlanNote, SendPlan, Via, WakeOutcome, WakeReport, WakeRequest};
use wol_core::{Error, Host, HostId, MacAddr, mac};

use crate::cli::WakeArgs;
use crate::ctrlc;
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::output::table::Cell;
use crate::output::{self, Table};
use crate::text::Text;
use crate::util;

/// Default `--poll`.
const DEFAULT_POLL: Duration = Duration::from_secs(2);

/// One thing to wake: the request, and the host for `--wait`.
struct Item {
    req: WakeRequest,
    host: Option<Host>,
}

fn push(items: &mut Vec<Item>, req: WakeRequest, host: Option<&Host>) {
    let dup = items.iter().any(|i| match (req.host_id, i.req.host_id) {
        (Some(a), Some(b)) => a == b,
        (None, None) => i.req.mac == req.mac,
        _ => false,
    });
    if !dup {
        items.push(Item {
            req,
            host: host.cloned(),
        });
    }
}

pub fn run(ctx: &mut Ctx, a: &WakeArgs) -> CmdResult {
    // Parse every flag before anything is looked up or sent.
    let port = a.port.as_deref().map(util::parse_port).transpose()?;
    let secureon = a
        .secureon
        .as_deref()
        .map(util::parse_secureon)
        .transpose()?;
    let targets =
        a.to.iter()
            .map(|t| util::parse_target(t))
            .collect::<Result<Vec<_>, _>>()?;
    let repeat = a
        .repeat
        .as_deref()
        .map(|v| util::parse_uint("--repeat", v, 1..=10))
        .transpose()?;
    let interval = a
        .interval_ms
        .as_deref()
        .map(|v| util::parse_uint("--interval-ms", v, 0..=5000))
        .transpose()?;
    let macs = a
        .mac
        .iter()
        .map(|m| util::parse_mac(m))
        .collect::<Result<Vec<_>, _>>()?;
    let timeout = a
        .timeout
        .as_deref()
        .map(|v| util::parse_duration("--timeout", v))
        .transpose()?;
    let poll = a
        .poll
        .as_deref()
        .map(|v| util::parse_duration("--poll", v))
        .transpose()?
        .unwrap_or(DEFAULT_POLL)
        .max(Duration::from_millis(200));
    let probe_method = a
        .probe
        .as_deref()
        .map(|v| util::parse_probe("--probe", v))
        .transpose()?;
    let tcp_ports = if a.tcp_port.is_empty() {
        None
    } else {
        Some(util::parse_ports(&a.tcp_port)?)
    };

    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let settings = &cfg.settings;

    let mut items: Vec<Item> = Vec::new();
    for q in &a.targets {
        match cfg.find(q) {
            Ok(h) => push(&mut items, WakeRequest::for_host(h, settings), Some(h)),
            Err(Error::HostNotFound(_)) if mac::looks_like_mac(q) => {
                let m = util::parse_mac(q)?;
                push(&mut items, WakeRequest::adhoc(m, settings), None);
            }
            Err(e) => return Err(e.into()),
        }
    }
    for m in &macs {
        push(&mut items, WakeRequest::adhoc(*m, settings), None);
    }
    for g in &a.group {
        let hosts = cfg.hosts_in_group(g);
        if hosts.is_empty() {
            return Err(Error::GroupNotFound(g.clone()).into());
        }
        for h in hosts {
            push(&mut items, WakeRequest::for_host(h, settings), Some(h));
        }
    }
    if a.all {
        if cfg.hosts.is_empty() {
            return Err(Failure::NotFound(ctx.t(Msg::NoHosts)));
        }
        for h in &cfg.hosts {
            push(&mut items, WakeRequest::for_host(h, settings), Some(h));
        }
    }
    if items.is_empty() {
        return Err(Failure::Usage(ctx.tx(Text::NothingToWake)));
    }

    for it in &mut items {
        let r = &mut it.req;
        if let Some(p) = port {
            r.port = p;
        }
        if let Some(s) = secureon {
            r.secureon = Some(s);
        }
        for t in &targets {
            if !r.targets.contains(t) {
                r.targets.push(t.clone());
            }
        }
        if !a.interface.is_empty() {
            r.filter.pinned = a
                .interface
                .iter()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if a.all_interfaces {
            r.filter.include_virtual = true;
            r.filter.pinned.clear();
        }
        if a.no_broadcast {
            r.broadcast = false;
            r.limited_broadcast = false;
        }
        if let Some(n) = repeat {
            r.repeat = n as u8;
        }
        if let Some(ms) = interval {
            r.interval = Duration::from_millis(ms);
        }
    }

    if a.dry_run {
        return dry_run(ctx, &items);
    }

    // --wait: decide before sending what can be verified.
    let mut specs: Vec<Option<ProbeSpec>> = Vec::new();
    if a.wait {
        for it in &items {
            let spec = it.host.as_ref().map(|h| {
                let mut s = ProbeSpec::for_host(h, settings);
                if let Some(m) = probe_method {
                    s.method = m;
                }
                if let Some(p) = &tcp_ports {
                    s.tcp_ports = p.clone();
                }
                s
            });
            specs.push(spec.filter(ProbeSpec::is_monitored));
        }
        if specs.iter().all(Option::is_none) {
            return Err(Failure::Usage(ctx.tx(Text::WaitNeedsAddress)));
        }
    }

    let reqs: Vec<WakeRequest> = items.iter().map(|i| i.req.clone()).collect();
    let reports = send::wake_many(&reqs);
    let mut code = exit::OK;
    for r in &reports {
        print_report(ctx, r);
        if r.outcome() == WakeOutcome::Failed {
            code = exit::NETWORK;
        }
    }

    if !a.wait {
        if ctx.json() {
            ctx.print_json(&WakeDoc {
                dry_run: false,
                reports: reports.iter().map(ReportView::new).collect(),
                wait: None,
            });
        } else if reports.iter().any(|r| r.sent_count() > 0) {
            ctx.note(&ctx.t(Msg::WakeNotGuaranteed));
        }
        return Ok(code);
    }

    let timeout = timeout.unwrap_or_else(|| settings.wake.effective_verify_timeout());
    let waits = wait_all(ctx, &items, &reports, specs, timeout, poll);
    let mut wait_code = exit::OK;
    for w in &waits {
        match &w.outcome {
            Some(WaitOutcome::Up { .. }) | None => {}
            Some(WaitOutcome::TimedOut { .. }) => {
                if wait_code == exit::OK {
                    wait_code = exit::TIMEOUT;
                }
            }
            Some(WaitOutcome::Cancelled) => wait_code = exit::CANCELLED,
        }
    }
    if ctx.json() {
        ctx.print_json(&WakeDoc {
            dry_run: false,
            reports: reports.iter().map(ReportView::new).collect(),
            wait: Some(waits),
        });
    }
    if wait_code == exit::CANCELLED {
        return Ok(exit::CANCELLED);
    }
    Ok(if code != exit::OK { code } else { wait_code })
}

fn via_text(ctx: &Ctx, via: Via, iface: Option<&send::IfaceRef>) -> String {
    match (via, iface) {
        (Via::Interface(addr), Some(i)) => ctx.t(Msg::ViaInterface {
            name: i.name.clone(),
            addr,
        }),
        (Via::Interface(addr), None) => ctx.t(Msg::ViaInterface {
            name: addr.to_string(),
            addr,
        }),
        (Via::Routed, Some(i)) => ctx.t(Msg::ViaRoutedThrough {
            name: i.name.clone(),
        }),
        (Via::Routed, None) => ctx.t(Msg::ViaRouted),
    }
}

fn print_note(ctx: &Ctx, n: &PlanNote) {
    let text = ctx.t(Msg::PlanNote(n.clone()));
    match n {
        PlanNote::ViaVirtual { .. }
        | PlanNote::NoInterfaces
        | PlanNote::AddressUnresolved { .. }
        | PlanNote::NoDestinations => ctx.warn(&text),
        PlanNote::NoDirectedBroadcast { .. } | PlanNote::AddressOffSubnet { .. } => ctx.note(&text),
    }
}

// ---- dry run ----

#[derive(Serialize)]
struct PlanView<'a> {
    #[serde(flatten)]
    plan: &'a SendPlan,
    /// The SecureOn password is shown as `**` (like everywhere else, it is never printed).
    packet_hex: String,
    has_secureon: bool,
}

#[derive(Serialize)]
struct PlanErrorView<'a> {
    label: &'a str,
    host_id: Option<HostId>,
    mac: MacAddr,
    error: &'static str,
    message: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PlanEntry<'a> {
    Plan(PlanView<'a>),
    Error(PlanErrorView<'a>),
}

#[derive(Serialize)]
struct DryRunDoc<'a> {
    dry_run: bool,
    plans: Vec<PlanEntry<'a>>,
}

fn dry_run(ctx: &Ctx, items: &[Item]) -> CmdResult {
    let reqs: Vec<WakeRequest> = items.iter().map(|i| i.req.clone()).collect();
    let plans = send::dry_run(&reqs);
    let mut code = exit::OK;
    for (p, r) in plans.iter().zip(&reqs) {
        if p.is_err() {
            code = exit::NETWORK;
        }
        if ctx.json() {
            continue;
        }
        match p {
            Ok(plan) => print_plan(ctx, plan),
            Err(e) => {
                ctx.out(&output::paint(output::BOLD, &r.label));
                ctx.warn(&match e {
                    Error::NoDestinations => ctx.t(Msg::WakeNoDestinations {
                        label: r.label.clone(),
                    }),
                    other => wol_core::i18n::describe_error(other, ctx.lang),
                });
            }
        }
    }
    if ctx.json() {
        let entries = plans
            .iter()
            .zip(&reqs)
            .map(|(p, r)| match p {
                Ok(plan) => PlanEntry::Plan(PlanView {
                    plan,
                    packet_hex: plan.packet_hex(),
                    has_secureon: plan.has_secureon(),
                }),
                Err(e) => PlanEntry::Error(PlanErrorView {
                    label: &r.label,
                    host_id: r.host_id,
                    mac: r.mac,
                    error: if matches!(e, Error::NoDestinations) {
                        "no_destinations"
                    } else {
                        "error"
                    },
                    message: wol_core::i18n::describe_error(e, ctx.lang),
                }),
            })
            .collect();
        ctx.print_json(&DryRunDoc {
            dry_run: true,
            plans: entries,
        });
    }
    Ok(code)
}

fn print_plan(ctx: &Ctx, p: &SendPlan) {
    ctx.out(&output::paint(
        output::BOLD,
        &ctx.t(Msg::DryRunHeader {
            label: p.label.clone(),
            mac: p.mac.to_string(),
            bytes: p.packet_len,
            repeat: p.repeat,
            interval_ms: p.interval.as_millis() as u64,
        }),
    ));
    let h = |x| ctx.t(Msg::Header(x));
    let mut t = Table::new(vec![
        h(Header::Via),
        h(Header::Destination),
        h(Header::Kind),
    ])
    .indent(2);
    for s in &p.sends {
        t.row(vec![
            Cell::plain(via_text(ctx, s.via, s.interface.as_ref())),
            Cell::plain(s.dest.to_string()),
            Cell::plain(ctx.t(Msg::SendKind(s.kind))),
        ]);
    }
    if !p.sends.is_empty() {
        for l in t.lines() {
            ctx.out(&l);
        }
    }
    for f in &p.failures {
        ctx.warn(&ctx.t(Msg::PlanFailure {
            target: f.target.clone(),
            error: f.error.clone(),
        }));
    }
    for n in &p.notes {
        print_note(ctx, n);
    }
    // `packet_hex` masks a SecureOn password (`** ** ...`).
    ctx.out(&format!("  {}:", ctx.tx(Text::Packet)));
    for line in p.packet_hex().lines() {
        ctx.out(&format!("    {line}"));
    }
}

// ---- real send ----

#[derive(Serialize)]
struct ReportView<'a> {
    #[serde(flatten)]
    report: &'a WakeReport,
    outcome: WakeOutcome,
    sent: u32,
    failed: u32,
}

impl<'a> ReportView<'a> {
    fn new(r: &'a WakeReport) -> ReportView<'a> {
        ReportView {
            report: r,
            outcome: r.outcome(),
            sent: r.sent_count(),
            failed: r.failed_count(),
        }
    }
}

#[derive(Serialize)]
struct WaitView {
    label: String,
    host_id: Option<HostId>,
    /// `None`: not checked (no address / probe off / nothing sent).
    outcome: Option<WaitOutcome>,
}

#[derive(Serialize)]
struct WakeDoc<'a> {
    dry_run: bool,
    reports: Vec<ReportView<'a>>,
    wait: Option<Vec<WaitView>>,
}

fn print_report(ctx: &Ctx, r: &WakeReport) {
    let label = r.label.clone();
    let (style, line) = match r.outcome() {
        WakeOutcome::Ok => (output::GREEN, ctx.t(Msg::WakeSent { label })),
        WakeOutcome::Partial => (
            output::YELLOW,
            ctx.t(Msg::WakePartial {
                label,
                sent: r.sent_count(),
                failed: r.failed_count(),
            }),
        ),
        WakeOutcome::Failed if r.no_destinations() || r.attempts.is_empty() => {
            (output::RED, ctx.t(Msg::WakeNoDestinations { label }))
        }
        WakeOutcome::Failed => (output::RED, ctx.t(Msg::WakeFailed { label })),
    };
    ctx.out(&output::paint(style, &line));
    if ctx.json() {
        return;
    }
    let show_table = ctx.verbose() > 0 || r.outcome() != WakeOutcome::Ok;
    if show_table && !r.attempts.is_empty() {
        let h = |x| ctx.t(Msg::Header(x));
        let mut t = Table::new(vec![
            h(Header::Via),
            h(Header::Destination),
            h(Header::Kind),
            h(Header::Sent),
            h(Header::Result),
        ])
        .indent(2);
        for at in &r.attempts {
            let result = match (&at.last_error, at.failed) {
                (Some(e), n) if n > 0 => Cell::styled(e.clone(), output::RED),
                (Some(e), _) => Cell::styled(e.clone(), output::DIM),
                (None, _) => Cell::styled(ctx.t(Msg::Outcome(WakeOutcome::Ok)), output::GREEN),
            };
            t.row(vec![
                Cell::plain(via_text(ctx, at.via, at.interface.as_ref())),
                Cell::plain(at.dest.to_string()),
                Cell::plain(ctx.t(Msg::SendKind(at.kind))),
                Cell::plain(at.sent.to_string()),
                result,
            ]);
        }
        for l in t.lines() {
            ctx.out(&l);
        }
    }
    for f in &r.failures {
        ctx.warn(&ctx.t(Msg::PlanFailure {
            target: f.target.clone(),
            error: f.error.clone(),
        }));
    }
    for n in &r.notes {
        if *n != PlanNote::NoDestinations {
            print_note(ctx, n);
        }
    }
}

fn wait_all(
    ctx: &Ctx,
    items: &[Item],
    reports: &[WakeReport],
    specs: Vec<Option<ProbeSpec>>,
    timeout: Duration,
    poll: Duration,
) -> Vec<WaitView> {
    let cancel = ctrlc::install();
    let deadline = Instant::now() + timeout;
    let secs = timeout.as_secs().max(1);
    let mut views: Vec<WaitView> = items
        .iter()
        .map(|i| WaitView {
            label: i.req.label.clone(),
            host_id: i.req.host_id,
            outcome: None,
        })
        .collect();
    let (tx, rx) = mpsc::channel::<(usize, WaitOutcome)>();
    let (tick_tx, tick_rx) = mpsc::channel::<(usize, HostState)>();
    let mut running = 0usize;
    for (i, spec) in specs.into_iter().enumerate() {
        let label = &items[i].req.label;
        let Some(spec) = spec else {
            ctx.warn(&ctx.tx(Text::WaitNotMonitored { label }));
            continue;
        };
        if reports[i].sent_count() == 0 {
            continue;
        }
        ctx.info(&ctx.t(Msg::Waiting {
            label: label.clone(),
            secs,
        }));
        running += 1;
        let tx = tx.clone();
        let tick_tx = tick_tx.clone();
        std::thread::spawn(move || {
            let out = probe::wait_until_up(&spec, deadline, poll, cancel, |st| {
                let _ = tick_tx.send((i, st.clone()));
            });
            let _ = tx.send((i, out));
        });
    }
    drop(tx);
    drop(tick_tx);
    let verbose = ctx.verbose() > 0;
    let mut done = 0usize;
    while done < running {
        // Progress ticks (-v) between results.
        while let Ok((i, st)) = tick_rx.try_recv() {
            if verbose {
                ctx.info(&format!(
                    "{}: {}",
                    views[i].label,
                    ctx.t(Msg::HostState(st))
                ));
            }
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((i, out)) => {
                done += 1;
                let label = views[i].label.clone();
                match &out {
                    WaitOutcome::Up { .. } => ctx.out(&output::paint(
                        output::GREEN,
                        &ctx.t(Msg::CameOnline { label }),
                    )),
                    WaitOutcome::TimedOut { .. } => ctx.out(&output::paint(
                        output::RED,
                        &ctx.t(Msg::WakeTimeout { label, secs }),
                    )),
                    WaitOutcome::Cancelled => {}
                }
                views[i].outcome = Some(out);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if views
        .iter()
        .any(|v| matches!(v.outcome, Some(WaitOutcome::Cancelled)))
    {
        ctx.warn(&ctx.t(Msg::WaitCancelled));
    }
    views
}
