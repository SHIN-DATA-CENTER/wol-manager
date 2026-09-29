//! `restart`, `shutdown` (with confirmation and `--wait` verification) and `abort`.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Serialize;
use wol_core::i18n::Msg;
use wol_core::model::limits;
use wol_core::remote::{
    self, BootInfo, PowerAction, PowerOptions, PowerOutcome, RemoteFailure, RemoteOp,
    RestartVerify, ShutdownVerify, VerifyPhase, VerifyTick,
};
use wol_core::{Host, HostId, RemoteKind, Settings};

use super::remote::{
    BootView, ErrorView, confirm, confirm_sign_in, find_hosts, parallel, precheck,
};
use crate::backend::Remote;
use crate::cli::{AbortArgs, PowerArgs};
use crate::ctrlc;
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::output;
use crate::text::Text;
use crate::util;

fn op_of(action: PowerAction) -> RemoteOp {
    match action {
        PowerAction::Restart => RemoteOp::Restart,
        PowerAction::Shutdown => RemoteOp::Shutdown,
    }
}

/// How a verification ended (restart and shutdown results in one owned form).
enum Verified {
    /// Back with a new boot.
    Restarted(BootInfo),
    /// Stopped answering.
    ShutDown,
    /// Shutdown not verifiable (no status check); refused up front, kept for completeness.
    NotMonitored,
    /// Deadline passed; the last error while reading the boot time, if any.
    TimedOut(Option<Failure>),
    /// An error that polling cannot fix (host key, configuration, secret store).
    Failed(Failure),
    /// Ctrl+C.
    Cancelled,
}

impl Verified {
    fn from_restart(v: RestartVerify) -> Verified {
        match v {
            RestartVerify::Restarted { boot } => Verified::Restarted(boot),
            RestartVerify::TimedOut { last_error, .. } => {
                Verified::TimedOut(last_error.map(Failure::from))
            }
            RestartVerify::Failed(e) => Verified::Failed(e.into()),
            RestartVerify::Cancelled => Verified::Cancelled,
        }
    }

    fn from_shutdown(v: ShutdownVerify) -> Verified {
        match v {
            ShutdownVerify::ShutDown => Verified::ShutDown,
            ShutdownVerify::TimedOut { .. } => Verified::TimedOut(None),
            ShutdownVerify::NotMonitored => Verified::NotMonitored,
            ShutdownVerify::Cancelled => Verified::Cancelled,
        }
    }

    fn code(&self) -> u8 {
        match self {
            Verified::Restarted(_) | Verified::ShutDown | Verified::NotMonitored => exit::OK,
            Verified::TimedOut(_) => exit::TIMEOUT,
            Verified::Failed(f) => f.exit_code(),
            Verified::Cancelled => exit::CANCELLED,
        }
    }

    fn result(&self) -> &'static str {
        match self {
            Verified::Restarted(_) => "restarted",
            Verified::ShutDown => "shut_down",
            Verified::NotMonitored => "not_monitored",
            Verified::TimedOut(_) => "timed_out",
            Verified::Failed(_) => "failed",
            Verified::Cancelled => "cancelled",
        }
    }

    /// The error of a failed verification, or the last one before a timeout.
    fn error(&self) -> Option<&Failure> {
        match self {
            Verified::Failed(f) | Verified::TimedOut(Some(f)) => Some(f),
            _ => None,
        }
    }
}

/// One host of a batch.
struct Item<'a> {
    host: &'a Host,
    request: Result<PowerOutcome, Failure>,
    /// `--wait`: the verification, and how long it could take.
    wait: Option<(Verified, Duration)>,
}

impl Item<'_> {
    /// A request the host may be carrying out: accepted, or sent but unconfirmed.
    fn may_run(&self) -> Option<PowerOutcome> {
        match &self.request {
            Ok(o) => Some(*o),
            Err(f) if f.is_remote(&RemoteFailure::PowerUnconfirmed) => Some(PowerOutcome::Accepted),
            Err(_) => None,
        }
    }

    fn code(&self) -> u8 {
        match (&self.request, &self.wait) {
            (_, Some((v, _))) => v.code(),
            (Ok(_), None) => exit::OK,
            (Err(f), None) => f.exit_code(),
        }
    }
}

#[derive(Serialize)]
struct WaitView<'a> {
    result: &'static str,
    timeout_secs: u64,
    boot: Option<BootView<'a>>,
    error: Option<ErrorView>,
}

#[derive(Serialize)]
struct PowerEntry<'a> {
    host: &'a str,
    id: HostId,
    kind: Option<RemoteKind>,
    address: Option<String>,
    /// SSH: the host's own command that ran instead of the platform default (`null` = none).
    custom_command: Option<&'a str>,
    ok: bool,
    outcome: Option<PowerOutcome>,
    error: Option<ErrorView>,
    wait: Option<WaitView<'a>>,
}

#[derive(Serialize)]
struct PowerDoc<'a> {
    action: PowerAction,
    options: &'a PowerOptions,
    results: Vec<PowerEntry<'a>>,
}

/// The question before a restart / shutdown: hosts, Windows options, SSH note, warning.
fn confirmation_lines(
    ctx: &Ctx,
    action: PowerAction,
    hosts: &[&Host],
    opts: &PowerOptions,
) -> Vec<String> {
    let mut lines = vec![output::paint(
        output::BOLD,
        &ctx.tx(Text::PowerConfirmHeader { action }),
    )];
    for h in hosts {
        let kind = h
            .remote_kind()
            .map(|k| ctx.t(Msg::RemoteKindName(k)))
            .unwrap_or_default();
        lines.push(
            ctx.tx(Text::PowerConfirmHost {
                label: &h.name,
                address: &h
                    .management_address()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                kind: &kind,
            }),
        );
    }
    if hosts
        .iter()
        .any(|h| h.remote_kind() == Some(RemoteKind::Windows))
    {
        lines.push(ctx.tx(Text::WindowsDelay {
            secs: opts.delay_secs,
        }));
        lines.push(ctx.tx(Text::WindowsForce { force: opts.force }));
        if let Some(m) = &opts.message {
            lines.push(ctx.tx(Text::WindowsMessage { message: m }));
        }
    }
    if hosts
        .iter()
        .any(|h| h.remote_kind() == Some(RemoteKind::Ssh))
    {
        lines.push(ctx.tx(Text::SshPowerNote));
    }
    lines.extend(
        custom_command_lines(ctx, action, hosts)
            .iter()
            .map(|l| output::paint(output::YELLOW, l)),
    );
    lines.push(output::paint(
        output::YELLOW,
        &ctx.tx(Text::UnsavedWorkWarning),
    ));
    lines
}

/// One line per SSH host that runs its own command instead of the platform default (cross
/// review X1: the command runs as root, so the user always sees it before it runs).
fn custom_command_lines(ctx: &Ctx, action: PowerAction, hosts: &[&Host]) -> Vec<String> {
    hosts
        .iter()
        .filter_map(|h| {
            remote::custom_power_command(h, action).map(|command| {
                ctx.tx(Text::CustomPowerCommand {
                    label: &h.name,
                    command,
                })
            })
        })
        .collect()
}

pub fn run(ctx: &mut Ctx, a: &PowerArgs, action: PowerAction) -> CmdResult {
    // Parse every flag before anything is looked up or sent.
    let max_delay = u64::from(*limits::SHUTDOWN_DELAY_SECS.end());
    let delay = if a.now {
        Some(0)
    } else {
        a.delay
            .as_deref()
            .map(|v| {
                util::parse_duration_in(
                    "--delay",
                    v,
                    Duration::ZERO..=Duration::from_secs(max_delay),
                    "0 to 600 seconds, e.g. 30 or 2m",
                )
            })
            .transpose()?
            .map(|d| d.as_secs() as u32)
    };
    let timeout = a
        .timeout
        .as_deref()
        .map(|v| {
            util::parse_duration_in(
                "--timeout",
                v,
                Duration::from_secs(1)..=Duration::from_secs(86_400),
                "1 s to 24 h, e.g. 5m",
            )
        })
        .transpose()?;
    let message = a
        .message
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_owned);

    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let s = &cfg.settings;
    let hosts = find_hosts(cfg, &a.hosts)?;
    for h in &hosts {
        precheck(ctx, h, op_of(action))?;
    }
    // A shutdown can only be confirmed for hosts whose status is checked: refuse before
    // anything happens rather than shut down and then say so.
    if a.wait && action == PowerAction::Shutdown {
        for h in &hosts {
            if !remote::verify_probe_spec(h, s).is_monitored() {
                return Err(Failure::Usage(ctx.t(Msg::VerifyNotMonitored {
                    label: h.name.clone(),
                })));
            }
        }
    }
    let mut opts = PowerOptions::from_settings(&s.remote);
    if let Some(d) = delay {
        opts.delay_secs = d;
    }
    if a.force {
        opts.force = true;
    }
    if a.no_force {
        opts.force = false;
    }
    opts.message = message;
    let windows_flags = a.delay.is_some() || a.now || a.force || a.no_force || a.message.is_some();
    if windows_flags {
        for h in &hosts {
            if h.remote_kind() == Some(RemoteKind::Ssh) {
                ctx.note(&ctx.tx(Text::SshIgnoresWindowsOptions { label: &h.name }));
            }
        }
    }

    let lines = confirmation_lines(ctx, action, &hosts, &opts);
    if !confirm(ctx, a.yes, &lines)? {
        return Ok(exit::NEGATIVE);
    }
    if a.yes {
        // No question was shown: a custom command is still printed (even with -q).
        for l in custom_command_lines(ctx, action, &hosts) {
            ctx.warn_always(l.trim());
        }
    }

    let remote = Remote::new()?;
    confirm_sign_in(ctx, remote.client(), &hosts);
    // The boot time before the restart tells the new boot from the old one.
    let before: Vec<Option<BootInfo>> = if a.wait && action == PowerAction::Restart {
        parallel(&hosts, |h| remote.boot_time(h, s).ok())
    } else {
        vec![None; hosts.len()]
    };
    let requests = parallel(&hosts, |h| {
        remote.power(h, s, action, &opts).map_err(Failure::from)
    });
    let mut items: Vec<Item> = hosts
        .iter()
        .zip(requests)
        .map(|(h, request)| Item {
            host: h,
            request,
            wait: None,
        })
        .collect();
    for it in &items {
        print_request(ctx, it, action, a.wait);
    }

    if a.wait {
        verify_all(ctx, &remote, s, action, timeout, &before, &mut items);
    }

    let cancelled = items.iter().any(|i| i.code() == exit::CANCELLED);
    if cancelled {
        ctx.warn(&ctx.t(Msg::WaitCancelled));
    }
    if ctx.json() {
        let results = items
            .iter()
            .map(|it| PowerEntry {
                host: &it.host.name,
                id: it.host.id,
                kind: it.host.remote_kind(),
                address: it.host.management_address().map(ToString::to_string),
                custom_command: remote::custom_power_command(it.host, action),
                ok: it.code() == exit::OK,
                outcome: it.request.as_ref().ok().copied(),
                error: it.request.as_ref().err().map(|f| ErrorView::of(ctx, f)),
                wait: it.wait.as_ref().map(|(v, dur)| WaitView {
                    result: v.result(),
                    timeout_secs: dur.as_secs(),
                    boot: match v {
                        Verified::Restarted(boot) => Some(BootView::new(boot)),
                        _ => None,
                    },
                    error: v.error().map(|f| ErrorView::of(ctx, f)),
                }),
            })
            .collect();
        ctx.print_json(&PowerDoc {
            action,
            options: &opts,
            results,
        });
    }
    if cancelled {
        return Ok(exit::CANCELLED);
    }
    Ok(items
        .iter()
        .map(Item::code)
        .find(|c| *c != exit::OK)
        .unwrap_or(exit::OK))
}

fn print_request(ctx: &Ctx, it: &Item<'_>, action: PowerAction, wait: bool) {
    let label = it.host.name.clone();
    match &it.request {
        Ok(PowerOutcome::Accepted) => ctx.out(&output::paint(
            output::GREEN,
            &ctx.t(Msg::PowerAccepted { label, action }),
        )),
        Ok(PowerOutcome::Scheduled { delay_secs }) => ctx.out(&output::paint(
            output::GREEN,
            &ctx.t(Msg::PowerScheduled {
                label,
                action,
                secs: *delay_secs,
            }),
        )),
        // Sent but not confirmed: with --wait, the verification decides.
        Err(f) if wait && f.is_remote(&RemoteFailure::PowerUnconfirmed) => {
            ctx.warn(&f.message(ctx.lang));
        }
        Err(f) => {
            if !ctx.json() {
                ctx.report(f);
            }
        }
    }
}

fn verify_all(
    ctx: &Ctx,
    remote: &Remote,
    s: &Settings,
    action: PowerAction,
    timeout: Option<Duration>,
    before: &[Option<BootInfo>],
    items: &mut [Item<'_>],
) {
    let cancel = ctrlc::install_with(Some(ctx.tx(Text::VerifyCancelling)));
    let verbose = ctx.verbose() > 0;
    let results: Vec<(usize, Verified, Duration)> = std::thread::scope(|sc| {
        let (tx, rx) = mpsc::channel::<(usize, Verified, Duration)>();
        let (tick_tx, tick_rx) = mpsc::channel::<(usize, VerifyTick)>();
        let mut running = 0usize;
        for (i, it) in items.iter().enumerate() {
            let Some(outcome) = it.may_run() else {
                continue;
            };
            let dur = match timeout {
                Some(t) => t + Duration::from_secs(u64::from(outcome.delay_secs())),
                None => remote::verify_timeout(action, s, &outcome),
            };
            ctx.info(&ctx.t(Msg::VerifyWaiting {
                label: it.host.name.clone(),
                action,
                secs: dur.as_secs(),
            }));
            let deadline = Instant::now() + dur;
            let (tx, tick_tx) = (tx.clone(), tick_tx.clone());
            let host = it.host;
            let before = before[i].as_ref();
            running += 1;
            sc.spawn(move || {
                let on_tick = |t: &VerifyTick| {
                    let _ = tick_tx.send((i, t.clone()));
                };
                let v = match action {
                    PowerAction::Restart => Verified::from_restart(
                        remote.verify_restart(host, s, before, deadline, cancel, on_tick),
                    ),
                    PowerAction::Shutdown => Verified::from_shutdown(
                        remote.verify_shutdown(host, s, deadline, cancel, on_tick),
                    ),
                };
                let _ = tx.send((i, v, dur));
            });
        }
        drop(tx);
        drop(tick_tx);
        let mut last: Vec<Option<VerifyPhase>> = vec![None; items.len()];
        // Progress: every phase change (every round with -v).
        let mut drain_ticks = || {
            while let Ok((i, t)) = tick_rx.try_recv() {
                if verbose || last[i] != Some(t.phase) {
                    print_tick(ctx, &items[i].host.name, action, &t, verbose);
                    last[i] = Some(t.phase);
                }
            }
        };
        let mut out = Vec::new();
        while out.len() < running {
            drain_ticks();
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok((i, v, dur)) => {
                    // A worker sends its last ticks before its result.
                    drain_ticks();
                    print_verified(ctx, &items[i].host.name, action, &v, dur);
                    out.push((i, v, dur));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        out
    });
    for (i, v, dur) in results {
        items[i].wait = Some((v, dur));
    }
}

fn print_tick(ctx: &Ctx, label: &str, action: PowerAction, t: &VerifyTick, verbose: bool) {
    let mut line = match (t.phase, action) {
        // Not seen answering yet: does not count (review R5).
        (VerifyPhase::Down { failures: 0 }, PowerAction::Shutdown) => {
            ctx.tx(Text::VerifyNotSeenYet { label })
        }
        (VerifyPhase::Down { failures }, PowerAction::Shutdown) => {
            ctx.tx(Text::VerifyNoAnswerCount { label, failures })
        }
        (VerifyPhase::Down { .. }, PowerAction::Restart) => ctx.tx(Text::VerifyNoAnswer { label }),
        (VerifyPhase::Up, PowerAction::Restart) => ctx.tx(Text::VerifyUpOldBoot { label }),
        (VerifyPhase::Up, PowerAction::Shutdown) => ctx.tx(Text::VerifyStillUp { label }),
    };
    if verbose {
        line = format!(
            "{line} [{}, {} s]",
            ctx.t(Msg::HostState(t.state.clone())),
            t.elapsed.as_secs()
        );
    }
    ctx.info(&line);
}

fn print_verified(ctx: &Ctx, label: &str, action: PowerAction, v: &Verified, dur: Duration) {
    let label = label.to_owned();
    match v {
        Verified::Restarted(boot) => {
            ctx.out(&output::paint(
                output::GREEN,
                &ctx.t(Msg::RestartVerified { label }),
            ));
            ctx.out(&format!("  {}", boot.boot_line(ctx.lang)));
        }
        Verified::ShutDown => ctx.out(&output::paint(
            output::GREEN,
            &ctx.t(Msg::ShutdownVerified { label }),
        )),
        Verified::TimedOut(last_error) => {
            ctx.out(&output::paint(
                output::RED,
                &ctx.t(Msg::VerifyTimedOut {
                    label,
                    action,
                    secs: dur.as_secs(),
                }),
            ));
            if let Some(f) = last_error {
                ctx.warn(&f.message(ctx.lang));
            }
        }
        Verified::Failed(f) => {
            if !ctx.json() {
                ctx.report(f);
            }
        }
        Verified::NotMonitored => ctx.warn(&ctx.t(Msg::VerifyNotMonitored { label })),
        Verified::Cancelled => {}
    }
}

pub fn abort(ctx: &mut Ctx, a: &AbortArgs) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let h = cfg.find(&a.host)?;
    precheck(ctx, h, RemoteOp::AbortShutdown)?;
    let remote = Remote::new()?;
    confirm_sign_in(ctx, remote.client(), &[h]);
    let aborted = match remote
        .abort_shutdown(h, &cfg.settings)
        .map_err(Failure::from)
    {
        Ok(()) => true,
        Err(f) if f.is_remote(&RemoteFailure::NoShutdownInProgress) => false,
        Err(f) => return Err(f),
    };
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc<'a> {
            host: &'a str,
            id: HostId,
            aborted: bool,
        }
        ctx.print_json(&Doc {
            host: &h.name,
            id: h.id,
            aborted,
        });
    } else if aborted {
        ctx.out(&output::paint(
            output::GREEN,
            &ctx.t(Msg::ShutdownAborted {
                label: h.name.clone(),
            }),
        ));
    } else {
        ctx.info(&ctx.t(Msg::NoShutdownPending {
            label: h.name.clone(),
        }));
    }
    Ok(if aborted { exit::OK } else { exit::NEGATIVE })
}
