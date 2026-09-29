//! Remote management in the GUI (v0.2.0, contract §10): boot times (menu, and automatically
//! when a managed host comes online), restart / shutdown with verification, cancel shutdown,
//! the SSH host-key dialog and the queue of top-layer dialogs.
//!
//! Every remote call blocks (network; tens of seconds in the worst case), so they run on the
//! app's `remote` pool — never on the io pool, whose two threads send magic packets — and each
//! verification runs on a thread of its own (it waits for minutes); "Cancel shutdown" too (it is
//! time-critical and must never wait behind other remote work). Results come back through
//! [`post_ui`] with a [`Ticket`]; the follow-up of a result for a host whose management endpoint
//! changed in the meantime (edit, delete) is dropped, but a request that ran is always reported.
//! The per-host bookkeeping ([`RemoteState`]) and every decision are pure and tested; the
//! `impl App` part is the glue.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use slint::ComponentHandle;
use wol_core::i18n::{self, Lang, Msg};
use wol_core::model::{RemoteSettings, limits};
use wol_core::probe::{self, HostState};
use wol_core::remote::{
    self as core, BootInfo, PowerOptions, PowerOutcome, RemoteClient, RemoteFailure, RestartVerify,
    ShutdownVerify,
};
use wol_core::{Config, Error, Host, HostId, HostKeyProblem};

use crate::app::{App, Pending};
use crate::persist::Op;
use crate::rows::RemoteRow;
use crate::scheduler::RemoteEnd;
use crate::texts::{GuiText, Text};
use crate::workers::{Barrier, SECRET_WAIT, post_ui};
use crate::{
    AppState, ConfirmKind, ConfirmRequest, EditorState, HostKeyPrompt, HostStatus, OverlayKind,
    PowerRequest, ProbeVia, RemoteKind, ToastKind,
};

/// Longest message shown on a Windows host during the countdown (characters).
pub const MESSAGE_MAX_CHARS: usize = 511;

// ---------------------------------------------------------------------------------------------
// Per-host bookkeeping

/// Identifies the state of a host a worker result belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    /// Host.
    pub id: HostId,
    generation: u64,
    boot_gen: u64,
}

#[derive(Debug, Clone)]
struct Verifying {
    action: core::PowerAction,
    token: u64,
    cancel: Arc<AtomicBool>,
    /// The boot known when the request was accepted: it still applies when the host did not
    /// go down after all (cancelled countdown, shutdown not seen; review C4).
    prior_boot: Option<BootInfo>,
}

/// A verification that ended or was cancelled ([`RemoteState::take_verify`],
/// [`RemoteState::cancel_verify`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Ended {
    /// Restart / shutdown.
    pub action: core::PowerAction,
    /// The boot known before the request.
    pub prior_boot: Option<BootInfo>,
}

/// Automatic boot-time fetches that failed with a network error are tried again this often
/// while the host stays online (review C6: right after a wake the host answers the probe
/// before sshd / SMB accept logons).
pub const AUTO_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(90),
];

#[derive(Debug, Default)]
struct HostRemote {
    /// [`remote_key`] of the host: a change starts a new generation.
    key: String,
    generation: u64,
    /// Last known boot.
    boot: Option<BootInfo>,
    /// Bumped whenever the boot info is cleared (offline, accepted restart / shutdown).
    boot_gen: u64,
    /// A user-started operation runs (row spinner, menus disabled).
    busy: bool,
    /// An automatic boot-time fetch runs.
    auto: bool,
    /// An automatic fetch was wanted while another operation ran: fetch once it ended
    /// (review C6).
    refetch: bool,
    /// Automatic retries after network errors so far, and when the next one is due.
    retries: u32,
    retry_at: Option<Instant>,
    verify: Option<Verifying>,
}

/// What a remote result depends on: the management endpoint (kind, management address, SSH
/// port). A change makes running work and the known boot time stale. Probe settings are not
/// part of it (review C1): changing them must not drop results or boot times of every host.
pub fn remote_key(h: &Host) -> String {
    format!(
        "{:?}|{:?}|{}",
        h.remote_kind(),
        h.management_address().map(ToString::to_string),
        h.remote.as_ref().map_or(0, |r| r.ssh_port())
    )
}

/// Remote state of every host (UI thread).
#[derive(Debug, Default)]
pub struct RemoteState {
    hosts: HashMap<HostId, HostRemote>,
    next_token: u64,
}

/// What [`RemoteState::sync`] changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Synced {
    /// Hosts whose verification was cancelled (their status must be restored).
    pub reset: Vec<HostId>,
    /// Known hosts whose management endpoint changed (e.g. remote management was just set
    /// up): fetch the boot time if they are online.
    pub changed: Vec<HostId>,
}

impl RemoteState {
    /// Follows the config. Hosts whose [`remote_key`] changed start a new generation: their
    /// boot time is forgotten, a busy marker cleared and a verification cancelled.
    pub fn sync(&mut self, cfg: &Config) -> Synced {
        let mut out = Synced::default();
        self.hosts.retain(|id, r| {
            let keep = cfg.get(*id).is_some();
            if !keep && let Some(v) = r.verify.take() {
                v.cancel.store(true, Ordering::Relaxed);
            }
            keep
        });
        for h in &cfg.hosts {
            let key = remote_key(h);
            match self.hosts.get_mut(&h.id) {
                Some(r) if r.key == key => {}
                Some(r) => {
                    r.key = key;
                    r.generation += 1;
                    r.boot = None;
                    r.boot_gen += 1;
                    r.busy = false;
                    r.auto = false;
                    r.refetch = false;
                    r.retries = 0;
                    r.retry_at = None;
                    if let Some(v) = r.verify.take() {
                        v.cancel.store(true, Ordering::Relaxed);
                        out.reset.push(h.id);
                    }
                    out.changed.push(h.id);
                }
                None => {
                    self.hosts.insert(
                        h.id,
                        HostRemote {
                            key,
                            generation: 1,
                            ..HostRemote::default()
                        },
                    );
                }
            }
        }
        out
    }

    /// Last known boot of a host.
    pub fn boot(&self, id: HostId) -> Option<&BootInfo> {
        self.hosts.get(&id).and_then(|r| r.boot.as_ref())
    }

    /// A user-started operation runs for the host.
    pub fn is_busy(&self, id: HostId) -> bool {
        self.hosts.get(&id).is_some_and(|r| r.busy)
    }

    /// The restart / shutdown being verified, if any.
    pub fn verifying(&self, id: HostId) -> Option<core::PowerAction> {
        self.hosts
            .get(&id)
            .and_then(|r| r.verify.as_ref().map(|v| v.action))
    }

    fn ticket(id: HostId, r: &HostRemote) -> Ticket {
        Ticket {
            id,
            generation: r.generation,
            boot_gen: r.boot_gen,
        }
    }

    /// Starts a user operation (boot time, restart / shutdown request, cancel shutdown):
    /// `None` while another one runs.
    pub fn begin_user(&mut self, id: HostId) -> Option<Ticket> {
        let r = self.hosts.get_mut(&id)?;
        if r.busy {
            return None;
        }
        r.busy = true;
        Some(Self::ticket(id, r))
    }

    /// Starts an automatic boot-time fetch: at most one per host, never while a user
    /// operation or a verification runs. Refused while another fetch or a user operation
    /// runs: remembered, so that it happens when that one ends ([`RemoteState::take_refetch`];
    /// review C6).
    pub fn begin_auto(&mut self, id: HostId) -> Option<Ticket> {
        let r = self.hosts.get_mut(&id)?;
        if r.verify.is_some() {
            return None;
        }
        if r.auto || r.busy {
            r.refetch = true;
            return None;
        }
        r.auto = true;
        r.retry_at = None;
        Some(Self::ticket(id, r))
    }

    /// An automatic fetch was refused while another operation ran (see
    /// [`RemoteState::begin_auto`]): `true` once, then forgotten.
    pub fn take_refetch(&mut self, id: HostId) -> bool {
        self.hosts
            .get_mut(&id)
            .is_some_and(|r| std::mem::take(&mut r.refetch))
    }

    /// An automatic fetch failed with a network error: schedules a retry (see
    /// [`AUTO_RETRY_DELAYS`]). `false` when every retry was used.
    pub fn schedule_retry(&mut self, id: HostId, now: Instant) -> bool {
        let Some(r) = self.hosts.get_mut(&id) else {
            return false;
        };
        let Some(delay) = usize::try_from(r.retries)
            .ok()
            .and_then(|i| AUTO_RETRY_DELAYS.get(i))
        else {
            return false;
        };
        r.retries += 1;
        r.retry_at = Some(now + *delay);
        true
    }

    /// Hosts whose automatic retry is due (each returned once).
    pub fn due_retries(&mut self, now: Instant) -> Vec<HostId> {
        let mut due: Vec<HostId> = Vec::new();
        for (id, r) in &mut self.hosts {
            if r.retry_at.is_some_and(|t| t <= now) {
                r.retry_at = None;
                due.push(*id);
            }
        }
        due.sort();
        due
    }

    /// A user operation ended. `false` when its result is stale (the host changed or is gone).
    pub fn end_user(&mut self, t: &Ticket) -> bool {
        match self.hosts.get_mut(&t.id) {
            Some(r) if r.generation == t.generation => {
                r.busy = false;
                true
            }
            _ => false,
        }
    }

    /// An automatic fetch ended. `false` when its result is stale.
    pub fn end_auto(&mut self, t: &Ticket) -> bool {
        match self.hosts.get_mut(&t.id) {
            Some(r) if r.generation == t.generation => {
                r.auto = false;
                true
            }
            _ => false,
        }
    }

    /// A boot time read with `t` may be shown: same generation, and the boot info was not
    /// cleared meanwhile (host went offline, restart accepted).
    pub fn accepts_boot(&self, t: &Ticket) -> bool {
        self.hosts
            .get(&t.id)
            .is_some_and(|r| r.generation == t.generation && r.boot_gen == t.boot_gen)
    }

    /// Remembers a boot (a successful read also ends the automatic retries).
    pub fn set_boot(&mut self, id: HostId, b: BootInfo) {
        if let Some(r) = self.hosts.get_mut(&id) {
            r.boot = Some(b);
            r.retries = 0;
            r.retry_at = None;
        }
    }

    /// Forgets the boot (running fetches are dropped, pending retries too). `true` when one
    /// was known.
    pub fn clear_boot(&mut self, id: HostId) -> bool {
        match self.hosts.get_mut(&id) {
            Some(r) => {
                r.boot_gen += 1;
                r.retries = 0;
                r.retry_at = None;
                r.boot.take().is_some()
            }
            None => false,
        }
    }

    /// Starts a verification for an accepted request (cancelling one that still runs). The
    /// known boot no longer applies: it is kept aside ([`Ended::prior_boot`]) and running
    /// fetches are dropped. `None` when `t` is stale.
    pub fn start_verify(
        &mut self,
        t: &Ticket,
        action: core::PowerAction,
    ) -> Option<(u64, Arc<AtomicBool>)> {
        self.next_token += 1;
        let token = self.next_token;
        let r = self.hosts.get_mut(&t.id)?;
        if r.generation != t.generation {
            return None;
        }
        let prior_boot = match r.verify.take() {
            Some(old) => {
                old.cancel.store(true, Ordering::Relaxed);
                old.prior_boot
            }
            None => r.boot.take(),
        };
        r.boot = None;
        r.boot_gen += 1;
        r.retry_at = None;
        let cancel = Arc::new(AtomicBool::new(false));
        r.verify = Some(Verifying {
            action,
            token,
            cancel: cancel.clone(),
            prior_boot,
        });
        Some((token, cancel))
    }

    /// The verification `token` finished, or `None` when it was cancelled or replaced
    /// meanwhile.
    pub fn take_verify(&mut self, id: HostId, token: u64) -> Option<Ended> {
        let r = self.hosts.get_mut(&id)?;
        if r.verify.as_ref().is_some_and(|v| v.token == token) {
            r.verify.take().map(|v| Ended {
                action: v.action,
                prior_boot: v.prior_boot,
            })
        } else {
            None
        }
    }

    /// Cancels the host's verification; the one that ran, if any.
    pub fn cancel_verify(&mut self, id: HostId) -> Option<Ended> {
        let v = self.hosts.get_mut(&id).and_then(|r| r.verify.take())?;
        v.cancel.store(true, Ordering::Relaxed);
        Some(Ended {
            action: v.action,
            prior_boot: v.prior_boot,
        })
    }

    /// Cancels every verification (app exit).
    pub fn cancel_all(&mut self) {
        for r in self.hosts.values_mut() {
            if let Some(v) = r.verify.take() {
                v.cancel.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Remote part of the host's row, the boot text rendered for `now`.
    pub fn row(&self, id: HostId, lang: Lang, now: SystemTime) -> RemoteRow {
        match self.hosts.get(&id) {
            Some(r) => RemoteRow {
                boot_text: r
                    .boot
                    .as_ref()
                    .map(|b| boot_text(lang, b, now))
                    .unwrap_or_default(),
                boot_approx: r.boot.as_ref().is_some_and(|b| b.approximate),
                busy: r.busy,
            },
            None => RemoteRow::default(),
        }
    }
}

/// The row's boot line (contract §10.2): boot time on this PC's clock and the uptime up to
/// `now`, e.g. `起動 9/29 08:12（稼働 3時間12分）`. "approx." is added by the UI.
pub fn boot_text(lang: Lang, b: &BootInfo, now: SystemTime) -> String {
    let uptime = now.duration_since(b.boot_time).unwrap_or(b.uptime);
    i18n::format_boot_line(
        lang,
        &i18n::LocalTime::from_system_time(b.boot_time),
        uptime,
        false,
    )
}

// ---------------------------------------------------------------------------------------------
// Pure decisions

/// Who started an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Menu, dialog, editor.
    User,
    /// `settings.remote.auto_boot_time`.
    Auto,
}

/// Automatic boot time: a managed host became Online (also its first check after the start).
/// A restart verification refreshes the boot time itself.
pub fn auto_boot_wanted(prev: HostStatus, now: HostStatus, managed: bool, enabled: bool) -> bool {
    enabled
        && managed
        && now == HostStatus::Online
        && !matches!(prev, HostStatus::Online | HostStatus::Restarting)
}

/// What the host-key dialog showed, for [`core::trust_host_key`]: the endpoint the unknown
/// key was read from (nothing was pinned then).
pub fn trust_basis(p: &HostKeyPrompt) -> core::TrustBasis {
    core::TrustBasis {
        address: p.address.to_string(),
        port: u16::try_from(p.port).unwrap_or(0),
        pinned: None,
    }
}

/// The host-key dialog of the contract (§10.6) for a problem.
pub fn prompt_of(p: &HostKeyProblem, host_id: &str, mismatch: bool) -> HostKeyPrompt {
    HostKeyPrompt {
        host_id: host_id.into(),
        host_name: p.host.as_str().into(),
        address: p.address.as_str().into(),
        port: i32::from(p.port),
        key_type: p.algorithm.as_str().into(),
        fingerprint: p.fingerprint.as_str().into(),
        key_line: if mismatch {
            Default::default()
        } else {
            p.openssh_line.as_str().into()
        },
        mismatch,
        expected_fingerprint: p.expected_fingerprint.as_deref().unwrap_or("").into(),
    }
}

/// What to do about a failed operation's error.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyStep {
    /// Not a host-key problem (show the error).
    NotKey,
    /// A host-key problem of an automatic fetch: never ask (only user-started operations may
    /// open the dialog); log it.
    Quiet,
    /// Unknown key: ask whether to trust it.
    Ask(HostKeyPrompt),
    /// Unknown key that `~/.ssh/known_hosts` already trusts: pin it with a notice.
    TrustKnown(HostKeyPrompt),
    /// Changed key: the mismatch dialog (never trusted directly).
    Mismatch(HostKeyPrompt),
}

/// Decides the host-key handling of an error (`host_id` = "" for an unsaved editor host).
pub fn key_step(origin: Origin, e: &Error, host_id: &str) -> KeyStep {
    match (e, origin) {
        (Error::UnknownHostKey(_) | Error::HostKeyMismatch(_), Origin::Auto) => KeyStep::Quiet,
        (Error::UnknownHostKey(p), Origin::User) if p.in_known_hosts => {
            KeyStep::TrustKnown(prompt_of(p, host_id, false))
        }
        (Error::UnknownHostKey(p), Origin::User) => KeyStep::Ask(prompt_of(p, host_id, false)),
        (Error::HostKeyMismatch(p), Origin::User) => KeyStep::Mismatch(prompt_of(p, host_id, true)),
        _ => KeyStep::NotKey,
    }
}

fn failure_of(e: &Error) -> Option<&RemoteFailure> {
    e.remote().map(|r| &r.failure)
}

/// "Cancel shutdown" found nothing to cancel.
pub fn no_shutdown_pending(e: &Error) -> bool {
    matches!(failure_of(e), Some(RemoteFailure::NoShutdownInProgress))
}

/// The request may have been executed although it was not confirmed: verify anyway.
pub fn power_unconfirmed(e: &Error) -> bool {
    matches!(failure_of(e), Some(RemoteFailure::PowerUnconfirmed))
}

/// Slint → wol-core.
pub fn core_action(a: crate::PowerAction) -> core::PowerAction {
    match a {
        crate::PowerAction::Restart => core::PowerAction::Restart,
        crate::PowerAction::Shutdown => core::PowerAction::Shutdown,
    }
}

/// The power dialog for a managed host: management address, kind, and the settings'
/// defaults (delay, force). `None` for unmanaged hosts.
pub fn power_request(
    h: &Host,
    action: crate::PowerAction,
    s: &RemoteSettings,
) -> Option<PowerRequest> {
    let kind = crate::rows::remote_kind(h);
    if kind == RemoteKind::None {
        return None;
    }
    Some(PowerRequest {
        host_id: h.id.to_string().into(),
        host_name: h.name.as_str().into(),
        address: h
            .management_address()
            .map(ToString::to_string)
            .unwrap_or_default()
            .into(),
        action,
        kind,
        delay_secs: i32::try_from(s.effective_shutdown_delay_secs()).unwrap_or(0),
        force: s.force_apps_closed,
        message: Default::default(),
        // Cross review X1: the host's own command (root) is always shown before it runs.
        command: core::custom_power_command(h, core_action(action))
            .unwrap_or_default()
            .into(),
    })
}

/// On a worker, before an operation the user started for `host`: waits for the Credential
/// Manager changes queued before it (a password saved in the editor right before; cross review
/// m1), then records that the host may use the current Windows sign-in (cross review X2; the
/// user asked for this host). Returns the account when that was recorded now (say it once).
fn before_user_op(client: &RemoteClient, secrets: &Barrier, host: &Host) -> Option<String> {
    if !secrets.wait(SECRET_WAIT) {
        log::warn!(
            "{}: earlier Credential Manager changes are still running",
            host.name
        );
    }
    match client.confirm_sign_in(host) {
        Ok(account) => account,
        Err(e) => {
            log::warn!(
                "{}: the sign-in confirmation was not recorded: {e}",
                host.name
            );
            None
        }
    }
}

/// A confirmed power request (plain data for the workers and the host-key retry).
#[derive(Debug, Clone, PartialEq)]
pub struct PowerReq {
    /// Host.
    pub id: HostId,
    /// Restart / shutdown.
    pub action: core::PowerAction,
    /// Windows options (SSH: defaults, ignored by the backend).
    pub opts: PowerOptions,
    /// What the dialog showed and the user confirmed: management address, kind and the SSH
    /// custom command ("" = the default). The request runs only while the host still matches
    /// ([`power_matches`]; review S1 / C9).
    pub address: String,
    /// Kind shown.
    pub kind: RemoteKind,
    /// Custom command shown.
    pub command: String,
}

/// `true` while `h` still has the management address, kind and custom command that the
/// dialog showed for `req` (config.toml may change while the dialog is open, e.g. `wolm
/// remote set`, an import or a synced folder).
pub fn power_matches(h: &Host, req: &PowerReq) -> bool {
    let address = h
        .management_address()
        .map(ToString::to_string)
        .unwrap_or_default();
    address == req.address
        && crate::rows::remote_kind(h) == req.kind
        && core::custom_power_command(h, req.action).unwrap_or_default() == req.command
}

/// The dialog's result as a request: Windows gets the delay (clamped to 0–600 s), force and
/// the message (trimmed, capped, dropped when the delay is 0: there is no countdown to show it
/// in); SSH ignores all options.
pub fn power_req(r: &PowerRequest) -> Option<PowerReq> {
    let id = HostId::parse_str(r.host_id.trim()).ok()?;
    let opts = match r.kind {
        RemoteKind::Windows => {
            let lo = i64::from(*limits::SHUTDOWN_DELAY_SECS.start());
            let hi = i64::from(*limits::SHUTDOWN_DELAY_SECS.end());
            let delay = u32::try_from(i64::from(r.delay_secs).clamp(lo, hi)).unwrap_or(0);
            let text: String = r.message.trim().chars().take(MESSAGE_MAX_CHARS).collect();
            PowerOptions {
                delay_secs: delay,
                force: r.force,
                message: (delay > 0 && !text.trim().is_empty()).then(|| text.trim().to_owned()),
            }
        }
        RemoteKind::Ssh | RemoteKind::None => PowerOptions::default(),
    };
    Some(PowerReq {
        id,
        action: core_action(r.action),
        opts,
        address: r.address.to_string(),
        kind: r.kind,
        command: r.command.to_string(),
    })
}

/// Success toast of an accepted request.
pub fn accepted_msg(label: &str, action: core::PowerAction, outcome: &PowerOutcome) -> Msg {
    match outcome {
        PowerOutcome::Accepted => Msg::PowerAccepted {
            label: label.to_owned(),
            action,
        },
        PowerOutcome::Scheduled { delay_secs } => Msg::PowerScheduled {
            label: label.to_owned(),
            action,
            secs: *delay_secs,
        },
    }
}

/// Result of a verification thread.
#[derive(Debug)]
pub enum Verified {
    /// [`core::verify_restart`].
    Restart(RestartVerify),
    /// [`core::verify_shutdown`].
    Shutdown(ShutdownVerify),
}

/// What a finished verification changes in the UI.
#[derive(Debug)]
pub struct VerifyEnd {
    /// The status that follows.
    pub end: RemoteEnd,
    /// New boot (verified restart).
    pub boot: Option<BootInfo>,
    /// The host did not go down as far as the app knows (a shutdown that did not happen or
    /// could not be watched): the boot known before the request still applies (review C4).
    pub keep_prior_boot: bool,
    /// Toast kind, text and detail.
    pub toast: (ToastKind, Text, Text),
}

fn up_end(state: &HostState) -> RemoteEnd {
    match state {
        HostState::Up { via, rtt, .. } => RemoteEnd::Up {
            via: match via {
                probe::ProbeVia::Icmp => ProbeVia::Icmp,
                probe::ProbeVia::Tcp { .. } => ProbeVia::Tcp,
            },
            rtt_ms: i32::try_from(rtt.as_millis()).unwrap_or(i32::MAX),
        },
        _ => RemoteEnd::Offline,
    }
}

/// Maps a verification result (contract §10.2): a verified restart → Online with the new boot
/// time; a restart timeout → Timeout + error; a verified shutdown → Offline; a shutdown
/// timeout → the last probe's state + warning; failures / not verifiable → the status before.
/// `None` for a cancelled verification (whoever cancelled it updated the status).
pub fn verify_end(label: &str, secs: u64, v: Verified) -> Option<VerifyEnd> {
    let label = label.to_owned();
    Some(match v {
        Verified::Restart(RestartVerify::Restarted { boot }) => VerifyEnd {
            end: RemoteEnd::Up {
                via: ProbeVia::None,
                rtt_ms: -1,
            },
            boot: Some(boot),
            keep_prior_boot: false,
            toast: (
                ToastKind::Success,
                Text::msg(Msg::RestartVerified { label }),
                Text::Empty,
            ),
        },
        Verified::Restart(RestartVerify::TimedOut { last_error, .. }) => VerifyEnd {
            end: RemoteEnd::Timeout,
            boot: None,
            keep_prior_boot: false,
            toast: (
                ToastKind::Error,
                Text::msg(Msg::VerifyTimedOut {
                    label,
                    action: core::PowerAction::Restart,
                    secs,
                }),
                last_error.as_ref().map_or(Text::Empty, Text::error),
            ),
        },
        Verified::Restart(RestartVerify::Failed(e)) => VerifyEnd {
            end: RemoteEnd::Restore,
            boot: None,
            // It may have restarted: the boot is read again instead (automatic fetch).
            keep_prior_boot: false,
            toast: (ToastKind::Error, Text::error(&e), Text::Empty),
        },
        Verified::Shutdown(ShutdownVerify::ShutDown) => VerifyEnd {
            end: RemoteEnd::Offline,
            boot: None,
            keep_prior_boot: false,
            toast: (
                ToastKind::Success,
                Text::msg(Msg::ShutdownVerified { label }),
                Text::Empty,
            ),
        },
        Verified::Shutdown(ShutdownVerify::TimedOut { last }) => VerifyEnd {
            end: up_end(&last),
            boot: None,
            keep_prior_boot: last.is_up(),
            toast: (
                ToastKind::Warning,
                Text::msg(Msg::VerifyTimedOut {
                    label,
                    action: core::PowerAction::Shutdown,
                    secs,
                }),
                Text::Empty,
            ),
        },
        Verified::Shutdown(ShutdownVerify::NotMonitored) => VerifyEnd {
            end: RemoteEnd::Restore,
            boot: None,
            keep_prior_boot: true,
            toast: (
                ToastKind::Info,
                Text::msg(Msg::VerifyNotMonitored { label }),
                Text::Empty,
            ),
        },
        Verified::Restart(RestartVerify::Cancelled)
        | Verified::Shutdown(ShutdownVerify::Cancelled) => return None,
    })
}

// ---------------------------------------------------------------------------------------------
// Top-layer dialogs

/// The operation a host-key dialog interrupted (retried after "trust").
#[derive(Debug, Clone, PartialEq)]
pub enum Retry {
    /// "Get boot time".
    BootTime(HostId),
    /// A confirmed restart / shutdown.
    Power(PowerReq),
    /// The editor's "Test connection" (editor token).
    Test {
        /// Editor token.
        token: u64,
    },
    /// The editor's "Get from IP".
    Mac {
        /// Editor token.
        token: u64,
        /// The address that was looked up.
        address: String,
    },
}

impl Retry {
    /// Editor token of an editor operation.
    pub fn editor_token(&self) -> Option<u64> {
        match self {
            Retry::Test { token } | Retry::Mac { token, .. } => Some(*token),
            Retry::BootTime(_) | Retry::Power(_) => None,
        }
    }
}

/// A dialog of the top layer (contract §10.8: at most one is open; the others wait).
#[derive(Debug, Clone)]
pub enum TopDialog {
    /// The confirm dialog.
    Confirm(ConfirmRequest),
    /// The SSH host-key dialog.
    HostKey(HostKeyPrompt, Retry),
    /// The editor's MAC picker (candidates are already in `EditorState`).
    MacPicker {
        /// Editor token.
        token: u64,
    },
}

// ---------------------------------------------------------------------------------------------
// UI glue

fn parse_id(id: &str) -> Option<HostId> {
    HostId::parse_str(id.trim()).ok()
}

impl App {
    /// Remote part of a host's row now.
    pub(crate) fn remote_row(&self, id: HostId) -> RemoteRow {
        self.remote
            .borrow()
            .row(id, self.lang.get(), SystemTime::now())
    }

    /// Pushes the remote part of one row.
    pub(crate) fn refresh_remote_row(&self, id: HostId) {
        let rx = self.remote_row(id);
        self.list.set_remote(&id.to_string(), &rx);
    }

    /// Re-renders every row's remote part (language switch; the uptime grows).
    pub(crate) fn refresh_remote_rows(&self) {
        for sid in self.list.all_ids() {
            if let Some(id) = parse_id(&sid) {
                self.refresh_remote_row(id);
            }
        }
    }

    fn managed_host(&self, id: HostId) -> Option<Host> {
        self.cfg
            .borrow()
            .get(id)
            .filter(|h| h.remote.is_some())
            .cloned()
    }

    /// A user operation cannot start: one runs, or a restart / shutdown is being verified.
    fn remote_blocked(&self, id: HostId) -> bool {
        let r = self.remote.borrow();
        r.is_busy(id) || r.verifying(id).is_some()
    }

    // ---- top-layer dialogs --------------------------------------------------------------

    /// Opens a top-layer dialog now, or queues it while another one is open.
    pub(crate) fn show_top(&self, d: TopDialog) {
        if self.top_open() {
            self.top_queue.borrow_mut().push_back(d);
        } else {
            self.open_top(d);
        }
    }

    fn top_valid(&self, d: &TopDialog) -> bool {
        let editor = self.editor.borrow().as_ref().map(|s| s.token);
        let editor_open = self.ui.global::<AppState>().get_overlay() == OverlayKind::Editor;
        match d {
            TopDialog::Confirm(_) => true,
            TopDialog::HostKey(_, r) => match r.editor_token() {
                Some(t) => editor_open && editor == Some(t),
                None => true,
            },
            TopDialog::MacPicker { token } => editor_open && editor == Some(*token),
        }
    }

    fn open_top(&self, d: TopDialog) {
        let st = self.ui.global::<AppState>();
        match d {
            TopDialog::Confirm(req) => {
                st.set_confirm(req);
                st.set_confirm_open(true);
            }
            TopDialog::HostKey(p, retry) => {
                st.set_hostkey(p.clone());
                st.set_hostkey_open(true);
                *self.hostkey_shown.borrow_mut() = Some((p, retry));
            }
            TopDialog::MacPicker { .. } => {
                self.ui.global::<EditorState>().set_mac_picker_open(true);
            }
        }
    }

    /// Opens the next queued dialog once nothing is open (after every dialog callback and
    /// every tick: the MAC picker closes without a callback when cancelled).
    pub(crate) fn pump_top(&self) {
        while !self.top_open() {
            let Some(d) = self.top_queue.borrow_mut().pop_front() else {
                return;
            };
            if self.top_valid(&d) {
                self.open_top(d);
                return;
            }
            // Its editor is gone: an interrupted editor operation just ends.
            log::debug!("dropping a queued dialog: {d:?}");
        }
    }

    // ---- menus ---------------------------------------------------------------------------

    /// Host menu / row menu "Restart…".
    pub fn restart_host(&self, id: &str) {
        self.open_power(id, crate::PowerAction::Restart);
    }

    /// Host menu / row menu "Shut down…".
    pub fn shutdown_host(&self, id: &str) {
        self.open_power(id, crate::PowerAction::Shutdown);
    }

    fn open_power(&self, id: &str, action: crate::PowerAction) {
        if !self.idle() {
            return;
        }
        let Some(h) = parse_id(id).and_then(|i| self.managed_host(i)) else {
            return;
        };
        if self.refuse_if_blocked(&h) {
            return;
        }
        let Some(req) = power_request(&h, action, &self.cfg.borrow().settings.remote) else {
            return;
        };
        let st = self.ui.global::<AppState>();
        st.set_power(req);
        st.set_power_open(true);
    }

    /// Says so (instead of doing nothing) when a menu action cannot start because another
    /// operation or a restart / shutdown verification of the host runs (review C8).
    fn refuse_if_blocked(&self, h: &Host) -> bool {
        if !self.remote_blocked(h.id) {
            return false;
        }
        self.toast(
            ToastKind::Info,
            GuiText::RemoteBusy {
                label: h.name.clone(),
            },
            Text::Empty,
        );
        true
    }

    /// Power dialog: Cancel / Esc.
    pub fn power_cancelled(&self, _req: PowerRequest) {
        self.pump_top();
    }

    /// Power dialog: Restart / Shut down. Runs only against what the dialog showed: when the
    /// host's management address, kind or custom command changed while it was open (the
    /// config is reloaded from disk every few seconds), nothing is sent (review S1 / C9).
    pub fn power_accepted(&self, req: PowerRequest) {
        if let Some(r) = power_req(&req) {
            match self.managed_host(r.id) {
                Some(h) if power_matches(&h, &r) => {
                    if !self.refuse_if_blocked(&h) {
                        self.run_power(h, r);
                    }
                }
                _ => self.power_host_changed(req.host_name.as_str()),
            }
        }
        self.pump_top();
    }

    fn power_host_changed(&self, label: &str) {
        log::warn!("{label}: the host changed while the power dialog was open; nothing sent");
        self.toast(
            ToastKind::Warning,
            GuiText::PowerHostChanged {
                label: label.to_owned(),
            },
            Text::Empty,
        );
    }

    fn run_power(&self, host: Host, req: PowerReq) {
        let id = host.id;
        let Some(t) = self.remote.borrow_mut().begin_user(id) else {
            return;
        };
        self.refresh_remote_row(id);
        let settings = self.cfg.borrow().settings.clone();
        let client = self.client.clone();
        let secrets = self.secret_queue.barrier();
        log::info!("{}: {} requested ({:?})", host.name, req.action, req.opts);
        self.remote_pool.spawn(move || {
            let confirmed = before_user_op(&client, &secrets, &host);
            // The boot right before a restart tells the verification what "new" means. Read
            // it now: a cached one may predate a restart done elsewhere, which would make the
            // current boot look new at once.
            let before = match req.action {
                core::PowerAction::Restart => client.boot_time(&host, &settings).ok(),
                core::PowerAction::Shutdown => None,
            };
            let r = client.power(&host, &settings, req.action, &req.opts);
            post_ui(move |app| {
                app.sign_in_confirmed(&host.name, confirmed);
                app.on_power_done(t, req, host, before, r);
            });
        });
    }

    /// Says once that a host without a saved password uses the current Windows sign-in (the
    /// user's operation confirmed it; automatic boot-time fetches may use it from now on).
    pub(crate) fn sign_in_confirmed(&self, label: &str, account: Option<String>) {
        if let Some(account) = account {
            self.toast(
                ToastKind::Info,
                GuiText::SignInConfirmed {
                    label: label.to_owned(),
                    account,
                },
                Text::Empty,
            );
        }
    }

    fn on_power_done(
        &self,
        t: Ticket,
        req: PowerReq,
        host: Host,
        before: Option<BootInfo>,
        r: wol_core::Result<PowerOutcome>,
    ) {
        let current = self.remote.borrow_mut().end_user(&t);
        self.refresh_remote_row(t.id);
        // The request ran: its outcome is always shown. Only the follow-up (verification,
        // host-key dialog) needs the host unchanged (review C1).
        if !current {
            log::info!(
                "{}: the host changed meanwhile; no verification of the {}",
                host.name,
                req.action
            );
            match r {
                Ok(outcome) => self.toast(
                    ToastKind::Success,
                    accepted_msg(&host.name, req.action, &outcome),
                    Text::Empty,
                ),
                Err(e) => {
                    log::warn!("{}: {} failed: {e}", host.name, req.action);
                    let kind = if power_unconfirmed(&e) {
                        ToastKind::Warning
                    } else {
                        ToastKind::Error
                    };
                    self.toast(kind, Text::error(&e), Text::Empty);
                }
            }
            return;
        }
        match r {
            Ok(outcome) => {
                self.toast(
                    ToastKind::Success,
                    accepted_msg(&host.name, req.action, &outcome),
                    Text::Empty,
                );
                self.begin_verify(t, host, req.action, outcome, before);
            }
            Err(e) => {
                log::warn!("{}: {} failed: {e}", host.name, req.action);
                match key_step(Origin::User, &e, &t.id.to_string()) {
                    KeyStep::NotKey | KeyStep::Quiet if power_unconfirmed(&e) => {
                        // It may run anyway: never retry, but watch what happens.
                        self.toast(ToastKind::Warning, Text::error(&e), Text::Empty);
                        self.begin_verify(t, host, req.action, PowerOutcome::Accepted, before);
                    }
                    KeyStep::NotKey | KeyStep::Quiet => {
                        self.toast(ToastKind::Error, Text::error(&e), Text::Empty);
                    }
                    step => self.host_key_step(step, Retry::Power(req)),
                }
            }
        }
    }

    fn begin_verify(
        &self,
        t: Ticket,
        host: Host,
        action: core::PowerAction,
        outcome: PowerOutcome,
        before: Option<BootInfo>,
    ) {
        let id = host.id;
        let settings = self.cfg.borrow().settings.clone();
        let timeout = core::verify_timeout(action, &settings, &outcome);
        let secs = timeout.as_secs();
        let deadline = Instant::now() + timeout;
        // The old boot time no longer applies (kept aside in case the host does not go down).
        let Some((token, cancel)) = self.remote.borrow_mut().start_verify(&t, action) else {
            return;
        };
        let status = match action {
            core::PowerAction::Restart => HostStatus::Restarting,
            core::PowerAction::Shutdown => HostStatus::ShuttingDown,
        };
        self.sched.borrow_mut().remote_started(id, status);
        self.refresh_row(id);
        self.refresh_remote_row(id);
        self.update_status_ui();
        let client = self.client.clone();
        let spawned =
            std::thread::Builder::new()
                .name("verify".into())
                .spawn(move || {
                    let v =
                        match action {
                            core::PowerAction::Restart => Verified::Restart(client.verify_restart(
                                &host,
                                &settings,
                                before.as_ref(),
                                deadline,
                                &cancel,
                                |_| {},
                            )),
                            core::PowerAction::Shutdown => Verified::Shutdown(
                                client.verify_shutdown(&host, &settings, deadline, &cancel, |_| {}),
                            ),
                        };
                    post_ui(move |app| app.on_verify_done(id, token, secs, v));
                });
        if let Err(e) = spawned {
            log::error!("cannot start the verification thread: {e}");
            let ended = self.remote.borrow_mut().take_verify(id, token);
            self.sched
                .borrow_mut()
                .remote_finished(id, RemoteEnd::Restore, Instant::now());
            if let Some(b) = ended.and_then(|e| e.prior_boot) {
                self.remote.borrow_mut().set_boot(id, b);
            }
            self.refresh_row(id);
            self.refresh_remote_row(id);
            self.update_status_ui();
        }
    }

    fn on_verify_done(&self, id: HostId, token: u64, secs: u64, v: Verified) {
        let Some(ended) = self.remote.borrow_mut().take_verify(id, token) else {
            log::debug!("verification of {id} ended after it was cancelled");
            return;
        };
        let label = self.host_name_of(id).unwrap_or_default();
        let now = Instant::now();
        let Some(end) = verify_end(&label, secs, v) else {
            self.sched
                .borrow_mut()
                .remote_finished(id, RemoteEnd::Restore, now);
            self.refresh_row(id);
            self.update_status_ui();
            return;
        };
        log::info!("{label}: verification ended: {:?}", end.end);
        self.sched.borrow_mut().remote_finished(id, end.end, now);
        // Review C4: a host that did not go down keeps its boot; one that may have restarted
        // gets it read again below.
        let boot = end
            .boot
            .or_else(|| ended.prior_boot.filter(|_| end.keep_prior_boot));
        match boot {
            Some(b) => self.remote.borrow_mut().set_boot(id, b),
            None => {
                self.remote.borrow_mut().clear_boot(id);
            }
        }
        self.refresh_row(id);
        self.refresh_remote_row(id);
        self.update_status_ui();
        let (kind, text, detail) = end.toast;
        self.toast(kind, text, detail);
        self.auto_boot_if_missing(id);
    }

    /// An online managed host without a known boot gets it read automatically
    /// (`auto_boot_time`): after a verification or a cancelled shutdown, the status goes back to
    /// Online without the offline → online transition that normally triggers it (review C4).
    fn auto_boot_if_missing(&self, id: HostId) {
        if !self.cfg.borrow().settings.remote.auto_boot_time
            || self.sched.borrow().row_state(id).status != HostStatus::Online
            || self.remote.borrow().boot(id).is_some()
        {
            return;
        }
        if let Some(h) = self.managed_host(id) {
            self.start_boot(h, Origin::Auto);
        }
    }

    fn host_name_of(&self, id: HostId) -> Option<String> {
        self.cfg.borrow().get(id).map(|h| h.name.clone())
    }

    /// "Cancel shutdown" (Windows hosts).
    pub fn abort_shutdown(&self, id: &str) {
        if !self.idle() {
            return;
        }
        let Some(h) = parse_id(id)
            .and_then(|i| self.managed_host(i))
            .filter(|h| h.remote_kind() == Some(wol_core::RemoteKind::Windows))
        else {
            return;
        };
        let Some(t) = self.remote.borrow_mut().begin_user(h.id) else {
            return;
        };
        self.refresh_remote_row(h.id);
        let settings = self.cfg.borrow().settings.clone();
        let client = self.client.clone();
        let secrets = self.secret_queue.barrier();
        log::info!("{}: cancel shutdown requested", h.name);
        // Time-critical (the countdown runs): a thread of its own, never queued behind other
        // remote work, not even editor jobs that wait minutes for a filtered host (review C5;
        // cross review m1).
        let job = move || {
            let confirmed = before_user_op(&client, &secrets, &h);
            let r = client.abort_shutdown(&h, &settings);
            let label = h.name;
            post_ui(move |app| {
                app.sign_in_confirmed(&label, confirmed);
                app.on_abort_done(t, label, r);
            });
        };
        let spawned = std::thread::Builder::new()
            .name("remote-abort".into())
            .spawn(job);
        if let Err(e) = spawned {
            log::error!("cannot start the cancel-shutdown thread: {e}");
            self.remote.borrow_mut().end_user(&t);
            self.refresh_remote_row(t.id);
        }
    }

    fn on_abort_done(&self, t: Ticket, label: String, r: wol_core::Result<()>) {
        let current = self.remote.borrow_mut().end_user(&t);
        self.refresh_remote_row(t.id);
        match r {
            Ok(()) => {
                // Always said: it ran (review C1).
                self.toast(ToastKind::Info, Msg::ShutdownAborted { label }, Text::Empty);
                let ended = if current {
                    self.remote.borrow_mut().cancel_verify(t.id)
                } else {
                    None
                };
                if let Some(ended) = ended {
                    self.sched.borrow_mut().remote_finished(
                        t.id,
                        RemoteEnd::Restore,
                        Instant::now(),
                    );
                    // Nothing happened on the host: its boot still applies (review C4).
                    if let Some(b) = ended.prior_boot {
                        self.remote.borrow_mut().set_boot(t.id, b);
                    }
                    self.refresh_row(t.id);
                    self.refresh_remote_row(t.id);
                    self.update_status_ui();
                    self.auto_boot_if_missing(t.id);
                }
            }
            Err(e) if no_shutdown_pending(&e) => {
                self.toast(
                    ToastKind::Info,
                    Msg::NoShutdownPending { label },
                    Text::Empty,
                );
            }
            Err(e) => {
                log::warn!("{label}: cancel shutdown failed: {e}");
                self.toast(ToastKind::Error, Text::error(&e), Text::Empty);
            }
        }
    }

    /// "Get boot time".
    pub fn fetch_boot_time(&self, id: &str) {
        if !self.idle() {
            return;
        }
        let Some(h) = parse_id(id).and_then(|i| self.managed_host(i)) else {
            return;
        };
        if self.refuse_if_blocked(&h) {
            return;
        }
        self.start_boot(h, Origin::User);
    }

    /// Reads a host's boot time: a user request on the remote pool, an automatic fetch on its
    /// own lane with an unattended client (cross review m1, X2).
    pub(crate) fn start_boot(&self, host: Host, origin: Origin) {
        let id = host.id;
        if origin == Origin::Auto && self.secrets_pending.borrow().contains(&id) {
            // An editor save is still storing this host's passwords: fetched afterwards
            // (`secrets_applied`, cross review m2).
            return;
        }
        let t = match origin {
            Origin::User => self.remote.borrow_mut().begin_user(id),
            Origin::Auto => self.remote.borrow_mut().begin_auto(id),
        };
        let Some(t) = t else {
            return;
        };
        let settings = self.cfg.borrow().settings.clone();
        let secrets = self.secret_queue.barrier();
        match origin {
            Origin::User => {
                self.refresh_remote_row(id);
                let client = self.client.clone();
                self.remote_pool.spawn(move || {
                    let confirmed = before_user_op(&client, &secrets, &host);
                    let r = client.boot_time(&host, &settings);
                    post_ui(move |app| {
                        app.sign_in_confirmed(&host.name, confirmed);
                        app.on_boot_done(t, origin, r);
                    });
                });
            }
            Origin::Auto => {
                // Nobody asked for this host: a Windows host without a saved password is only
                // contacted with the current sign-in when the user confirmed that for its
                // address (`SignInNotConfirmed` otherwise, logged quietly).
                let client = self.client.clone().unattended();
                self.auto_pool.spawn(move || {
                    secrets.wait(SECRET_WAIT);
                    let r = client.boot_time(&host, &settings);
                    post_ui(move |app| app.on_boot_done(t, origin, r));
                });
            }
        }
    }

    /// An editor save's Credential Manager work for `id` ran (passwords written / rebound,
    /// sign-in confirmed): the automatic boot-time fetch that the save would have started
    /// runs now, with the new password (cross review m2).
    pub(crate) fn secrets_applied(&self, id: HostId) {
        self.secrets_pending.borrow_mut().remove(&id);
        if !self.cfg.borrow().settings.remote.auto_boot_time {
            return;
        }
        let online = self.sched.borrow().row_state(id).status == HostStatus::Online;
        let known = self.remote.borrow().boot(id).is_some();
        if online
            && !known
            && let Some(h) = self.managed_host(id)
        {
            self.start_boot(h, Origin::Auto);
        }
    }

    fn on_boot_done(&self, t: Ticket, origin: Origin, r: wol_core::Result<BootInfo>) {
        let current = match origin {
            Origin::User => self.remote.borrow_mut().end_user(&t),
            Origin::Auto => self.remote.borrow_mut().end_auto(&t),
        };
        if origin == Origin::User {
            self.refresh_remote_row(t.id);
        }
        if !current {
            return;
        }
        // Review C6: an automatic fetch wanted while this one ran (the host came online again
        // meanwhile) happens now, and so does one for a result that is outdated.
        let mut again = self.remote.borrow_mut().take_refetch(t.id);
        match r {
            Ok(b) => {
                if self.remote.borrow().accepts_boot(&t) {
                    log::info!(
                        "boot time of {} ({origin:?}): {} [{}]",
                        self.host_name_of(t.id).unwrap_or_default(),
                        boot_text(Lang::En, &b, SystemTime::now()),
                        b.source
                    );
                    self.remote.borrow_mut().set_boot(t.id, b);
                    self.refresh_remote_row(t.id);
                    again = false;
                } else {
                    log::debug!("boot time of {} is outdated; dropped", t.id);
                    again = true;
                }
            }
            Err(e) => match key_step(origin, &e, &t.id.to_string()) {
                KeyStep::Quiet => log::info!("automatic boot time of {}: {e}", t.id),
                KeyStep::NotKey if origin == Origin::Auto => {
                    // Right after a wake the host answers the probe before sshd / SMB accept
                    // logons: network errors are tried again a few times (review C6);
                    // permission, sign-in and host-key errors are not.
                    let retry = e.is_remote_transient()
                        && self
                            .remote
                            .borrow_mut()
                            .schedule_retry(t.id, Instant::now());
                    log::info!(
                        "automatic boot time of {}: {e}{}",
                        t.id,
                        if retry { " (will try again)" } else { "" }
                    );
                }
                KeyStep::NotKey => {
                    log::warn!("boot time of {}: {e}", t.id);
                    self.toast(ToastKind::Error, Text::error(&e), Text::Empty);
                }
                step => self.host_key_step(step, Retry::BootTime(t.id)),
            },
        }
        if again {
            self.auto_boot_if_missing(t.id);
        }
    }

    /// Timer: automatic boot-time retries that are due (review C6), for hosts that are still
    /// online without a known boot.
    pub(crate) fn run_due_boot_retries(&self) {
        let due = self.remote.borrow_mut().due_retries(Instant::now());
        for id in due {
            self.auto_boot_if_missing(id);
        }
    }

    /// A host's status changed: clear its boot time when it went down, fetch it when a managed
    /// host came online (`settings.remote.auto_boot_time`).
    pub(crate) fn remote_status_changed(&self, id: HostId, prev: HostStatus, now: HostStatus) {
        if prev == now {
            return;
        }
        if matches!(now, HostStatus::Offline | HostStatus::Timeout) {
            if self.remote.borrow_mut().clear_boot(id) {
                self.refresh_remote_row(id);
            }
            return;
        }
        let enabled = self.cfg.borrow().settings.remote.auto_boot_time;
        let host = self.managed_host(id);
        if auto_boot_wanted(prev, now, host.is_some(), enabled)
            && let Some(h) = host
        {
            self.start_boot(h, Origin::Auto);
        }
    }

    /// `remote.auto_boot_time` was turned on: fetch for the managed hosts that are online and
    /// have no boot time yet.
    pub(crate) fn auto_boot_online_hosts(&self) {
        let hosts: Vec<Host> = {
            let cfg = self.cfg.borrow();
            let sched = self.sched.borrow();
            let remote = self.remote.borrow();
            cfg.hosts
                .iter()
                .filter(|h| {
                    h.remote.is_some()
                        && sched.row_state(h.id).status == HostStatus::Online
                        && remote.boot(h.id).is_none()
                })
                .cloned()
                .collect()
        };
        for h in hosts {
            self.start_boot(h, Origin::Auto);
        }
    }

    /// A wake superseded a restart / shutdown verification.
    pub(crate) fn remote_wake_started(&self, id: HostId) {
        let _ = self.remote.borrow_mut().cancel_verify(id);
    }

    /// Follows a new config (from `reconcile_from`): stale work is cancelled, the status of
    /// cancelled verifications restored, and a host that was just set up for remote management
    /// while online gets its boot time (`auto_boot_time`).
    pub(crate) fn remote_sync(&self) {
        let synced = {
            let cfg = self.cfg.borrow();
            self.remote.borrow_mut().sync(&cfg)
        };
        let now = Instant::now();
        for id in &synced.reset {
            log::info!("{id}: remote management changed; verification cancelled");
            self.sched
                .borrow_mut()
                .remote_finished(*id, RemoteEnd::Restore, now);
        }
        if !self.cfg.borrow().settings.remote.auto_boot_time {
            return;
        }
        for id in synced.changed {
            let online = self.sched.borrow().row_state(id).status == HostStatus::Online;
            if online && let Some(h) = self.managed_host(id) {
                self.start_boot(h, Origin::Auto);
            }
        }
    }

    // ---- host keys -----------------------------------------------------------------------

    /// Handles the host-key part of a failed user operation.
    pub(crate) fn host_key_step(&self, step: KeyStep, retry: Retry) {
        match step {
            KeyStep::NotKey | KeyStep::Quiet => {}
            KeyStep::Ask(p) | KeyStep::Mismatch(p) => {
                self.show_top(TopDialog::HostKey(p, retry));
            }
            KeyStep::TrustKnown(p) => self.trust_key(p, retry, true),
        }
    }

    fn trust_key(&self, p: HostKeyPrompt, retry: Retry, known: bool) {
        match retry {
            Retry::Test { .. } | Retry::Mac { .. } => self.editor_trust_key(&p, retry, known),
            Retry::BootTime(id) | Retry::Power(PowerReq { id, .. }) => {
                let name = self.host_name_of(id).unwrap_or_default();
                log::info!("{name}: trusting SSH host key {}", p.fingerprint);
                self.submit(
                    Op::TrustHostKey {
                        id,
                        line: p.key_line.to_string(),
                        // Pinned only while the host still has the endpoint the key came from
                        // and no other key (an unknown key: nothing was pinned; review S4).
                        basis: trust_basis(&p),
                    },
                    Pending::TrustKey {
                        name,
                        fingerprint: p.fingerprint.to_string(),
                        retry,
                        known,
                    },
                );
            }
        }
    }

    /// The trusted key is saved: tell the user and run the interrupted operation again with
    /// the host as saved (`cfg`; the app's own copy may still be deferred).
    pub(crate) fn host_key_trusted(
        &self,
        name: String,
        fingerprint: String,
        retry: Retry,
        known: bool,
        cfg: &Config,
    ) {
        let msg = if known {
            Msg::HostKeyFromKnownHosts {
                label: name,
                fingerprint,
            }
        } else {
            Msg::HostKeyTrusted {
                label: name,
                fingerprint,
            }
        };
        self.toast(ToastKind::Info, msg, Text::Empty);
        let managed = |id: HostId| cfg.get(id).filter(|h| h.remote.is_some()).cloned();
        match retry {
            Retry::BootTime(id) => {
                if let Some(h) = managed(id) {
                    self.start_boot(h, Origin::User);
                }
            }
            Retry::Power(req) => match managed(req.id) {
                // Only what the power dialog showed (review S1).
                Some(h) if power_matches(&h, &req) => {
                    if !self.refuse_if_blocked(&h) {
                        self.run_power(h, req);
                    }
                }
                other => {
                    let label = other.map(|h| h.name).unwrap_or_default();
                    self.power_host_changed(&label);
                }
            },
            Retry::Test { .. } | Retry::Mac { .. } => {}
        }
    }

    /// Host-key dialog: Trust.
    pub fn hostkey_trusted(&self, p: HostKeyPrompt) {
        let shown = self.hostkey_shown.borrow_mut().take();
        if let Some((prompt, retry)) = shown
            && !prompt.mismatch
            && prompt.key_line == p.key_line
            && !prompt.key_line.is_empty()
        {
            self.trust_key(prompt, retry, false);
        }
        self.pump_top();
    }

    /// Host-key dialog: Cancel / Close / Esc.
    pub fn hostkey_cancelled(&self, _p: HostKeyPrompt) {
        let shown = self.hostkey_shown.borrow_mut().take();
        if let Some((_, retry)) = shown {
            self.editor_retry_abandoned(&retry);
        }
        self.pump_top();
    }

    /// Mismatch dialog: "Forget…".
    pub fn hostkey_forget(&self, _p: HostKeyPrompt) {
        let shown = self.hostkey_shown.borrow_mut().take();
        match shown {
            Some((_, retry)) if retry.editor_token().is_some() => {
                // The pinned key belongs to the editor's draft: a draft flag, no confirm.
                self.editor_forget_key(&retry);
            }
            Some((prompt, _)) => {
                if let Some(id) = parse_id(&prompt.host_id)
                    && let Some(name) = self.host_name_of(id)
                {
                    self.show_top(TopDialog::Confirm(ConfirmRequest {
                        kind: ConfirmKind::ForgetHostKey,
                        host_id: prompt.host_id.clone(),
                        subject: name.into(),
                        ..ConfirmRequest::default()
                    }));
                }
            }
            None => {}
        }
        self.pump_top();
    }

    /// Confirmed "forget the host key".
    pub(crate) fn forget_host_key(&self, req: &ConfirmRequest) {
        let Some(id) = parse_id(&req.host_id) else {
            return;
        };
        let name = self.host_name_of(id).unwrap_or_default();
        self.submit(Op::ForgetHostKey { id }, Pending::ForgetKey { name });
    }

    /// App exit: stop every verification.
    pub(crate) fn cancel_remote_work(&self) {
        self.remote.borrow_mut().cancel_all();
    }
}

// ---------------------------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use wol_core::remote::{RemoteClient, SystemSsh, SystemWindows, VerifyEnv};
    use wol_core::secret::SecretStore;
    use wol_core::{HostAddr, MacAddr, RemoteConfig, Settings};

    fn managed(name: &str, kind: wol_core::RemoteKind, addr: &str) -> Host {
        let mut h = Host::new(name, MacAddr::parse("00:11:22:33:44:55").unwrap());
        h.address = Some(HostAddr::parse(addr).unwrap());
        h.remote = Some(RemoteConfig::new(kind));
        h
    }

    fn cfg(hosts: Vec<Host>) -> Config {
        Config {
            hosts,
            ..Config::default()
        }
    }

    fn boot(ago: Duration, now: SystemTime) -> BootInfo {
        BootInfo {
            boot_time: now - ago,
            uptime: ago,
            source: "test".into(),
            approximate: false,
            boot_id: None,
        }
    }

    fn problem(in_known_hosts: bool) -> HostKeyProblem {
        HostKeyProblem {
            host: "pve".into(),
            address: "100.105.1.2".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:abc".into(),
            openssh_line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into(),
            expected_fingerprint: None,
            in_known_hosts,
        }
    }

    #[test]
    fn boot_text_follows_the_clock_and_language() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_669_520);
        let b = boot(Duration::from_secs(3 * 3600 + 12 * 60), now);
        let ja = boot_text(Lang::Ja, &b, now);
        assert!(ja.starts_with("起動 "), "{ja}");
        assert!(ja.ends_with("（稼働 3時間12分）"), "{ja}");
        let en = boot_text(Lang::En, &b, now);
        assert!(
            en.starts_with("Up since ") && en.ends_with("(3h 12m)"),
            "{en}"
        );
        // The uptime grows with the clock (the boot time stays).
        let later = boot_text(Lang::En, &b, now + Duration::from_secs(3600));
        assert!(later.ends_with("(4h 12m)"), "{later}");
        // The UI adds its own "approx." marker.
        let approx = BootInfo {
            approximate: true,
            ..b.clone()
        };
        assert!(!boot_text(Lang::En, &approx, now).contains("approx"));
        // A clock that went backwards falls back to the reported uptime.
        assert!(
            boot_text(Lang::En, &b, now - Duration::from_secs(86_400 * 2)).ends_with("(3h 12m)")
        );
    }

    #[test]
    fn state_rows_tickets_and_generations() {
        let now = SystemTime::now();
        let h = managed("pc", wol_core::RemoteKind::Windows, "10.0.0.5");
        let id = h.id;
        let mut c = cfg(vec![h]);
        let mut st = RemoteState::default();
        assert_eq!(st.sync(&c), Synced::default());
        assert_eq!(st.row(id, Lang::En, now), RemoteRow::default());

        // User operation: busy until it ends; a second one is refused.
        let t = st.begin_user(id).unwrap();
        assert!(st.is_busy(id));
        assert!(st.row(id, Lang::En, now).busy);
        assert!(st.begin_user(id).is_none());
        assert!(st.begin_auto(id).is_none(), "no automatic fetch while busy");
        assert!(st.end_user(&t));
        assert!(st.accepts_boot(&t));
        st.set_boot(id, boot(Duration::from_secs(600), now));
        let row = st.row(id, Lang::En, now);
        assert!(!row.busy && row.boot_text.ends_with("(10m)"));

        // Going offline clears the boot; a fetch started before is no longer shown.
        let t2 = st.begin_user(id).unwrap();
        assert!(st.clear_boot(id));
        assert!(!st.clear_boot(id));
        assert!(st.end_user(&t2), "the operation itself is current");
        assert!(!st.accepts_boot(&t2), "but its boot time is outdated");

        // An unrelated edit keeps everything; a new management address starts over.
        let t3 = st.begin_user(id).unwrap();
        st.set_boot(id, boot(Duration::from_secs(60), now));
        c.hosts[0].name = "renamed".into();
        assert_eq!(st.sync(&c), Synced::default(), "rename");
        assert!(st.boot(id).is_some() && st.is_busy(id));
        c.hosts[0].remote.as_mut().unwrap().address = Some(HostAddr::parse("100.64.0.9").unwrap());
        assert_eq!(st.sync(&c).changed, vec![id], "new endpoint");
        assert!(st.boot(id).is_none());
        assert!(!st.is_busy(id), "stale busy marker cleared");
        assert!(!st.end_user(&t3), "stale result dropped");
        // Deleted hosts are forgotten.
        c.hosts.clear();
        st.sync(&c);
        assert!(st.begin_user(id).is_none());
    }

    #[test]
    fn auto_boot_trigger_rules() {
        use HostStatus as S;
        // Transition to Online only (also the first check after the start).
        assert!(auto_boot_wanted(S::Checking, S::Online, true, true));
        assert!(auto_boot_wanted(S::Offline, S::Online, true, true));
        assert!(auto_boot_wanted(S::Waking, S::Online, true, true));
        assert!(auto_boot_wanted(S::Timeout, S::Online, true, true));
        assert!(
            !auto_boot_wanted(S::Online, S::Online, true, true),
            "periodic checks"
        );
        assert!(!auto_boot_wanted(S::Checking, S::Offline, true, true));
        assert!(
            !auto_boot_wanted(S::Restarting, S::Online, true, true),
            "the verification refreshes it"
        );
        assert!(
            !auto_boot_wanted(S::Checking, S::Online, false, true),
            "unmanaged"
        );
        assert!(
            !auto_boot_wanted(S::Checking, S::Online, true, false),
            "setting off"
        );

        // One in flight per host; never while verifying.
        let h = managed("pc", wol_core::RemoteKind::Ssh, "10.0.0.5");
        let id = h.id;
        let mut st = RemoteState::default();
        st.sync(&cfg(vec![h]));
        let t = st.begin_auto(id).unwrap();
        assert!(st.begin_auto(id).is_none());
        assert!(!st.row(id, Lang::Ja, SystemTime::now()).busy, "no spinner");
        let tu = st.begin_user(id).expect("the user may still ask");
        assert!(st.end_auto(&t));
        assert!(st.end_user(&tu));
        let v = st.begin_user(id).unwrap();
        st.end_user(&v);
        st.start_verify(&v, core::PowerAction::Restart).unwrap();
        assert!(st.begin_auto(id).is_none());

        // Automatic fetches never open the host-key dialog.
        let e = Error::UnknownHostKey(Box::new(problem(false)));
        assert_eq!(key_step(Origin::Auto, &e, ""), KeyStep::Quiet);
        let m = Error::HostKeyMismatch(Box::new(problem(false)));
        assert_eq!(key_step(Origin::Auto, &m, ""), KeyStep::Quiet);
    }

    #[test]
    fn host_key_decisions() {
        let id = HostId::new_v4().to_string();
        let e = Error::UnknownHostKey(Box::new(problem(false)));
        match key_step(Origin::User, &e, &id) {
            KeyStep::Ask(p) => {
                assert_eq!(p.host_id, id.as_str());
                assert_eq!(p.host_name, "pve");
                assert_eq!(p.port, 22);
                assert_eq!(p.key_type, "ssh-ed25519");
                assert_eq!(p.fingerprint, "SHA256:abc");
                assert!(p.key_line.starts_with("ssh-ed25519 "));
                assert!(!p.mismatch);
            }
            other => panic!("{other:?}"),
        }
        // Already trusted by OpenSSH: pinned with a notice.
        let known = Error::UnknownHostKey(Box::new(problem(true)));
        assert!(matches!(
            key_step(Origin::User, &known, ""),
            KeyStep::TrustKnown(p) if p.host_id.is_empty()
        ));
        // Mismatch: never offers the received key for pinning.
        let mut mp = problem(false);
        mp.expected_fingerprint = Some("SHA256:old".into());
        mp.openssh_line = String::new();
        let m = Error::HostKeyMismatch(Box::new(mp));
        match key_step(Origin::User, &m, &id) {
            KeyStep::Mismatch(p) => {
                assert!(p.mismatch);
                assert_eq!(p.expected_fingerprint, "SHA256:old");
                assert_eq!(p.key_line, "");
            }
            other => panic!("{other:?}"),
        }
        let other = Error::RemoteNotConfigured { host: "x".into() };
        assert_eq!(key_step(Origin::User, &other, &id), KeyStep::NotKey);
        assert!(!no_shutdown_pending(&other) && !power_unconfirmed(&other));
        assert_eq!(
            Retry::Test { token: 4 }.editor_token(),
            Some(4),
            "editor retries follow the editor"
        );
        assert_eq!(Retry::BootTime(HostId::new_v4()).editor_token(), None);
    }

    #[test]
    fn power_request_mapping() {
        let mut s = RemoteSettings::default();
        let h = managed("PC", wol_core::RemoteKind::Windows, "192.168.1.5");
        let req = power_request(&h, crate::PowerAction::Restart, &s).unwrap();
        assert_eq!(req.host_id, h.id.to_string().as_str());
        assert_eq!(
            req.address, "192.168.1.5",
            "management address = host address"
        );
        assert_eq!(req.kind, RemoteKind::Windows);
        assert_eq!(req.delay_secs, 30);
        assert!(req.force);
        assert_eq!(req.message, "");
        assert_eq!(req.command, "", "Windows hosts run no custom command");
        // Cross review X1: an SSH host's own command is always shown in the dialog.
        let mut nas = managed("NAS", wol_core::RemoteKind::Ssh, "192.0.2.20");
        nas.remote.as_mut().unwrap().reboot_command = Some(" /sbin/reboot -f ".into());
        assert_eq!(
            power_request(&nas, crate::PowerAction::Restart, &s)
                .unwrap()
                .command,
            "/sbin/reboot -f"
        );
        assert_eq!(
            power_request(&nas, crate::PowerAction::Shutdown, &s)
                .unwrap()
                .command,
            ""
        );
        // The management address wins.
        let mut v = h.clone();
        v.remote.as_mut().unwrap().address = Some(HostAddr::parse("100.105.1.2").unwrap());
        s.shutdown_delay_secs = 0;
        s.force_apps_closed = false;
        let r2 = power_request(&v, crate::PowerAction::Shutdown, &s).unwrap();
        assert_eq!(r2.address, "100.105.1.2");
        assert_eq!((r2.delay_secs, r2.force), (0, false));
        assert!(power_request(&Host::default(), crate::PowerAction::Restart, &s).is_none());

        // Dialog result → request.
        let mut edited = req.clone();
        edited.delay_secs = 9999;
        edited.message = "  Maintenance  ".into();
        let r = power_req(&edited).unwrap();
        assert_eq!(r.id, h.id);
        assert_eq!(r.action, core::PowerAction::Restart);
        assert_eq!(r.opts.delay_secs, 600, "clamped");
        assert!(r.opts.force);
        assert_eq!(r.opts.message.as_deref(), Some("Maintenance"));
        // No countdown: the message has nowhere to show.
        edited.delay_secs = 0;
        assert_eq!(power_req(&edited).unwrap().opts.message, None);
        edited.delay_secs = -5;
        assert_eq!(power_req(&edited).unwrap().opts.delay_secs, 0);
        // Long messages are capped.
        edited.delay_secs = 30;
        edited.message = "x".repeat(2000).into();
        assert_eq!(
            power_req(&edited)
                .unwrap()
                .opts
                .message
                .unwrap()
                .chars()
                .count(),
            MESSAGE_MAX_CHARS
        );
        // SSH ignores the Windows options.
        let mut ssh = edited.clone();
        ssh.kind = RemoteKind::Ssh;
        ssh.action = crate::PowerAction::Shutdown;
        let r = power_req(&ssh).unwrap();
        assert_eq!(r.opts, PowerOptions::default());
        assert_eq!(r.action, core::PowerAction::Shutdown);
        edited.host_id = "nope".into();
        assert!(power_req(&edited).is_none());
        // Toast texts.
        assert!(matches!(
            accepted_msg(
                "PC",
                core::PowerAction::Restart,
                &PowerOutcome::Scheduled { delay_secs: 30 }
            ),
            Msg::PowerScheduled { secs: 30, .. }
        ));
        assert!(matches!(
            accepted_msg("PC", core::PowerAction::Shutdown, &PowerOutcome::Accepted),
            Msg::PowerAccepted { .. }
        ));
    }

    #[test]
    fn verification_results_map_to_statuses() {
        let now = SystemTime::now();
        let b = boot(Duration::from_secs(20), now);
        let e = verify_end(
            "PC",
            600,
            Verified::Restart(RestartVerify::Restarted { boot: b.clone() }),
        )
        .unwrap();
        assert!(matches!(e.end, RemoteEnd::Up { .. }));
        assert_eq!(e.boot, Some(b));
        assert_eq!(e.toast.0, ToastKind::Success);

        let e = verify_end(
            "PC",
            600,
            Verified::Restart(RestartVerify::TimedOut {
                went_down: true,
                online: false,
                last_error: None,
            }),
        )
        .unwrap();
        assert_eq!(e.end, RemoteEnd::Timeout);
        assert_eq!(e.toast.0, ToastKind::Error);
        assert!(e.toast.1.render(Lang::En).contains("600"));

        let e = verify_end("PC", 300, Verified::Shutdown(ShutdownVerify::ShutDown)).unwrap();
        assert_eq!(e.end, RemoteEnd::Offline);
        assert_eq!(e.toast.0, ToastKind::Success);

        let up = HostState::Up {
            via: probe::ProbeVia::Tcp { port: 445 },
            rtt: Duration::from_millis(7),
            ip: std::net::Ipv4Addr::LOCALHOST,
        };
        let e = verify_end(
            "PC",
            300,
            Verified::Shutdown(ShutdownVerify::TimedOut { last: up }),
        )
        .unwrap();
        assert_eq!(
            e.end,
            RemoteEnd::Up {
                via: ProbeVia::Tcp,
                rtt_ms: 7
            }
        );
        assert_eq!(e.toast.0, ToastKind::Warning);
        let e = verify_end("PC", 300, Verified::Shutdown(ShutdownVerify::NotMonitored)).unwrap();
        assert_eq!(e.end, RemoteEnd::Restore);
        let e = verify_end(
            "PC",
            300,
            Verified::Restart(RestartVerify::Failed(Error::RemoteNotConfigured {
                host: "PC".into(),
            })),
        )
        .unwrap();
        assert_eq!(e.end, RemoteEnd::Restore);
        assert_eq!(e.toast.0, ToastKind::Error);
        assert!(verify_end("PC", 1, Verified::Restart(RestartVerify::Cancelled)).is_none());
        assert!(verify_end("PC", 1, Verified::Shutdown(ShutdownVerify::Cancelled)).is_none());
    }

    /// Scripted probes and a fake clock for wol-core's verification loops (no network, no
    /// power API: `verify_shutdown` only probes).
    struct Script {
        probes: Mutex<Vec<bool>>,
        now: Mutex<Instant>,
    }

    impl VerifyEnv for Script {
        fn probe(&self, _spec: &probe::ProbeSpec) -> HostState {
            let up = {
                let mut p = self.probes.lock().unwrap();
                if p.is_empty() { false } else { p.remove(0) }
            };
            if up {
                HostState::Up {
                    via: probe::ProbeVia::Icmp,
                    rtt: Duration::from_millis(1),
                    ip: std::net::Ipv4Addr::LOCALHOST,
                }
            } else {
                HostState::Down {
                    ip: std::net::Ipv4Addr::LOCALHOST,
                }
            }
        }
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
        fn sleep_until(&self, until: Instant, cancel: &AtomicBool) -> bool {
            *self.now.lock().unwrap() = until;
            !cancel.load(Ordering::Relaxed)
        }
    }

    fn client(script: Vec<bool>) -> (RemoteClient, Instant) {
        let t0 = Instant::now();
        let env = Script {
            probes: Mutex::new(script),
            now: Mutex::new(t0),
        };
        let c = RemoteClient::new(
            SecretStore::in_memory(),
            Arc::new(SystemWindows),
            Arc::new(SystemSsh),
        )
        .with_verify_env(Arc::new(env));
        (c, t0)
    }

    #[test]
    fn shutting_down_goes_offline_after_three_failed_probes() {
        let h = managed("pc", wol_core::RemoteKind::Windows, "192.0.2.10");
        let s = Settings::default();
        let cancel = AtomicBool::new(false);
        // Still up twice, then three failures in a row.
        let (c, t0) = client(vec![true, true, false, false, false, true]);
        let mut ticks = 0;
        let v = c.verify_shutdown(&h, &s, t0 + Duration::from_secs(300), &cancel, |_| {
            ticks += 1
        });
        assert_eq!(v, ShutdownVerify::ShutDown);
        assert_eq!(ticks, 5);
        let end = verify_end("pc", 300, Verified::Shutdown(v)).unwrap();
        assert_eq!(end.end, RemoteEnd::Offline);

        // A failure streak that is interrupted does not count; the deadline ends it.
        let (c, t0) = client(vec![false, false, true, false, false, true, true, true]);
        let v = c.verify_shutdown(&h, &s, t0 + Duration::from_secs(20), &cancel, |_| {});
        assert!(matches!(v, ShutdownVerify::TimedOut { .. }), "{v:?}");
        let end = verify_end("pc", 20, Verified::Shutdown(v)).unwrap();
        assert!(matches!(end.end, RemoteEnd::Up { .. }));

        // Cancelled (app exit, host edited).
        let (c, t0) = client(vec![true; 10]);
        cancel.store(true, Ordering::Relaxed);
        let v = c.verify_shutdown(&h, &s, t0 + Duration::from_secs(300), &cancel, |_| {});
        assert_eq!(v, ShutdownVerify::Cancelled);
        assert!(verify_end("pc", 300, Verified::Shutdown(v)).is_none());
    }

    #[test]
    fn verification_tokens_and_cancel() {
        let h = managed("pc", wol_core::RemoteKind::Windows, "10.0.0.5");
        let id = h.id;
        let mut c = cfg(vec![h]);
        let mut st = RemoteState::default();
        st.sync(&c);
        let t = st.begin_user(id).unwrap();
        st.end_user(&t);
        let (tok1, cancel1) = st.start_verify(&t, core::PowerAction::Shutdown).unwrap();
        assert_eq!(st.verifying(id), Some(core::PowerAction::Shutdown));
        // A second request replaces (and cancels) the first verification.
        let (tok2, _cancel2) = st.start_verify(&t, core::PowerAction::Restart).unwrap();
        assert!(cancel1.load(Ordering::Relaxed));
        assert_eq!(st.take_verify(id, tok1), None, "replaced");
        assert_eq!(
            st.take_verify(id, tok2).map(|e| e.action),
            Some(core::PowerAction::Restart)
        );
        assert_eq!(st.verifying(id), None);
        // Cancel by the user (abort) or by an edit of the endpoint.
        let (_, c3) = st.start_verify(&t, core::PowerAction::Restart).unwrap();
        assert!(st.cancel_verify(id).is_some());
        assert!(c3.load(Ordering::Relaxed));
        assert!(st.cancel_verify(id).is_none());
        let (_, c4) = st.start_verify(&t, core::PowerAction::Restart).unwrap();
        c.hosts[0].address = Some(HostAddr::parse("10.0.0.6").unwrap());
        assert_eq!(
            st.sync(&c),
            Synced {
                reset: vec![id],
                changed: vec![id]
            },
            "status to restore"
        );
        assert!(c4.load(Ordering::Relaxed));
        assert!(
            st.start_verify(&t, core::PowerAction::Restart).is_none(),
            "stale ticket"
        );
        // App exit.
        let t = st.begin_user(id).unwrap();
        let (_, c5) = st.start_verify(&t, core::PowerAction::Shutdown).unwrap();
        st.cancel_all();
        assert!(c5.load(Ordering::Relaxed));
        assert_eq!(st.verifying(id), None);
    }
    /// Review C1: probe settings are not part of the remote generation (a probe change
    /// neither cancels a verification nor drops results or boot times); the endpoint is.
    #[test]
    fn probe_changes_keep_remote_work_and_boot_times() {
        let now = SystemTime::now();
        let h = managed("pc", wol_core::RemoteKind::Windows, "10.0.0.5");
        let id = h.id;
        let mut c = cfg(vec![h]);
        let mut st = RemoteState::default();
        st.sync(&c);
        let t = st.begin_user(id).unwrap();
        st.set_boot(id, boot(Duration::from_secs(60), now));
        c.settings.probe.timeout_ms = 2500;
        c.settings.probe.tcp_ports = vec![22];
        c.hosts[0].probe = Some(wol_core::probe::ProbeMethod::Icmp);
        c.hosts[0].tcp_ports = vec![8080];
        assert_eq!(st.sync(&c), Synced::default());
        assert!(st.boot(id).is_some() && st.is_busy(id));
        assert!(st.end_user(&t), "the result still counts");
        let (_, cancel) = st.start_verify(&t, core::PowerAction::Restart).unwrap();
        c.settings.probe.timeout_ms = 900;
        assert_eq!(st.sync(&c), Synced::default());
        assert!(!cancel.load(Ordering::Relaxed), "not cancelled");
        assert_eq!(st.verifying(id), Some(core::PowerAction::Restart));
        // The endpoint (kind, management address, SSH port) is.
        c.hosts[0].remote.as_mut().unwrap().kind = wol_core::RemoteKind::Ssh;
        assert_eq!(st.sync(&c).reset, vec![id]);
        assert!(cancel.load(Ordering::Relaxed));
        assert_eq!(remote_key(&c.hosts[0]), {
            let mut x = c.hosts[0].clone();
            x.probe = None;
            remote_key(&x)
        });
    }

    /// Review C4: the boot known before a restart / shutdown comes back when the host did
    /// not go down (cancelled countdown, shutdown not seen), not after a verified change.
    #[test]
    fn prior_boot_survives_a_cancelled_or_unseen_shutdown() {
        let now = SystemTime::now();
        let h = managed("pc", wol_core::RemoteKind::Windows, "10.0.0.5");
        let id = h.id;
        let c = cfg(vec![h]);
        let mut st = RemoteState::default();
        st.sync(&c);
        let b = boot(Duration::from_secs(3600), now);
        st.set_boot(id, b.clone());
        let t = st.begin_user(id).unwrap();
        st.end_user(&t);
        let (tok, _) = st.start_verify(&t, core::PowerAction::Shutdown).unwrap();
        assert!(st.boot(id).is_none(), "cleared while verifying");
        // A fetch started before the request is outdated now.
        assert!(!st.accepts_boot(&t));
        let ended = st.cancel_verify(id).unwrap();
        assert_eq!(
            ended.prior_boot.as_ref(),
            Some(&b),
            "Cancel shutdown: kept aside"
        );
        // A second request while one is verified keeps the first prior boot.
        st.set_boot(id, b.clone());
        let (_, _) = st.start_verify(&t, core::PowerAction::Shutdown).unwrap();
        let (tok2, _) = st.start_verify(&t, core::PowerAction::Restart).unwrap();
        assert_eq!(st.take_verify(id, tok2).unwrap().prior_boot, Some(b));
        assert!(st.take_verify(id, tok).is_none());
        // Which ends keep it.
        let up = HostState::Up {
            via: probe::ProbeVia::Icmp,
            rtt: Duration::from_millis(1),
            ip: std::net::Ipv4Addr::LOCALHOST,
        };
        let down = HostState::Down {
            ip: std::net::Ipv4Addr::LOCALHOST,
        };
        let keep = |v| verify_end("pc", 1, v).unwrap().keep_prior_boot;
        assert!(keep(Verified::Shutdown(ShutdownVerify::TimedOut {
            last: up
        })));
        assert!(keep(Verified::Shutdown(ShutdownVerify::NotMonitored)));
        assert!(!keep(Verified::Shutdown(ShutdownVerify::TimedOut {
            last: down
        })));
        assert!(!keep(Verified::Shutdown(ShutdownVerify::ShutDown)));
        assert!(!keep(Verified::Restart(RestartVerify::Failed(
            Error::RemoteNotConfigured { host: "pc".into() }
        ))));
    }

    /// Review C6: an automatic fetch wanted while another ran happens afterwards, and network
    /// failures are tried again a few times (never for good once the host is offline).
    #[test]
    fn automatic_fetches_are_not_lost() {
        let now = Instant::now();
        let h = managed("pc", wol_core::RemoteKind::Ssh, "10.0.0.5");
        let id = h.id;
        let mut st = RemoteState::default();
        st.sync(&cfg(vec![h]));
        let t = st.begin_auto(id).unwrap();
        // Offline and online again while it runs: refused now, wanted afterwards.
        st.clear_boot(id);
        assert!(st.begin_auto(id).is_none());
        assert!(st.end_auto(&t));
        assert!(!st.accepts_boot(&t), "outdated");
        assert!(st.take_refetch(id));
        assert!(!st.take_refetch(id), "once");
        // Retries with growing delays, then no more.
        for (i, d) in AUTO_RETRY_DELAYS.iter().enumerate() {
            assert!(st.schedule_retry(id, now), "retry {i}");
            assert!(
                st.due_retries(now + *d - Duration::from_millis(1))
                    .is_empty()
            );
            assert_eq!(st.due_retries(now + *d), vec![id]);
            assert!(st.due_retries(now + *d).is_empty(), "returned once");
        }
        assert!(!st.schedule_retry(id, now), "all used");
        // A success or the host going offline starts over; so does a scheduled retry.
        st.set_boot(id, boot(Duration::from_secs(5), SystemTime::now()));
        assert!(st.schedule_retry(id, now));
        st.clear_boot(id);
        assert!(st.due_retries(now + Duration::from_secs(3600)).is_empty());
        assert!(st.schedule_retry(id, now));
    }

    /// Review S1 / C9: a confirmed request runs only against what the dialog showed.
    #[test]
    fn power_requests_run_only_as_shown() {
        let s = RemoteSettings::default();
        let mut nas = managed("NAS", wol_core::RemoteKind::Ssh, "192.0.2.20");
        nas.remote.as_mut().unwrap().reboot_command = Some("/sbin/reboot".into());
        let req =
            power_req(&power_request(&nas, crate::PowerAction::Restart, &s).unwrap()).unwrap();
        assert_eq!(
            (req.address.as_str(), req.command.as_str()),
            ("192.0.2.20", "/sbin/reboot")
        );
        assert!(power_matches(&nas, &req));
        // Re-pointed while the dialog was open.
        let mut moved = nas.clone();
        moved.remote.as_mut().unwrap().address = Some(HostAddr::parse("192.0.2.21").unwrap());
        assert!(!power_matches(&moved, &req));
        // Another command.
        let mut cmd = nas.clone();
        cmd.remote.as_mut().unwrap().reboot_command = Some("/usr/sbin/reboot -f".into());
        assert!(!power_matches(&cmd, &req));
        // Another kind.
        let mut kind = nas.clone();
        kind.remote.as_mut().unwrap().kind = wol_core::RemoteKind::Windows;
        assert!(!power_matches(&kind, &req));
        // Unrelated edits are fine.
        let mut renamed = nas.clone();
        renamed.name = "Storage".into();
        renamed.notes = Some("x".into());
        assert!(power_matches(&renamed, &req));
    }
}
