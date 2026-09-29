//! Verification of accepted restart / shutdown requests (polling state machines).
//!
//! Both loops run on a [`VerifyEnv`] (probe, clocks, sleep) so tests drive them with a fake
//! clock and scripted probe results; the boot time comes from the [`RemoteClient`] (mock
//! backends in tests).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;

use super::{BootInfo, RemoteClient, RemoteFailure};
use crate::error::{Error, ErrorKind};
use crate::model::{Host, RemoteKind, Settings};
use crate::probe::{self, HostState, ProbeMethod, ProbeSpec};

/// Poll interval of [`super::verify_restart`].
pub const RESTART_POLL: Duration = Duration::from_secs(5);
/// Poll interval of [`super::verify_shutdown`].
pub const SHUTDOWN_POLL: Duration = Duration::from_secs(3);
/// Failed probes in a row that confirm a shutdown.
pub const SHUTDOWN_FAILURES: u32 = 3;

/// A boot read during [`super::verify_restart`] is new when its uptime is at most the time
/// since the verification started plus this (round trip and rounding of the host's clock).
pub const NEW_BOOT_SLACK: Duration = Duration::from_secs(10);

/// While the probe says "down", the restart verification still reads the boot time every
/// this many rounds: probes can have blind spots (ICMP filtered on a VPN...).
const DOWN_READ_EVERY: u32 = 3;

/// Consecutive permission errors (wrong password, access denied) that end the restart
/// verification: polling every 5 s would otherwise risk an account lockout / fail2ban.
const PERMISSION_FAILURES_FATAL: u32 = 2;

/// Probe, clocks and sleep used by the verification loops (a test seam).
pub trait VerifyEnv: Send + Sync {
    /// One probe. **Blocking** (see [`probe::probe`]).
    fn probe(&self, spec: &ProbeSpec) -> HostState {
        probe::probe(spec)
    }
    /// Monotonic now.
    fn now(&self) -> Instant {
        Instant::now()
    }
    /// Wall clock now (not used by the loops any more: they compare uptimes with the
    /// monotonic clock; kept for implementors).
    fn wall_clock(&self) -> SystemTime {
        SystemTime::now()
    }
    /// Sleeps until `until`, waking at least every 100 ms to check `cancel`. Returns `false`
    /// when cancelled.
    fn sleep_until(&self, until: Instant, cancel: &AtomicBool) -> bool {
        loop {
            if cancel.load(Ordering::Relaxed) {
                return false;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }
}

/// Real probes, clocks and sleep.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemVerifyEnv;

impl VerifyEnv for SystemVerifyEnv {}

/// What the last round saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum VerifyPhase {
    /// The host answers (restart: still the old boot, or the boot time is not readable yet).
    Up,
    /// The host does not answer (`failures` rounds in a row without an answer).
    Down {
        /// Consecutive rounds without an answer.
        failures: u32,
    },
}

/// Progress of a verification round (for `--wait` output / GUI tooltips).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyTick {
    /// Phase after this round.
    pub phase: VerifyPhase,
    /// The probe result of this round ([`HostState::Unknown`] when the host is not probed).
    pub state: HostState,
    /// Time since the verification started.
    #[serde(rename = "elapsed_ms", serialize_with = "ser_ms")]
    pub elapsed: Duration,
}

fn ser_ms<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_millis() as u64)
}

/// How [`super::verify_restart`] ended.
#[derive(Debug)]
pub enum RestartVerify {
    /// Back online with a new boot (refresh the displayed boot time with `boot`).
    Restarted {
        /// The new boot.
        boot: BootInfo,
    },
    /// The deadline passed.
    TimedOut {
        /// The host stopped answering at least once (probe down, or, when it is not probed,
        /// the boot time could not be read because of a network error).
        went_down: bool,
        /// The last round got an answer (probe up, or a boot time / non-network error from
        /// the host). Not monitored + `online` + no `went_down` = it never restarted.
        online: bool,
        /// Last error while reading the boot time, if any.
        last_error: Option<Error>,
    },
    /// An error that polling cannot fix (host key, configuration, stored password, secret
    /// store; permission errors after two in a row).
    Failed(Error),
    /// `cancel` was set.
    Cancelled,
}

/// How [`super::verify_shutdown`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownVerify {
    /// The host stopped answering ([`SHUTDOWN_FAILURES`] probes in a row after it was seen
    /// answering).
    ShutDown,
    /// The deadline passed; the last probe result.
    TimedOut {
        /// Last probe result.
        last: HostState,
    },
    /// Cannot verify: the host is not monitored (no address, probe method `none`), or the
    /// probe never saw it answer in the first [`SHUTDOWN_FAILURES`] rounds (it cannot see this
    /// host, so a missing answer says nothing; review R5).
    NotMonitored,
    /// `cancel` was set.
    Cancelled,
}

/// The probe used for verification: the host's probe settings (method, ports, timeout) on
/// the **management address** (`remote.address`, else `address`): the path that carried the
/// request. The host's `address` is often a LAN address that is not reachable from here when
/// management goes through a VPN (and may even belong to another machine on this PC's LAN).
///
/// The port remote management uses (445 for Windows, the SSH port) is added to the TCP ports:
/// it answered moments ago, so it shows whether the host still runs even when ICMP and the
/// probe ports are filtered (review R5). An ICMP-only probe becomes "auto" (ICMP, then that
/// port); probe `none` stays unmonitored.
pub fn verify_probe_spec(host: &Host, settings: &Settings) -> ProbeSpec {
    let mut spec = ProbeSpec::for_host(host, settings);
    if let Some(a) = host.management_address() {
        spec.address = Some(a.clone());
    }
    let port = host.remote.as_ref().map(|r| match r.kind {
        RemoteKind::Windows => WINDOWS_MANAGEMENT_PORT,
        RemoteKind::Ssh => r.ssh_port(),
    });
    if let Some(port) = port {
        match spec.method {
            ProbeMethod::None => {}
            ProbeMethod::Icmp => {
                spec.method = ProbeMethod::Auto;
                spec.tcp_ports = vec![port];
            }
            ProbeMethod::Auto | ProbeMethod::Tcp => {
                if !spec.tcp_ports.contains(&port) {
                    spec.tcp_ports.push(port);
                }
            }
        }
    }
    spec
}

/// TCP port of Windows remote management (SMB).
const WINDOWS_MANAGEMENT_PORT: u16 = 445;

/// What the restart verification has seen so far (for [`is_new_boot`]).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Seen {
    /// The host stopped answering at least once.
    pub went_down: bool,
    /// It stopped answering after the old boot was read in this verification (so a
    /// stale `before` or a blind probe cannot fake a restart).
    pub down_after_old: bool,
}

/// `true` when `now` (read `elapsed` after the verification started) is a new boot compared
/// with `baseline` (the boot before the restart, when known). See [`super::verify_restart`].
pub(crate) fn is_new_boot(
    baseline: Option<&BootInfo>,
    now: &BootInfo,
    elapsed: Duration,
    seen: Seen,
) -> bool {
    let fresh = now.uptime <= elapsed + NEW_BOOT_SLACK;
    match (
        baseline.and_then(|b| b.boot_id.as_deref()),
        now.boot_id.as_deref(),
    ) {
        (Some(old), Some(new)) => old != new && (fresh || seen.down_after_old),
        // Without ids and without having seen the host go down, the uptime must also have
        // gone backwards since the old boot was read (a host that booted shortly before the
        // request, read with a stuck or coarse clock, is not a restart).
        _ => {
            fresh
                && (seen.went_down
                    || (!now.approximate && baseline.is_none_or(|b| now.uptime < b.uptime)))
        }
    }
}

/// Errors that end the restart verification at once: polling cannot fix them.
fn is_fatal(e: &Error) -> bool {
    if matches!(
        e,
        Error::UnknownHostKey(_) | Error::HostKeyMismatch(_) | Error::SecretStore { .. }
    ) || e.kind() == ErrorKind::InvalidInput
    {
        return true;
    }
    use RemoteFailure as F;
    matches!(
        e.remote().map(|r| &r.failure),
        Some(
            F::SecretStoreUnavailable
                | F::SecretMismatch { .. }
                | F::PasswordRequired { .. }
                | F::NoCredentials
                | F::KeyPassphraseRequired { .. }
                | F::KeyPassphraseWrong { .. }
                | F::AuthPartial { .. }
                | F::AuthPromptUnsupported { .. }
                | F::CredentialConflict
                | F::Local
                | F::SignInNotConfirmed
        )
    )
}

pub(crate) fn restart(
    client: &RemoteClient,
    host: &Host,
    settings: &Settings,
    before: Option<&BootInfo>,
    deadline: Instant,
    cancel: &AtomicBool,
    mut on_tick: impl FnMut(&VerifyTick),
) -> RestartVerify {
    let env = &*client.env;
    let spec = verify_probe_spec(host, settings);
    let monitored = spec.is_monitored();
    let start = env.now();
    let mut baseline: Option<BootInfo> = before.cloned();
    let mut seen = Seen::default();
    let mut seen_old = false;
    let mut down_rounds = 0u32;
    let mut permission_errors = 0u32;
    let mut last_error: Option<Error> = None;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return RestartVerify::Cancelled;
        }
        let state = if monitored {
            env.probe(&spec)
        } else {
            HostState::Unknown
        };
        let probe_up = state.is_up();
        let read = !monitored || probe_up || (down_rounds + 1).is_multiple_of(DOWN_READ_EVERY);
        // Did the host answer this round (probe, boot time, or an error it sent)?
        let mut answered = probe_up;
        if read {
            let result = client.boot_time(host, settings);
            let at = env.now();
            if cancel.load(Ordering::Relaxed) {
                return RestartVerify::Cancelled;
            }
            match result {
                Ok(b) => {
                    answered = true;
                    permission_errors = 0;
                    last_error = None;
                    let elapsed = at.saturating_duration_since(start);
                    if is_new_boot(baseline.as_ref(), &b, elapsed, seen) {
                        on_tick(&VerifyTick {
                            phase: VerifyPhase::Up,
                            state,
                            elapsed,
                        });
                        return RestartVerify::Restarted { boot: b };
                    }
                    // The old boot (or a stale `before`): compare later readings with it.
                    baseline = Some(b);
                    seen_old = true;
                }
                Err(e) if is_fatal(&e) => return RestartVerify::Failed(e),
                Err(e) => {
                    if e.kind() == ErrorKind::Permission {
                        permission_errors += 1;
                        if permission_errors >= PERMISSION_FAILURES_FATAL {
                            return RestartVerify::Failed(e);
                        }
                    } else {
                        permission_errors = 0;
                    }
                    if !e.is_remote_transient() {
                        // The host answered, with an error.
                        answered = true;
                    }
                    log::debug!("{}: boot time not readable yet: {e}", host.name);
                    last_error = Some(e);
                }
            }
        }
        // Not monitored: a round without an answer is a boot-time read that failed with a
        // network error (the host is down).
        if answered {
            down_rounds = 0;
        } else if !monitored
            || matches!(state, HostState::Down { .. } | HostState::Unresolved { .. })
        {
            down_rounds += 1;
            seen.went_down = true;
            seen.down_after_old |= seen_old;
        }
        let phase = if answered {
            VerifyPhase::Up
        } else {
            VerifyPhase::Down {
                failures: down_rounds,
            }
        };
        let now = env.now();
        on_tick(&VerifyTick {
            phase,
            state: state.clone(),
            elapsed: now.saturating_duration_since(start),
        });
        if now >= deadline {
            return RestartVerify::TimedOut {
                went_down: seen.went_down,
                online: answered,
                last_error,
            };
        }
        if !env.sleep_until((now + RESTART_POLL).min(deadline), cancel) {
            return RestartVerify::Cancelled;
        }
    }
}

pub(crate) fn shutdown(
    client: &RemoteClient,
    host: &Host,
    settings: &Settings,
    deadline: Instant,
    cancel: &AtomicBool,
    mut on_tick: impl FnMut(&VerifyTick),
) -> ShutdownVerify {
    let env = &*client.env;
    let spec = verify_probe_spec(host, settings);
    if !spec.is_monitored() {
        return ShutdownVerify::NotMonitored;
    }
    let start = env.now();
    let mut failures = 0u32;
    // The host was seen answering in this verification. Until then a missing answer does not
    // count: the probe may simply not see this host (review R5).
    let mut seen_up = false;
    let mut unseen = 0u32;
    let mut last = VerifyPhase::Down { failures: 0 };
    loop {
        if cancel.load(Ordering::Relaxed) {
            return ShutdownVerify::Cancelled;
        }
        let state = env.probe(&spec);
        let phase = match &state {
            HostState::Up { .. } => {
                seen_up = true;
                failures = 0;
                VerifyPhase::Up
            }
            // No answer; a name that stopped resolving (served by the host itself) counts too.
            HostState::Down { .. } | HostState::Unresolved { .. } => {
                if seen_up {
                    failures += 1;
                } else {
                    unseen += 1;
                }
                VerifyPhase::Down { failures }
            }
            // The local probe failed: says nothing about the host (neither counts nor resets;
            // the phase stays).
            HostState::Error { .. } | HostState::Unknown => last,
        };
        last = phase;
        let now = env.now();
        on_tick(&VerifyTick {
            phase,
            state: state.clone(),
            elapsed: now.saturating_duration_since(start),
        });
        if failures >= SHUTDOWN_FAILURES {
            return ShutdownVerify::ShutDown;
        }
        // The request went through moments ago, so the host was running: a probe that never
        // saw it answer cannot tell whether it stopped.
        if !seen_up && unseen >= SHUTDOWN_FAILURES {
            return ShutdownVerify::NotMonitored;
        }
        if now >= deadline {
            return ShutdownVerify::TimedOut { last: state };
        }
        if !env.sleep_until((now + SHUTDOWN_POLL).min(deadline), cancel) {
            return ShutdownVerify::Cancelled;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot(read_at: SystemTime, uptime_s: u64, id: Option<&str>) -> BootInfo {
        BootInfo {
            boot_time: read_at - Duration::from_secs(uptime_s),
            uptime: Duration::from_secs(uptime_s),
            source: "test".into(),
            approximate: false,
            boot_id: id.map(str::to_owned),
        }
    }

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn new_boot_rules() {
        let t0 = SystemTime::UNIX_EPOCH + S(1_800_000_000);
        let none = Seen::default();
        let down = Seen {
            went_down: true,
            down_after_old: false,
        };
        let down_after_old = Seen {
            went_down: true,
            down_after_old: true,
        };
        let old = boot(t0, 3600, None);
        // Same boot read later (uptime grew with the elapsed time): not new.
        let same = boot(t0 + S(100), 3700, None);
        assert!(!is_new_boot(Some(&old), &same, S(100), down_after_old));
        // Booted after the start (uptime < elapsed): new, with or without a baseline.
        let new = boot(t0 + S(120), 40, None);
        assert!(is_new_boot(Some(&old), &new, S(120), none));
        assert!(is_new_boot(None, &new, S(120), none));
        // Review m1: 40 s of uptime right at the start is the old boot, not a restart.
        assert!(!is_new_boot(None, &boot(t0, 40, None), S(0), none));
        assert!(!is_new_boot(None, &boot(t0, 40, None), S(1), down));
        // ... also when later readings report the same uptime (repro r2's static host).
        let b40 = boot(t0, 40, None);
        assert!(!is_new_boot(Some(&b40), &boot(t0, 40, None), S(30), none));
        assert!(!is_new_boot(Some(&b40), &boot(t0, 40, None), S(300), none));
        assert!(is_new_boot(Some(&b40), &boot(t0, 12, None), S(30), none));
        // Slack for round trips / rounding.
        assert!(is_new_boot(None, &boot(t0, 14, None), S(5), none));
        // Boot ids decide when both have one. Another id that is not a fresh boot needs the
        // host to have gone down after the old boot was read here (a stale `before` or a
        // blind probe cannot fake it).
        let a = boot(t0, 3600, Some("a"));
        let a_again = boot(t0, 5, Some("a"));
        assert!(!is_new_boot(Some(&a), &a_again, S(600), down_after_old));
        assert!(is_new_boot(Some(&a), &boot(t0, 5, Some("b")), S(10), none));
        let b_old = boot(t0, 7200, Some("b"));
        assert!(!is_new_boot(Some(&a), &b_old, S(10), none));
        assert!(!is_new_boot(Some(&a), &b_old, S(10), down));
        assert!(is_new_boot(Some(&a), &b_old, S(10), down_after_old));
        // Review m2: approximate readings (Windows 49.7-day wrap) also need "went down".
        let mut wrapped = boot(t0, 3, None);
        wrapped.approximate = true;
        assert!(!is_new_boot(Some(&old), &wrapped, S(30), none));
        assert!(is_new_boot(Some(&old), &wrapped, S(30), down));
    }

    /// Review r7 / m2: a step of this PC's clock is not a reboot for `rebooted_since`.
    #[test]
    fn rebooted_since_ignores_clock_steps_smaller_than_the_uptime() {
        let t0 = SystemTime::UNIX_EPOCH + S(1_800_000_000);
        let b = boot(t0, 400 * 86_400, None);
        let stepped = BootInfo {
            boot_time: b.boot_time + S(45),
            ..b.clone()
        };
        assert!(!stepped.rebooted_since(&b));
        // A real reboot moves the boot time by more than the earlier uptime.
        let fresh = boot(t0, 3600, None);
        let later = boot(t0 + S(600), 120, None);
        assert!(later.rebooted_since(&fresh));
        assert!(!boot(t0 + S(100), 3700, None).rebooted_since(&fresh));
        // Boot ids decide.
        assert!(boot(t0, 5, Some("b")).rebooted_since(&boot(t0, 9, Some("a"))));
        assert!(!boot(t0 + S(3600), 5, Some("a")).rebooted_since(&boot(t0, 9, Some("a"))));
    }
}
