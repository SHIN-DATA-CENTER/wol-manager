//! Status scheduler: a pure state machine driven by a 1 s UI timer (plan §7.3).
//!
//! * Periodic checks every `poll_interval_secs` (none when 0). While the window is hidden
//!   (tray) or minimized, only waking hosts are probed.
//! * First check: `Unknown → Checking → Online / Offline`.
//! * After a wake: `Waking`, probed every 3 s until `verify_timeout_secs`, then `Online` or
//!   `Timeout`. `Timeout` is kept until the host answers or is woken again.
//! * Every job carries the host's generation; editing the address / probe options or
//!   deleting the host bumps it, so late results are dropped.
//!
//! The scheduler never touches Slint or threads; `app` turns [`Job`]s into probes on the
//! probe pool and feeds results back through [`Scheduler::on_result`].

use std::collections::HashMap;
use std::time::{Duration, Instant};

use wol_core::probe::{self, HostState, ProbeSpec};
use wol_core::{Config, HostId};

use crate::rows::RowState;
use crate::{HostStatus, ProbeVia};

/// Interval of the probes while a host is waking.
pub const WAKE_PROBE_INTERVAL: Duration = Duration::from_secs(3);

/// Why a probe runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    /// Periodic check.
    Periodic,
    /// F5 / Refresh.
    Manual,
    /// Verification after a wake.
    Wake,
}

/// A probe to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Host.
    pub id: HostId,
    /// Generation the result must match.
    pub generation: u64,
    /// Why.
    pub kind: JobKind,
}

/// Something worth a toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The host answered while waking.
    CameOnline(HostId),
    /// The host did not answer within the verify timeout.
    WakeTimedOut(HostId, u64),
}

/// What [`Scheduler::on_result`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Applied {
    /// The row state changed.
    pub changed: bool,
    /// A toast-worthy event.
    pub event: Option<Event>,
    /// A status round finished with this result.
    pub round_done: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct Waking {
    deadline: Instant,
    next_probe: Instant,
    secs: u64,
    prev: RowStateKey,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct RowStateKey {
    status: HostStatus,
    via: ProbeVia,
    rtt_ms: i32,
}

impl From<RowStateKey> for RowState {
    fn from(k: RowStateKey) -> RowState {
        RowState {
            status: k.status,
            via: k.via,
            rtt_ms: k.rtt_ms,
        }
    }
}

#[derive(Debug, Clone)]
struct Mon {
    st: RowStateKey,
    generation: u64,
    monitored: bool,
    probe_key: String,
    in_flight: Option<u64>, // round id (0 = not part of a round)
    next_due: Option<Instant>,
    waking: Option<Waking>,
}

impl Mon {
    fn idle_status(monitored: bool) -> HostStatus {
        if monitored {
            HostStatus::Unknown
        } else {
            HostStatus::NotMonitored
        }
    }
}

/// Key of everything that affects a probe: a change resets the host's status.
pub fn probe_key(spec: &ProbeSpec) -> String {
    format!(
        "{:?}|{:?}|{:?}|{}",
        spec.address.as_ref().map(ToString::to_string),
        spec.method,
        spec.tcp_ports,
        spec.timeout.as_millis()
    )
}

/// Per-host status bookkeeping.
#[derive(Debug, Default)]
pub struct Scheduler {
    hosts: HashMap<HostId, Mon>,
    poll: Option<Duration>,
    next_round: u64,
    rounds: HashMap<u64, usize>,
}

impl Scheduler {
    /// New scheduler with the periodic interval (`None` = off).
    pub fn new(poll: Option<Duration>) -> Scheduler {
        Scheduler {
            poll,
            next_round: 1,
            ..Scheduler::default()
        }
    }

    /// Changes the periodic interval. Hosts are rescheduled relative to `now`.
    pub fn set_poll(&mut self, poll: Option<Duration>, now: Instant) {
        if self.poll == poll {
            return;
        }
        self.poll = poll;
        for m in self.hosts.values_mut() {
            m.next_due = match poll {
                None => None,
                // Never checked yet: check at once.
                Some(_) if m.st.status == HostStatus::Unknown => Some(now),
                Some(p) => Some(now + p),
            };
        }
    }

    fn release(&mut self, round: Option<u64>) -> bool {
        let Some(r) = round.filter(|r| *r != 0) else {
            return false;
        };
        let done = match self.rounds.get_mut(&r) {
            Some(n) => {
                *n = n.saturating_sub(1);
                *n == 0
            }
            None => false,
        };
        if done {
            self.rounds.remove(&r);
        }
        done
    }

    /// Adds / removes / updates hosts to match `cfg`. A host whose probe inputs changed gets
    /// a new generation and starts over (`Unknown` / `NotMonitored`). Returns `true` when a
    /// status round finished because hosts went away.
    pub fn sync(&mut self, cfg: &Config, now: Instant) -> bool {
        let mut round_done = false;
        let ids: std::collections::HashSet<HostId> = cfg.hosts.iter().map(|h| h.id).collect();
        let gone: Vec<HostId> = self
            .hosts
            .keys()
            .filter(|id| !ids.contains(id))
            .copied()
            .collect();
        for id in gone {
            if let Some(m) = self.hosts.remove(&id) {
                round_done |= self.release(m.in_flight);
            }
        }
        for h in &cfg.hosts {
            let spec = ProbeSpec::for_host(h, &cfg.settings);
            let monitored = spec.is_monitored();
            let key = probe_key(&spec);
            match self.hosts.get_mut(&h.id) {
                Some(m) if m.probe_key == key => {}
                Some(m) => {
                    let old_round = m.in_flight.take();
                    m.generation += 1;
                    m.monitored = monitored;
                    m.probe_key = key;
                    m.waking = None;
                    m.st = RowStateKey {
                        status: Mon::idle_status(monitored),
                        via: ProbeVia::None,
                        rtt_ms: -1,
                    };
                    m.next_due = self.poll.map(|_| now);
                    round_done |= self.release(old_round);
                }
                None => {
                    self.hosts.insert(
                        h.id,
                        Mon {
                            st: RowStateKey {
                                status: Mon::idle_status(monitored),
                                via: ProbeVia::None,
                                rtt_ms: -1,
                            },
                            generation: 1,
                            monitored,
                            probe_key: key,
                            in_flight: None,
                            next_due: self.poll.map(|_| now),
                            waking: None,
                        },
                    );
                }
            }
        }
        round_done
    }

    /// Forgets one host (optimistic delete). Returns `true` when a round finished.
    pub fn remove(&mut self, id: HostId) -> bool {
        match self.hosts.remove(&id) {
            Some(m) => self.release(m.in_flight),
            None => false,
        }
    }

    fn dispatch(m: &mut Mon, id: HostId, kind: JobKind, round: u64) -> Job {
        m.in_flight = Some(round);
        if m.st.status == HostStatus::Unknown {
            m.st.status = HostStatus::Checking;
        }
        Job {
            id,
            generation: m.generation,
            kind,
        }
    }

    /// One timer tick. `visible` = the window is shown and not minimized.
    pub fn tick(&mut self, now: Instant, visible: bool) -> (Vec<Job>, Vec<Event>) {
        let mut jobs = Vec::new();
        let mut events = Vec::new();
        let round = self.next_round;
        let mut in_round = 0usize;
        let mut ids: Vec<HostId> = self.hosts.keys().copied().collect();
        ids.sort();
        for id in ids {
            let poll = self.poll;
            let Some(m) = self.hosts.get_mut(&id) else {
                continue;
            };
            if let Some(w) = m.waking.clone() {
                if now >= w.deadline {
                    m.waking = None;
                    m.st = RowStateKey {
                        status: HostStatus::Timeout,
                        via: ProbeVia::None,
                        rtt_ms: -1,
                    };
                    m.next_due = poll.map(|p| now + p);
                    events.push(Event::WakeTimedOut(id, w.secs));
                } else if m.in_flight.is_none() && now >= w.next_probe {
                    if let Some(wk) = m.waking.as_mut() {
                        wk.next_probe = now + WAKE_PROBE_INTERVAL;
                    }
                    jobs.push(Self::dispatch(m, id, JobKind::Wake, 0));
                }
                continue;
            }
            if !visible || !m.monitored || m.in_flight.is_some() {
                continue;
            }
            if poll.is_some() && m.next_due.is_some_and(|d| now >= d) {
                jobs.push(Self::dispatch(m, id, JobKind::Periodic, round));
                in_round += 1;
            }
        }
        if in_round > 0 {
            self.rounds.insert(round, in_round);
            self.next_round += 1;
        }
        (jobs, events)
    }

    /// F5: probes every monitored host that is not waking and has no probe in flight.
    /// Returns nothing while a round is running.
    pub fn refresh_all(&mut self) -> Vec<Job> {
        if self.checking() {
            return Vec::new();
        }
        let round = self.next_round;
        let mut jobs = Vec::new();
        let mut ids: Vec<HostId> = self.hosts.keys().copied().collect();
        ids.sort();
        for id in ids {
            let Some(m) = self.hosts.get_mut(&id) else {
                continue;
            };
            if m.monitored && m.waking.is_none() && m.in_flight.is_none() {
                jobs.push(Self::dispatch(m, id, JobKind::Manual, round));
            }
        }
        if !jobs.is_empty() {
            self.rounds.insert(round, jobs.len());
            self.next_round += 1;
        }
        jobs
    }

    /// Applies a probe result. `None` when it is stale (generation changed, host gone).
    pub fn on_result(
        &mut self,
        id: HostId,
        generation: u64,
        state: &HostState,
        now: Instant,
    ) -> Option<Applied> {
        let poll = self.poll;
        let m = self.hosts.get_mut(&id)?;
        if m.generation != generation {
            return None;
        }
        let round = m.in_flight.take();
        let before = m.st;
        let mut event = None;
        match state {
            HostState::Up { via, rtt, .. } => {
                m.st = RowStateKey {
                    status: HostStatus::Online,
                    via: match via {
                        probe::ProbeVia::Icmp => ProbeVia::Icmp,
                        probe::ProbeVia::Tcp { .. } => ProbeVia::Tcp,
                    },
                    rtt_ms: i32::try_from(rtt.as_millis()).unwrap_or(i32::MAX),
                };
                if m.waking.take().is_some() {
                    event = Some(Event::CameOnline(id));
                }
            }
            HostState::Unknown => {
                m.waking = None;
                m.st = RowStateKey {
                    status: HostStatus::NotMonitored,
                    via: ProbeVia::None,
                    rtt_ms: -1,
                };
            }
            HostState::Down { .. } | HostState::Unresolved { .. } | HostState::Error { .. } => {
                if m.waking.is_none() && m.st.status != HostStatus::Timeout {
                    m.st = RowStateKey {
                        status: HostStatus::Offline,
                        via: ProbeVia::None,
                        rtt_ms: -1,
                    };
                }
            }
        }
        m.next_due = poll.map(|p| now + p);
        let changed = m.st != before;
        let round_done = self.release(round);
        Some(Applied {
            changed,
            event,
            round_done,
        })
    }

    /// A magic packet is being sent: `Waking` until `now + verify` (monitored hosts only).
    /// Returns `true` when the host is now waking.
    pub fn wake_started(&mut self, id: HostId, now: Instant, verify: Duration) -> bool {
        let Some(m) = self.hosts.get_mut(&id) else {
            return false;
        };
        if !m.monitored {
            return false;
        }
        let prev = match &m.waking {
            Some(w) => w.prev,
            None => m.st,
        };
        m.waking = Some(Waking {
            deadline: now + verify,
            next_probe: now + WAKE_PROBE_INTERVAL,
            secs: verify.as_secs(),
            prev,
        });
        m.st = RowStateKey {
            status: HostStatus::Waking,
            via: ProbeVia::None,
            rtt_ms: -1,
        };
        true
    }

    /// Sending failed: back to the status before the wake.
    pub fn wake_failed(&mut self, id: HostId) -> bool {
        let Some(m) = self.hosts.get_mut(&id) else {
            return false;
        };
        match m.waking.take() {
            Some(w) => {
                m.st = w.prev;
                if m.st.status == HostStatus::Checking {
                    m.st.status = HostStatus::Unknown;
                }
                true
            }
            None => false,
        }
    }

    /// Row state of a host (default for unknown ids).
    pub fn row_state(&self, id: HostId) -> RowState {
        self.hosts.get(&id).map(|m| m.st.into()).unwrap_or_default()
    }

    /// Whether the host is monitored.
    pub fn is_monitored(&self, id: HostId) -> bool {
        self.hosts.get(&id).is_some_and(|m| m.monitored)
    }

    /// Some host is `Checking` or `Waking` (drives the pulse animation).
    pub fn any_pulsing(&self) -> bool {
        self.hosts
            .values()
            .any(|m| matches!(m.st.status, HostStatus::Checking | HostStatus::Waking))
    }

    /// Number of hosts that are waking.
    pub fn waking_count(&self) -> usize {
        self.hosts
            .values()
            .filter(|m| m.st.status == HostStatus::Waking)
            .count()
    }

    /// Number of online hosts.
    pub fn online_count(&self) -> usize {
        self.hosts
            .values()
            .filter(|m| m.st.status == HostStatus::Online)
            .count()
    }

    /// A status round is running.
    pub fn checking(&self) -> bool {
        !self.rounds.is_empty()
    }
}

/// `AppState.animating`: only while the window is visible and something pulses.
pub fn animating(visible: bool, sched: &Scheduler) -> bool {
    visible && sched.any_pulsing()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use wol_core::model::ProbeMethod;
    use wol_core::{Host, HostAddr, MacAddr};

    const T30: Duration = Duration::from_secs(30);

    fn host(name: &str, addr: Option<&str>) -> Host {
        let mut h = Host::new(name, MacAddr::parse("00:11:22:33:44:55").unwrap());
        h.address = addr.map(|a| HostAddr::parse(a).unwrap());
        h
    }

    fn cfg(hosts: Vec<Host>) -> Config {
        Config {
            hosts,
            ..Config::default()
        }
    }

    fn up() -> HostState {
        HostState::Up {
            via: probe::ProbeVia::Icmp,
            rtt: Duration::from_millis(4),
            ip: Ipv4Addr::new(127, 0, 0, 1),
        }
    }

    fn down() -> HostState {
        HostState::Down {
            ip: Ipv4Addr::new(127, 0, 0, 1),
        }
    }

    fn status(s: &Scheduler, id: HostId) -> HostStatus {
        s.row_state(id).status
    }

    #[test]
    fn first_check_unknown_checking_online_offline() {
        let a = host("a", Some("127.0.0.1"));
        let b = host("b", Some("127.0.0.2"));
        let c = host("c", None);
        let (ia, ib, ic) = (a.id, b.id, c.id);
        let t0 = Instant::now();
        let mut s = Scheduler::new(Some(T30));
        s.sync(&cfg(vec![a, b, c]), t0);
        assert_eq!(status(&s, ia), HostStatus::Unknown);
        assert_eq!(status(&s, ic), HostStatus::NotMonitored);

        let (jobs, ev) = s.tick(t0, true);
        assert!(ev.is_empty());
        assert_eq!(jobs.len(), 2, "unmonitored hosts are never probed");
        assert!(jobs.iter().all(|j| j.kind == JobKind::Periodic));
        assert_eq!(status(&s, ia), HostStatus::Checking);
        assert!(s.checking());
        assert!(s.any_pulsing());
        // No double dispatch while in flight.
        assert!(s.tick(t0 + Duration::from_secs(1), true).0.is_empty());

        let ja = jobs.iter().find(|j| j.id == ia).unwrap();
        let jb = jobs.iter().find(|j| j.id == ib).unwrap();
        let r = s.on_result(ia, ja.generation, &up(), t0).unwrap();
        assert!(r.changed && !r.round_done);
        assert_eq!(s.row_state(ia).via, ProbeVia::Icmp);
        assert_eq!(s.row_state(ia).rtt_ms, 4);
        let r = s.on_result(ib, jb.generation, &down(), t0).unwrap();
        assert!(r.round_done);
        assert_eq!(status(&s, ib), HostStatus::Offline);
        assert!(!s.checking());
        assert_eq!(s.online_count(), 1);

        // Next periodic check only after the interval.
        assert!(s.tick(t0 + Duration::from_secs(29), true).0.is_empty());
        assert_eq!(s.tick(t0 + T30, true).0.len(), 2);
        // Periodic re-checks keep the displayed status (no flicker to "checking").
        assert_eq!(status(&s, ia), HostStatus::Online);
    }

    #[test]
    fn waking_then_online_or_timeout() {
        let a = host("a", Some("127.0.0.1"));
        let b = host("b", Some("127.0.0.2"));
        let (ia, ib) = (a.id, b.id);
        let t0 = Instant::now();
        let mut s = Scheduler::new(None);
        s.sync(&cfg(vec![a, b]), t0);
        let verify = Duration::from_secs(10);
        assert!(s.wake_started(ia, t0, verify));
        assert!(s.wake_started(ib, t0, verify));
        assert_eq!(status(&s, ia), HostStatus::Waking);
        assert_eq!(s.waking_count(), 2);

        // Probes every 3 s, also while hidden.
        assert!(s.tick(t0 + Duration::from_secs(1), false).0.is_empty());
        let (jobs, _) = s.tick(t0 + Duration::from_secs(3), false);
        assert_eq!(jobs.len(), 2);
        assert!(jobs.iter().all(|j| j.kind == JobKind::Wake));
        assert!(!s.checking(), "wake probes are not a status round");
        let ga = jobs.iter().find(|j| j.id == ia).unwrap().generation;
        let gb = jobs.iter().find(|j| j.id == ib).unwrap().generation;
        // Down while waking: still waking.
        let r = s
            .on_result(ib, gb, &down(), t0 + Duration::from_secs(4))
            .unwrap();
        assert!(!r.changed);
        assert_eq!(status(&s, ib), HostStatus::Waking);
        // Up: online + event.
        let r = s
            .on_result(ia, ga, &up(), t0 + Duration::from_secs(4))
            .unwrap();
        assert_eq!(r.event, Some(Event::CameOnline(ia)));
        assert_eq!(status(&s, ia), HostStatus::Online);

        // b times out.
        let (_, ev) = s.tick(t0 + verify, false);
        assert_eq!(ev, vec![Event::WakeTimedOut(ib, 10)]);
        assert_eq!(status(&s, ib), HostStatus::Timeout);
        assert!(!s.any_pulsing());
    }

    #[test]
    fn timeout_persists_until_answer_or_wake() {
        let a = host("a", Some("127.0.0.1"));
        let ia = a.id;
        let t0 = Instant::now();
        let mut s = Scheduler::new(Some(T30));
        s.sync(&cfg(vec![a]), t0);
        s.wake_started(ia, t0, Duration::from_secs(10));
        s.tick(t0 + Duration::from_secs(10), true);
        assert_eq!(status(&s, ia), HostStatus::Timeout);
        // Periodic check with no answer keeps Timeout.
        let (jobs, _) = s.tick(t0 + Duration::from_secs(40), true);
        assert_eq!(jobs.len(), 1);
        s.on_result(
            ia,
            jobs[0].generation,
            &down(),
            t0 + Duration::from_secs(40),
        );
        assert_eq!(status(&s, ia), HostStatus::Timeout);
        // A new wake -> waking again.
        s.wake_started(ia, t0 + Duration::from_secs(50), Duration::from_secs(10));
        assert_eq!(status(&s, ia), HostStatus::Waking);
        // Send failed -> previous status (Timeout).
        assert!(s.wake_failed(ia));
        assert_eq!(status(&s, ia), HostStatus::Timeout);
        // Answer -> online.
        let (jobs, _) = s.tick(t0 + Duration::from_secs(80), true);
        s.on_result(ia, jobs[0].generation, &up(), t0 + Duration::from_secs(80));
        assert_eq!(status(&s, ia), HostStatus::Online);
    }

    #[test]
    fn stale_generation_is_dropped() {
        let a = host("a", Some("127.0.0.1"));
        let ia = a.id;
        let t0 = Instant::now();
        let mut c = cfg(vec![a]);
        let mut s = Scheduler::new(Some(T30));
        s.sync(&c, t0);
        let (jobs, _) = s.tick(t0, true);
        let old = jobs[0].generation;
        assert!(s.checking());

        // Unrelated edit (name) keeps generation and status.
        c.get_mut(ia).unwrap().name = "renamed".into();
        s.sync(&c, t0);
        assert_eq!(status(&s, ia), HostStatus::Checking);

        // Address edit: new generation, the running round is released.
        c.get_mut(ia).unwrap().address = Some(HostAddr::parse("127.0.0.9").unwrap());
        assert!(
            s.sync(&c, t0),
            "round finished because its only job became stale"
        );
        assert!(!s.checking());
        assert_eq!(status(&s, ia), HostStatus::Unknown);
        assert_eq!(s.on_result(ia, old, &up(), t0), None);
        assert_eq!(status(&s, ia), HostStatus::Unknown);

        // Probe method change also resets.
        let (jobs, _) = s.tick(t0 + Duration::from_secs(1), true);
        let g = jobs[0].generation;
        s.on_result(ia, g, &up(), t0 + Duration::from_secs(1));
        assert_eq!(status(&s, ia), HostStatus::Online);
        c.get_mut(ia).unwrap().probe = Some(ProbeMethod::None);
        s.sync(&c, t0 + Duration::from_secs(2));
        assert_eq!(status(&s, ia), HostStatus::NotMonitored);

        // Deleted host: results dropped.
        c.hosts.clear();
        s.sync(&c, t0);
        assert_eq!(s.on_result(ia, g + 1, &up(), t0), None);
        assert_eq!(s.row_state(ia), RowState::default());
    }

    #[test]
    fn hidden_window_probes_only_waking_hosts() {
        let a = host("a", Some("127.0.0.1"));
        let b = host("b", Some("127.0.0.2"));
        let (ia, ib) = (a.id, b.id);
        let t0 = Instant::now();
        let mut s = Scheduler::new(Some(T30));
        s.sync(&cfg(vec![a, b]), t0);
        s.wake_started(ib, t0, Duration::from_secs(60));
        let (jobs, _) = s.tick(t0 + Duration::from_secs(3), false);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, ib);
        assert_eq!(status(&s, ia), HostStatus::Unknown);
        assert!(!animating(false, &s), "no animation while hidden");
        assert!(animating(true, &s));
        // Visible again: the overdue periodic check runs at once.
        let (jobs, _) = s.tick(t0 + Duration::from_secs(4), true);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, ia);
    }

    #[test]
    fn manual_refresh_and_poll_off() {
        let a = host("a", Some("127.0.0.1"));
        let ia = a.id;
        let t0 = Instant::now();
        let mut s = Scheduler::new(None);
        s.sync(&cfg(vec![a]), t0);
        assert!(s.tick(t0 + Duration::from_secs(100), true).0.is_empty());
        let jobs = s.refresh_all();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, JobKind::Manual);
        assert!(s.checking());
        assert!(s.refresh_all().is_empty(), "ignored while checking");
        let r = s.on_result(ia, jobs[0].generation, &down(), t0).unwrap();
        assert!(r.round_done);
        assert_eq!(status(&s, ia), HostStatus::Offline);
        // Turning polling on schedules the next check.
        s.set_poll(Some(T30), t0);
        assert!(s.tick(t0 + Duration::from_secs(29), true).0.is_empty());
        assert_eq!(s.tick(t0 + T30, true).0.len(), 1);
    }

    #[test]
    fn unmonitored_host_does_not_wake_state() {
        let a = host("a", None);
        let ia = a.id;
        let t0 = Instant::now();
        let mut s = Scheduler::new(Some(T30));
        s.sync(&cfg(vec![a]), t0);
        assert!(!s.wake_started(ia, t0, Duration::from_secs(10)));
        assert_eq!(status(&s, ia), HostStatus::NotMonitored);
        assert!(!s.is_monitored(ia));
    }
}
