//! Online checks.
//!
//! * ICMP echo via `IcmpSendEcho` ([`icmp::ping`]), no administrator rights needed.
//! * TCP connect to a list of ports in parallel ([`tcp::probe_ports`]); a connection or a
//!   refusal both mean "up" (Windows often blocks ICMP but answers on 3389 / 445).
//! * `auto` tries ICMP first, then TCP.
//!
//! All functions block; the GUI calls them on its probe pool.

pub mod icmp;
pub mod tcp;

use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Serialize, Serializer};

pub use crate::model::ProbeMethod;

use crate::addr::HostAddr;
use crate::model::{Host, HostId, Settings};

fn ser_ms<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_millis() as u64)
}

/// What to probe and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeSpec {
    /// Label for reports.
    pub label: String,
    /// Host id, if the spec comes from the config.
    pub host_id: Option<HostId>,
    /// Address to probe; `None` = not monitored.
    pub address: Option<HostAddr>,
    /// Method.
    pub method: ProbeMethod,
    /// Timeout of one ICMP echo and of the TCP connect attempts.
    #[serde(rename = "timeout_ms", serialize_with = "ser_ms")]
    pub timeout: Duration,
    /// Ports for the TCP probe.
    pub tcp_ports: Vec<u16>,
}

impl ProbeSpec {
    /// Spec for a configured host (host overrides on top of `[settings.probe]`).
    pub fn for_host(host: &Host, settings: &Settings) -> ProbeSpec {
        ProbeSpec {
            label: host.name.clone(),
            host_id: Some(host.id),
            address: host.address.clone(),
            method: host.effective_probe(settings),
            timeout: settings.probe.effective_timeout(),
            tcp_ports: host.effective_tcp_ports(settings).to_vec(),
        }
    }

    /// Spec for an arbitrary address with the settings' defaults.
    pub fn adhoc(address: HostAddr, settings: &Settings) -> ProbeSpec {
        ProbeSpec {
            label: address.to_string(),
            host_id: None,
            address: Some(address),
            method: settings.probe.method,
            timeout: settings.probe.effective_timeout(),
            tcp_ports: settings.probe.tcp_ports.clone(),
        }
    }

    /// `false` when there is no address, the method is `none`, or the method is `tcp` without
    /// ports ("not monitored").
    pub fn is_monitored(&self) -> bool {
        self.address.is_some()
            && self.method != ProbeMethod::None
            && !(self.method == ProbeMethod::Tcp && self.tcp_ports.is_empty())
    }
}

/// Which check succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProbeVia {
    /// ICMP echo reply.
    Icmp,
    /// TCP connect or refusal on this port.
    Tcp {
        /// Port.
        port: u16,
    },
}

/// Result of one probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HostState {
    /// The host answered.
    Up {
        /// Which check answered.
        via: ProbeVia,
        /// Round-trip / connect time.
        #[serde(rename = "rtt_ms", serialize_with = "ser_ms")]
        rtt: Duration,
        /// Address probed.
        ip: Ipv4Addr,
    },
    /// No answer within the timeout.
    Down {
        /// Address probed.
        ip: Ipv4Addr,
    },
    /// The host name could not be resolved.
    Unresolved {
        /// The name.
        name: String,
        /// OS message.
        error: String,
    },
    /// Not monitored (no address, or method `none`).
    Unknown,
    /// The probe itself failed (API error).
    Error {
        /// English message.
        message: String,
    },
}

impl HostState {
    /// `true` for [`HostState::Up`].
    pub fn is_up(&self) -> bool {
        matches!(self, HostState::Up { .. })
    }

    /// Address that was probed, if any.
    pub fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            HostState::Up { ip, .. } | HostState::Down { ip } => Some(*ip),
            _ => None,
        }
    }
}

/// Probes once. **Blocking**: DNS for names, then up to `timeout` for ICMP and up to
/// `timeout` more for TCP (auto mode: worst case about 2 × timeout + DNS).
pub fn probe(spec: &ProbeSpec) -> HostState {
    if !spec.is_monitored() {
        return HostState::Unknown;
    }
    let Some(addr) = &spec.address else {
        return HostState::Unknown;
    };
    let ip = match addr.resolve_v4() {
        Ok(ip) => ip,
        Err(e) => {
            return HostState::Unresolved {
                name: addr.to_string(),
                error: match e {
                    crate::Error::Resolve { message, .. } => message,
                    other => other.to_string(),
                },
            };
        }
    };
    let use_icmp = matches!(spec.method, ProbeMethod::Auto | ProbeMethod::Icmp);
    let use_tcp = matches!(spec.method, ProbeMethod::Auto | ProbeMethod::Tcp);
    let mut icmp_error = None;
    if use_icmp {
        match icmp::ping(ip, spec.timeout) {
            Ok(Some(rtt)) => {
                return HostState::Up {
                    via: ProbeVia::Icmp,
                    rtt,
                    ip,
                };
            }
            Ok(None) => {}
            Err(e) => icmp_error = Some(e.to_string()),
        }
    }
    if use_tcp && let Some((port, rtt)) = tcp::probe_ports(ip, &spec.tcp_ports, spec.timeout) {
        return HostState::Up {
            via: ProbeVia::Tcp { port },
            rtt,
            ip,
        };
    }
    match (spec.method, icmp_error) {
        (ProbeMethod::Icmp, Some(message)) => HostState::Error { message },
        _ => HostState::Down { ip },
    }
}

/// Probes many specs with at most `max_parallel` threads (clamped to `1..=32`). Results are
/// in input order. **Blocking** until all probes finish.
pub fn probe_all(specs: &[ProbeSpec], max_parallel: usize) -> Vec<HostState> {
    let workers = max_parallel.clamp(1, 32).min(specs.len().max(1));
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<HostState>>> = specs.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= specs.len() {
                        break;
                    }
                    let st = probe(&specs[i]);
                    *results[i].lock().unwrap_or_else(|p| p.into_inner()) = Some(st);
                }
            });
        }
    });
    results
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(|p| p.into_inner())
                .unwrap_or(HostState::Error {
                    message: "probe did not run".to_owned(),
                })
        })
        .collect()
}

/// How [`wait_until_up`] ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum WaitOutcome {
    /// The host came up (the `Up` state).
    Up {
        /// The successful probe.
        state: HostState,
    },
    /// The deadline passed; the last probe result.
    TimedOut {
        /// Last probe result.
        last: HostState,
    },
    /// `cancel` was set.
    Cancelled,
}

/// Probes every `poll` until the host is up, `deadline` passes, or `cancel` becomes true.
/// `on_tick` is called with every probe result (for progress output).
///
/// **Blocking** until then; checks `cancel` at least every 100 ms while sleeping.
/// A spec that is not monitored returns `TimedOut { last: Unknown }` immediately.
pub fn wait_until_up(
    spec: &ProbeSpec,
    deadline: Instant,
    poll: Duration,
    cancel: &AtomicBool,
    mut on_tick: impl FnMut(&HostState),
) -> WaitOutcome {
    if !spec.is_monitored() {
        return WaitOutcome::TimedOut {
            last: HostState::Unknown,
        };
    }
    loop {
        if cancel.load(Ordering::Relaxed) {
            return WaitOutcome::Cancelled;
        }
        let st = probe(spec);
        on_tick(&st);
        if st.is_up() {
            return WaitOutcome::Up { state: st };
        }
        let now = Instant::now();
        if now >= deadline {
            return WaitOutcome::TimedOut { last: st };
        }
        let wake_at = (now + poll).min(deadline);
        while Instant::now() < wake_at {
            if cancel.load(Ordering::Relaxed) {
                return WaitOutcome::Cancelled;
            }
            let left = wake_at.saturating_duration_since(Instant::now());
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
        if Instant::now() >= deadline {
            // One last probe at the deadline.
            let st = probe(spec);
            on_tick(&st);
            return if st.is_up() {
                WaitOutcome::Up { state: st }
            } else {
                WaitOutcome::TimedOut { last: st }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(addr: Option<&str>, method: ProbeMethod) -> ProbeSpec {
        ProbeSpec {
            label: "t".into(),
            host_id: None,
            address: addr.map(|a| a.parse().unwrap()),
            method,
            timeout: Duration::from_millis(500),
            tcp_ports: vec![],
        }
    }

    #[test]
    fn unmonitored_is_unknown() {
        assert_eq!(probe(&spec(None, ProbeMethod::Auto)), HostState::Unknown);
        assert_eq!(
            probe(&spec(Some("127.0.0.1"), ProbeMethod::None)),
            HostState::Unknown
        );
        // TCP without ports cannot check anything.
        assert_eq!(
            probe(&spec(Some("127.0.0.1"), ProbeMethod::Tcp)),
            HostState::Unknown
        );
    }

    #[test]
    fn for_host_overrides() {
        let mut s = Settings::default();
        s.probe.method = ProbeMethod::Icmp;
        let mut h = Host::new("x", "02:00:00:00:00:01".parse().unwrap());
        h.address = Some("192.0.2.1".parse().unwrap());
        let p = ProbeSpec::for_host(&h, &s);
        assert_eq!(p.method, ProbeMethod::Icmp);
        assert_eq!(p.tcp_ports, vec![3389, 445, 22]);
        h.probe = Some(ProbeMethod::Tcp);
        h.tcp_ports = vec![22];
        let p = ProbeSpec::for_host(&h, &s);
        assert_eq!(p.method, ProbeMethod::Tcp);
        assert_eq!(p.tcp_ports, vec![22]);
    }

    #[test]
    fn tcp_probe_against_local_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut s = spec(Some("127.0.0.1"), ProbeMethod::Tcp);
        s.tcp_ports = vec![port];
        match probe(&s) {
            HostState::Up { via, ip, .. } => {
                assert_eq!(via, ProbeVia::Tcp { port });
                assert_eq!(ip, Ipv4Addr::LOCALHOST);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn probe_all_keeps_order() {
        let specs = vec![
            spec(None, ProbeMethod::Auto),
            spec(Some("127.0.0.1"), ProbeMethod::None),
            spec(None, ProbeMethod::Tcp),
        ];
        let r = probe_all(&specs, 32);
        assert_eq!(r, vec![HostState::Unknown; 3]);
        assert!(probe_all(&[], 4).is_empty());
    }

    #[test]
    fn wait_cancel_and_unmonitored() {
        let cancel = AtomicBool::new(true);
        let s = spec(Some("127.0.0.1"), ProbeMethod::Icmp);
        let r = wait_until_up(
            &s,
            Instant::now() + Duration::from_secs(5),
            Duration::from_secs(1),
            &cancel,
            |_| {},
        );
        assert_eq!(r, WaitOutcome::Cancelled);
        let r = wait_until_up(
            &spec(None, ProbeMethod::Auto),
            Instant::now(),
            Duration::from_secs(1),
            &AtomicBool::new(false),
            |_| {},
        );
        assert_eq!(
            r,
            WaitOutcome::TimedOut {
                last: HostState::Unknown
            }
        );
    }

    #[test]
    fn wait_until_up_with_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut s = spec(Some("127.0.0.1"), ProbeMethod::Tcp);
        s.tcp_ports = vec![port];
        let mut ticks = 0;
        let r = wait_until_up(
            &s,
            Instant::now() + Duration::from_secs(5),
            Duration::from_millis(200),
            &AtomicBool::new(false),
            |_| ticks += 1,
        );
        assert!(matches!(r, WaitOutcome::Up { .. }), "{r:?}");
        assert_eq!(ticks, 1);
    }
}
