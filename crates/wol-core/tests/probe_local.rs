//! Probes against the local machine: ICMP echo to 127.0.0.1 (IcmpSendEcho, no admin rights)
//! and a TCP listener.

use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use wol_core::probe::{self, HostState, ProbeMethod, ProbeSpec, ProbeVia, WaitOutcome, icmp};

fn spec(addr: &str, method: ProbeMethod, ports: Vec<u16>) -> ProbeSpec {
    ProbeSpec {
        label: addr.to_owned(),
        host_id: None,
        address: Some(addr.parse().unwrap()),
        method,
        timeout: Duration::from_millis(1000),
        tcp_ports: ports,
    }
}

#[test]
fn icmp_to_loopback_is_up() {
    let rtt = icmp::ping(Ipv4Addr::LOCALHOST, Duration::from_millis(1000)).expect("IcmpSendEcho");
    assert!(rtt.is_some(), "127.0.0.1 must answer ICMP echo");
    match probe::probe(&spec("127.0.0.1", ProbeMethod::Icmp, vec![])) {
        HostState::Up { via, ip, .. } => {
            assert_eq!(via, ProbeVia::Icmp);
            assert_eq!(ip, Ipv4Addr::LOCALHOST);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn auto_uses_icmp_first() {
    match probe::probe(&spec("127.0.0.1", ProbeMethod::Auto, vec![9])) {
        HostState::Up { via, .. } => assert_eq!(via, ProbeVia::Icmp),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn tcp_listener_is_up_and_probe_all_keeps_order() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let specs = vec![
        spec("127.0.0.1", ProbeMethod::Tcp, vec![port]),
        ProbeSpec {
            address: None,
            ..spec("127.0.0.1", ProbeMethod::Auto, vec![])
        },
        spec("127.0.0.1", ProbeMethod::Icmp, vec![]),
    ];
    let r = probe::probe_all(&specs, 32);
    assert!(matches!(r[0], HostState::Up { via: ProbeVia::Tcp { port: p }, .. } if p == port));
    assert_eq!(r[1], HostState::Unknown);
    assert!(matches!(
        r[2],
        HostState::Up {
            via: ProbeVia::Icmp,
            ..
        }
    ));
}

/// No route (IcmpSendEcho fails with ERROR_NETWORK_UNREACHABLE) means offline, in ICMP-only
/// mode too, not a probe error.
#[test]
fn icmp_only_without_route_is_down() {
    let st = probe::probe(&ProbeSpec {
        timeout: Duration::from_millis(300),
        ..spec("240.0.0.1", ProbeMethod::Icmp, vec![])
    });
    assert!(matches!(st, HostState::Down { .. }), "{st:?}");
}

#[test]
fn unresolvable_name() {
    let st = probe::probe(&spec("no-such-host.invalid", ProbeMethod::Icmp, vec![]));
    assert!(matches!(st, HostState::Unresolved { .. }), "{st:?}");
}

#[test]
fn wait_until_up_returns_immediately_for_loopback() {
    let start = Instant::now();
    let r = probe::wait_until_up(
        &spec("127.0.0.1", ProbeMethod::Icmp, vec![]),
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(3),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(matches!(r, WaitOutcome::Up { .. }), "{r:?}");
    assert!(start.elapsed() < Duration::from_secs(3));
}
