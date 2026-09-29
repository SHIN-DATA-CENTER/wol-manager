//! Sends real magic packets to a UDP receiver on 127.0.0.1 through an explicit target and
//! checks size, content and repetition. Broadcasts are disabled so nothing leaves the host.

use std::net::UdpSocket;
use std::time::Duration;

use wol_core::magic;
use wol_core::model::Settings;
use wol_core::send::{self, Via, WakeOutcome, WakeRequest};
use wol_core::{MacAddr, SecureOn};

fn receiver() -> (UdpSocket, u16) {
    let rx = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    rx.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let port = rx.local_addr().unwrap().port();
    (rx, port)
}

fn loopback_request(mac: MacAddr, port: u16, repeat: u8) -> WakeRequest {
    let mut s = Settings::default();
    s.wake.repeat = repeat;
    s.wake.interval_ms = 20;
    let mut req = WakeRequest::adhoc(mac, &s);
    req.broadcast = false;
    req.limited_broadcast = false;
    req.targets = vec![format!("127.0.0.1:{port}").parse().unwrap()];
    req
}

fn recv(rx: &UdpSocket) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let (n, from) = rx.recv_from(&mut buf).expect("packet expected");
    assert!(from.ip().is_loopback());
    buf[..n].to_vec()
}

#[test]
fn magic_packet_arrives_102_bytes_times_repeat() {
    let (rx, port) = receiver();
    let mac: MacAddr = "00:11:22:33:44:55".parse().unwrap();
    let req = loopback_request(mac, port, 3);
    let report = send::wake(&req).expect("wake");
    assert_eq!(report.outcome(), WakeOutcome::Ok, "{report:#?}");
    assert_eq!(report.sent_count(), 3);
    assert_eq!(report.packet_len, 102);
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.attempts[0].via, Via::Routed);
    for _ in 0..3 {
        let p = recv(&rx);
        assert_eq!(p.len(), 102);
        assert_eq!(p, magic::build(mac, None));
        assert_eq!(magic::parse(&p).unwrap().mac, mac);
    }
    rx.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 512];
    assert!(rx.recv_from(&mut buf).is_err(), "exactly `repeat` packets");
}

#[test]
fn secureon_packet_is_108_bytes() {
    let (rx, port) = receiver();
    let mac: MacAddr = "AA-BB-CC-DD-EE-FF".parse().unwrap();
    let mut req = loopback_request(mac, port, 1);
    req.secureon = Some("01:23:45:67:89:AB".parse::<SecureOn>().unwrap());
    let report = send::wake(&req).unwrap();
    assert_eq!(report.outcome(), WakeOutcome::Ok);
    let p = recv(&rx);
    assert_eq!(p.len(), 108);
    let parsed = magic::parse(&p).unwrap();
    assert_eq!(parsed.mac, mac);
    assert_eq!(
        parsed.secureon.map(|s| s.to_string()).as_deref(),
        Some("01:23:45:67:89:AB")
    );
}

#[test]
fn rounds_interleave_hosts() {
    let (rx, port) = receiver();
    let a: MacAddr = "02:00:00:00:00:0A".parse().unwrap();
    let b: MacAddr = "02:00:00:00:00:0B".parse().unwrap();
    let reqs = vec![loopback_request(a, port, 2), loopback_request(b, port, 2)];
    let reports = send::wake_many(&reqs);
    assert_eq!(reports.len(), 2);
    assert!(reports.iter().all(|r| r.outcome() == WakeOutcome::Ok));
    let order: Vec<MacAddr> = (0..4)
        .map(|_| magic::parse(&recv(&rx)).unwrap().mac)
        .collect();
    assert_eq!(order, vec![a, b, a, b]);
}

#[test]
fn dry_run_plans_without_sending() {
    let (rx, port) = receiver();
    let mac: MacAddr = "00:11:22:33:44:66".parse().unwrap();
    let req = loopback_request(mac, port, 3);
    let plans = send::dry_run(std::slice::from_ref(&req));
    let plan = plans[0].as_ref().unwrap();
    assert_eq!(plan.sends.len(), 1);
    assert_eq!(plan.sends[0].dest.port(), port);
    assert!(
        plan.packet_hex()
            .starts_with("FF FF FF FF FF FF 00 11 22 33 44 66")
    );
    rx.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = [0u8; 512];
    assert!(rx.recv_from(&mut buf).is_err(), "dry run sends nothing");
}
