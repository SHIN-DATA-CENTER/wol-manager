//! TCP connect probe: a completed connection or a refusal (RST) both prove the host is up.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::model::limits::TCP_PORTS_MAX;

/// `true` when a connect result proves the host answered (connected, or actively refused).
pub fn is_alive(result: &io::Result<TcpStream>) -> bool {
    match result {
        Ok(_) => true,
        Err(e) => e.kind() == io::ErrorKind::ConnectionRefused,
    }
}

/// Tries the ports in parallel (one thread each) and returns the first port that proves the
/// host is up, with the elapsed time. `None` when no port answered within `timeout`.
///
/// Only the first [`TCP_PORTS_MAX`] ports are tried (a hand-edited or imported list can be
/// longer; `Config::validate` reports it). A zero `timeout` counts as 1 ms
/// (`connect_timeout` rejects zero, which would read as "down").
///
/// **Blocking** up to `timeout` (returns as soon as one port answers; the other attempts
/// finish in the background within `timeout`).
pub fn probe_ports(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Option<(u16, Duration)> {
    let ports = &ports[..ports.len().min(TCP_PORTS_MAX)];
    if ports.is_empty() {
        return None;
    }
    let timeout = timeout.max(Duration::from_millis(1));
    let start = Instant::now();
    let (tx, rx) = mpsc::channel::<Option<u16>>();
    for &port in ports {
        let worker_tx = tx.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("wol-tcp-probe-{port}"))
            .spawn(move || {
                let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
                let r = TcpStream::connect_timeout(&addr, timeout);
                let _ = worker_tx.send(is_alive(&r).then_some(port));
            });
        if spawned.is_err() {
            let _ = tx.send(None);
        }
    }
    drop(tx);
    let deadline = start + timeout + Duration::from_millis(500);
    let mut pending = ports.len();
    while pending > 0 {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Some(port)) => return Some((port, start.elapsed())),
            Ok(None) => pending -= 1,
            Err(_) => break,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn listening_port_is_up() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let r = probe_ports(Ipv4Addr::LOCALHOST, &[port], Duration::from_secs(2));
        assert_eq!(r.map(|(p, _)| p), Some(port));
    }

    #[test]
    fn refused_counts_as_alive() {
        assert!(is_alive(&Err(io::Error::from(
            io::ErrorKind::ConnectionRefused
        ))));
        assert!(!is_alive(&Err(io::Error::from(io::ErrorKind::TimedOut))));
    }

    #[test]
    fn no_ports_means_none() {
        assert!(probe_ports(Ipv4Addr::LOCALHOST, &[], Duration::from_millis(10)).is_none());
    }

    /// `connect_timeout` rejects a zero duration; that must not turn a live host "down".
    #[test]
    fn zero_timeout_still_probes() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let r = probe_ports(Ipv4Addr::LOCALHOST, &[port], Duration::ZERO);
        assert_eq!(r.map(|(p, _)| p), Some(port));
    }

    /// Only the first TCP_PORTS_MAX ports are tried: a listening port after them is never
    /// reached (no thread per entry of a huge list).
    #[test]
    fn long_lists_are_cut() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        // Whatever ports 1..=16 do on loopback, the listening port after them is not tried
        // (without the limit it would answer at once).
        let mut ports: Vec<u16> = (1..=TCP_PORTS_MAX as u16).collect();
        ports.push(port);
        let r = probe_ports(Ipv4Addr::LOCALHOST, &ports, Duration::from_millis(300));
        assert_ne!(r.map(|(p, _)| p), Some(port));
    }
}
