//! `arp`, `interfaces`, `listen`.

use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use serde::Serialize;
use wol_core::i18n::{Header, Msg};
use wol_core::netif::{self, Explained, InterfaceFilter, Reason};
use wol_core::{Error, Field, MacAddr, arp, magic};

use crate::cli::{ArpArgs, InterfacesArgs, ListenArgs};
use crate::ctrlc;
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult};
use crate::output::table::Cell;
use crate::output::{self, Table};
use crate::text::Text;
use crate::util;

pub fn arp(ctx: &mut Ctx, a: &ArpArgs) -> CmdResult {
    let ip = util::parse_ipv4(Field::Address, &a.ip)?;
    // The settings only refine the adapter choice; a broken file must not block ARP.
    let filter = match ctx.load_silent() {
        Ok((_, loaded)) => InterfaceFilter::from_settings(&loaded.config.settings.wake),
        Err(_) => InterfaceFilter::default(),
    };
    let mac = arp::mac_from_ip_with(ip, &netif::list(), &filter)?;
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc {
            ip: std::net::Ipv4Addr,
            mac: MacAddr,
        }
        ctx.print_json(&Doc { ip, mac });
    } else {
        ctx.out(&ctx.t(Msg::ArpFound {
            ip,
            mac: mac.to_string(),
        }));
    }
    Ok(exit::OK)
}

fn hidden_by_default(e: &Explained) -> bool {
    matches!(e.reason, Reason::Down | Reason::Loopback | Reason::NoIpv4)
}

pub fn interfaces(ctx: &mut Ctx, a: &InterfacesArgs) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let filter = InterfaceFilter::from_settings(&loaded.config.settings.wake);
    let all = netif::explain(&netif::list(), &filter);
    let shown: Vec<&Explained> = all
        .iter()
        .filter(|e| a.all || !hidden_by_default(e))
        .collect();
    if ctx.json() {
        ctx.print_json(&shown);
        return Ok(exit::OK);
    }
    let h = |x| ctx.t(Msg::Header(x));
    let verbose = ctx.verbose() > 0;
    let mut headers = vec![
        h(Header::Used),
        h(Header::Interface),
        h(Header::Kind),
        h(Header::Ipv4),
        h(Header::Reason),
    ];
    if verbose {
        headers.push(h(Header::Mac));
        headers.push(h(Header::Guid));
    }
    let mut t = Table::new(headers);
    for e in &shown {
        let i = &e.interface;
        let used = if e.used {
            Cell::styled(ctx.t(Msg::Yes), output::GREEN)
        } else {
            Cell::styled(ctx.t(Msg::No), output::DIM)
        };
        let addrs: Vec<String> = e
            .addresses
            .iter()
            .map(|v| match (&v.note, verbose) {
                (Some(n), true) => format!("{} ({})", v.subnet, ctx.t(Msg::AddrNote(*n))),
                _ => v.subnet.to_string(),
            })
            .collect();
        let name = if verbose && i.description != i.friendly_name {
            format!("{} [{}] #{}", i.display_name(), i.description, i.index)
        } else {
            i.display_name().to_owned()
        };
        let mut row = vec![
            used,
            Cell::styled(name, output::BOLD),
            Cell::plain(ctx.t(Msg::IfKind(i.kind))),
            Cell::plain(if addrs.is_empty() {
                "-".to_owned()
            } else {
                addrs.join(", ")
            }),
            Cell::plain(ctx.t(Msg::IfReason(e.reason))),
        ];
        if verbose {
            row.push(Cell::plain(
                i.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
            ));
            row.push(Cell::styled(i.guid.clone(), output::DIM));
        }
        t.row(row);
    }
    for l in t.lines() {
        ctx.out(&l);
    }
    Ok(exit::OK)
}

#[derive(Serialize)]
struct Received {
    from: SocketAddr,
    mac: MacAddr,
    len: usize,
    secureon: bool,
}

#[derive(Serialize)]
struct ListenDoc {
    bind: SocketAddrV4,
    /// Magic packets received (all of them, also those not listed in `packets`).
    received: usize,
    /// The first [`MAX_LISTED`] packets.
    packets: Vec<Received>,
    timed_out: bool,
    cancelled: bool,
}

/// Packets kept for the `--json` document (a flood must not grow memory without limit).
const MAX_LISTED: usize = 10_000;
/// Receive buffer: the largest UDP payload over IPv4, so no datagram is too long for it.
const RECV_BUFFER: usize = 65_536;
/// `WSAEMSGSIZE`: a datagram was longer than the buffer (and was cut).
const WSAEMSGSIZE: i32 = 10040;

pub fn listen(ctx: &mut Ctx, a: &ListenArgs) -> CmdResult {
    let port = util::parse_port(&a.port)?;
    let ip = util::parse_ipv4(Field::Address, &a.bind)?;
    let count = a
        .count
        .as_deref()
        .map(|v| util::parse_uint("--count", v, 1..=1_000_000))
        .transpose()?
        .map(|n| n as usize);
    let timeout = a
        .timeout
        .as_deref()
        .map(|v| util::parse_duration("--timeout", v))
        .transpose()?;
    ctx.soft_lang();

    let bind = SocketAddrV4::new(ip, port);
    let sock = UdpSocket::bind(bind).map_err(|e| Error::Network {
        op: "bind",
        source: e,
    })?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| Error::Network {
            op: "set_read_timeout",
            source: e,
        })?;
    let cancel = ctrlc::install();
    ctx.info(&ctx.t(Msg::Listening { port }));

    let deadline = timeout.map(|t| Instant::now() + t);
    // Anyone on the network can send to the port: only the count grows with the traffic.
    let mut received = 0usize;
    let mut packets: Vec<Received> = Vec::new();
    let mut buf = vec![0u8; RECV_BUFFER];
    let mut timed_out = false;
    let mut cancelled = false;
    loop {
        if count.is_some_and(|c| received >= c) {
            break;
        }
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            cancelled = true;
            break;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            timed_out = true;
            break;
        }
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                continue;
            }
            // Not a magic packet (those are 102 or 108 bytes); never a reason to stop.
            Err(e) if e.raw_os_error() == Some(WSAEMSGSIZE) => {
                if ctx.verbose() > 0 {
                    ctx.info(&ctx.tx(Text::Oversized));
                }
                continue;
            }
            Err(e) => {
                return Err(Error::Network {
                    op: "recv_from",
                    source: e,
                }
                .into());
            }
        };
        match magic::parse(&buf[..n]) {
            Some(p) => {
                let mut line = ctx.t(Msg::PacketReceived {
                    mac: p.mac.to_string(),
                    from: from.to_string(),
                    len: n,
                });
                if p.has_secureon {
                    line.push_str(" [SecureOn]");
                }
                ctx.out(&line);
                received += 1;
                if ctx.json() && packets.len() < MAX_LISTED {
                    packets.push(Received {
                        from,
                        mac: p.mac,
                        len: n,
                        secureon: p.has_secureon,
                    });
                }
            }
            None => {
                if ctx.verbose() > 0 {
                    ctx.info(&ctx.tx(Text::NotMagic {
                        from: &from.to_string(),
                        len: n,
                    }));
                }
            }
        }
    }
    if timed_out {
        ctx.info(&ctx.tx(Text::ListenTimeout { received }));
    }
    let code = if cancelled {
        exit::CANCELLED
    } else if timed_out {
        match count {
            Some(_) => exit::TIMEOUT,
            None if received == 0 => exit::NEGATIVE,
            None => exit::OK,
        }
    } else {
        exit::OK
    };
    if ctx.json() {
        ctx.print_json(&ListenDoc {
            bind,
            received,
            packets,
            timed_out,
            cancelled,
        });
    }
    Ok(code)
}
