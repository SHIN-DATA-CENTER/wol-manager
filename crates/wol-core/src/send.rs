//! Planning and sending magic packets.
//!
//! 1. Build a [`WakeRequest`] ([`WakeRequest::for_host`] or [`WakeRequest::adhoc`]).
//! 2. [`plan`] (pure) turns it into a [`SendPlan`]: for every selected interface address A
//!    (subnet N) a socket bound to A sends to `N.broadcast:port` (when `broadcast`) and to
//!    `255.255.255.255:port` (when `limited_broadcast`). The host address is sent to by
//!    unicast when it lies in a selected subnet. Explicit targets:
//!    * `255.255.255.255[:port]` → expanded to the limited broadcast of every selected
//!      interface (an unbound send would leave through the lowest-metric interface, often a
//!      VPN);
//!    * inside (or the broadcast of) a selected subnet → sent from that interface;
//!    * anything else → [`Via::Routed`] (unbound socket, OS routing). [`resolve_names`] also
//!      asks the routing table which interface such a destination leaves through
//!      (`GetBestInterface`); the send records it, and when it is a VPN / virtual adapter
//!      that is not selected (a VPN's own subnet or a route it pushed, e.g. 10.0.20.0/24 via
//!      `wt0`) the plan carries a [`PlanNote::ViaVirtual`] note.
//! 3. [`execute`] sends `repeat` rounds, interleaving all plans, pausing `interval` between
//!    rounds. `WSAEADDRNOTAVAIL` (10049) / `WSAEHOSTUNREACH` (10065) on a bound socket mean the
//!    interface vanished: those sends are *skipped* (not failures). [`wake_many`] then
//!    re-enumerates interfaces once for requests that sent nothing.
//!
//! A successful send does not mean the host woke up; use [`crate::probe`] to verify.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Serialize, Serializer};

use crate::addr::{HostAddr, Target};
use crate::consts::DEFAULT_WOL_PORT;
use crate::error::{Error, Result};
use crate::mac::{MacAddr, SecureOn};
use crate::magic;
use crate::model::{Host, HostId, Settings, limits};
use crate::netif::{self, InterfaceFilter, Ipv4Subnet, NetInterface, Selected};

fn ser_ms<S: Serializer>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_millis() as u64)
}

/// Everything needed to wake one machine.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WakeRequest {
    /// Name shown in reports (host name, or the MAC for ad-hoc wakes).
    pub label: String,
    /// Host id when the request comes from the config.
    pub host_id: Option<HostId>,
    /// Target MAC.
    pub mac: MacAddr,
    /// SecureOn password.
    #[serde(skip)]
    pub secureon: Option<SecureOn>,
    /// UDP port.
    pub port: u16,
    /// Send the directed broadcast of every selected subnet.
    pub broadcast: bool,
    /// Send 255.255.255.255 from every selected interface.
    pub limited_broadcast: bool,
    /// Host address; used for unicast when it is inside a selected subnet.
    pub unicast: Option<HostAddr>,
    /// Explicit targets.
    pub targets: Vec<Target>,
    /// Interface selection.
    pub filter: InterfaceFilter,
    /// Send rounds (clamped to `1..=10` by [`plan`]).
    pub repeat: u8,
    /// Pause between rounds.
    #[serde(rename = "interval_ms", serialize_with = "ser_ms")]
    pub interval: Duration,
}

impl WakeRequest {
    /// Request for a configured host: host overrides (port, targets, broadcast, pinned
    /// interfaces) on top of `[settings.wake]`.
    pub fn for_host(host: &Host, settings: &Settings) -> WakeRequest {
        WakeRequest {
            label: host.name.clone(),
            host_id: Some(host.id),
            mac: host.mac,
            secureon: host.secureon,
            port: host.effective_port(settings),
            broadcast: host.broadcast,
            limited_broadcast: settings.wake.limited_broadcast,
            unicast: host.address.clone(),
            targets: host.targets.clone(),
            filter: InterfaceFilter::for_host(host, settings),
            repeat: settings.wake.effective_repeat(),
            interval: settings.wake.effective_interval(),
        }
    }

    /// Ad-hoc request for a bare MAC (`wolm wake AA:BB:...`) using `[settings.wake]`.
    pub fn adhoc(mac: MacAddr, settings: &Settings) -> WakeRequest {
        WakeRequest {
            label: mac.to_string(),
            host_id: None,
            mac,
            secureon: None,
            port: settings.wake.effective_port(),
            broadcast: true,
            limited_broadcast: settings.wake.limited_broadcast,
            unicast: None,
            targets: Vec::new(),
            filter: InterfaceFilter::from_settings(&settings.wake),
            repeat: settings.wake.effective_repeat(),
            interval: settings.wake.effective_interval(),
        }
    }

    /// Host names (lower-cased) that [`resolve_names`] must look up for this request.
    fn names(&self) -> impl Iterator<Item = &str> {
        self.unicast
            .iter()
            .chain(self.targets.iter().map(|t| &t.addr))
            .filter_map(|a| match a {
                HostAddr::Name(n) => Some(n.as_str()),
                HostAddr::V4(_) => None,
            })
    }
}

/// Results of the lookups [`plan`] needs from the OS: name resolution (keyed by lower-cased
/// name) and the egress interface the routing table picks for explicit targets. Filled by
/// [`resolve_names`] or by tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    map: HashMap<String, std::result::Result<Ipv4Addr, String>>,
    routes: HashMap<Ipv4Addr, u32>,
}

impl Resolved {
    /// Empty set (every name is "not resolved", no routes known).
    pub fn new() -> Resolved {
        Resolved::default()
    }

    /// Records a result for `name`.
    pub fn insert(&mut self, name: &str, result: std::result::Result<Ipv4Addr, String>) {
        self.map.insert(name.to_ascii_lowercase(), result);
    }

    /// Looks up `name`.
    pub fn get(&self, name: &str) -> Option<&std::result::Result<Ipv4Addr, String>> {
        self.map.get(&name.to_ascii_lowercase())
    }

    /// Records that datagrams to `dest` leave through the interface with index `if_index`
    /// ([`NetInterface::index`], from [`netif::best_interface`]).
    pub fn insert_route(&mut self, dest: Ipv4Addr, if_index: u32) {
        self.routes.insert(dest, if_index);
    }

    /// Egress interface index for `dest`, if known.
    pub fn route(&self, dest: Ipv4Addr) -> Option<u32> {
        self.routes.get(&dest).copied()
    }

    fn lookup(&self, a: &HostAddr) -> std::result::Result<Ipv4Addr, String> {
        match a {
            HostAddr::V4(ip) => Ok(*ip),
            HostAddr::Name(n) => self
                .get(n)
                .cloned()
                .unwrap_or_else(|| Err("not resolved".to_owned())),
        }
    }
}

/// At most this many name lookups run at the same time.
const MAX_PARALLEL_LOOKUPS: usize = 16;

/// Runs `f` on every item with at most `max_parallel` scoped threads; results in input order.
fn parallel_map<T: Sync, R: Send>(
    items: &[T],
    max_parallel: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    if items.len() <= 1 {
        return items.iter().map(f).collect();
    }
    let workers = max_parallel.clamp(1, items.len());
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    let r = f(&items[i]);
                    *results[i].lock().unwrap_or_else(|p| p.into_inner()) = Some(r);
                }
            });
        }
    });
    results
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(|p| p.into_inner())
                .expect("every item is processed")
        })
        .collect()
}

/// Resolves every host name used by the requests (unicast address and targets) and asks the
/// routing table for the egress interface of every explicit target ([`netif::best_interface`],
/// used for [`PlanNote::ViaVirtual`] and [`PlannedSend::interface`] of routed sends).
///
/// **Blocking**: DNS. A name that does not resolve costs about 1-3 s (DNS suffixes, LLMNR,
/// NetBIOS), which is typical for a sleeping PC addressed by its computer name. Distinct
/// names are looked up in parallel (up to 16 at a time), so a group wake waits about as long
/// as its slowest name, not the sum. Literal IPv4 addresses cost nothing.
pub fn resolve_names(reqs: &[WakeRequest]) -> Resolved {
    let mut names: Vec<&str> = Vec::new();
    for n in reqs.iter().flat_map(WakeRequest::names) {
        if !names.iter().any(|x| x.eq_ignore_ascii_case(n)) {
            names.push(n);
        }
    }
    let results = parallel_map(&names, MAX_PARALLEL_LOOKUPS, |n| {
        crate::addr::resolve_name_v4(n).map_err(|e| match e {
            Error::Resolve { message, .. } => message,
            other => other.to_string(),
        })
    });
    let mut r = Resolved::new();
    for (n, res) in names.iter().zip(results) {
        r.insert(n, res);
    }
    for t in reqs.iter().flat_map(|q| &q.targets) {
        if let Ok(ip) = r.lookup(&t.addr)
            && ip != Ipv4Addr::BROADCAST
            && r.route(ip).is_none()
            && let Some(idx) = netif::best_interface(ip)
        {
            r.insert_route(ip, idx);
        }
    }
    r
}

/// How a datagram leaves the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// Socket bound to this local interface address (strong-host send pins the interface).
    Interface(Ipv4Addr),
    /// Unbound socket; the OS routing table decides.
    Routed,
}

/// Why a datagram is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SendKind {
    /// Directed broadcast of a selected subnet.
    DirectedBroadcast,
    /// 255.255.255.255 from a selected interface.
    LimitedBroadcast,
    /// Unicast to the host address (inside a selected subnet).
    Unicast,
    /// Explicit target.
    Target,
}

/// The interface a send is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IfaceRef {
    /// Interface index.
    pub index: u32,
    /// GUID.
    pub guid: String,
    /// Display name.
    pub name: String,
    /// VPN / virtual adapter.
    pub is_virtual: bool,
}

impl From<&Selected> for IfaceRef {
    fn from(s: &Selected) -> Self {
        IfaceRef {
            index: s.index,
            guid: s.guid.clone(),
            name: s.name.clone(),
            is_virtual: s.is_virtual,
        }
    }
}

impl From<&NetInterface> for IfaceRef {
    fn from(i: &NetInterface) -> Self {
        IfaceRef {
            index: i.index,
            guid: i.guid.clone(),
            name: i.display_name().to_owned(),
            is_virtual: i.is_virtual,
        }
    }
}

/// One planned datagram (sent once per round).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlannedSend {
    /// Bound interface or routed.
    pub via: Via,
    /// For [`Via::Interface`]: the bound interface. For [`Via::Routed`]: the interface the
    /// routing table picks, when known ([`Resolved::route`]); informational only (show it as
    /// `Msg::ViaRoutedThrough`).
    pub interface: Option<IfaceRef>,
    /// Destination.
    pub dest: SocketAddrV4,
    /// Reason.
    pub kind: SendKind,
}

/// Remarks attached to a plan / report (for dry-run output and GUI tooltips).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlanNote {
    /// No interface was selected (automatic mode found nothing usable, or pins matched
    /// nothing).
    NoInterfaces,
    /// /31 or /32 subnet: no directed broadcast.
    NoDirectedBroadcast {
        /// Interface name.
        interface: String,
        /// The subnet.
        subnet: Ipv4Subnet,
    },
    /// The host address is not inside a selected subnet, so no unicast is sent. Add it as a
    /// target to send it through the routing table.
    AddressOffSubnet {
        /// The address as configured.
        address: String,
    },
    /// The host address could not be resolved (no unicast).
    AddressUnresolved {
        /// The name.
        address: String,
        /// OS message.
        error: String,
    },
    /// A routed target leaves through a VPN / virtual adapter that is not selected: the
    /// routing table sends it there (a route the VPN pushed, or its own subnet).
    ViaVirtual {
        /// The target.
        target: String,
        /// Adapter name.
        interface: String,
    },
    /// Nothing could be sent to (the request produced no destination).
    NoDestinations,
}

/// A target that could not be planned (name resolution failure). Counts as a failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanFailure {
    /// The target as configured.
    pub target: String,
    /// English error.
    pub error: String,
}

/// The pure result of [`plan`] for one request.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SendPlan {
    /// Label (host name or MAC).
    pub label: String,
    /// Host id, if any.
    pub host_id: Option<HostId>,
    /// Target MAC.
    pub mac: MacAddr,
    /// Magic packet payload (contains the SecureOn password, if any).
    #[serde(skip)]
    pub packet: Vec<u8>,
    /// Payload length (102 or 108).
    pub packet_len: usize,
    /// Datagrams sent in each round.
    pub sends: Vec<PlannedSend>,
    /// Targets that could not be planned.
    pub failures: Vec<PlanFailure>,
    /// Remarks.
    pub notes: Vec<PlanNote>,
    /// Rounds.
    pub repeat: u8,
    /// Pause between rounds.
    #[serde(rename = "interval_ms", serialize_with = "ser_ms")]
    pub interval: Duration,
}

impl SendPlan {
    /// Hex dump of the packet (for `--dry-run`). A SecureOn password is shown as `**`
    /// ([`magic::to_hex_masked`]).
    pub fn packet_hex(&self) -> String {
        magic::to_hex_masked(&self.packet)
    }

    /// The packet carries a SecureOn password.
    pub fn has_secureon(&self) -> bool {
        self.packet.len() == magic::PACKET_LEN_SECUREON
    }
}

/// Plans the datagrams for one request. Pure: interfaces, name resolution results and routes
/// are passed in. Port 0 (in the request or a target) means the default port 9.
///
/// Errors: [`Error::NoDestinations`] when there is nothing to send to and no failed target
/// to report.
pub fn plan(req: &WakeRequest, ifaces: &[NetInterface], resolved: &Resolved) -> Result<SendPlan> {
    let selected = netif::select(ifaces, &req.filter);
    let mut sends: Vec<PlannedSend> = Vec::new();
    let mut notes: Vec<PlanNote> = Vec::new();
    let mut failures: Vec<PlanFailure> = Vec::new();
    let req_port = if req.port == 0 {
        DEFAULT_WOL_PORT
    } else {
        req.port
    };

    fn push(sends: &mut Vec<PlannedSend>, s: PlannedSend) {
        if !sends.iter().any(|x| x.via == s.via && x.dest == s.dest) {
            sends.push(s);
        }
    }
    let bound = |sel: &Selected, dest: Ipv4Addr, port: u16, kind: SendKind| PlannedSend {
        via: Via::Interface(sel.subnet.addr),
        interface: Some(IfaceRef::from(sel)),
        dest: SocketAddrV4::new(dest, port),
        kind,
    };

    if selected.is_empty() {
        notes.push(PlanNote::NoInterfaces);
    }

    for sel in &selected {
        if req.broadcast {
            match sel.subnet.broadcast() {
                Some(b) => push(
                    &mut sends,
                    bound(sel, b, req_port, SendKind::DirectedBroadcast),
                ),
                None => notes.push(PlanNote::NoDirectedBroadcast {
                    interface: sel.name.clone(),
                    subnet: sel.subnet,
                }),
            }
        }
        if req.limited_broadcast {
            push(
                &mut sends,
                bound(
                    sel,
                    Ipv4Addr::BROADCAST,
                    req_port,
                    SendKind::LimitedBroadcast,
                ),
            );
        }
    }

    if let Some(a) = &req.unicast {
        match resolved.lookup(a) {
            Ok(ip) => {
                let hits: Vec<&Selected> = selected
                    .iter()
                    .filter(|s| s.subnet.contains(ip) && s.subnet.addr != ip)
                    .collect();
                if hits.is_empty() {
                    notes.push(PlanNote::AddressOffSubnet {
                        address: a.to_string(),
                    });
                }
                for sel in hits {
                    push(&mut sends, bound(sel, ip, req_port, SendKind::Unicast));
                }
            }
            Err(e) => notes.push(PlanNote::AddressUnresolved {
                address: a.to_string(),
                error: e,
            }),
        }
    }

    for t in &req.targets {
        let port = t.port.filter(|p| *p != 0).unwrap_or(req_port);
        let ip = match resolved.lookup(&t.addr) {
            Ok(ip) => ip,
            Err(e) => {
                failures.push(PlanFailure {
                    target: t.to_string(),
                    error: e,
                });
                continue;
            }
        };
        if ip == Ipv4Addr::BROADCAST {
            if selected.is_empty() {
                failures.push(PlanFailure {
                    target: t.to_string(),
                    error: "no interface selected for the limited broadcast".to_owned(),
                });
            }
            for sel in &selected {
                push(&mut sends, bound(sel, ip, port, SendKind::Target));
            }
            continue;
        }
        let hits: Vec<&Selected> = selected
            .iter()
            .filter(|s| s.subnet.broadcast() == Some(ip) || s.subnet.contains(ip))
            .collect();
        if !hits.is_empty() {
            for sel in hits {
                push(&mut sends, bound(sel, ip, port, SendKind::Target));
            }
            continue;
        }
        // Where the routing table sends it (GetBestInterface via `resolved`); without that
        // information, fall back to "inside a VPN adapter's own subnet".
        let egress: Option<&NetInterface> = resolved
            .route(ip)
            .and_then(|idx| ifaces.iter().find(|i| i.index == idx));
        push(
            &mut sends,
            PlannedSend {
                via: Via::Routed,
                interface: egress.map(IfaceRef::from),
                dest: SocketAddrV4::new(ip, port),
                kind: SendKind::Target,
            },
        );
        let is_selected = |i: &NetInterface| selected.iter().any(|s| s.index == i.index);
        let via_virtual = match (resolved.route(ip), egress) {
            (Some(_), Some(i)) => (i.is_virtual && !is_selected(i)).then_some(i),
            (Some(_), None) => None,
            (None, _) => ifaces.iter().find(|i| {
                i.is_virtual
                    && i.oper_up
                    && !is_selected(i)
                    && i.ipv4.iter().any(|s| s.contains(ip))
            }),
        };
        if let Some(vi) = via_virtual {
            let note = PlanNote::ViaVirtual {
                target: t.to_string(),
                interface: vi.display_name().to_owned(),
            };
            if !notes.contains(&note) {
                notes.push(note);
            }
        }
    }

    if sends.is_empty() && failures.is_empty() {
        return Err(Error::NoDestinations);
    }
    let packet = magic::build(req.mac, req.secureon);
    Ok(SendPlan {
        label: req.label.clone(),
        host_id: req.host_id,
        mac: req.mac,
        packet_len: packet.len(),
        packet,
        sends,
        failures,
        notes,
        repeat: req
            .repeat
            .clamp(*limits::REPEAT.start(), *limits::REPEAT.end()),
        interval: req
            .interval
            .min(Duration::from_millis(u64::from(*limits::INTERVAL_MS.end()))),
    })
}

/// Result of one planned datagram over all rounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attempt {
    /// Bound interface or routed.
    pub via: Via,
    /// Interface details (see [`PlannedSend::interface`]).
    pub interface: Option<IfaceRef>,
    /// Destination.
    pub dest: SocketAddrV4,
    /// Reason.
    pub kind: SendKind,
    /// Rounds in which the datagram was sent.
    pub sent: u32,
    /// Rounds in which sending failed.
    pub failed: u32,
    /// Rounds skipped because the interface vanished (10049 / 10065). Not failures.
    pub skipped: u32,
    /// Last error message (English, OS text).
    pub last_error: Option<String>,
    /// Last OS error code, if any.
    pub last_os_error: Option<i32>,
}

/// Overall result of a wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeOutcome {
    /// Every destination was sent to.
    Ok,
    /// Some destinations failed, at least one succeeded.
    Partial,
    /// Nothing was sent.
    Failed,
}

/// Report for one request.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WakeReport {
    /// Label (host name or MAC).
    pub label: String,
    /// Host id, if any.
    pub host_id: Option<HostId>,
    /// Target MAC.
    pub mac: MacAddr,
    /// Payload length (102 or 108).
    pub packet_len: usize,
    /// Per-destination results.
    pub attempts: Vec<Attempt>,
    /// Targets that could not be planned (count as failures).
    pub failures: Vec<PlanFailure>,
    /// Remarks from planning.
    pub notes: Vec<PlanNote>,
    /// Interfaces were re-enumerated because the planned ones vanished.
    pub reenumerated: bool,
}

impl WakeReport {
    /// Ok / Partial / Failed. Skipped sends (vanished interface) are neither.
    pub fn outcome(&self) -> WakeOutcome {
        let any_sent = self.attempts.iter().any(|a| a.sent > 0);
        let any_failed = self.attempts.iter().any(|a| a.failed > 0) || !self.failures.is_empty();
        match (any_sent, any_failed) {
            (false, _) => WakeOutcome::Failed,
            (true, true) => WakeOutcome::Partial,
            (true, false) => WakeOutcome::Ok,
        }
    }

    /// Total datagrams sent.
    pub fn sent_count(&self) -> u32 {
        self.attempts.iter().map(|a| a.sent).sum()
    }

    /// Total failed sends plus unplannable targets.
    pub fn failed_count(&self) -> u32 {
        self.attempts.iter().map(|a| a.failed).sum::<u32>() + self.failures.len() as u32
    }

    /// Total skipped sends.
    pub fn skipped_count(&self) -> u32 {
        self.attempts.iter().map(|a| a.skipped).sum()
    }

    /// `true` when planning found nothing to send to.
    pub fn no_destinations(&self) -> bool {
        self.notes.contains(&PlanNote::NoDestinations)
    }

    fn from_plan(p: &SendPlan) -> WakeReport {
        WakeReport {
            label: p.label.clone(),
            host_id: p.host_id,
            mac: p.mac,
            packet_len: p.packet_len,
            attempts: p
                .sends
                .iter()
                .map(|s| Attempt {
                    via: s.via,
                    interface: s.interface.clone(),
                    dest: s.dest,
                    kind: s.kind,
                    sent: 0,
                    failed: 0,
                    skipped: 0,
                    last_error: None,
                    last_os_error: None,
                })
                .collect(),
            failures: p.failures.clone(),
            notes: p.notes.clone(),
            reenumerated: false,
        }
    }

    fn no_destinations_for(req: &WakeRequest) -> WakeReport {
        WakeReport {
            label: req.label.clone(),
            host_id: req.host_id,
            mac: req.mac,
            packet_len: magic::build(req.mac, req.secureon).len(),
            attempts: Vec::new(),
            failures: Vec::new(),
            notes: vec![PlanNote::NoDestinations],
            reenumerated: false,
        }
    }
}

const WSAEADDRNOTAVAIL: i32 = 10049;
const WSAEHOSTUNREACH: i32 = 10065;

fn vanished(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(WSAEADDRNOTAVAIL | WSAEHOSTUNREACH))
}

enum Sock {
    Ready(UdpSocket),
    Vanished,
    Broken(io::Error),
}

fn open_socket(via: Via) -> Sock {
    let bind = match via {
        Via::Interface(a) => SocketAddrV4::new(a, 0),
        Via::Routed => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    };
    let r = UdpSocket::bind(bind).and_then(|s| {
        s.set_broadcast(true)?;
        Ok(s)
    });
    match r {
        Ok(s) => Sock::Ready(s),
        Err(e) if matches!(via, Via::Interface(_)) && vanished(&e) => Sock::Vanished,
        Err(e) => Sock::Broken(e),
    }
}

/// Sends the plans: `max(repeat)` rounds, all plans interleaved in each round, pausing the
/// largest `interval` between rounds (not after the last).
///
/// **Blocking** for about `(repeat - 1) × interval` (default 200 ms, at most 45 s).
pub fn execute(plans: &[SendPlan]) -> Vec<WakeReport> {
    let mut reports: Vec<WakeReport> = plans.iter().map(WakeReport::from_plan).collect();
    let rounds = plans.iter().map(|p| p.repeat).max().unwrap_or(0);
    let interval = plans.iter().map(|p| p.interval).max().unwrap_or_default();
    let mut sockets: HashMap<Via, Sock> = HashMap::new();

    for round in 0..rounds {
        for (pi, p) in plans.iter().enumerate() {
            if round >= p.repeat {
                continue;
            }
            for (si, s) in p.sends.iter().enumerate() {
                let att = &mut reports[pi].attempts[si];
                let sock = sockets.entry(s.via).or_insert_with(|| open_socket(s.via));
                match sock {
                    Sock::Ready(sk) => match sk.send_to(&p.packet, s.dest) {
                        Ok(n) if n == p.packet.len() => att.sent += 1,
                        Ok(n) => {
                            att.failed += 1;
                            att.last_error = Some(format!("short send ({n} bytes)"));
                        }
                        Err(e) if matches!(s.via, Via::Interface(_)) && vanished(&e) => {
                            att.skipped += 1;
                            att.last_error = Some(e.to_string());
                            att.last_os_error = e.raw_os_error();
                            *sock = Sock::Vanished;
                        }
                        Err(e) => {
                            att.failed += 1;
                            att.last_error = Some(e.to_string());
                            att.last_os_error = e.raw_os_error();
                        }
                    },
                    Sock::Vanished => att.skipped += 1,
                    Sock::Broken(e) => {
                        att.failed += 1;
                        att.last_error = Some(e.to_string());
                        att.last_os_error = e.raw_os_error();
                    }
                }
            }
        }
        if round + 1 < rounds && !interval.is_zero() {
            std::thread::sleep(interval);
        }
    }
    reports
}

/// Plans every request against the current interfaces without sending (for `--dry-run`).
/// **Blocking** for DNS: see [`resolve_names`] (about 1-3 s when a host name does not
/// resolve; names are looked up in parallel).
pub fn dry_run(reqs: &[WakeRequest]) -> Vec<Result<SendPlan>> {
    let ifaces = netif::list();
    let resolved = resolve_names(reqs);
    reqs.iter().map(|r| plan(r, &ifaces, &resolved)).collect()
}

/// Enumerates interfaces, resolves names, plans and sends all requests (interleaved), with
/// one re-enumeration for requests whose interfaces vanished. One report per request, in
/// order; a request with nothing to send to gets a report with no attempts and
/// [`PlanNote::NoDestinations`] (outcome `Failed`).
///
/// **Blocking**: DNS for host names before anything is sent (see [`resolve_names`]: about
/// 1-3 s when a name does not resolve, e.g. a sleeping PC's computer name; names are looked
/// up in parallel, so this does not grow with the number of hosts), plus
/// `(repeat - 1) × interval`.
pub fn wake_many(reqs: &[WakeRequest]) -> Vec<WakeReport> {
    let ifaces = netif::list();
    let resolved = resolve_names(reqs);
    let planned: Vec<Result<SendPlan>> = reqs.iter().map(|r| plan(r, &ifaces, &resolved)).collect();
    let ok_plans: Vec<SendPlan> = planned
        .iter()
        .filter_map(|p| p.as_ref().ok().cloned())
        .collect();
    let mut executed = execute(&ok_plans).into_iter();
    let mut reports: Vec<WakeReport> = planned
        .iter()
        .zip(reqs)
        .map(|(p, r)| match p {
            Ok(_) => executed.next().expect("one report per plan"),
            Err(_) => WakeReport::no_destinations_for(r),
        })
        .collect();

    // Interfaces that vanished between enumeration and send: re-enumerate once.
    let retry: Vec<usize> = reports
        .iter()
        .enumerate()
        .filter(|(_, r)| r.sent_count() == 0 && r.skipped_count() > 0)
        .map(|(i, _)| i)
        .collect();
    if !retry.is_empty() {
        let ifaces = netif::list();
        let replans: Vec<(usize, Result<SendPlan>)> = retry
            .iter()
            .map(|&i| (i, plan(&reqs[i], &ifaces, &resolved)))
            .collect();
        let ok: Vec<SendPlan> = replans
            .iter()
            .filter_map(|(_, p)| p.as_ref().ok().cloned())
            .collect();
        let mut again = execute(&ok).into_iter();
        for (i, p) in replans {
            let r = &mut reports[i];
            r.reenumerated = true;
            match p {
                Ok(_) => {
                    let new = again.next().expect("one report per plan");
                    r.attempts.extend(new.attempts);
                    for n in new.notes {
                        if !r.notes.contains(&n) {
                            r.notes.push(n);
                        }
                    }
                }
                Err(_) => {
                    if !r.notes.contains(&PlanNote::NoDestinations) {
                        r.notes.push(PlanNote::NoDestinations);
                    }
                }
            }
        }
    }
    reports
}

/// Wakes one request. Errors: [`Error::NoDestinations`] when there is nothing to send to;
/// send failures are reported in the [`WakeReport`], not as errors. **Blocking** like
/// [`wake_many`].
pub fn wake(req: &WakeRequest) -> Result<WakeReport> {
    let r = wake_many(std::slice::from_ref(req))
        .pop()
        .expect("one report");
    if r.attempts.is_empty() && r.failures.is_empty() {
        return Err(Error::NoDestinations);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netif::NetInterface;

    fn eth() -> NetInterface {
        NetInterface::new(
            12,
            "{B}",
            "イーサネット",
            "Intel Ethernet",
            6,
            true,
            None,
            vec!["192.0.2.10/24".parse().unwrap()],
        )
    }

    fn wt0() -> NetInterface {
        NetInterface::new(
            7,
            "{A}",
            "wt0",
            "WireGuard Tunnel",
            53,
            true,
            None,
            vec!["100.64.0.5/10".parse().unwrap()],
        )
    }

    fn wifi() -> NetInterface {
        NetInterface::new(
            18,
            "{D}",
            "Wi-Fi",
            "Wi-Fi 6",
            71,
            true,
            None,
            vec!["198.51.100.20/24".parse().unwrap()],
        )
    }

    fn ptp() -> NetInterface {
        NetInterface::new(
            30,
            "{E}",
            "Ethernet P2P",
            "USB NIC",
            6,
            true,
            None,
            vec![
                "203.0.113.1/31".parse().unwrap(),
                "203.0.113.9/32".parse().unwrap(),
            ],
        )
    }

    fn req() -> WakeRequest {
        let mut r = WakeRequest::adhoc("00:11:22:33:44:55".parse().unwrap(), &Settings::default());
        r.label = "PC".into();
        r
    }

    fn dests(p: &SendPlan) -> Vec<String> {
        p.sends
            .iter()
            .map(|s| {
                let via = match s.via {
                    Via::Interface(a) => a.to_string(),
                    Via::Routed => "routed".to_string(),
                };
                format!("{via}->{}", s.dest)
            })
            .collect()
    }

    #[test]
    fn basic_plan_binds_per_interface() {
        let p = plan(&req(), &[wt0(), eth(), wifi()], &Resolved::new()).unwrap();
        assert_eq!(
            dests(&p),
            vec![
                "192.0.2.10->192.0.2.255:9",
                "192.0.2.10->255.255.255.255:9",
                "198.51.100.20->198.51.100.255:9",
                "198.51.100.20->255.255.255.255:9",
            ]
        );
        assert_eq!(p.packet_len, 102);
        assert_eq!(p.repeat, 3);
        assert_eq!(p.interval, Duration::from_millis(100));
        assert!(p.notes.is_empty());
    }

    #[test]
    fn limited_broadcast_target_expands_to_every_selected_interface() {
        let mut r = req();
        r.broadcast = false;
        r.limited_broadcast = false;
        r.targets = vec!["255.255.255.255:7".parse().unwrap()];
        let p = plan(&r, &[wt0(), eth(), wifi()], &Resolved::new()).unwrap();
        assert_eq!(
            dests(&p),
            vec![
                "192.0.2.10->255.255.255.255:7",
                "198.51.100.20->255.255.255.255:7",
            ]
        );
        assert!(p.sends.iter().all(|s| s.via != Via::Routed));
    }

    #[test]
    fn duplicates_are_removed() {
        let mut r = req();
        r.targets = vec![
            "255.255.255.255".parse().unwrap(),
            "192.0.2.255".parse().unwrap(),
        ];
        let p = plan(&r, &[eth()], &Resolved::new()).unwrap();
        assert_eq!(
            dests(&p),
            vec!["192.0.2.10->192.0.2.255:9", "192.0.2.10->255.255.255.255:9"]
        );
    }

    #[test]
    fn no_directed_broadcast_on_31_and_32() {
        let r = req();
        let p = plan(&r, &[ptp()], &Resolved::new()).unwrap();
        assert_eq!(
            dests(&p),
            vec![
                "203.0.113.1->255.255.255.255:9",
                "203.0.113.9->255.255.255.255:9"
            ]
        );
        assert_eq!(
            p.notes
                .iter()
                .filter(|n| matches!(n, PlanNote::NoDirectedBroadcast { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn targets_inside_selected_subnet_use_that_interface() {
        let mut r = req();
        r.broadcast = false;
        r.limited_broadcast = false;
        r.targets = vec![
            "192.0.2.50:40000".parse().unwrap(),
            "relay.lan".parse().unwrap(),
        ];
        let mut res = Resolved::new();
        res.insert("RELAY.lan", Ok(Ipv4Addr::new(198, 51, 100, 7)));
        let p = plan(&r, &[wt0(), eth(), wifi()], &res).unwrap();
        assert_eq!(
            dests(&p),
            vec![
                "192.0.2.10->192.0.2.50:40000",
                "198.51.100.20->198.51.100.7:9"
            ]
        );
    }

    #[test]
    fn routed_target_in_vpn_subnet_is_noted() {
        let mut r = req();
        r.broadcast = false;
        r.limited_broadcast = false;
        r.targets = vec![
            "100.64.1.1".parse().unwrap(),
            "10.0.20.255".parse().unwrap(),
        ];
        let p = plan(&r, &[wt0(), eth()], &Resolved::new()).unwrap();
        assert_eq!(
            dests(&p),
            vec!["routed->100.64.1.1:9", "routed->10.0.20.255:9"]
        );
        assert_eq!(
            p.notes,
            vec![PlanNote::ViaVirtual {
                target: "100.64.1.1".into(),
                interface: "wt0".into()
            }]
        );
    }

    /// A VPN that pushes a subnet route (10.0.20.0/24 via wt0) is not visible from wt0's own
    /// prefix; the routing table lookup in `Resolved` catches it.
    #[test]
    fn routed_target_through_vpn_route_is_noted() {
        let mut r = req();
        r.broadcast = false;
        r.limited_broadcast = false;
        r.targets = vec![
            "10.0.20.255".parse().unwrap(),
            "203.0.113.50:7".parse().unwrap(),
            "198.18.0.1".parse().unwrap(),
        ];
        let mut res = Resolved::new();
        res.insert_route(Ipv4Addr::new(10, 0, 20, 255), 7); // wt0
        res.insert_route(Ipv4Addr::new(203, 0, 113, 50), 12); // Ethernet (default route)
        let p = plan(&r, &[wt0(), eth()], &res).unwrap();
        assert_eq!(
            dests(&p),
            vec![
                "routed->10.0.20.255:9",
                "routed->203.0.113.50:7",
                "routed->198.18.0.1:9"
            ]
        );
        let egress: Vec<Option<&str>> = p
            .sends
            .iter()
            .map(|s| s.interface.as_ref().map(|i| i.name.as_str()))
            .collect();
        assert_eq!(egress, vec![Some("wt0"), Some("イーサネット"), None]);
        assert!(p.sends[0].interface.as_ref().unwrap().is_virtual);
        assert_eq!(
            p.notes,
            vec![PlanNote::ViaVirtual {
                target: "10.0.20.255".into(),
                interface: "wt0".into()
            }]
        );
        // A known route through a physical adapter beats the on-link heuristic.
        let mut r2 = r.clone();
        r2.targets = vec!["100.64.1.1".parse().unwrap()];
        let mut res2 = Resolved::new();
        res2.insert_route(Ipv4Addr::new(100, 64, 1, 1), 12);
        assert!(plan(&r2, &[wt0(), eth()], &res2).unwrap().notes.is_empty());
        // A selected (pinned) VPN adapter is intended: no note.
        r.filter.pinned = vec!["wt0".into(), "{B}".into()];
        assert!(plan(&r, &[wt0(), eth()], &res).unwrap().notes.is_empty());
    }

    #[test]
    fn port_zero_means_default_port() {
        let mut r = req();
        r.port = 0;
        r.limited_broadcast = false;
        r.targets = vec!["192.0.2.50".parse().unwrap()];
        let p = plan(&r, &[eth()], &Resolved::new()).unwrap();
        assert_eq!(
            dests(&p),
            vec!["192.0.2.10->192.0.2.255:9", "192.0.2.10->192.0.2.50:9"]
        );
        // Through for_host: a hand-edited `port = 0` on the host.
        let mut h = Host::new("PC", "02:00:00:00:00:01".parse().unwrap());
        h.port = Some(0);
        assert_eq!(WakeRequest::for_host(&h, &Settings::default()).port, 9);
    }

    #[test]
    fn parallel_map_keeps_order() {
        let items: Vec<u32> = (0..50).collect();
        let out = parallel_map(&items, 8, |i| {
            std::thread::sleep(Duration::from_millis(u64::from(50 - i) / 10));
            i * 2
        });
        assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
        assert!(parallel_map(&[] as &[u32], 4, |i| *i).is_empty());
    }

    /// resolve_names looks names up through parallel_map: slow lookups (an unresolvable
    /// single-label name costs about 2.7 s) overlap instead of adding up.
    #[test]
    fn parallel_map_overlaps_slow_items() {
        let items = [0u8; 8];
        let start = std::time::Instant::now();
        parallel_map(&items, MAX_PARALLEL_LOOKUPS, |_| {
            std::thread::sleep(Duration::from_millis(200))
        });
        let took = start.elapsed();
        // Sequential: 1.6 s.
        assert!(took < Duration::from_millis(800), "took {took:?}");
    }

    /// Every distinct name gets a result; literal targets get their egress interface from
    /// the routing table.
    #[test]
    fn resolve_names_fills_names_and_routes() {
        let names = [
            "wolm-missing-a.invalid",
            "wolm-missing-b.invalid",
            "wolm-missing-c.invalid",
            "wolm-missing-d.invalid",
        ];
        let mut reqs: Vec<WakeRequest> = names
            .iter()
            .map(|n| {
                let mut r = req();
                r.unicast = Some(n.parse().unwrap());
                r
            })
            .collect();
        reqs[0].targets = vec![
            "127.0.0.1:40009".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        ];
        let mut dup = req();
        dup.unicast = Some("WOLM-MISSING-A.invalid".parse().unwrap());
        reqs.push(dup);
        let res = resolve_names(&reqs);
        for n in names {
            assert!(matches!(res.get(n), Some(Err(_))), "{n}");
        }
        assert_eq!(
            res.map.len(),
            4,
            "case-insensitive duplicates are looked up once"
        );
        assert!(res.route(Ipv4Addr::LOCALHOST).is_some());
        assert_eq!(res.route(Ipv4Addr::BROADCAST), None);
    }

    #[test]
    fn pinned_vpn_interface_is_used() {
        let mut r = req();
        r.filter.pinned = vec!["wt0".into()];
        let p = plan(&r, &[wt0(), eth()], &Resolved::new()).unwrap();
        assert_eq!(
            dests(&p),
            vec![
                "100.64.0.5->100.127.255.255:9",
                "100.64.0.5->255.255.255.255:9"
            ]
        );
    }

    #[test]
    fn unicast_only_inside_selected_subnet() {
        let mut r = req();
        r.unicast = Some("192.0.2.77".parse().unwrap());
        let p = plan(&r, &[eth()], &Resolved::new()).unwrap();
        assert!(dests(&p).contains(&"192.0.2.10->192.0.2.77:9".to_string()));
        assert_eq!(
            p.sends
                .iter()
                .find(|s| s.kind == SendKind::Unicast)
                .unwrap()
                .dest,
            "192.0.2.77:9".parse().unwrap()
        );
        r.unicast = Some("203.0.113.5".parse().unwrap());
        let p = plan(&r, &[eth()], &Resolved::new()).unwrap();
        assert!(p.sends.iter().all(|s| s.kind != SendKind::Unicast));
        assert_eq!(
            p.notes,
            vec![PlanNote::AddressOffSubnet {
                address: "203.0.113.5".into()
            }]
        );
        r.unicast = Some("nas.lan".parse().unwrap());
        let p = plan(&r, &[eth()], &Resolved::new()).unwrap();
        assert!(matches!(p.notes[0], PlanNote::AddressUnresolved { .. }));
    }

    #[test]
    fn unresolved_target_is_a_failure_and_no_destinations_is_an_error() {
        let mut r = req();
        r.broadcast = false;
        r.limited_broadcast = false;
        r.targets = vec!["missing.example".parse().unwrap()];
        let mut res = Resolved::new();
        res.insert("missing.example", Err("No such host".into()));
        let p = plan(&r, &[eth()], &res).unwrap();
        assert!(p.sends.is_empty());
        assert_eq!(p.failures.len(), 1);
        r.targets.clear();
        assert!(matches!(
            plan(&r, &[eth()], &res),
            Err(Error::NoDestinations)
        ));
        // No interfaces at all and no targets.
        assert!(matches!(
            plan(&req(), &[wt0()], &res),
            Err(Error::NoDestinations)
        ));
    }

    #[test]
    fn for_host_uses_overrides() {
        let mut s = Settings::default();
        s.wake.repeat = 5;
        s.wake.interfaces = vec!["{A}".into()];
        let mut h = Host::new("Lab", "AA:BB:CC:DD:EE:FF".parse().unwrap());
        h.port = Some(7);
        h.broadcast = false;
        h.interfaces = vec!["{B}".into()];
        h.secureon = Some("01:02:03:04:05:06".parse().unwrap());
        let r = WakeRequest::for_host(&h, &s);
        assert_eq!(r.port, 7);
        assert!(!r.broadcast);
        assert_eq!(r.repeat, 5);
        assert_eq!(r.filter.pinned, vec!["{B}"]);
        let p = plan(&r, &[eth()], &Resolved::new()).unwrap();
        assert_eq!(p.packet_len, 108);
        assert_eq!(dests(&p), vec!["192.0.2.10->255.255.255.255:7"]);
    }

    #[test]
    fn outcome_rules() {
        let p = plan(&req(), &[eth()], &Resolved::new()).unwrap();
        let mut r = WakeReport::from_plan(&p);
        assert_eq!(r.outcome(), WakeOutcome::Failed);
        r.attempts[0].sent = 3;
        r.attempts[1].sent = 3;
        assert_eq!(r.outcome(), WakeOutcome::Ok);
        r.attempts[1].failed = 1;
        assert_eq!(r.outcome(), WakeOutcome::Partial);
        r.attempts[1].failed = 0;
        r.attempts[1].skipped = 3;
        assert_eq!(r.outcome(), WakeOutcome::Ok);
        r.failures.push(PlanFailure {
            target: "x".into(),
            error: "y".into(),
        });
        assert_eq!(r.outcome(), WakeOutcome::Partial);
    }

    #[test]
    fn vanished_codes() {
        assert!(vanished(&io::Error::from_raw_os_error(10049)));
        assert!(vanished(&io::Error::from_raw_os_error(10065)));
        assert!(!vanished(&io::Error::from_raw_os_error(10013)));
    }
}
