//! MAC address discovery for Wake-on-LAN: parse the network facts printed by the net script
//! and pick the physical NIC(s) behind the default route.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

use crate::boot::kv_map;
use crate::error::{Result, SshError};
use crate::scripts::marker_lines;

/// A 48-bit MAC address (`[0x00, 0x11, ...]`).
pub type Mac = [u8; 6];

/// `"AA:BB:CC:DD:EE:FF"`. Pure.
pub fn format_mac(mac: &Mac) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Kind of a candidate NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NicKind {
    /// Wired physical NIC (Linux: has `/sys/class/net/<if>/device`; FreeBSD: has a
    /// `dev.<driver>.<unit>.%parent`).
    Physical,
    /// Wireless NIC (WoL over Wi-Fi rarely works; ranked low).
    Wifi,
    /// Last resort: the default-route interface itself when no physical NIC could be
    /// identified (never a bridge, bond or VLAN).
    Other,
}

/// Wake-on-LAN state from `ethtool` (Linux, needs root) or `ifconfig -m` (FreeBSD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WolInfo {
    /// Supported modes, ethtool letters (e.g. `"pumbg"`; `"g"` = magic packet).
    pub supported: String,
    /// Enabled modes (e.g. `"g"`, or `"d"` = disabled).
    pub enabled: String,
}

impl WolInfo {
    /// The NIC supports magic-packet wake.
    pub fn supports_magic(&self) -> bool {
        self.supported.contains('g')
    }

    /// Magic-packet wake is currently enabled. When `false` although supported, WoL must be
    /// enabled on the host (and usually made persistent) before waking works.
    pub fn magic_enabled(&self) -> bool {
        self.enabled.contains('g')
    }
}

/// One NIC that may be the right MAC address for waking the host. Lists are sorted by
/// [`MacCandidate::score`], best first; equal top scores mean "let the user choose".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacCandidate {
    /// Interface name on the host (e.g. `"eno1"`, `"igb0"`).
    pub iface: String,
    /// The MAC to store for WoL: the permanent (burned-in) address when known, else the
    /// current one. Never a bridge's own address.
    pub mac: Mac,
    /// The address currently programmed on the NIC (differs from `mac` on bond/lagg members
    /// or when the MAC was changed); worth offering as an alternative when different.
    pub current_mac: Mac,
    /// Permanent address (`ethtool -P`, iproute2 `permaddr`, FreeBSD `hwaddr`), if known.
    pub permanent_mac: Option<Mac>,
    /// Wired, wireless or last-resort.
    pub kind: NicKind,
    /// The NIC carries the host's IPv4 default route (directly or below a bridge / bond /
    /// VLAN / OVS port).
    pub on_default_route: bool,
    /// The L3 interface holding the default route when different from `iface`
    /// (e.g. `"vmbr0"`, `"bond0.20"`, `"bridge0"`, `"ovs_eth0"`).
    pub via: Option<String>,
    /// Carrier / link is up.
    pub link_up: bool,
    /// WoL state (Linux: only when the login user is root; FreeBSD: always).
    pub wol: Option<WolInfo>,
    /// LAN IPv4 address and prefix length of the L3 interface (VPN 100.64.0.0/10,
    /// link-local and loopback excluded), e.g. to suggest a directed broadcast address.
    pub lan_ipv4: Option<(Ipv4Addr, u8)>,
    /// Ranking: +100 on the default route, +20 link up, -50 Wi-Fi, -30 last-resort,
    /// +5 permanent MAC equals current MAC (or unknown), +5 supports magic packet,
    /// +2 magic packet enabled.
    pub score: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IfKind {
    Phys,
    Wifi,
    Bridge,
    Bond,
    Vlan,
    Virtual,
}

#[derive(Debug, Clone)]
struct Iface {
    name: String,
    mac: Option<Mac>,
    kind: IfKind,
    link_up: bool,
    lower: Vec<String>,
    perm: Option<Mac>,
    wol: Option<WolInfo>,
    ipv4: Vec<(Ipv4Addr, u8)>,
}

impl Iface {
    fn is_leaf(&self) -> bool {
        matches!(self.kind, IfKind::Phys | IfKind::Wifi)
    }
}

#[derive(Debug, Default)]
pub(crate) struct NetFacts {
    uid: Option<u32>,
    routes: Vec<(String, u32)>,
    ifaces: Vec<Iface>,
}

impl NetFacts {
    #[cfg(test)]
    fn set_routes(&mut self, routes: &[&str]) {
        self.routes = routes.iter().map(|r| (r.to_string(), 0)).collect();
    }
}

/// Parse `aa:bb:cc:dd:ee:ff` (or `-` separated). Rejects all-zero and group (multicast /
/// broadcast) addresses.
pub(crate) fn parse_mac(s: &str) -> Option<Mac> {
    let mut out = [0u8; 6];
    let mut it = s.trim().split([':', '-']);
    for b in &mut out {
        let p = it.next()?;
        if p.len() != 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    if it.next().is_some() || out == [0; 6] || out[0] & 1 == 1 {
        return None;
    }
    Some(out)
}

/// `192.168.1.10/24` or FreeBSD `192.168.1.20/0xffffff00`.
fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, m) = s.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let prefix = match m.strip_prefix("0x").or_else(|| m.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?.count_ones() as u8,
        None => m.parse::<u8>().ok().filter(|p| *p <= 32)?,
    };
    Some((ip, prefix))
}

fn is_lan_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    let cgnat = o[0] == 100 && (64..128).contains(&o[1]); // 100.64.0.0/10: NetBird / Tailscale
    !(cgnat || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified())
}

/// Parse the net script output. Pure.
pub(crate) fn parse_net(stdout: &str) -> Result<NetFacts> {
    let mut f = NetFacts::default();
    let mut saw_header = false;
    let mut inet: Vec<(String, (Ipv4Addr, u8))> = Vec::new();
    for rest in marker_lines(stdout) {
        let mut w = rest.split_whitespace();
        match w.next() {
            Some("hdr") => {
                saw_header = true;
                f.uid = kv_map(rest).get("uid").and_then(|v| v.parse().ok());
            }
            Some("route") => {
                if let Some(i) = w.next() {
                    let metric = w.next().and_then(|m| m.parse().ok()).unwrap_or(0);
                    f.routes.push((i.to_string(), metric));
                }
            }
            Some("inet") => {
                if let (Some(i), Some(a)) = (w.next(), w.next())
                    && let Some(c) = parse_cidr(a)
                {
                    let name = i.split('@').next().unwrap_or(i).trim_end_matches(':');
                    inet.push((name.to_string(), c));
                }
            }
            Some("if") => {
                let Some(name) = w.next() else { continue };
                let kv = kv_map(rest);
                let g = |k: &str| kv.get(k).copied().filter(|v| !v.is_empty() && *v != "-");
                let kind = match g("kind") {
                    Some("phys") => IfKind::Phys,
                    Some("wifi") => IfKind::Wifi,
                    Some("bridge") => IfKind::Bridge,
                    Some("bond") => IfKind::Bond,
                    Some("vlan") => IfKind::Vlan,
                    _ => IfKind::Virtual,
                };
                let wol = g("wol").map(|w| {
                    let (s, e) = w.split_once('/').unwrap_or((w, ""));
                    WolInfo {
                        supported: s.to_string(),
                        enabled: e.to_string(),
                    }
                });
                f.ifaces.push(Iface {
                    name: name.to_string(),
                    mac: g("mac").and_then(parse_mac),
                    kind,
                    link_up: g("carrier") == Some("1")
                        || matches!(g("oper"), Some("up") | Some("active")),
                    lower: g("lower")
                        .map(|l| {
                            l.split(',')
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default(),
                    perm: g("perm").and_then(parse_mac),
                    wol,
                    ipv4: Vec::new(),
                });
            }
            _ => {}
        }
    }
    if !saw_header {
        return Err(SshError::UnexpectedOutput(crate::boot::no_marker_hint(
            "network", stdout,
        )));
    }
    for (name, c) in inet {
        if let Some(x) = f.ifaces.iter_mut().find(|x| x.name == name) {
            x.ipv4.push(c);
        }
    }
    f.routes.sort_by_key(|r| r.1);
    Ok(f)
}

/// Leaves (physical / Wi-Fi NICs) reachable from `start` over `lower` links, breadth-first.
fn walk_down<'a>(start: &'a Iface, by_name: &HashMap<&str, &'a Iface>) -> Vec<&'a Iface> {
    let mut out = Vec::new();
    let mut q = VecDeque::from([start]);
    let mut seen = HashSet::new();
    while let Some(i) = q.pop_front() {
        if !seen.insert(i.name.as_str()) {
            continue;
        }
        if i.is_leaf() {
            out.push(i);
            continue;
        }
        q.extend(
            i.lower
                .iter()
                .filter_map(|n| by_name.get(n.as_str()).copied()),
        );
    }
    out
}

/// Names that are never a physical NIC (last-resort filter).
const VIRTUAL_PREFIXES: &[&str] = &[
    "br",
    "vmbr",
    "virbr",
    "bridge",
    "ovs",
    "docker",
    "veth",
    "tap",
    "tun",
    "wg",
    "wt",
    "bond",
    "lagg",
    "vlan",
    "lo",
    "kube",
    "cni",
    "flannel",
    "podman",
    "lxc",
    "zt",
    "tailscale",
];

/// Rank the NICs of the host for WoL. Pure.
pub(crate) fn select(f: &NetFacts) -> Vec<MacCandidate> {
    let by_name: HashMap<&str, &Iface> = f.ifaces.iter().map(|i| (i.name.as_str(), i)).collect();

    // 1) Default-route L3 interfaces that have an Ethernet MAC (drops wt0/wg0/tun, lo).
    let l3: Vec<&Iface> = f
        .routes
        .iter()
        .filter_map(|(n, _)| by_name.get(n.as_str()).copied())
        .filter(|i| i.mac.is_some())
        .collect();

    let mut found: Vec<(&Iface, Option<&Iface>)> = Vec::new(); // (leaf, L3 interface)
    for d in &l3 {
        // 2) Walk lower_* links: vmbr0 -> eno1, bond0.20 -> bond0 -> eno3/eno4, bridge0 -> lagg0 -> igb0.
        let leaves = walk_down(d, &by_name);
        if !leaves.is_empty() {
            found.extend(leaves.into_iter().map(|l| (l, Some(*d))));
            continue;
        }
        // 3) No lower links (OVS internal ports such as Synology ovs_eth0 or a PVE OVSBridge).
        let same_mac = |i: &&Iface| i.mac == d.mac || (i.perm.is_some() && i.perm == d.mac);
        //    a) Synology names the OVS port after its NIC: ovs_eth0 -> eth0.
        if let Some(n) = d.name.strip_prefix("ovs_")
            && let Some(leaf) = by_name.get(n).filter(|i| i.is_leaf())
        {
            found.push((leaf, Some(*d)));
            continue;
        }
        //    b) The NICs attached to the OVS datapath hang below "ovs-system".
        let pool = match by_name.get("ovs-system") {
            Some(ovs) if d.lower.is_empty() => walk_down(ovs, &by_name),
            _ => Vec::new(),
        };
        let pool_same: Vec<&Iface> = pool.iter().copied().filter(same_mac).collect();
        if !pool_same.is_empty() {
            found.extend(pool_same.into_iter().map(|l| (l, Some(*d))));
            continue;
        }
        //    c) Any physical NIC carrying the same MAC as the L3 interface.
        let any_same: Vec<&Iface> = f
            .ifaces
            .iter()
            .filter(|i| i.is_leaf())
            .filter(same_mac)
            .collect();
        if !any_same.is_empty() {
            found.extend(any_same.into_iter().map(|l| (l, Some(*d))));
            continue;
        }
        //    d) All OVS ports (one of them is the uplink).
        found.extend(pool.into_iter().map(|l| (l, Some(*d))));
    }
    // 4) Nothing tied to a default route (VPN-only or IPv6-only default route): every NIC.
    if found.is_empty() {
        found = f
            .ifaces
            .iter()
            .filter(|i| i.is_leaf())
            .map(|i| (i, None))
            .collect();
    }

    let mut out: Vec<MacCandidate> = Vec::new();
    for (i, via) in found {
        if out.iter().any(|c| c.iface == i.name) {
            continue;
        }
        let Some(current) = i.mac.or(i.perm) else {
            continue;
        };
        let kind = if i.kind == IfKind::Wifi {
            NicKind::Wifi
        } else {
            NicKind::Physical
        };
        out.push(candidate(i, via, current, kind));
    }
    // 5) Last resort: a plain default-route interface (never a bridge / bond / VLAN / upper
    //    device) when no physical NIC was recognized at all.
    if out.is_empty() {
        for d in &l3 {
            let plain = d.kind == IfKind::Virtual
                && d.lower.is_empty()
                && !VIRTUAL_PREFIXES.iter().any(|p| d.name.starts_with(p));
            if plain
                && !out.iter().any(|c| c.iface == d.name)
                && let Some(current) = d.mac
            {
                out.push(candidate(d, Some(d), current, NicKind::Other));
            }
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.iface.cmp(&b.iface)));
    out
}

fn candidate(i: &Iface, via: Option<&Iface>, current: Mac, kind: NicKind) -> MacCandidate {
    let mac = i.perm.unwrap_or(current);
    let lan_ipv4 = via
        .map(|v| &v.ipv4)
        .filter(|v| v.iter().any(|(ip, _)| is_lan_ipv4(ip)))
        .unwrap_or(&i.ipv4)
        .iter()
        .copied()
        .find(|(ip, _)| is_lan_ipv4(ip));
    let mut score = 0;
    if via.is_some() {
        score += 100;
    }
    if i.link_up {
        score += 20;
    }
    match kind {
        NicKind::Wifi => score -= 50,
        NicKind::Other => score -= 30,
        NicKind::Physical => {}
    }
    if mac == current {
        score += 5;
    }
    if let Some(w) = &i.wol {
        if w.supports_magic() {
            score += 5;
        }
        if w.magic_enabled() {
            score += 2;
        }
    }
    MacCandidate {
        iface: i.name.clone(),
        mac,
        current_mac: current,
        permanent_mac: i.perm,
        kind,
        on_default_route: via.is_some(),
        via: via.filter(|v| v.name != i.name).map(|v| v.name.clone()),
        link_up: i.link_up,
        wol: i.wol.clone(),
        lan_ipv4,
        score,
    }
}

/// `true` when the facts came from a root login (WoL state available on Linux).
#[cfg(test)]
fn is_root(f: &NetFacts) -> bool {
    f.uid == Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(s: &str) -> Mac {
        parse_mac(s).unwrap()
    }

    fn fixture(name: &str) -> NetFacts {
        let text = match name {
            "debian" => include_str!("../tests/fixtures/net_debian.txt"),
            "proxmox" => include_str!("../tests/fixtures/net_proxmox.txt"),
            "bond_vlan" => include_str!("../tests/fixtures/net_bond_vlan.txt"),
            "synology" => include_str!("../tests/fixtures/net_synology_ovs.txt"),
            "truenas_scale" => include_str!("../tests/fixtures/net_truenas_scale.txt"),
            "freebsd_lagg" => include_str!("../tests/fixtures/net_freebsd_lagg.txt"),
            "wg_only" => include_str!("../tests/fixtures/net_wireguard_only.txt"),
            _ => unreachable!(),
        };
        parse_net(text).unwrap()
    }

    fn names(c: &[MacCandidate]) -> Vec<&str> {
        c.iter().map(|c| c.iface.as_str()).collect()
    }

    #[test]
    fn mac_parsing() {
        assert_eq!(
            parse_mac("aa:BB:cc:00:00:01"),
            Some([0xaa, 0xbb, 0xcc, 0, 0, 1])
        );
        assert_eq!(
            parse_mac("aa-bb-cc-00-00-01"),
            Some([0xaa, 0xbb, 0xcc, 0, 0, 1])
        );
        assert_eq!(parse_mac("00:00:00:00:00:00"), None);
        assert_eq!(parse_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(parse_mac("01:00:5e:00:00:01"), None);
        assert_eq!(parse_mac("aa:bb:cc:00:00"), None);
        assert_eq!(parse_mac("aa:bb:cc:00:00:01:02"), None);
        assert_eq!(parse_mac("-"), None);
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0xcc, 0, 0, 1]),
            "AA:BB:CC:00:00:01"
        );
        assert_eq!(
            parse_cidr("192.168.1.20/0xffffff00"),
            Some((Ipv4Addr::new(192, 168, 1, 20), 24))
        );
        assert_eq!(
            parse_cidr("10.0.0.1/8"),
            Some((Ipv4Addr::new(10, 0, 0, 1), 8))
        );
        assert_eq!(parse_cidr("10.0.0.1/33"), None);
    }

    #[test]
    fn debian_plain_nic_non_root() {
        let f = fixture("debian");
        assert!(!is_root(&f));
        let c = select(&f);
        assert_eq!(names(&c), ["enp1s0"], "{c:#?}");
        assert_eq!(c[0].mac, m("52:54:00:12:34:56"));
        assert!(c[0].on_default_route && c[0].via.is_none());
        assert_eq!(c[0].kind, NicKind::Physical);
        assert_eq!(c[0].wol, None, "non-root: no WoL state");
        assert_eq!(c[0].lan_ipv4, Some((Ipv4Addr::new(192, 168, 10, 21), 24)));
        assert_eq!(c[0].score, 125);
    }

    #[test]
    fn proxmox_bridge_resolves_to_physical_port() {
        let f = fixture("proxmox");
        assert!(is_root(&f));
        let c = select(&f);
        assert_eq!(names(&c), ["eno1"], "{c:#?}");
        assert_eq!(c[0].mac, m("aa:bb:cc:00:00:01"));
        assert_eq!(c[0].via.as_deref(), Some("vmbr0"));
        assert_eq!(
            c[0].lan_ipv4,
            Some((Ipv4Addr::new(192, 168, 1, 10), 24)),
            "wt0 100.105.x dropped"
        );
        let w = c[0].wol.as_ref().unwrap();
        assert!(w.supports_magic() && !w.magic_enabled());
        // Never the bridge's own MAC, even though vmbr0 has a different one here.
        assert!(c.iter().all(|c| c.mac != m("aa:bb:cc:00:00:99")));
    }

    #[test]
    fn bond_vlan_path_prefers_permanent_mac() {
        let c = select(&fixture("bond_vlan"));
        assert_eq!(names(&c), ["eno3", "eno4"], "{c:#?}");
        assert_eq!(c[0].mac, m("aa:bb:cc:00:00:03"));
        assert_eq!(c[0].via.as_deref(), Some("bond0.20"));
        assert_eq!(c[1].mac, m("aa:bb:cc:00:00:04"), "permanent MAC preferred");
        assert_eq!(c[1].current_mac, m("aa:bb:cc:00:00:03"));
        assert_eq!(c[1].permanent_mac, Some(m("aa:bb:cc:00:00:04")));
        assert!(c[0].score > c[1].score);
        assert_eq!(c[0].lan_ipv4, Some((Ipv4Addr::new(10, 0, 20, 2), 24)));
    }

    #[test]
    fn synology_ovs_port_maps_to_its_nic() {
        let c = select(&fixture("synology"));
        assert_eq!(c[0].iface, "eth0", "{c:#?}");
        assert_eq!(c[0].mac, m("00:11:32:aa:bb:01"));
        assert_eq!(c[0].via.as_deref(), Some("ovs_eth0"));
        assert!(c[0].on_default_route);
        assert_eq!(c[0].lan_ipv4, Some((Ipv4Addr::new(192, 168, 1, 30), 24)));
        assert_eq!(c.len(), 1, "{c:#?}");
    }

    #[test]
    fn synology_ovs_without_name_match_uses_ovs_system_and_mac() {
        let mut f = fixture("synology");
        for i in &mut f.ifaces {
            if i.name == "ovs_eth0" {
                i.name = "ovs_br0".into();
            }
        }
        f.set_routes(&["ovs_br0"]);
        let c = select(&f);
        assert_eq!(names(&c), ["eth0"], "{c:#?}");
        // Without a MAC match either, every NIC under ovs-system is offered.
        for i in &mut f.ifaces {
            if i.name == "ovs_br0" {
                i.mac = Some(m("02:11:32:ff:ff:ff"));
            }
        }
        let c = select(&f);
        assert_eq!(names(&c), ["eth0", "eth1"], "{c:#?}");
        assert!(c.iter().all(|c| c.on_default_route));
    }

    #[test]
    fn truenas_scale_bridge_non_root() {
        let c = select(&fixture("truenas_scale"));
        assert_eq!(names(&c), ["enp4s0"], "{c:#?}");
        assert_eq!(c[0].via.as_deref(), Some("br0"));
        assert_eq!(c[0].mac, m("3c:ec:ef:00:10:01"));
        assert_eq!(c[0].lan_ipv4, Some((Ipv4Addr::new(192, 168, 1, 40), 24)));
        assert_eq!(c[0].wol, None);
    }

    #[test]
    fn freebsd_bridge_over_lagg() {
        let c = select(&fixture("freebsd_lagg"));
        assert_eq!(names(&c), ["igb0", "igb1"], "{c:#?}");
        assert_eq!(c[0].mac, m("00:11:22:33:44:77"));
        assert_eq!(c[0].current_mac, m("00:11:22:33:44:66"));
        assert_eq!(c[0].via.as_deref(), Some("bridge0"));
        assert_eq!(c[0].lan_ipv4, Some((Ipv4Addr::new(192, 168, 1, 20), 24)));
        assert!(c[0].wol.as_ref().unwrap().magic_enabled());
        assert!(!c[1].link_up);
        assert!(
            c.iter().all(|c| c.mac != m("58:9c:fc:10:ff:e1")),
            "never the bridge MAC"
        );
    }

    #[test]
    fn wireguard_only_default_route_offers_all_nics() {
        let c = select(&fixture("wg_only"));
        assert_eq!(names(&c), ["eno1", "enp2s0", "wlp3s0"], "{c:#?}");
        assert!(c.iter().all(|c| !c.on_default_route && c.via.is_none()));
        assert_eq!(c[2].kind, NicKind::Wifi);
        assert_eq!(c[0].lan_ipv4, Some((Ipv4Addr::new(192, 168, 0, 7), 24)));
        assert_eq!(c[1].lan_ipv4, None);
    }

    #[test]
    fn last_resort_plain_interface() {
        let out = "WOLM1 hdr os=Linux uid=0\nWOLM1 route eth0 0\n\
                   WOLM1 if eth0 mac=02:00:00:00:00:10 type=1 kind=virtual aat=0 oper=up carrier=1 lower=- perm=- wol=-\n\
                   WOLM1 if br-lan mac=02:00:00:00:00:11 type=1 kind=bridge aat=0 oper=up carrier=1 lower=- perm=- wol=-\n\
                   WOLM1 inet eth0 192.168.5.5/24\nWOLM1 end\n";
        let c = select(&parse_net(out).unwrap());
        assert_eq!(names(&c), ["eth0"]);
        assert_eq!(c[0].kind, NicKind::Other);
        assert_eq!(c[0].score, 100 + 20 - 30 + 5);
        // A bridge as the only default-route interface is never offered.
        let out = out.replace("route eth0", "route br-lan");
        assert!(select(&parse_net(&out).unwrap()).is_empty());
    }

    #[test]
    fn missing_header_is_an_error() {
        assert!(matches!(
            parse_net("fish: Unknown command\n"),
            Err(SshError::UnexpectedOutput(_))
        ));
    }
}
