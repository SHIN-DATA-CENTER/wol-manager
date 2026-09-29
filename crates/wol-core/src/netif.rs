//! Network interface enumeration and selection for sending magic packets.
//!
//! Windows sends an unbound datagram to 255.255.255.255 only through the lowest-metric
//! interface, which is often a VPN tunnel (e.g. a WireGuard `wt0`). WoL Manager therefore
//! binds one socket per selected interface address. This module decides which addresses:
//!
//! * automatic mode: interfaces that are up, not loopback, have IPv4, and are Ethernet or
//!   Wi-Fi. VPN / tunnel / virtual adapters only with `include_virtual`.
//! * pinned mode (`interfaces = [...]` in settings or on the host): exactly the pinned
//!   interfaces, whatever their type (a pinned `wt0` is used).
//! * 169.254/16 addresses are used only when no selected interface has another address
//!   (pinned interfaces keep all addresses).
//! * /31 and /32 subnets get no directed broadcast.
//!
//! [`select`] and [`explain`] are pure and unit-tested with fixtures; [`list`] reads the OS.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::mac::MacAddr;
use crate::model::{Host, Settings, WakeSettings};
use crate::normalize;

/// An IPv4 address with its on-link prefix length.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Subnet {
    /// The interface's address.
    pub addr: Ipv4Addr,
    /// On-link prefix length (0..=32).
    pub prefix_len: u8,
}

impl Ipv4Subnet {
    /// Creates a subnet; `None` when `prefix_len > 32`.
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Option<Ipv4Subnet> {
        (prefix_len <= 32).then_some(Ipv4Subnet { addr, prefix_len })
    }

    fn mask_u32(&self) -> u32 {
        if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix_len))
        }
    }

    /// Netmask, e.g. `255.255.255.0` for /24.
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.mask_u32())
    }

    /// Network address.
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask_u32())
    }

    /// Directed broadcast address; `None` for /31 and /32 (point-to-point), where none exists.
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        (self.prefix_len <= 30).then(|| Ipv4Addr::from(u32::from(self.addr) | !self.mask_u32()))
    }

    /// `true` when `ip` is inside this subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask_u32() == u32::from(self.addr) & self.mask_u32()
    }

    /// `true` for 169.254.0.0/16 (APIPA).
    pub fn is_link_local(&self) -> bool {
        self.addr.is_link_local()
    }
}

impl fmt::Display for Ipv4Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl fmt::Debug for Ipv4Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ipv4Subnet({self})")
    }
}

impl FromStr for Ipv4Subnet {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (a, p) = s
            .split_once('/')
            .ok_or_else(|| format!("expected a.b.c.d/len, got {s:?}"))?;
        let addr: Ipv4Addr = a.trim().parse().map_err(|e| format!("{e}"))?;
        let len: u8 = p.trim().parse().map_err(|e| format!("{e}"))?;
        Ipv4Subnet::new(addr, len).ok_or_else(|| "prefix length > 32".to_owned())
    }
}

impl Serialize for Ipv4Subnet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ipv4Subnet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Interface category derived from the IANA ifType (and the description for VPN adapters
/// that pretend to be Ethernet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IfKind {
    /// Wired Ethernet (ifType 6, 62, 69, 117), including Hyper-V vEthernet.
    Ethernet,
    /// Wi-Fi (ifType 71).
    Wireless,
    /// Loopback (ifType 24).
    Loopback,
    /// Tunnel (ifType 131).
    Tunnel,
    /// PPP / SLIP (ifType 23, 28), e.g. dial-up style VPNs.
    Ppp,
    /// Proprietary virtual (ifType 53), e.g. WireGuard, Wintun, Tailscale.
    Virtual,
    /// Anything else (WWAN, ATM...). Used only when pinned.
    Other,
}

/// Description / name fragments of VPN adapters that report an Ethernet ifType.
const VPN_HINTS: &[&str] = &[
    "wireguard",
    "wintun",
    "tap-windows",
    "tap-win32",
    "openvpn",
    "zerotier",
    "tailscale",
    "nordlynx",
    "netbird",
    "anyconnect",
    "fortinet",
    "forticlient",
    "globalprotect",
    "pangp",
    "juniper",
    "pulse secure",
    "sonicwall",
    "hamachi",
    "radmin vpn",
    "softether",
    "vpn",
];

/// Classifies an interface: returns its kind and whether it is a VPN / tunnel / virtual
/// adapter that is skipped unless `include_virtual` is set.
pub fn classify(if_type: u32, description: &str, friendly_name: &str) -> (IfKind, bool) {
    let kind = match if_type {
        6 | 26 | 62 | 69 | 117 => IfKind::Ethernet,
        71 => IfKind::Wireless,
        24 => IfKind::Loopback,
        131 => IfKind::Tunnel,
        23 | 28 => IfKind::Ppp,
        53 => IfKind::Virtual,
        _ => IfKind::Other,
    };
    let text = format!("{description} {friendly_name}").to_lowercase();
    let vpn_like = VPN_HINTS.iter().any(|h| text.contains(h));
    let is_virtual = matches!(kind, IfKind::Tunnel | IfKind::Ppp | IfKind::Virtual) || vpn_like;
    (kind, is_virtual)
}

/// One network adapter as seen by WoL Manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetInterface {
    /// Interface index (changes across reboots; do not store).
    pub index: u32,
    /// Adapter GUID with braces, e.g. `{4F2A...}`. This is what settings should pin.
    pub guid: String,
    /// Friendly name shown by Windows (may be Japanese, e.g. `イーサネット`).
    pub friendly_name: String,
    /// Driver description.
    pub description: String,
    /// Raw IANA ifType.
    pub if_type: u32,
    /// Category.
    pub kind: IfKind,
    /// VPN / tunnel / virtual adapter (skipped unless `include_virtual` or pinned).
    pub is_virtual: bool,
    /// Operational status is Up.
    pub oper_up: bool,
    /// Hardware address, when the adapter has a 6-byte one.
    #[serde(default)]
    pub mac: Option<MacAddr>,
    /// IPv4 addresses with prefix lengths.
    #[serde(default)]
    pub ipv4: Vec<Ipv4Subnet>,
}

impl NetInterface {
    /// Builds an interface from raw values, classifying it with [`classify`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: u32,
        guid: impl Into<String>,
        friendly_name: impl Into<String>,
        description: impl Into<String>,
        if_type: u32,
        oper_up: bool,
        mac: Option<MacAddr>,
        ipv4: Vec<Ipv4Subnet>,
    ) -> NetInterface {
        let friendly_name = friendly_name.into();
        let description = description.into();
        let (kind, is_virtual) = classify(if_type, &description, &friendly_name);
        NetInterface {
            index,
            guid: guid.into(),
            friendly_name,
            description,
            if_type,
            kind,
            is_virtual,
            oper_up,
            mac,
            ipv4,
        }
    }

    /// `true` for the loopback pseudo-interface.
    pub fn is_loopback(&self) -> bool {
        self.kind == IfKind::Loopback
    }

    /// Friendly name, or the description / GUID when it is empty.
    pub fn display_name(&self) -> &str {
        if !self.friendly_name.trim().is_empty() {
            &self.friendly_name
        } else if !self.description.trim().is_empty() {
            &self.description
        } else {
            &self.guid
        }
    }

    /// `true` when `pin` designates this interface: GUID (braces optional,
    /// case-insensitive), friendly name, description, decimal index, or one of its IPv4
    /// addresses.
    pub fn matches_pin(&self, pin: &str) -> bool {
        let raw = pin.trim();
        if raw.is_empty() {
            return false;
        }
        // Names are compared as typed (width-folded); `ー` must stay a kana here.
        let key = normalize::name_key(raw);
        if normalize::name_key(&self.friendly_name) == key
            || normalize::name_key(&self.description) == key
        {
            return true;
        }
        let tech = normalize::normalize_input(raw);
        let pin = tech.trim();
        let strip = |s: &str| {
            s.trim()
                .trim_start_matches('{')
                .trim_end_matches('}')
                .to_ascii_lowercase()
        };
        if !self.guid.is_empty() && strip(&self.guid) == strip(pin) {
            return true;
        }
        if pin.bytes().all(|b| b.is_ascii_digit()) {
            return pin.parse::<u32>().ok() == Some(self.index);
        }
        if let Ok(ip) = pin.parse::<Ipv4Addr>() {
            return self.ipv4.iter().any(|s| s.addr == ip);
        }
        false
    }
}

/// Enumerates adapters through `GetAdaptersAddresses` (netdev without its gateway probing).
///
/// Fast (a few ms), does not touch the network. Returns an empty list if the OS call fails.
pub fn list() -> Vec<NetInterface> {
    netdev::get_interfaces()
        .into_iter()
        .map(|i| {
            let ipv4 = i
                .ipv4
                .iter()
                .filter_map(|n| Ipv4Subnet::new(n.addr(), n.prefix_len()))
                .collect();
            NetInterface::new(
                i.index,
                i.name.clone(),
                i.friendly_name.clone().unwrap_or_default(),
                i.description.clone().unwrap_or_default(),
                i.if_type.value(),
                i.is_oper_up(),
                i.mac_addr
                    .map(|m| MacAddr(m.octets()))
                    .filter(|m| !m.is_zero()),
                ipv4,
            )
        })
        .collect()
}

/// Index of the interface the IPv4 routing table picks for `dest` (`GetBestInterface`), i.e.
/// where an unbound datagram to `dest` leaves; compare with [`NetInterface::index`]. `None`
/// when there is no route or the call fails. Fast (a routing table lookup, no traffic).
pub fn best_interface(dest: Ipv4Addr) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
    let mut index = 0u32;
    // SAFETY: plain FFI call; the address is passed by value (network order in memory, as
    // IPAddr expects) and `index` is a valid, writable u32.
    let rc = unsafe { GetBestInterface(u32::from_ne_bytes(dest.octets()), &mut index) };
    (rc == 0).then_some(index)
}

/// Which interfaces to use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceFilter {
    /// Also use VPN / tunnel / virtual adapters in automatic mode.
    pub include_virtual: bool,
    /// Pinned interfaces (GUID, friendly name, index or IPv4). Non-empty = only these.
    pub pinned: Vec<String>,
}

impl InterfaceFilter {
    /// Filter from `[settings.wake]`.
    pub fn from_settings(w: &WakeSettings) -> InterfaceFilter {
        InterfaceFilter {
            include_virtual: w.include_virtual,
            pinned: w.interfaces.clone(),
        }
    }

    /// Filter for a host: the host's pins replace the settings' pins when present.
    pub fn for_host(host: &Host, settings: &Settings) -> InterfaceFilter {
        let mut f = Self::from_settings(&settings.wake);
        if !host.interfaces.is_empty() {
            f.pinned = host.interfaces.clone();
        }
        f
    }
}

/// Why an interface is (not) used. Shown by `wolm interfaces`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Used: selected automatically (Ethernet / Wi-Fi).
    Auto,
    /// Used: virtual adapter included because `include_virtual` is on.
    VirtualIncluded,
    /// Used: pinned in the settings or on the host.
    Pinned,
    /// Not used: operational status is not Up.
    Down,
    /// Not used: loopback.
    Loopback,
    /// Not used: no IPv4 address.
    NoIpv4,
    /// Not used: VPN / tunnel / virtual adapter (enable `include_virtual` or pin it).
    Virtual,
    /// Not used: unsupported adapter type (pin it to use it anyway).
    UnsupportedType,
    /// Not used: other interfaces are pinned.
    NotPinned,
    /// Not used: only a 169.254/16 address while other interfaces have real addresses.
    LinkLocalOnly,
}

impl Reason {
    /// `true` for the "used" reasons.
    pub fn is_used(self) -> bool {
        matches!(
            self,
            Reason::Auto | Reason::VirtualIncluded | Reason::Pinned
        )
    }
}

/// Per-address remark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddrNote {
    /// 169.254/16 address skipped because real addresses exist.
    LinkLocalSkipped,
    /// /31 or /32: no directed broadcast is sent.
    NoDirectedBroadcast,
}

/// Verdict for one address of an interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddrVerdict {
    /// The address and prefix.
    pub subnet: Ipv4Subnet,
    /// Whether packets are sent from this address.
    pub used: bool,
    /// Directed broadcast address (None for /31, /32).
    pub broadcast: Option<Ipv4Addr>,
    /// Remark, if any.
    pub note: Option<AddrNote>,
}

/// Verdict for one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Explained {
    /// The interface.
    pub interface: NetInterface,
    /// Whether any of its addresses is used.
    pub used: bool,
    /// Why.
    pub reason: Reason,
    /// Per-address verdicts.
    pub addresses: Vec<AddrVerdict>,
}

/// A selected source address (one socket is bound to `subnet.addr`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Selected {
    /// Interface index.
    pub index: u32,
    /// Interface GUID.
    pub guid: String,
    /// Display name of the interface.
    pub name: String,
    /// Source address and prefix.
    pub subnet: Ipv4Subnet,
    /// The interface is a VPN / tunnel / virtual adapter.
    pub is_virtual: bool,
    /// Selected because it is pinned.
    pub pinned: bool,
}

/// Explains, for every interface, whether and why it is used. Pure.
pub fn explain(ifaces: &[NetInterface], filter: &InterfaceFilter) -> Vec<Explained> {
    let pins: Vec<&str> = filter
        .pinned
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let pinned_mode = !pins.is_empty();

    let mut out: Vec<Explained> = ifaces
        .iter()
        .map(|i| {
            let reason = if pinned_mode {
                if !pins.iter().any(|p| i.matches_pin(p)) {
                    Reason::NotPinned
                } else if !i.oper_up {
                    Reason::Down
                } else if i.ipv4.is_empty() {
                    Reason::NoIpv4
                } else {
                    Reason::Pinned
                }
            } else if i.kind == IfKind::Loopback {
                Reason::Loopback
            } else if !i.oper_up {
                Reason::Down
            } else if i.ipv4.is_empty() {
                Reason::NoIpv4
            } else if i.kind == IfKind::Other {
                Reason::UnsupportedType
            } else if i.is_virtual {
                if filter.include_virtual {
                    Reason::VirtualIncluded
                } else {
                    Reason::Virtual
                }
            } else {
                Reason::Auto
            };
            let used = reason.is_used();
            let addresses = i
                .ipv4
                .iter()
                .map(|s| AddrVerdict {
                    subnet: *s,
                    used,
                    broadcast: s.broadcast(),
                    note: s
                        .broadcast()
                        .is_none()
                        .then_some(AddrNote::NoDirectedBroadcast),
                })
                .collect();
            Explained {
                interface: i.clone(),
                used,
                reason,
                addresses,
            }
        })
        .collect();

    // 169.254/16 only when nothing better exists (pinned interfaces keep everything).
    let has_real = out
        .iter()
        .filter(|e| e.used)
        .flat_map(|e| &e.addresses)
        .any(|a| !a.subnet.is_link_local());
    if has_real {
        for e in out
            .iter_mut()
            .filter(|e| e.used && e.reason != Reason::Pinned)
        {
            for a in e.addresses.iter_mut().filter(|a| a.subnet.is_link_local()) {
                a.used = false;
                a.note = Some(AddrNote::LinkLocalSkipped);
            }
            if !e.addresses.iter().any(|a| a.used) {
                e.used = false;
                e.reason = Reason::LinkLocalOnly;
            }
        }
    }
    out
}

/// Selected source addresses, in interface order. Pure.
pub fn select(ifaces: &[NetInterface], filter: &InterfaceFilter) -> Vec<Selected> {
    explain(ifaces, filter)
        .into_iter()
        .filter(|e| e.used)
        .flat_map(|e| {
            let i = e.interface;
            let pinned = e.reason == Reason::Pinned;
            e.addresses
                .into_iter()
                .filter(|a| a.used)
                .map(move |a| Selected {
                    index: i.index,
                    guid: i.guid.clone(),
                    name: i.display_name().to_owned(),
                    subnet: a.subnet,
                    is_virtual: i.is_virtual,
                    pinned,
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anonymized copy of the development machine: Netbird's WireGuard `wt0` (ifType 53,
    /// interface metric 5) routes 255.255.255.255 before the Ethernet LAN (metric 20).
    const FIXTURE: &str = include_str!("../tests/fixtures/interfaces-wt0-low-metric.toml");

    #[derive(Deserialize)]
    struct Fixture {
        interface: Vec<RawIf>,
    }

    #[derive(Deserialize)]
    struct RawIf {
        index: u32,
        guid: String,
        friendly_name: String,
        description: String,
        if_type: u32,
        oper_up: bool,
        #[serde(default)]
        mac: Option<MacAddr>,
        #[serde(default)]
        ipv4: Vec<Ipv4Subnet>,
    }

    fn fixture() -> Vec<NetInterface> {
        let f: Fixture = toml::from_str(FIXTURE).unwrap();
        f.interface
            .into_iter()
            .map(|r| {
                NetInterface::new(
                    r.index,
                    r.guid,
                    r.friendly_name,
                    r.description,
                    r.if_type,
                    r.oper_up,
                    r.mac,
                    r.ipv4,
                )
            })
            .collect()
    }

    fn names(sel: &[Selected]) -> Vec<String> {
        sel.iter()
            .map(|s| format!("{}={}", s.name, s.subnet))
            .collect()
    }

    #[test]
    fn subnet_math() {
        let s: Ipv4Subnet = "192.0.2.10/24".parse().unwrap();
        assert_eq!(s.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(s.network(), Ipv4Addr::new(192, 0, 2, 0));
        assert_eq!(s.broadcast(), Some(Ipv4Addr::new(192, 0, 2, 255)));
        assert!(s.contains(Ipv4Addr::new(192, 0, 2, 200)));
        assert!(!s.contains(Ipv4Addr::new(192, 0, 3, 1)));
        let t: Ipv4Subnet = "100.64.0.5/10".parse().unwrap();
        assert_eq!(t.broadcast(), Some(Ipv4Addr::new(100, 127, 255, 255)));
        let p31: Ipv4Subnet = "10.0.0.0/31".parse().unwrap();
        assert_eq!(p31.broadcast(), None);
        let p32: Ipv4Subnet = "10.0.0.1/32".parse().unwrap();
        assert_eq!(p32.broadcast(), None);
        assert!(p32.contains(Ipv4Addr::new(10, 0, 0, 1)));
        let p30: Ipv4Subnet = "10.0.0.1/30".parse().unwrap();
        assert_eq!(p30.broadcast(), Some(Ipv4Addr::new(10, 0, 0, 3)));
        let all: Ipv4Subnet = "10.0.0.1/0".parse().unwrap();
        assert_eq!(all.broadcast(), Some(Ipv4Addr::BROADCAST));
        assert!(Ipv4Subnet::new(Ipv4Addr::LOCALHOST, 33).is_none());
    }

    #[test]
    fn classification() {
        assert_eq!(
            classify(6, "Intel(R) Ethernet", "イーサネット"),
            (IfKind::Ethernet, false)
        );
        assert_eq!(classify(71, "Wi-Fi 6", "Wi-Fi"), (IfKind::Wireless, false));
        assert_eq!(
            classify(53, "WireGuard Tunnel", "wt0"),
            (IfKind::Virtual, true)
        );
        assert_eq!(classify(131, "Teredo", "x"), (IfKind::Tunnel, true));
        assert_eq!(
            classify(6, "TAP-Windows Adapter V9", "OpenVPN"),
            (IfKind::Ethernet, true)
        );
        assert_eq!(
            classify(
                6,
                "Hyper-V Virtual Ethernet Adapter",
                "vEthernet (External)"
            ),
            (IfKind::Ethernet, false)
        );
        assert_eq!(classify(243, "Mobile", "Cellular"), (IfKind::Other, false));
    }

    #[test]
    fn wireguard_with_lower_metric_is_not_selected_by_default() {
        let ifs = fixture();
        let sel = select(&ifs, &InterfaceFilter::default());
        assert_eq!(names(&sel), vec!["イーサネット=192.0.2.10/24"]);
        assert!(sel.iter().all(|s| !s.is_virtual && !s.pinned));
        let ex = explain(&ifs, &InterfaceFilter::default());
        let reason = |n: &str| {
            ex.iter()
                .find(|e| e.interface.friendly_name == n)
                .map(|e| e.reason)
                .unwrap()
        };
        assert_eq!(reason("wt0"), Reason::Virtual);
        assert_eq!(reason("イーサネット"), Reason::Auto);
        assert_eq!(reason("Loopback Pseudo-Interface 1"), Reason::Loopback);
        assert_eq!(reason("Bluetooth ネットワーク接続"), Reason::Down);
        assert_eq!(reason("Wi-Fi"), Reason::NoIpv4);
        assert_eq!(reason("OpenVPN TAP"), Reason::Virtual);
        // Only 169.254.x while Ethernet has a real address.
        assert_eq!(reason("vEthernet (Default Switch)"), Reason::LinkLocalOnly);
    }

    #[test]
    fn include_virtual_adds_wt0() {
        let ifs = fixture();
        let f = InterfaceFilter {
            include_virtual: true,
            pinned: vec![],
        };
        let sel = select(&ifs, &f);
        assert_eq!(
            names(&sel),
            vec![
                "wt0=100.64.0.5/10",
                "イーサネット=192.0.2.10/24",
                "OpenVPN TAP=10.8.0.2/24"
            ]
        );
    }

    #[test]
    fn pinned_interface_is_used_even_if_virtual() {
        let ifs = fixture();
        for pin in [
            "{00000000-0000-0000-0000-00000000000A}",
            "00000000-0000-0000-0000-00000000000a",
            "wt0",
            "7",
            "100.64.0.5",
        ] {
            let f = InterfaceFilter {
                include_virtual: false,
                pinned: vec![pin.to_owned()],
            };
            let sel = select(&ifs, &f);
            assert_eq!(names(&sel), vec!["wt0=100.64.0.5/10"], "pin {pin}");
            assert!(sel[0].pinned);
        }
        let f = InterfaceFilter {
            include_virtual: false,
            pinned: vec!["ｲｰｻﾈｯﾄ".into(), "nothing".into()],
        };
        // Half-width katakana does not fold to full width; no match -> nothing selected.
        assert!(select(&ifs, &f).is_empty());
        let f = InterfaceFilter {
            include_virtual: false,
            pinned: vec!["イーサネット".into()],
        };
        assert_eq!(names(&select(&ifs, &f)), vec!["イーサネット=192.0.2.10/24"]);
    }

    #[test]
    fn link_local_used_when_nothing_else() {
        let ifs = vec![NetInterface::new(
            3,
            "{G}",
            "Ethernet 2",
            "Realtek",
            6,
            true,
            None,
            vec!["169.254.10.20/16".parse().unwrap()],
        )];
        let sel = select(&ifs, &InterfaceFilter::default());
        assert_eq!(sel.len(), 1);
    }

    #[test]
    fn host_pins_override_settings() {
        let mut s = Settings::default();
        s.wake.interfaces = vec!["{A}".into()];
        let mut h = Host::default();
        assert_eq!(InterfaceFilter::for_host(&h, &s).pinned, vec!["{A}"]);
        h.interfaces = vec!["{B}".into()];
        assert_eq!(InterfaceFilter::for_host(&h, &s).pinned, vec!["{B}"]);
    }

    #[test]
    fn list_does_not_panic() {
        // Real enumeration: must not panic; loopback is normally present.
        let l = list();
        for i in &l {
            let _ = i.display_name();
        }
    }

    #[test]
    fn best_interface_of_loopback_is_an_enumerated_interface() {
        let idx = best_interface(Ipv4Addr::LOCALHOST).expect("route to 127.0.0.1");
        assert!(
            list().iter().any(|i| i.index == idx),
            "index {idx} not in list()"
        );
    }
}
