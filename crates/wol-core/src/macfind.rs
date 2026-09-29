//! Smart "MAC from IP" (v0.2.0): ARP on the local LAN, else the host's remote management.
//!
//! ARP ([`crate::arp`]) only works on-link. A host reached through a VPN (NetBird / WireGuard
//! `wt0`, an L3 tunnel without MACs) or a router has no ARP entry here, so [`find_mac`]:
//! 1. address inside the subnet of a selected, non-virtual local interface → ARP (as before;
//!    when nobody answers and remote management is set up, that is tried next);
//! 2. otherwise, when the host has remote management → the host's own physical NICs
//!    ([`crate::remote::RemoteClient::mac_candidates`]: WMI on Windows, a script over SSH);
//! 3. otherwise → [`Error::MacNeedsRemote`] (with `via_vpn` when the address is in
//!    100.64.0.0/10 or routed through a VPN / virtual adapter), whose message explains that
//!    setting up remote management lets the app read the physical NIC's MAC.
//!
//! `arp` itself stays local-only (`wolm arp`).

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::addr::HostAddr;
use crate::arp;
use crate::error::{Error, Field, FieldIssue, Result};
use crate::mac::MacAddr;
use crate::model::{Host, Settings};
use crate::netif::{self, InterfaceFilter, NetInterface, Selected};
use crate::remote::{self, MacCandidate, RemoteClient};

/// What to look up.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacQuery<'a> {
    /// Address to look up (the editor's address field, `wolm mac <IP>`). `None` = the host's
    /// address, else its management address.
    pub address: Option<&'a HostAddr>,
    /// The host (possibly built from an editor draft) whose remote management and adapter
    /// pins may be used.
    pub host: Option<&'a Host>,
}

/// Result of [`find_mac`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum MacFound {
    /// ARP answered on the local LAN.
    Arp {
        /// The address.
        ip: Ipv4Addr,
        /// Its MAC.
        mac: MacAddr,
    },
    /// The host reported its NICs (best first, never empty).
    Remote {
        /// Candidates.
        candidates: Vec<MacCandidate>,
    },
}

impl MacFound {
    /// The MAC when there is exactly one sensible answer (ARP, or a remote list whose best
    /// score is unique and which is a good WoL target: wired, link up, WoL not disabled, see
    /// [`remote::unique_best`]). `None` = show a picker with [`MacFound::candidates`] (with the
    /// Wi-Fi / link-down / [`crate::i18n::Msg::WolDisabledOn`] notes).
    pub fn unique(&self) -> Option<MacAddr> {
        match self {
            MacFound::Arp { mac, .. } => Some(*mac),
            MacFound::Remote { candidates } => remote::unique_best(candidates).map(|c| c.mac),
        }
    }

    /// The remote candidates (empty for ARP).
    pub fn candidates(&self) -> &[MacCandidate] {
        match self {
            MacFound::Arp { .. } => &[],
            MacFound::Remote { candidates } => candidates,
        }
    }
}

/// Which way [`find_mac`] goes for an address (pure decision).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacRoute {
    /// On a local selected non-virtual subnet: ARP from this interface address.
    Arp(Selected),
    /// Off-link, remote management configured.
    Remote,
    /// Off-link and no remote management.
    NeedsRemote {
        /// VPN / tunnel address (see [`is_vpn_address`]).
        via_vpn: bool,
    },
}

/// `true` for the shared / CGNAT range 100.64.0.0/10 that NetBird, Tailscale and other VPNs
/// use.
pub fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// `true` when `ip` is a VPN address: in 100.64.0.0/10, inside the subnet of a virtual /
/// tunnel adapter, or routed through one (`egress` = [`netif::best_interface`]). Pure.
pub fn is_vpn_address(ip: Ipv4Addr, ifaces: &[NetInterface], egress: Option<u32>) -> bool {
    is_cgnat(ip)
        || egress
            .and_then(|i| ifaces.iter().find(|n| n.index == i))
            .is_some_and(|n| n.is_virtual)
        || ifaces
            .iter()
            .any(|n| n.is_virtual && n.ipv4.iter().any(|s| s.contains(ip)))
}

/// Decides how to find the MAC of `ip` (pure; see the module docs).
pub fn route(
    ip: Ipv4Addr,
    ifaces: &[NetInterface],
    filter: &InterfaceFilter,
    egress: Option<u32>,
    has_remote: bool,
) -> MacRoute {
    if let Some(sel) = arp::local_source_for(ip, ifaces, filter) {
        MacRoute::Arp(sel)
    } else if has_remote {
        MacRoute::Remote
    } else {
        MacRoute::NeedsRemote {
            via_vpn: is_vpn_address(ip, ifaces, egress),
        }
    }
}

/// OS access used by [`find_mac_with`] (a test seam).
pub trait MacEnv {
    /// Local interfaces ([`netif::list`]).
    fn interfaces(&self) -> Vec<NetInterface> {
        netif::list()
    }
    /// Egress interface for `ip` ([`netif::best_interface`]).
    fn best_interface(&self, ip: Ipv4Addr) -> Option<u32> {
        netif::best_interface(ip)
    }
    /// Name resolution. **Blocking**.
    fn resolve(&self, addr: &HostAddr) -> Result<Ipv4Addr> {
        addr.resolve_v4()
    }
    /// ARP. **Blocking** (≈ 3 s without an answer).
    fn arp(
        &self,
        ip: Ipv4Addr,
        ifaces: &[NetInterface],
        filter: &InterfaceFilter,
    ) -> Result<MacAddr> {
        arp::mac_from_ip_with(ip, ifaces, filter)
    }
}

/// The real OS.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemMacEnv;

impl MacEnv for SystemMacEnv {}

/// Finds the MAC for `query` (see the module docs), with the real OS and backends.
///
/// **Blocking**: DNS for names, ARP (≈ 3 s without an answer) or a remote query (see
/// [`crate::remote`]: typically 1–2 s, tens of seconds when a firewall drops WMI).
///
/// Errors: [`Error::MacNeedsRemote`], [`Error::ArpNoReply`], [`Error::Resolve`],
/// [`Error::InvalidValue`] (no address and no remote management), and the remote errors
/// ([`Error::Remote`], [`Error::UnknownHostKey`] → offer "trust" and retry, ...).
pub fn find_mac(query: &MacQuery<'_>, settings: &Settings) -> Result<MacFound> {
    find_mac_with(query, settings, &RemoteClient::system(), &SystemMacEnv)
}

/// [`find_mac`] with an explicit remote client (e.g. secret overrides for an editor draft)
/// and OS access.
pub fn find_mac_with(
    query: &MacQuery<'_>,
    settings: &Settings,
    client: &RemoteClient,
    env: &dyn MacEnv,
) -> Result<MacFound> {
    let host = query.host;
    let managed = host.filter(|h| h.remote.is_some());
    let via_remote = |h: &Host| {
        client
            .mac_candidates(h, settings)
            .map(|candidates| MacFound::Remote { candidates })
    };
    let addr = query
        .address
        .or_else(|| host.and_then(|h| h.address.as_ref()))
        .or_else(|| host.and_then(Host::management_address));
    let Some(addr) = addr else {
        return match managed {
            Some(h) => via_remote(h),
            None => Err(Error::invalid(Field::Address, FieldIssue::Required, "")),
        };
    };
    let ip = match env.resolve(addr) {
        Ok(ip) => ip,
        Err(e) => {
            return match managed {
                Some(h) => via_remote(h),
                None => Err(e),
            };
        }
    };
    let ifaces = env.interfaces();
    let filter = match host {
        Some(h) => InterfaceFilter::for_host(h, settings),
        None => InterfaceFilter::from_settings(&settings.wake),
    };
    match route(
        ip,
        &ifaces,
        &filter,
        env.best_interface(ip),
        managed.is_some(),
    ) {
        MacRoute::Arp(_) => match (env.arp(ip, &ifaces, &filter), managed) {
            (Ok(mac), _) => Ok(MacFound::Arp { ip, mac }),
            (Err(Error::ArpNoReply { .. }), Some(h)) => via_remote(h),
            (Err(e), _) => Err(e),
        },
        MacRoute::Remote => via_remote(managed.expect("route() returns Remote only when managed")),
        MacRoute::NeedsRemote { via_vpn } => Err(Error::MacNeedsRemote { ip, via_vpn }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netif::fixture;

    fn filter() -> InterfaceFilter {
        InterfaceFilter::default()
    }

    #[test]
    fn cgnat_range() {
        assert!(is_cgnat(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_cgnat(Ipv4Addr::new(100, 105, 128, 173)));
        assert!(is_cgnat(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 128, 0, 1)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_cgnat(Ipv4Addr::new(192, 168, 1, 1)));
    }

    /// Decisions on the development machine's interfaces (wt0 with the lower metric).
    #[test]
    fn routes_on_the_wt0_fixture() {
        let ifs = fixture::interfaces();
        let lan = Ipv4Addr::new(192, 0, 2, 50);
        match route(lan, &ifs, &filter(), Some(12), false) {
            MacRoute::Arp(sel) => assert_eq!(sel.subnet.addr, Ipv4Addr::new(192, 0, 2, 10)),
            other => panic!("{other:?}"),
        }
        // Local LAN wins even when remote management is configured.
        assert!(matches!(
            route(lan, &ifs, &filter(), Some(12), true),
            MacRoute::Arp(_)
        ));
        // NetBird peer (via wt0): remote when configured, else a VPN explanation.
        let peer = Ipv4Addr::new(100, 105, 128, 173);
        assert_eq!(
            route(peer, &ifs, &filter(), Some(7), true),
            MacRoute::Remote
        );
        assert_eq!(
            route(peer, &ifs, &filter(), Some(7), false),
            MacRoute::NeedsRemote { via_vpn: true }
        );
        // Even with virtual adapters included, ARP is never tried through the tunnel.
        let incl = InterfaceFilter {
            include_virtual: true,
            pinned: vec![],
        };
        assert_eq!(
            route(Ipv4Addr::new(100, 64, 0, 9), &ifs, &incl, Some(7), false),
            MacRoute::NeedsRemote { via_vpn: true }
        );
        // A LAN behind the VPN (route pushed to wt0), and the OpenVPN TAP subnet.
        assert_eq!(
            route(Ipv4Addr::new(10, 0, 20, 5), &ifs, &filter(), Some(7), false),
            MacRoute::NeedsRemote { via_vpn: true }
        );
        assert_eq!(
            route(Ipv4Addr::new(10, 8, 0, 9), &ifs, &filter(), None, false),
            MacRoute::NeedsRemote { via_vpn: true }
        );
        // An ordinary routed address (another subnet behind the LAN router).
        assert_eq!(
            route(
                Ipv4Addr::new(198, 51, 100, 7),
                &ifs,
                &filter(),
                Some(12),
                false
            ),
            MacRoute::NeedsRemote { via_vpn: false }
        );
        assert_eq!(
            route(Ipv4Addr::new(198, 51, 100, 7), &ifs, &filter(), None, false),
            MacRoute::NeedsRemote { via_vpn: false }
        );
    }

    /// Review m11: Hyper-V / WSL / VMware host-only adapters are Ethernet adapters, not VPN /
    /// tunnel adapters: their subnets go to ARP and are never explained as "VPN".
    #[test]
    fn virtual_switch_subnets_are_on_link_not_vpn() {
        let mut ifs = fixture::interfaces();
        let mac = Some(MacAddr([0x00, 0x15, 0x5D, 0, 0, 1]));
        ifs.push(NetInterface::new(
            30,
            "{00000000-0000-0000-0000-000000000030}",
            "vEthernet (WSL (Hyper-V firewall))",
            "Hyper-V Virtual Ethernet Adapter #2",
            6,
            true,
            mac,
            vec!["172.28.16.1/20".parse().unwrap()],
        ));
        ifs.push(NetInterface::new(
            31,
            "{00000000-0000-0000-0000-000000000031}",
            "VMware Network Adapter VMnet1",
            "VMware Virtual Ethernet Adapter for VMnet1",
            6,
            true,
            mac,
            vec!["192.168.56.1/24".parse().unwrap()],
        ));
        for (ip, egress) in [
            (Ipv4Addr::new(172, 28, 20, 5), 30),
            (Ipv4Addr::new(192, 168, 56, 101), 31),
        ] {
            assert!(!is_vpn_address(ip, &ifs, Some(egress)), "{ip}");
            assert!(
                matches!(
                    route(ip, &ifs, &filter(), Some(egress), false),
                    MacRoute::Arp(_)
                ),
                "{ip}"
            );
        }
        // A real tunnel (wt0) stays a VPN.
        assert!(is_vpn_address(Ipv4Addr::new(10, 9, 0, 1), &ifs, Some(7)));
    }

    // ---- find_mac_with: mock OS + mock remote backends -----------------------------------------

    use crate::i18n::{Lang, describe_error};
    use crate::model::RemoteKind;
    use crate::remote::tests::{Rig, host};
    use std::cell::Cell;

    const LAN_MAC: MacAddr = MacAddr([0x02, 0, 0x5E, 0, 0, 0x50]);

    struct Env {
        ifaces: Vec<NetInterface>,
        egress: Option<u32>,
        arp: fn(Ipv4Addr) -> Result<MacAddr>,
        arp_calls: Cell<u32>,
    }

    impl Env {
        fn new(egress: Option<u32>, arp: fn(Ipv4Addr) -> Result<MacAddr>) -> Env {
            Env {
                ifaces: fixture::interfaces(),
                egress,
                arp,
                arp_calls: Cell::new(0),
            }
        }
    }

    impl MacEnv for Env {
        fn interfaces(&self) -> Vec<NetInterface> {
            self.ifaces.clone()
        }
        fn best_interface(&self, _ip: Ipv4Addr) -> Option<u32> {
            self.egress
        }
        fn resolve(&self, addr: &HostAddr) -> Result<Ipv4Addr> {
            addr.as_ipv4().ok_or_else(|| Error::Resolve {
                name: addr.to_string(),
                message: "not found".into(),
            })
        }
        fn arp(
            &self,
            ip: Ipv4Addr,
            _ifaces: &[NetInterface],
            _filter: &InterfaceFilter,
        ) -> Result<MacAddr> {
            self.arp_calls.set(self.arp_calls.get() + 1);
            (self.arp)(ip)
        }
    }

    fn arp_ok(_ip: Ipv4Addr) -> Result<MacAddr> {
        Ok(LAN_MAC)
    }

    fn arp_silent(ip: Ipv4Addr) -> Result<MacAddr> {
        Err(Error::ArpNoReply { ip })
    }

    fn rig_with_ssh_nics() -> Rig {
        let rig = Rig::new();
        let nic = |iface: &str, last: u8, score: i32| wol_ssh::MacCandidate {
            iface: iface.into(),
            mac: [0x02, 0, 0, 0, 0, last],
            current_mac: [0x02, 0, 0, 0, 0, last],
            permanent_mac: None,
            kind: wol_ssh::NicKind::Physical,
            on_default_route: score > 100,
            via: None,
            link_up: true,
            wol: None,
            lan_ipv4: None,
            score,
        };
        *rig.ssh.macs.lock().unwrap() = vec![nic("eno1", 0x11, 125), nic("eno2", 0x12, 25)];
        rig
    }

    fn at(addr: &str, kind: Option<RemoteKind>) -> Host {
        let mut h = host(kind);
        h.address = Some(addr.parse().unwrap());
        h
    }

    #[test]
    fn lan_address_uses_arp() {
        let rig = rig_with_ssh_nics();
        let env = Env::new(Some(12), arp_ok);
        // Even a managed host: the LAN wins, the host is not contacted.
        let h = at("192.0.2.50", Some(RemoteKind::Ssh));
        let q = MacQuery {
            address: None,
            host: Some(&h),
        };
        let found = find_mac_with(&q, &rig.settings, &rig.client(), &env).unwrap();
        assert_eq!(
            found,
            MacFound::Arp {
                ip: Ipv4Addr::new(192, 0, 2, 50),
                mac: LAN_MAC
            }
        );
        assert_eq!(found.unique(), Some(LAN_MAC));
        assert!(found.candidates().is_empty());
        assert_eq!(rig.ssh.calls(), 0);
        // An ad-hoc IP without a host.
        let ip: HostAddr = "192.0.2.77".parse().unwrap();
        let q = MacQuery {
            address: Some(&ip),
            host: None,
        };
        assert!(matches!(
            find_mac_with(&q, &rig.settings, &rig.client(), &env),
            Ok(MacFound::Arp { .. })
        ));
    }

    #[test]
    fn silent_lan_host_falls_back_to_remote_only_when_managed() {
        let rig = rig_with_ssh_nics();
        let env = Env::new(Some(12), arp_silent);
        let managed = at("192.0.2.50", Some(RemoteKind::Ssh));
        let q = MacQuery {
            address: None,
            host: Some(&managed),
        };
        let found = find_mac_with(&q, &rig.settings, &rig.client(), &env).unwrap();
        assert_eq!(found.candidates().len(), 2);
        assert_eq!(found.unique(), Some(MacAddr([0x02, 0, 0, 0, 0, 0x11])));
        let plain = at("192.0.2.50", None);
        let q = MacQuery {
            address: None,
            host: Some(&plain),
        };
        assert!(matches!(
            find_mac_with(&q, &rig.settings, &rig.client(), &env),
            Err(Error::ArpNoReply { .. })
        ));
    }

    #[test]
    fn vpn_address_uses_remote_management_or_explains() {
        let rig = rig_with_ssh_nics();
        let env = Env::new(Some(7), arp_ok);
        let managed = at("100.105.128.173", Some(RemoteKind::Ssh));
        let q = MacQuery {
            address: None,
            host: Some(&managed),
        };
        let found = find_mac_with(&q, &rig.settings, &rig.client(), &env).unwrap();
        assert!(matches!(found, MacFound::Remote { .. }));
        assert_eq!(rig.ssh.last().host, "100.105.128.173");
        assert_eq!(env.arp_calls.get(), 0);

        let plain = at("100.105.128.173", None);
        let q = MacQuery {
            address: None,
            host: Some(&plain),
        };
        let e = find_mac_with(&q, &rig.settings, &rig.client(), &env).unwrap_err();
        assert!(matches!(e, Error::MacNeedsRemote { via_vpn: true, .. }));
        assert_eq!(e.kind(), crate::ErrorKind::NotFound);
        let ja = describe_error(&e, Lang::Ja);
        assert!(
            ja.contains(
                "VPN（NetBird など）経由のホストは ARP で MAC を取得できません。ホストの「リモート管理」（Windows / SSH）を設定すると、相手の物理 NIC の MAC を取得できます。"
            ),
            "{ja}"
        );
        let en = describe_error(&e, Lang::En);
        assert!(en.contains("VPN") && en.is_ascii(), "{en}");
        assert_eq!(env.arp_calls.get(), 0);

        // Routed through the Ethernet router (not a VPN).
        let env = Env::new(Some(12), arp_ok);
        let routed = at("198.51.100.7", None);
        let q = MacQuery {
            address: None,
            host: Some(&routed),
        };
        let e = find_mac_with(&q, &rig.settings, &rig.client(), &env).unwrap_err();
        assert!(matches!(e, Error::MacNeedsRemote { via_vpn: false, .. }));
        assert!(!describe_error(&e, Lang::Ja).contains("NetBird"));
    }

    #[test]
    fn names_and_missing_addresses() {
        let rig = rig_with_ssh_nics();
        let env = Env::new(None, arp_ok);
        // A name that does not resolve (sleeping PC): remote management still works.
        let mut managed = host(Some(RemoteKind::Ssh));
        managed.address = Some("nas.invalid".parse().unwrap());
        let q = MacQuery {
            address: None,
            host: Some(&managed),
        };
        assert!(matches!(
            find_mac_with(&q, &rig.settings, &rig.client(), &env),
            Ok(MacFound::Remote { .. })
        ));
        let mut plain = host(None);
        plain.address = Some("nas.invalid".parse().unwrap());
        let q = MacQuery {
            address: None,
            host: Some(&plain),
        };
        assert!(matches!(
            find_mac_with(&q, &rig.settings, &rig.client(), &env),
            Err(Error::Resolve { .. })
        ));
        // No address at all.
        let mut bare = host(None);
        bare.address = None;
        let q = MacQuery {
            address: None,
            host: Some(&bare),
        };
        assert!(matches!(
            find_mac_with(&q, &rig.settings, &rig.client(), &env),
            Err(Error::InvalidValue {
                field: crate::Field::Address,
                ..
            })
        ));
        // Only a management address: used for the lookup (VPN → remote).
        let mut mgmt = host(Some(RemoteKind::Ssh));
        mgmt.address = None;
        mgmt.remote.as_mut().unwrap().address = Some("100.64.3.4".parse().unwrap());
        let q = MacQuery {
            address: None,
            host: Some(&mgmt),
        };
        assert!(matches!(
            find_mac_with(&q, &rig.settings, &rig.client(), &env),
            Ok(MacFound::Remote { .. })
        ));
        // A typed address overrides the host's.
        let typed: HostAddr = "192.0.2.60".parse().unwrap();
        let q = MacQuery {
            address: Some(&typed),
            host: Some(&mgmt),
        };
        assert!(matches!(
            find_mac_with(&q, &rig.settings, &rig.client(), &env),
            Ok(MacFound::Arp { .. })
        ));
    }
}
