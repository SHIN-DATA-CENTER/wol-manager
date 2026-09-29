//! MAC lookup from an IPv4 address ("get MAC from IP" in the editor, `wolm arp`, `wolm add --arp`).
//!
//! `SendARP` only works on-link, returns garbage (all-zero MACs) through tunnels, and blocks
//! for about 3 seconds when nobody answers. Therefore the IP must lie inside the subnet of a
//! selected, non-virtual interface; otherwise the lookup is refused without calling the API.

use std::net::Ipv4Addr;

use windows_sys::Win32::Foundation::{ERROR_BAD_NET_NAME, ERROR_NOT_FOUND, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

use crate::error::{Error, Result};
use crate::mac::MacAddr;
use crate::netif::{self, InterfaceFilter, NetInterface, Selected};

/// The selected non-virtual interface address whose subnet contains `ip` (pure). `None`
/// when `ip` is off-link, is the subnet's network / broadcast address, or only reachable via
/// a VPN / virtual adapter.
pub fn local_source_for(
    ip: Ipv4Addr,
    ifaces: &[NetInterface],
    filter: &InterfaceFilter,
) -> Option<Selected> {
    netif::select(ifaces, filter).into_iter().find(|s| {
        !s.is_virtual
            && s.subnet.contains(ip)
            && (s.subnet.prefix_len >= 31
                || (ip != s.subnet.network() && Some(ip) != s.subnet.broadcast()))
    })
}

/// Accepts a `SendARP` result only when it has exactly 6 bytes and is a plausible NIC
/// address (not all-zero, not broadcast / multicast). Pure.
pub fn accept_mac(bytes: &[u8], len: u32) -> Option<MacAddr> {
    if len != 6 || bytes.len() < 6 {
        return None;
    }
    let m = MacAddr(bytes[..6].try_into().ok()?);
    (m.is_usable() && !m.is_broadcast()).then_some(m)
}

/// Looks up the MAC of `ip` with the current interfaces and the default filter (automatic
/// selection, virtual adapters excluded).
///
/// **Blocking**: up to about 3 s when the host does not answer.
/// Errors: [`Error::NotOnLocalSubnet`], [`Error::ArpNoReply`], [`Error::Network`].
pub fn mac_from_ip(ip: Ipv4Addr) -> Result<MacAddr> {
    mac_from_ip_with(ip, &netif::list(), &InterfaceFilter::default())
}

/// Like [`mac_from_ip`] with explicit interfaces and filter (e.g. the settings' pins).
/// **Blocking**.
pub fn mac_from_ip_with(
    ip: Ipv4Addr,
    ifaces: &[NetInterface],
    filter: &InterfaceFilter,
) -> Result<MacAddr> {
    let src = local_source_for(ip, ifaces, filter).ok_or(Error::NotOnLocalSubnet { ip })?;
    let mut buf = [0u64; 1];
    let mut len: u32 = 6;
    // SAFETY: `buf` is 8 writable, aligned bytes; `len` tells the API 6 bytes are wanted.
    let rc = unsafe {
        SendARP(
            u32::from_ne_bytes(ip.octets()),
            u32::from_ne_bytes(src.subnet.addr.octets()),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    match rc {
        NO_ERROR => {
            let bytes = buf[0].to_ne_bytes();
            accept_mac(&bytes, len).ok_or(Error::ArpNoReply { ip })
        }
        ERROR_BAD_NET_NAME | ERROR_NOT_FOUND => Err(Error::ArpNoReply { ip }),
        code => Err(Error::Network {
            op: "arp",
            source: std::io::Error::from_raw_os_error(code as i32),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ifaces() -> Vec<NetInterface> {
        vec![
            NetInterface::new(
                12,
                "{B}",
                "Ethernet",
                "Intel",
                6,
                true,
                None,
                vec!["192.0.2.10/24".parse().unwrap()],
            ),
            NetInterface::new(
                7,
                "{A}",
                "wt0",
                "WireGuard Tunnel",
                53,
                true,
                None,
                vec!["100.64.0.5/10".parse().unwrap()],
            ),
        ]
    }

    #[test]
    fn source_selection() {
        let f = InterfaceFilter::default();
        let s = local_source_for(Ipv4Addr::new(192, 0, 2, 50), &ifaces(), &f).unwrap();
        assert_eq!(s.subnet.addr, Ipv4Addr::new(192, 0, 2, 10));
        assert!(local_source_for(Ipv4Addr::new(192, 0, 2, 255), &ifaces(), &f).is_none());
        assert!(local_source_for(Ipv4Addr::new(192, 0, 2, 0), &ifaces(), &f).is_none());
        assert!(local_source_for(Ipv4Addr::new(198, 51, 100, 1), &ifaces(), &f).is_none());
        // VPN subnets are refused even when the VPN interface is selected.
        let f = InterfaceFilter {
            include_virtual: true,
            pinned: vec![],
        };
        assert!(local_source_for(Ipv4Addr::new(100, 64, 0, 9), &ifaces(), &f).is_none());
    }

    #[test]
    fn off_subnet_is_refused_without_calling_the_api() {
        let e = mac_from_ip_with(
            Ipv4Addr::new(203, 0, 113, 1),
            &ifaces(),
            &InterfaceFilter::default(),
        )
        .unwrap_err();
        assert!(matches!(e, Error::NotOnLocalSubnet { .. }));
        assert_eq!(e.kind(), crate::ErrorKind::NotFound);
    }

    #[test]
    fn accept_rules() {
        let good = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0];
        assert_eq!(
            accept_mac(&good, 6),
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(accept_mac(&good, 0), None);
        assert_eq!(accept_mac(&good, 8), None);
        assert_eq!(accept_mac(&[0; 8], 6), None);
        assert_eq!(accept_mac(&[0xFF; 8], 6), None);
        assert_eq!(accept_mac(&[0x01, 0, 0x5E, 0, 0, 1, 0, 0], 6), None);
        assert_eq!(accept_mac(&good[..4], 6), None);
    }
}
