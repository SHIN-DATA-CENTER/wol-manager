//! Detection of "this is the computer we are running on", so power operations never act on the
//! local PC (the app manages *other* machines).
//!
//! The check compares the target against this PC's computer names (`GetComputerNameExW`) and, when
//! the target is an IP literal, against this PC's own adapter addresses (`GetAdaptersAddresses`)
//! plus loopback / unspecified. IP literals are parsed leniently, the way the Windows resolver does
//! (`127.1`, `2130706433`, `0x7f.1`, `::ffff:127.0.0.1`), so no spelling of a local address slips
//! through. [`crate::power()`] additionally resolves host names (DNS / hosts file / LLMNR) and refuses
//! a name that resolves to one of this PC's addresses.
//!
//! The real guarantee that tests never shut anything down is the [`crate::power::ShutdownBackend`]
//! seam: the crate-private real backend panics in `cfg(test)` builds.
//!
//! # Blocking
//! [`is_local_target`] enumerates local adapters; it does no network I/O and returns promptly.

use std::net::{IpAddr, Ipv4Addr};

/// Parses one component of a lenient IPv4 literal (`inet_aton` rules): decimal, octal with a
/// leading `0`, or hexadecimal with `0x`.
fn parse_inet_part(p: &str) -> Option<u64> {
    if p.is_empty() || p.len() > 12 {
        return None;
    }
    let (digits, radix) = if let Some(h) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
        (h, 16)
    } else if p.len() > 1 && p.starts_with('0') {
        (&p[1..], 8)
    } else {
        (p, 10)
    };
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Parses the classic `inet_aton` IPv4 forms that Windows name resolution also accepts: `a`,
/// `a.b`, `a.b.c`, `a.b.c.d`, each part decimal, octal (`0` prefix) or hex (`0x` prefix); the last
/// part fills the remaining bytes. E.g. `127.1` = `127.0.0.1`, `2130706433` = `127.0.0.1`.
pub(crate) fn parse_ipv4_lenient(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let nums: Vec<u64> = parts
        .iter()
        .map(|p| parse_inet_part(p))
        .collect::<Option<_>>()?;
    let (last, init) = nums.split_last()?;
    if init.iter().any(|&n| n > 255) {
        return None;
    }
    let rest_bytes = 4 - init.len() as u32;
    let max = if rest_bytes == 4 {
        u64::from(u32::MAX)
    } else {
        (1u64 << (8 * rest_bytes)) - 1
    };
    if *last > max {
        return None;
    }
    let mut v: u32 = 0;
    for (i, &n) in init.iter().enumerate() {
        v |= (n as u32) << (24 - 8 * i as u32);
    }
    v |= *last as u32;
    Some(Ipv4Addr::from(v))
}

/// Parses an IP literal: strict IPv4 / IPv6 (optionally bracketed, optionally with a `%zone`), or a
/// lenient IPv4 form. IPv4-mapped IPv6 addresses are canonicalized to IPv4.
pub(crate) fn parse_ip_lenient(s: &str) -> Option<IpAddr> {
    let t = s.trim_start_matches('[').trim_end_matches(']');
    let t = t.split('%').next().unwrap_or(t);
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    parse_ipv4_lenient(t).map(IpAddr::V4)
}

fn is_local_ip(ip: IpAddr, local_ips: &[IpAddr]) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback() || ip.is_unspecified() || local_ips.iter().any(|l| l.to_canonical() == ip)
}

/// Pure core of [`is_local_target`]: decides whether `target` names this PC, given the PC's own
/// computer names and unicast IP addresses.
///
/// - Empty or `.` is the local machine (Win32 APIs treat an empty server name as "this PC").
/// - An IP literal (see [`parse_ip_lenient`]) matches when it is loopback / unspecified or equals
///   one of `local_ips`.
/// - A name matches when its first DNS label is `localhost`, or it equals one of `local_names`, or
///   shares a first DNS label with one (conservative: `mypc.other.domain` is refused too).
pub(crate) fn matches_local(target: &str, local_names: &[String], local_ips: &[IpAddr]) -> bool {
    let t = target.trim().trim_start_matches(r"\\");
    if t.is_empty() || t == "." {
        return true;
    }
    if let Some(ip) = parse_ip_lenient(t) {
        return is_local_ip(ip, local_ips);
    }

    let lower = t.trim_end_matches('.').to_ascii_lowercase();
    let target_label = lower.split('.').next().unwrap_or(&lower);
    if target_label == "localhost" {
        return true;
    }
    local_names.iter().any(|n| {
        let n = n.trim_end_matches('.').to_ascii_lowercase();
        n == lower || n.split('.').next().unwrap_or(&n) == target_label
    })
}

/// Strict variant of [`matches_local`] with **no** heuristics: `.` / `localhost`, an IP literal
/// that is loopback or one of `local_ips`, or a name exactly equal to one of `local_names`. Used to
/// redirect read-only queries to the local machine, where a false positive would silently return
/// this PC's data for another host.
pub(crate) fn matches_local_exact(
    target: &str,
    local_names: &[String],
    local_ips: &[IpAddr],
) -> bool {
    let t = target.trim();
    if t == "." {
        return true;
    }
    if let Some(ip) = parse_ip_lenient(t) {
        return !ip.is_unspecified() && is_local_ip(ip, local_ips);
    }
    let lower = t.trim_end_matches('.').to_ascii_lowercase();
    lower == "localhost"
        || local_names
            .iter()
            .any(|n| n.trim_end_matches('.').eq_ignore_ascii_case(&lower))
}

/// `true` only when `host` certainly is this PC (see [`matches_local_exact`]); `false` when unsure
/// or when this PC's addresses cannot be enumerated. No network I/O.
#[cfg(windows)]
pub(crate) fn is_exactly_local(host: &str) -> bool {
    local_unicast_ips().is_some_and(|ips| matches_local_exact(host, &local_computer_names(), &ips))
}

/// Returns `true` when `host` refers to the computer this program runs on.
///
/// Fails **closed**: if this PC's addresses cannot be enumerated, every target is treated as local.
/// Does no network I/O (names are not resolved; [`crate::power()`] does that in addition).
#[cfg(windows)]
pub fn is_local_target(host: &str) -> bool {
    match local_unicast_ips() {
        Some(ips) => matches_local(host, &local_computer_names(), &ips),
        None => true,
    }
}

/// The full guard used before a power operation: the pure name / IP check plus a system name
/// resolution of `host`. `Err(())` when this PC's addresses cannot be enumerated.
#[cfg(windows)]
pub(crate) fn check_local_target_resolving(host: &str) -> Result<bool, ()> {
    let ips = local_unicast_ips().ok_or(())?;
    if matches_local(host, &local_computer_names(), &ips) {
        return Ok(true);
    }
    Ok(resolves_to_local(host, &ips))
}

/// Resolves `host` with the system resolver and reports whether any address is this PC's.
/// A resolution failure is "not local" (the operation then fails to connect anyway).
fn resolves_to_local(host: &str, local_ips: &[IpAddr]) -> bool {
    use std::net::ToSocketAddrs;
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|a| a.ip()).any(|ip| is_local_ip(ip, local_ips)),
        Err(_) => false,
    }
}

#[cfg(windows)]
pub(crate) fn local_computer_names() -> Vec<String> {
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsFullyQualified, ComputerNameDnsHostname, ComputerNameNetBIOS,
        ComputerNamePhysicalDnsFullyQualified, ComputerNamePhysicalDnsHostname,
        ComputerNamePhysicalNetBIOS, GetComputerNameExW,
    };
    let mut out = Vec::new();
    for fmt in [
        ComputerNameNetBIOS,
        ComputerNameDnsHostname,
        ComputerNameDnsFullyQualified,
        ComputerNamePhysicalNetBIOS,
        ComputerNamePhysicalDnsHostname,
        ComputerNamePhysicalDnsFullyQualified,
    ] {
        let mut size = 0u32;
        // First call: learn the required size (fails with ERROR_MORE_DATA).
        // SAFETY: null buffer with size 0 is the documented "query size" form.
        unsafe {
            GetComputerNameExW(fmt, std::ptr::null_mut(), &mut size);
        }
        if size == 0 {
            continue;
        }
        let mut buf = vec![0u16; size as usize];
        // SAFETY: `buf` has `size` u16 slots; `size` is updated to the written length.
        let ok = unsafe { GetComputerNameExW(fmt, buf.as_mut_ptr(), &mut size) } != 0;
        if ok {
            let name = String::from_utf16_lossy(&buf[..(size as usize).min(buf.len())]);
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// This PC's unicast addresses on every adapter, or `None` when they cannot be enumerated.
#[cfg(windows)]
pub(crate) fn local_unicast_ips() -> Option<Vec<IpAddr>> {
    use std::net::Ipv6Addr;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
        GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    const AF_UNSPEC: u32 = 0;
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;

    // u64-backed so the IP_ADAPTER_ADDRESSES_LH list (8-byte aligned) is properly aligned.
    let mut size = 16 * 1024u32;
    let mut buf: Vec<u64> = Vec::new();
    let mut done = false;
    for _ in 0..4 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        size = (buf.len() * 8) as u32;
        // SAFETY: `buf` is `size` writable, 8-byte-aligned bytes; `size` receives the needed length.
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        match rc {
            NO_ERROR => {
                done = true;
                break;
            }
            // No adapters at all: an empty (but valid) set.
            ERROR_NO_DATA => return Some(Vec::new()),
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return None,
        }
    }
    if !done {
        return None;
    }

    let mut ips = Vec::new();
    // SAFETY: on success the buffer holds a linked list of IP_ADAPTER_ADDRESSES_LH whose pointers
    // all refer into `buf`, which outlives this walk.
    unsafe {
        let mut ad = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !ad.is_null() {
            let mut ua = (*ad).FirstUnicastAddress;
            while !ua.is_null() {
                let sa = (*ua).Address.lpSockaddr;
                if !sa.is_null() {
                    match (*sa).sa_family {
                        AF_INET => {
                            let s = &*(sa as *const SOCKADDR_IN);
                            let b = s.sin_addr.S_un.S_un_b;
                            ips.push(IpAddr::V4(Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4)));
                        }
                        AF_INET6 => {
                            let s = &*(sa as *const SOCKADDR_IN6);
                            ips.push(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.u.Byte)));
                        }
                        _ => {}
                    }
                }
                ua = (*ua).Next;
            }
            ad = (*ad).Next;
        }
    }
    Some(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_and_unspecified_are_local() {
        assert!(matches_local("127.0.0.1", &[], &[]));
        assert!(matches_local("127.53.0.9", &[], &[]));
        assert!(matches_local("::1", &[], &[]));
        assert!(matches_local("0.0.0.0", &[], &[]));
        assert!(matches_local(r"\\127.0.0.1", &[], &[]));
        assert!(matches_local("[::1]", &[], &[]));
        assert!(matches_local("localhost", &[], &[]));
        assert!(matches_local("", &[], &[]));
        assert!(matches_local(".", &[], &[]));
    }

    #[test]
    fn lenient_loopback_spellings_are_local() {
        // Regression: these all reach 127.0.0.1 through the Windows resolver but were treated as
        // host names (not local) before.
        for t in [
            "127.1",
            "127.0.1",
            "2130706433",
            "0x7f000001",
            "0x7f.1",
            "0177.0.0.1",
            "::ffff:127.0.0.1",
            "[::ffff:7f00:1]",
            "0",
            "LOCALHOST.",
            "localhost.localdomain",
        ] {
            assert!(matches_local(t, &[], &[]), "{t} must be local");
        }
    }

    #[test]
    fn lenient_ipv4_parser() {
        assert_eq!(
            parse_ipv4_lenient("127.1"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            parse_ipv4_lenient("192.168.1.199"),
            Some(Ipv4Addr::new(192, 168, 1, 199))
        );
        assert_eq!(
            parse_ipv4_lenient("100.105.33272"),
            Some(Ipv4Addr::new(100, 105, 129, 248))
        );
        assert_eq!(
            parse_ipv4_lenient("0xC0.0xA8.1.1"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(parse_ipv4_lenient("256.1"), None);
        assert_eq!(parse_ipv4_lenient("1.2.3.4.5"), None);
        assert_eq!(parse_ipv4_lenient("1..2"), None);
        assert_eq!(parse_ipv4_lenient("08"), None);
        assert_eq!(parse_ipv4_lenient("server1"), None);
        assert_eq!(parse_ipv4_lenient("4294967296"), None);
        assert_eq!(parse_ipv4_lenient(""), None);
    }

    #[test]
    fn own_ip_is_local_others_are_not() {
        let mine = vec![ip("192.168.1.199"), ip("100.105.128.173")];
        assert!(matches_local("192.168.1.199", &[], &mine));
        assert!(matches_local("100.105.128.173", &[], &mine));
        assert!(matches_local(r"\\100.105.128.173", &[], &mine));
        assert!(matches_local("::ffff:192.168.1.199", &[], &mine));
        // Lenient spelling of 192.168.1.199 (455 = 1 * 256 + 199).
        assert!(matches_local("192.168.455", &[], &mine));
        assert!(!matches_local("192.168.467", &[], &mine)); // 192.168.1.211
        assert!(!matches_local("192.168.1.50", &[], &mine));
        assert!(!matches_local("100.105.9.9", &[], &mine));
    }

    #[test]
    fn own_name_is_local() {
        let names = vec!["DESKTOP-ABC".to_owned(), "desktop-abc.lan".to_owned()];
        assert!(matches_local("DESKTOP-ABC", &names, &[]));
        assert!(matches_local("desktop-abc", &names, &[]));
        assert!(matches_local("DESKTOP-ABC.lan", &names, &[]));
        assert!(matches_local("DESKTOP-ABC.lan.", &names, &[]));
        // Shares first label with the FQDN.
        assert!(matches_local("desktop-abc.other.domain", &names, &[]));
        assert!(!matches_local("OTHER-PC", &names, &[]));
        assert!(!matches_local("server1", &names, &[]));
    }

    #[test]
    fn exact_match_has_no_heuristics() {
        let names = vec!["DESKTOP-ABC".to_owned(), "desktop-abc.lan".to_owned()];
        let mine = vec![ip("192.168.1.199")];
        for t in [
            ".",
            "localhost",
            "127.0.0.1",
            "127.1",
            "::1",
            "192.168.1.199",
            "desktop-abc",
        ] {
            assert!(matches_local_exact(t, &names, &mine), "{t}");
        }
        assert!(matches_local_exact("DESKTOP-ABC.lan.", &names, &mine));
        // The conservative power guard refuses these; the exact check must not claim them.
        for t in [
            "desktop-abc.other.domain",
            "0.0.0.0",
            "",
            "192.168.1.50",
            "localhost.x",
        ] {
            assert!(!matches_local_exact(t, &names, &mine), "{t}");
        }
    }

    #[test]
    fn ipv6_with_zone_id() {
        // A link-local address with a zone id matches the same address in local_ips.
        assert!(matches_local("fe80::1%12", &[], &[ip("fe80::1")]));
        assert!(matches_local("[fe80::1%12]", &[], &[ip("fe80::1")]));
        assert!(!matches_local("fe80::2%12", &[], &[ip("fe80::1")]));
    }

    #[test]
    fn numeric_names_resolve_locally_without_dns() {
        // Numeric forms never reach DNS; the resolver maps them to loopback.
        assert!(resolves_to_local("127.0.0.1", &[]));
        assert!(!resolves_to_local("192.0.2.1", &[])); // TEST-NET-1, not local
    }

    #[cfg(windows)]
    #[test]
    fn this_pc_is_detected_by_name_and_address() {
        let ips = local_unicast_ips().expect("adapters enumerate");
        for a in &ips {
            assert!(
                is_local_target(&a.to_string()),
                "{a} is one of our addresses"
            );
        }
        for n in local_computer_names() {
            assert!(is_local_target(&n), "{n} is our computer name");
        }
        assert_eq!(check_local_target_resolving("127.1"), Ok(true));
    }
}
