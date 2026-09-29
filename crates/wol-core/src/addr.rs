//! IPv4 addresses, ports, host addresses and `host[:port]` targets.
//!
//! All parsers accept IME full-width input (see [`crate::normalize`]) and return a
//! [`FieldIssue`] so the GUI can show a translated message next to the field. `FromStr`
//! implementations return [`Error::InvalidValue`] for the CLI.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Field, FieldIssue};
use crate::normalize;

/// Parses a dotted-quad IPv4 address.
///
/// Leading zeros are read as decimal (`192.168.001.010` → `192.168.1.10`), unlike
/// `Ipv4Addr::from_str`. Errors: `Required`, `ImeKana`, `InvalidAddress`.
pub fn parse_ipv4(input: &str) -> Result<Ipv4Addr, FieldIssue> {
    let s = normalize::check_technical(input)?;
    if s.is_empty() {
        return Err(FieldIssue::Required);
    }
    parse_ipv4_ascii(&s).ok_or(FieldIssue::InvalidAddress)
}

fn parse_ipv4_ascii(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        o[i] = p.parse::<u16>().ok().filter(|v| *v <= 255)? as u8;
    }
    Some(Ipv4Addr::from(o))
}

/// Parses a UDP/TCP port in `1..=65535`. Errors: `Required`, `ImeKana`, `InvalidPort`.
pub fn parse_port(input: &str) -> Result<u16, FieldIssue> {
    let s = normalize::check_technical(input)?;
    if s.is_empty() {
        return Err(FieldIssue::Required);
    }
    parse_port_ascii(&s).ok_or(FieldIssue::InvalidPort)
}

fn parse_port_ascii(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>()
        .ok()
        .filter(|p| (1..=65535).contains(p))
        .map(|p| p as u16)
}

/// Splits a list field on `,` `;` whitespace and newlines (after folding `、` to `,`).
pub fn split_list(input: &str) -> Vec<String> {
    normalize::normalize_list_input(input)
        .split([',', ';', ' ', '\t', '\r', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parses a list of ports (`3389, 445 22`). Empty input gives an empty list. Duplicates are
/// removed, order is kept. Errors: `ImeKana`, `InvalidPortList`, `TooManyPorts` (more than
/// [`crate::model::limits::TCP_PORTS_MAX`] different ports).
pub fn parse_port_list(input: &str) -> Result<Vec<u16>, FieldIssue> {
    let s = normalize::check_technical_list(input)?;
    let mut out = Vec::new();
    for item in split_list(&s) {
        let p = parse_port_ascii(&item).ok_or(FieldIssue::InvalidPortList)?;
        if !out.contains(&p) {
            out.push(p);
        }
    }
    if out.len() > crate::model::limits::TCP_PORTS_MAX {
        return Err(FieldIssue::TooManyPorts);
    }
    Ok(out)
}

/// Checks a stored port list (config file, import): no port 0 and at most
/// [`crate::model::limits::TCP_PORTS_MAX`] entries.
pub fn check_port_list(ports: &[u16]) -> Result<(), FieldIssue> {
    if ports.contains(&0) {
        Err(FieldIssue::InvalidPortList)
    } else if ports.len() > crate::model::limits::TCP_PORTS_MAX {
        Err(FieldIssue::TooManyPorts)
    } else {
        Ok(())
    }
}

/// Formats a port list as `3389, 445, 22` (the form the editor shows).
pub fn format_port_list(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn valid_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// An IPv4 address or a DNS / NetBIOS host name.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum HostAddr {
    /// Literal IPv4 address.
    V4(Ipv4Addr),
    /// Host name, resolved at use time (IPv4 results only).
    Name(String),
}

impl HostAddr {
    /// Parses an IPv4 address or host name. Input made only of digits and dots must be a
    /// valid IPv4 address. Errors: `Required`, `ImeKana`, `InvalidAddress`.
    pub fn parse(input: &str) -> Result<HostAddr, FieldIssue> {
        let s = normalize::check_technical(input)?;
        if s.is_empty() {
            return Err(FieldIssue::Required);
        }
        if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return parse_ipv4_ascii(&s)
                .map(HostAddr::V4)
                .ok_or(FieldIssue::InvalidAddress);
        }
        if valid_hostname(&s) {
            Ok(HostAddr::Name(s))
        } else {
            Err(FieldIssue::InvalidAddress)
        }
    }

    /// The literal IPv4 address, if this is one.
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            HostAddr::V4(ip) => Some(*ip),
            HostAddr::Name(_) => None,
        }
    }

    /// Resolves to the first IPv4 address.
    ///
    /// **Blocking** for names (DNS / LLMNR / NetBIOS, can take seconds when the name does not
    /// exist). Returns [`Error::Resolve`] on failure or when only IPv6 results exist.
    pub fn resolve_v4(&self) -> Result<Ipv4Addr, Error> {
        match self {
            HostAddr::V4(ip) => Ok(*ip),
            HostAddr::Name(name) => resolve_name_v4(name),
        }
    }
}

/// Resolves a host name to its first IPv4 address. **Blocking**.
pub fn resolve_name_v4(name: &str) -> Result<Ipv4Addr, Error> {
    match (name, 0u16).to_socket_addrs() {
        Ok(iter) => {
            for a in iter {
                if let SocketAddr::V4(v4) = a {
                    return Ok(*v4.ip());
                }
            }
            Err(Error::Resolve {
                name: name.to_owned(),
                message: "no IPv4 address".to_owned(),
            })
        }
        Err(e) => Err(Error::Resolve {
            name: name.to_owned(),
            message: e.to_string(),
        }),
    }
}

impl fmt::Display for HostAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostAddr::V4(ip) => ip.fmt(f),
            HostAddr::Name(n) => f.write_str(n),
        }
    }
}

impl FromStr for HostAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        HostAddr::parse(s).map_err(|issue| Error::invalid(Field::Address, issue, s))
    }
}

impl Serialize for HostAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HostAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        HostAddr::parse(&s).map_err(|_| serde::de::Error::custom(format!("invalid address {s:?}")))
    }
}

/// An explicit send target `host[:port]`, e.g. `10.0.20.255` or `relay.lan:9`.
///
/// Without a port the request's port is used. `255.255.255.255` is special: it is expanded
/// to the limited broadcast of every selected interface (see [`crate::send::plan`]).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Target {
    /// Destination address or name.
    pub addr: HostAddr,
    /// Optional port override.
    pub port: Option<u16>,
}

impl Target {
    /// Parses `host[:port]`. Errors: `Required`, `ImeKana`, `InvalidTarget`.
    pub fn parse(input: &str) -> Result<Target, FieldIssue> {
        let s = normalize::check_technical(input)?;
        if s.is_empty() {
            return Err(FieldIssue::Required);
        }
        let (host, port) = match s.rsplit_once(':') {
            Some((h, p)) => {
                let port = parse_port_ascii(p).ok_or(FieldIssue::InvalidTarget)?;
                (h, Some(port))
            }
            None => (s.as_str(), None),
        };
        let addr = HostAddr::parse(host).map_err(|_| FieldIssue::InvalidTarget)?;
        Ok(Target { addr, port })
    }

    /// `true` for `255.255.255.255`.
    pub fn is_limited_broadcast(&self) -> bool {
        self.addr == HostAddr::V4(Ipv4Addr::BROADCAST)
    }
}

/// Parses a list of targets separated by `,` `;` whitespace or newlines. Empty input gives an
/// empty list. Errors: `ImeKana`, `InvalidTarget`.
pub fn parse_target_list(input: &str) -> Result<Vec<Target>, FieldIssue> {
    let s = normalize::check_technical_list(input)?;
    let mut out: Vec<Target> = Vec::new();
    for item in split_list(&s) {
        let t = Target::parse(&item).map_err(|e| match e {
            FieldIssue::ImeKana => FieldIssue::ImeKana,
            _ => FieldIssue::InvalidTarget,
        })?;
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

/// Formats targets one per line (the editor's multi-line form).
pub fn format_target_list(targets: &[Target]) -> String {
    targets
        .iter()
        .map(Target::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(p) => write!(f, "{}:{p}", self.addr),
            None => write!(f, "{}", self.addr),
        }
    }
}

impl FromStr for Target {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Target::parse(s).map_err(|issue| Error::invalid(Field::Targets, issue, s))
    }
}

impl Serialize for Target {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Target::parse(&s).map_err(|_| serde::de::Error::custom(format!("invalid target {s:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4() {
        assert_eq!(
            parse_ipv4("192.168.1.10"),
            Ok(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(
            parse_ipv4("192.168.001.010"),
            Ok(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(
            parse_ipv4("１９２．１６８．１．１０"),
            Ok(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(
            parse_ipv4("192。168。1。10"),
            Ok(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(parse_ipv4(""), Err(FieldIssue::Required));
        for bad in [
            "256.1.1.1",
            "1.2.3",
            "1.2.3.4.5",
            "1..2.3",
            "a.b.c.d",
            "1.2.3.0004",
        ] {
            assert_eq!(parse_ipv4(bad), Err(FieldIssue::InvalidAddress), "{bad}");
        }
    }

    #[test]
    fn ports() {
        assert_eq!(parse_port("9"), Ok(9));
        assert_eq!(parse_port("６５５３５"), Ok(65535));
        assert_eq!(parse_port("0"), Err(FieldIssue::InvalidPort));
        assert_eq!(parse_port("65536"), Err(FieldIssue::InvalidPort));
        assert_eq!(parse_port("-1"), Err(FieldIssue::InvalidPort));
        assert_eq!(parse_port(""), Err(FieldIssue::Required));
        assert_eq!(parse_port_list("3389, 445、22 22"), Ok(vec![3389, 445, 22]));
        assert_eq!(parse_port_list(""), Ok(vec![]));
        assert_eq!(parse_port_list("22,x"), Err(FieldIssue::InvalidPortList));
        assert_eq!(format_port_list(&[3389, 22]), "3389, 22");
        // At most TCP_PORTS_MAX different ports (duplicates do not count).
        let sixteen: Vec<String> = (1..=16).map(|p| p.to_string()).collect();
        assert_eq!(parse_port_list(&sixteen.join(",")).unwrap().len(), 16);
        assert_eq!(
            parse_port_list(&format!("{},1,2", sixteen.join(",")))
                .unwrap()
                .len(),
            16
        );
        assert_eq!(
            parse_port_list(&format!("{},17", sixteen.join(","))),
            Err(FieldIssue::TooManyPorts)
        );
        assert_eq!(check_port_list(&[22, 445]), Ok(()));
        assert_eq!(check_port_list(&[22, 0]), Err(FieldIssue::InvalidPortList));
        let many: Vec<u16> = (20000..20017).collect();
        assert_eq!(check_port_list(&many), Err(FieldIssue::TooManyPorts));
    }

    #[test]
    fn host_addr() {
        assert_eq!(
            HostAddr::parse("192.168.1.10"),
            Ok(HostAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
        assert_eq!(
            HostAddr::parse("lab-pc.example.lan"),
            Ok(HostAddr::Name("lab-pc.example.lan".into()))
        );
        assert_eq!(HostAddr::parse("NAS"), Ok(HostAddr::Name("NAS".into())));
        assert_eq!(
            HostAddr::parse("192.168.1.300"),
            Err(FieldIssue::InvalidAddress)
        );
        assert_eq!(HostAddr::parse("bad host"), Err(FieldIssue::InvalidAddress));
        assert_eq!(HostAddr::parse("-x"), Err(FieldIssue::InvalidAddress));
        assert_eq!(HostAddr::parse("ぬas"), Err(FieldIssue::ImeKana));
        assert_eq!(
            HostAddr::V4(Ipv4Addr::LOCALHOST).resolve_v4().unwrap(),
            Ipv4Addr::LOCALHOST
        );
    }

    #[test]
    fn targets() {
        let t = Target::parse("relay.lan:9").unwrap();
        assert_eq!(t.addr, HostAddr::Name("relay.lan".into()));
        assert_eq!(t.port, Some(9));
        assert_eq!(t.to_string(), "relay.lan:9");
        let t = Target::parse("10.0.20.255").unwrap();
        assert_eq!(t.port, None);
        assert!(
            Target::parse("255.255.255.255")
                .unwrap()
                .is_limited_broadcast()
        );
        assert_eq!(Target::parse("x:0"), Err(FieldIssue::InvalidTarget));
        assert_eq!(Target::parse("x:"), Err(FieldIssue::InvalidTarget));
        assert_eq!(Target::parse("a b"), Err(FieldIssue::InvalidTarget));
        let list = parse_target_list("10.0.20.255\nrelay.lan:9, 10.0.20.255").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(format_target_list(&list), "10.0.20.255\nrelay.lan:9");
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(json, r#"["10.0.20.255","relay.lan:9"]"#);
    }
}
