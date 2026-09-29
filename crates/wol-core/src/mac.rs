//! MAC addresses and SecureOn passwords.
//!
//! Accepted input forms (after [`crate::normalize`] folding, case-insensitive):
//! `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, `AA BB CC DD EE FF`, `0:1:2:3:4:5` (1-digit
//! groups), `aabb.ccdd.eeff` (Cisco), `aabbcc-ddeeff`, and `AABBCCDDEEFF`.
//! Display is always upper-case and colon separated.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Field, FieldIssue};
use crate::normalize;

/// Parses 6 bytes in any accepted MAC notation. `input` must already be normalized.
fn parse_six(input: &str) -> Option<[u8; 6]> {
    let groups: Vec<&str> = input
        .split([':', '-', '.', ' '])
        .filter(|g| !g.is_empty())
        .collect();
    if groups.is_empty()
        || !groups
            .iter()
            .all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    let mut out = [0u8; 6];
    if groups.len() == 6 && groups.iter().all(|g| g.len() <= 2) {
        for (i, g) in groups.iter().enumerate() {
            out[i] = u8::from_str_radix(g, 16).ok()?;
        }
        return Some(out);
    }
    // Groups of even length that concatenate to 12 digits (Cisco 3x4, 2x6, 1x12).
    if groups.iter().all(|g| g.len() % 2 == 0 && g.len() >= 4) || groups.len() == 1 {
        let hex: String = groups.concat();
        if hex.len() != 12 {
            return None;
        }
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(out);
    }
    None
}

fn fmt_six(b: &[u8; 6], sep: char, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
        f,
        "{:02X}{sep}{:02X}{sep}{:02X}{sep}{:02X}{sep}{:02X}{sep}{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

/// A 48-bit MAC address.
///
/// `Default` is the all-zero address, which [`MacAddr::is_usable`] rejects.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The broadcast address `FF:FF:FF:FF:FF:FF`.
    pub const BROADCAST: MacAddr = MacAddr([0xFF; 6]);

    /// Creates a MAC address from bytes.
    pub const fn new(bytes: [u8; 6]) -> Self {
        MacAddr(bytes)
    }

    /// The 6 bytes.
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Parses user input (full-width tolerated). Errors: [`FieldIssue::Required`] for empty
    /// input, [`FieldIssue::ImeKana`], [`FieldIssue::InvalidMac`]. Does not reject zero /
    /// broadcast addresses; use [`MacAddr::parse_usable`] for host MACs.
    pub fn parse(input: &str) -> Result<MacAddr, FieldIssue> {
        let s = normalize::check_technical(input)?;
        if s.is_empty() {
            return Err(FieldIssue::Required);
        }
        parse_six(&s).map(MacAddr).ok_or(FieldIssue::InvalidMac)
    }

    /// Like [`MacAddr::parse`] but also rejects all-zero, broadcast and multicast MACs
    /// ([`FieldIssue::MacNotUnicast`]), which can never be a WoL target.
    pub fn parse_usable(input: &str) -> Result<MacAddr, FieldIssue> {
        let m = Self::parse(input)?;
        if m.is_usable() {
            Ok(m)
        } else {
            Err(FieldIssue::MacNotUnicast)
        }
    }

    /// `true` for `00:00:00:00:00:00`.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    /// `true` for `FF:FF:FF:FF:FF:FF`.
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    /// `true` when the group bit (least significant bit of the first byte) is set.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// `true` for a unicast, non-zero address (a plausible NIC address).
    pub fn is_usable(&self) -> bool {
        !self.is_zero() && !self.is_multicast()
    }

    /// Formats with `-` separators (`AA-BB-...`, the Windows `ipconfig` style).
    pub fn to_hyphenated(&self) -> String {
        struct H<'a>(&'a [u8; 6]);
        impl fmt::Display for H<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt_six(self.0, '-', f)
            }
        }
        H(&self.0).to_string()
    }

    /// 12 lower-case hex digits without separators (useful for search).
    pub fn to_compact(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// `true` when `s` parses as a MAC address in any accepted notation.
pub fn looks_like_mac(s: &str) -> bool {
    MacAddr::parse(s).is_ok()
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_six(&self.0, ':', f)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

impl FromStr for MacAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        MacAddr::parse(s).map_err(|issue| Error::invalid(Field::Mac, issue, s))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        MacAddr::parse(&s)
            .map_err(|_| serde::de::Error::custom(format!("invalid MAC address {s:?}")))
    }
}

/// A 6-byte SecureOn password, appended to the magic packet (108 bytes in total).
///
/// Stored in plain text in `config.toml` (the UI says so). `Debug` is redacted; `Display`
/// shows the value (needed for serialization) so never log it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecureOn(pub [u8; 6]);

impl SecureOn {
    /// The 6 bytes.
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Parses `AA:BB:CC:DD:EE:FF` style input (same notations as [`MacAddr`]).
    /// Errors: [`FieldIssue::Required`], [`FieldIssue::ImeKana`], [`FieldIssue::InvalidSecureOn`].
    pub fn parse(input: &str) -> Result<SecureOn, FieldIssue> {
        let s = normalize::check_technical(input)?;
        if s.is_empty() {
            return Err(FieldIssue::Required);
        }
        parse_six(&s)
            .map(SecureOn)
            .ok_or(FieldIssue::InvalidSecureOn)
    }
}

impl fmt::Display for SecureOn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_six(&self.0, ':', f)
    }
}

impl fmt::Debug for SecureOn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureOn(<redacted>)")
    }
}

impl FromStr for SecureOn {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        SecureOn::parse(s).map_err(|issue| Error::invalid(Field::SecureOn, issue, s))
    }
}

impl Serialize for SecureOn {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecureOn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SecureOn::parse(&s).map_err(|_| serde::de::Error::custom("invalid SecureOn password"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: MacAddr = MacAddr([0xAA, 0xBB, 0xCC, 0x0D, 0xEE, 0xFF]);

    #[test]
    fn accepted_formats() {
        for s in [
            "AA:BB:CC:0D:EE:FF",
            "aa:bb:cc:0d:ee:ff",
            "AA-BB-CC-0D-EE-FF",
            "AA BB CC 0D EE FF",
            "aa:bb:cc:d:ee:ff",
            "aabb.cc0d.eeff",
            "aabbcc-0deeff",
            "AABBCC0DEEFF",
            " ＡＡ：ＢＢ：ＣＣ：０Ｄ：ＥＥ：ＦＦ ",
            "AAーBBーCCー0DーEEーFF",
        ] {
            assert_eq!(MacAddr::parse(s), Ok(M), "input {s:?}");
        }
    }

    #[test]
    fn rejected_formats() {
        assert_eq!(MacAddr::parse(""), Err(FieldIssue::Required));
        assert_eq!(MacAddr::parse("   "), Err(FieldIssue::Required));
        assert_eq!(
            MacAddr::parse("あa:bb:cc:dd:ee:ff"),
            Err(FieldIssue::ImeKana)
        );
        for s in [
            "AA:BB:CC:DD:EE",
            "AA:BB:CC:DD:EE:FF:00",
            "AABBCCDDEEF",
            "GG:BB:CC:DD:EE:FF",
            "AAA:BB:CC:DD:EE:F",
            "NAS",
            "abc.def",
        ] {
            assert_eq!(
                MacAddr::parse(s),
                Err(FieldIssue::InvalidMac),
                "input {s:?}"
            );
        }
    }

    #[test]
    fn display_and_serde() {
        assert_eq!(M.to_string(), "AA:BB:CC:0D:EE:FF");
        assert_eq!(M.to_hyphenated(), "AA-BB-CC-0D-EE-FF");
        assert_eq!(M.to_compact(), "aabbcc0deeff");
        let json = serde_json::to_string(&M).unwrap();
        assert_eq!(json, "\"AA:BB:CC:0D:EE:FF\"");
        let back: MacAddr = serde_json::from_str("\"aa-bb-cc-0d-ee-ff\"").unwrap();
        assert_eq!(back, M);
        assert!(serde_json::from_str::<MacAddr>("\"zz\"").is_err());
    }

    #[test]
    fn usable() {
        assert!(M.is_usable());
        assert!(!MacAddr::default().is_usable());
        assert!(!MacAddr::BROADCAST.is_usable());
        // Well-formed but never a network adapter's address: a precise reason, not "format".
        for s in [
            "01:00:5E:00:00:01",
            "11-22-33-44-55-66",
            "FF:FF:FF:FF:FF:FF",
            "00:00:00:00:00:00",
        ] {
            assert_eq!(
                MacAddr::parse_usable(s),
                Err(FieldIssue::MacNotUnicast),
                "{s}"
            );
        }
        assert_eq!(MacAddr::parse_usable("zz"), Err(FieldIssue::InvalidMac));
        assert!(looks_like_mac("001122334455"));
        assert!(!looks_like_mac("NAS"));
    }

    #[test]
    fn secureon() {
        let s = SecureOn::parse("01-23-45-67-89-ab").unwrap();
        assert_eq!(s.to_string(), "01:23:45:67:89:AB");
        assert_eq!(format!("{s:?}"), "SecureOn(<redacted>)");
        assert_eq!(SecureOn::parse("12345"), Err(FieldIssue::InvalidSecureOn));
        assert!("xx".parse::<SecureOn>().is_err());
    }
}
