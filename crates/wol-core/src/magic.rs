//! Magic packet construction and parsing.
//!
//! Layout: 6 × `0xFF`, then the target MAC 16 times (102 bytes), optionally followed by a
//! 6-byte SecureOn password (108 bytes).

use std::fmt::Write as _;

use serde::Serialize;

use crate::mac::{MacAddr, SecureOn};

/// Length of a magic packet without SecureOn.
pub const PACKET_LEN: usize = 102;
/// Length of a magic packet with SecureOn.
pub const PACKET_LEN_SECUREON: usize = 108;

/// Builds the magic packet payload (102 or 108 bytes).
pub fn build(mac: MacAddr, secureon: Option<SecureOn>) -> Vec<u8> {
    let mut v = Vec::with_capacity(PACKET_LEN_SECUREON);
    v.extend_from_slice(&[0xFF; 6]);
    for _ in 0..16 {
        v.extend_from_slice(&mac.0);
    }
    if let Some(s) = secureon {
        v.extend_from_slice(&s.0);
    }
    v
}

/// A decoded magic packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MagicPacket {
    /// Target MAC.
    pub mac: MacAddr,
    /// SecureOn password, if the packet carries one.
    #[serde(skip)]
    pub secureon: Option<SecureOn>,
    /// `true` when a SecureOn password was present (for JSON output without the secret).
    pub has_secureon: bool,
}

/// Parses a UDP payload as a magic packet. Returns `None` unless it is exactly 102 or 108
/// bytes with the sync stream and 16 identical MAC copies. Used by `wolm listen`.
pub fn parse(bytes: &[u8]) -> Option<MagicPacket> {
    if bytes.len() != PACKET_LEN && bytes.len() != PACKET_LEN_SECUREON {
        return None;
    }
    if bytes[..6] != [0xFF; 6] {
        return None;
    }
    let mac: [u8; 6] = bytes[6..12].try_into().ok()?;
    let (copies, _) = bytes[6..PACKET_LEN].as_chunks::<6>();
    if copies.len() != 16 || !copies.iter().all(|c| *c == mac) {
        return None;
    }
    let secureon = if bytes.len() == PACKET_LEN_SECUREON {
        Some(SecureOn(bytes[PACKET_LEN..].try_into().ok()?))
    } else {
        None
    };
    Some(MagicPacket {
        mac: MacAddr(mac),
        secureon,
        has_secureon: secureon.is_some(),
    })
}

/// Hex dump for `--dry-run`: lines of 16 bytes (`FF FF FF ...`), upper case.
pub fn to_hex(bytes: &[u8]) -> String {
    dump(bytes, bytes.len())
}

/// Like [`to_hex`] for a magic packet, but a SecureOn password (the bytes after the 102-byte
/// payload) is shown as `**`: dry-run output ends up in logs and bug reports, and the
/// password is never printed elsewhere either.
pub fn to_hex_masked(bytes: &[u8]) -> String {
    dump(bytes, PACKET_LEN)
}

/// Hex dump that shows bytes from index `visible` on as `**`.
fn dump(bytes: &[u8], visible: usize) -> String {
    let mut s = String::with_capacity(bytes.len() * 3 + bytes.len() / 16);
    for (i, line) in bytes.chunks(16).enumerate() {
        if i > 0 {
            s.push('\n');
        }
        for (j, b) in line.iter().enumerate() {
            if j > 0 {
                s.push(' ');
            }
            if i * 16 + j < visible {
                let _ = write!(s, "{b:02X}");
            } else {
                s.push_str("**");
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    fn expected_102() -> Vec<u8> {
        // Written out by hand on purpose.
        #[rustfmt::skip]
        let v: Vec<u8> = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        v
    }

    #[test]
    fn packet_102_matches_hand_written_bytes() {
        let p = build(MAC, None);
        assert_eq!(p.len(), 102);
        assert_eq!(p, expected_102());
    }

    #[test]
    fn packet_108_with_secureon() {
        let so = SecureOn([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        let p = build(MAC, Some(so));
        assert_eq!(p.len(), 108);
        let mut expected = expected_102();
        expected.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        assert_eq!(p, expected);
        let parsed = parse(&p).unwrap();
        assert_eq!(parsed.mac, MAC);
        assert_eq!(parsed.secureon, Some(so));
        assert!(parsed.has_secureon);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse(&build(MAC, None)).unwrap().mac, MAC);
        assert!(parse(&[0u8; 102]).is_none());
        let mut p = build(MAC, None);
        p[50] ^= 1;
        assert!(parse(&p).is_none());
        assert!(parse(&p[..101]).is_none());
    }

    #[test]
    fn hex_dump() {
        let h = to_hex(&build(MAC, None));
        assert!(h.starts_with("FF FF FF FF FF FF 00 11 22 33 44 55 00 11 22 33\n"));
        assert_eq!(h.lines().count(), 7);
        assert_eq!(to_hex_masked(&build(MAC, None)), h);
        let so = SecureOn([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        let m = to_hex_masked(&build(MAC, Some(so)));
        assert!(m.ends_with("00 11 22 33 44 55 ** ** ** ** ** **"), "{m}");
        assert!(!m.contains("01 23 45"), "{m}");
        assert!(to_hex(&build(MAC, Some(so))).ends_with("01 23 45 67 89 AB"));
    }
}
