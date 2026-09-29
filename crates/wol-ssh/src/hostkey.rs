//! Host key pinning: parse / fingerprint OpenSSH public-key lines, verify the server key,
//! read-only seeding from `~/.ssh/known_hosts`.

use std::path::Path;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PublicKey};

use crate::error::{Result, SshError};

/// A parsed SSH host public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostKeyInfo {
    /// Key algorithm as in the OpenSSH line, e.g. `"ssh-ed25519"`, `"ecdsa-sha2-nistp256"`,
    /// `"ssh-rsa"`.
    pub algorithm: String,
    /// SHA-256 fingerprint in `ssh-keygen -lf` notation: `"SHA256:<base64 without padding>"`.
    pub fingerprint_sha256: String,
    /// Normalized OpenSSH line without comment (`"ssh-ed25519 AAAA..."`); store this as the pin.
    pub openssh_line: String,
}

/// Parse an OpenSSH public-key line (`"<algorithm> <base64> [comment]"`, as stored in
/// [`Target::host_key`](crate::Target::host_key) or printed by `ssh-keyscan` without the host
/// column) and compute its fingerprint. Pure; no I/O.
///
/// # Errors
/// [`SshError::InvalidInput`] when the line is not a valid public key.
pub fn parse_host_key(line: &str) -> Result<HostKeyInfo> {
    Ok(info_of(&parse_pin(line)?))
}

/// `true` when two SHA-256 fingerprints denote the same key. Tolerates a missing or
/// differently-cased `SHA256:` prefix, surrounding whitespace and trailing `=` padding
/// (so a fingerprint typed from `ssh-keygen -lf` output matches). Pure.
pub fn fingerprints_match(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> &str {
        let s = s.trim();
        let s = match (s.get(..7), s.get(7..)) {
            (Some(p), Some(rest)) if p.eq_ignore_ascii_case("SHA256:") => rest,
            _ => s,
        };
        s.trim_end_matches('=')
    }
    let (a, b) = (norm(a), norm(b));
    !a.is_empty() && a == b
}

/// Host keys recorded for `host` / `port` in the current user's `~/.ssh/known_hosts`
/// (read-only; the file is never written). Most preferred first (ed25519, ECDSA, RSA);
/// unsupported key types are skipped. Hashed (`|1|`) entries are matched; `@cert-authority`
/// and `@revoked` markers are not interpreted (such lines never match).
///
/// Returns an empty list when the file or home directory is missing or when any matching
/// line cannot be parsed (the underlying parser fails as a whole). Use the result only as a
/// suggestion to show to the user (or as a pin the user has already trusted in OpenSSH).
///
/// **Blocking** (file read): milliseconds.
pub fn known_hosts_keys(host: &str, port: u16) -> Vec<HostKeyInfo> {
    let host = strip_brackets(host.trim());
    match russh::keys::known_hosts::known_host_keys(host, port) {
        Ok(keys) => sort_and_dedup(keys.into_iter().map(|(_, k)| k)),
        Err(e) => {
            log::debug!("known_hosts lookup failed: {e}");
            Vec::new()
        }
    }
}

/// Like [`known_hosts_keys`] but reads the given file.
///
/// **Blocking** (file read): milliseconds.
pub fn known_hosts_keys_in(path: &Path, host: &str, port: u16) -> Vec<HostKeyInfo> {
    let host = strip_brackets(host.trim());
    match russh::keys::known_hosts::known_host_keys_path(host, port, path) {
        Ok(keys) => sort_and_dedup(keys.into_iter().map(|(_, k)| k)),
        Err(e) => {
            log::debug!("known_hosts lookup in {} failed: {e}", path.display());
            Vec::new()
        }
    }
}

fn sort_and_dedup(keys: impl Iterator<Item = PublicKey>) -> Vec<HostKeyInfo> {
    let mut v: Vec<(u8, HostKeyInfo)> = keys
        .filter_map(|k| preference_rank(&k.algorithm()).map(|r| (r, info_of(&k))))
        .collect();
    v.sort_by_key(|(r, _)| *r);
    let mut out: Vec<HostKeyInfo> = Vec::new();
    for (_, info) in v {
        if !out.iter().any(|o| o.openssh_line == info.openssh_line) {
            out.push(info);
        }
    }
    out
}

pub(crate) fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Preference among host key types supported by this client (lower = preferred), `None` for
/// unsupported types (DSA, security keys, ...).
fn preference_rank(alg: &Algorithm) -> Option<u8> {
    match alg {
        Algorithm::Ed25519 => Some(0),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => Some(1),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        } => Some(2),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        } => Some(3),
        Algorithm::Rsa { .. } => Some(4),
        _ => None,
    }
}

pub(crate) fn is_supported_host_key_type(alg: &Algorithm) -> bool {
    preference_rank(alg).is_some()
}

pub(crate) fn parse_pin(line: &str) -> Result<PublicKey> {
    let line = line.trim().trim_start_matches('\u{feff}');
    if line.is_empty() {
        return Err(SshError::InvalidInput(
            "the pinned host key is empty".into(),
        ));
    }
    PublicKey::from_openssh(line).map_err(|e| {
        SshError::InvalidInput(format!(
            "the pinned host key is not a valid OpenSSH public key: {e}"
        ))
    })
}

pub(crate) fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub(crate) fn openssh_line(key: &PublicKey) -> String {
    let bare = PublicKey::new(key.key_data().clone(), "");
    bare.to_openssh()
        .unwrap_or_else(|_| key.algorithm().as_str().to_string())
}

pub(crate) fn info_of(key: &PublicKey) -> HostKeyInfo {
    HostKeyInfo {
        algorithm: key.algorithm().as_str().to_string(),
        fingerprint_sha256: fingerprint(key),
        openssh_line: openssh_line(key),
    }
}

/// RSA keys may be negotiated with any of the RSA signature hashes; everything else must match
/// exactly.
pub(crate) fn same_key_type(a: &Algorithm, b: &Algorithm) -> bool {
    matches!((a, b), (Algorithm::Rsa { .. }, Algorithm::Rsa { .. })) || a == b
}

/// The host-key verdict: `Ok` only when a pin exists and the key material is identical
/// (comments are ignored).
pub(crate) fn verify(pinned: Option<&PublicKey>, offered: &PublicKey) -> Result<()> {
    match pinned {
        Some(p) if p.key_data() == offered.key_data() => Ok(()),
        Some(p) => Err(SshError::HostKeyMismatch {
            expected_fp: fingerprint(p),
            actual_fp: fingerprint(offered),
        }),
        None => Err(SshError::UnknownHostKey {
            openssh_line: openssh_line(offered),
            fingerprint_sha256: fingerprint(offered),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::private::Ed25519Keypair;

    fn key(seed: u8) -> PublicKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
            .public_key()
            .clone()
    }

    #[test]
    fn parse_and_fingerprint() {
        let k = key(7);
        let line = format!("{}  my comment\r\n", k.to_openssh().unwrap());
        let info = parse_host_key(&line).unwrap();
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert!(info.fingerprint_sha256.starts_with("SHA256:"), "{info:?}");
        assert!(!info.fingerprint_sha256.ends_with('='));
        assert!(!info.openssh_line.contains("comment"));
        assert_eq!(parse_host_key(&info.openssh_line).unwrap(), info);
        assert!(matches!(
            parse_host_key("ssh-ed25519 notbase64"),
            Err(SshError::InvalidInput(_))
        ));
        assert!(matches!(
            parse_host_key("   "),
            Err(SshError::InvalidInput(_))
        ));
    }

    #[test]
    fn fingerprint_comparison() {
        let fp = parse_host_key(&key(1).to_openssh().unwrap())
            .unwrap()
            .fingerprint_sha256;
        let bare = fp.strip_prefix("SHA256:").unwrap();
        assert!(fingerprints_match(&fp, &fp));
        assert!(fingerprints_match(&fp, bare));
        assert!(fingerprints_match(&format!(" sha256:{bare}= "), &fp));
        assert!(!fingerprints_match(&fp, &bare.to_lowercase()));
        assert!(!fingerprints_match("", ""));
        // Non-ASCII input must not panic (byte 7 inside a multi-byte character).
        assert!(!fingerprints_match("日本語の指紋", &fp));
        assert!(!fingerprints_match("SHA25日本", "x"));
        let other = parse_host_key(&key(2).to_openssh().unwrap())
            .unwrap()
            .fingerprint_sha256;
        assert!(!fingerprints_match(&fp, &other));
    }

    #[test]
    fn verify_verdicts() {
        let (a, b) = (key(1), key(2));
        assert!(verify(Some(&a), &a).is_ok());
        match verify(Some(&a), &b) {
            Err(SshError::HostKeyMismatch {
                expected_fp,
                actual_fp,
            }) => {
                assert_eq!(expected_fp, fingerprint(&a));
                assert_eq!(actual_fp, fingerprint(&b));
            }
            other => panic!("{other:?}"),
        }
        match verify(None, &b) {
            Err(SshError::UnknownHostKey {
                openssh_line: l,
                fingerprint_sha256,
            }) => {
                assert_eq!(parse_pin(&l).unwrap().key_data(), b.key_data());
                assert_eq!(fingerprint_sha256, fingerprint(&b));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn known_hosts_file_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let (a, b) = (key(3), key(4));
        let body = format!(
            "# comment\n\
             other.example {}\n\
             nas.lan,192.168.1.5 {}\n\
             [nas.lan]:2222 {}\n",
            a.to_openssh().unwrap(),
            a.to_openssh().unwrap(),
            b.to_openssh().unwrap()
        );
        std::fs::write(&path, body).unwrap();
        let hits = known_hosts_keys_in(&path, "nas.lan", 22);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].openssh_line, openssh_line(&a));
        assert_eq!(known_hosts_keys_in(&path, "192.168.1.5", 22).len(), 1);
        let hits = known_hosts_keys_in(&path, "nas.lan", 2222);
        assert_eq!(hits[0].openssh_line, openssh_line(&b));
        assert!(known_hosts_keys_in(&path, "unknown", 22).is_empty());
        assert!(known_hosts_keys_in(&dir.path().join("missing"), "nas.lan", 22).is_empty());
        // One broken matching line makes the parser fail as a whole -> "no seed".
        std::fs::write(&path, "nas.lan ssh-ed25519 !!!!\n").unwrap();
        assert!(known_hosts_keys_in(&path, "nas.lan", 22).is_empty());
    }

    #[test]
    fn key_type_matching() {
        use russh::keys::HashAlg;
        assert!(same_key_type(
            &Algorithm::Rsa { hash: None },
            &Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        ));
        assert!(same_key_type(&Algorithm::Ed25519, &Algorithm::Ed25519));
        assert!(!same_key_type(
            &Algorithm::Ed25519,
            &Algorithm::Rsa { hash: None }
        ));
        assert!(!same_key_type(
            &Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            },
            &Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384
            }
        ));
        assert!(is_supported_host_key_type(&Algorithm::Ed25519));
        assert!(!is_supported_host_key_type(&Algorithm::Dsa));
        assert_eq!(strip_brackets("[fe80::1]"), "fe80::1");
        assert_eq!(strip_brackets("host"), "host");
    }
}
