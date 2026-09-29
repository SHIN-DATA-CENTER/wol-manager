//! Per-host secret storage in Windows Credential Manager.
//!
//! Secrets are stored as `CRED_TYPE_GENERIC` credentials with `CRED_PERSIST_LOCAL_MACHINE`, the
//! password held as a UTF-16LE blob (interoperable with `cmdkey` and the Control Panel editor).
//! Target names are `wol-manager/host/<uuid-lowercase-hyphenated>/<kind>`; the `UserName` field
//! holds the account.
//!
//! # Blocking
//! The Windows-backed [`WindowsCredentialStore`] calls the `Cred*` APIs, which are local and
//! return in well under a millisecond in practice. There is no network I/O.
//!
//! # Testing
//! [`InMemoryStore`] is a process-local mock that implements [`SecretStore`] without touching the
//! real Credential Manager, so downstream tests never write to the user's vault. Tests that must
//! exercise the real store use targets under the `wol-manager-test/` prefix (see
//! [`target_name_in`]) and always delete what they create.

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Op, Result};

/// Prefix of every target name this crate manages.
pub const TARGET_PREFIX: &str = "wol-manager/host/";

/// The kind of secret stored for a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecretKind {
    /// The Windows admin password, or the SSH login password (also used for `sudo -S`).
    Login,
    /// The passphrase of an SSH private key.
    KeyPassphrase,
    /// A separate sudo password (when it differs from the login password).
    Sudo,
}

impl SecretKind {
    /// The lowercase token used in the target name.
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::Login => "login",
            SecretKind::KeyPassphrase => "key-passphrase",
            SecretKind::Sudo => "sudo",
        }
    }

    /// Parses a kind token (case-insensitive).
    pub fn parse(s: &str) -> Option<SecretKind> {
        match s.to_ascii_lowercase().as_str() {
            "login" => Some(SecretKind::Login),
            "key-passphrase" => Some(SecretKind::KeyPassphrase),
            "sudo" => Some(SecretKind::Sudo),
            _ => None,
        }
    }

    /// Every kind, for exhaustive cleanup.
    pub const ALL: [SecretKind; 3] = [
        SecretKind::Login,
        SecretKind::KeyPassphrase,
        SecretKind::Sudo,
    ];
}

/// The target name for a host id (already formatted, lowercase-hyphenated UUID) and kind, under the
/// production [`TARGET_PREFIX`].
pub fn target_name(host_id: &str, kind: SecretKind) -> String {
    target_name_in(TARGET_PREFIX, host_id, kind)
}

/// The target name `<prefix><host-id-lowercase>/<kind>` under an explicit namespace `prefix`
/// (which should end in `/`). Tests use `"wol-manager-test/host/"`.
pub fn target_name_in(prefix: &str, host_id: &str, kind: SecretKind) -> String {
    format!("{prefix}{}/{}", host_id.to_ascii_lowercase(), kind.as_str())
}

/// Splits a target name of the form `<TARGET_PREFIX><host-id>/<kind>` into its parts.
/// Returns `None` when the name does not match this crate's scheme.
pub fn parse_target(target: &str) -> Option<(String, SecretKind)> {
    parse_target_in(TARGET_PREFIX, target)
}

/// Like [`parse_target`] for an explicit namespace `prefix` (matched case-insensitively, as
/// Credential Manager does). The host id must be non-empty and contain no `/`.
pub fn parse_target_in(prefix: &str, target: &str) -> Option<(String, SecretKind)> {
    let head = target.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = &target[prefix.len()..];
    let (id, kind) = rest.split_once('/')?;
    if validate_host_id(id).is_err() {
        return None;
    }
    Some((id.to_ascii_lowercase(), SecretKind::parse(kind)?))
}

/// A host id must be a non-empty token without `/`, `*` (the enumeration wildcard) or control
/// characters; wol-core passes a lowercase hyphenated UUID.
fn validate_host_id(host_id: &str) -> Result<()> {
    if host_id.is_empty()
        || host_id.len() > 128
        || host_id
            .chars()
            .any(|c| c == '/' || c == '\\' || c == '*' || c.is_control() || c.is_whitespace())
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            Op::SecretStore,
            format!("invalid host id {host_id:?}"),
        ));
    }
    Ok(())
}

/// A retrieved secret. Its [`Debug`] never prints the password.
pub struct HostSecret {
    /// The account (`HOST\user`, `user@domain`, or a Linux user).
    pub user: String,
    /// The plaintext password, wiped on drop.
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for HostSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSecret")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// One enumerated credential (never carries the password).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    /// The host id parsed from the target name (lowercase).
    pub host_id: String,
    /// The kind of secret.
    pub kind: SecretKind,
    /// The account stored in the credential's `UserName`.
    pub user: String,
}

/// Maximum blob size accepted by `CredWriteW` (bytes). A larger blob fails with error 1783.
pub const MAX_BLOB_BYTES: usize = 2560;
/// Maximum user name length accepted by `CredWriteW` (UTF-16 code units).
pub const MAX_USER_UNITS: usize = 513;

/// Encodes a password as a UTF-16LE blob, validating the length limits **before** any OS call
/// (an over-long blob otherwise fails with the opaque error 1783). The blob is allocated at its
/// exact size so no partial plaintext copy is left behind by a reallocation.
pub(crate) fn encode_blob(user: &str, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = password.encode_utf16().count() * 2;
    if bytes > MAX_BLOB_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            Op::SecretStore,
            format!("password is too long: {bytes} bytes UTF-16LE, limit {MAX_BLOB_BYTES}"),
        ));
    }
    if user.encode_utf16().count() > MAX_USER_UNITS {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            Op::SecretStore,
            "user name is too long",
        ));
    }
    if user.contains('\0') {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            Op::SecretStore,
            "user name contains NUL",
        ));
    }
    let mut blob: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(bytes));
    for unit in password.encode_utf16() {
        blob.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(blob)
}

/// Decodes a UTF-16LE blob into a password without leaving unscrubbed intermediate copies (the
/// `String` is pre-sized to its exact UTF-8 length).
fn decode_blob(blob: &[u8]) -> Result<Zeroizing<String>> {
    let bad = |what: &str| {
        Error::new(
            ErrorKind::Other,
            Op::SecretStore,
            format!("stored secret is not valid UTF-16LE ({what})"),
        )
    };
    if !blob.len().is_multiple_of(2) {
        return Err(bad("odd length"));
    }
    let units: Zeroizing<Vec<u16>> = Zeroizing::new(
        blob.as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect(),
    );
    let mut len = 0usize;
    for c in char::decode_utf16(units.iter().copied()) {
        len += c.map_err(|_| bad("unpaired surrogate"))?.len_utf8();
    }
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.extend(char::decode_utf16(units.iter().copied()).map_while(|c| c.ok()));
    Ok(out)
}

/// A backend that stores per-host secrets. Implemented by [`WindowsCredentialStore`] (the real
/// vault) and [`InMemoryStore`] (a test mock). Object-safe (`&dyn SecretStore` works).
pub trait SecretStore {
    /// Reads the secret at `target`, or `None` when absent.
    fn read(&self, target: &str) -> Result<Option<HostSecret>>;
    /// Writes (creating or replacing) the secret at `target`.
    fn write(&self, target: &str, user: &str, password: &str) -> Result<()>;
    /// Deletes the secret at `target`, returning `true` if one existed.
    fn delete(&self, target: &str) -> Result<bool>;
    /// Enumerates every credential named `<prefix><host-id>/<kind>` (never returns passwords).
    /// Entries under `prefix` that do not follow that scheme are skipped.
    fn list_prefix(&self, prefix: &str) -> Result<Vec<StoredEntry>>;

    /// Reads the secret for a host id + kind.
    fn read_host(&self, host_id: &str, kind: SecretKind) -> Result<Option<HostSecret>> {
        validate_host_id(host_id)?;
        self.read(&target_name(host_id, kind))
    }
    /// Writes the secret for a host id + kind.
    fn write_host(
        &self,
        host_id: &str,
        kind: SecretKind,
        user: &str,
        password: &str,
    ) -> Result<()> {
        validate_host_id(host_id)?;
        self.write(&target_name(host_id, kind), user, password)
    }
    /// Deletes the secret for a host id + kind.
    fn delete_host(&self, host_id: &str, kind: SecretKind) -> Result<bool> {
        validate_host_id(host_id)?;
        self.delete(&target_name(host_id, kind))
    }
    /// Deletes every secret kind for a host id. Returns the number deleted.
    fn delete_all(&self, host_id: &str) -> Result<usize> {
        validate_host_id(host_id)?;
        let mut n = 0;
        for kind in SecretKind::ALL {
            if self.delete(&target_name(host_id, kind))? {
                n += 1;
            }
        }
        Ok(n)
    }
    /// Enumerates every credential this crate manages.
    fn list(&self) -> Result<Vec<StoredEntry>> {
        self.list_prefix(TARGET_PREFIX)
    }
    /// `wolm cred prune`: deletes every managed secret whose host id `keep` rejects (e.g. hosts no
    /// longer in the config) and returns the deleted entries.
    fn prune(&self, keep: &dyn Fn(&str) -> bool) -> Result<Vec<StoredEntry>> {
        self.prune_prefix(TARGET_PREFIX, keep)
    }
    /// [`SecretStore::prune`] under an explicit namespace `prefix` (tests).
    fn prune_prefix(&self, prefix: &str, keep: &dyn Fn(&str) -> bool) -> Result<Vec<StoredEntry>> {
        let mut removed = Vec::new();
        for e in self.list_prefix(prefix)? {
            if !keep(&e.host_id) && self.delete(&target_name_in(prefix, &e.host_id, e.kind))? {
                removed.push(e);
            }
        }
        Ok(removed)
    }
}

/// Whether a `CredWriteW` must be preceded by a delete: writing a credential whose existing
/// `Persist` differs from the target one (e.g. an `ENTERPRISE` entry left by `cmdkey /generic`) and
/// then deleting it leaves a stale copy that reappears, so the entry is deleted first.
pub(crate) fn needs_delete_before_write(
    existing_persist: Option<u32>,
    target_persist: u32,
) -> bool {
    matches!(existing_persist, Some(p) if p != target_persist)
}

#[cfg(windows)]
pub use windows_impl::WindowsCredentialStore;

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, FILETIME, GetLastError};
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CRED_TYPE_MAXIMUM, CREDENTIALW, CredDeleteW,
        CredEnumerateW, CredFree, CredGetSessionTypes, CredReadW, CredWriteW,
    };
    use zeroize::Zeroize;

    /// The real Windows Credential Manager store.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct WindowsCredentialStore;

    impl WindowsCredentialStore {
        /// `true` when this logon session can persist generic credentials on this machine
        /// (`CredGetSessionTypes`). `false` e.g. in a network logon (wolm over SSH), where every
        /// store call would fail with [`ErrorKind::SecretStoreUnavailable`]; offer a one-shot
        /// `--password-stdin` instead.
        pub fn is_available() -> bool {
            let mut persist = [0u32; CRED_TYPE_MAXIMUM as usize];
            // SAFETY: `persist` has exactly CRED_TYPE_MAXIMUM writable entries.
            let ok = unsafe { CredGetSessionTypes(CRED_TYPE_MAXIMUM, persist.as_mut_ptr()) } != 0;
            ok && persist[CRED_TYPE_GENERIC as usize] >= CRED_PERSIST_LOCAL_MACHINE
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// Reads `GetLastError` exactly once, right after the failing call.
    fn last_error() -> u32 {
        // SAFETY: GetLastError reads thread-local state and is always safe.
        unsafe { GetLastError() }
    }

    struct RawCred {
        user: String,
        persist: u32,
        blob: Zeroizing<Vec<u8>>,
    }

    fn read_raw(target: &str) -> Result<Option<RawCred>> {
        let t = wide(target);
        let mut p: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: `t` is a NUL-terminated wide string; `p` receives an owned buffer to CredFree.
        let ok = unsafe { CredReadW(t.as_ptr(), CRED_TYPE_GENERIC, 0, &mut p) } != 0;
        if !ok {
            let code = last_error();
            return match code {
                ERROR_NOT_FOUND => Ok(None),
                _ => Err(Error::from_win32(
                    Op::SecretStore,
                    code,
                    format!("CredReadW({target})"),
                )),
            };
        }
        // SAFETY: CredReadW succeeded, so `p` points to a single CredFree-able CREDENTIALW whose
        // CredentialBlob (if non-null) is `CredentialBlobSize` writable bytes inside that block.
        // The plaintext is copied into a pre-sized Zeroizing buffer, then scrubbed in place
        // before CredFree.
        let raw = unsafe {
            let c = &*p;
            let mut blob = Zeroizing::new(Vec::new());
            if !c.CredentialBlob.is_null() && c.CredentialBlobSize > 0 {
                let src =
                    std::slice::from_raw_parts_mut(c.CredentialBlob, c.CredentialBlobSize as usize);
                blob.reserve_exact(src.len());
                blob.extend_from_slice(src);
                src.zeroize();
            }
            let raw = RawCred {
                user: crate::wide::from_pwstr(c.UserName),
                persist: c.Persist,
                blob,
            };
            CredFree(p.cast());
            raw
        };
        Ok(Some(raw))
    }

    /// `CredWriteW` with an explicit `Persist` (the store always uses LOCAL_MACHINE; tests use
    /// other values to reproduce the persist-conflict case).
    pub(super) fn write_raw(target: &str, user: &str, password: &str, persist: u32) -> Result<()> {
        let blob = encode_blob(user, password)?;
        let mut t = wide(target);
        let mut u = wide(user);
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: t.as_mut_ptr(),
            Comment: ptr::null_mut(),
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: if blob.is_empty() {
                ptr::null_mut()
            } else {
                blob.as_ptr().cast_mut()
            },
            Persist: persist,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: ptr::null_mut(),
            UserName: u.as_mut_ptr(),
        };
        // SAFETY: `cred` and every pointer inside it are valid for the duration of the call;
        // CredWriteW only reads the blob.
        let ok = unsafe { CredWriteW(&cred, 0) } != 0;
        if ok {
            Ok(())
        } else {
            let code = last_error();
            Err(Error::from_win32(
                Op::SecretStore,
                code,
                format!("CredWriteW({target})"),
            ))
        }
    }

    /// The stored `Persist` of `target`, for tests.
    #[cfg(test)]
    pub(super) fn persist_of(target: &str) -> Result<Option<u32>> {
        Ok(read_raw(target)?.map(|r| r.persist))
    }

    impl SecretStore for WindowsCredentialStore {
        fn read(&self, target: &str) -> Result<Option<HostSecret>> {
            match read_raw(target)? {
                None => Ok(None),
                Some(r) => Ok(Some(HostSecret {
                    password: decode_blob(&r.blob)?,
                    user: r.user,
                })),
            }
        }

        fn write(&self, target: &str, user: &str, password: &str) -> Result<()> {
            // Validate before touching the vault (the existing entry stays intact on bad input).
            drop(encode_blob(user, password)?);
            // A persist change followed by a delete resurrects the old copy: delete first.
            if let Some(old) = read_raw(target)?
                && needs_delete_before_write(Some(old.persist), CRED_PERSIST_LOCAL_MACHINE)
            {
                self.delete(target)?;
            }
            write_raw(target, user, password, CRED_PERSIST_LOCAL_MACHINE)
        }

        fn delete(&self, target: &str) -> Result<bool> {
            let t = wide(target);
            // SAFETY: `t` is a NUL-terminated wide string.
            if unsafe { CredDeleteW(t.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
                return Ok(true);
            }
            match last_error() {
                ERROR_NOT_FOUND => Ok(false),
                code => Err(Error::from_win32(
                    Op::SecretStore,
                    code,
                    format!("CredDeleteW({target})"),
                )),
            }
        }

        fn list_prefix(&self, prefix: &str) -> Result<Vec<StoredEntry>> {
            let filter = wide(&format!("{prefix}*"));
            let mut count = 0u32;
            let mut list: *mut *mut CREDENTIALW = ptr::null_mut();
            // SAFETY: `filter` is NUL-terminated; `count`/`list` receive an owned CredFree-able array.
            let ok = unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut list) } != 0;
            if !ok {
                return match last_error() {
                    ERROR_NOT_FOUND => Ok(Vec::new()),
                    // Any other code (e.g. 1312 no-such-logon-session) is classified by from_win32.
                    code => Err(Error::from_win32(Op::SecretStore, code, "CredEnumerateW")),
                };
            }
            let mut out = Vec::new();
            // SAFETY: on success `list` is an array of `count` pointers to CREDENTIALW, all freed
            // together by a single CredFree(list). Every blob is scrubbed before the free.
            unsafe {
                for i in 0..count as usize {
                    let c = &mut **list.add(i);
                    if !c.CredentialBlob.is_null() && c.CredentialBlobSize > 0 {
                        std::slice::from_raw_parts_mut(
                            c.CredentialBlob,
                            c.CredentialBlobSize as usize,
                        )
                        .zeroize();
                    }
                    let target = crate::wide::from_pwstr(c.TargetName);
                    if let Some((host_id, kind)) = parse_target_in(prefix, &target) {
                        out.push(StoredEntry {
                            host_id,
                            kind,
                            user: crate::wide::from_pwstr(c.UserName),
                        });
                    }
                }
                CredFree(list.cast());
            }
            Ok(out)
        }
    }
}

/// Lowercased target -> (user, password).
type MemMap = std::collections::HashMap<String, (String, Zeroizing<String>)>;

/// A process-local, in-memory [`SecretStore`] for tests. Never touches the real vault. Target
/// names are case-insensitive, like Credential Manager's.
#[derive(Default)]
pub struct InMemoryStore {
    inner: std::sync::Mutex<MemMap>,
}

impl InMemoryStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn map(&self) -> std::sync::MutexGuard<'_, MemMap> {
        // The map stays consistent even if a holder panicked; recover instead of propagating.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl SecretStore for InMemoryStore {
    fn read(&self, target: &str) -> Result<Option<HostSecret>> {
        Ok(self
            .map()
            .get(&target.to_ascii_lowercase())
            .map(|(user, pw)| HostSecret {
                user: user.clone(),
                password: pw.clone(),
            }))
    }

    fn write(&self, target: &str, user: &str, password: &str) -> Result<()> {
        // Validate exactly as the real store does, so tests catch over-long secrets.
        drop(encode_blob(user, password)?);
        self.map().insert(
            target.to_ascii_lowercase(),
            (user.to_owned(), Zeroizing::new(password.to_owned())),
        );
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<bool> {
        Ok(self.map().remove(&target.to_ascii_lowercase()).is_some())
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<StoredEntry>> {
        let mut out: Vec<StoredEntry> = self
            .map()
            .iter()
            .filter_map(|(target, (user, _))| {
                let (host_id, kind) = parse_target_in(prefix, target)?;
                Some(StoredEntry {
                    host_id,
                    kind,
                    user: user.clone(),
                })
            })
            .collect();
        out.sort_by(|a, b| (&a.host_id, a.kind.as_str()).cmp(&(&b.host_id, b.kind.as_str())));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "1e9a5b2c-0000-4000-8000-000000000001";
    const TEST_PREFIX: &str = "wol-manager-test/host/";

    #[test]
    fn target_name_and_parse_round_trip() {
        let t = target_name(HOST, SecretKind::Login);
        assert_eq!(t, format!("wol-manager/host/{HOST}/login"));
        assert_eq!(parse_target(&t), Some((HOST.to_owned(), SecretKind::Login)));
        // Case-insensitive parse of the kind and prefix; ids are lowercased.
        assert_eq!(
            parse_target(&format!(
                "WOL-MANAGER/HOST/{}/KEY-PASSPHRASE",
                HOST.to_uppercase()
            )),
            Some((HOST.to_owned(), SecretKind::KeyPassphrase))
        );
        assert_eq!(parse_target("unrelated/target"), None);
        assert_eq!(
            parse_target(&format!("wol-manager/host/{HOST}/bogus")),
            None
        );
        // Empty / nested ids are rejected.
        assert_eq!(parse_target("wol-manager/host//login"), None);
        assert_eq!(
            parse_target(&format!("wol-manager/host/a/{HOST}/login")),
            None
        );
        // A test namespace does not parse as production and vice versa.
        let tt = target_name_in(TEST_PREFIX, HOST, SecretKind::Sudo);
        assert_eq!(tt, format!("wol-manager-test/host/{HOST}/sudo"));
        assert_eq!(parse_target(&tt), None);
        assert_eq!(
            parse_target_in(TEST_PREFIX, &tt),
            Some((HOST.to_owned(), SecretKind::Sudo))
        );
    }

    #[test]
    fn kind_strings() {
        for k in SecretKind::ALL {
            assert_eq!(SecretKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(SecretKind::parse("Login"), Some(SecretKind::Login));
        assert_eq!(SecretKind::parse("nope"), None);
    }

    #[test]
    fn blob_size_is_validated_before_any_os_call() {
        // 1280 UTF-16 units = 2560 bytes is the maximum.
        let ok = "a".repeat(1280);
        assert_eq!(encode_blob("user", &ok).unwrap().len(), MAX_BLOB_BYTES);
        let too_long = "a".repeat(1281);
        let e = encode_blob("user", &too_long).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput);
        assert_eq!(e.op(), Op::SecretStore);
        // Emoji count as 2 UTF-16 units each.
        assert!(encode_blob("user", &"🔑".repeat(640)).is_ok());
        assert!(encode_blob("user", &"🔑".repeat(641)).is_err());
        // Over-long user name.
        assert!(encode_blob(&"u".repeat(514), "pw").is_err());
        assert!(encode_blob(&"u".repeat(513), "pw").is_ok());
    }

    #[test]
    fn blob_is_allocated_exactly_once() {
        let blob = encode_blob("u", "pässwörd日本🔑").unwrap();
        assert_eq!(blob.capacity(), blob.len(), "no growth reallocation");
        let back = decode_blob(&blob).unwrap();
        assert_eq!(back.capacity(), back.len(), "no growth reallocation");
    }

    #[test]
    fn utf16le_round_trips_via_encode_decode() {
        for pw in ["", "pässwörd日本🔑", "simple"] {
            let blob = encode_blob("u", pw).unwrap();
            let back = decode_blob(&blob).unwrap();
            assert_eq!(&*back, pw);
        }
        // Odd-length blob and unpaired surrogates are rejected.
        assert!(decode_blob(&[0x41]).is_err());
        assert!(decode_blob(&[0x00, 0xD8]).is_err());
    }

    #[test]
    fn persist_conflict_decision() {
        const LOCAL_MACHINE: u32 = 2;
        const ENTERPRISE: u32 = 3;
        assert!(needs_delete_before_write(Some(ENTERPRISE), LOCAL_MACHINE));
        assert!(!needs_delete_before_write(
            Some(LOCAL_MACHINE),
            LOCAL_MACHINE
        ));
        assert!(!needs_delete_before_write(None, LOCAL_MACHINE));
    }

    #[test]
    fn host_ids_are_validated() {
        let s = InMemoryStore::new();
        for bad in ["", "a/b", "a*", "a b", "x\0"] {
            let e = s.write_host(bad, SecretKind::Login, "u", "p").unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad:?}");
            assert!(s.delete_all(bad).is_err());
        }
    }

    #[test]
    fn in_memory_store_round_trip() {
        let s = InMemoryStore::new();
        assert!(s.read_host(HOST, SecretKind::Login).unwrap().is_none());
        s.write_host(HOST, SecretKind::Login, "HOST\\admin", "secret")
            .unwrap();
        let got = s.read_host(HOST, SecretKind::Login).unwrap().unwrap();
        assert_eq!(got.user, "HOST\\admin");
        assert_eq!(&*got.password, "secret");
        // Debug never leaks the password.
        assert!(!format!("{got:?}").contains("secret"));
        assert!(format!("{got:?}").contains("<redacted>"));
        // Case-insensitive targets, like the real vault.
        assert!(
            s.read_host(&HOST.to_uppercase(), SecretKind::Login)
                .unwrap()
                .is_some()
        );

        s.write_host(HOST, SecretKind::Sudo, "root", "sudopw")
            .unwrap();
        let list = s.list().unwrap();
        assert_eq!(list.len(), 2);

        assert_eq!(s.delete_all(HOST).unwrap(), 2);
        assert!(s.list().unwrap().is_empty());
        assert!(!s.delete_host(HOST, SecretKind::Login).unwrap());
    }

    #[test]
    fn prune_removes_only_unknown_hosts() {
        let s = InMemoryStore::new();
        let other = "22222222-0000-4000-8000-000000000002";
        s.write_host(HOST, SecretKind::Login, "a", "1").unwrap();
        s.write_host(other, SecretKind::Login, "b", "2").unwrap();
        s.write_host(other, SecretKind::KeyPassphrase, "b", "3")
            .unwrap();
        // An unrelated target and a test-namespace target are never touched.
        s.write("unrelated/thing", "x", "y").unwrap();
        s.write(
            &target_name_in(TEST_PREFIX, other, SecretKind::Login),
            "t",
            "t",
        )
        .unwrap();
        let removed = s.prune(&|id| id == HOST).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(removed.iter().all(|e| e.host_id == other));
        assert_eq!(s.list().unwrap().len(), 1);
        assert!(s.read("unrelated/thing").unwrap().is_some());
        assert_eq!(s.list_prefix(TEST_PREFIX).unwrap().len(), 1);
    }

    #[test]
    fn in_memory_store_rejects_over_long() {
        let s = InMemoryStore::new();
        assert!(
            s.write_host(HOST, SecretKind::Login, "u", &"a".repeat(1281))
                .is_err()
        );
    }

    /// Real Credential Manager tests. `#[ignore]`d: they write to the current user's vault, only
    /// under `wol-manager-test/`, and always delete what they create (also on panic).
    #[cfg(windows)]
    mod vault {
        use super::super::windows_impl::{persist_of, write_raw};
        use super::*;
        use windows_sys::Win32::Security::Credentials::{
            CRED_PERSIST_ENTERPRISE, CRED_PERSIST_LOCAL_MACHINE,
        };

        /// Deletes the given targets on drop (twice, to also catch a resurrected stale copy).
        struct Cleanup(Vec<String>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for t in &self.0 {
                    let _ = WindowsCredentialStore.delete(t);
                    let _ = WindowsCredentialStore.delete(t);
                }
            }
        }

        fn unique_id(tag: u32) -> String {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            format!(
                "{:08x}-{tag:04x}-4000-8000-{:012x}",
                std::process::id(),
                nanos & 0xFFFF_FFFF_FFFF
            )
        }

        #[test]
        #[ignore = "writes to the real Credential Manager (wol-manager-test/ only); run explicitly"]
        fn real_vault_round_trip() {
            let s = WindowsCredentialStore;
            assert!(WindowsCredentialStore::is_available());
            let id = unique_id(1);
            let login = target_name_in(TEST_PREFIX, &id, SecretKind::Login);
            let pass = target_name_in(TEST_PREFIX, &id, SecretKind::KeyPassphrase);
            let _cleanup = Cleanup(vec![login.clone(), pass.clone()]);

            // Not found -> None / false / not listed.
            assert!(s.read(&login).unwrap().is_none());
            assert!(!s.delete(&login).unwrap());
            assert!(
                s.list_prefix(TEST_PREFIX)
                    .unwrap()
                    .iter()
                    .all(|e| e.host_id != id)
            );

            // Write + read back (Japanese account, non-BMP password), stored as LOCAL_MACHINE.
            s.write(&login, r"管理者PC\Administrator", "pässwörd日本🔑")
                .unwrap();
            let got = s.read(&login).unwrap().unwrap();
            assert_eq!(got.user, r"管理者PC\Administrator");
            assert_eq!(&*got.password, "pässwörd日本🔑");
            assert!(!format!("{got:?}").contains("pässwörd"));
            assert_eq!(
                persist_of(&login).unwrap(),
                Some(CRED_PERSIST_LOCAL_MACHINE)
            );
            // Case-insensitive target lookup.
            assert!(s.read(&login.to_uppercase()).unwrap().is_some());

            // The OS accepts exactly MAX_BLOB_BYTES; one more unit is refused before the OS call
            // and leaves the stored value untouched.
            let max = "k".repeat(MAX_BLOB_BYTES / 2);
            s.write(&pass, "u", &max).unwrap();
            assert_eq!(
                s.read(&pass).unwrap().unwrap().password.len(),
                MAX_BLOB_BYTES / 2
            );
            let e = s
                .write(&pass, "u", &"k".repeat(MAX_BLOB_BYTES / 2 + 1))
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput);
            assert_eq!(&*s.read(&pass).unwrap().unwrap().password, &max);

            // Overwrite with the same persist keeps one entry.
            s.write(&login, "HOST\\admin", "second").unwrap();
            assert_eq!(&*s.read(&login).unwrap().unwrap().password, "second");

            // Enumerate under the test namespace (no passwords returned).
            let mine: Vec<_> = s
                .list_prefix(TEST_PREFIX)
                .unwrap()
                .into_iter()
                .filter(|e| e.host_id == id)
                .collect();
            assert_eq!(mine.len(), 2, "{mine:?}");
            assert!(
                mine.iter()
                    .any(|e| e.kind == SecretKind::Login && e.user == "HOST\\admin")
            );

            // Prune everything of this id (and nothing else) in the test namespace.
            let removed = s.prune_prefix(TEST_PREFIX, &|h| h != id).unwrap();
            assert_eq!(removed.len(), 2);
            assert!(s.read(&login).unwrap().is_none());
            assert!(s.read(&pass).unwrap().is_none());
            println!("real vault round trip OK for {TEST_PREFIX}{id}/*");
        }

        #[test]
        #[ignore = "writes to the real Credential Manager (wol-manager-test/ only); run explicitly"]
        fn real_vault_persist_conflict_is_deleted_then_rewritten() {
            let s = WindowsCredentialStore;
            let id = unique_id(2);
            let t = target_name_in(TEST_PREFIX, &id, SecretKind::Login);
            let _cleanup = Cleanup(vec![t.clone()]);

            // An entry with another Persist, as `cmdkey /generic` creates (ENTERPRISE).
            write_raw(&t, "old", "old-secret", CRED_PERSIST_ENTERPRISE).unwrap();
            assert_eq!(persist_of(&t).unwrap(), Some(CRED_PERSIST_ENTERPRISE));

            // The store deletes it first and recreates it as LOCAL_MACHINE.
            s.write(&t, "new", "new-secret").unwrap();
            assert_eq!(persist_of(&t).unwrap(), Some(CRED_PERSIST_LOCAL_MACHINE));
            assert_eq!(&*s.read(&t).unwrap().unwrap().password, "new-secret");

            // After a delete nothing comes back (the stale copy reappeared within ~3 s when the
            // persist was changed in place).
            assert!(s.delete(&t).unwrap());
            std::thread::sleep(std::time::Duration::from_secs(5));
            assert!(
                s.read(&t).unwrap().is_none(),
                "stale credential resurrected"
            );
            println!("persist conflict handled for {t}");
        }
    }
}
