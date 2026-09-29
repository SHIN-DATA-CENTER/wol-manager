//! Per-host secrets for remote management (v0.2.0): the Windows / SSH login password, the SSH
//! key passphrase and an optional separate sudo password.
//!
//! Secrets live in Windows Credential Manager (generic credentials, persisted for this Windows
//! user on this PC; see `wol-winremote`), never in `config.toml`, exports or portable data.
//! Target names: `wol-manager/host/<uuid-lowercase-hyphenated>/<kind>` with kind
//! `login` | `key-passphrase` | `sudo`; the credential's user name is the account.
//!
//! [`SecretStore`] is a cheap, cloneable facade (`Send + Sync`) over a [`SecretBackend`]:
//! [`CredentialManager`] (real) or [`MemoryBackend`] (tests; nothing leaves the process).
//! Calls are local and fast (well under a millisecond), but still I/O: the GUI calls them on
//! a worker thread.
//!
//! # Binding
//! A login or sudo password is **bound** to what it was saved for: the remote-management kind,
//! the management address and the SSH port ([`SecretBinding`], stored inside the credential
//! blob in front of the secret) and the account (the credential's user name). Remote
//! operations use a stored password only while the host still matches
//! ([`SecretStore::state`]). After an import, an edit or a kind switch that points the host
//! somewhere else, or at another account, the password is never sent: the operation fails
//! with [`crate::remote::RemoteFailure::SecretMismatch`] ("enter it again").
//!
//! * Store secrets with [`SecretStore::set_for_host`] (after the host is saved). The
//!   deprecated [`SecretStore::set`] writes unbound secrets, which remote operations refuse.
//! * [`SecretStore::rebind`] moves the binding when the **user** changed the management
//!   address or SSH port of the same account in the editor / CLI. Never call it after an
//!   import.
//! * The key passphrase only decrypts the local key file (it is never sent) and is not bound.
//!
//! # Shared namespace
//! The target names are the same for every copy of WoL Manager this Windows user runs on this
//! PC: the installed copy, a portable copy (which starts from a copy of the same
//! `config.toml`, so its hosts have the same ids) and any `--config-dir` /
//! `WOL_MANAGER_CONFIG_DIR` folder. So:
//! * a secret whose host is missing from *this* config may belong to another copy:
//!   [`SecretStore::orphans`] only lists candidates for the user to confirm (never prune
//!   automatically), and never lists hosts that exist in the config;
//! * deleting a host ([`forget_host`], [`forget_removed_hosts`]) also deletes what another
//!   copy may still use for that host id (accepted: the user deleted the host).
//!
//! # Confirmed use of the current Windows sign-in
//! A Windows host without a saved password connects with the Windows sign-in of the user
//! running WoL Manager (NTLM / Kerberos single sign-on). Automatic operations (the GUI's
//! automatic boot time) may only do that for a host the **user** confirmed on this PC: an
//! explicit action (editor save, `wolm remote set`, an operation the user started for the
//! host) records a marker next to the host's secrets, `<prefix><uuid>/sign-in`, bound to the
//! host's current management address like a password ([`SecretStore::confirm_sign_in`],
//! [`SecretStore::sign_in_confirmed`]). It holds no secret, is not a [`SecretKind`] and is
//! never listed; it lives outside `config.toml`, so an import can neither create it nor move it
//! to another address (a host an import added or re-pointed is not confirmed). It is deleted
//! with the host's secrets ([`SecretStore::delete_all`], [`forget_host`]).

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use uuid::Uuid;
use wol_winremote::SecretStore as _;
use zeroize::Zeroizing;

use crate::error::{Error, Result, SecretStoreFailure};
use crate::model::{Config, Host, HostId, RemoteConfig, RemoteKind, SCHEMA_VERSION};

/// Prefix of every production target name.
pub const TARGET_PREFIX: &str = wol_winremote::secret::TARGET_PREFIX;

/// Prefix for tests that touch the real Credential Manager (always cleaned up).
pub const TEST_TARGET_PREFIX: &str = "wol-manager-test/host/";

/// Longest secret [`SecretStore::set_for_host`] accepts, in UTF-16 code units. The Credential
/// Manager blob holds [`MAX_STORED_UNITS`]; the rest is reserved for the [`SecretBinding`].
pub const MAX_SECRET_UNITS: usize = 1000;

/// Longest value a [`SecretBackend`] stores, in UTF-16 code units (the Credential Manager blob
/// limit, 2560 bytes). Bound secrets are checked against [`MAX_SECRET_UNITS`] before the
/// binding is added, so test backends that apply this limit behave like the real one.
pub const MAX_STORED_UNITS: usize = wol_winremote::secret::MAX_BLOB_BYTES / 2;

/// Longest account (credential user name) a [`SecretBackend`] stores, in UTF-16 code units.
pub const MAX_USER_UNITS: usize = wol_winremote::secret::MAX_USER_UNITS;

/// Marks a stored value that carries its [`SecretBinding`]: `<SEAL_PREFIX><kind>\t<port>\t
/// <address>\0<secret>`. A NUL never occurs in a typed password.
const SEAL_PREFIX: &str = "\u{0}wolm-bound/1\u{0}";

/// Last part of the target name of the sign-in confirmation (see the module docs). Not a
/// [`SecretKind`], so listing, `status` and prune never see it.
pub const SIGN_IN_MARKER: &str = "sign-in";

/// Kind of a stored secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretKind {
    /// Windows administrator password, or SSH login password (also used for sudo unless a
    /// separate sudo password is configured).
    Login,
    /// Passphrase of the SSH private key.
    KeyPassphrase,
    /// Separate sudo password (SSH, sudo mode `separate`; `auto` uses it when stored).
    Sudo,
}

impl SecretKind {
    /// Every kind.
    pub const ALL: [SecretKind; 3] = [
        SecretKind::Login,
        SecretKind::KeyPassphrase,
        SecretKind::Sudo,
    ];

    /// `login` / `key-passphrase` / `sudo` (target name and command-line spelling).
    pub const fn as_str(self) -> &'static str {
        match self {
            SecretKind::Login => "login",
            SecretKind::KeyPassphrase => "key-passphrase",
            SecretKind::Sudo => "sudo",
        }
    }

    fn backend(self) -> wol_winremote::SecretKind {
        match self {
            SecretKind::Login => wol_winremote::SecretKind::Login,
            SecretKind::KeyPassphrase => wol_winremote::SecretKind::KeyPassphrase,
            SecretKind::Sudo => wol_winremote::SecretKind::Sudo,
        }
    }

    fn from_backend(k: wol_winremote::SecretKind) -> SecretKind {
        match k {
            wol_winremote::SecretKind::Login => SecretKind::Login,
            wol_winremote::SecretKind::KeyPassphrase => SecretKind::KeyPassphrase,
            wol_winremote::SecretKind::Sudo => SecretKind::Sudo,
        }
    }

    /// `true` for the secrets that are sent to the host (login, sudo) and therefore bound.
    pub const fn is_bound(self) -> bool {
        !matches!(self, SecretKind::KeyPassphrase)
    }
}

impl fmt::Display for SecretKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SecretKind {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match crate::normalize::normalize_input(s)
            .trim()
            .to_ascii_lowercase()
            .replace('_', "-")
            .as_str()
        {
            "login" | "password" => Ok(SecretKind::Login),
            "key-passphrase" | "passphrase" => Ok(SecretKind::KeyPassphrase),
            "sudo" => Ok(SecretKind::Sudo),
            _ => Err("expected one of: login | key-passphrase | sudo".to_owned()),
        }
    }
}

/// A secret read from the store. `Debug` never prints it.
///
/// From [`SecretStore::get`] `secret` is the plain secret. A [`SecretBackend`] stores and
/// returns the raw value (which starts with the binding for bound secrets).
#[derive(Clone)]
pub struct Secret {
    /// Account stored with the secret (may be empty).
    pub user: String,
    /// The secret, wiped on drop.
    pub secret: Zeroizing<String>,
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("user", &self.user)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// One stored secret (without the secret), for `wolm cred list` / prune.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretEntry {
    /// Host id from the target name.
    pub host_id: HostId,
    /// Kind.
    pub kind: SecretKind,
    /// Account stored with it.
    pub user: String,
}

/// Which secrets a host has (GUI "saved" markers). Existence only: see
/// [`SecretStore::state`] for whether a stored password is still usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct SecretStatus {
    /// Login password stored.
    pub login: bool,
    /// Key passphrase stored.
    pub key_passphrase: bool,
    /// Separate sudo password stored.
    pub sudo: bool,
}

impl SecretStatus {
    /// Flag for `kind`.
    pub fn has(&self, kind: SecretKind) -> bool {
        match kind {
            SecretKind::Login => self.login,
            SecretKind::KeyPassphrase => self.key_passphrase,
            SecretKind::Sudo => self.sudo,
        }
    }

    fn set(&mut self, kind: SecretKind) {
        match kind {
            SecretKind::Login => self.login = true,
            SecretKind::KeyPassphrase => self.key_passphrase = true,
            SecretKind::Sudo => self.sudo = true,
        }
    }
}

/// What a stored login / sudo password was saved for (public data, never secret): the
/// remote-management kind, the management address and the SSH port of the host at that time.
/// The account is the credential's user name. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SecretBinding {
    /// Windows or SSH.
    pub kind: RemoteKind,
    /// Management address (`remote.address`, else `address`), lower case, without a trailing
    /// dot.
    pub address: String,
    /// SSH port; 0 for Windows.
    pub port: u16,
}

fn normalize_address(a: &str) -> String {
    let t = a.trim();
    t.strip_suffix('.').unwrap_or(t).to_ascii_lowercase()
}

impl SecretBinding {
    /// The binding for `host` as it is now. `None` when it has no remote management or no
    /// management address.
    pub fn for_host(host: &Host) -> Option<SecretBinding> {
        let r = host.remote.as_ref()?;
        let address = normalize_address(&host.management_address()?.to_string());
        Some(SecretBinding {
            kind: r.kind,
            address,
            port: match r.kind {
                RemoteKind::Windows => 0,
                RemoteKind::Ssh => r.ssh_port(),
            },
        })
    }

    /// Short description for messages: `root@192.168.1.20:22 (SSH)`,
    /// `DESK\admin @ 192.168.1.20 (Windows)` (without the account when it is empty).
    pub fn label(&self, account: &str) -> String {
        let account = account.trim();
        match self.kind {
            RemoteKind::Ssh if account.is_empty() => {
                format!("{}:{} (SSH)", self.address, self.port)
            }
            RemoteKind::Ssh => format!("{account}@{}:{} (SSH)", self.address, self.port),
            RemoteKind::Windows if account.is_empty() => format!("{} (Windows)", self.address),
            RemoteKind::Windows => format!("{account} @ {} (Windows)", self.address),
        }
    }

    /// The value stored in the credential blob: this binding followed by `secret`. (Test
    /// backends can seed bound secrets with it.)
    pub fn seal(&self, secret: &str) -> Zeroizing<String> {
        let meta = format!("{}\t{}\t{}", self.kind.as_str(), self.port, self.address);
        let mut out = Zeroizing::new(String::with_capacity(
            SEAL_PREFIX.len() + meta.len() + 1 + secret.len(),
        ));
        out.push_str(SEAL_PREFIX);
        out.push_str(&meta);
        out.push('\0');
        out.push_str(secret);
        out
    }

    /// Splits a stored value into its binding (`None` for unbound values: older builds,
    /// [`SecretStore::set`], or edited outside WoL Manager) and the secret.
    pub fn unseal(stored: &str) -> (Option<SecretBinding>, Zeroizing<String>) {
        let Some(rest) = stored.strip_prefix(SEAL_PREFIX) else {
            return (None, Zeroizing::new(stored.to_owned()));
        };
        let Some((meta, secret)) = rest.split_once('\0') else {
            return (None, Zeroizing::new(stored.to_owned()));
        };
        let secret = Zeroizing::new(secret.to_owned());
        let mut parts = meta.splitn(3, '\t');
        let binding = (|| {
            let kind = match parts.next()? {
                "windows" => RemoteKind::Windows,
                "ssh" => RemoteKind::Ssh,
                _ => return None,
            };
            let port = parts.next()?.parse::<u16>().ok()?;
            let address = parts.next()?.to_owned();
            (!address.is_empty()).then_some(SecretBinding {
                kind,
                address,
                port,
            })
        })();
        (binding, secret)
    }
}

/// `true` when two account names mean the same account for `kind`. Windows: case-insensitive,
/// `.\user` = `user` (other prefixes are kept: `PC\user` and `user` can be different accounts).
/// SSH: exact (trimmed).
pub fn same_account(kind: RemoteKind, a: &str, b: &str) -> bool {
    match kind {
        RemoteKind::Windows => {
            crate::remote::windows_account(a).to_lowercase()
                == crate::remote::windows_account(b).to_lowercase()
        }
        RemoteKind::Ssh => a.trim() == b.trim(),
    }
}

/// The account a stored login / sudo password must belong to: SSH the login user, Windows
/// `remote.user` (`None`: a Windows host without a user name uses the account stored with the
/// password).
pub(crate) fn expected_account(r: &RemoteConfig) -> Option<&str> {
    match r.kind {
        RemoteKind::Windows => r.user(),
        RemoteKind::Ssh => Some(r.ssh_user()),
    }
}

/// The account [`SecretStore::set_for_host`] stores: SSH the login user; Windows `remote.user`,
/// else `user` (e.g. `wolm cred set --user`), else the current Windows sign-in.
fn account_to_store(r: &RemoteConfig, user: &str) -> String {
    match r.kind {
        RemoteKind::Ssh => r.ssh_user().to_owned(),
        RemoteKind::Windows => r
            .user()
            .map(str::to_owned)
            .or_else(|| Some(user.trim().to_owned()).filter(|u| !u.is_empty()))
            .or_else(crate::remote::current_windows_account)
            .unwrap_or_default(),
    }
}

/// `Ok` when a stored secret (with its binding) may be used for `host` as it is now; else the
/// description of what it was stored for (`""` = unknown: unbound).
pub(crate) fn check_usable(
    host: &Host,
    kind: SecretKind,
    stored: &Secret,
    binding: Option<&SecretBinding>,
) -> std::result::Result<(), String> {
    if !kind.is_bound() {
        return Ok(());
    }
    let stored_for = || binding.map(|b| b.label(&stored.user)).unwrap_or_default();
    let (Some(want), Some(r)) = (SecretBinding::for_host(host), host.remote.as_ref()) else {
        return Err(stored_for());
    };
    if binding != Some(&want) {
        return Err(stored_for());
    }
    match expected_account(r) {
        Some(acc) if !same_account(r.kind, acc, &stored.user) => Err(stored_for()),
        _ => Ok(()),
    }
}

/// Kind, normalized management address (`None` when there is none) and SSH port (0 for
/// Windows) of a managed host.
pub(crate) fn endpoint(h: &Host) -> Option<(RemoteKind, Option<String>, u16)> {
    let r = h.remote.as_ref()?;
    Some((
        r.kind,
        h.management_address()
            .map(|a| normalize_address(&a.to_string())),
        match r.kind {
            RemoteKind::Windows => 0,
            RemoteKind::Ssh => r.ssh_port(),
        },
    ))
}

/// `true` when `a` and `b` would use the same stored passwords: same kind, management address,
/// SSH port and account (both must be managed).
pub(crate) fn same_target(a: &Host, b: &Host) -> bool {
    let (Some(ra), Some(rb)) = (a.remote.as_ref(), b.remote.as_ref()) else {
        return false;
    };
    endpoint(a) == endpoint(b)
        && match (expected_account(ra), expected_account(rb)) {
            (Some(x), Some(y)) => same_account(ra.kind, x, y),
            (None, None) => true,
            _ => false,
        }
}

/// Whether a stored secret can be used for a host as it is now ([`SecretStore::state`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SecretState {
    /// Nothing stored.
    Missing,
    /// Stored for this host's current kind, account, management address and SSH port.
    Usable,
    /// Stored, but for another kind / account / address / port (or without a binding: saved
    /// by an older build or changed outside WoL Manager). Remote operations do not use it;
    /// the user has to enter it again. GUI: "saved (for another connection)".
    Stale {
        /// What it was stored for ([`SecretBinding::label`]); `""` when unknown.
        stored_for: String,
    },
}

/// Storage behind [`SecretStore`], addressed by full target names. Stores the value it is
/// given (bound secrets start with their binding, see [`SecretBinding::seal`]).
pub trait SecretBackend: Send + Sync {
    /// Reads a secret; `Ok(None)` when absent.
    fn read(&self, target: &str) -> Result<Option<Secret>>;
    /// Creates or replaces a secret.
    fn write(&self, target: &str, user: &str, secret: &str) -> Result<()>;
    /// Deletes a secret; `true` if it existed.
    fn delete(&self, target: &str) -> Result<bool>;
    /// Target names (with their user) starting with `prefix`.
    fn list(&self, prefix: &str) -> Result<Vec<(String, String)>>;
}

fn store_error(e: &wol_winremote::Error) -> Error {
    let failure = match e.kind() {
        wol_winremote::ErrorKind::SecretStoreUnavailable => SecretStoreFailure::Unavailable,
        wol_winremote::ErrorKind::InvalidInput => SecretStoreFailure::TooLong,
        _ => SecretStoreFailure::Other,
    };
    Error::SecretStore {
        failure,
        detail: e.to_string(),
    }
}

/// Windows Credential Manager (`CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`).
#[derive(Debug, Clone, Copy, Default)]
pub struct CredentialManager;

impl CredentialManager {
    /// `false` when Credential Manager cannot be used in this logon session (network / SSH
    /// logon): offer `--password-stdin` up front instead of failing later. Fast, local.
    pub fn is_available() -> bool {
        wol_winremote::secret::WindowsCredentialStore::is_available()
    }
}

impl SecretBackend for CredentialManager {
    fn read(&self, target: &str) -> Result<Option<Secret>> {
        let s = wol_winremote::secret::WindowsCredentialStore
            .read(target)
            .map_err(|e| store_error(&e))?;
        Ok(s.map(|s| Secret {
            user: s.user,
            secret: s.password,
        }))
    }

    fn write(&self, target: &str, user: &str, secret: &str) -> Result<()> {
        wol_winremote::secret::WindowsCredentialStore
            .write(target, user, secret)
            .map_err(|e| store_error(&e))
    }

    fn delete(&self, target: &str) -> Result<bool> {
        wol_winremote::secret::WindowsCredentialStore
            .delete(target)
            .map_err(|e| store_error(&e))
    }

    fn list(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let entries = wol_winremote::secret::WindowsCredentialStore
            .list_prefix(prefix)
            .map_err(|e| store_error(&e))?;
        Ok(entries
            .into_iter()
            .map(|e| {
                (
                    wol_winremote::secret::target_name_in(prefix, &e.host_id, e.kind),
                    e.user,
                )
            })
            .collect())
    }
}

/// In-memory backend for tests (and dry runs). Applies the Credential Manager size limits.
#[derive(Default)]
pub struct MemoryBackend {
    map: Mutex<BTreeMap<String, (String, Zeroizing<String>)>>,
}

impl MemoryBackend {
    /// Empty store.
    pub fn new() -> MemoryBackend {
        MemoryBackend::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, (String, Zeroizing<String>)>> {
        self.map.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl fmt::Debug for MemoryBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryBackend")
            .field("entries", &self.lock().len())
            .finish()
    }
}

impl SecretBackend for MemoryBackend {
    fn read(&self, target: &str) -> Result<Option<Secret>> {
        Ok(self.lock().get(target).map(|(u, s)| Secret {
            user: u.clone(),
            secret: s.clone(),
        }))
    }

    fn write(&self, target: &str, user: &str, secret: &str) -> Result<()> {
        if secret.encode_utf16().count() > MAX_STORED_UNITS
            || user.encode_utf16().count() > MAX_USER_UNITS
        {
            return Err(Error::SecretStore {
                failure: SecretStoreFailure::TooLong,
                detail: "secret or user name too long".to_owned(),
            });
        }
        self.lock().insert(
            target.to_owned(),
            (user.to_owned(), Zeroizing::new(secret.to_owned())),
        );
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<bool> {
        Ok(self.lock().remove(target).is_some())
    }

    fn list(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        Ok(self
            .lock()
            .iter()
            .filter(|(t, _)| t.starts_with(prefix))
            .map(|(t, (u, _))| (t.clone(), u.clone()))
            .collect())
    }
}

/// Facade over a [`SecretBackend`] with the target naming scheme. Cheap to clone.
#[derive(Clone)]
pub struct SecretStore {
    backend: Arc<dyn SecretBackend>,
    prefix: Arc<str>,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl SecretStore {
    /// Windows Credential Manager with the production prefix.
    pub fn system() -> SecretStore {
        SecretStore::with_backend(Arc::new(CredentialManager), TARGET_PREFIX)
    }

    /// A fresh in-memory store (tests).
    pub fn in_memory() -> SecretStore {
        SecretStore::with_backend(Arc::new(MemoryBackend::new()), TARGET_PREFIX)
    }

    /// Any backend with a target prefix (ending in `/`), e.g. [`TEST_TARGET_PREFIX`].
    pub fn with_backend(backend: Arc<dyn SecretBackend>, prefix: &str) -> SecretStore {
        SecretStore {
            backend,
            prefix: Arc::from(prefix),
        }
    }

    /// The target name prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Full target name of a secret: `<prefix><uuid-lowercase-hyphenated>/<kind>`.
    pub fn target(&self, host: HostId, kind: SecretKind) -> String {
        format!("{}{}/{}", self.prefix, host.hyphenated(), kind.as_str())
    }

    /// Reads a secret (the plain secret, without its binding). Remote operations do not use
    /// this: they check the binding ([`SecretStore::state`]).
    /// Errors: [`Error::SecretStore`].
    pub fn get(&self, host: HostId, kind: SecretKind) -> Result<Option<Secret>> {
        Ok(self.get_with_binding(host, kind)?.map(|(s, _)| s))
    }

    /// Reads a secret with its binding (`None` = unbound).
    pub(crate) fn get_with_binding(
        &self,
        host: HostId,
        kind: SecretKind,
    ) -> Result<Option<(Secret, Option<SecretBinding>)>> {
        Ok(self.backend.read(&self.target(host, kind))?.map(|raw| {
            let (binding, secret) = SecretBinding::unseal(&raw.secret);
            (
                Secret {
                    user: raw.user,
                    secret,
                },
                binding,
            )
        }))
    }

    /// `true` when the secret exists (usable or not).
    pub fn has(&self, host: HostId, kind: SecretKind) -> Result<bool> {
        Ok(self.status(host)?.has(kind))
    }

    /// Which secrets `host` has (existence only; one enumeration, no secret is read).
    pub fn status(&self, host: HostId) -> Result<SecretStatus> {
        let mut st = SecretStatus::default();
        for e in self.list()?.into_iter().filter(|e| e.host_id == host) {
            st.set(e.kind);
        }
        Ok(st)
    }

    /// Whether the stored secret of `kind` can be used for `host` as it is now (binding and
    /// account match). GUI: "saved" vs "saved for another connection, enter it again".
    /// Errors: [`Error::SecretStore`].
    pub fn state(&self, host: &Host, kind: SecretKind) -> Result<SecretState> {
        Ok(match self.get_with_binding(host.id, kind)? {
            None => SecretState::Missing,
            Some((s, b)) => match check_usable(host, kind, &s, b.as_ref()) {
                Ok(()) => SecretState::Usable,
                Err(stored_for) => SecretState::Stale { stored_for },
            },
        })
    }

    /// Creates or replaces a secret of `host`, bound to its current kind, management address
    /// and SSH port. Call it with the host **as saved** (after `Store::update`; an id that
    /// reading assigned, `ParseNote::AssignedIds`, is only final once written: call
    /// [`crate::store::Store::persist_assigned_ids`] first and use its config / `is_saved`).
    ///
    /// The account stored as the credential's user name: SSH the login user; Windows
    /// `remote.user`, else `user` (e.g. `wolm cred set --user`), else the current Windows
    /// sign-in ([`crate::remote::current_windows_account`]). Returns that account.
    ///
    /// Errors: [`Error::RemoteNotConfigured`], [`Error::RemoteNoAddress`],
    /// [`Error::SecretStore`] (`TooLong` above [`MAX_SECRET_UNITS`] UTF-16 units).
    pub fn set_for_host(
        &self,
        host: &Host,
        kind: SecretKind,
        user: &str,
        secret: &str,
    ) -> Result<String> {
        let r = host
            .remote
            .as_ref()
            .ok_or_else(|| Error::RemoteNotConfigured {
                host: host.name.clone(),
            })?;
        let binding = SecretBinding::for_host(host).ok_or_else(|| Error::RemoteNoAddress {
            host: host.name.clone(),
        })?;
        if secret.encode_utf16().count() > MAX_SECRET_UNITS {
            return Err(Error::SecretStore {
                failure: SecretStoreFailure::TooLong,
                detail: format!("the secret is longer than {MAX_SECRET_UNITS} characters"),
            });
        }
        let account = account_to_store(r, user);
        self.backend
            .write(&self.target(host.id, kind), &account, &binding.seal(secret))?;
        Ok(account)
    }

    /// Creates or replaces an **unbound** secret. Remote operations refuse unbound login /
    /// sudo passwords (`RemoteFailure::SecretMismatch`), so this only suits the key
    /// passphrase and low-level tools. Errors: [`Error::SecretStore`] (`TooLong` above 1280
    /// UTF-16 units).
    #[deprecated(
        since = "0.2.0",
        note = "use SecretStore::set_for_host: remote operations refuse unbound login / sudo passwords"
    )]
    pub fn set(&self, host: HostId, kind: SecretKind, user: &str, secret: &str) -> Result<()> {
        self.backend.write(&self.target(host, kind), user, secret)
    }

    /// Moves the binding of `before`'s usable secrets to `after` (same host id, same kind and
    /// account; only the management address and / or SSH port changed). Returns how many were
    /// rewritten. Stale secrets are never revived, and nothing happens when the kind or the
    /// account changed (the user has to enter the password again).
    ///
    /// Call it only after the **user** changed the address / port of this host in the editor
    /// or with the CLI, never after an import (an import must not make a stored password usable
    /// for another machine).
    pub fn rebind(&self, before: &Host, after: &Host) -> Result<usize> {
        if before.id != after.id {
            return Ok(0);
        }
        let (Some(rb), Some(ra)) = (before.remote.as_ref(), after.remote.as_ref()) else {
            return Ok(0);
        };
        if rb.kind != ra.kind {
            return Ok(0);
        }
        let Some(want) = SecretBinding::for_host(after) else {
            return Ok(0);
        };
        let mut n = 0;
        for kind in SecretKind::ALL {
            let Some((s, b)) = self.get_with_binding(before.id, kind)? else {
                continue;
            };
            if b.as_ref() == Some(&want) || check_usable(before, kind, &s, b.as_ref()).is_err() {
                continue;
            }
            if kind.is_bound()
                && let Some(acc) = expected_account(ra)
                && !same_account(ra.kind, acc, &s.user)
            {
                continue;
            }
            self.backend.write(
                &self.target(before.id, kind),
                &s.user,
                &want.seal(&s.secret),
            )?;
            n += 1;
        }
        Ok(n)
    }

    /// Deletes a secret; `true` if it existed.
    pub fn delete(&self, host: HostId, kind: SecretKind) -> Result<bool> {
        self.backend.delete(&self.target(host, kind))
    }

    /// Deletes every secret of `host` and its sign-in confirmation; returns how many secrets
    /// existed (the confirmation is not a secret and is not counted).
    pub fn delete_all(&self, host: HostId) -> Result<usize> {
        let mut n = 0;
        for kind in SecretKind::ALL {
            if self.delete(host, kind)? {
                n += 1;
            }
        }
        self.forget_sign_in(host)?;
        Ok(n)
    }

    /// Target name of the sign-in confirmation of `host`: `<prefix><uuid>/sign-in`.
    pub fn sign_in_target(&self, host: HostId) -> String {
        format!("{}{}/{SIGN_IN_MARKER}", self.prefix, host.hyphenated())
    }

    /// The binding a sign-in confirmation of `host` must have: a Windows host with a
    /// management address.
    fn sign_in_binding(host: &Host) -> Option<SecretBinding> {
        SecretBinding::for_host(host).filter(|b| b.kind == RemoteKind::Windows)
    }

    /// `true` when the user confirmed on this PC that `host` may be contacted with the current
    /// Windows sign-in at its **current** management address (see the module docs). `false`
    /// for other hosts, for a confirmation of another address (the host was re-pointed, e.g.
    /// by an import) and when none was recorded. Errors: [`Error::SecretStore`].
    pub fn sign_in_confirmed(&self, host: &Host) -> Result<bool> {
        let Some(want) = Self::sign_in_binding(host) else {
            return Ok(false);
        };
        Ok(match self.backend.read(&self.sign_in_target(host.id))? {
            Some(s) => SecretBinding::unseal(&s.secret).0.as_ref() == Some(&want),
            None => false,
        })
    }

    /// Records that the user confirmed contacting `host` (Windows) with the current Windows
    /// sign-in at its current management address. Only for an explicit user action for this
    /// host (editor save, `wolm remote set`, an operation the user started), **never** for an
    /// import or an automatic operation. Returns `true` when it was written now, `false` when
    /// the same confirmation already existed. Callers usually go through
    /// `RemoteClient::confirm_sign_in`, which records it only for hosts that use the sign-in.
    ///
    /// Errors: [`Error::RemoteNotConfigured`] (not a Windows host), [`Error::RemoteNoAddress`],
    /// [`Error::SecretStore`].
    pub fn confirm_sign_in(&self, host: &Host) -> Result<bool> {
        let want = match (host.remote_kind(), Self::sign_in_binding(host)) {
            (_, Some(b)) => b,
            (Some(RemoteKind::Windows), None) => {
                return Err(Error::RemoteNoAddress {
                    host: host.name.clone(),
                });
            }
            _ => {
                return Err(Error::RemoteNotConfigured {
                    host: host.name.clone(),
                });
            }
        };
        if self.sign_in_confirmed(host)? {
            return Ok(false);
        }
        let account = crate::remote::current_windows_account().unwrap_or_default();
        self.backend
            .write(&self.sign_in_target(host.id), &account, &want.seal(""))?;
        Ok(true)
    }

    /// Removes the sign-in confirmation of `host`; `true` if one existed.
    pub fn forget_sign_in(&self, host: HostId) -> Result<bool> {
        self.backend.delete(&self.sign_in_target(host))
    }

    /// Every secret under this store's prefix (sorted by host id, then kind). Target names
    /// that do not follow the scheme are skipped.
    pub fn list(&self) -> Result<Vec<SecretEntry>> {
        let mut v: Vec<SecretEntry> = self
            .backend
            .list(&self.prefix)?
            .into_iter()
            .filter_map(|(target, user)| {
                let rest = target.get(self.prefix.len()..)?;
                let (id, kind) = rest.rsplit_once('/')?;
                let host_id = Uuid::parse_str(id).ok()?;
                let kind = SecretKind::from_backend(wol_winremote::SecretKind::parse(kind)?);
                Some(SecretEntry {
                    host_id,
                    kind,
                    user,
                })
            })
            .collect();
        v.sort_by_key(|e| (e.host_id, e.kind));
        v.dedup_by_key(|e| (e.host_id, e.kind));
        Ok(v)
    }

    /// Candidates for `wolm cred prune`: secrets whose host is **not in `cfg`** (hosts that
    /// exist, managed or not, are never listed). Nothing is deleted.
    ///
    /// Other copies of WoL Manager of this Windows user share the store (see the module docs):
    /// show the list, say so, and delete only what the user confirmed.
    /// Errors: [`Error::NewerSchema`] for a newer-schema (read-only) view, which may have
    /// dropped hosts or tables this build cannot read; [`Error::SecretStore`].
    pub fn orphans(&self, cfg: &Config) -> Result<Vec<SecretEntry>> {
        if cfg.is_newer_schema() {
            return Err(Error::NewerSchema {
                found: cfg.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(self
            .list()?
            .into_iter()
            .filter(|e| cfg.get(e.host_id).is_none())
            .collect())
    }

    /// Deletes [`SecretStore::orphans`] and returns them. Only after the user confirmed the
    /// list (other copies of WoL Manager share the store); never automatically.
    /// Errors: as [`SecretStore::orphans`].
    pub fn prune(&self, cfg: &Config) -> Result<Vec<SecretEntry>> {
        let orphans = self.orphans(cfg)?;
        for e in &orphans {
            self.delete(e.host_id, e.kind)?;
        }
        Ok(orphans)
    }
}

impl SecretKind {
    /// The `wol-winremote` kind (for code that talks to that crate directly).
    pub fn to_backend(self) -> wol_winremote::SecretKind {
        self.backend()
    }
}

/// Best-effort cleanup after a host was deleted (or the user removed its remote management):
/// deletes every secret of `host` (and its sign-in confirmation), logs failures, returns how
/// many secrets were deleted. Never fails, so it can run after the config change is saved.
///
/// Other copies of WoL Manager of this Windows user (portable / installed / other settings
/// folders) that have a host with the same id lose its secrets too (see the module docs).
pub fn forget_host(store: &SecretStore, host: HostId) -> usize {
    match store.delete_all(host) {
        Ok(n) => n,
        Err(e) => {
            log::warn!("could not delete the secrets of host {host}: {e}");
            0
        }
    }
}

/// [`forget_host`] for every host that is in `before` but no longer in `after` (after
/// `transfer::import` in any mode, or a bulk delete). Hosts that are still there keep their
/// secrets, also when they lost remote management: a stored password is bound to its target
/// and is not used for anything else. Does nothing for newer-schema (read-only) views.
/// Returns how many secrets were deleted.
pub fn forget_removed_hosts(store: &SecretStore, before: &Config, after: &Config) -> usize {
    if before.is_newer_schema() || after.is_newer_schema() {
        log::warn!("not deleting secrets: the settings were written by a newer version");
        return 0;
    }
    before
        .hosts
        .iter()
        .filter(|h| after.get(h.id).is_none())
        .map(|h| forget_host(store, h.id))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RemoteConfig;

    fn host(name: &str, managed: bool) -> Host {
        let mut h = Host::new(name, "02:00:00:00:00:01".parse().unwrap());
        h.address = Some("192.168.1.20".parse().unwrap());
        if managed {
            h.remote = Some(RemoteConfig::new(RemoteKind::Ssh));
        }
        h
    }

    fn windows(name: &str, user: Option<&str>) -> Host {
        let mut h = host(name, false);
        let mut r = RemoteConfig::new(RemoteKind::Windows);
        r.user = user.map(str::to_owned);
        h.remote = Some(r);
        h
    }

    #[test]
    fn kinds_parse_and_print() {
        for k in SecretKind::ALL {
            assert_eq!(k.as_str().parse::<SecretKind>(), Ok(k));
            assert_eq!(SecretKind::from_backend(k.backend()), k);
            assert_eq!(k.backend().as_str(), k.as_str());
        }
        assert_eq!("KEY_PASSPHRASE".parse(), Ok(SecretKind::KeyPassphrase));
        assert!("pin".parse::<SecretKind>().is_err());
        assert_eq!(
            serde_json::to_string(&SecretKind::KeyPassphrase).unwrap(),
            "\"key-passphrase\""
        );
        assert!(SecretKind::Login.is_bound() && SecretKind::Sudo.is_bound());
        assert!(!SecretKind::KeyPassphrase.is_bound());
    }

    #[test]
    fn target_names_match_the_backend_scheme() {
        let s = SecretStore::in_memory();
        let id = Uuid::parse_str("1E9A5B2C-0000-4000-8000-00000000000A").unwrap();
        let t = s.target(id, SecretKind::KeyPassphrase);
        assert_eq!(
            t,
            "wol-manager/host/1e9a5b2c-0000-4000-8000-00000000000a/key-passphrase"
        );
        assert_eq!(
            t,
            wol_winremote::secret::target_name(
                &id.hyphenated().to_string(),
                wol_winremote::SecretKind::KeyPassphrase
            )
        );
    }

    #[test]
    fn seal_and_unseal() {
        let b = SecretBinding {
            kind: RemoteKind::Ssh,
            address: "nas.lan".into(),
            port: 2222,
        };
        let sealed = b.seal("pä\tss\0word");
        assert!(sealed.starts_with('\0'));
        let (got, secret) = SecretBinding::unseal(&sealed);
        assert_eq!(got.as_ref(), Some(&b));
        assert_eq!(&*secret, "pä\tss\0word");
        assert_eq!(b.label("pi"), "pi@nas.lan:2222 (SSH)");
        let w = SecretBinding {
            kind: RemoteKind::Windows,
            address: "100.105.1.2".into(),
            port: 0,
        };
        assert_eq!(
            w.label(r"DESK\admin"),
            r"DESK\admin @ 100.105.1.2 (Windows)"
        );
        assert_eq!(w.label(""), "100.105.1.2 (Windows)");
        // Unbound and malformed values.
        let (none, plain) = SecretBinding::unseal("legacy");
        assert!(none.is_none());
        assert_eq!(&*plain, "legacy");
        let (none, _) = SecretBinding::unseal("\u{0}wolm-bound/1\u{0}ipmi\t1\tx\0pw");
        assert!(none.is_none());
        // The longest management address (a 253-character host name, normalized without the
        // trailing dot) still leaves MAX_SECRET_UNITS for the secret, for both kinds.
        let mut h = host("long", true);
        h.address = Some(
            format!("{}.", vec!["a".repeat(63); 4].join(".").get(..253).unwrap())
                .parse()
                .unwrap(),
        );
        h.remote.as_mut().unwrap().port = Some(65535);
        for kind in [RemoteKind::Ssh, RemoteKind::Windows] {
            h.remote.as_mut().unwrap().kind = kind;
            let b = SecretBinding::for_host(&h).unwrap();
            assert_eq!(b.address.len(), 253);
            let sealed = b.seal(&"x".repeat(MAX_SECRET_UNITS));
            assert!(sealed.encode_utf16().count() <= 1280, "{kind}");
        }
    }

    #[test]
    fn account_rules() {
        use RemoteKind::*;
        assert!(same_account(Windows, r".\Admin", "admin"));
        assert!(same_account(Windows, r"DESK\Admin", r"desk\admin"));
        assert!(!same_account(Windows, r"DESK\admin", "admin"));
        assert!(same_account(Ssh, " pi ", "pi"));
        assert!(!same_account(Ssh, "Pi", "pi"));
    }

    #[test]
    fn memory_round_trip_status_delete_all() {
        let s = SecretStore::in_memory();
        let h = windows("desk", Some(r"PC\admin"));
        let a = h.id;
        assert!(s.get(a, SecretKind::Login).unwrap().is_none());
        assert_eq!(
            s.state(&h, SecretKind::Login).unwrap(),
            SecretState::Missing
        );
        assert_eq!(
            s.set_for_host(&h, SecretKind::Login, "ignored", "pässwörd")
                .unwrap(),
            r"PC\admin"
        );
        s.set_for_host(&h, SecretKind::Sudo, "", "sudo-pw").unwrap();
        let got = s.get(a, SecretKind::Login).unwrap().unwrap();
        assert_eq!(got.user, r"PC\admin");
        assert_eq!(&*got.secret, "pässwörd");
        assert!(!format!("{got:?}").contains("pässwörd"));
        assert_eq!(s.state(&h, SecretKind::Login).unwrap(), SecretState::Usable);
        assert_eq!(
            s.status(a).unwrap(),
            SecretStatus {
                login: true,
                key_passphrase: false,
                sudo: true
            }
        );
        assert!(s.has(a, SecretKind::Sudo).unwrap());
        // Replace.
        s.set_for_host(&h, SecretKind::Login, "", "new").unwrap();
        assert_eq!(
            &*s.get(a, SecretKind::Login).unwrap().unwrap().secret,
            "new"
        );
        assert!(s.delete(a, SecretKind::Sudo).unwrap());
        assert!(!s.delete(a, SecretKind::Sudo).unwrap());
        s.set_for_host(&h, SecretKind::KeyPassphrase, "", "pp")
            .unwrap();
        assert_eq!(s.delete_all(a).unwrap(), 2);
        assert!(s.list().unwrap().is_empty());
        // Too long (with room for the binding).
        let e = s
            .set_for_host(
                &h,
                SecretKind::Login,
                "u",
                &"x".repeat(MAX_SECRET_UNITS + 1),
            )
            .unwrap_err();
        assert!(matches!(
            e,
            Error::SecretStore {
                failure: SecretStoreFailure::TooLong,
                ..
            }
        ));
        assert_eq!(e.kind(), crate::ErrorKind::InvalidInput);
        s.set_for_host(&h, SecretKind::Login, "u", &"x".repeat(MAX_SECRET_UNITS))
            .unwrap();
        // Unmanaged / address-less hosts cannot bind.
        assert!(matches!(
            s.set_for_host(&host("plain", false), SecretKind::Login, "", "x"),
            Err(Error::RemoteNotConfigured { .. })
        ));
        let mut nowhere = host("nowhere", true);
        nowhere.address = None;
        assert!(matches!(
            s.set_for_host(&nowhere, SecretKind::Login, "", "x"),
            Err(Error::RemoteNoAddress { .. })
        ));
    }

    #[test]
    fn stored_account_per_kind() {
        let s = SecretStore::in_memory();
        // SSH: always the login user (the `user` argument is ignored).
        let mut ssh = host("pi", true);
        assert_eq!(
            s.set_for_host(&ssh, SecretKind::Login, "someone", "pw")
                .unwrap(),
            "root"
        );
        ssh.remote.as_mut().unwrap().user = Some("pi".into());
        assert_eq!(
            s.set_for_host(&ssh, SecretKind::Login, "", "pw").unwrap(),
            "pi"
        );
        // Windows without a user name: the given account, else the current sign-in.
        let w = windows("desk", None);
        assert_eq!(
            s.set_for_host(&w, SecretKind::Login, r" NAS\backup ", "pw")
                .unwrap(),
            r"NAS\backup"
        );
        assert_eq!(s.state(&w, SecretKind::Login).unwrap(), SecretState::Usable);
        assert_eq!(
            s.set_for_host(&w, SecretKind::Login, "", "pw").unwrap(),
            crate::remote::current_windows_account().unwrap_or_default()
        );
    }

    /// Review M2 / M3: a password is only usable for the kind, account, address and port it
    /// was saved for.
    #[test]
    fn binding_makes_changed_hosts_stale() {
        let s = SecretStore::in_memory();
        let mut h = host("nas", true);
        h.remote.as_mut().unwrap().user = Some("admin".into());
        s.set_for_host(&h, SecretKind::Login, "", "pw").unwrap();
        s.set_for_host(&h, SecretKind::KeyPassphrase, "", "pp")
            .unwrap();
        assert_eq!(s.state(&h, SecretKind::Login).unwrap(), SecretState::Usable);
        let stale = |h: &Host| s.state(h, SecretKind::Login).unwrap();
        let want_stale = SecretState::Stale {
            stored_for: "admin@192.168.1.20:22 (SSH)".into(),
        };
        // Re-pointed address (import), management address, port, user, kind.
        let mut x = h.clone();
        x.address = Some("203.0.113.66".parse().unwrap());
        assert_eq!(stale(&x), want_stale);
        let mut x = h.clone();
        x.remote.as_mut().unwrap().address = Some("100.64.0.9".parse().unwrap());
        assert_eq!(stale(&x), want_stale);
        let mut x = h.clone();
        x.remote.as_mut().unwrap().port = Some(2222);
        assert_eq!(stale(&x), want_stale);
        let mut x = h.clone();
        x.remote.as_mut().unwrap().user = Some("root".into());
        assert_eq!(stale(&x), want_stale);
        let mut x = h.clone();
        x.remote.as_mut().unwrap().kind = RemoteKind::Windows;
        assert_eq!(stale(&x), want_stale);
        let mut x = h.clone();
        x.remote = None;
        assert_eq!(stale(&x), want_stale);
        // Cosmetic differences are the same target.
        let mut x = h.clone();
        x.address = Some("192.168.1.20".parse().unwrap());
        x.remote.as_mut().unwrap().port = Some(22);
        assert_eq!(stale(&x), SecretState::Usable);
        // The key passphrase is local only: never stale.
        let mut x = h.clone();
        x.address = Some("203.0.113.66".parse().unwrap());
        assert_eq!(
            s.state(&x, SecretKind::KeyPassphrase).unwrap(),
            SecretState::Usable
        );
        // Unbound secrets (older builds, Credential Manager UI) are never usable.
        #[allow(deprecated)]
        s.set(h.id, SecretKind::Login, "admin", "legacy").unwrap();
        assert_eq!(
            stale(&h),
            SecretState::Stale {
                stored_for: String::new()
            }
        );
        assert_eq!(
            &*s.get(h.id, SecretKind::Login).unwrap().unwrap().secret,
            "legacy"
        );
        // Windows accounts compare case-insensitively; `.\u` = `u`; no user = any account.
        let mut w = windows("desk", Some(r".\Admin"));
        s.set_for_host(&w, SecretKind::Login, "", "pw").unwrap();
        w.remote.as_mut().unwrap().user = Some("admin".into());
        assert_eq!(s.state(&w, SecretKind::Login).unwrap(), SecretState::Usable);
        w.remote.as_mut().unwrap().user = None;
        assert_eq!(s.state(&w, SecretKind::Login).unwrap(), SecretState::Usable);
        w.remote.as_mut().unwrap().user = Some(r"DESK\other".into());
        assert!(matches!(
            s.state(&w, SecretKind::Login).unwrap(),
            SecretState::Stale { .. }
        ));
    }

    #[test]
    fn rebind_moves_only_usable_secrets_of_the_same_account() {
        let s = SecretStore::in_memory();
        let mut before = host("nas", true);
        before.remote.as_mut().unwrap().user = Some("pi".into());
        s.set_for_host(&before, SecretKind::Login, "", "pw")
            .unwrap();
        s.set_for_host(&before, SecretKind::Sudo, "", "sudo")
            .unwrap();
        s.set_for_host(&before, SecretKind::KeyPassphrase, "", "pp")
            .unwrap();
        // The user changed the address (DHCP) and the port in the editor.
        let mut after = before.clone();
        after.address = Some("192.168.1.21".parse().unwrap());
        after.remote.as_mut().unwrap().port = Some(2222);
        assert!(matches!(
            s.state(&after, SecretKind::Login).unwrap(),
            SecretState::Stale { .. }
        ));
        assert_eq!(s.rebind(&before, &after).unwrap(), 3);
        assert_eq!(
            s.state(&after, SecretKind::Login).unwrap(),
            SecretState::Usable
        );
        assert_eq!(
            &*s.get(after.id, SecretKind::Sudo).unwrap().unwrap().secret,
            "sudo"
        );
        assert_eq!(s.rebind(&after, &after).unwrap(), 0);
        // Another account or kind: nothing is moved.
        let mut other_user = after.clone();
        other_user.remote.as_mut().unwrap().user = Some("root".into());
        other_user.address = Some("192.168.1.22".parse().unwrap());
        assert_eq!(s.rebind(&after, &other_user).unwrap(), 1); // the passphrase only
        assert!(matches!(
            s.state(&other_user, SecretKind::Login).unwrap(),
            SecretState::Stale { .. }
        ));
        let mut win = after.clone();
        win.remote.as_mut().unwrap().kind = RemoteKind::Windows;
        assert_eq!(s.rebind(&after, &win).unwrap(), 0);
        // A stale secret is never revived by a rebind.
        let fresh = SecretStore::in_memory();
        fresh
            .set_for_host(&before, SecretKind::Login, "", "pw")
            .unwrap();
        let mut elsewhere = before.clone();
        elsewhere.address = Some("203.0.113.66".parse().unwrap());
        let mut target = before.clone();
        target.address = Some("192.168.1.30".parse().unwrap());
        assert_eq!(fresh.rebind(&elsewhere, &target).unwrap(), 0);
        assert!(matches!(
            fresh.state(&target, SecretKind::Login).unwrap(),
            SecretState::Stale { .. }
        ));
        // Different hosts: nothing.
        let mut other = after.clone();
        other.id = Uuid::new_v4();
        assert_eq!(s.rebind(&after, &other).unwrap(), 0);
    }

    /// Review M5: prune never touches hosts that exist, and refuses newer-schema views.
    #[test]
    fn list_prune_and_forget() {
        let backend = Arc::new(MemoryBackend::new());
        let s = SecretStore::with_backend(backend.clone(), TARGET_PREFIX);
        let kept = host("kept", true);
        let unmanaged = host("unmanaged", false);
        let gone = Uuid::new_v4();
        let cfg = Config {
            hosts: vec![kept.clone(), unmanaged.clone()],
            ..Config::default()
        };
        s.set_for_host(&kept, SecretKind::Login, "root", "a")
            .unwrap();
        backend
            .write(&s.target(unmanaged.id, SecretKind::Login), "root", "b")
            .unwrap();
        backend
            .write(&s.target(gone, SecretKind::KeyPassphrase), "", "c")
            .unwrap();
        // Foreign / malformed entries are ignored.
        backend
            .write("wol-manager/host/not-a-uuid/login", "", "x")
            .unwrap();
        backend.write("other-app/secret", "", "x").unwrap();
        assert_eq!(s.list().unwrap().len(), 3);
        let orphans = s.orphans(&cfg).unwrap();
        assert_eq!(
            orphans.iter().map(|e| e.host_id).collect::<Vec<_>>(),
            vec![gone]
        );
        assert_eq!(s.prune(&cfg).unwrap().len(), 1);
        assert_eq!(s.list().unwrap().len(), 2);
        assert!(s.has(kept.id, SecretKind::Login).unwrap());
        assert!(s.has(unmanaged.id, SecretKind::Login).unwrap());
        // A newer-schema view may lack hosts / tables this build cannot read: no pruning.
        let mut newer = cfg.clone();
        newer.schema_version = SCHEMA_VERSION + 1;
        newer.hosts.clear();
        assert!(matches!(s.orphans(&newer), Err(Error::NewerSchema { .. })));
        assert!(matches!(s.prune(&newer), Err(Error::NewerSchema { .. })));
        assert_eq!(forget_removed_hosts(&s, &cfg, &newer), 0);
        assert_eq!(s.list().unwrap().len(), 2);

        // forget_removed_hosts: only removed hosts; losing remote management keeps them.
        let mut after = cfg.clone();
        after.hosts[1].remote = None;
        after.hosts[0].remote = None;
        assert_eq!(forget_removed_hosts(&s, &cfg, &after), 0);
        after.hosts.retain(|h| h.id != kept.id);
        assert_eq!(forget_removed_hosts(&s, &cfg, &after), 1);
        assert!(!s.has(kept.id, SecretKind::Login).unwrap());
        s.set_for_host(&kept, SecretKind::Sudo, "", "d").unwrap();
        assert_eq!(forget_host(&s, kept.id), 1);
        assert_eq!(forget_host(&s, kept.id), 0);
    }

    /// Cross review X2: the confirmation to use the current Windows sign-in is bound to the host
    /// and its management address, is not a secret (never listed, counted or pruned) and goes
    /// with the host.
    #[test]
    fn sign_in_confirmation_is_bound_and_not_listed() {
        let backend = Arc::new(MemoryBackend::new());
        let s = SecretStore::with_backend(backend.clone(), TARGET_PREFIX);
        let mut pc = windows("pc", None);
        assert!(!s.sign_in_confirmed(&pc).unwrap());
        assert!(s.confirm_sign_in(&pc).unwrap(), "written now");
        assert!(!s.confirm_sign_in(&pc).unwrap(), "already there");
        assert!(s.sign_in_confirmed(&pc).unwrap());
        assert!(
            backend
                .read(&format!("wol-manager/host/{}/sign-in", pc.id.hyphenated()))
                .unwrap()
                .is_some()
        );
        // Not a secret: invisible to list / status / orphans / prune.
        assert!(s.list().unwrap().is_empty());
        assert_eq!(s.status(pc.id).unwrap(), SecretStatus::default());
        let cfg = Config::default();
        assert!(s.prune(&cfg).unwrap().is_empty());
        assert!(s.sign_in_confirmed(&pc).unwrap(), "prune leaves it");
        // Another management address (an import re-pointed the host) or kind: not confirmed.
        let mut moved = pc.clone();
        moved.address = Some("203.0.113.66".parse().unwrap());
        assert!(!s.sign_in_confirmed(&moved).unwrap());
        let mut via = pc.clone();
        via.remote.as_mut().unwrap().address = Some("100.64.0.9".parse().unwrap());
        assert!(!s.sign_in_confirmed(&via).unwrap());
        let mut ssh = pc.clone();
        ssh.remote.as_mut().unwrap().kind = RemoteKind::Ssh;
        assert!(!s.sign_in_confirmed(&ssh).unwrap());
        // Another host id (an import adding a copy) is not confirmed either.
        let mut other = pc.clone();
        other.id = Uuid::new_v4();
        assert!(!s.sign_in_confirmed(&other).unwrap());
        // A new explicit confirmation follows the new address.
        assert!(s.confirm_sign_in(&moved).unwrap());
        assert!(s.sign_in_confirmed(&moved).unwrap() && !s.sign_in_confirmed(&pc).unwrap());
        // Only Windows hosts with an address can be confirmed.
        assert!(matches!(
            s.confirm_sign_in(&ssh),
            Err(Error::RemoteNotConfigured { .. })
        ));
        let mut nowhere = pc.clone();
        nowhere.address = None;
        assert!(matches!(
            s.confirm_sign_in(&nowhere),
            Err(Error::RemoteNoAddress { .. })
        ));
        // Deleted with the host's secrets, but not counted as one.
        s.set_for_host(&moved, SecretKind::Login, "", "pw").unwrap();
        assert_eq!(forget_host(&s, moved.id), 1);
        assert!(!s.sign_in_confirmed(&moved).unwrap());
        assert!(backend.list("").unwrap().is_empty());
        s.confirm_sign_in(&pc).unwrap();
        assert!(s.forget_sign_in(pc.id).unwrap());
        assert!(!s.forget_sign_in(pc.id).unwrap());
        pc.remote = None;
        assert!(!s.sign_in_confirmed(&pc).unwrap());
    }

    /// The real Credential Manager, under the test prefix only; always cleaned up.
    #[test]
    fn credential_manager_round_trip_with_test_prefix() {
        struct Cleanup(SecretStore, HostId);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.0.delete_all(self.1);
            }
        }
        let s = SecretStore::with_backend(Arc::new(CredentialManager), TEST_TARGET_PREFIX);
        let h = windows("cm-test", Some(r".\tester"));
        let id = h.id;
        let _cleanup = Cleanup(s.clone(), id);
        assert!(
            s.target(id, SecretKind::Login)
                .starts_with("wol-manager-test/")
        );
        match s.set_for_host(&h, SecretKind::Login, "", "pw-日本語🔑") {
            Ok(_) => {}
            Err(Error::SecretStore {
                failure: SecretStoreFailure::Unavailable,
                ..
            }) => {
                eprintln!("Credential Manager unavailable in this session; skipped");
                return;
            }
            Err(e) => panic!("{e}"),
        }
        let got = s.get(id, SecretKind::Login).unwrap().unwrap();
        assert_eq!(got.user, r".\tester");
        assert_eq!(&*got.secret, "pw-日本語🔑");
        assert_eq!(s.state(&h, SecretKind::Login).unwrap(), SecretState::Usable);
        assert!(s.has(id, SecretKind::Login).unwrap());
        assert!(!s.has(id, SecretKind::Sudo).unwrap());
        let mine: Vec<SecretEntry> = s
            .list()
            .unwrap()
            .into_iter()
            .filter(|e| e.host_id == id)
            .collect();
        assert_eq!(
            mine,
            vec![SecretEntry {
                host_id: id,
                kind: SecretKind::Login,
                user: r".\tester".into()
            }]
        );
        // The sign-in confirmation: stored, never enumerated as a secret, deleted with them.
        assert!(s.confirm_sign_in(&h).unwrap());
        assert!(s.sign_in_confirmed(&h).unwrap());
        assert_eq!(
            s.list().unwrap().iter().filter(|e| e.host_id == id).count(),
            1
        );
        assert_eq!(s.delete_all(id).unwrap(), 1);
        assert!(s.get(id, SecretKind::Login).unwrap().is_none());
        assert!(!s.sign_in_confirmed(&h).unwrap());
    }
}
