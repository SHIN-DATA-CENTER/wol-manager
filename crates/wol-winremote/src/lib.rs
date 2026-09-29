//! Windows remote management for WoL Manager.
//!
//! This crate manages **other** Windows machines over SMB/RPC and WMI/DCOM, with per-host admin
//! credentials kept in Windows Credential Manager. It has no dependency on `wol-core`; the
//! integration layer (`wol-core::remote`) dispatches to it and translates its errors into localized
//! messages and CLI exit codes.
//!
//! # Capabilities
//! - [`boot_time`] — last kernel boot time over SMB (`NetRemoteTOD`, 49.7-day wrap resolved).
//! - [`power()`] / [`abort_shutdown`] — restart / shutdown / cancel, behind a mockable seam.
//! - [`mac_candidates`] — the physical NIC's MAC via WMI, for hosts reachable only over a VPN
//!   (where ARP has no MAC to read).
//! - [`test_connection`] — a combined reachability / OS / boot-time probe.
//! - [`secret`] — per-host secrets in Credential Manager, with an in-memory mock for tests.
//!
//! # Blocking
//! Every operation here is **blocking** and may take tens of seconds against an unreachable host
//! (SMB/DCOM connect timeouts). Callers run them on worker threads. Each function's own docs give
//! its worst case.
//!
//! # Safety
//! The OS shutdown APIs are reached only through a crate-private implementation of the
//! [`power::ShutdownBackend`] seam, constructed only by [`power()`] / [`abort_shutdown`] after they
//! refuse a target that is this PC (names, own addresses in any spelling, and names that resolve to
//! them). That backend panics in `cfg(test)` builds, so tests never shut anything down.
//!
//! # Error classification
//! [`Error`] carries a stable [`ErrorKind`], the failing [`Op`], the OS [`Code`] and an optional
//! [`Hint`]. The main Win32/NetAPI mappings are:
//!
//! | Code(s) | Kind | Hint | Notes |
//! |---|---|---|---|
//! | 5, 1314, 1385 | `AccessDenied` | `UacRemoteRestriction` (Power/Abort; WMI once authenticated) / `WmiAccessDenied` (WMI before) / `CheckCredentials` | |
//! | 53 | `Unreachable` (`SmbFirewall`) → `AccessDenied` (`UacRemoteRestriction`) when *reachable* on Power/Abort | | 53 from shutdown is ambiguous |
//! | 1722, 1727, 1753 | `Unreachable` (`SmbFirewall`; `WmiFirewall` for WMI; `RemoteShutdownFirewall` when reachable on Power/Abort) | | RPC unavailable / no endpoint |
//! | 1219 | `CredentialConflict` | `CloseOtherConnections` | one credential per server per session |
//! | 1312 | `SecretStoreUnavailable` (SecretStore) / `AuthFailed` (`StoreCredentials`) | | no credential set in this logon |
//! | 1115, 1190 | `ShutdownInProgress` | `RetryLater` | |
//! | 21 | `NotReady` | `RetryLater` | sign-in screen w/ fast user switching |
//! | 1191 | `UsersLoggedOn` | | other users signed in |
//! | 1116 | `NoShutdownInProgress` | | nothing to abort |
//! | 50, 3023 | `Unsupported` | | e.g. server statistics need SMB1 |
//! | 87 | `InvalidInput` | | 1783 / 2202 are `InvalidInput` only for SecretStore |
//! | 2102 | `Other` | | local Workstation service not started |
//! | 1326 and other auth codes | `AuthFailed` | `CheckCredentials` (`StoreCredentials` when no credential was given) | |
//!
//! WMI/DCOM `HRESULT`s: `E_ACCESSDENIED` / `WBEM_E_ACCESS_DENIED` → `AccessDenied`, with
//! `UacRemoteRestriction` once the credentials are proven or `WmiAccessDenied` (check both) before;
//! transport/timeout HRESULTs → `Unreachable` (`WmiFirewall`); invalid namespace/class/query →
//! `Unsupported`.

#![warn(missing_docs)]

pub mod boot;
pub mod error;
pub mod power;
pub mod secret;
pub mod wmi;

mod ipc;
mod local;
mod wide;

pub use boot::BootInfo;
pub use error::{Code, Error, ErrorKind, Hint, Op, Result};
#[cfg(windows)]
pub use ipc::cancel_owned_connections;
#[cfg(windows)]
pub use local::is_local_target;
pub use power::{PowerAction, PowerOptions, PowerOutcome};
pub use secret::{HostSecret, InMemoryStore, SecretKind, SecretStore, StoredEntry};
pub use wmi::{MacCandidate, NicKind};

use std::time::Duration;
use zeroize::Zeroizing;

/// A host to manage, with its optional admin credentials and connect timeout.
#[derive(Clone)]
pub struct RemoteHost {
    /// The management address or name (an IPv4/IPv6 literal or a host name), **without** leading
    /// backslashes. Every SMB/RPC call reuses this exact string (IPv6 literals are converted to
    /// the `ipv6-literal.net` UNC form).
    pub host: String,
    /// The account (`HOST\user`, `DOMAIN\user`, or `user@domain`). `None` uses the current Windows
    /// logon.
    pub user: Option<String>,
    /// The password, wiped on drop. `None` (or a missing `user`) uses the current logon.
    pub password: Option<Zeroizing<String>>,
    /// TCP pre-probe timeout for the reachability check before the blocking SMB/DCOM calls.
    pub connect_timeout: Duration,
}

impl std::fmt::Debug for RemoteHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteHost")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl RemoteHost {
    /// Creates a host with no stored credentials (uses the current logon) and a 5 s connect timeout.
    pub fn new(host: impl Into<String>) -> Self {
        RemoteHost {
            host: host.into(),
            user: None,
            password: None,
            connect_timeout: Duration::from_secs(5),
        }
    }

    /// Sets the credentials.
    pub fn with_credentials(
        mut self,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.user = Some(user.into());
        self.password = Some(Zeroizing::new(password.into()));
        self
    }

    /// The `(user, password)` pair when both are present.
    fn creds(&self) -> Option<(&str, &str)> {
        match (&self.user, &self.password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            _ => None,
        }
    }

    /// The server name for UNC / WMI paths: the host as given, or the `ipv6-literal.net` form of
    /// an IPv6 literal (a raw IPv6 address is not a valid UNC server name).
    fn server_name(&self) -> String {
        unc_server_name(&self.host)
    }

    /// The `\\host` string for SMB/RPC calls.
    fn unc(&self) -> String {
        format!(r"\\{}", self.server_name())
    }
}

/// `fe80::1%12` -> `fe80--1s12.ipv6-literal.net`; anything else unchanged.
fn unc_server_name(host: &str) -> String {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let (addr, zone) = match bare.split_once('%') {
        Some((a, z)) => (a, Some(z)),
        None => (bare, None),
    };
    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        let mut s = addr.replace(':', "-");
        if let Some(z) = zone {
            s.push('s');
            s.push_str(z);
        }
        s.push_str(".ipv6-literal.net");
        s
    } else {
        host.to_owned()
    }
}

/// Rejects host strings that cannot be a server name: empty, surrounding spaces, backslashes /
/// slashes (a UNC path, not a name), control characters, or longer than 255 characters.
fn validate_host(host: &str, op: Op) -> Result<()> {
    let bad = host.is_empty()
        || host.len() > 255
        || host.trim() != host
        || host
            .chars()
            .any(|c| c == '\\' || c == '/' || c.is_control() || c.is_whitespace());
    if bad {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            op,
            format!("invalid host name or address {host:?} (give it without leading \\\\)"),
        ));
    }
    Ok(())
}

/// The result of [`test_connection`].
#[derive(Clone, Debug)]
pub struct ConnInfo {
    /// The OS caption (e.g. `"Microsoft Windows 11 Pro"`), when WMI could be reached.
    pub os: Option<String>,
    /// The host's boot time.
    pub boot: BootInfo,
    /// Whether the account has a full administrative token, when it could be inferred (a WMI query
    /// succeeding implies an unfiltered admin token under the default namespace security; WMI
    /// refusing an account that SMB accepted implies the opposite). `None` when unknown.
    pub user_is_admin_or_root: Option<bool>,
    /// How the administrator check (the WMI query) ended, for the note under a successful test.
    pub admin_check: AdminCheck,
}

/// How the administrator check of [`test_connection`] ended. Remotely, a WMI query needs a full
/// administrator token, so its outcome tells whether restart / shutdown / "MAC from IP" will be
/// allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AdminCheck {
    /// Remote WMI answered: the account has a full administrator token.
    Admin,
    /// WMI refused the account ("access denied") although SMB accepted it: it is not an
    /// administrator of the host, or UAC remote restrictions filtered its token (KB951016;
    /// local accounts, including Microsoft accounts, of a workgroup PC).
    Denied,
    /// WMI could not be reached (TCP 135 closed, or its dynamic RPC ports filtered): firewall.
    Unreachable,
    /// WMI failed for another reason; rights unknown.
    Failed,
    /// The target is this PC: not checked (WMI works locally for any user).
    Local,
}

impl AdminCheck {
    /// `Some(true)` for [`AdminCheck::Admin`], `Some(false)` for [`AdminCheck::Denied`], else
    /// `None`.
    pub fn is_admin(self) -> Option<bool> {
        match self {
            AdminCheck::Admin => Some(true),
            AdminCheck::Denied => Some(false),
            AdminCheck::Unreachable | AdminCheck::Failed | AdminCheck::Local => None,
        }
    }

    /// The check's outcome for a failed WMI query.
    pub fn of_wmi_error(e: &Error) -> AdminCheck {
        match e.kind() {
            ErrorKind::AccessDenied => AdminCheck::Denied,
            ErrorKind::Unreachable => AdminCheck::Unreachable,
            _ => AdminCheck::Failed,
        }
    }
}

// ---- per-host serialization -----------------------------------------------------------------

/// The per-host mutex, keyed by the lowercased UNC server name (an IPC$ connection is per server
/// name and logon session). It covers the IPC$ part of an operation only: WMI (DCOM) does not use
/// that connection and can take minutes against a filtered host, so it runs outside the lock and
/// never holds up "cancel shutdown" or a power request (review C5). Poisoning is ignored: the
/// guarded state is
/// `()`, so a panic in one operation must not make every later operation on that host panic.
fn host_lock(host: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = map.lock().unwrap_or_else(|p| p.into_inner());
    g.entry(host.to_ascii_lowercase())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Runs `f` while holding the per-host lock.
fn with_host_lock<T>(host: &str, f: impl FnOnce() -> T) -> T {
    let lock = host_lock(host);
    let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());
    f()
}

/// TCP pre-probe: connect to `host:port` within `timeout`, mapping failure to
/// [`ErrorKind::Unreachable`] (hint: SMB firewall for 445, WMI firewall for 135; none when the
/// name does not resolve).
fn probe_tcp(host: &str, port: u16, timeout: Duration) -> Result<()> {
    use std::net::{TcpStream, ToSocketAddrs};
    let firewall_hint = match port {
        135 => Hint::WmiFirewall,
        _ => Hint::SmbFirewall,
    };
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            Error::new(
                ErrorKind::Unreachable,
                Op::Connect,
                format!("cannot resolve {host}: {e}"),
            )
        })?
        .collect();
    if addrs.is_empty() {
        return Err(Error::new(
            ErrorKind::Unreachable,
            Op::Connect,
            format!("{host} resolved to no addresses"),
        ));
    }
    let mut last = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    Err(Error::new(
        ErrorKind::Unreachable,
        Op::Connect,
        format!(
            "cannot reach {host}:{port}: {}",
            last.map(|e| e.to_string()).unwrap_or_default()
        ),
    )
    .with_hint(firewall_hint))
}

/// Without explicit credentials the current Windows logon was rejected: suggest storing an account
/// rather than "check the password" (there is none).
fn current_logon_hint(e: Error, has_creds: bool) -> Error {
    if !has_creds && e.hint() == Some(Hint::CheckCredentials) {
        e.with_hint(Hint::StoreCredentials)
    } else {
        e
    }
}

// ---- high-level operations ------------------------------------------------------------------

/// Refuses a target that is this PC: pure name / address match (any spelling), then a system name
/// resolution. Fails closed when this PC's addresses cannot be enumerated.
#[cfg(windows)]
fn ensure_not_local(host: &str, op: Op) -> Result<()> {
    match local::check_local_target_resolving(host) {
        Ok(false) => Ok(()),
        Ok(true) => Err(Error::new(
            ErrorKind::LocalTarget,
            op,
            format!("{host} is this computer; refusing"),
        )),
        Err(()) => Err(Error::new(
            ErrorKind::Other,
            op,
            format!("cannot enumerate this computer's addresses to rule out {host}; refusing"),
        )),
    }
}

/// Opens the IPC$ session and proves reachability + authentication with `NetRemoteTOD` (read-only,
/// any authenticated user), so that a later 5 / 53 from the shutdown RPC means *rights*.
#[cfg(windows)]
fn connect_and_verify(host: &RemoteHost) -> Result<(ipc::IpcSession, String)> {
    probe_tcp(&host.host, 445, host.connect_timeout)?;
    let unc = host.unc();
    let has_creds = host.creds().is_some();
    let session =
        ipc::IpcSession::open(&unc, host.creds()).map_err(|e| current_logon_hint(e, has_creds))?;
    boot::remote_tod(&unc).map_err(|e| current_logon_hint(e, has_creds))?;
    Ok((session, unc))
}

/// Restarts or shuts down a remote host.
///
/// Refuses an invalid host ([`ErrorKind::InvalidInput`]) and a host that is this PC
/// ([`ErrorKind::LocalTarget`]; the name is also resolved). Pre-probes TCP 445, opens an IPC$
/// session with the given credentials, proves it with `NetRemoteTOD`, then issues the request.
/// The result only means the request was **accepted**; confirm by polling boot time /
/// reachability.
///
/// # Blocking
/// Name resolution, up to `host.connect_timeout` for the pre-probe, then an SMB logon, one
/// `NetRemoteTOD` and one shutdown RPC. Worst case is tens of seconds if the shutdown endpoint is
/// filtered.
#[cfg(windows)]
pub fn power(host: &RemoteHost, action: PowerAction, opts: &PowerOptions) -> Result<PowerOutcome> {
    validate_host(&host.host, Op::Power)?;
    ensure_not_local(&host.host, Op::Power)?;
    with_host_lock(&host.server_name(), || {
        let (_ipc, unc) = connect_and_verify(host)?;
        // Reachable and authenticated: 5/53 now mean rights, not unreachability.
        power::power_with(&power::RealShutdown, &unc, true, action, opts)
    })
}

/// Cancels a pending shutdown on a remote host (Windows only). Refuses an invalid host and a host
/// that is this PC.
///
/// # Blocking
/// Name resolution, TCP pre-probe, an SMB logon, one `NetRemoteTOD` and one abort RPC.
#[cfg(windows)]
pub fn abort_shutdown(host: &RemoteHost) -> Result<()> {
    validate_host(&host.host, Op::Abort)?;
    ensure_not_local(&host.host, Op::Abort)?;
    with_host_lock(&host.server_name(), || {
        let (_ipc, unc) = connect_and_verify(host)?;
        power::abort_with(&power::RealShutdown, &unc, true)
    })
}

/// Reads the remote host's last boot time over SMB.
///
/// # Blocking
/// TCP pre-probe, an SMB logon and two NetAPI round-trips.
#[cfg(windows)]
pub fn boot_time(host: &RemoteHost) -> Result<BootInfo> {
    validate_host(&host.host, Op::BootTime)?;
    with_host_lock(&host.server_name(), || {
        probe_tcp(&host.host, 445, host.connect_timeout)?;
        let unc = host.unc();
        let has_creds = host.creds().is_some();
        let _ipc = ipc::IpcSession::open(&unc, host.creds())
            .map_err(|e| current_logon_hint(e, has_creds))?;
        boot::boot_time(&unc).map_err(|e| current_logon_hint(e, has_creds))
    })
}

/// Reads the physical-NIC MAC candidates of a remote host via WMI.
///
/// With credentials, and when TCP 445 answers, validates them over IPC$ first (so a wrong password
/// is reported as [`ErrorKind::AuthFailed`], not a WMI/UAC problem), then queries WMI over DCOM.
/// A closed 445 does not stop the WMI attempt. If the host is this PC, WMI is queried with the
/// process identity (WMI refuses explicit credentials locally).
///
/// # Blocking
/// TCP pre-probes (135, 445), possibly an SMB logon, and a DCOM/WMI session. Up to two minutes if
/// the WMI dynamic ports are filtered while 135 answers.
#[cfg(windows)]
pub fn mac_candidates(host: &RemoteHost) -> Result<Vec<MacCandidate>> {
    validate_host(&host.host, Op::Wmi)?;
    if local::is_exactly_local(&host.host) {
        // WMI refuses explicit credentials for "." / its own names and treats this PC's own IP
        // literals as remote (loopback DCOM logon with the given account). Query locally instead.
        return wmi::mac_candidates(".", None, false);
    }
    probe_tcp(&host.host, 135, host.connect_timeout)?;
    let creds = host.creds();
    // Validate credentials over IPC$ (445), under the per-host lock. A bad password / conflict
    // is fatal now; a closed or failing 445 only means the WMI error cannot be disambiguated
    // later.
    let validated = match creds {
        Some(_) if probe_tcp(&host.host, 445, host.connect_timeout).is_ok() => {
            with_host_lock(&host.server_name(), || {
                match ipc::IpcSession::open(&host.unc(), creds) {
                    Ok(session) => Ok(session.authenticated()),
                    Err(e)
                        if matches!(
                            e.kind(),
                            ErrorKind::AuthFailed | ErrorKind::CredentialConflict
                        ) =>
                    {
                        Err(e)
                    }
                    Err(_) => Ok(false),
                }
            })?
        }
        _ => false,
    };
    // Outside the per-host lock (see `host_lock`).
    wmi::mac_candidates(&host.server_name(), creds, validated)
}

/// Combined reachability / OS / boot-time probe for the GUI "接続テスト" and `wolm remote test`.
///
/// # Blocking
/// TCP pre-probe, an SMB logon, the boot-time NetAPI calls, then (only if TCP 135 answers) a
/// best-effort WMI OS query that can take up to two minutes when WMI's dynamic ports are filtered
/// (outside the per-host lock).
#[cfg(windows)]
pub fn test_connection(host: &RemoteHost) -> Result<ConnInfo> {
    validate_host(&host.host, Op::Connect)?;
    let (boot, authenticated) = with_host_lock(&host.server_name(), || -> Result<_> {
        probe_tcp(&host.host, 445, host.connect_timeout)?;
        let unc = host.unc();
        let has_creds = host.creds().is_some();
        let ipc = ipc::IpcSession::open(&unc, host.creds())
            .map_err(|e| current_logon_hint(e, has_creds))?;
        let boot = boot::boot_time(&unc).map_err(|e| current_logon_hint(e, has_creds))?;
        // The effective credentials are proven by NetRemoteTOD (explicit ones via our IPC$
        // session, or the current logon).
        Ok((boot, !has_creds || ipc.authenticated()))
    })?;
    // WMI is optional (needs admin + the WMI firewall group); remotely its success implies a
    // full admin token and "access denied" for an account SMB accepted implies a filtered /
    // non-admin token (review R3). Locally WMI works for any user, so nothing is inferred.
    let log_err = |e: &Error| log::debug!("WMI OS caption for {} failed: {e}", host.host);
    let (os, admin_check) = if local::is_exactly_local(&host.host) {
        let os = wmi::os_caption(".", None, true).inspect_err(log_err).ok();
        (os, AdminCheck::Local)
    } else if probe_tcp(&host.host, 135, host.connect_timeout).is_ok() {
        match wmi::os_caption(&host.server_name(), host.creds(), authenticated) {
            Ok(os) => (Some(os), AdminCheck::Admin),
            Err(e) => {
                log_err(&e);
                (None, AdminCheck::of_wmi_error(&e))
            }
        }
    } else {
        (None, AdminCheck::Unreachable)
    };
    Ok(ConnInfo {
        os,
        boot,
        user_is_admin_or_root: admin_check.is_admin(),
        admin_check,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_host_redacts_password() {
        let h = RemoteHost::new("100.105.1.2").with_credentials("HOST\\admin", "hunter2");
        let dbg = format!("{h:?}");
        assert!(!dbg.contains("hunter2"), "{dbg}");
        assert!(dbg.contains("<redacted>"));
        assert_eq!(h.creds(), Some(("HOST\\admin", "hunter2")));
        assert_eq!(h.unc(), r"\\100.105.1.2");
    }

    #[test]
    fn host_without_password_uses_current_logon() {
        let h = RemoteHost::new("host");
        assert_eq!(h.creds(), None);
        let mut h = RemoteHost::new("host");
        h.user = Some("u".into());
        assert_eq!(
            h.creds(),
            None,
            "a user without a password is the current logon"
        );
    }

    #[test]
    fn ipv6_literals_use_the_unc_literal_form() {
        assert_eq!(
            RemoteHost::new("fe80::1%12").unc(),
            r"\\fe80--1s12.ipv6-literal.net"
        );
        assert_eq!(
            RemoteHost::new("[2001:db8::5]").unc(),
            r"\\2001-db8--5.ipv6-literal.net"
        );
        assert_eq!(RemoteHost::new("pc-1.lan").unc(), r"\\pc-1.lan");
    }

    #[test]
    fn invalid_hosts_are_rejected() {
        for bad in [
            "", " host", "host ", r"\\host", "a/b", "a b", "x\0", "tab\t",
        ] {
            let e = validate_host(bad, Op::Power).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad:?}");
        }
        for ok in [
            "100.105.128.173",
            "DESKTOP-6FDOQLK",
            "pc.example.com",
            "fe80::1%12",
        ] {
            assert!(validate_host(ok, Op::Power).is_ok(), "{ok}");
        }
    }

    #[test]
    fn per_host_lock_is_stable_and_case_insensitive() {
        let a = host_lock("HostA");
        let b = host_lock("hosta");
        let c = host_lock("HostB");
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        assert!(!std::sync::Arc::ptr_eq(&a, &c));
    }

    #[test]
    fn a_panic_does_not_poison_the_host_forever() {
        // Regression: the lock was taken with `.expect("host lock poisoned")`, so one panicking
        // operation made every later operation on that host panic.
        let r = std::panic::catch_unwind(|| with_host_lock("poison-test", || panic!("boom")));
        assert!(r.is_err());
        assert_eq!(with_host_lock("POISON-TEST", || 7), 7);
    }

    #[test]
    fn probe_tcp_closed_local_port_is_unreachable_with_port_hint() {
        // A port that was just released on loopback: connection refused, no network involved.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let e = probe_tcp("127.0.0.1", port, Duration::from_millis(500)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unreachable);
        assert_eq!(e.op(), Op::Connect);
        assert_eq!(e.hint(), Some(Hint::SmbFirewall));
        // An open loopback listener passes.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = l.local_addr().unwrap().port();
        assert!(probe_tcp("127.0.0.1", open, Duration::from_millis(500)).is_ok());
    }

    /// Review R3: "access denied" from WMI (UAC-filtered or non-admin token) is told apart from
    /// an unreachable WMI and from other failures.
    #[test]
    fn admin_check_follows_the_wmi_outcome() {
        let denied = Error::from_win32(Op::Wmi, 5, "");
        assert_eq!(denied.kind(), ErrorKind::AccessDenied);
        assert_eq!(AdminCheck::of_wmi_error(&denied), AdminCheck::Denied);
        let unreachable = Error::from_win32(Op::Wmi, 1722, "");
        assert_eq!(
            AdminCheck::of_wmi_error(&unreachable),
            AdminCheck::Unreachable
        );
        let other = Error::new(ErrorKind::Unsupported, Op::Wmi, "x");
        assert_eq!(AdminCheck::of_wmi_error(&other), AdminCheck::Failed);
        assert_eq!(AdminCheck::Admin.is_admin(), Some(true));
        assert_eq!(AdminCheck::Denied.is_admin(), Some(false));
        for c in [
            AdminCheck::Unreachable,
            AdminCheck::Failed,
            AdminCheck::Local,
        ] {
            assert_eq!(c.is_admin(), None, "{c:?}");
        }
    }

    #[test]
    fn current_logon_failures_suggest_storing_credentials() {
        let e = Error::from_win32(Op::Connect, 1326, "");
        assert_eq!(
            current_logon_hint(e.clone(), false).hint(),
            Some(Hint::StoreCredentials)
        );
        assert_eq!(
            current_logon_hint(e, true).hint(),
            Some(Hint::CheckCredentials)
        );
    }

    /// The top-level power / abort entry points refuse every spelling of this PC before any
    /// network I/O. (Should the guard ever fail, the real backend still panics in test builds, and
    /// refuses local machine names itself, so this test can never shut this PC down.)
    #[cfg(windows)]
    #[test]
    fn power_and_abort_refuse_this_pc() {
        let mut targets: Vec<String> = [
            "127.0.0.1",
            "127.1",
            "2130706433",
            "0x7f.1",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1",
            "0.0.0.0",
            "localhost",
            "LOCALHOST.",
            ".",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        targets.extend(local::local_computer_names());
        targets.extend(
            local::local_unicast_ips()
                .unwrap()
                .iter()
                .map(|ip| ip.to_string()),
        );
        let opts = PowerOptions::default();
        for t in &targets {
            let h = RemoteHost::new(t.clone()).with_credentials("x", "y");
            for action in [PowerAction::Restart, PowerAction::Shutdown] {
                let e = power(&h, action, &opts).unwrap_err();
                assert_eq!(e.kind(), ErrorKind::LocalTarget, "{t}: {e}");
            }
            let e = abort_shutdown(&h).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::LocalTarget, "{t}: {e}");
        }
        // Empty / UNC-prefixed input never gets that far.
        for t in ["", r"\\127.0.0.1"] {
            let e = power(&RemoteHost::new(t), PowerAction::Shutdown, &opts).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{t:?}");
        }
    }
}
