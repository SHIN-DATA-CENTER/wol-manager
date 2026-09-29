//! Error type of the crate: a classified [`ErrorKind`], the failing [`Op`], the OS [`Code`]
//! and an optional remediation [`Hint`].
//!
//! Callers (wol-core) translate `kind` + `hint` into localized messages and CLI exit codes; the
//! English [`Display`](std::fmt::Display) text is meant for logs and as a fallback.

use std::fmt;

/// What went wrong, independent of the OS error code. Stable for i18n and exit codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Invalid argument: bad host name, too-long secret / message, malformed secret target.
    InvalidInput,
    /// Restart / shutdown / abort was requested for the computer this program runs on.
    /// Refused on purpose (the app manages other machines).
    LocalTarget,
    /// Network problem: name resolution failed, TCP 445 / 135 not reachable, SMB path not
    /// found, RPC server unavailable, timeout.
    Unreachable,
    /// The target rejected the user name / password (wrong password, unknown user, account
    /// locked / disabled / expired), or the current logon has no usable network credentials.
    AuthFailed,
    /// Authenticated but not allowed: not an administrator, UAC remote restrictions on a local
    /// account (see [`Hint::UacRemoteRestriction`]), DCOM / WMI permissions.
    AccessDenied,
    /// Windows error 1219: this Windows logon already has a connection to the same server name
    /// with different credentials (Explorer window, mapped drive, `net use`).
    CredentialConflict,
    /// A shutdown / restart is already in progress or scheduled on the target (1115, 1190).
    ShutdownInProgress,
    /// The target is not ready (21): typically the sign-in screen with fast user switching.
    NotReady,
    /// Other users are signed in to the target and the request did not force (1191).
    UsersLoggedOn,
    /// `abort_shutdown`: there was no pending shutdown to cancel (1116).
    NoShutdownInProgress,
    /// Windows Credential Manager is not available in this logon session (1312, e.g. inside an
    /// SSH or other network logon on the controlling PC).
    SecretStoreUnavailable,
    /// The target does not support the query (old Windows without `root\StandardCimv2`, SMB1-only
    /// statistics, ...), or returned unusable data.
    Unsupported,
    /// Any other failure; see [`Error::code`] and the detail text.
    Other,
}

/// Remediation hint attached to some errors. Callers render their own localized text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Hint {
    /// Local (non-domain) administrator accounts get a filtered token over the network (UAC
    /// remote restrictions, Microsoft KB951016, `LocalAccountTokenFilterPolicy`). Use a domain
    /// admin / the built-in Administrator, or change the policy on the target knowingly.
    UacRemoteRestriction,
    /// Allow "File and Printer Sharing (SMB-In)" (TCP 445) on the target from this PC / the VPN range.
    SmbFirewall,
    /// Enable the "Windows Management Instrumentation (WMI)" firewall rule group on the target
    /// (DCOM TCP 135 + dynamic ports).
    WmiFirewall,
    /// The remote-shutdown RPC endpoint was unavailable although SMB works: check the target's
    /// "Remote Shutdown" / "Remote Service Management" firewall groups.
    RemoteShutdownFirewall,
    /// A WMI/DCOM call returned access-denied and the credentials have **not** been proven yet
    /// (no successful IPC$ or `NetRemoteTOD`). It can mean either a wrong password or UAC remote
    /// restrictions / missing DCOM rights, so ask the user to check both.
    WmiAccessDenied,
    /// Check user name and password. Local accounts: `TARGETPC\user`; domain: `DOMAIN\user` or
    /// `user@domain`; Microsoft account: the e-mail address with the account password (not the PIN).
    CheckCredentials,
    /// No credential is stored for this host and the current Windows logon was not accepted:
    /// store an administrator account for the host.
    StoreCredentials,
    /// Close the other connection to the same server (`net use`, Explorer, mapped drive) or use
    /// another address / name for the host.
    CloseOtherConnections,
    /// Temporary state on the target; try again later.
    RetryLater,
}

/// Operation during which an error happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Op {
    /// Validating arguments.
    Validate,
    /// Resolving the host / TCP pre-probe / IPC$ connection.
    Connect,
    /// Reading the boot time (NetRemoteTOD / workstation statistics).
    BootTime,
    /// Restart or shutdown request.
    Power,
    /// Cancelling a pending shutdown.
    Abort,
    /// WMI query (MAC candidates, OS information).
    Wmi,
    /// Windows Credential Manager access.
    SecretStore,
}

impl Op {
    fn describe(self) -> &'static str {
        match self {
            Op::Validate => "invalid request",
            Op::Connect => "connection failed",
            Op::BootTime => "reading the boot time failed",
            Op::Power => "restart/shutdown request failed",
            Op::Abort => "cancelling the shutdown failed",
            Op::Wmi => "WMI query failed",
            Op::SecretStore => "Credential Manager access failed",
        }
    }
}

/// OS-level error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    /// Win32 / NetAPI error (`GetLastError`, `WIN32_ERROR`, `NET_API_STATUS`).
    Win32(u32),
    /// COM / WMI `HRESULT`.
    HResult(i32),
}

impl Code {
    /// The Win32 error code, also for `HRESULT_FROM_WIN32` values (facility 7).
    pub fn win32(self) -> Option<u32> {
        match self {
            Code::Win32(c) => Some(c),
            Code::HResult(hr) => {
                let u = hr as u32;
                (u & 0xFFFF_0000 == 0x8007_0000).then_some(u & 0xFFFF)
            }
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Code::Win32(c) => write!(f, "error {c}"),
            Code::HResult(hr) => write!(f, "HRESULT {:#010X}", *hr as u32),
        }
    }
}

/// Error returned by every fallible function of this crate. Cheap to clone; never contains secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    op: Op,
    code: Option<Code>,
    hint: Option<Hint>,
    detail: String,
}

impl Error {
    /// Builds an error. `detail` is free English text for logs (host, port, API name ...).
    pub fn new(kind: ErrorKind, op: Op, detail: impl Into<String>) -> Self {
        Error {
            kind,
            op,
            code: None,
            hint: None,
            detail: detail.into(),
        }
    }

    /// Classified kind (stable; use this for i18n and exit codes).
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The operation that failed.
    pub fn op(&self) -> Op {
        self.op
    }

    /// OS error code, when the failure came from a Win32 / COM call.
    pub fn code(&self) -> Option<Code> {
        self.code
    }

    /// Remediation hint, when one applies.
    pub fn hint(&self) -> Option<Hint> {
        self.hint
    }

    /// Free-form detail text for logs (never contains secrets). It usually names the failing API
    /// and the host/port. When the error came from a COM/WMI call via `Error::from_windows`, it
    /// may also carry the OS-formatted message, which is **localized** to the controlling PC's
    /// display language. Do not parse it or show it as the primary user message; use
    /// [`Error::kind`] and [`Error::hint`] for that.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the error with `code` set.
    pub fn with_code(mut self, code: Code) -> Self {
        self.code = Some(code);
        self
    }

    /// Returns the error with `hint` set (replacing any previous hint).
    pub fn with_hint(mut self, hint: Hint) -> Self {
        self.hint = Some(hint);
        self
    }

    /// Classifies a Win32 / NetAPI error code with reachability/authentication unknown.
    ///
    /// Use this at the connection stage (before an IPC$ session or `NetRemoteTOD` has succeeded).
    /// Once the target is proven reachable and the credentials accepted, prefer
    /// [`Error::from_win32_reachable`], which resolves the ambiguity of codes 5 and 53 on
    /// [`Op::Power`] / [`Op::Abort`]. The full mapping is documented at the crate root.
    pub fn from_win32(op: Op, code: u32, detail: impl Into<String>) -> Self {
        Self::from_win32_reachable(op, code, false, detail)
    }

    /// Classifies a Win32 / NetAPI error code, given whether the target has already been proven
    /// reachable **and** the credentials accepted (a successful IPC$ connection or `NetRemoteTOD`).
    ///
    /// When `reachable` is `true`, ambiguous shutdown/abort codes are re-interpreted:
    /// - 5 / 53 / 1314 / 1385 become [`ErrorKind::AccessDenied`] with
    ///   [`Hint::UacRemoteRestriction`] (the research shows `WsdrInitiateShutdown` returns 53 and
    ///   `BaseInitiateShutdownEx` returns 5 for *insufficient privilege*, not unreachability);
    /// - 1722 / 1727 (RPC unavailable) become [`ErrorKind::Unreachable`] with
    ///   [`Hint::RemoteShutdownFirewall`], because SMB works but the shutdown RPC endpoint does not.
    pub fn from_win32_reachable(
        op: Op,
        code: u32,
        reachable: bool,
        detail: impl Into<String>,
    ) -> Self {
        let (kind, hint) = classify_win32(op, code, reachable);
        let mut e = Error::new(kind, op, detail).with_code(Code::Win32(code));
        e.hint = hint;
        e
    }

    /// Classifies a COM / WMI `HRESULT` with authentication state unknown (equivalent to
    /// [`Error::from_hresult_authenticated`] with `authenticated = false`).
    pub fn from_hresult(op: Op, hr: i32, detail: impl Into<String>) -> Self {
        Self::from_hresult_authenticated(op, hr, false, detail)
    }

    /// Classifies a COM / WMI `HRESULT`, given whether the credentials have already been accepted
    /// by an IPC$ / `NetRemoteTOD` pre-check.
    ///
    /// A WMI/DCOM `E_ACCESSDENIED` (`0x80070005`) or `WBEM_E_ACCESS_DENIED` is ambiguous: it is the
    /// usual response both to a wrong password and to UAC remote restrictions on a local admin. When
    /// `authenticated` is `true` the password is already known to be correct, so it maps to
    /// [`Hint::UacRemoteRestriction`]; otherwise it maps to the combined [`Hint::WmiAccessDenied`].
    pub fn from_hresult_authenticated(
        op: Op,
        hr: i32,
        authenticated: bool,
        detail: impl Into<String>,
    ) -> Self {
        let (kind, hint) = classify_hresult(op, hr, authenticated);
        let mut e = Error::new(kind, op, detail).with_code(Code::HResult(hr));
        e.hint = hint;
        e
    }

    pub(crate) fn from_windows(op: Op, e: &windows::core::Error, what: &str) -> Self {
        Self::from_windows_authenticated(op, e, false, what)
    }

    pub(crate) fn from_windows_authenticated(
        op: Op,
        e: &windows::core::Error,
        authenticated: bool,
        what: &str,
    ) -> Self {
        let msg = e.message();
        let detail = if msg.is_empty() {
            what.to_owned()
        } else {
            format!("{what}: {}", msg.trim())
        };
        Error::from_hresult_authenticated(op, e.code().0, authenticated, detail)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.op.describe(), kind_text(self.kind))?;
        if let Some(c) = self.code {
            write!(f, " ({c})")?;
        }
        if !self.detail.is_empty() {
            write!(f, " - {}", self.detail)?;
        }
        if let Some(h) = self.hint {
            write!(f, ". Hint: {}", hint_text(h))?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

/// Crate result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

fn kind_text(k: ErrorKind) -> &'static str {
    match k {
        ErrorKind::InvalidInput => "invalid input",
        ErrorKind::LocalTarget => "refusing to act on the computer this program runs on",
        ErrorKind::Unreachable => "host unreachable",
        ErrorKind::AuthFailed => "authentication failed",
        ErrorKind::AccessDenied => "access denied",
        ErrorKind::CredentialConflict => {
            "another connection to this server uses different credentials"
        }
        ErrorKind::ShutdownInProgress => "a shutdown is already in progress or scheduled",
        ErrorKind::NotReady => "the target is not ready (sign-in screen?)",
        ErrorKind::UsersLoggedOn => "other users are signed in",
        ErrorKind::NoShutdownInProgress => "no shutdown is in progress",
        ErrorKind::SecretStoreUnavailable => {
            "Windows Credential Manager is not available in this logon session"
        }
        ErrorKind::Unsupported => "not supported by the target",
        ErrorKind::Other => "failed",
    }
}

fn hint_text(h: Hint) -> &'static str {
    match h {
        Hint::UacRemoteRestriction => {
            "local administrator accounts are filtered by UAC remote restrictions over the network \
             (Microsoft KB951016, LocalAccountTokenFilterPolicy); use a domain administrator or the \
             built-in Administrator account"
        }
        Hint::SmbFirewall => {
            "allow 'File and Printer Sharing (SMB-In)' (TCP 445) on the target for this PC"
        }
        Hint::WmiFirewall => {
            "enable the 'Windows Management Instrumentation (WMI)' firewall rule group on the target"
        }
        Hint::RemoteShutdownFirewall => {
            "the remote shutdown endpoint is unavailable; check the 'Remote Shutdown' firewall \
             rule group on the target"
        }
        Hint::WmiAccessDenied => {
            "WMI access was denied: check the user name and password, and note that local \
             administrator accounts are filtered by UAC remote restrictions (KB951016) and need \
             DCOM rights"
        }
        Hint::CheckCredentials => {
            "check the user name (TARGETPC\\user for local accounts, DOMAIN\\user or user@domain) \
             and the password"
        }
        Hint::StoreCredentials => "store an administrator account for this host",
        Hint::CloseOtherConnections => {
            "close other connections to this server (net use, Explorer, mapped drives) or use \
             another address for the host"
        }
        Hint::RetryLater => "try again later",
    }
}

// --- classification tables -------------------------------------------------------------------

/// Win32 codes meaning "network path not reachable".
pub(crate) const UNREACHABLE_CODES: &[u32] = &[
    51,   // ERROR_REM_NOT_LIST
    53,   // ERROR_BAD_NETPATH
    59,   // ERROR_UNEXP_NET_ERR
    64,   // ERROR_NETNAME_DELETED
    67,   // ERROR_BAD_NET_NAME
    121,  // ERROR_SEM_TIMEOUT
    1203, // ERROR_NO_NET_OR_BAD_PATH
    1222, // ERROR_NO_NETWORK
    1225, // ERROR_CONNECTION_REFUSED
    1231, // ERROR_NETWORK_UNREACHABLE
    1232, // ERROR_HOST_UNREACHABLE
    1236, // ERROR_CONNECTION_ABORTED
    1460, // ERROR_TIMEOUT
    1722, // RPC_S_SERVER_UNAVAILABLE
    1727, // RPC_S_CALL_FAILED_DNE
    1753, // EPT_S_NOT_REGISTERED (endpoint mapper has no endpoint: service/firewall)
];

/// `NERR_WkstaNotStarted`: the **local** Workstation (`LanmanWorkstation`) service is not running.
/// This is a local problem, not the target's, so it carries no target-firewall hint.
pub(crate) const NERR_WKSTA_NOT_STARTED: u32 = 2102;

const AUTH_CODES: &[u32] = &[
    86,   // ERROR_INVALID_PASSWORD
    1244, // ERROR_NOT_AUTHENTICATED
    1311, // ERROR_NO_LOGON_SERVERS
    1317, // ERROR_NO_SUCH_USER
    1326, // ERROR_LOGON_FAILURE
    1327, // ERROR_ACCOUNT_RESTRICTION (e.g. blank password)
    1328, // ERROR_INVALID_LOGON_HOURS
    1329, // ERROR_INVALID_WORKSTATION
    1330, // ERROR_PASSWORD_EXPIRED
    1331, // ERROR_ACCOUNT_DISABLED
    1793, // ERROR_ACCOUNT_EXPIRED
    1825, // RPC_S_SEC_PKG_ERROR
    1907, // ERROR_PASSWORD_MUST_CHANGE
    1909, // ERROR_ACCOUNT_LOCKED_OUT
    2202, // NERR_BadUsername
];

fn classify_win32(op: Op, code: u32, reachable: bool) -> (ErrorKind, Option<Hint>) {
    let admin_op = matches!(op, Op::Power | Op::Abort | Op::Wmi);
    let shutdown_op = matches!(op, Op::Power | Op::Abort);
    match code {
        // Once the target is proven reachable, RPC-unavailable on a shutdown/abort means the
        // remote-shutdown endpoint is filtered, not that the host is gone.
        1722 | 1727 | 1753 if reachable && shutdown_op => {
            (ErrorKind::Unreachable, Some(Hint::RemoteShutdownFirewall))
        }
        // Wsdr*/Base* shutdown routines return 53/5 for insufficient privilege. When we already
        // reached the host, treat 53 (like 5) as rights, not unreachability.
        53 if reachable && shutdown_op => {
            (ErrorKind::AccessDenied, Some(Hint::UacRemoteRestriction))
        }
        // WMI/DCOM access denied is a wrong password OR UAC/DCOM rights until the credentials
        // have been proven (same rule as `classify_hresult`).
        5 | 1314 | 1385 if op == Op::Wmi => (
            ErrorKind::AccessDenied,
            Some(if reachable {
                Hint::UacRemoteRestriction
            } else {
                Hint::WmiAccessDenied
            }),
        ),
        5 | 1314 | 1385 => (
            ErrorKind::AccessDenied,
            Some(if admin_op {
                Hint::UacRemoteRestriction
            } else {
                Hint::CheckCredentials
            }),
        ),
        1219 => (
            ErrorKind::CredentialConflict,
            Some(Hint::CloseOtherConnections),
        ),
        1312 if op == Op::SecretStore => (ErrorKind::SecretStoreUnavailable, None),
        // No network credentials in this logon session (e.g. SSH key logon) -> store a credential.
        1312 => (ErrorKind::AuthFailed, Some(Hint::StoreCredentials)),
        1115 | 1190 => (ErrorKind::ShutdownInProgress, Some(Hint::RetryLater)),
        21 => (ErrorKind::NotReady, Some(Hint::RetryLater)),
        1191 => (ErrorKind::UsersLoggedOn, None),
        1116 => (ErrorKind::NoShutdownInProgress, None),
        50 | 3023 => (ErrorKind::Unsupported, None),
        // 87 is genuinely a bad argument. 1783 (RPC_X_BAD_STUB_DATA) is only an "input" problem
        // for the local Credential Manager blob-size guard; on remote RPC ops it is a protocol
        // failure, which stays generic here.
        87 => (ErrorKind::InvalidInput, None),
        1783 if op == Op::SecretStore => (ErrorKind::InvalidInput, None),
        // CredWriteW: ERROR_BAD_USERNAME is a malformed argument, not a failed logon.
        2202 if op == Op::SecretStore => (ErrorKind::InvalidInput, None),
        // Local Workstation service down: local problem, no target firewall hint.
        NERR_WKSTA_NOT_STARTED => (ErrorKind::Other, None),
        1722 | 1727 | 1753 if op == Op::Wmi => (ErrorKind::Unreachable, Some(Hint::WmiFirewall)),
        c if UNREACHABLE_CODES.contains(&c) => (ErrorKind::Unreachable, Some(Hint::SmbFirewall)),
        c if AUTH_CODES.contains(&c) => (ErrorKind::AuthFailed, Some(Hint::CheckCredentials)),
        _ => (ErrorKind::Other, None),
    }
}

// WBEM status codes (wbemcli.h).
pub(crate) const WBEM_E_ACCESS_DENIED: i32 = 0x8004_1003_u32 as i32;
pub(crate) const WBEM_E_INVALID_NAMESPACE: i32 = 0x8004_100E_u32 as i32;
pub(crate) const WBEM_E_INVALID_CLASS: i32 = 0x8004_1010_u32 as i32;
pub(crate) const WBEM_E_INVALID_QUERY: i32 = 0x8004_1017_u32 as i32;
/// Success code of `IEnumWbemClassObject::Next` when the timeout elapsed first.
pub(crate) const WBEM_S_TIMEDOUT: i32 = 0x0004_0004;
pub(crate) const WBEM_E_TRANSPORT_FAILURE: i32 = 0x8004_1015_u32 as i32;
pub(crate) const WBEM_E_LOCAL_CREDENTIALS: i32 = 0x8004_1064_u32 as i32;
pub(crate) const WBEM_E_TIMED_OUT: i32 = 0x8004_1069_u32 as i32;
pub(crate) const WBEM_E_CALL_CANCELLED: i32 = 0x8004_1032_u32 as i32;
pub(crate) const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;
pub(crate) const RPC_E_TIMEOUT: i32 = 0x8001_011F_u32 as i32;
pub(crate) const RPC_E_DISCONNECTED: i32 = 0x8001_0108_u32 as i32;

fn classify_hresult(op: Op, hr: i32, authenticated: bool) -> (ErrorKind, Option<Hint>) {
    match hr {
        WBEM_E_ACCESS_DENIED | E_ACCESSDENIED => (
            ErrorKind::AccessDenied,
            Some(if authenticated {
                // Password already proven correct via IPC$/NetRemoteTOD: this is UAC/DCOM.
                Hint::UacRemoteRestriction
            } else {
                // Could equally be a wrong password: ask the user to check both.
                Hint::WmiAccessDenied
            }),
        ),
        // Old Windows without the class / property (e.g. no root\StandardCimv2 before Windows 8).
        WBEM_E_INVALID_NAMESPACE | WBEM_E_INVALID_CLASS | WBEM_E_INVALID_QUERY => {
            (ErrorKind::Unsupported, None)
        }
        WBEM_S_TIMEDOUT => (ErrorKind::Unreachable, Some(Hint::WmiFirewall)),
        WBEM_E_TRANSPORT_FAILURE
        | WBEM_E_TIMED_OUT
        | WBEM_E_CALL_CANCELLED
        | RPC_E_TIMEOUT
        | RPC_E_DISCONNECTED => (ErrorKind::Unreachable, Some(Hint::WmiFirewall)),
        WBEM_E_LOCAL_CREDENTIALS => (ErrorKind::InvalidInput, None),
        _ => match Code::HResult(hr).win32() {
            Some(w) => classify_win32(op, w, authenticated),
            None => (ErrorKind::Other, None),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win32_classification() {
        let k = |op, c| Error::from_win32(op, c, "").kind();
        assert_eq!(k(Op::Connect, 1326), ErrorKind::AuthFailed);
        assert_eq!(k(Op::Connect, 1219), ErrorKind::CredentialConflict);
        assert_eq!(k(Op::Connect, 53), ErrorKind::Unreachable);
        assert_eq!(k(Op::Connect, 67), ErrorKind::Unreachable);
        assert_eq!(k(Op::Connect, 1203), ErrorKind::Unreachable);
        assert_eq!(k(Op::Connect, 1311), ErrorKind::AuthFailed);
        assert_eq!(k(Op::Connect, 5), ErrorKind::AccessDenied);
        assert_eq!(k(Op::Power, 1115), ErrorKind::ShutdownInProgress);
        assert_eq!(k(Op::Power, 1190), ErrorKind::ShutdownInProgress);
        assert_eq!(k(Op::Power, 21), ErrorKind::NotReady);
        assert_eq!(k(Op::Power, 1191), ErrorKind::UsersLoggedOn);
        assert_eq!(k(Op::Abort, 1116), ErrorKind::NoShutdownInProgress);
        assert_eq!(k(Op::Power, 1722), ErrorKind::Unreachable);
        assert_eq!(k(Op::SecretStore, 1312), ErrorKind::SecretStoreUnavailable);
        assert_eq!(k(Op::Connect, 1312), ErrorKind::AuthFailed);
        assert_eq!(k(Op::BootTime, 3023), ErrorKind::Unsupported);
        assert_eq!(k(Op::Connect, 999_999), ErrorKind::Other);
    }

    #[test]
    fn hints() {
        assert_eq!(
            Error::from_win32(Op::Power, 5, "").hint(),
            Some(Hint::UacRemoteRestriction)
        );
        assert_eq!(
            Error::from_win32(Op::Connect, 5, "").hint(),
            Some(Hint::CheckCredentials)
        );
        assert_eq!(
            Error::from_win32(Op::Connect, 1219, "").hint(),
            Some(Hint::CloseOtherConnections)
        );
        assert_eq!(
            Error::from_win32(Op::Connect, 53, "").hint(),
            Some(Hint::SmbFirewall)
        );
        assert_eq!(
            Error::from_win32(Op::Wmi, 1722, "").hint(),
            Some(Hint::WmiFirewall)
        );
    }

    #[test]
    fn hresult_classification() {
        let k = |hr: u32| Error::from_hresult(Op::Wmi, hr as i32, "").kind();
        assert_eq!(k(0x8004_1003), ErrorKind::AccessDenied);
        assert_eq!(k(0x8007_0005), ErrorKind::AccessDenied);
        assert_eq!(k(0x8007_06BA), ErrorKind::Unreachable); // RPC server unavailable
        assert_eq!(k(0x8007_052E), ErrorKind::AuthFailed); // 1326
        assert_eq!(k(0x8004_100E), ErrorKind::Unsupported);
        assert_eq!(k(0x8004_1010), ErrorKind::Unsupported);
        assert_eq!(k(0x8000_4005), ErrorKind::Other);
        assert_eq!(Code::HResult(0x8007_06BA_u32 as i32).win32(), Some(1722));
        assert_eq!(Code::HResult(0x8004_1003_u32 as i32).win32(), None);
    }

    #[test]
    fn reachable_disambiguates_shutdown_rights() {
        // Before we reach the host, 53 is "unreachable / open SMB".
        let e = Error::from_win32(Op::Power, 53, "");
        assert_eq!(e.kind(), ErrorKind::Unreachable);
        assert_eq!(e.hint(), Some(Hint::SmbFirewall));

        // After IPC$/NetRemoteTOD succeeded, 53 and 5 on Power/Abort mean rights, not reachability.
        for op in [Op::Power, Op::Abort] {
            for code in [5, 53, 1314, 1385] {
                let e = Error::from_win32_reachable(op, code, true, "");
                assert_eq!(e.kind(), ErrorKind::AccessDenied, "{op:?} {code}");
                assert_eq!(e.hint(), Some(Hint::UacRemoteRestriction), "{op:?} {code}");
            }
        }
        // Non-shutdown ops keep the connection-stage meaning even when reachable.
        let e = Error::from_win32_reachable(Op::Connect, 53, true, "");
        assert_eq!(e.kind(), ErrorKind::Unreachable);
    }

    #[test]
    fn reachable_shutdown_rpc_unavailable_is_shutdown_firewall() {
        for code in [1722, 1727] {
            let e = Error::from_win32_reachable(Op::Power, code, true, "");
            assert_eq!(e.kind(), ErrorKind::Unreachable);
            assert_eq!(e.hint(), Some(Hint::RemoteShutdownFirewall));
        }
        // WMI keeps the WMI-firewall hint; unknown-reachability keeps SMB firewall.
        assert_eq!(
            Error::from_win32(Op::Wmi, 1722, "").hint(),
            Some(Hint::WmiFirewall)
        );
        assert_eq!(
            Error::from_win32(Op::Power, 1722, "").hint(),
            Some(Hint::SmbFirewall)
        );
    }

    #[test]
    fn wmi_access_denied_depends_on_prior_auth() {
        // Not yet authenticated: could be a bad password OR UAC/DCOM -> combined hint.
        let e = Error::from_hresult(Op::Wmi, E_ACCESSDENIED, "");
        assert_eq!(e.kind(), ErrorKind::AccessDenied);
        assert_eq!(e.hint(), Some(Hint::WmiAccessDenied));
        // Password already proven by IPC$: this is UAC/DCOM specifically.
        let e = Error::from_hresult_authenticated(Op::Wmi, WBEM_E_ACCESS_DENIED, true, "");
        assert_eq!(e.hint(), Some(Hint::UacRemoteRestriction));
    }

    #[test]
    fn code_1783_is_input_only_for_secret_store() {
        assert_eq!(
            Error::from_win32(Op::SecretStore, 1783, "").kind(),
            ErrorKind::InvalidInput
        );
        // On a remote RPC op it is a protocol failure, not caller input.
        assert_eq!(
            Error::from_win32(Op::Power, 1783, "").kind(),
            ErrorKind::Other
        );
        assert_ne!(
            Error::from_win32(Op::Wmi, 1783, "").kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn wmi_win32_access_denied_follows_authentication_state() {
        // Regression: from_win32(Op::Wmi, 5) always blamed UAC even before the password was proven.
        let e = Error::from_win32(Op::Wmi, 5, "");
        assert_eq!(e.kind(), ErrorKind::AccessDenied);
        assert_eq!(e.hint(), Some(Hint::WmiAccessDenied));
        let e = Error::from_win32_reachable(Op::Wmi, 5, true, "");
        assert_eq!(e.hint(), Some(Hint::UacRemoteRestriction));
        // Same answer through the HRESULT path.
        let e = Error::from_hresult(Op::Wmi, E_ACCESSDENIED, "");
        assert_eq!(e.hint(), Some(Hint::WmiAccessDenied));
    }

    #[test]
    fn endpoint_mapper_and_query_codes() {
        let e = Error::from_win32_reachable(Op::Power, 1753, true, "");
        assert_eq!(e.kind(), ErrorKind::Unreachable);
        assert_eq!(e.hint(), Some(Hint::RemoteShutdownFirewall));
        assert_eq!(
            Error::from_hresult(Op::Wmi, 0x8007_06D9_u32 as i32, "").hint(),
            Some(Hint::WmiFirewall)
        );
        assert_eq!(
            Error::from_hresult(Op::Wmi, WBEM_E_INVALID_QUERY, "").kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            Error::from_hresult(Op::Wmi, WBEM_S_TIMEDOUT, "").kind(),
            ErrorKind::Unreachable
        );
        assert_eq!(
            Error::from_win32(Op::SecretStore, 2202, "").kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            Error::from_win32(Op::Connect, 2202, "").kind(),
            ErrorKind::AuthFailed
        );
    }

    #[test]
    fn local_workstation_service_has_no_target_hint() {
        let e = Error::from_win32(Op::Connect, 2102, "");
        assert_eq!(e.kind(), ErrorKind::Other);
        assert_eq!(e.hint(), None);
    }

    #[test]
    fn display_is_informative() {
        let e = Error::from_win32(Op::Power, 5, r"\\host");
        let s = e.to_string();
        assert!(s.contains("access denied"), "{s}");
        assert!(s.contains("error 5"), "{s}");
        assert!(s.contains(r"\\host"), "{s}");
        assert!(s.contains("KB951016"), "{s}");
        let e = Error::from_hresult(Op::Wmi, 0x8004_1003_u32 as i32, "x");
        assert!(e.to_string().contains("0x80041003"), "{e}");
    }
}
