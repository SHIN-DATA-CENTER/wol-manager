//! Remote management (v0.2.0): restart, shutdown, cancel a pending shutdown (Windows), boot
//! time, the physical NIC's MAC, connection test, and the verification of restarts /
//! shutdowns.
//!
//! Operations dispatch on `host.remote.kind`:
//! * **Windows** → `wol-winremote` (SMB/RPC for power and boot time, WMI for the MAC). The
//!   account is `remote.user` (or the one stored with the password) with the `login` secret.
//!   Without a stored password the current Windows sign-in is used, but only when
//!   `remote.user` is empty or names the current sign-in itself; for any other configured
//!   account the operation fails with [`RemoteFailure::PasswordRequired`]. Automatic
//!   operations ([`RemoteClient::unattended`]) use the sign-in only for hosts whose user
//!   confirmed it on this PC ([`RemoteClient::confirm_sign_in`], bound to the management
//!   address; see [`crate::secret`]); otherwise [`RemoteFailure::SignInNotConfirmed`].
//! * **SSH** → `wol-ssh` (Linux, Proxmox, NAS, FreeBSD). User `remote.user` or `root`,
//!   `key_file` (+ `key-passphrase` secret) and / or the `login` password; sudo per
//!   [`SudoMode`] (the `sudo` secret for `separate`, and for `auto` when stored; else the
//!   login password). Key files on network (UNC) paths are refused.
//!
//! The management address is `remote.address`, else the host's `address`. Timeouts come from
//! `[settings.remote]`. Secrets come from [`crate::secret`] just in time and are never logged.
//!
//! # Stored passwords
//! A stored login / sudo password is used only for the kind, account, management address and
//! SSH port it was saved for ([`crate::secret::SecretBinding`]); otherwise the operation fails
//! with [`RemoteFailure::SecretMismatch`] (Permission, exit 7: "enter it again") instead of
//! sending it to another machine or account. When Windows Credential Manager is unavailable
//! (network / SSH logon on this PC) and the operation needs a stored password, it fails with
//! [`RemoteFailure::SecretStoreUnavailable`]; when it can proceed without (key file, current
//! sign-in), a later permission error carries [`RemoteHint::SecretStoreUnavailable`].
//!
//! # Blocking
//! **Every operation blocks** (network I/O, no async): run them on worker threads, never on
//! the GUI thread. Typical duration on a LAN / VPN is well under a second (SSH) or one to two
//! seconds (Windows, WMI). Worst cases:
//! * Windows: `connect_timeout` for the TCP pre-probe, then an SMB logon and one or two RPCs;
//!   **tens of seconds** when a firewall silently drops SMB / RPC / WMI (DCOM) traffic.
//! * SSH: 3 × `connect_timeout` + 15 s handshake + 30 s per command + 1 s (61 s with the
//!   defaults; `power`: 121 s).
//! * [`verify_restart`] / [`verify_shutdown`]: until the deadline you pass
//!   (`settings.remote.*_verify_timeout_secs`, see [`verify_timeout`]).
//!
//! # Test seams
//! [`RemoteClient`] bundles the [`SecretStore`], the two backends ([`WindowsBackend`],
//! [`SshBackend`]) and the [`VerifyEnv`] (probe, clocks, sleep). Tests build it with mocks so
//! they never touch the network or real power APIs; the free functions use
//! [`RemoteClient::system`].

mod error;
mod verify;

#[cfg(test)]
pub(crate) mod tests;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

pub use error::{RemoteError, RemoteFailure, RemoteHint, RemoteOp, RemoteStage};
pub use verify::{
    NEW_BOOT_SLACK, RESTART_POLL, RestartVerify, SHUTDOWN_FAILURES, SHUTDOWN_POLL, ShutdownVerify,
    SystemVerifyEnv, VerifyEnv, VerifyPhase, VerifyTick, verify_probe_spec,
};

pub use crate::model::{RemoteConfig, RemoteKind, SudoMode};

use crate::error::{
    Error, ErrorKind, Field, FieldIssue, HostKeyProblem, Result, SecretStoreFailure,
};
use crate::i18n::{self, Lang};
use crate::mac::MacAddr;
use crate::model::{Config, Host, HostId, RemoteSettings, Settings};
use crate::netif::Ipv4Subnet;
use crate::secret::{self as secrets, Secret, SecretBinding, SecretKind, SecretStore};
use error::Where;

fn ser_ms<S: Serializer>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_millis() as u64)
}

fn ser_unix_ms<S: Serializer>(t: &SystemTime, s: S) -> std::result::Result<S::Ok, S::Error> {
    let ms = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    };
    s.serialize_i64(ms)
}

/// A restart counts as detected when the boot time moved forward by more than this
/// (without boot ids on both sides).
pub const REBOOT_MARGIN: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------------------------

/// Last boot of a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootInfo {
    /// Boot time on the LOCAL clock (`local now − uptime`, so clock skew between the two
    /// machines cancels out). Display this one. JSON: `boot_time_unix_ms`.
    #[serde(rename = "boot_time_unix_ms", serialize_with = "ser_unix_ms")]
    pub boot_time: SystemTime,
    /// Time since boot. JSON: `uptime_ms`.
    #[serde(rename = "uptime_ms", serialize_with = "ser_ms")]
    pub uptime: Duration,
    /// Where it came from: `"windows/NetRemoteTOD+NetStatisticsGet"`, `"ssh/proc_stat"`...
    pub source: String,
    /// `true` when the value may be off: Windows could not resolve the 49.7-day counter wrap
    /// (statistics access denied), or an SSH host did not report its own clock.
    pub approximate: bool,
    /// Linux boot id (a new UUID every boot); `None` on Windows / FreeBSD.
    pub boot_id: Option<String>,
}

impl BootInfo {
    /// `wol-winremote` already anchors the boot time on this PC's clock (local now − remote
    /// uptime), like the SSH backend.
    fn from_windows(b: wol_winremote::BootInfo) -> BootInfo {
        BootInfo {
            boot_time: b.boot_time_utc,
            uptime: b.uptime,
            source: format!("windows/{}", b.source),
            approximate: b.approximate,
            boot_id: b.boot_id,
        }
    }

    fn from_ssh(b: wol_ssh::BootInfo) -> BootInfo {
        BootInfo {
            boot_time: b.boot_time_local,
            uptime: b.uptime,
            source: format!("ssh/{}", b.source),
            approximate: b.approximate,
            boot_id: b.boot_id,
        }
    }

    /// `true` when `self` (read later) is a different boot than `earlier`: the boot ids
    /// differ (when both have one), else the boot time moved forward by more than
    /// [`REBOOT_MARGIN`] **and** by at least about `earlier.uptime` (a new boot starts after
    /// the earlier reading, so its boot time is at least that much later; a step of this PC's
    /// clock by less than the host's uptime is not a reboot).
    ///
    /// Heuristic on local-clock-anchored values: a clock step larger than `earlier.uptime`
    /// and, for `approximate` Windows readings, the 49.7-day counter wrap can still look like
    /// a reboot. [`verify_restart`] does not use this: it compares uptimes with the monotonic
    /// clock and asks approximate readings to have seen the host go down.
    pub fn rebooted_since(&self, earlier: &BootInfo) -> bool {
        match (&self.boot_id, &earlier.boot_id) {
            (Some(a), Some(b)) => a != b,
            _ => self
                .boot_time
                .duration_since(earlier.boot_time)
                .is_ok_and(|d| d > REBOOT_MARGIN && d + REBOOT_MARGIN >= earlier.uptime),
        }
    }

    /// Localized one-line summary for the host row / CLI, e.g. `起動 9/29 08:12（稼働 3時間12分）`
    /// ([`i18n::format_boot_line`]).
    pub fn boot_line(&self, lang: Lang) -> String {
        i18n::format_boot_line(
            lang,
            &i18n::LocalTime::from_system_time(self.boot_time),
            self.uptime,
            self.approximate,
        )
    }
}

/// Restart or shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerAction {
    /// Restart.
    Restart,
    /// Shut down (power off).
    Shutdown,
}

impl PowerAction {
    /// `"restart"` / `"shutdown"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            PowerAction::Restart => "restart",
            PowerAction::Shutdown => "shutdown",
        }
    }

    fn op(self) -> RemoteOp {
        match self {
            PowerAction::Restart => RemoteOp::Restart,
            PowerAction::Shutdown => RemoteOp::Shutdown,
        }
    }
}

impl fmt::Display for PowerAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Options of a power request. SSH hosts ignore all of them (the command runs about 2 s
/// later, applications are not asked).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct PowerOptions {
    /// Windows countdown in seconds (0 = immediately; cannot be cancelled then).
    pub delay_secs: u32,
    /// Windows: close applications without asking (unsaved work is lost).
    pub force: bool,
    /// Windows: message shown during the countdown (blank = none).
    pub message: Option<String>,
}

impl PowerOptions {
    /// Defaults from `[settings.remote]` (delay, force), no message.
    pub fn from_settings(s: &RemoteSettings) -> PowerOptions {
        PowerOptions {
            delay_secs: s.effective_shutdown_delay_secs(),
            force: s.force_apps_closed,
            message: None,
        }
    }
}

/// The host accepted a power request. This is not proof that it happened: verify with
/// [`verify_restart`] / [`verify_shutdown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PowerOutcome {
    /// Runs now (Windows without countdown; SSH: scheduled about 2 s later on the host).
    Accepted,
    /// Windows countdown; [`abort_shutdown`] can cancel it until it fires.
    Scheduled {
        /// The countdown.
        delay_secs: u32,
    },
}

impl PowerOutcome {
    /// Countdown in seconds (0 for `Accepted`).
    pub fn delay_secs(&self) -> u32 {
        match self {
            PowerOutcome::Accepted => 0,
            PowerOutcome::Scheduled { delay_secs } => *delay_secs,
        }
    }
}

/// Physical kind of a NIC candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NicKind {
    /// Wired Ethernet.
    Physical,
    /// Wi-Fi (WoL rarely works).
    Wifi,
    /// Last resort (SSH: the default-route interface itself when no physical NIC was found).
    Other,
}

/// A NIC of the remote host that may be the right MAC for waking it. Lists are sorted by
/// `score`, best first; equal top scores mean "let the user choose".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MacCandidate {
    /// Adapter name as the host reports it (`"Ethernet"`, `"eno1"`).
    pub iface: String,
    /// The MAC to store for WoL (SSH: the permanent address when known).
    pub mac: MacAddr,
    /// Burned-in address, when known.
    pub permanent_mac: Option<MacAddr>,
    /// SSH: the currently programmed address when it differs from `mac` (bond / lagg
    /// members): offer it as an alternative.
    pub current_mac: Option<MacAddr>,
    /// Wired / Wi-Fi / other.
    pub kind: NicKind,
    /// Carries the IPv4 default route.
    pub on_default_route: bool,
    /// SSH: the L3 interface above it (`vmbr0`, `bond0.20`), when different.
    pub via: Option<String>,
    /// Link up.
    pub link_up: bool,
    /// SSH (root logins / FreeBSD): `Some(false)` = the NIC supports magic packets but WoL is
    /// disabled (warn). `None` = unknown.
    pub wol_enabled: Option<bool>,
    /// LAN IPv4 address / prefix of the adapter (VPN and link-local excluded).
    pub lan_ipv4: Option<Ipv4Subnet>,
    /// Ranking score (higher = better).
    pub score: i32,
}

impl MacCandidate {
    fn from_windows(c: wol_winremote::MacCandidate) -> Option<MacCandidate> {
        Some(MacCandidate {
            mac: MacAddr::parse(&c.mac).ok()?,
            permanent_mac: c
                .permanent_mac
                .as_deref()
                .and_then(|m| MacAddr::parse(m).ok()),
            current_mac: None,
            kind: match c.kind {
                wol_winremote::NicKind::Physical => NicKind::Physical,
                wol_winremote::NicKind::Wifi => NicKind::Wifi,
                wol_winremote::NicKind::Other => NicKind::Other,
            },
            on_default_route: c.on_default_route,
            via: None,
            link_up: c.link_up,
            wol_enabled: None,
            lan_ipv4: c.lan_ipv4.and_then(|(a, p)| Ipv4Subnet::new(a, p)),
            score: c.score,
            iface: c.iface,
        })
    }

    fn from_ssh(c: wol_ssh::MacCandidate) -> MacCandidate {
        let mac = MacAddr(c.mac);
        MacCandidate {
            permanent_mac: c.permanent_mac.map(MacAddr),
            current_mac: (c.current_mac != c.mac).then_some(MacAddr(c.current_mac)),
            kind: match c.kind {
                wol_ssh::NicKind::Physical => NicKind::Physical,
                wol_ssh::NicKind::Wifi => NicKind::Wifi,
                wol_ssh::NicKind::Other => NicKind::Other,
            },
            on_default_route: c.on_default_route,
            via: c.via,
            link_up: c.link_up,
            wol_enabled: c
                .wol
                .as_ref()
                .filter(|w| w.supports_magic())
                .map(|w| w.magic_enabled()),
            lan_ipv4: c.lan_ipv4.and_then(|(a, p)| Ipv4Subnet::new(a, p)),
            score: c.score,
            iface: c.iface,
            mac,
        }
    }
}

/// The best candidate when it can be taken without asking: the first one, if its score is
/// higher than the second's (or it is the only one) **and** it is a good WoL target
/// ([`auto_pickable`]: wired, link up, WoL not known to be disabled). `None` = let the user
/// choose with the list (a Wi-Fi / disconnected / WoL-disabled best candidate is shown with
/// its badges or [`crate::i18n::Msg::WolDisabledOn`] instead of being stored silently).
pub fn unique_best(candidates: &[MacCandidate]) -> Option<&MacCandidate> {
    let best = match candidates {
        [only] => only,
        [first, second, ..] if first.score > second.score => first,
        _ => return None,
    };
    auto_pickable(best).then_some(best)
}

/// `true` for a candidate that may be stored without asking: [`NicKind::Physical`], link up,
/// and WoL not reported as disabled (`wol_enabled != Some(false)`).
pub fn auto_pickable(c: &MacCandidate) -> bool {
    c.kind == NicKind::Physical && c.link_up && c.wol_enabled != Some(false)
}

/// Result of [`test_connection`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnInfo {
    /// OS description (`"Microsoft Windows 11 Pro"`, `"Debian GNU/Linux 12 (bookworm)"`).
    /// Windows: `None` when WMI is not reachable (the connection itself worked).
    pub os: Option<String>,
    /// Boot time.
    pub boot: BootInfo,
    /// Hint whether the account has administrator / root rights (Windows: `Some(true)` when
    /// a WMI query worked, `Some(false)` when WMI refused the account; SSH: root or member of
    /// sudo / wheel / admin). `None` = unknown. `Some(false)` → warn that restart / shutdown
    /// will probably fail. [`ConnInfo::admin_check`] says which note to show.
    pub admin_hint: Option<bool>,
    /// How the administrator check ended (the note under a successful test:
    /// [`AdminCheck::note`]).
    pub admin_check: AdminCheck,
    /// SSH: the login user as the host sees it.
    pub user: Option<String>,
    /// SSH: kernel (`"Linux 6.8.12-1-pve"`).
    pub kernel: Option<String>,
}

/// How the administrator check of [`RemoteClient::test_connection`] ended (review R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AdminCheck {
    /// Administrator / root rights are likely (Windows: a remote WMI query worked; SSH: root
    /// or a member of sudo / wheel / admin).
    Admin,
    /// SSH: neither root nor a member of sudo / wheel / admin.
    NotAdmin,
    /// Windows: WMI refused the account although SMB accepted it: not an administrator of the
    /// host, or UAC remote restrictions (KB951016) filtered its token.
    WmiDenied,
    /// Windows: WMI (TCP 135 and its dynamic ports) is not reachable: firewall.
    WmiUnreachable,
    /// Windows: WMI failed otherwise; rights unknown.
    Unknown,
    /// Windows: the target is this PC; nothing to check.
    NotChecked,
}

impl AdminCheck {
    /// The note under a successful test: `(warning, text)`; `None` when there is nothing to
    /// say. A warning (`true`) means restart / shutdown will probably fail.
    pub fn note(self) -> Option<(bool, i18n::Msg)> {
        match self {
            AdminCheck::Admin | AdminCheck::NotChecked => None,
            AdminCheck::NotAdmin => Some((true, i18n::Msg::RemoteNotAdmin)),
            AdminCheck::WmiDenied => Some((true, i18n::Msg::RemoteWmiDenied)),
            AdminCheck::WmiUnreachable => Some((false, i18n::Msg::RemoteWmiUnreachable)),
            AdminCheck::Unknown => Some((false, i18n::Msg::RemoteAdminUnknown)),
        }
    }

    fn of_windows(c: wol_winremote::AdminCheck) -> AdminCheck {
        match c {
            wol_winremote::AdminCheck::Admin => AdminCheck::Admin,
            wol_winremote::AdminCheck::Denied => AdminCheck::WmiDenied,
            wol_winremote::AdminCheck::Unreachable => AdminCheck::WmiUnreachable,
            wol_winremote::AdminCheck::Local => AdminCheck::NotChecked,
            _ => AdminCheck::Unknown,
        }
    }
}

/// An SSH host key (public data).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct HostKeyInfo {
    /// Algorithm, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// `SHA256:...` (what `ssh-keygen -lf` prints).
    pub fingerprint: String,
    /// OpenSSH line without comment (store this in `remote.host_key`).
    pub openssh_line: String,
}

impl From<wol_ssh::HostKeyInfo> for HostKeyInfo {
    fn from(k: wol_ssh::HostKeyInfo) -> HostKeyInfo {
        HostKeyInfo {
            algorithm: k.algorithm,
            fingerprint: k.fingerprint_sha256,
            openssh_line: k.openssh_line,
        }
    }
}

/// Parses an OpenSSH public-key line (comment optional). Pure.
/// Errors: [`Error::InvalidValue`] (`SshHostKey`, `InvalidHostKey`).
pub fn parse_host_key(line: &str) -> Result<HostKeyInfo> {
    wol_ssh::parse_host_key(line.trim())
        .map(HostKeyInfo::from)
        .map_err(|_| Error::invalid(Field::SshHostKey, FieldIssue::InvalidHostKey, line))
}

/// `true` when two `SHA256:` fingerprints are equal (tolerant of the prefix, case of the
/// prefix, `=` padding and spaces). Pure.
pub fn fingerprints_match(a: &str, b: &str) -> bool {
    wol_ssh::fingerprints_match(a, b)
}

// ---------------------------------------------------------------------------------------------
// Secrets for one operation
// ---------------------------------------------------------------------------------------------

/// Replaces one stored secret for an operation (editor "Test connection" before saving).
#[derive(Clone, Default)]
pub enum SecretOverride {
    /// Use the stored secret, if any (default).
    #[default]
    Stored,
    /// Use this value (typed in the editor).
    Value(Zeroizing<String>),
    /// Act as if none were stored (the editor's "delete" flag is set).
    Absent,
}

impl fmt::Debug for SecretOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SecretOverride::Stored => "Stored",
            SecretOverride::Value(_) => "Value(<redacted>)",
            SecretOverride::Absent => "Absent",
        })
    }
}

/// Secret overrides per kind (see [`RemoteClient::with_overrides`]).
#[derive(Debug, Clone, Default)]
pub struct SecretOverrides {
    /// Login password.
    pub login: SecretOverride,
    /// SSH key passphrase.
    pub key_passphrase: SecretOverride,
    /// Separate sudo password.
    pub sudo: SecretOverride,
}

impl SecretOverrides {
    fn get(&self, kind: SecretKind) -> &SecretOverride {
        match kind {
            SecretKind::Login => &self.login,
            SecretKind::KeyPassphrase => &self.key_passphrase,
            SecretKind::Sudo => &self.sudo,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Backends (test seams)
// ---------------------------------------------------------------------------------------------

/// The Windows backend (`wol-winremote`). A seam for tests: [`SystemWindows`] calls the real
/// crate; mocks must never call power APIs.
pub trait WindowsBackend: Send + Sync {
    /// Boot time. **Blocking**.
    fn boot_time(
        &self,
        host: &wol_winremote::RemoteHost,
    ) -> wol_winremote::Result<wol_winremote::BootInfo>;
    /// Restart / shutdown request. **Blocking**.
    fn power(
        &self,
        host: &wol_winremote::RemoteHost,
        action: wol_winremote::PowerAction,
        opts: &wol_winremote::PowerOptions,
    ) -> wol_winremote::Result<wol_winremote::PowerOutcome>;
    /// Cancel a pending shutdown. **Blocking**.
    fn abort_shutdown(&self, host: &wol_winremote::RemoteHost) -> wol_winremote::Result<()>;
    /// Physical NIC candidates (WMI). **Blocking**.
    fn mac_candidates(
        &self,
        host: &wol_winremote::RemoteHost,
    ) -> wol_winremote::Result<Vec<wol_winremote::MacCandidate>>;
    /// Connection test. **Blocking**.
    fn test_connection(
        &self,
        host: &wol_winremote::RemoteHost,
    ) -> wol_winremote::Result<wol_winremote::ConnInfo>;
}

/// The real Windows backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWindows;

impl WindowsBackend for SystemWindows {
    fn boot_time(
        &self,
        host: &wol_winremote::RemoteHost,
    ) -> wol_winremote::Result<wol_winremote::BootInfo> {
        wol_winremote::boot_time(host)
    }
    fn power(
        &self,
        host: &wol_winremote::RemoteHost,
        action: wol_winremote::PowerAction,
        opts: &wol_winremote::PowerOptions,
    ) -> wol_winremote::Result<wol_winremote::PowerOutcome> {
        wol_winremote::power(host, action, opts)
    }
    fn abort_shutdown(&self, host: &wol_winremote::RemoteHost) -> wol_winremote::Result<()> {
        wol_winremote::abort_shutdown(host)
    }
    fn mac_candidates(
        &self,
        host: &wol_winremote::RemoteHost,
    ) -> wol_winremote::Result<Vec<wol_winremote::MacCandidate>> {
        wol_winremote::mac_candidates(host)
    }
    fn test_connection(
        &self,
        host: &wol_winremote::RemoteHost,
    ) -> wol_winremote::Result<wol_winremote::ConnInfo> {
        wol_winremote::test_connection(host)
    }
}

/// Process exit (GUI exit, Ctrl+C in `wolm`): closes the Windows `\\host\IPC$` connections that
/// remote operations of this process opened with a stored password and that are still open (a
/// thread ended without unwinding would leave them until logoff, and later operations would
/// reuse their credentials), and refuses new ones. Returns how many were closed. Call it only
/// right before the process exits (review C3).
pub fn cancel_owned_connections() -> usize {
    wol_winremote::cancel_owned_connections()
}

/// The SSH backend (`wol-ssh`). A seam for tests: [`SystemSsh`] calls the real crate.
pub trait SshBackend: Send + Sync {
    /// Boot time. **Blocking**.
    fn boot_time(&self, target: &wol_ssh::Target) -> wol_ssh::Result<wol_ssh::BootInfo>;
    /// Schedules a restart / power-off. **Blocking**.
    fn power(
        &self,
        target: &wol_ssh::Target,
        action: wol_ssh::PowerAction,
        overrides: &wol_ssh::PowerOverrides,
    ) -> wol_ssh::Result<wol_ssh::PowerScheduled>;
    /// NIC candidates. **Blocking**.
    fn mac_candidates(
        &self,
        target: &wol_ssh::Target,
    ) -> wol_ssh::Result<Vec<wol_ssh::MacCandidate>>;
    /// Connection test. **Blocking**.
    fn test_connection(&self, target: &wol_ssh::Target) -> wol_ssh::Result<wol_ssh::ConnInfo>;
    /// Reads the host key without logging in. **Blocking**.
    fn scan_host_key(
        &self,
        host: &str,
        port: u16,
        timeouts: wol_ssh::Timeouts,
    ) -> wol_ssh::Result<wol_ssh::HostKeyInfo>;
    /// Keys `~/.ssh/known_hosts` has for `host:port` (read-only, fast).
    fn known_hosts_keys(&self, host: &str, port: u16) -> Vec<wol_ssh::HostKeyInfo>;
}

/// The real SSH backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSsh;

impl SshBackend for SystemSsh {
    fn boot_time(&self, target: &wol_ssh::Target) -> wol_ssh::Result<wol_ssh::BootInfo> {
        wol_ssh::boot_time(target)
    }
    fn power(
        &self,
        target: &wol_ssh::Target,
        action: wol_ssh::PowerAction,
        overrides: &wol_ssh::PowerOverrides,
    ) -> wol_ssh::Result<wol_ssh::PowerScheduled> {
        wol_ssh::power(target, action, overrides)
    }
    fn mac_candidates(
        &self,
        target: &wol_ssh::Target,
    ) -> wol_ssh::Result<Vec<wol_ssh::MacCandidate>> {
        wol_ssh::mac_candidates(target)
    }
    fn test_connection(&self, target: &wol_ssh::Target) -> wol_ssh::Result<wol_ssh::ConnInfo> {
        wol_ssh::test_connection(target)
    }
    fn scan_host_key(
        &self,
        host: &str,
        port: u16,
        timeouts: wol_ssh::Timeouts,
    ) -> wol_ssh::Result<wol_ssh::HostKeyInfo> {
        wol_ssh::scan_host_key(host, port, timeouts)
    }
    fn known_hosts_keys(&self, host: &str, port: u16) -> Vec<wol_ssh::HostKeyInfo> {
        wol_ssh::known_hosts_keys(host, port)
    }
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

/// Remote management with explicit dependencies. Cheap to clone (`Arc`s); `Send + Sync`.
#[derive(Clone)]
pub struct RemoteClient {
    secrets: SecretStore,
    windows: Arc<dyn WindowsBackend>,
    ssh: Arc<dyn SshBackend>,
    env: Arc<dyn VerifyEnv>,
    overrides: SecretOverrides,
    /// [`RemoteClient::unattended`].
    unattended: bool,
}

impl fmt::Debug for RemoteClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteClient")
            .field("secrets", &self.secrets)
            .field("overrides", &self.overrides)
            .field("unattended", &self.unattended)
            .finish_non_exhaustive()
    }
}

/// The account as sent to the Windows host. `.\user` (the "this machine" notation) would make
/// WMI send the *client's* name as the domain, so it is sent as the bare `user`, which the
/// target resolves to its own local account. Other forms (`PC\user`, `DOMAIN\user`,
/// `user@domain`) are kept.
pub fn windows_account(user: &str) -> String {
    let u = user.trim();
    u.strip_prefix(".\\").unwrap_or(u).to_owned()
}

/// `USERNAME`, `USERDOMAIN`, `COMPUTERNAME` of this process (trimmed, non-empty).
fn sign_in_env() -> (Option<String>, Option<String>, Option<String>) {
    let var = |k: &str| {
        std::env::var(k)
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    (var("USERNAME"), var("USERDOMAIN"), var("COMPUTERNAME"))
}

/// The sign-in as an account name for another PC: `DOMAIN\user` for a domain account, the
/// bare `user` for a local (or Microsoft) account, whose "domain" is this PC's name, which the
/// target must not receive (the same reason [`windows_account`] strips `.\`).
fn account_from_env(
    user: Option<String>,
    domain: Option<String>,
    computer: Option<String>,
) -> Option<String> {
    let user = user?;
    Some(match domain {
        Some(d)
            if computer
                .as_deref()
                .is_none_or(|c| !c.eq_ignore_ascii_case(&d)) =>
        {
            format!("{d}\\{user}")
        }
        _ => user,
    })
}

/// The current Windows sign-in as an account for the target: `DOMAIN\user` for a domain
/// account, the bare `user` for a local account (the target resolves it to its own local
/// account of that name; this PC's name is never sent as the domain). Windows hosts use it as
/// the account of a password that was stored (or typed in the editor) without a user name,
/// and [`SecretStore::set_for_host`] stores it in that case. `None` when unknown.
///
/// Microsoft accounts: `USERNAME` is the local profile name, not the account; a target
/// signed in with a Microsoft account needs its e-mail address as `remote.user` (the GUI /
/// CLI should pre-fill this value visibly so the user can correct it).
pub fn current_windows_account() -> Option<String> {
    let (user, domain, computer) = sign_in_env();
    account_from_env(user, domain, computer)
}

fn is_current_account_in(
    user: &str,
    name: Option<&str>,
    domain: Option<&str>,
    computer: Option<&str>,
) -> bool {
    let Some(name) = name.map(str::to_lowercase) else {
        return false;
    };
    let u = windows_account(user).to_lowercase();
    let domain = domain.map(str::to_lowercase);
    let computer = computer.map(str::to_lowercase);
    let local = match (&domain, &computer) {
        (None, _) => true,
        (Some(d), Some(c)) => d == c,
        (Some(_), None) => false,
    };
    match u.split_once('\\') {
        None => local && u == name,
        Some((d, n)) => {
            n == name && (domain.as_deref() == Some(d) || (local && computer.as_deref() == Some(d)))
        }
    }
}

/// `true` when `user` (a `remote.user` value) names the current Windows sign-in: a Windows
/// host with this user and no stored password connects with the current sign-in (single
/// sign-on). `user@domain` forms are not recognized.
pub fn is_current_windows_account(user: &str) -> bool {
    let (name, domain, computer) = sign_in_env();
    is_current_account_in(
        user,
        name.as_deref(),
        domain.as_deref(),
        computer.as_deref(),
    )
}

/// The SSH command override that a restart / shutdown of `host` runs instead of the platform
/// default (trimmed; `None` for the default, and for Windows hosts, which never use one).
/// Every restart / shutdown confirmation shows it (cross review X1).
pub fn custom_power_command(host: &Host, action: PowerAction) -> Option<&str> {
    let r = host.remote.as_ref().filter(|r| r.kind == RemoteKind::Ssh)?;
    let c = match action {
        PowerAction::Restart => &r.reboot_command,
        PowerAction::Shutdown => &r.shutdown_command,
    };
    c.as_deref().map(str::trim).filter(|c| !c.is_empty())
}

/// Why a configured SSH key file cannot work (checked when it is set, before any connection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileIssue {
    /// A network (UNC) path: never read (the operation fails with `RemoteFailure::KeyFile`).
    NetworkPath,
    /// A `.pub` file: the private key is needed.
    PublicKey,
    /// The file does not exist (or is not a file).
    Missing,
}

/// Checks a key file path as it will be used (`""` = none → `None`). Reads only the file's
/// metadata (never for network paths). Used by `wolm remote set --key-file` and the editor.
pub fn key_file_issue(path: &std::path::Path) -> Option<KeyFileIssue> {
    if path.as_os_str().is_empty() || path.to_string_lossy().trim().is_empty() {
        return None;
    }
    if is_network_path(path) {
        return Some(KeyFileIssue::NetworkPath);
    }
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pub"))
    {
        return Some(KeyFileIssue::PublicKey);
    }
    (!path.is_file()).then_some(KeyFileIssue::Missing)
}

/// `true` for a UNC / network path (`\\server\share\key`, `//server/...`, `\\?\UNC\...`):
/// reading a key file there would make Windows log on to that server with this user's
/// credentials, and an imported config could name any server. Pure (no I/O).
pub fn is_network_path(p: &std::path::Path) -> bool {
    let s = p.to_string_lossy().replace('/', "\\");
    match s.strip_prefix(r"\\?\") {
        Some(rest) => rest
            .get(..4)
            .is_some_and(|x| x.eq_ignore_ascii_case(r"UNC\")),
        None => s.starts_with(r"\\"),
    }
}

/// The configured SSH key file (blank = none).
fn key_file(r: &RemoteConfig) -> Option<std::path::PathBuf> {
    r.key_file
        .clone()
        .filter(|p| !p.to_string_lossy().trim().is_empty())
}

/// Resolved target of one operation.
struct Endpoint<'a> {
    remote: &'a RemoteConfig,
    at: Where,
}

/// A secret for one operation ([`RemoteClient::lookup`]).
enum Lookup {
    /// An override, or a stored secret whose binding matches.
    Found(Secret),
    /// Nothing stored (or hidden by an override).
    Missing,
    /// Stored for another kind / account / address / port, or unbound.
    Stale { stored_for: String },
    /// Credential Manager cannot be used in this logon session.
    Unavailable,
}

/// What the credential lookup noticed without failing: added as a hint to a permission error
/// of the operation.
#[derive(Debug, Clone, Copy, Default)]
struct CredNotes {
    unavailable: bool,
    stale: bool,
}

/// Account and password of a Windows operation (no password = the current sign-in).
struct WindowsLogin {
    user: Option<String>,
    password: Option<Zeroizing<String>>,
    notes: CredNotes,
}

impl CredNotes {
    fn apply(self, e: Error) -> Error {
        match e {
            Error::Remote(mut r) if r.kind() == ErrorKind::Permission => {
                let replaceable = matches!(r.hint, None | Some(RemoteHint::StoreCredentials));
                if self.unavailable && replaceable {
                    r.hint = Some(RemoteHint::SecretStoreUnavailable);
                } else if self.stale && r.hint.is_none() {
                    r.hint = Some(RemoteHint::StoredSecretNotUsed);
                }
                Error::Remote(r)
            }
            other => other,
        }
    }
}

impl RemoteClient {
    /// Real backends, Credential Manager, real probes and clocks.
    pub fn system() -> RemoteClient {
        RemoteClient::new(
            SecretStore::system(),
            Arc::new(SystemWindows),
            Arc::new(SystemSsh),
        )
    }

    /// Explicit secret store and backends (tests: mocks + [`SecretStore::in_memory`]).
    pub fn new(
        secrets: SecretStore,
        windows: Arc<dyn WindowsBackend>,
        ssh: Arc<dyn SshBackend>,
    ) -> RemoteClient {
        RemoteClient {
            secrets,
            windows,
            ssh,
            env: Arc::new(SystemVerifyEnv),
            overrides: SecretOverrides::default(),
            unattended: false,
        }
    }

    /// Replaces the probe / clock / sleep seam of the verification loops.
    pub fn with_verify_env(mut self, env: Arc<dyn VerifyEnv>) -> RemoteClient {
        self.env = env;
        self
    }

    /// For operations nobody started for this host (the GUI's automatic boot time, anything
    /// in the background): a Windows host that would connect with the current Windows sign-in
    /// (no usable saved password, see [`RemoteClient::uses_sign_in`]) is only contacted when
    /// the user confirmed that for its current management address
    /// ([`RemoteClient::confirm_sign_in`]). Otherwise the operation fails with
    /// [`RemoteFailure::SignInNotConfirmed`] before anything is sent, so a host that an import
    /// added or pointed elsewhere never receives this user's Windows logon by itself.
    pub fn unattended(mut self) -> RemoteClient {
        self.unattended = true;
        self
    }

    /// `true` when an operation for `host` would now connect with the current Windows sign-in:
    /// a Windows host without a usable saved password (or typed override) whose `remote.user`
    /// is empty or names the current sign-in. `false` for SSH hosts, hosts that send a saved
    /// password, and hosts whose operations fail before connecting (e.g. a password saved for
    /// another address). Reads the secret store (fast, local).
    pub fn uses_sign_in(&self, host: &Host) -> bool {
        let Ok(ep) = self.endpoint(host) else {
            return false;
        };
        ep.remote.kind == RemoteKind::Windows
            && self
                .windows_login(host, &ep, RemoteOp::BootTime)
                .is_ok_and(|l| l.password.is_none())
    }

    /// The check an [`RemoteClient::unattended`] client makes, for callers that decide before
    /// they start (e.g. `wolm boot-time` without host names): `Ok` unless `host` would use the
    /// current Windows sign-in without the user's confirmation for its management address
    /// ([`RemoteFailure::SignInNotConfirmed`], reported for `op`). Other problems of the host
    /// are left to the operation itself.
    pub fn check_sign_in(&self, host: &Host, op: RemoteOp) -> Result<()> {
        let Ok(ep) = self.endpoint(host) else {
            return Ok(());
        };
        if self.uses_sign_in(host) {
            self.require_sign_in_confirmed(host, &ep, op)
        } else {
            Ok(())
        }
    }

    /// Records that the **user** wants `host` contacted with the current Windows sign-in at its
    /// management address, when it would use it ([`RemoteClient::uses_sign_in`]). Call it for
    /// explicit user actions only: an operation the user started for this host, the editor's
    /// save, `wolm remote set` / `wolm edit` — never for an import or an automatic operation.
    ///
    /// Returns the account (`remote.user`, else the current sign-in, `""` when unknown) when
    /// the confirmation was recorded now (tell the user once: "connects with your Windows
    /// sign-in"), `None` when it is not needed or was already recorded.
    /// Errors: [`Error::SecretStore`] (callers may go on: the operation itself still works).
    pub fn confirm_sign_in(&self, host: &Host) -> Result<Option<String>> {
        if !self.uses_sign_in(host) || !self.secrets.confirm_sign_in(host)? {
            return Ok(None);
        }
        let account = host
            .remote
            .as_ref()
            .and_then(|r| r.user())
            .map(str::to_owned)
            .or_else(current_windows_account)
            .unwrap_or_default();
        log::info!(
            "{}: the use of the current Windows sign-in is confirmed for {}",
            host.name,
            host.management_address()
                .map(ToString::to_string)
                .unwrap_or_default()
        );
        Ok(Some(account))
    }

    /// Uses these secrets instead of the stored ones (editor "Test connection" / "Get from IP"
    /// with a draft: typed values, or "deleted" flags). Typed values are used as they are;
    /// [`SecretOverride::Stored`] secrets must match the draft host's kind, account,
    /// management address and SSH port like any stored secret (after the user changed one of
    /// them in the editor, a stored password is not used until it is typed again:
    /// [`RemoteFailure::SecretMismatch`]).
    pub fn with_overrides(mut self, overrides: SecretOverrides) -> RemoteClient {
        self.overrides = overrides;
        self
    }

    /// The secret store.
    pub fn secrets(&self) -> &SecretStore {
        &self.secrets
    }

    fn endpoint<'h>(&self, host: &'h Host) -> Result<Endpoint<'h>> {
        let remote = host
            .remote
            .as_ref()
            .ok_or_else(|| Error::RemoteNotConfigured {
                host: host.name.clone(),
            })?;
        let address = host
            .management_address()
            .ok_or_else(|| Error::RemoteNoAddress {
                host: host.name.clone(),
            })?
            .to_string();
        Ok(Endpoint {
            remote,
            at: Where {
                host: host.name.clone(),
                address,
                backend: remote.kind,
                port: match remote.kind {
                    RemoteKind::Windows => 0,
                    RemoteKind::Ssh => remote.ssh_port(),
                },
            },
        })
    }

    /// A secret for this operation: the override, else the stored one when its binding and
    /// account match the host as it is now.
    fn lookup(&self, host: &Host, kind: SecretKind) -> Result<Lookup> {
        match self.overrides.get(kind) {
            SecretOverride::Value(v) => Ok(Lookup::Found(Secret {
                user: String::new(),
                secret: v.clone(),
            })),
            SecretOverride::Absent => Ok(Lookup::Missing),
            SecretOverride::Stored => match self.secrets.get_with_binding(host.id, kind) {
                Ok(None) => Ok(Lookup::Missing),
                Ok(Some((s, b))) => Ok(match secrets::check_usable(host, kind, &s, b.as_ref()) {
                    Ok(()) => Lookup::Found(s),
                    Err(stored_for) => {
                        log::warn!(
                            "{}: the stored {kind} was saved for {:?}, not for the current settings; not used",
                            host.name,
                            stored_for
                        );
                        Lookup::Stale { stored_for }
                    }
                }),
                Err(Error::SecretStore {
                    failure: SecretStoreFailure::Unavailable,
                    detail,
                }) => {
                    log::warn!(
                        "Credential Manager unavailable; cannot read the stored {kind}: {detail}"
                    );
                    Ok(Lookup::Unavailable)
                }
                Err(e) => Err(e),
            },
        }
    }

    /// [`RemoteFailure::SecretMismatch`] for a stale stored secret.
    fn mismatch(
        &self,
        host: &Host,
        ep: &Endpoint<'_>,
        op: RemoteOp,
        kind: SecretKind,
        stored_for: String,
    ) -> Error {
        let expected_for = SecretBinding::for_host(host)
            .map(|b| b.label(secrets::expected_account(ep.remote).unwrap_or("")))
            .unwrap_or_default();
        ep.at.error(
            op,
            RemoteFailure::SecretMismatch {
                secret: kind,
                stored_for,
                expected_for,
            },
            None,
            None,
            format!("the stored {kind} was saved for another account or address; not used"),
        )
    }

    fn store_unavailable(ep: &Endpoint<'_>, op: RemoteOp, kind: SecretKind) -> Error {
        ep.at.error(
            op,
            RemoteFailure::SecretStoreUnavailable,
            None,
            None,
            format!("Credential Manager is not available in this logon session; the stored {kind} cannot be read"),
        )
    }

    fn windows_host(
        &self,
        host: &Host,
        ep: &Endpoint<'_>,
        settings: &Settings,
        op: RemoteOp,
    ) -> Result<(wol_winremote::RemoteHost, CredNotes)> {
        let login = self.windows_login(host, ep, op)?;
        if login.password.is_none() && self.unattended {
            // Cross review X2: never an unconfirmed single sign-on from a background operation.
            self.require_sign_in_confirmed(host, ep, op)?;
        }
        let mut rh = wol_winremote::RemoteHost::new(ep.at.address.clone());
        rh.connect_timeout = settings.remote.effective_connect_timeout();
        rh.user = login.user;
        rh.password = login.password;
        Ok((rh, login.notes))
    }

    /// The Windows account and password of an operation; no password = the current Windows
    /// sign-in (single sign-on).
    fn windows_login(&self, host: &Host, ep: &Endpoint<'_>, op: RemoteOp) -> Result<WindowsLogin> {
        let mut login = WindowsLogin {
            user: None,
            password: None,
            notes: CredNotes::default(),
        };
        let configured = ep.remote.user();
        // Without a password the current sign-in is used: fine when no account is configured
        // or the configured one is the current sign-in, never silently for another account.
        let sign_in_ok = configured.is_none_or(is_current_windows_account);
        match self.lookup(host, SecretKind::Login)? {
            Lookup::Found(s) => {
                let user = configured
                    .map(str::to_owned)
                    .or_else(|| Some(s.user.trim().to_owned()).filter(|u| !u.is_empty()))
                    .or_else(current_windows_account);
                match user {
                    Some(u) => {
                        login.user = Some(windows_account(&u));
                        login.password = Some(s.secret);
                    }
                    None => log::warn!(
                        "{}: a password is stored but no user name is known; using the current Windows sign-in",
                        host.name
                    ),
                }
            }
            Lookup::Missing if sign_in_ok => {}
            Lookup::Missing => {
                let account = configured.unwrap_or_default().to_owned();
                return Err(ep.at.error(
                    op,
                    RemoteFailure::PasswordRequired { account },
                    None,
                    None,
                    "a user name is configured but no password is stored",
                ));
            }
            Lookup::Stale { stored_for } => {
                return Err(self.mismatch(host, ep, op, SecretKind::Login, stored_for));
            }
            Lookup::Unavailable if sign_in_ok => login.notes.unavailable = true,
            Lookup::Unavailable => return Err(Self::store_unavailable(ep, op, SecretKind::Login)),
        }
        Ok(login)
    }

    /// [`RemoteFailure::SignInNotConfirmed`] unless the user confirmed the current sign-in for
    /// `host` at its management address (a store that cannot be read counts as "no").
    fn require_sign_in_confirmed(
        &self,
        host: &Host,
        ep: &Endpoint<'_>,
        op: RemoteOp,
    ) -> Result<()> {
        match self.secrets.sign_in_confirmed(host) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => log::warn!("{}: cannot read the sign-in confirmation: {e}", host.name),
        }
        Err(ep.at.error(
            op,
            RemoteFailure::SignInNotConfirmed,
            None,
            None,
            "the current Windows sign-in is not confirmed for this host and address; nothing was sent",
        ))
    }

    fn ssh_target(
        &self,
        host: &Host,
        ep: &Endpoint<'_>,
        settings: &Settings,
        op: RemoteOp,
    ) -> Result<(wol_ssh::Target, CredNotes)> {
        let r = ep.remote;
        let mut t = wol_ssh::Target::new(ep.at.address.clone(), r.ssh_user());
        t.port = r.ssh_port();
        t.host_key = r.host_key().map(str::to_owned);
        t.timeouts = wol_ssh::Timeouts::with_connect_ms(u64::from(
            settings.remote.effective_connect_timeout_ms(),
        ));
        let key = key_file(r);
        if let Some(k) = key.as_deref()
            && is_network_path(k)
        {
            return Err(ep.at.error(
                op,
                RemoteFailure::KeyFile {
                    path: k.display().to_string(),
                },
                None,
                None,
                "key files on network (UNC) paths are not used",
            ));
        }
        t.auth.key_file = key.clone();
        let mut notes = CredNotes::default();
        match self.lookup(host, SecretKind::Login)? {
            Lookup::Found(s) => t.auth.password = Some(s.secret),
            Lookup::Missing => {}
            Lookup::Stale { stored_for } if key.is_none() => {
                return Err(self.mismatch(host, ep, op, SecretKind::Login, stored_for));
            }
            Lookup::Stale { .. } => notes.stale = true,
            Lookup::Unavailable if key.is_none() => {
                return Err(Self::store_unavailable(ep, op, SecretKind::Login));
            }
            Lookup::Unavailable => notes.unavailable = true,
        }
        if key.is_some() {
            match self.lookup(host, SecretKind::KeyPassphrase)? {
                Lookup::Found(s) => t.auth.key_passphrase = Some(s.secret),
                Lookup::Missing | Lookup::Stale { .. } => {}
                Lookup::Unavailable => notes.unavailable = true,
            }
        }
        t.sudo = match r.sudo {
            SudoMode::Auto => wol_ssh::SudoMode::Auto,
            SudoMode::Root => wol_ssh::SudoMode::Root,
            SudoMode::NoPasswd => wol_ssh::SudoMode::NoPasswd,
            SudoMode::Password | SudoMode::Separate => wol_ssh::SudoMode::Password,
        };
        if matches!(op, RemoteOp::Restart | RemoteOp::Shutdown) {
            match r.sudo {
                SudoMode::Auto => match self.lookup(host, SecretKind::Sudo)? {
                    Lookup::Found(s) => t.sudo_password = Some(s.secret),
                    Lookup::Missing => {}
                    // wol-ssh falls back to the login password.
                    Lookup::Stale { .. } => notes.stale = true,
                    Lookup::Unavailable => notes.unavailable = true,
                },
                SudoMode::Separate => match self.lookup(host, SecretKind::Sudo)? {
                    Lookup::Found(s) => t.sudo_password = Some(s.secret),
                    Lookup::Missing => {
                        return Err(ep.at.error(
                            op,
                            RemoteFailure::SudoPasswordRequired,
                            None,
                            None,
                            "sudo mode `separate` but no sudo password is stored",
                        ));
                    }
                    Lookup::Stale { stored_for } => {
                        return Err(self.mismatch(host, ep, op, SecretKind::Sudo, stored_for));
                    }
                    Lookup::Unavailable => {
                        return Err(Self::store_unavailable(ep, op, SecretKind::Sudo));
                    }
                },
                SudoMode::Root | SudoMode::NoPasswd | SudoMode::Password => {}
            }
        }
        Ok((t, notes))
    }

    fn ssh_error(
        &self,
        ep: &Endpoint<'_>,
        op: RemoteOp,
        notes: CredNotes,
        e: wol_ssh::SshError,
    ) -> Error {
        let (addr, port) = (ep.at.address.clone(), ep.at.port);
        notes.apply(ep.at.ssh(
            op,
            e,
            || self.ssh.known_hosts_keys(&addr, port),
            key_file(ep.remote).is_some(),
            ep.remote.host_key(),
        ))
    }

    /// Reads the host's last boot time.
    ///
    /// **Blocking** (see the module docs; typically < 1 s). Errors: [`Error::RemoteNotConfigured`],
    /// [`Error::RemoteNoAddress`], [`Error::Remote`], [`Error::UnknownHostKey`],
    /// [`Error::HostKeyMismatch`], [`Error::SecretStore`].
    pub fn boot_time(&self, host: &Host, settings: &Settings) -> Result<BootInfo> {
        let ep = self.endpoint(host)?;
        let op = RemoteOp::BootTime;
        match ep.remote.kind {
            RemoteKind::Windows => {
                let (rh, notes) = self.windows_host(host, &ep, settings, op)?;
                self.windows
                    .boot_time(&rh)
                    .map(BootInfo::from_windows)
                    .map_err(|e| notes.apply(ep.at.windows(op, &e)))
            }
            RemoteKind::Ssh => {
                let (t, notes) = self.ssh_target(host, &ep, settings, op)?;
                self.ssh
                    .boot_time(&t)
                    .map(BootInfo::from_ssh)
                    .map_err(|e| self.ssh_error(&ep, op, notes, e))
            }
        }
    }

    /// Requests a restart or shutdown. Windows uses `opts` (countdown, force, message); SSH
    /// ignores them and runs the platform command (or the configured override) with root
    /// rights about 2 s later. Success only means the host **accepted** the request.
    ///
    /// Never retry automatically after [`RemoteFailure::PowerUnconfirmed`] (the command may
    /// be running): verify instead.
    ///
    /// **Blocking** (Windows: tens of seconds worst case; SSH: up to 121 s with defaults).
    /// Errors: as [`RemoteClient::boot_time`], plus sudo failures, `LocalTarget` (this PC).
    pub fn power(
        &self,
        host: &Host,
        settings: &Settings,
        action: PowerAction,
        opts: &PowerOptions,
    ) -> Result<PowerOutcome> {
        let ep = self.endpoint(host)?;
        let op = action.op();
        match ep.remote.kind {
            RemoteKind::Windows => {
                let (rh, notes) = self.windows_host(host, &ep, settings, op)?;
                let wopts = wol_winremote::PowerOptions {
                    delay_secs: opts.delay_secs,
                    force: opts.force,
                    message: opts
                        .message
                        .as_deref()
                        .map(str::trim)
                        .filter(|m| !m.is_empty())
                        .map(str::to_owned),
                };
                let waction = match action {
                    PowerAction::Restart => wol_winremote::PowerAction::Restart,
                    PowerAction::Shutdown => wol_winremote::PowerAction::Shutdown,
                };
                let out = self
                    .windows
                    .power(&rh, waction, &wopts)
                    .map_err(|e| notes.apply(ep.at.windows(op, &e)))?;
                log::info!("{}: {action} accepted ({out:?})", host.name);
                Ok(match out {
                    wol_winremote::PowerOutcome::Accepted => PowerOutcome::Accepted,
                    wol_winremote::PowerOutcome::Scheduled => PowerOutcome::Scheduled {
                        delay_secs: opts.delay_secs,
                    },
                })
            }
            RemoteKind::Ssh => {
                let (t, notes) = self.ssh_target(host, &ep, settings, op)?;
                let overrides = wol_ssh::PowerOverrides {
                    reboot_command: ep.remote.reboot_command.clone(),
                    shutdown_command: ep.remote.shutdown_command.clone(),
                    arm_wol_iface: None,
                };
                let saction = match action {
                    PowerAction::Restart => wol_ssh::PowerAction::Restart,
                    PowerAction::Shutdown => wol_ssh::PowerAction::Shutdown,
                };
                let s = self
                    .ssh
                    .power(&t, saction, &overrides)
                    .map_err(|e| self.ssh_error(&ep, op, notes, e))?;
                log::info!(
                    "{}: {action} scheduled via {} ({:?}): {}",
                    host.name,
                    s.method,
                    s.elevation,
                    s.command
                );
                Ok(PowerOutcome::Accepted)
            }
        }
    }

    /// Cancels a pending Windows shutdown / restart (the countdown).
    ///
    /// **Blocking** (like [`RemoteClient::power`]). Errors: [`Error::RemoteUnsupported`] for
    /// SSH hosts; [`RemoteFailure::NoShutdownInProgress`] when nothing is pending.
    pub fn abort_shutdown(&self, host: &Host, settings: &Settings) -> Result<()> {
        let ep = self.endpoint(host)?;
        let op = RemoteOp::AbortShutdown;
        match ep.remote.kind {
            RemoteKind::Windows => {
                let (rh, notes) = self.windows_host(host, &ep, settings, op)?;
                self.windows
                    .abort_shutdown(&rh)
                    .map_err(|e| notes.apply(ep.at.windows(op, &e)))
            }
            RemoteKind::Ssh => Err(Error::RemoteUnsupported {
                host: host.name.clone(),
                kind: RemoteKind::Ssh,
                op,
            }),
        }
    }

    /// Reads the host's physical NIC candidates, best first (never empty on success).
    ///
    /// **Blocking** (Windows: WMI over DCOM, tens of seconds when the WMI firewall group is
    /// closed). Errors: as [`RemoteClient::boot_time`]; [`RemoteFailure::NoCandidates`].
    pub fn mac_candidates(&self, host: &Host, settings: &Settings) -> Result<Vec<MacCandidate>> {
        let ep = self.endpoint(host)?;
        let op = RemoteOp::MacCandidates;
        let mut v: Vec<MacCandidate> = match ep.remote.kind {
            RemoteKind::Windows => {
                let (rh, notes) = self.windows_host(host, &ep, settings, op)?;
                self.windows
                    .mac_candidates(&rh)
                    .map_err(|e| notes.apply(ep.at.windows(op, &e)))?
                    .into_iter()
                    .filter_map(MacCandidate::from_windows)
                    .collect()
            }
            RemoteKind::Ssh => {
                let (t, notes) = self.ssh_target(host, &ep, settings, op)?;
                self.ssh
                    .mac_candidates(&t)
                    .map_err(|e| self.ssh_error(&ep, op, notes, e))?
                    .into_iter()
                    .map(MacCandidate::from_ssh)
                    .collect()
            }
        };
        v.sort_by_key(|c| std::cmp::Reverse(c.score));
        if v.is_empty() {
            return Err(ep.at.error(
                op,
                RemoteFailure::NoCandidates,
                None,
                None,
                "no physical network adapter found",
            ));
        }
        Ok(v)
    }

    /// Connects and reads OS, boot time and an administrator hint ("Test connection").
    ///
    /// **Blocking** (as [`RemoteClient::boot_time`], plus a best-effort WMI query on Windows).
    pub fn test_connection(&self, host: &Host, settings: &Settings) -> Result<ConnInfo> {
        let ep = self.endpoint(host)?;
        let op = RemoteOp::TestConnection;
        match ep.remote.kind {
            RemoteKind::Windows => {
                let (rh, notes) = self.windows_host(host, &ep, settings, op)?;
                let c = self
                    .windows
                    .test_connection(&rh)
                    .map_err(|e| notes.apply(ep.at.windows(op, &e)))?;
                Ok(ConnInfo {
                    os: c.os,
                    boot: BootInfo::from_windows(c.boot),
                    admin_hint: c.user_is_admin_or_root,
                    admin_check: AdminCheck::of_windows(c.admin_check),
                    user: None,
                    kernel: None,
                })
            }
            RemoteKind::Ssh => {
                let (t, notes) = self.ssh_target(host, &ep, settings, op)?;
                let c = self
                    .ssh
                    .test_connection(&t)
                    .map_err(|e| self.ssh_error(&ep, op, notes, e))?;
                let admin = c.likely_admin();
                Ok(ConnInfo {
                    os: Some(c.os),
                    boot: BootInfo::from_ssh(c.boot),
                    admin_hint: Some(admin),
                    admin_check: if admin {
                        AdminCheck::Admin
                    } else {
                        AdminCheck::NotAdmin
                    },
                    user: Some(c.user),
                    kernel: Some(c.kernel),
                })
            }
        }
    }

    /// Reads an SSH host's key without logging in (no credentials are sent), for
    /// `wolm ssh trust`. **Blocking** (≤ 3 × connect timeout + 15 s).
    /// Errors: [`Error::RemoteUnsupported`] for Windows hosts, [`Error::Remote`].
    pub fn scan_host_key(&self, host: &Host, settings: &Settings) -> Result<HostKeyInfo> {
        let ep = self.endpoint(host)?;
        let op = RemoteOp::ScanHostKey;
        if ep.remote.kind != RemoteKind::Ssh {
            return Err(Error::RemoteUnsupported {
                host: host.name.clone(),
                kind: ep.remote.kind,
                op,
            });
        }
        let timeouts = wol_ssh::Timeouts::with_connect_ms(u64::from(
            settings.remote.effective_connect_timeout_ms(),
        ));
        self.ssh
            .scan_host_key(&ep.at.address, ep.at.port, timeouts)
            .map(HostKeyInfo::from)
            .map_err(|e| self.ssh_error(&ep, op, CredNotes::default(), e))
    }

    /// `true` when `~/.ssh/known_hosts` (read-only) has exactly this key for the host's
    /// management address and port, i.e. OpenSSH already trusts it.
    pub fn in_known_hosts(&self, host: &Host, openssh_line: &str) -> bool {
        let Ok(ep) = self.endpoint(host) else {
            return false;
        };
        let Ok(k) = parse_host_key(openssh_line) else {
            return false;
        };
        self.ssh
            .known_hosts_keys(&ep.at.address, ep.at.port)
            .iter()
            .any(|x| x.openssh_line == k.openssh_line)
    }

    /// Waits until a restarted host is back with a new boot. See [`verify_restart`].
    pub fn verify_restart(
        &self,
        host: &Host,
        settings: &Settings,
        before: Option<&BootInfo>,
        deadline: Instant,
        cancel: &AtomicBool,
        on_tick: impl FnMut(&VerifyTick),
    ) -> RestartVerify {
        verify::restart(self, host, settings, before, deadline, cancel, on_tick)
    }

    /// Waits until a host stops answering. See [`verify_shutdown`].
    pub fn verify_shutdown(
        &self,
        host: &Host,
        settings: &Settings,
        deadline: Instant,
        cancel: &AtomicBool,
        on_tick: impl FnMut(&VerifyTick),
    ) -> ShutdownVerify {
        verify::shutdown(self, host, settings, deadline, cancel, on_tick)
    }
}

// ---------------------------------------------------------------------------------------------
// Free functions (real backends)
// ---------------------------------------------------------------------------------------------

/// [`RemoteClient::boot_time`] with the real backends. **Blocking**.
pub fn boot_time(host: &Host, settings: &Settings) -> Result<BootInfo> {
    RemoteClient::system().boot_time(host, settings)
}

/// [`RemoteClient::power`] with the real backends. **Blocking**.
pub fn power(
    host: &Host,
    settings: &Settings,
    action: PowerAction,
    opts: &PowerOptions,
) -> Result<PowerOutcome> {
    RemoteClient::system().power(host, settings, action, opts)
}

/// [`RemoteClient::abort_shutdown`] with the real backends (Windows only). **Blocking**.
pub fn abort_shutdown(host: &Host, settings: &Settings) -> Result<()> {
    RemoteClient::system().abort_shutdown(host, settings)
}

/// [`RemoteClient::mac_candidates`] with the real backends. **Blocking**.
pub fn mac_candidates(host: &Host, settings: &Settings) -> Result<Vec<MacCandidate>> {
    RemoteClient::system().mac_candidates(host, settings)
}

/// [`RemoteClient::test_connection`] with the real backends. **Blocking**.
pub fn test_connection(host: &Host, settings: &Settings) -> Result<ConnInfo> {
    RemoteClient::system().test_connection(host, settings)
}

/// [`RemoteClient::scan_host_key`] with the real backend. **Blocking**.
pub fn scan_host_key(host: &Host, settings: &Settings) -> Result<HostKeyInfo> {
    RemoteClient::system().scan_host_key(host, settings)
}

/// Waits until a restarted host answers again **and** reports a new boot: a boot that started
/// after this call started (its uptime is at most the elapsed monotonic time +
/// [`NEW_BOOT_SLACK`], so clock steps on this PC do not matter), with another boot id than
/// `before` / the first reading when both have one. `approximate` readings (Windows without
/// statistics rights, whose uptime can wrap every 49.7 days) also need the host to have been
/// seen down. A reading of the old boot (or a stale `before`) becomes the baseline.
///
/// Call it right after [`power`] returned, with `before` read right before [`power`] (not a
/// cached value; a stale one is tolerated but not needed).
///
/// Probes every [`RESTART_POLL`] ([`verify_probe_spec`]: the management address) and reads
/// the boot time whenever the host answers, every round when it is not probed, and every
/// third round while the probe says "down" (probes can have blind spots). Network errors
/// while it boots keep the loop going; host-key, configuration and credential errors end it
/// ([`RestartVerify::Failed`]), permission errors (wrong password) after two in a row.
///
/// **Blocking** until verified, `deadline` (use [`verify_timeout`]) or `cancel` (checked at
/// least every 100 ms while sleeping and after every remote call). One boot-time read can
/// block (up to about a minute for SSH with the default timeouts), so cancelling and the
/// deadline can be late by one such call. `on_tick` gets every round's result.
pub fn verify_restart(
    host: &Host,
    settings: &Settings,
    before: Option<&BootInfo>,
    deadline: Instant,
    cancel: &AtomicBool,
    on_tick: impl FnMut(&VerifyTick),
) -> RestartVerify {
    RemoteClient::system().verify_restart(host, settings, before, deadline, cancel, on_tick)
}

/// Waits until a host stops answering: [`SHUTDOWN_FAILURES`] probes in a row without an
/// answer (`Down`, or `Unresolved` for names the host served itself) after the host was seen
/// answering, every [`SHUTDOWN_POLL`], on the management address and port
/// ([`verify_probe_spec`]). A failing local probe (`HostState::Error`) neither counts nor
/// resets. A host that is not monitored (no address, probe `none`) returns
/// [`ShutdownVerify::NotMonitored`] at once, and so does, after [`SHUTDOWN_FAILURES`] rounds, a
/// host the probe never saw answering (it cannot tell whether it stopped; review R5).
///
/// **Blocking** until then, `deadline` or `cancel`.
pub fn verify_shutdown(
    host: &Host,
    settings: &Settings,
    deadline: Instant,
    cancel: &AtomicBool,
    on_tick: impl FnMut(&VerifyTick),
) -> ShutdownVerify {
    RemoteClient::system().verify_shutdown(host, settings, deadline, cancel, on_tick)
}

/// How long to verify an accepted request: `settings.remote.restart_verify_timeout_secs` /
/// `shutdown_verify_timeout_secs`, plus the Windows countdown of a scheduled request.
pub fn verify_timeout(
    action: PowerAction,
    settings: &Settings,
    outcome: &PowerOutcome,
) -> Duration {
    let base = match action {
        PowerAction::Restart => settings.remote.effective_restart_verify_timeout(),
        PowerAction::Shutdown => settings.remote.effective_shutdown_verify_timeout(),
    };
    base + Duration::from_secs(u64::from(outcome.delay_secs()))
}

// ---------------------------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------------------------

/// What the user saw when deciding to trust a host key: where the key was received and the key
/// that was pinned then (review S4). [`trust_host_key`] refuses when the host no longer matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBasis {
    /// Management address the key was read from ([`HostKeyProblem::address`]).
    pub address: String,
    /// SSH port.
    pub port: u16,
    /// The pinned key at that time (`None` for a first trust).
    pub pinned: Option<String>,
}

impl TrustBasis {
    /// `host` as it is now: its management address, SSH port and pinned key (`None` when it is
    /// not an SSH host with an address).
    pub fn of(host: &Host) -> Option<TrustBasis> {
        let r = host.remote.as_ref().filter(|r| r.kind == RemoteKind::Ssh)?;
        Some(TrustBasis {
            address: host.management_address()?.to_string(),
            port: r.ssh_port(),
            pinned: r.host_key().map(str::to_owned),
        })
    }

    /// The first contact reported by [`Error::UnknownHostKey`] (nothing was pinned).
    pub fn unknown_key(p: &HostKeyProblem) -> TrustBasis {
        TrustBasis {
            address: p.address.clone(),
            port: p.port,
            pinned: None,
        }
    }
}

/// Same address (case-insensitive, trailing dot ignored).
fn same_address(a: &str, b: &str) -> bool {
    let n = |s: &str| s.trim().trim_end_matches('.').to_ascii_lowercase();
    n(a) == n(b)
}

/// Same pinned key (both unparsable lines compare as text).
fn same_pin(a: Option<&str>, b: Option<&str>) -> bool {
    let n = |s: &str| {
        parse_host_key(s)
            .map(|k| k.openssh_line)
            .unwrap_or_else(|_| s.trim().to_owned())
    };
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => n(a) == n(b),
        _ => false,
    }
}

/// Pins `openssh_line` as the SSH host key of host `id` (call inside `Store::update`, then
/// retry the operation). Returns the parsed key.
///
/// `basis` is what the user saw when deciding (review S4): the key is pinned only while the
/// host still has that management address and SSH port and the same pinned key as then (or
/// already this key). Otherwise nothing changes and [`Error::RemoteChanged`] asks to connect
/// again: a key read from one server is never pinned for another address, and a key pinned
/// meanwhile (by the other program, an import) is never replaced.
///
/// Errors: [`Error::HostIdNotFound`], [`Error::RemoteNotConfigured`],
/// [`Error::RemoteUnsupported`] (Windows host), [`Error::InvalidValue`] (bad line),
/// [`Error::RemoteChanged`].
pub fn trust_host_key(
    cfg: &mut Config,
    id: HostId,
    openssh_line: &str,
    basis: &TrustBasis,
) -> Result<HostKeyInfo> {
    let key = parse_host_key(openssh_line)?;
    let host = cfg.get_mut(id).ok_or(Error::HostIdNotFound(id))?;
    let name = host.name.clone();
    let address = host.management_address().map(ToString::to_string);
    let r = host
        .remote
        .as_mut()
        .ok_or(Error::RemoteNotConfigured { host: name.clone() })?;
    if r.kind != RemoteKind::Ssh {
        return Err(Error::RemoteUnsupported {
            host: name,
            kind: r.kind,
            op: RemoteOp::HostKey,
        });
    }
    let same_target =
        address.is_some_and(|a| same_address(&a, &basis.address)) && r.ssh_port() == basis.port;
    let current = r.host_key();
    let pin_ok =
        same_pin(current, basis.pinned.as_deref()) || same_pin(current, Some(&key.openssh_line));
    if !same_target || !pin_ok {
        return Err(Error::RemoteChanged { host: name });
    }
    r.host_key = Some(key.openssh_line.clone());
    Ok(key)
}

/// Removes the pinned SSH host key of host `id` (the next connection asks again). Returns
/// `true` when a key was pinned. Errors: [`Error::HostIdNotFound`].
pub fn forget_host_key(cfg: &mut Config, id: HostId) -> Result<bool> {
    let host = cfg.get_mut(id).ok_or(Error::HostIdNotFound(id))?;
    Ok(host
        .remote
        .as_mut()
        .and_then(|r| r.host_key.take())
        .is_some())
}
