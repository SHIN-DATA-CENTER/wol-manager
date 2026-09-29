//! Connection parameters: [`Target`], [`Auth`], [`SudoMode`], [`Timeouts`].

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

/// Everything needed to reach and authenticate to one host.
///
/// Secrets are held in [`Zeroizing`] buffers; the [`Debug`] output redacts them.
#[derive(Clone)]
pub struct Target {
    /// Host name, IPv4 or IPv6 address (brackets around IPv6 are accepted).
    pub host: String,
    /// TCP port (default 22).
    pub port: u16,
    /// Login user (WoL Manager's config default is `"root"`).
    pub user: String,
    /// Credentials for SSH user authentication.
    pub auth: Auth,
    /// Pinned server key as an OpenSSH public-key line (`"ssh-ed25519 AAAA... [comment]"`).
    /// `None` = first contact: connecting fails with
    /// [`SshError::UnknownHostKey`](crate::SshError::UnknownHostKey).
    pub host_key: Option<String>,
    /// How privileged commands (restart / shutdown) obtain root.
    pub sudo: SudoMode,
    /// Separate sudo password. `None` = use [`Auth::password`] (the login password).
    pub sudo_password: Option<Zeroizing<String>>,
    /// Connect / handshake / command time limits.
    pub timeouts: Timeouts,
}

impl Target {
    /// A target with port 22, no credentials, no pinned key, [`SudoMode::Auto`] and
    /// default [`Timeouts`].
    pub fn new(host: impl Into<String>, user: impl Into<String>) -> Self {
        Target {
            host: host.into(),
            port: 22,
            user: user.into(),
            auth: Auth::default(),
            host_key: None,
            sudo: SudoMode::Auto,
            sudo_password: None,
            timeouts: Timeouts::default(),
        }
    }

    /// The password used for sudo: [`Target::sudo_password`], else [`Auth::password`].
    pub fn effective_sudo_password(&self) -> Option<&Zeroizing<String>> {
        self.sudo_password.as_ref().or(self.auth.password.as_ref())
    }
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("auth", &self.auth)
            .field("host_key", &self.host_key)
            .field("sudo", &self.sudo)
            .field("sudo_password", &redacted(&self.sudo_password))
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

/// SSH user-authentication credentials. Tried in this order: key file (if set and offered by
/// the server), then password (method `password`, or `keyboard-interactive` answering the
/// password prompt when the server does not offer `password`, e.g. stock FreeBSD).
#[derive(Clone, Default)]
pub struct Auth {
    /// OpenSSH private key file (ed25519, ECDSA P-256/384/521, RSA; OpenSSH, PEM or PuTTY
    /// format). `None` = no public-key authentication.
    pub key_file: Option<PathBuf>,
    /// Passphrase for an encrypted key file.
    pub key_passphrase: Option<Zeroizing<String>>,
    /// Login password (also answers a single hidden keyboard-interactive prompt).
    pub password: Option<Zeroizing<String>>,
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Auth")
            .field("key_file", &self.key_file)
            .field("key_passphrase", &redacted(&self.key_passphrase))
            .field("password", &redacted(&self.password))
            .finish()
    }
}

fn redacted(v: &Option<Zeroizing<String>>) -> &'static str {
    if v.is_some() { "<set>" } else { "<none>" }
}

/// How privileged commands obtain root. Config spelling: `auto | root | nopasswd | password`.
///
/// Whatever the mode, a login that already is uid 0 runs the command directly (no sudo;
/// Proxmox VE has no sudo by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SudoMode {
    /// uid 0 → direct; else `sudo -n`; if sudo answers that a password is required (classic
    /// sudo: "a password is required"; sudo-rs, the default on Ubuntu 25.10+: "interactive
    /// authentication is required") and a password is available
    /// ([`Target::effective_sudo_password`]), one attempt with `sudo -S` (no retry after a
    /// wrong password).
    #[default]
    Auto,
    /// The login must be root; a non-root login fails with
    /// [`SshError::NotRoot`](crate::SshError::NotRoot) without running anything.
    Root,
    /// Only `sudo -n` (NOPASSWD). A password prompt fails with
    /// [`SshError::SudoPasswordRequired`](crate::SshError::SudoPasswordRequired).
    NoPasswd,
    /// Always `sudo -S` with [`Target::effective_sudo_password`] on stdin.
    Password,
}

impl SudoMode {
    /// Config spelling: `"auto"`, `"root"`, `"nopasswd"`, `"password"`.
    pub fn as_str(self) -> &'static str {
        match self {
            SudoMode::Auto => "auto",
            SudoMode::Root => "root",
            SudoMode::NoPasswd => "nopasswd",
            SudoMode::Password => "password",
        }
    }

    /// Parse the config spelling (ASCII case-insensitive, surrounding whitespace ignored).
    pub fn parse(s: &str) -> Option<SudoMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(SudoMode::Auto),
            "root" => Some(SudoMode::Root),
            "nopasswd" => Some(SudoMode::NoPasswd),
            "password" => Some(SudoMode::Password),
            _ => None,
        }
    }
}

impl fmt::Display for SudoMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Time limits of one connection.
///
/// Worst case of [`Session::connect`](crate::Session::connect) =
/// [`Timeouts::connect_worst_case`]: name resolution (`connect`) + up to two TCP attempts
/// (`connect` each; IPv4 addresses first) + `handshake` (key exchange and authentication
/// together).
///
/// Any field may be [`Duration::MAX`] for "no limit" (deadlines saturate instead of
/// overflowing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Name resolution, and each TCP connect attempt. Default 5 s.
    pub connect: Duration,
    /// SSH banner + key exchange + user authentication, combined. Default 15 s.
    pub handshake: Duration,
    /// Default limit for each remote command run by the high-level operations. Default 30 s.
    pub command: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_secs(5),
            handshake: Duration::from_secs(15),
            command: Duration::from_secs(30),
        }
    }
}

impl Timeouts {
    /// Default timeouts with the given connect timeout (WoL Manager's
    /// `settings.remote.connect_timeout_ms`).
    pub fn with_connect_ms(ms: u64) -> Self {
        Timeouts {
            connect: Duration::from_millis(ms),
            ..Timeouts::default()
        }
    }

    /// Upper bound of [`Session::connect`](crate::Session::connect): `3 × connect + handshake`
    /// (saturating, so [`Duration::MAX`] fields mean "no limit" instead of overflowing).
    pub fn connect_worst_case(&self) -> Duration {
        self.connect
            .saturating_mul(3)
            .saturating_add(self.handshake)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secrets() {
        let mut t = Target::new("h", "u");
        t.auth.password = Some(Zeroizing::new("hunter2".into()));
        t.auth.key_passphrase = Some(Zeroizing::new("pass phrase".into()));
        t.sudo_password = Some(Zeroizing::new("sud0".into()));
        let s = format!("{t:?}");
        assert!(
            !s.contains("hunter2") && !s.contains("pass phrase") && !s.contains("sud0"),
            "{s}"
        );
        assert!(s.contains("<set>"));
    }

    #[test]
    fn sudo_password_falls_back_to_login_password() {
        let mut t = Target::new("h", "u");
        assert!(t.effective_sudo_password().is_none());
        t.auth.password = Some(Zeroizing::new("login".into()));
        assert_eq!(t.effective_sudo_password().unwrap().as_str(), "login");
        t.sudo_password = Some(Zeroizing::new("sudo".into()));
        assert_eq!(t.effective_sudo_password().unwrap().as_str(), "sudo");
    }

    #[test]
    fn sudo_mode_round_trip() {
        for m in [
            SudoMode::Auto,
            SudoMode::Root,
            SudoMode::NoPasswd,
            SudoMode::Password,
        ] {
            assert_eq!(SudoMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(SudoMode::parse(" NOPASSWD "), Some(SudoMode::NoPasswd));
        assert_eq!(SudoMode::parse("sudo"), None);
    }

    #[test]
    fn timeouts() {
        let t = Timeouts::with_connect_ms(2000);
        assert_eq!(t.connect, Duration::from_secs(2));
        assert_eq!(t.connect_worst_case(), Duration::from_secs(21));
        // Duration::MAX ("no limit") saturates instead of panicking.
        let t = Timeouts {
            connect: Duration::MAX,
            handshake: Duration::MAX,
            command: Duration::MAX,
        };
        assert_eq!(t.connect_worst_case(), Duration::MAX);
        let t = Timeouts {
            handshake: Duration::MAX,
            ..Timeouts::default()
        };
        assert_eq!(t.connect_worst_case(), Duration::MAX);
    }
}
