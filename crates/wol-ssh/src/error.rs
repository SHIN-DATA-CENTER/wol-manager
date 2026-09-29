//! [`SshError`] and its coarse classification [`ErrorClass`].

use std::fmt;
use std::path::PathBuf;

/// Result alias used throughout the crate.
pub type Result<T, E = SshError> = std::result::Result<T, E>;

/// Which phase of an operation ran out of time (see [`SshError::Timeout`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeoutStage {
    /// Host name resolution (bounded by [`Timeouts::connect`](crate::Timeouts::connect)).
    Resolve,
    /// TCP connect (bounded by [`Timeouts::connect`](crate::Timeouts::connect) per address).
    Connect,
    /// SSH banner exchange and key exchange (shares
    /// [`Timeouts::handshake`](crate::Timeouts::handshake) with authentication).
    Handshake,
    /// User authentication (shares [`Timeouts::handshake`](crate::Timeouts::handshake) with the
    /// key exchange).
    Authentication,
    /// A remote command (bounded by the per-command timeout).
    Command,
}

impl fmt::Display for TimeoutStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TimeoutStage::Resolve => "name resolution",
            TimeoutStage::Connect => "TCP connect",
            TimeoutStage::Handshake => "SSH handshake",
            TimeoutStage::Authentication => "SSH authentication",
            TimeoutStage::Command => "remote command",
        })
    }
}

/// Coarse error class, for exit codes and i18n message selection (see [`SshError::class`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// Unreachable, refused, timed out or the connection dropped (CLI exit 5).
    Network,
    /// Authentication or privilege failure: wrong/missing credentials, sudo problems,
    /// not root (CLI exit 7).
    Permission,
    /// Host key unknown or changed (CLI exit 7 with a specific message).
    HostKey,
    /// Invalid local configuration or input (bad pin, bad override, unreadable key file).
    Config,
    /// The remote side misbehaved: protocol error, refused command, non-zero exit,
    /// unexpected output, unconfirmed power command.
    Remote,
    /// A local failure unrelated to the remote host (e.g. the async runtime could not start).
    Internal,
}

/// Errors returned by every operation of this crate.
///
/// Messages are English and meant for logs; user-facing text should be chosen from the
/// variant (and [`ErrorClass`]) by the caller. No variant ever contains a secret.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SshError {
    /// Invalid local input: empty host/user, unparsable pinned host key, disallowed characters
    /// in a power command override, invalid interface name, password containing a line break.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The host name could not be resolved.
    #[error("cannot resolve host name {host:?}: {message}")]
    Resolve {
        /// The host name as given.
        host: String,
        /// Resolver error text.
        message: String,
    },

    /// TCP connection failed (refused, unreachable, reset).
    #[error("cannot connect to {addr}: {message}")]
    Connect {
        /// `ip:port` that was tried last.
        addr: String,
        /// OS error text.
        message: String,
    },

    /// A phase did not finish within its timeout.
    #[error("timed out during {0}")]
    Timeout(TimeoutStage),

    /// The SSH connection was closed or lost (by the server, the network or a keepalive
    /// timeout) while it was needed.
    #[error("SSH connection lost: {0}")]
    Disconnected(String),

    /// SSH protocol failure: not an SSH server, no common algorithm, bad signature, ...
    #[error("SSH protocol error: {0}")]
    Protocol(String),

    /// First contact: no host key is pinned. Show `fingerprint_sha256` to the user and, if they
    /// trust it, store `openssh_line` as the pinned key and retry.
    #[error("unknown SSH host key {fingerprint_sha256}")]
    UnknownHostKey {
        /// The server's public key as an OpenSSH line without comment
        /// (`"ssh-ed25519 AAAA..."`), suitable for [`Target::host_key`](crate::Target::host_key).
        openssh_line: String,
        /// `"SHA256:..."`, the same text `ssh-keygen -lf` prints.
        fingerprint_sha256: String,
    },

    /// The server presented a different key than the pinned one. Never auto-replace the pin.
    #[error("SSH HOST KEY MISMATCH: pinned {expected_fp}, server presented {actual_fp}")]
    HostKeyMismatch {
        /// Fingerprint of the pinned key (`"SHA256:..."`).
        expected_fp: String,
        /// Fingerprint of the key the server presented.
        actual_fp: String,
    },

    /// The server no longer offers a host key of the pinned type (it may have been
    /// reinstalled or reconfigured). Treat like [`SshError::HostKeyMismatch`].
    #[error("the server no longer offers a {key_type} host key (pinned {expected_fp})")]
    HostKeyTypeUnavailable {
        /// Fingerprint of the pinned key.
        expected_fp: String,
        /// Algorithm of the pinned key, e.g. `"ssh-ed25519"`.
        key_type: String,
    },

    /// The private key file could not be read or is not a supported private key.
    #[error("cannot use SSH key file {}: {message}", path.display())]
    KeyFile {
        /// The key file path.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },

    /// The private key is passphrase-protected and no passphrase was supplied.
    #[error("SSH key file {} is passphrase-protected", path.display())]
    KeyPassphraseRequired {
        /// The key file path.
        path: PathBuf,
    },

    /// Decoding failed although a passphrase was supplied: wrong passphrase, or a key format
    /// that is not supported (e.g. PKCS#8 with PBKDF2-HMAC-SHA1 from `ssh-keygen -m PKCS8`;
    /// `ssh-keygen -p -f <key>` rewrites it in OpenSSH format).
    #[error("wrong passphrase for SSH key file {} (or unsupported key format)", path.display())]
    KeyPassphraseWrong {
        /// The key file path.
        path: PathBuf,
    },

    /// Neither a key file nor a password is configured.
    #[error("no SSH credentials configured (neither key file nor password)")]
    NoCredentials,

    /// The server rejected every credential that was tried.
    #[error(
        "SSH authentication failed (server accepts: {})",
        join_or_none(server_methods)
    )]
    AuthFailed {
        /// Methods the server still accepts (e.g. `["publickey"]` when password
        /// authentication is disabled on the server). May be empty.
        server_methods: Vec<String>,
    },

    /// A credential was accepted but the server requires additional authentication
    /// (e.g. `AuthenticationMethods publickey,password`) that is not configured.
    #[error(
        "SSH server requires additional authentication ({})",
        join_or_none(remaining_methods)
    )]
    AuthPartial {
        /// Methods that could complete authentication.
        remaining_methods: Vec<String>,
    },

    /// Keyboard-interactive authentication asked something other than a password
    /// (one-time code, second factor, several prompts).
    #[error("SSH server asked an unsupported authentication question: {prompt:?}")]
    AuthPromptUnsupported {
        /// The prompt text (sanitized, truncated).
        prompt: String,
    },

    /// The server refused to open a session or run the command (restricted account,
    /// `ForceCommand`, subsystem-only account, `MaxSessions`).
    #[error("the SSH server refused to run the command")]
    ExecRefused,

    /// Root privileges are required but the login user is not root and
    /// [`SudoMode::Root`](crate::SudoMode::Root) forbids sudo (or the privileged script reported
    /// `err=notroot`).
    #[error("root privileges required: the login user is not root")]
    NotRoot,

    /// sudo needs a password, but none is available or the mode forbids using it
    /// (`sudo -n`: "a password is required"; sudo-rs: "interactive authentication is required").
    #[error("sudo requires a password (store a sudo password or configure NOPASSWD)")]
    SudoPasswordRequired,

    /// sudo rejected the password. Never retried automatically (pam_faillock).
    #[error("sudo rejected the password")]
    SudoWrongPassword,

    /// The user may not run the command via sudo ("not in the sudoers file",
    /// "not allowed to execute", "may not run", sudo-rs "I'm afraid I can't do that",
    /// restricted command lists).
    #[error("the user is not allowed to run the command via sudo")]
    SudoNotAllowed,

    /// sudoers has `requiretty`; sudo cannot run without a terminal.
    #[error("sudo requires a terminal (sudoers requiretty)")]
    SudoNeedsTty,

    /// sudo is not installed on the host (e.g. Proxmox VE by default; log in as root).
    #[error("sudo is not installed on the remote host")]
    SudoMissing,

    /// The remote command exited unsuccessfully.
    #[error(
        "remote command failed (exit status {exit_status:?}, signal {exit_signal:?}): {stderr}"
    )]
    CommandFailed {
        /// Exit status, if the server sent one.
        exit_status: Option<u32>,
        /// Signal name (e.g. `"KILL"`), if the command was killed.
        exit_signal: Option<String>,
        /// Remote stderr (lossy UTF-8, trimmed, at most 2000 characters).
        stderr: String,
    },

    /// The power script produced no `WOLM1 power ok` marker and neither an exit status nor a
    /// diagnostic: the channel closed early, or the command timeout expired after the request
    /// was sent. The host may or may not be going down. Never treat this as success, and do
    /// not retry blindly (a second restart could be scheduled); verify by polling.
    #[error("power command not confirmed (no marker, no exit status); verify by polling")]
    PowerUnconfirmed,

    /// A read-only script produced no parsable `WOLM1` output (non-POSIX or `nologin` login
    /// shell, restricted account, unexpected platform).
    #[error("unexpected output from remote script: {0}")]
    UnexpectedOutput(String),

    /// Local failure (the async runtime or a helper thread could not be created, ...).
    #[error("internal error: {0}")]
    Internal(String),
}

fn join_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join(",")
    }
}

impl SshError {
    /// Coarse classification for exit codes and messages.
    pub fn class(&self) -> ErrorClass {
        use SshError::*;
        match self {
            Resolve { .. } | Connect { .. } | Timeout(_) | Disconnected(_) => ErrorClass::Network,
            UnknownHostKey { .. } | HostKeyMismatch { .. } | HostKeyTypeUnavailable { .. } => {
                ErrorClass::HostKey
            }
            KeyPassphraseRequired { .. }
            | KeyPassphraseWrong { .. }
            | NoCredentials
            | AuthFailed { .. }
            | AuthPartial { .. }
            | AuthPromptUnsupported { .. }
            | NotRoot
            | SudoPasswordRequired
            | SudoWrongPassword
            | SudoNotAllowed
            | SudoNeedsTty
            | SudoMissing => ErrorClass::Permission,
            InvalidInput(_) | KeyFile { .. } => ErrorClass::Config,
            Protocol(_)
            | ExecRefused
            | CommandFailed { .. }
            | PowerUnconfirmed
            | UnexpectedOutput(_) => ErrorClass::Remote,
            Internal(_) => ErrorClass::Internal,
        }
    }

    /// `true` for [`ErrorClass::Network`]: unreachable, refused, timed out, connection lost.
    pub fn is_network(&self) -> bool {
        self.class() == ErrorClass::Network
    }

    /// `true` for [`ErrorClass::Permission`]: credentials, authentication, sudo, not root.
    pub fn is_permission(&self) -> bool {
        self.class() == ErrorClass::Permission
    }

    /// `true` for [`ErrorClass::HostKey`]: unknown, changed or unavailable host key.
    pub fn is_host_key(&self) -> bool {
        self.class() == ErrorClass::HostKey
    }

    /// `true` for any [`SshError::Timeout`].
    pub fn is_timeout(&self) -> bool {
        matches!(self, SshError::Timeout(_))
    }

    /// `true` for the sudo-related permission errors ([`SshError::SudoPasswordRequired`],
    /// [`SshError::SudoWrongPassword`], [`SshError::SudoNotAllowed`],
    /// [`SshError::SudoNeedsTty`], [`SshError::SudoMissing`], [`SshError::NotRoot`]).
    pub fn is_sudo(&self) -> bool {
        matches!(
            self,
            SshError::SudoPasswordRequired
                | SshError::SudoWrongPassword
                | SshError::SudoNotAllowed
                | SshError::SudoNeedsTty
                | SshError::SudoMissing
                | SshError::NotRoot
        )
    }
}

/// Map a russh error that is not a host-key verdict.
pub(crate) fn from_russh(e: russh::Error) -> SshError {
    use russh::Error as E;
    match e {
        E::Disconnect
        | E::HUP
        | E::SendError
        | E::RecvError
        | E::ConnectionTimeout
        | E::KeepaliveTimeout
        | E::InactivityTimeout
        | E::IO(_)
        | E::Join(_) => SshError::Disconnected(e.to_string()),
        E::ChannelOpenFailure(_) => SshError::ExecRefused,
        other => SshError::Protocol(other.to_string()),
    }
}

/// Keep at most `max` characters, replacing control characters with spaces.
pub(crate) fn sanitize(s: &str, max: usize) -> String {
    let cleaned: String = s
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect();
    cleaned.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert!(SshError::Timeout(TimeoutStage::Connect).is_network());
        assert!(SshError::Timeout(TimeoutStage::Command).is_timeout());
        assert!(
            SshError::Connect {
                addr: "a".into(),
                message: "b".into()
            }
            .is_network()
        );
        assert!(SshError::SudoWrongPassword.is_permission());
        assert!(SshError::SudoWrongPassword.is_sudo());
        assert!(SshError::NotRoot.is_sudo());
        assert!(
            !SshError::AuthFailed {
                server_methods: vec![]
            }
            .is_sudo()
        );
        assert!(
            SshError::AuthFailed {
                server_methods: vec![]
            }
            .is_permission()
        );
        assert!(
            SshError::UnknownHostKey {
                openssh_line: String::new(),
                fingerprint_sha256: String::new()
            }
            .is_host_key()
        );
        assert_eq!(
            SshError::InvalidInput("x".into()).class(),
            ErrorClass::Config
        );
        assert_eq!(SshError::PowerUnconfirmed.class(), ErrorClass::Remote);
        assert_eq!(SshError::Internal("x".into()).class(), ErrorClass::Internal);
    }

    #[test]
    fn messages_are_readable() {
        let e = SshError::AuthFailed {
            server_methods: vec!["publickey".into(), "password".into()],
        };
        assert_eq!(
            e.to_string(),
            "SSH authentication failed (server accepts: publickey,password)"
        );
        let e = SshError::AuthFailed {
            server_methods: vec![],
        };
        assert!(e.to_string().ends_with("(server accepts: none)"));
        assert_eq!(
            SshError::Timeout(TimeoutStage::Handshake).to_string(),
            "timed out during SSH handshake"
        );
    }

    #[test]
    fn sanitize_strips_controls_and_truncates() {
        assert_eq!(sanitize("  a\tb\x1b[0m\n", 100), "a b [0m");
        assert_eq!(sanitize("abcdef", 3), "abc");
    }
}
