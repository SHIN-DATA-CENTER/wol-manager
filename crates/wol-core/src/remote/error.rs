//! Remote-management failures ([`RemoteError`], carried by [`crate::Error::Remote`]) and the
//! translation of `wol-winremote` / `wol-ssh` errors into [`crate::Error`].

use std::fmt;

use serde::Serialize;

use crate::error::{Error, ErrorKind, HostKeyProblem};
use crate::model::RemoteKind;

/// The remote operation that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteOp {
    /// Reading the boot time.
    BootTime,
    /// Restart request.
    Restart,
    /// Shutdown request.
    Shutdown,
    /// Cancelling a pending Windows shutdown.
    AbortShutdown,
    /// Reading the physical NIC's MAC candidates.
    MacCandidates,
    /// "Test connection".
    TestConnection,
    /// Reading an SSH host key without logging in (`wolm ssh trust`).
    ScanHostKey,
    /// Pinning / forgetting an SSH host key in the config.
    HostKey,
}

/// Which phase of an SSH connection ran out of time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteStage {
    /// Name resolution.
    Resolve,
    /// TCP connect.
    Connect,
    /// SSH banner / key exchange.
    Handshake,
    /// SSH authentication.
    Authentication,
    /// A remote command.
    Command,
}

/// What went wrong, independent of the backend. Drives the user text
/// ([`crate::i18n::describe_error`]) and [`RemoteFailure::kind`] (CLI exit code).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteFailure {
    /// Name not resolvable, port closed / filtered, host down, RPC unavailable.
    Unreachable,
    /// A phase of the SSH connection timed out.
    Timeout {
        /// The phase.
        stage: RemoteStage,
    },
    /// The connection was lost while it was needed.
    Disconnected,
    /// The host rejected the credentials (or the current Windows sign-in).
    AuthFailed {
        /// SSH: methods the server still accepts (`["publickey"]` = no password logins).
        server_methods: Vec<String>,
    },
    /// Authenticated but not allowed (not an administrator, UAC remote restrictions, DCOM).
    AccessDenied,
    /// Windows error 1219: this Windows logon already has a connection to the same server
    /// with other credentials.
    CredentialConflict,
    /// SSH: neither a key file nor a password is configured.
    NoCredentials,
    /// SSH: the key file cannot be used (unreadable, not a private key, `.pub` selected).
    KeyFile {
        /// The key file.
        path: String,
    },
    /// SSH: the key is passphrase-protected and no passphrase is stored.
    KeyPassphraseRequired {
        /// The key file.
        path: String,
    },
    /// SSH: wrong passphrase or unsupported key format.
    KeyPassphraseWrong {
        /// The key file.
        path: String,
    },
    /// SSH: the server wants an additional authentication step (2FA).
    AuthPartial {
        /// Methods that could complete the login.
        methods: Vec<String>,
    },
    /// SSH: keyboard-interactive asked something other than a password (one-time code).
    AuthPromptUnsupported {
        /// The prompt (sanitized).
        prompt: String,
    },
    /// SSH: root rights needed, the login is not root and the sudo mode is `root`.
    NotRoot,
    /// SSH: sudo needs a password and none is available.
    SudoPasswordRequired,
    /// SSH: sudo rejected the password (never retried).
    SudoWrongPassword,
    /// SSH: the user may not run the command with sudo.
    SudoNotAllowed,
    /// SSH: sudoers `requiretty`.
    SudoNeedsTty,
    /// SSH: sudo is not installed (Proxmox VE: log in as root).
    SudoMissing,
    /// Windows: restart / shutdown / abort of this PC itself is refused.
    LocalTarget,
    /// Invalid local input (host name, message, sudo password with a line break...).
    InvalidInput,
    /// The host does not support the query.
    Unsupported,
    /// Windows: a shutdown / restart is already in progress.
    ShutdownInProgress,
    /// Windows: the host is not ready (sign-in screen with fast user switching).
    NotReady,
    /// Windows: other users are signed in and "force" was off.
    UsersLoggedOn,
    /// Windows: there is no pending shutdown to cancel.
    NoShutdownInProgress,
    /// Windows Credential Manager is not available in this logon session.
    SecretStoreUnavailable,
    /// SSH protocol failure (not an SSH server, no common algorithm...).
    Protocol,
    /// SSH: the server refused to run the command (restricted account).
    ExecRefused,
    /// SSH: the power command failed.
    CommandFailed {
        /// Exit status, if known.
        exit_status: Option<u32>,
        /// Remote stderr (sanitized, at most 2000 characters).
        stderr: String,
    },
    /// SSH: the power command was sent but not confirmed (no marker, no exit status). The host
    /// may or may not be going down: verify by polling, never retry blindly.
    PowerUnconfirmed,
    /// The host answered with output that could not be parsed (e.g. a login shell that
    /// cannot run `sh`).
    UnexpectedOutput,
    /// No physical network adapter was found on the host.
    NoCandidates,
    /// Anything else (see the code and detail).
    Other,
    /// A password is stored for this host, but for another account, kind, management address
    /// or SSH port (the host was changed, e.g. by an import or an edit), or without that
    /// information (older build, changed outside WoL Manager). It was **not** sent; the user
    /// has to enter it again (editor / `wolm cred set`). Permission (exit 7).
    SecretMismatch {
        /// Which secret.
        secret: crate::secret::SecretKind,
        /// What it was stored for (`root@192.168.1.20:22 (SSH)`), `""` when unknown.
        stored_for: String,
        /// What the host needs now (same format).
        expected_for: String,
    },
    /// Windows: `remote.user` names an account other than the current sign-in and no password
    /// is stored for it (the current sign-in is not used instead). Permission (exit 7).
    PasswordRequired {
        /// The configured account.
        account: String,
    },
    /// A failure on this PC, not on the host (SSH: the runtime could not be created...).
    /// Io (exit 6).
    Local,
    /// Windows: an automatic operation ([`crate::remote::RemoteClient::unattended`]) would
    /// connect with the current Windows sign-in (no saved password), which the user has not
    /// confirmed for this host and management address on this PC (e.g. an import added or
    /// re-pointed it). Nothing was sent. Permission (exit 7).
    SignInNotConfirmed,
}

impl RemoteFailure {
    /// Coarse class: network → [`ErrorKind::Network`] (exit 5); credentials, rights, sudo,
    /// stored-password problems → [`ErrorKind::Permission`] (exit 7); bad local input, local
    /// target, unsupported → [`ErrorKind::InvalidInput`] (exit 2); no NIC →
    /// [`ErrorKind::NotFound`] (exit 3); local failures → [`ErrorKind::Io`] (exit 6); what
    /// the host reported → [`ErrorKind::Remote`] (exit 1).
    pub fn kind(&self) -> ErrorKind {
        use RemoteFailure::*;
        match self {
            Unreachable | Timeout { .. } | Disconnected => ErrorKind::Network,
            AuthFailed { .. }
            | AccessDenied
            | CredentialConflict
            | NoCredentials
            | KeyPassphraseRequired { .. }
            | KeyPassphraseWrong { .. }
            | AuthPartial { .. }
            | AuthPromptUnsupported { .. }
            | NotRoot
            | SudoPasswordRequired
            | SudoWrongPassword
            | SudoNotAllowed
            | SudoNeedsTty
            | SudoMissing
            | SecretStoreUnavailable
            | SecretMismatch { .. }
            | PasswordRequired { .. }
            | SignInNotConfirmed => ErrorKind::Permission,
            KeyFile { .. } | LocalTarget | InvalidInput | Unsupported => ErrorKind::InvalidInput,
            NoCandidates => ErrorKind::NotFound,
            Local => ErrorKind::Io,
            ShutdownInProgress
            | NotReady
            | UsersLoggedOn
            | NoShutdownInProgress
            | Protocol
            | ExecRefused
            | CommandFailed { .. }
            | PowerUnconfirmed
            | UnexpectedOutput
            | Other => ErrorKind::Remote,
        }
    }

    /// `true` for the sudo / root failures of SSH power requests.
    pub fn is_sudo(&self) -> bool {
        use RemoteFailure::*;
        matches!(
            self,
            NotRoot
                | SudoPasswordRequired
                | SudoWrongPassword
                | SudoNotAllowed
                | SudoNeedsTty
                | SudoMissing
        )
    }
}

/// How to fix a failure (rendered by [`crate::i18n::describe_error`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteHint {
    /// Local administrator accounts get a filtered token over the network (UAC remote
    /// restrictions, KB951016, `LocalAccountTokenFilterPolicy`).
    UacRemoteRestriction,
    /// Allow "File and Printer Sharing (SMB-In)" (TCP 445) on the target.
    SmbFirewall,
    /// Enable the "Windows Management Instrumentation (WMI)" firewall group on the target.
    WmiFirewall,
    /// SMB works but the remote-shutdown RPC endpoint is blocked.
    RemoteShutdownFirewall,
    /// WMI access denied before the password was proven: wrong password OR UAC / DCOM.
    WmiAccessDenied,
    /// Check user name and password (account name formats).
    CheckCredentials,
    /// The current Windows sign-in was not accepted: store an administrator account.
    StoreCredentials,
    /// Close the other connection to the same server (1219).
    CloseOtherConnections,
    /// Temporary state on the target; try again later.
    RetryLater,
    /// SSH server accepts only public keys: configure a key file.
    PasswordAuthDisabled,
    /// Credential Manager is not available in this logon session, so stored passwords could
    /// not be read (the operation went on without them).
    SecretStoreUnavailable,
    /// A stored password was not used because it was saved for another account / address
    /// (the operation went on without it, e.g. with the key file).
    StoredSecretNotUsed,
    /// SSH protocol error: check that the port is the SSH server's.
    CheckPort,
}

/// A failed remote operation ([`crate::Error::Remote`]). Never contains a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteError {
    /// Host name (label).
    pub host: String,
    /// Management address that was contacted.
    pub address: String,
    /// Backend.
    pub backend: RemoteKind,
    /// Operation.
    pub op: RemoteOp,
    /// What went wrong.
    pub failure: RemoteFailure,
    /// How to fix it, when known.
    pub hint: Option<RemoteHint>,
    /// OS error code for logs / support (`"error 1219"`, `"HRESULT 0x80070005"`).
    pub code: Option<String>,
    /// English detail for logs (may contain a localized OS message; not for display).
    pub detail: String,
}

impl RemoteError {
    /// Coarse class (see [`RemoteFailure::kind`]).
    pub fn kind(&self) -> ErrorKind {
        self.failure.kind()
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} on {} ({}) failed: {:?}",
            self.op, self.host, self.address, self.failure
        )?;
        if let Some(c) = &self.code {
            write!(f, " [{c}]")?;
        }
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

/// Where an operation went: for building errors.
#[derive(Debug, Clone)]
pub(crate) struct Where {
    pub host: String,
    pub address: String,
    pub backend: RemoteKind,
    pub port: u16,
}

impl Where {
    pub(crate) fn error(
        &self,
        op: RemoteOp,
        failure: RemoteFailure,
        hint: Option<RemoteHint>,
        code: Option<String>,
        detail: impl Into<String>,
    ) -> Error {
        Error::Remote(Box::new(RemoteError {
            host: self.host.clone(),
            address: self.address.clone(),
            backend: self.backend,
            op,
            failure,
            hint,
            code,
            detail: detail.into(),
        }))
    }

    /// Translates a `wol-winremote` error.
    pub(crate) fn windows(&self, op: RemoteOp, e: &wol_winremote::Error) -> Error {
        use wol_winremote::ErrorKind as K;
        let failure = match e.kind() {
            K::InvalidInput => RemoteFailure::InvalidInput,
            K::LocalTarget => RemoteFailure::LocalTarget,
            K::Unreachable => RemoteFailure::Unreachable,
            K::AuthFailed => RemoteFailure::AuthFailed {
                server_methods: Vec::new(),
            },
            K::AccessDenied => RemoteFailure::AccessDenied,
            K::CredentialConflict => RemoteFailure::CredentialConflict,
            K::ShutdownInProgress => RemoteFailure::ShutdownInProgress,
            K::NotReady => RemoteFailure::NotReady,
            K::UsersLoggedOn => RemoteFailure::UsersLoggedOn,
            K::NoShutdownInProgress => RemoteFailure::NoShutdownInProgress,
            K::SecretStoreUnavailable => RemoteFailure::SecretStoreUnavailable,
            K::Unsupported => RemoteFailure::Unsupported,
            _ => RemoteFailure::Other,
        };
        self.error(
            op,
            failure,
            e.hint().and_then(windows_hint),
            e.code().map(|c| c.to_string()),
            e.detail(),
        )
    }

    /// Translates a `wol-ssh` error. `known_hosts` lists the keys the user's
    /// `~/.ssh/known_hosts` has for this host (for [`HostKeyProblem::in_known_hosts`]);
    /// `pinned` is the pinned host key line (its algorithm names a changed key).
    pub(crate) fn ssh(
        &self,
        op: RemoteOp,
        e: wol_ssh::SshError,
        known_hosts: impl FnOnce() -> Vec<wol_ssh::HostKeyInfo>,
        has_key_file: bool,
        pinned: Option<&str>,
    ) -> Error {
        use wol_ssh::SshError as S;
        let detail = e.to_string();
        let (failure, hint) = match e {
            S::UnknownHostKey {
                openssh_line,
                fingerprint_sha256,
            } => {
                let algorithm = openssh_line
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let in_known_hosts = known_hosts().iter().any(|k| k.openssh_line == openssh_line);
                return Error::UnknownHostKey(Box::new(HostKeyProblem {
                    host: self.host.clone(),
                    address: self.address.clone(),
                    port: self.port,
                    algorithm,
                    fingerprint: fingerprint_sha256,
                    openssh_line,
                    expected_fingerprint: None,
                    in_known_hosts,
                }));
            }
            S::HostKeyMismatch {
                expected_fp,
                actual_fp,
            } => {
                // The server presents a key of the pinned type (it is compared with the pin):
                // name that type, so the `ssh-keygen -lf` hint points at the right file.
                let algorithm = pinned
                    .and_then(|k| k.split_whitespace().next())
                    .unwrap_or_default()
                    .to_owned();
                return Error::HostKeyMismatch(Box::new(HostKeyProblem {
                    host: self.host.clone(),
                    address: self.address.clone(),
                    port: self.port,
                    algorithm,
                    fingerprint: actual_fp,
                    openssh_line: String::new(),
                    expected_fingerprint: Some(expected_fp),
                    in_known_hosts: false,
                }));
            }
            S::HostKeyTypeUnavailable {
                expected_fp,
                key_type,
            } => {
                return Error::HostKeyMismatch(Box::new(HostKeyProblem {
                    host: self.host.clone(),
                    address: self.address.clone(),
                    port: self.port,
                    algorithm: key_type,
                    fingerprint: String::new(),
                    openssh_line: String::new(),
                    expected_fingerprint: Some(expected_fp),
                    in_known_hosts: false,
                }));
            }
            S::InvalidInput(_) => (RemoteFailure::InvalidInput, None),
            S::Resolve { .. } | S::Connect { .. } => (RemoteFailure::Unreachable, None),
            S::Timeout(stage) => (
                RemoteFailure::Timeout {
                    stage: match stage {
                        wol_ssh::TimeoutStage::Resolve => RemoteStage::Resolve,
                        wol_ssh::TimeoutStage::Connect => RemoteStage::Connect,
                        wol_ssh::TimeoutStage::Handshake => RemoteStage::Handshake,
                        wol_ssh::TimeoutStage::Authentication => RemoteStage::Authentication,
                        wol_ssh::TimeoutStage::Command => RemoteStage::Command,
                    },
                },
                None,
            ),
            S::Disconnected(_) => (RemoteFailure::Disconnected, None),
            S::Protocol(_) => (RemoteFailure::Protocol, Some(RemoteHint::CheckPort)),
            S::KeyFile { path, .. } => (
                RemoteFailure::KeyFile {
                    path: path.display().to_string(),
                },
                None,
            ),
            S::KeyPassphraseRequired { path } => (
                RemoteFailure::KeyPassphraseRequired {
                    path: path.display().to_string(),
                },
                None,
            ),
            S::KeyPassphraseWrong { path } => (
                RemoteFailure::KeyPassphraseWrong {
                    path: path.display().to_string(),
                },
                None,
            ),
            S::NoCredentials => (RemoteFailure::NoCredentials, None),
            S::AuthFailed { server_methods } => {
                let password_ok = server_methods
                    .iter()
                    .any(|m| m == "password" || m == "keyboard-interactive");
                let hint = (!has_key_file
                    && !password_ok
                    && server_methods.iter().any(|m| m == "publickey"))
                .then_some(RemoteHint::PasswordAuthDisabled);
                (RemoteFailure::AuthFailed { server_methods }, hint)
            }
            S::AuthPartial { remaining_methods } => (
                RemoteFailure::AuthPartial {
                    methods: remaining_methods,
                },
                None,
            ),
            S::AuthPromptUnsupported { prompt } => {
                (RemoteFailure::AuthPromptUnsupported { prompt }, None)
            }
            S::ExecRefused => (RemoteFailure::ExecRefused, None),
            S::NotRoot => (RemoteFailure::NotRoot, None),
            S::SudoPasswordRequired => (RemoteFailure::SudoPasswordRequired, None),
            S::SudoWrongPassword => (RemoteFailure::SudoWrongPassword, None),
            S::SudoNotAllowed => (RemoteFailure::SudoNotAllowed, None),
            S::SudoNeedsTty => (RemoteFailure::SudoNeedsTty, None),
            S::SudoMissing => (RemoteFailure::SudoMissing, None),
            S::CommandFailed {
                exit_status,
                stderr,
                ..
            } => (
                RemoteFailure::CommandFailed {
                    exit_status,
                    stderr,
                },
                None,
            ),
            S::PowerUnconfirmed => (RemoteFailure::PowerUnconfirmed, None),
            S::UnexpectedOutput(_) => (RemoteFailure::UnexpectedOutput, None),
            S::Internal(_) => (RemoteFailure::Local, None),
            _ => (RemoteFailure::Other, None),
        };
        self.error(op, failure, hint, None, detail)
    }
}

fn windows_hint(h: wol_winremote::Hint) -> Option<RemoteHint> {
    use wol_winremote::Hint as H;
    Some(match h {
        H::UacRemoteRestriction => RemoteHint::UacRemoteRestriction,
        H::SmbFirewall => RemoteHint::SmbFirewall,
        H::WmiFirewall => RemoteHint::WmiFirewall,
        H::RemoteShutdownFirewall => RemoteHint::RemoteShutdownFirewall,
        H::WmiAccessDenied => RemoteHint::WmiAccessDenied,
        H::CheckCredentials => RemoteHint::CheckCredentials,
        H::StoreCredentials => RemoteHint::StoreCredentials,
        H::CloseOtherConnections => RemoteHint::CloseOtherConnections,
        H::RetryLater => RemoteHint::RetryLater,
        _ => return None,
    })
}
