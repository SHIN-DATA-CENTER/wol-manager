//! Exit codes (plan §6) and the error type of the commands.

use wol_core::i18n::{self, Lang, Msg};
use wol_core::{Error, ErrorKind, HostKeyProblem};

use crate::text::Text;

/// Success / changed / present.
pub const OK: u8 = 0;
/// Negative result: no change, a host is down, not on PATH, validation warnings.
pub const NEGATIVE: u8 = 1;
/// Usage error, invalid input, duplicate, ambiguous.
pub const USAGE: u8 = 2;
/// Not found.
pub const NOT_FOUND: u8 = 3;
/// `--wait` timeout.
pub const TIMEOUT: u8 = 4;
/// Network: no destinations, every send failed.
pub const NETWORK: u8 = 5;
/// Config / IO / registry error, PATH too long.
pub const CONFIG: u8 = 6;
/// Permission, elevation required, not writable, refused on an installed copy.
pub const PERMISSION: u8 = 7;
/// Internal error (panic).
pub const INTERNAL: u8 = 10;
/// Cancelled with Ctrl+C (conventional 128 + SIGINT).
pub const CANCELLED: u8 = 130;

/// Result of a command: the exit code on success paths (0, 1, 4, 5, 130).
pub type CmdResult = Result<u8, Failure>;

/// Why a command failed. The message is produced in the output language when printed.
#[derive(Debug)]
pub enum Failure {
    /// A wol-core error (exit code from its kind).
    Core(Error),
    /// A CLI usage problem (exit 2).
    Usage(String),
    /// Something the CLI looked for is missing (exit 3).
    NotFound(String),
    /// Refused for trust reasons, e.g. a host key whose fingerprint does not match (exit 7).
    Permission(String),
    /// A bug (exit 10).
    Internal(String),
    /// Another failure, with a hint of its own (shown after it; review R1).
    WithHint(Box<Failure>, String),
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Failure::Core(e)
    }
}

/// Exit code for a wol-core error kind.
pub fn code_for_kind(kind: ErrorKind) -> u8 {
    match kind {
        ErrorKind::InvalidInput | ErrorKind::Ambiguous => USAGE,
        ErrorKind::NotFound => NOT_FOUND,
        ErrorKind::Timeout => TIMEOUT,
        ErrorKind::Network => NETWORK,
        ErrorKind::Config | ErrorKind::Io => CONFIG,
        ErrorKind::Permission | ErrorKind::Unsupported => PERMISSION,
        // v0.2.0: the remote host reported a failure (wol-core suggests exit 1).
        ErrorKind::Remote => NEGATIVE,
    }
}

fn kind_name(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::InvalidInput => "invalid_input",
        ErrorKind::NotFound => "not_found",
        ErrorKind::Ambiguous => "ambiguous",
        ErrorKind::Network => "network",
        ErrorKind::Timeout => "timeout",
        ErrorKind::Config => "config",
        ErrorKind::Io => "io",
        ErrorKind::Permission => "permission",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::Remote => "remote",
    }
}

impl Failure {
    /// Process exit code.
    pub fn exit_code(&self) -> u8 {
        match self {
            Failure::Core(e) => code_for_kind(e.kind()),
            Failure::Usage(_) => USAGE,
            Failure::NotFound(_) => NOT_FOUND,
            Failure::Permission(_) => PERMISSION,
            Failure::Internal(_) => INTERNAL,
            Failure::WithHint(f, _) => f.exit_code(),
        }
    }

    /// `kind` of the JSON error object.
    pub fn kind(&self) -> &'static str {
        match self {
            Failure::Core(e) => kind_name(e.kind()),
            Failure::Usage(_) => "usage",
            Failure::NotFound(_) => "not_found",
            Failure::Permission(_) => "permission",
            Failure::Internal(_) => "internal",
            Failure::WithHint(f, _) => f.kind(),
        }
    }

    /// One-line message.
    pub fn message(&self, lang: Lang) -> String {
        match self {
            Failure::Core(e) => i18n::describe_error(e, lang),
            Failure::Usage(m) | Failure::NotFound(m) | Failure::Permission(m) => m.clone(),
            Failure::Internal(m) => Text::Internal { message: m }.text(lang),
            Failure::WithHint(f, _) => f.message(lang),
        }
    }

    /// Human output: one line per field error, else the message.
    pub fn lines(&self, lang: Lang) -> Vec<String> {
        match self {
            Failure::Core(e @ Error::InvalidFields(_)) => e
                .field_errors()
                .into_iter()
                .map(|fe| Msg::FieldError(fe).text(lang))
                .collect(),
            Failure::WithHint(f, _) => f.lines(lang),
            _ => vec![self.message(lang)],
        }
    }

    /// The command that fixes the failure, shown after it (SSH host keys).
    pub fn hint(&self, lang: Lang) -> Option<String> {
        match self {
            Failure::WithHint(_, h) => Some(h.clone()),
            Failure::Core(Error::UnknownHostKey(p)) => Some(
                Text::TrustHint {
                    host: &shell_arg(&p.host),
                }
                .text(lang),
            ),
            Failure::Core(Error::HostKeyMismatch(p)) => Some(
                Text::ForgetHint {
                    host: &shell_arg(&p.host),
                }
                .text(lang),
            ),
            // A stored password that was not used (another account / address), or none for
            // the configured Windows account: store it (again).
            Failure::Core(Error::Remote(e)) => {
                use wol_core::remote::{RemoteFailure as F, RemoteHint as H};
                if e.failure == F::SignInNotConfirmed {
                    return Some(
                        Text::SignInConfirmHint {
                            host: &shell_arg(&e.host),
                        }
                        .text(lang),
                    );
                }
                let kind = match (&e.failure, e.hint) {
                    (F::SecretMismatch { secret, .. }, _) => Some(*secret),
                    (F::PasswordRequired { .. }, _) | (_, Some(H::StoredSecretNotUsed)) => {
                        Some(wol_core::secret::SecretKind::Login)
                    }
                    _ => None,
                }?;
                Some(
                    Text::CredSetHint {
                        host: &shell_arg(&e.host),
                        kind,
                    }
                    .text(lang),
                )
            }
            _ => None,
        }
    }

    /// Host key details of an SSH host-key failure (public data; for `--json`).
    pub fn host_key(&self) -> Option<&HostKeyProblem> {
        match self {
            Failure::Core(e) => e.host_key_problem(),
            Failure::WithHint(f, _) => f.host_key(),
            _ => None,
        }
    }

    /// `true` for a remote failure of this kind.
    pub fn is_remote(&self, failure: &wol_core::remote::RemoteFailure) -> bool {
        match self {
            Failure::WithHint(f, _) => f.is_remote(failure),
            _ => matches!(self, Failure::Core(Error::Remote(e)) if e.failure == *failure),
        }
    }
}

/// A host name as a command-line argument: in double quotes unless it is a plain word.
pub fn shell_arg(name: &str) -> String {
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if plain {
        name.to_owned()
    } else {
        format!("\"{}\"", name.replace('"', ""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wol_core::{Field, FieldIssue};

    #[test]
    fn kinds_map_to_the_documented_codes() {
        assert_eq!(code_for_kind(ErrorKind::InvalidInput), 2);
        assert_eq!(code_for_kind(ErrorKind::Ambiguous), 2);
        assert_eq!(code_for_kind(ErrorKind::NotFound), 3);
        assert_eq!(code_for_kind(ErrorKind::Timeout), 4);
        assert_eq!(code_for_kind(ErrorKind::Network), 5);
        assert_eq!(code_for_kind(ErrorKind::Config), 6);
        assert_eq!(code_for_kind(ErrorKind::Io), 6);
        assert_eq!(code_for_kind(ErrorKind::Permission), 7);
        assert_eq!(code_for_kind(ErrorKind::Unsupported), 7);
        assert_eq!(Failure::from(Error::ElevationRequired).exit_code(), 7);
        assert_eq!(
            Failure::from(Error::PathTooLong {
                len: 40000,
                max: 32767
            })
            .exit_code(),
            6
        );
        assert_eq!(Failure::from(Error::NoDestinations).exit_code(), 5);
        assert_eq!(Failure::Internal("x".into()).exit_code(), 10);
        assert_eq!(Failure::Permission("x".into()).exit_code(), 7);
        assert_eq!(Failure::Permission("x".into()).kind(), "permission");
    }

    #[test]
    fn host_key_failures_carry_a_hint() {
        let p = HostKeyProblem {
            host: "My NAS".into(),
            address: "192.0.2.5".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:abc".into(),
            openssh_line: "ssh-ed25519 AAAA".into(),
            expected_fingerprint: None,
            in_known_hosts: false,
        };
        let f = Failure::from(Error::UnknownHostKey(Box::new(p.clone())));
        assert_eq!(f.exit_code(), 7);
        let hint = f.hint(Lang::En).unwrap();
        assert!(hint.contains("wolm ssh trust \"My NAS\""), "{hint}");
        assert!(f.message(Lang::En).contains("SHA256:abc"));
        assert_eq!(f.host_key().unwrap().fingerprint, "SHA256:abc");
        let f = Failure::from(Error::HostKeyMismatch(Box::new(p)));
        assert!(f.hint(Lang::Ja).unwrap().contains("wolm ssh forget"));
        assert_eq!(shell_arg("nas-1.lan"), "nas-1.lan");
        assert_eq!(shell_arg("書斎"), "書斎");
        assert_eq!(shell_arg("a b"), "\"a b\"");
    }

    #[test]
    fn field_errors_are_one_line_each() {
        let f = Failure::from(Error::InvalidFields(vec![
            wol_core::FieldError::new(Field::Name, FieldIssue::DuplicateName),
            wol_core::FieldError::new(Field::Mac, FieldIssue::Required),
        ]));
        assert_eq!(f.lines(Lang::En).len(), 2);
        assert_eq!(f.kind(), "invalid_input");
        assert_eq!(f.exit_code(), 2);
    }
}
