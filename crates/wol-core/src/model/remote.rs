//! `[hosts.remote]`: remote management of one host (v0.2.0).
//!
//! ```toml
//! [hosts.remote]
//! kind = "ssh"                   # "windows" | "ssh" (a missing table = not managed)
//! user = "admin"                 # Windows: account; SSH: login user (default "root")
//! address = "100.105.128.173"    # management address (default: the host's address)
//! port = 22                      # SSH only
//! key_file = 'C:\Users\me\.ssh\id_ed25519'
//! host_key = "ssh-ed25519 AAAA..."   # pinned SSH host key (public data)
//! sudo = "auto"                  # auto | root | nopasswd | password | separate
//! reboot_command = "..."         # SSH only, optional overrides
//! shutdown_command = "..."
//! ```
//!
//! Secrets (passwords, key passphrases) are never part of the config; they live in Windows
//! Credential Manager ([`crate::secret`]). Unknown keys inside the table are preserved in
//! [`RemoteConfig::extra`].

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::addr::{self, HostAddr};
use crate::error::{Field, FieldError, FieldIssue};
use crate::normalize;

/// SSH port used when `port` is not set.
pub const DEFAULT_SSH_PORT: u16 = 22;

/// SSH login user used when `user` is not set.
pub const DEFAULT_SSH_USER: &str = "root";

/// Longest accepted `reboot_command` / `shutdown_command`, in bytes.
pub const COMMAND_MAX_BYTES: usize = 512;

/// Characters a power command override may not contain. The command is embedded in a quoted
/// one-liner that the remote login shell parses (same rule as `wol-ssh`).
const COMMAND_FORBIDDEN: &[char] = &['\'', '"', '\\', '!', '$', '`'];

/// Characters Windows does not allow in an account name (`DOMAIN\user`, `user@domain` and
/// `.\user` stay valid).
const WINDOWS_USER_FORBIDDEN: &[char] = &[
    '"', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>',
];

/// How the host is managed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteKind {
    /// Windows: SMB/RPC (restart, shutdown, boot time) and WMI (MAC).
    Windows,
    /// Linux / NAS / FreeBSD over SSH (`linux` is accepted as an alias when reading).
    #[serde(alias = "linux")]
    Ssh,
}

impl RemoteKind {
    /// All values, in display order.
    pub const ALL: &'static [RemoteKind] = &[RemoteKind::Windows, RemoteKind::Ssh];

    /// `"windows"` / `"ssh"` (config and command-line spelling).
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteKind::Windows => "windows",
            RemoteKind::Ssh => "ssh",
        }
    }
}

impl fmt::Display for RemoteKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RemoteKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match normalize::normalize_input(s)
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "windows" | "win" => Ok(RemoteKind::Windows),
            "ssh" | "linux" => Ok(RemoteKind::Ssh),
            _ => Err("expected one of: windows | ssh".to_owned()),
        }
    }
}

str_enum! {
    /// How an SSH host gets root rights for restart / shutdown (`sudo`).
    SudoMode {
        /// Root login: nothing; else `sudo -n`, and when sudo asks for a password, one attempt
        /// with the separate sudo password if one is stored, else the login password (default).
        #[default]
        Auto => "auto",
        /// The login user must be root; sudo is never used.
        Root => "root",
        /// Only `sudo -n` (NOPASSWD in sudoers).
        NoPasswd => "nopasswd",
        /// `sudo -S` with the login password.
        Password => "password",
        /// `sudo -S` with its own password (Credential Manager secret of kind `sudo`).
        Separate => "separate",
    }
}

fn is_auto(m: &SudoMode) -> bool {
    *m == SudoMode::Auto
}

/// `[hosts.remote]`. `kind` is required; every other key is optional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// Windows or SSH.
    pub kind: RemoteKind,
    /// Windows: the account (`PC\user`, `DOMAIN\user`, `user@domain`, `.\Administrator`;
    /// `None` = the current Windows sign-in, or the account stored with the password).
    /// SSH: the login user (`None` = `root`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Management address when it differs from the host's `address` (e.g. the VPN address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<HostAddr>,
    /// SSH port (`None` = 22).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SSH private key file (`None` = password authentication only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
    /// Pinned SSH host key as an OpenSSH public-key line (`"ssh-ed25519 AAAA..."`). Public
    /// data; `None` = not trusted yet (the first connection reports
    /// [`crate::Error::UnknownHostKey`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// SSH: how root rights are obtained for restart / shutdown.
    #[serde(default, skip_serializing_if = "is_auto")]
    pub sudo: SudoMode,
    /// SSH: replaces the platform reboot command (rarely needed; NAS firmwares).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reboot_command: Option<String>,
    /// SSH: replaces the platform power-off command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shutdown_command: Option<String>,
    /// Unknown keys, preserved.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl RemoteConfig {
    /// A table of `kind` with every option unset.
    pub fn new(kind: RemoteKind) -> RemoteConfig {
        RemoteConfig {
            kind,
            user: None,
            address: None,
            port: None,
            key_file: None,
            host_key: None,
            sudo: SudoMode::Auto,
            reboot_command: None,
            shutdown_command: None,
            extra: toml::Table::new(),
        }
    }

    /// The configured user, trimmed; `None` when unset or blank.
    pub fn user(&self) -> Option<&str> {
        self.user
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
    }

    /// SSH login user: the configured user or [`DEFAULT_SSH_USER`].
    pub fn ssh_user(&self) -> &str {
        self.user().unwrap_or(DEFAULT_SSH_USER)
    }

    /// SSH port: the configured port or [`DEFAULT_SSH_PORT`] (a hand-edited 0 counts as unset).
    pub fn ssh_port(&self) -> u16 {
        match self.port {
            Some(p) if p != 0 => p,
            _ => DEFAULT_SSH_PORT,
        }
    }

    /// The pinned host key, trimmed; `None` when unset or blank.
    pub fn host_key(&self) -> Option<&str> {
        self.host_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
    }

    /// Problems of this table (the same rules as the editor): user name, SSH port 0, host
    /// key, power command overrides. Empty = fine.
    pub fn check(&self) -> Vec<FieldError> {
        let mut v = Vec::new();
        if let Some(u) = &self.user
            && let Err(i) = check_remote_user(u, self.kind)
        {
            v.push(FieldError::new(Field::RemoteUser, i));
        }
        if self.port == Some(0) {
            v.push(FieldError::new(Field::SshPort, FieldIssue::InvalidPort));
        }
        if let Some(k) = &self.host_key
            && let Err(i) = check_host_key(k)
        {
            v.push(FieldError::new(Field::SshHostKey, i));
        }
        for (field, cmd) in [
            (Field::RebootCommand, &self.reboot_command),
            (Field::ShutdownCommand, &self.shutdown_command),
        ] {
            if let Some(c) = cmd
                && let Err(i) = check_power_command(c)
            {
                v.push(FieldError::new(field, i));
            }
        }
        v
    }
}

/// Checks and cleans a remote user name as typed. `Ok("")` for empty input.
///
/// * Windows: `user`, `PC\user`, `DOMAIN\user`, `.\user`, `user@domain`, also non-ASCII
///   (Japanese) names; full-width ASCII is folded; `" / [ ] : ; | = , + * ? < >`, control
///   characters and more than one `\` → [`FieldIssue::InvalidUser`].
/// * SSH: full-width input is folded; kana → [`FieldIssue::ImeKana`]; spaces, `\` and
///   control characters → [`FieldIssue::InvalidUser`].
pub fn check_remote_user(input: &str, kind: RemoteKind) -> Result<String, FieldIssue> {
    match kind {
        RemoteKind::Windows => {
            let folded = normalize::fold_width(input);
            let t = folded.trim();
            if t.is_empty() {
                return Ok(String::new());
            }
            let backslashes = t.matches('\\').count();
            let bad = t
                .chars()
                .any(|c| c.is_control() || WINDOWS_USER_FORBIDDEN.contains(&c))
                || backslashes > 1
                || t.starts_with('\\')
                || t.ends_with('\\')
                || t.starts_with('@')
                || t.ends_with('@');
            if bad {
                Err(FieldIssue::InvalidUser)
            } else {
                Ok(t.to_owned())
            }
        }
        RemoteKind::Ssh => {
            let n = normalize::normalize_input(input);
            let t = n.trim();
            if t.is_empty() {
                return Ok(String::new());
            }
            if normalize::contains_kana(t) {
                return Err(FieldIssue::ImeKana);
            }
            if t.chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
            {
                return Err(FieldIssue::InvalidUser);
            }
            Ok(t.to_owned())
        }
    }
}

/// Checks a reboot / shutdown command override: printable ASCII except `' " \ ! $` and
/// backtick, at most [`COMMAND_MAX_BYTES`] bytes (the rule `wol-ssh` enforces before it runs
/// anything). Full-width input is folded; kana → [`FieldIssue::ImeKana`]; otherwise
/// [`FieldIssue::InvalidCommand`]. `Ok("")` for empty input (= platform default).
pub fn check_power_command(input: &str) -> Result<String, FieldIssue> {
    let t = normalize::check_technical(input)?;
    if t.is_empty() {
        return Ok(t);
    }
    let bad = t.len() > COMMAND_MAX_BYTES
        || t.chars()
            .any(|c| !(' '..='~').contains(&c) || COMMAND_FORBIDDEN.contains(&c));
    if bad {
        Err(FieldIssue::InvalidCommand)
    } else {
        Ok(t)
    }
}

/// Checks a pinned SSH host key (an OpenSSH public-key line, comment optional) and returns
/// its normalized form without comment. `Ok("")` for empty input.
/// Errors: [`FieldIssue::InvalidHostKey`].
pub fn check_host_key(input: &str) -> Result<String, FieldIssue> {
    let t = input.trim();
    if t.is_empty() {
        return Ok(String::new());
    }
    wol_ssh::parse_host_key(t)
        .map(|i| i.openssh_line)
        .map_err(|_| FieldIssue::InvalidHostKey)
}

/// Cleans a key file path as typed or pasted: trims, removes surrounding quotes
/// (`"C:\Users\me\.ssh\id_ed25519"` from Explorer's "Copy as path"), and expands what a shell
/// would have expanded but PowerShell / the app do not (review R10): `%NAME%` of a defined
/// environment variable (`%USERPROFILE%\.ssh\id_ed25519`, as typed in cmd.exe) and a leading
/// `~` (`~\.ssh\id_ed25519`, the user profile). `""` = none.
pub fn clean_key_file(input: &str) -> String {
    clean_key_file_with(input, |name| std::env::var(name).ok())
}

/// [`clean_key_file`] with an explicit environment (tests).
pub(crate) fn clean_key_file_with(input: &str, env: impl Fn(&str) -> Option<String>) -> String {
    let t = input.trim();
    let t = t
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(t)
        .trim();
    let t = match t.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with(['\\', '/']) => {
            match env("USERPROFILE").filter(|p| !p.is_empty()) {
                Some(home) => format!("{home}{rest}"),
                None => t.to_owned(),
            }
        }
        _ => t.to_owned(),
    };
    expand_env_vars(&t, env)
}

/// Replaces `%NAME%` of defined variables (case as given; Windows variable names are
/// case-insensitive, and so is `std::env::var` there). Unknown names and a lone `%` stay.
fn expand_env_vars(s: &str, env: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                let valid = !name.is_empty()
                    && !name.contains(|c: char| c == '=' || c.is_control() || c == '\\');
                match valid.then(|| env(name)).flatten() {
                    Some(v) => {
                        out.push_str(&v);
                        rest = &after[end + 1..];
                    }
                    None => {
                        // Not a variable: keep the first `%`, look for another from the second.
                        out.push('%');
                        rest = after;
                    }
                }
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Checks a management address (optional): `Ok(None)` for empty input.
pub fn check_management_address(input: &str) -> Result<Option<HostAddr>, FieldIssue> {
    if normalize::normalize_input(input).trim().is_empty() {
        Ok(None)
    } else {
        HostAddr::parse(input).map(Some)
    }
}

/// Checks an SSH port (optional): `Ok(None)` for empty input.
pub fn check_ssh_port(input: &str) -> Result<Option<u16>, FieldIssue> {
    if normalize::normalize_input(input).trim().is_empty() {
        Ok(None)
    } else {
        addr::parse_port(input).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn kind_and_sudo_spellings() {
        assert_eq!("Linux".parse::<RemoteKind>(), Ok(RemoteKind::Ssh));
        assert_eq!(
            "ＷＩＮＤＯＷＳ".parse::<RemoteKind>(),
            Ok(RemoteKind::Windows)
        );
        assert!("ipmi".parse::<RemoteKind>().is_err());
        assert_eq!(RemoteKind::Ssh.to_string(), "ssh");
        assert_eq!("NOPASSWD".parse::<SudoMode>(), Ok(SudoMode::NoPasswd));
        assert_eq!("separate".parse::<SudoMode>(), Ok(SudoMode::Separate));
        assert_eq!(SudoMode::NoPasswd.as_str(), "nopasswd");
        assert_eq!(
            serde_json::to_string(&SudoMode::NoPasswd).unwrap(),
            "\"nopasswd\""
        );
        assert!("doas".parse::<SudoMode>().is_err());
    }

    #[test]
    fn user_rules() {
        use RemoteKind::*;
        for ok in [
            "admin",
            r"DESKTOP-6FDOQLK\admin",
            r".\Administrator",
            "me@example.com",
            "山田 太郎",
            "コーヒー",
        ] {
            assert_eq!(check_remote_user(ok, Windows).as_deref(), Ok(ok), "{ok}");
        }
        assert_eq!(
            check_remote_user(" ａｄｍｉｎ ", Windows).as_deref(),
            Ok("admin")
        );
        for bad in ["a/b", "a:b", "x*", r"a\b\c", r"\admin", "admin@", "a\u{7}"] {
            assert_eq!(
                check_remote_user(bad, Windows),
                Err(FieldIssue::InvalidUser),
                "{bad}"
            );
        }
        assert_eq!(check_remote_user("", Windows).as_deref(), Ok(""));
        assert_eq!(check_remote_user("pi", Ssh).as_deref(), Ok("pi"));
        assert_eq!(check_remote_user("ｒｏｏｔ", Ssh).as_deref(), Ok("root"));
        assert_eq!(check_remote_user("るーと", Ssh), Err(FieldIssue::ImeKana));
        assert_eq!(check_remote_user("a b", Ssh), Err(FieldIssue::InvalidUser));
        assert_eq!(
            check_remote_user(r"dom\user", Ssh),
            Err(FieldIssue::InvalidUser)
        );
    }

    #[test]
    fn command_rules() {
        assert_eq!(check_power_command("").as_deref(), Ok(""));
        assert_eq!(
            check_power_command(" /sbin/reboot || reboot ").as_deref(),
            Ok("/sbin/reboot || reboot")
        );
        for bad in ["echo $HOME", "a'b", "a\"b", "a\\b", "a!b", "`id`", "é"] {
            assert_eq!(
                check_power_command(bad),
                Err(FieldIssue::InvalidCommand),
                "{bad}"
            );
        }
        assert_eq!(
            check_power_command(&"x".repeat(COMMAND_MAX_BYTES)).map(|s| s.len()),
            Ok(COMMAND_MAX_BYTES)
        );
        assert_eq!(
            check_power_command(&"x".repeat(COMMAND_MAX_BYTES + 1)),
            Err(FieldIssue::InvalidCommand)
        );
        assert_eq!(check_power_command("りぶーと"), Err(FieldIssue::ImeKana));
    }

    #[test]
    fn host_key_rules() {
        assert_eq!(
            check_host_key(&format!("  {ED25519} root@pve ")).as_deref(),
            Ok(ED25519)
        );
        assert_eq!(check_host_key("").as_deref(), Ok(""));
        assert_eq!(
            check_host_key("ssh-ed25519 notbase64"),
            Err(FieldIssue::InvalidHostKey)
        );
    }

    #[test]
    fn key_file_and_small_checks() {
        assert_eq!(
            clean_key_file(r#" "C:\Users\me\.ssh\id_ed25519" "#),
            r"C:\Users\me\.ssh\id_ed25519"
        );
        // Review R10: %VAR% (as typed for cmd.exe) and a leading ~ are expanded.
        let env = |n: &str| match n {
            "USERPROFILE" => Some(r"C:\Users\me".to_owned()),
            "HOMEDRIVE" => Some("C:".to_owned()),
            _ => None,
        };
        let c = |s: &str| clean_key_file_with(s, env);
        assert_eq!(
            c(r"%USERPROFILE%\.ssh\id_ed25519"),
            r"C:\Users\me\.ssh\id_ed25519"
        );
        assert_eq!(c(r#""~\.ssh\id rsa""#), r"C:\Users\me\.ssh\id rsa");
        assert_eq!(c("~/.ssh/id"), r"C:\Users\me/.ssh/id");
        assert_eq!(c("~"), r"C:\Users\me");
        assert_eq!(c(r"~me\id"), r"~me\id", "not the profile");
        assert_eq!(c(r"%HOMEDRIVE%\keys\%NOPE%\a%"), r"C:\keys\%NOPE%\a%");
        assert_eq!(c(r"C:\100%\%%USERPROFILE%x"), r"C:\100%\%C:\Users\mex");
        assert_eq!(c(r"%USERPROFILE%"), r"C:\Users\me");
        assert_eq!(c(""), "");
        assert_eq!(
            clean_key_file_with("~\\k", |_| None),
            "~\\k",
            "no profile: unchanged"
        );
        assert_eq!(check_ssh_port(""), Ok(None));
        assert_eq!(check_ssh_port("２２２２"), Ok(Some(2222)));
        assert_eq!(check_ssh_port("0"), Err(FieldIssue::InvalidPort));
        assert_eq!(check_management_address(" "), Ok(None));
        assert!(check_management_address("100.105.1.2").unwrap().is_some());
        assert_eq!(
            check_management_address("1.2.3"),
            Err(FieldIssue::InvalidAddress)
        );
    }

    #[test]
    fn config_helpers_and_check() {
        let mut r = RemoteConfig::new(RemoteKind::Ssh);
        assert_eq!(r.ssh_user(), "root");
        assert_eq!(r.ssh_port(), 22);
        r.port = Some(0);
        assert_eq!(r.ssh_port(), 22);
        r.user = Some("  ".into());
        assert_eq!(r.user(), None);
        r.user = Some("a b".into());
        r.host_key = Some("junk".into());
        r.reboot_command = Some("echo $x".into());
        let fields: Vec<Field> = r.check().iter().map(|e| e.field).collect();
        assert_eq!(
            fields,
            vec![
                Field::RemoteUser,
                Field::SshPort,
                Field::SshHostKey,
                Field::RebootCommand
            ]
        );
        assert!(RemoteConfig::new(RemoteKind::Windows).check().is_empty());
    }
}
