//! Restart / shutdown: types, the sudo decision flow and the classification of the
//! privileged script's result.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::{Result, SshError, TimeoutStage, sanitize};
use crate::scripts::{self, SUDO_PROMPT, marker_lines};
use crate::session::{ExecEnd, ExecOutput, Session};
use crate::target::SudoMode;

/// What to do with the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerAction {
    /// Reboot (`systemctl reboot`, `shutdown -r now`, `midclt call system.reboot`, ...).
    Restart,
    /// Power off (`systemctl poweroff`, FreeBSD `shutdown -p now`, `midclt call system.shutdown`,
    /// ...).
    Shutdown,
}

impl fmt::Display for PowerAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PowerAction::Restart => "restart",
            PowerAction::Shutdown => "shutdown",
        })
    }
}

/// Per-host overrides (WoL Manager config `reboot_command` / `shutdown_command`).
///
/// Overrides replace the platform command that the script would pick, and still run
/// detached 2 s later as root. Allowed characters: printable ASCII except
/// `' " \ ! $` and backtick, at most 512 bytes; blank = not set. Compound commands
/// (`a || b`, `a; b`) are allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PowerOverrides {
    /// Replaces the reboot command.
    pub reboot_command: Option<String>,
    /// Replaces the power-off command.
    pub shutdown_command: Option<String>,
    /// Opt-in: on [`PowerAction::Shutdown`], run `ethtool -s <iface> wol g` (Linux) or
    /// `ifconfig <iface> wol_magic` (FreeBSD) right before powering off, so an app-initiated
    /// shutdown stays wakeable even without a persistent WoL setting. 1..=15 characters of
    /// `[A-Za-z0-9_.-]`, not starting with `-`.
    pub arm_wol_iface: Option<String>,
}

/// How root was obtained for the privileged script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Elevation {
    /// The login user is root: `/bin/sh -c '...'`.
    Direct,
    /// `sudo -n` (NOPASSWD).
    SudoNoPasswd,
    /// `sudo -k -S` with the password on stdin.
    SudoPassword,
}

/// The remote host confirmed (with the `WOLM1 power ok` marker) that the power command was
/// scheduled to run detached about 2 s later. This is NOT proof that it happened: callers
/// verify (restart: boot id / boot time changed; shutdown: host stops answering).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerScheduled {
    /// `"systemd-run"` (transient timer, survives the SSH session) or `"nohup"`.
    pub method: String,
    /// Transient systemd unit (`"wolm-power-<hex>"`), when `method` is `systemd-run`.
    /// `systemctl show -p Result wolm-power-<hex>.service` on the host tells whether it failed
    /// (e.g. blocked by a shutdown inhibitor).
    pub unit: Option<String>,
    /// The command that was scheduled, as reported by the host (e.g. `"systemctl reboot"`).
    pub command: String,
    /// Interface on which WoL was armed ([`PowerOverrides::arm_wol_iface`]), if that succeeded.
    pub wol_armed: Option<String>,
    /// How root was obtained.
    pub elevation: Elevation,
}

/// The sudo decision flow (see [`SudoMode`]); called by [`Session::power`].
pub(crate) fn run_power(
    s: &mut Session,
    action: PowerAction,
    overrides: &PowerOverrides,
) -> Result<PowerScheduled> {
    // Validate the overrides before touching the host. (A sudo password with a line break is
    // rejected by `attempt` right before it would be used; a root login never needs it.)
    let script = scripts::power_script(action, overrides, &scripts::nonce())?;
    let password = s.sudo_password().cloned();
    let uid = s.remote_uid()?;
    if uid == Some(0) {
        return attempt(s, &script, Elevation::Direct, None);
    }
    match s.sudo_mode() {
        SudoMode::Root => Err(SshError::NotRoot),
        SudoMode::NoPasswd => attempt(s, &script, Elevation::SudoNoPasswd, None),
        SudoMode::Password => match password {
            Some(pw) => attempt(s, &script, Elevation::SudoPassword, Some(&pw)),
            None => Err(SshError::SudoPasswordRequired),
        },
        SudoMode::Auto => match attempt(s, &script, Elevation::SudoNoPasswd, None) {
            Err(SshError::SudoPasswordRequired) => match password {
                // One password attempt; a wrong password is reported, never retried.
                Some(pw) => attempt(s, &script, Elevation::SudoPassword, Some(&pw)),
                None => Err(SshError::SudoPasswordRequired),
            },
            other => other,
        },
    }
}

fn attempt(
    s: &mut Session,
    script: &str,
    elevation: Elevation,
    password: Option<&Zeroizing<String>>,
) -> Result<PowerScheduled> {
    let command = scripts::privileged_command(script, elevation)?;
    let stdin = match password {
        Some(pw) => Some(scripts::sudo_stdin(pw)?),
        None => None,
    };
    log::debug!("ssh: running power script ({elevation:?})");
    let timeout = s.command_timeout();
    match s.exec_collect(&command, stdin.as_ref().map(|v| &v[..]), timeout)? {
        (out, ExecEnd::Closed) => classify_power(&out, elevation),
        (out, ExecEnd::TimedOut { exec_sent }) => {
            log::debug!("ssh: power script timed out (request sent: {exec_sent})");
            classify_power_timeout(&out, elevation, exec_sent)
        }
    }
}

/// The power command's time limit expired before CHANNEL_CLOSE (e.g. a VPN tunnel that stops
/// before sshd while the host goes down). What already arrived still counts: the marker means
/// scheduled; a sudo / root diagnostic or an exit status is that result. Otherwise, once the
/// exec request was sent the command may be scheduled: [`SshError::PowerUnconfirmed`] (verify
/// by polling; a blind retry could schedule a second reboot). Only when nothing was sent is it
/// a plain [`SshError::Timeout`]. Pure.
pub(crate) fn classify_power_timeout(
    out: &ExecOutput,
    elevation: Elevation,
    exec_sent: bool,
) -> Result<PowerScheduled> {
    match classify_power(out, elevation) {
        Err(SshError::PowerUnconfirmed) if !exec_sent => {
            Err(SshError::Timeout(TimeoutStage::Command))
        }
        other => other,
    }
}

/// Interpret the privileged script's result. Pure.
pub(crate) fn classify_power(out: &ExecOutput, elevation: Elevation) -> Result<PowerScheduled> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut wol_armed = None;
    let mut not_root = false;
    let mut ok: Option<PowerScheduled> = None;
    for line in marker_lines(&stdout) {
        if let Some(rest) = line.strip_prefix("power ") {
            if let Some(r) = rest.strip_prefix("ok=") {
                let (head, command) = match r.split_once(" cmd=") {
                    Some((h, c)) => (h, c.trim().to_string()),
                    None => (r, String::new()),
                };
                let mut words = head.split_whitespace();
                let method = words.next().unwrap_or("").to_string();
                let unit = words
                    .find_map(|w| w.strip_prefix("unit="))
                    .map(str::to_string);
                ok.get_or_insert(PowerScheduled {
                    method,
                    unit,
                    command: sanitize(&command, 200),
                    wol_armed: None,
                    elevation,
                });
            } else if rest.starts_with("err=notroot") {
                not_root = true;
            }
        } else if let Some(i) = line.strip_prefix("wol armed=") {
            wol_armed = Some(sanitize(i, 32));
        }
    }
    if let Some(mut ok) = ok {
        ok.wol_armed = wol_armed;
        return Ok(ok);
    }
    if not_root {
        return Err(SshError::NotRoot);
    }
    if elevation != Elevation::Direct
        && let Some(e) = classify_sudo_failure(&stderr, out.exit_status)
    {
        return Err(e);
    }
    if out.exit_status.is_none() && out.exit_signal.is_none() {
        return Err(SshError::PowerUnconfirmed);
    }
    Err(SshError::CommandFailed {
        exit_status: out.exit_status,
        exit_signal: out.exit_signal.clone(),
        stderr: sanitize(&stderr.replace(SUDO_PROMPT, ""), 2000),
    })
}

/// Map sudo's C-locale diagnostics (forced with `env LC_ALL=C`) to specific errors. Pure.
///
/// Knows both implementations: classic (Todd Miller) sudo and sudo-rs, the default `sudo` on
/// Ubuntu 25.10 / 26.04 LTS (messages from sudo-rs 0.2.13 `src/common/error.rs` and
/// `src/sudo/pam.rs`). The `-p` prompt marker is only a secondary signal: PAM may show its
/// own prompt instead.
pub(crate) fn classify_sudo_failure(stderr: &str, exit_status: Option<u32>) -> Option<SshError> {
    let e = stderr.to_ascii_lowercase();
    if e.contains("must have a tty") {
        return Some(SshError::SudoNeedsTty);
    }
    if e.contains("is not in the sudoers file")
        || e.contains("is not allowed to execute")
        || e.contains("is not allowed to run sudo")
        // classic "Sorry, user U may not run sudo on H.", sudo-rs "... may not run CMD on H."
        || e.lines().any(|l| l.contains("sorry, user") && l.contains("may not run"))
        // sudo-rs: no sudoers rule at all (checked before authentication)
        || e.contains("i'm afraid i can't do that")
    {
        return Some(SshError::SudoNotAllowed);
    }
    if e.contains("incorrect password attempt")
        || e.contains("no password was provided")
        || e.contains("sorry, try again")
        // sudo-rs
        || e.contains("authentication failed, try again")
        || e.contains("incorrect authentication attempt")
        || stderr.matches(SUDO_PROMPT).count() >= 2
    {
        return Some(SshError::SudoWrongPassword);
    }
    if e.contains("a password is required")
        || e.contains("a terminal is required to read the password")
        // sudo-rs `-n`: "interactive authentication is required"
        || e.contains("interactive authentication is required")
        || e.contains("interaction is required")
    {
        return Some(SshError::SudoPasswordRequired);
    }
    let sudo_not_found = e.lines().any(|l| {
        l.contains("sudo") && (l.contains("not found") || l.contains("no such file or directory"))
    });
    if sudo_not_found && matches!(exit_status, Some(127) | Some(126) | None) {
        return Some(SshError::SudoMissing);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(stdout: &str, stderr: &str, exit: Option<u32>) -> ExecOutput {
        ExecOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            exit_status: exit,
            exec_accepted: true,
            closed_early: exit.is_none(),
            ..ExecOutput::default()
        }
    }

    #[test]
    fn scheduled_via_systemd_run() {
        let o = out(
            "bashrc noise\nWOLM1 power ok=systemd-run unit=wolm-power-0badf00d cmd=systemctl reboot\n",
            "",
            Some(0),
        );
        let p = classify_power(&o, Elevation::Direct).unwrap();
        assert_eq!(p.method, "systemd-run");
        assert_eq!(p.unit.as_deref(), Some("wolm-power-0badf00d"));
        assert_eq!(p.command, "systemctl reboot");
        assert_eq!(p.elevation, Elevation::Direct);
        assert_eq!(p.wol_armed, None);
    }

    #[test]
    fn marker_wins_even_without_exit_status() {
        let o = out(
            "WOLM1 wol armed=eno1\nWOLM1 power ok=nohup cmd=midclt call system.shutdown wol-manager || midclt call system.shutdown\n",
            "",
            None,
        );
        let p = classify_power(&o, Elevation::SudoPassword).unwrap();
        assert_eq!(p.method, "nohup");
        assert_eq!(p.unit, None);
        assert_eq!(
            p.command,
            "midclt call system.shutdown wol-manager || midclt call system.shutdown"
        );
        assert_eq!(p.wol_armed.as_deref(), Some("eno1"));
    }

    #[test]
    fn missing_marker_is_never_success() {
        assert!(matches!(
            classify_power(&out("", "", None), Elevation::Direct),
            Err(SshError::PowerUnconfirmed)
        ));
        match classify_power(&out("done\n", "boom\n", Some(0)), Elevation::Direct) {
            Err(SshError::CommandFailed {
                exit_status: Some(0),
                stderr,
                ..
            }) => assert_eq!(stderr, "boom"),
            other => panic!("{other:?}"),
        }
        let mut o = out("", "", None);
        o.exit_signal = Some("KILL".into());
        assert!(matches!(
            classify_power(&o, Elevation::Direct),
            Err(SshError::CommandFailed {
                exit_signal: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn timeout_keeps_what_arrived() {
        let marker = "WOLM1 power ok=systemd-run unit=wolm-power-1 cmd=systemctl poweroff\n";
        // Marker and exit status arrived, CLOSE did not (review probe r4).
        let mut o = out(marker, "", Some(0));
        o.closed_early = false;
        let p = classify_power_timeout(&o, Elevation::Direct, true).unwrap();
        assert_eq!(p.command, "systemctl poweroff");
        // Marker without exit status.
        let p = classify_power_timeout(&out(marker, "", None), Elevation::SudoPassword, true);
        assert!(p.is_ok(), "{p:?}");
        // Sent, nothing definite came back: may be scheduled -> poll, never "network, retry".
        let e =
            classify_power_timeout(&out("noise\n", "", None), Elevation::Direct, true).unwrap_err();
        assert!(matches!(e, SshError::PowerUnconfirmed), "{e:?}");
        assert!(!e.is_network());
        // A definite diagnostic is still that diagnostic.
        let e = classify_power_timeout(
            &out("", "sudo: interactive authentication is required\n", None),
            Elevation::SudoNoPasswd,
            true,
        )
        .unwrap_err();
        assert!(matches!(e, SshError::SudoPasswordRequired), "{e:?}");
        let e = classify_power_timeout(&out("", "boom\n", Some(2)), Elevation::Direct, true)
            .unwrap_err();
        assert!(matches!(e, SshError::CommandFailed { .. }), "{e:?}");
        // Nothing was sent: a plain (network) timeout.
        let e =
            classify_power_timeout(&ExecOutput::default(), Elevation::Direct, false).unwrap_err();
        assert!(
            matches!(e, SshError::Timeout(TimeoutStage::Command)),
            "{e:?}"
        );
    }

    #[test]
    fn not_root() {
        assert!(matches!(
            classify_power(
                &out("WOLM1 power err=notroot\n", "", Some(3)),
                Elevation::SudoNoPasswd
            ),
            Err(SshError::NotRoot)
        ));
    }

    #[test]
    fn sudo_failures() {
        let p = SUDO_PROMPT;
        let cases: Vec<(String, Option<u32>, SshError)> = vec![
            (
                format!("{p}Sorry, try again.\n{p}sudo: no password was provided\nsudo: 1 incorrect password attempt\n"),
                Some(1),
                SshError::SudoWrongPassword,
            ),
            // PAM replaced our prompt: the message strings still identify the failure.
            (
                "Password: \nsudo: 1 incorrect password attempt\n".into(),
                Some(1),
                SshError::SudoWrongPassword,
            ),
            (format!("{p}{p}"), Some(1), SshError::SudoWrongPassword),
            ("sudo: a password is required\n".into(), Some(1), SshError::SudoPasswordRequired),
            (
                "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper\n".into(),
                Some(1),
                SshError::SudoPasswordRequired,
            ),
            (
                format!("{p}alice is not in the sudoers file.  This incident will be reported.\n"),
                Some(1),
                SshError::SudoNotAllowed,
            ),
            (
                format!("{p}Sorry, user alice is not allowed to execute '/bin/sh -c ...' as root on nas.\n"),
                Some(1),
                SshError::SudoNotAllowed,
            ),
            ("sudo: sorry, you must have a tty to run sudo\n".into(), Some(1), SshError::SudoNeedsTty),
            ("env: 'sudo': No such file or directory\n".into(), Some(127), SshError::SudoMissing),
            ("env: sudo: No such file or directory\n".into(), Some(127), SshError::SudoMissing),
            (
                "Sorry, user alice may not run sudo on nas.\n".into(),
                Some(1),
                SshError::SudoNotAllowed,
            ),
            // sudo-rs (Ubuntu 25.10 / 26.04 LTS), verbatim from sudo-rs 0.2.13.
            (
                "sudo: interactive authentication is required\n".into(),
                Some(1),
                SshError::SudoPasswordRequired,
            ),
            (
                format!("{p}sudo: Authentication failed, try again.\n{p}sudo: Authentication failed, try again.\n{p}sudo: maximum 3 incorrect authentication attempts\n"),
                Some(1),
                SshError::SudoWrongPassword,
            ),
            // PAM replaced the prompt; only the final message is left.
            (
                "Password: sudo: maximum 3 incorrect authentication attempts\n".into(),
                Some(1),
                SshError::SudoWrongPassword,
            ),
            (
                "Password: sudo: Authentication failed, try again.\n".into(),
                Some(1),
                SshError::SudoWrongPassword,
            ),
            (
                "sudo: I'm sorry alice. I'm afraid I can't do that\n".into(),
                Some(1),
                SshError::SudoNotAllowed,
            ),
            (
                format!("{p}sudo: Sorry, user alice may not run /bin/sh on nas.\n"),
                Some(1),
                SshError::SudoNotAllowed,
            ),
            (
                "sudo: Sorry, user alice is not allowed to execute '/bin/sh -c x' as root on nas.\n"
                    .into(),
                Some(1),
                SshError::SudoNotAllowed,
            ),
        ];
        for (stderr, exit, want) in cases {
            let got = classify_power(&out("", &stderr, exit), Elevation::SudoPassword).unwrap_err();
            assert_eq!(
                std::mem::discriminant(&got),
                std::mem::discriminant(&want),
                "{stderr:?} -> {got:?}"
            );
        }
        // The script's own stderr (sudo already succeeded) is not a sudoers refusal.
        assert!(matches!(
            classify_power(
                &out("", "units may not run while inhibited\n", Some(1)),
                Elevation::SudoNoPasswd
            ),
            Err(SshError::CommandFailed { .. })
        ));
        // Without sudo the same text is just a failed command.
        assert!(matches!(
            classify_power(
                &out("", "sudo: a password is required\n", Some(1)),
                Elevation::Direct
            ),
            Err(SshError::CommandFailed { .. })
        ));
        // The prompt is stripped from the reported stderr.
        match classify_power(
            &out("", &format!("{p}\nsomething else\n"), Some(2)),
            Elevation::SudoPassword,
        ) {
            Err(SshError::CommandFailed { stderr, .. }) => assert_eq!(stderr, "something else"),
            other => panic!("{other:?}"),
        }
    }
}
