//! [`ConnInfo`]: what "接続テスト" (test connection) shows.

use std::time::SystemTime;

use crate::boot::{BootInfo, no_marker_hint, parse_boot};
use crate::error::{Result, SshError, sanitize};
use crate::scripts::marker_lines;

/// Result of [`test_connection`](crate::test_connection): who we are on which system, and its
/// boot time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnInfo {
    /// Human-readable OS, e.g. `"Debian GNU/Linux 12 (bookworm)"`, `"Proxmox VE 8.2.4"`,
    /// `"Synology DSM 7.2.1"`, `"TrueNAS 24.10.2"`, `"FreeBSD 14.1-RELEASE"`.
    pub os: String,
    /// Kernel name and release (`uname -sr`), e.g. `"Linux 6.8.12-1-pve"`.
    pub kernel: String,
    /// Login user name as seen by the host (`id -un`).
    pub user: String,
    /// Login user id (`id -u`).
    pub uid: Option<u32>,
    /// The login user is root (uid 0): restart / shutdown need no sudo.
    pub is_root: bool,
    /// Group names of the login user (`id -Gn`).
    pub groups: Vec<String>,
    /// Boot time.
    pub boot: BootInfo,
}

/// Groups that usually grant sudo / administrator rights.
const ADMIN_GROUPS: &[&str] = &[
    "sudo",
    "wheel",
    "admin",
    "administrators",
    "builtin_administrators",
];

impl ConnInfo {
    /// Root, or member of a group that usually grants sudo (`sudo`, `wheel`, `admin`,
    /// `administrators`, `builtin_administrators`). A hint only: whether sudo actually works
    /// is known after the first privileged command.
    pub fn likely_admin(&self) -> bool {
        self.is_root
            || self
                .groups
                .iter()
                .any(|g| ADMIN_GROUPS.contains(&g.as_str()))
    }
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    for q in ['"', '\''] {
        if let Some(inner) = s.strip_prefix(q).and_then(|x| x.strip_suffix(q)) {
            return inner.trim();
        }
    }
    s
}

/// Parse the info script output (boot + id + OS facts). Pure.
pub(crate) fn parse_conn_info(stdout: &str, local_now: SystemTime) -> Result<ConnInfo> {
    let boot = parse_boot(stdout, local_now)?;
    let mut uid = None;
    let mut user = String::new();
    let mut groups = Vec::new();
    let (mut osrel, mut dsm, mut truenas, mut pve, mut uname) = (None, None, None, None, None);
    for line in marker_lines(stdout) {
        let (key, rest) = line.split_once(' ').unwrap_or((line, ""));
        let value = sanitize(unquote(rest), 120);
        let value = (!value.is_empty()).then_some(value);
        match key {
            "uid" => uid = value.and_then(|v| v.parse::<u32>().ok()),
            "user" => user = value.unwrap_or_default(),
            "groups" => groups = rest.split_whitespace().map(|g| sanitize(g, 64)).collect(),
            "osrel" => osrel = value,
            "dsm" => dsm = value,
            "truenas" => truenas = value,
            "pve" => pve = value,
            "uname" => uname = value,
            _ => {}
        }
    }
    if uid.is_none() && user.is_empty() {
        return Err(SshError::UnexpectedOutput(no_marker_hint(
            "identity", stdout,
        )));
    }
    let kernel = uname.clone().unwrap_or_else(|| boot.kernel.clone());
    let os = if let Some(t) = truenas {
        if t.starts_with("TrueNAS") {
            t.split_whitespace().next().unwrap_or("TrueNAS").to_string()
        } else {
            format!("TrueNAS {t}")
        }
    } else if let Some(v) = dsm {
        format!("Synology DSM {v}")
    } else if let Some(p) = pve.as_deref().and_then(|p| p.strip_prefix("pve-manager/")) {
        format!("Proxmox VE {}", p.split('/').next().unwrap_or(p))
    } else if let Some(o) = osrel {
        o
    } else {
        kernel.clone()
    };
    Ok(ConnInfo {
        os,
        kernel,
        user,
        is_root: uid == Some(0),
        uid,
        groups,
        boot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    const BOOT: &str = "WOLM1 boot os=Linux btime=1727600000 now=1727610000 src=proc_stat boot_id=11111111-2222-3333-4444-555555555555\n";

    fn parse(extra: &str) -> ConnInfo {
        parse_conn_info(
            &format!("{BOOT}{extra}"),
            UNIX_EPOCH + Duration::from_secs(1727610000),
        )
        .unwrap()
    }

    #[test]
    fn debian_non_root() {
        let c = parse(
            "WOLM1 uid 1000\nWOLM1 user alice\nWOLM1 groups alice cdrom sudo users\n\
             WOLM1 osrel \"Debian GNU/Linux 12 (bookworm)\"\nWOLM1 uname Linux 6.1.0-25-amd64\n",
        );
        assert_eq!(c.os, "Debian GNU/Linux 12 (bookworm)");
        assert_eq!(c.kernel, "Linux 6.1.0-25-amd64");
        assert_eq!(c.user, "alice");
        assert_eq!(c.uid, Some(1000));
        assert!(!c.is_root);
        assert!(c.likely_admin());
        assert_eq!(c.boot.uptime, Duration::from_secs(10000));
    }

    #[test]
    fn proxmox_root() {
        let c = parse(
            "WOLM1 uid 0\nWOLM1 user root\nWOLM1 groups root\n\
             WOLM1 osrel \"Debian GNU/Linux 12 (bookworm)\"\n\
             WOLM1 pve pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.12-1-pve)\n\
             WOLM1 uname Linux 6.8.12-1-pve\n",
        );
        assert_eq!(c.os, "Proxmox VE 8.2.4");
        assert!(c.is_root && c.likely_admin());
    }

    #[test]
    fn synology_dsm() {
        let c = parse(
            "WOLM1 uid 1026\nWOLM1 user admin2\nWOLM1 groups users administrators\n\
             WOLM1 dsm \"7.2.1\"\nWOLM1 uname Linux 4.4.302+\n",
        );
        assert_eq!(c.os, "Synology DSM 7.2.1");
        assert!(!c.is_root && c.likely_admin());
    }

    #[test]
    fn truenas_scale_and_core() {
        let c = parse(
            "WOLM1 uid 950\nWOLM1 user truenas_admin\nWOLM1 groups truenas_admin builtin_administrators\n\
             WOLM1 osrel \"Debian GNU/Linux 12 (bookworm)\"\nWOLM1 truenas 24.10.2\nWOLM1 uname Linux 6.6.44-production+truenas\n",
        );
        assert_eq!(c.os, "TrueNAS 24.10.2");
        assert!(c.likely_admin());
        let c = parse(
            "WOLM1 uid 0\nWOLM1 user root\nWOLM1 groups wheel operator\n\
             WOLM1 osrel FreeBSD\nWOLM1 truenas TrueNAS-13.0-U6.1 (1d7f5e9d0b)\nWOLM1 uname FreeBSD 13.1-RELEASE-p9\n",
        );
        assert_eq!(c.os, "TrueNAS-13.0-U6.1");
        assert_eq!(c.kernel, "FreeBSD 13.1-RELEASE-p9");
    }

    #[test]
    fn fallbacks() {
        let c = parse(
            "WOLM1 uid 0\nWOLM1 user root\nWOLM1 groups \nWOLM1 pve \nWOLM1 uname FreeBSD 14.1-RELEASE\n",
        );
        assert_eq!(c.os, "FreeBSD 14.1-RELEASE");
        assert!(c.groups.is_empty());
        let c = parse("WOLM1 uid 5\nWOLM1 user x\n");
        assert_eq!(c.os, "Linux", "kernel name from the boot line");
        assert!(!c.likely_admin());
    }

    #[test]
    fn errors() {
        let now = UNIX_EPOCH + Duration::from_secs(10);
        assert!(matches!(
            parse_conn_info("nothing", now),
            Err(SshError::UnexpectedOutput(_))
        ));
        assert!(matches!(
            parse_conn_info(BOOT, now),
            Err(SshError::UnexpectedOutput(_))
        ));
    }
}
