//! Remote shell scripts and the command lines that carry them.
//!
//! Protocol (see the v0.2.0 research notes):
//! - The exec string is parsed by the account's LOGIN shell (sh, bash, zsh, fish, csh/tcsh).
//!   Read-only scripts are therefore sent as the trivial command `sh -s` with the script on
//!   stdin, wrapped in `{ ... }` so the shell parses it completely before running any of it.
//! - Privileged scripts are ONE line with no `'`, `\`, `!`, CR/LF or NUL, run as
//!   `/bin/sh -c '<script>'`, optionally prefixed by a sudo invocation. The sudo password only
//!   ever travels on stdin (`sudo -k -S -p 'WOLM_SUDO_PROMPT:'`), never on a command line.
//! - Every fact line starts with `WOLM1 `; everything else (`.bashrc` noise) is ignored.
//! - `PATH` is extended with the sbin directories and `LC_ALL=C` is forced.

use std::hash::{BuildHasher, Hasher};

use zeroize::Zeroizing;

use crate::error::{Result, SshError};
use crate::power::{Elevation, PowerAction, PowerOverrides};

/// Prefix of every line the scripts print.
pub(crate) const MARKER: &str = "WOLM1 ";
/// The sudo prompt (`-p`); no `%` escapes.
pub(crate) const SUDO_PROMPT: &str = "WOLM_SUDO_PROMPT:";
/// Exec string for read-only scripts (script on stdin).
pub(crate) const READONLY_COMMAND: &str = "sh -s";

const PRELUDE: &str = "PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin; export PATH\n\
LC_ALL=C; export LC_ALL\n";

/// Boot time: /proc/stat btime (Linux incl. BusyBox/DSM), kern.boottime (FreeBSD), or
/// now - /proc/uptime; plus remote now and the Linux boot_id.
const BOOT_BODY: &str = r#"now=$(date +%s 2>/dev/null)
case $now in ''|*[!0-9]*) now=$(awk 'BEGIN { srand(); print srand() }' 2>/dev/null) ;; esac
bt=; src=
if [ -r /proc/stat ]; then
  bt=$(awk '$1 == "btime" { print $2; exit }' /proc/stat 2>/dev/null)
  [ -n "$bt" ] && src=proc_stat
fi
if [ -z "$bt" ]; then
  bt=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ *sec *= *\([0-9][0-9]*\).*/\1/p')
  [ -n "$bt" ] && src=kern_boottime
fi
if [ -z "$bt" ] && [ -r /proc/uptime ] && [ -n "$now" ]; then
  up=$(awk '{ printf "%d", $1 }' /proc/uptime 2>/dev/null)
  if [ -n "$up" ]; then bt=$((now - up)); src=proc_uptime; fi
fi
bid=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
echo "WOLM1 boot os=$(uname -s 2>/dev/null) btime=${bt:--} now=${now:--} src=${src:--} boot_id=${bid:--}"
"#;

/// Login identity.
const ID_BODY: &str = r#"echo "WOLM1 uid $(id -u 2>/dev/null)"
echo "WOLM1 user $(id -un 2>/dev/null)"
echo "WOLM1 groups $(id -Gn 2>/dev/null)"
"#;

/// OS identification facts; the display name is chosen in Rust.
const OS_BODY: &str = r#"f=
if [ -r /etc/os-release ]; then f=/etc/os-release; elif [ -r /usr/lib/os-release ]; then f=/usr/lib/os-release; fi
if [ -n "$f" ]; then echo "WOLM1 osrel $(sed -n 's/^PRETTY_NAME=//p' "$f" 2>/dev/null | head -n 1)"; fi
if [ -r /etc.defaults/VERSION ]; then echo "WOLM1 dsm $(sed -n 's/^productversion=//p' /etc.defaults/VERSION 2>/dev/null | head -n 1)"; fi
if command -v midclt >/dev/null 2>&1 && [ -r /etc/version ]; then echo "WOLM1 truenas $(head -n 1 /etc/version 2>/dev/null)"; fi
if [ -x /usr/bin/pveversion ]; then echo "WOLM1 pve $(/usr/bin/pveversion 2>/dev/null | head -n 1)"; fi
echo "WOLM1 uname $(uname -sr 2>/dev/null)"
"#;

/// Network facts for MAC selection (Linux sysfs, or FreeBSD ifconfig).
const NET_BODY: &str = r#"uid=$(id -u 2>/dev/null)
echo "WOLM1 hdr os=$(uname -s 2>/dev/null) uid=${uid:--}"
if [ -d /sys/class/net ]; then
  awk 'NR > 1 && $2 == "00000000" && $8 == "00000000" { print "WOLM1 route", $1, $7 }' /proc/net/route 2>/dev/null
  for p in /sys/class/net/*; do
    i=${p##*/}
    [ -r "$p/address" ] || continue
    mac=$(cat "$p/address" 2>/dev/null)
    kind=virtual
    [ -e "$p/device" ] && kind=phys
    if [ -d "$p/wireless" ] || [ -e "$p/phy80211" ]; then kind=wifi; fi
    if [ -d "$p/bridge" ]; then kind=bridge
    elif [ -d "$p/bonding" ]; then kind=bond
    elif [ -r "/proc/net/vlan/$i" ]; then kind=vlan
    fi
    low=
    for l in "$p"/lower_*; do
      [ -e "$l" ] || continue
      low="$low${low:+,}${l##*/lower_}"
    done
    perm=- wol=-
    if [ "$kind" = phys ] || [ "$kind" = wifi ]; then
      perm=$(ethtool -P "$i" 2>/dev/null | awk '{ print $NF }')
      [ -n "$perm" ] || perm=$(ip -o link show dev "$i" 2>/dev/null | sed -n 's/.* permaddr \([0-9a-fA-F:]*\).*/\1/p')
      [ -n "$perm" ] || perm=-
      if [ "$uid" = 0 ]; then
        wol=$(ethtool "$i" 2>/dev/null | awk '$1 == "Supports" && $2 == "Wake-on:" { s = $3 } $1 == "Wake-on:" { w = $2 } END { if (s != "" || w != "") print s "/" w }')
        [ -n "$wol" ] || wol=-
      fi
    fi
    echo "WOLM1 if $i mac=${mac:--} type=$(cat "$p/type" 2>/dev/null) kind=$kind aat=$(cat "$p/addr_assign_type" 2>/dev/null) oper=$(cat "$p/operstate" 2>/dev/null) carrier=$(cat "$p/carrier" 2>/dev/null) lower=${low:--} perm=$perm wol=$wol"
  done
  ip -o -4 addr show 2>/dev/null | awk '{ print "WOLM1 inet", $2, $4 }'
elif command -v ifconfig >/dev/null 2>&1; then
  d=$(route -n get default 2>/dev/null | awk '$1 == "interface:" { print $2 }')
  [ -n "$d" ] && echo "WOLM1 route $d 0"
  for i in $(ifconfig -l); do
    drv=${i%%[0-9]*}; unit=${i#"$drv"}
    kind=virtual
    [ -n "$(sysctl -n "dev.$drv.$unit.%parent" 2>/dev/null)" ] && kind=phys
    ifconfig -m "$i" 2>/dev/null | awk -v i="$i" -v kind="$kind" '
      $1 == "ether" { mac = $2 }
      $1 == "hwaddr" { perm = $2 }
      $1 == "inet" { print "WOLM1 inet", i, $2 "/" $4 }
      $1 == "member:" || $1 == "laggport:" { low = low (low == "" ? "" : ",") $2 }
      /parent interface:/ { low = low (low == "" ? "" : ",") $NF }
      $1 ~ /^options(=|$)/ { on = ($0 ~ /WOL_MAGIC/) }
      $1 ~ /^capabilities(=|$)/ { cap = ($0 ~ /WOL_MAGIC/) }
      $1 == "status:" { st = $0; sub(/^[ \t]*status:[ \t]*/, "", st); gsub(/[ \t]+/, "_", st) }
      END {
        w = cap ? (on ? "g/g" : "g/d") : (on ? "g/g" : "-")
        print "WOLM1 if", i, "mac=" (mac == "" ? "-" : mac), "type=-", "kind=" kind, "aat=-", \
          "oper=" (st == "" ? "-" : st), "carrier=-", "lower=" (low == "" ? "-" : low), \
          "perm=" (perm == "" ? "-" : perm), "wol=" w
      }'
  done
fi
echo "WOLM1 end"
"#;

/// Privileged power script template (one line; see [`check_one_line`]). Placeholders:
/// `@A@` reboot|poweroff, `@W@` validated interface name or empty, `@O@` validated override
/// command or empty, `@N@` hex nonce for the transient systemd unit name.
const POWER_TEMPLATE: &str = concat!(
    "a=@A@; w=@W@; o=\"@O@\"; n=@N@; ",
    "PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin; export PATH; LC_ALL=C; export LC_ALL; ",
    "[ \"$(id -u)\" = 0 ] || { echo \"WOLM1 power err=notroot\"; exit 3; }; ",
    "os=$(uname -s); ",
    "if [ \"$a\" = reboot ]; then c=reboot; t=system.reboot; s=-r; else c=poweroff; t=system.shutdown; s=-s; fi; ",
    "if [ -n \"$w\" ] && [ \"$a\" = poweroff ]; then ",
    "if [ \"$os\" = FreeBSD ]; then ifconfig \"$w\" wol_magic >/dev/null 2>&1 && echo \"WOLM1 wol armed=$w\"; ",
    "elif command -v ethtool >/dev/null 2>&1; then ethtool -s \"$w\" wol g >/dev/null 2>&1 && echo \"WOLM1 wol armed=$w\"; fi; fi; ",
    "if [ -n \"$o\" ]; then c=$o; ",
    "elif command -v midclt >/dev/null 2>&1; then c=\"midclt call $t wol-manager || midclt call $t\"; ",
    "elif [ -x /usr/syno/sbin/synoshutdown ]; then c=\"/usr/syno/sbin/synoshutdown $s\"; ",
    "elif [ \"$os\" = FreeBSD ]; then if [ \"$a\" = reboot ]; then c=\"shutdown -r now\"; else c=\"shutdown -p now\"; fi; ",
    "elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then c=\"systemctl $a\"; fi; ",
    "if [ -d /run/systemd/system ] && command -v systemd-run >/dev/null 2>&1 && ",
    "systemd-run --quiet --unit=wolm-power-$n --on-active=2 --timer-property=AccuracySec=100ms /bin/sh -c \"$c\" >/dev/null 2>&1; ",
    "then echo \"WOLM1 power ok=systemd-run unit=wolm-power-$n cmd=$c\"; exit 0; fi; ",
    "ss=; if command -v setsid >/dev/null 2>&1; then ss=setsid; elif command -v daemon >/dev/null 2>&1; then ss=\"daemon -f\"; fi; ",
    "nohup $ss /bin/sh -c \"sleep 2; $c\" </dev/null >/dev/null 2>&1 & echo \"WOLM1 power ok=nohup cmd=$c\"; exit 0"
);

fn wrap(tag: &str, bodies: &[&str]) -> String {
    let mut s = format!("{{\n# wolm:{tag} v1\n{PRELUDE}");
    for b in bodies {
        s.push_str(b);
    }
    s.push_str("}\n");
    s
}

/// Script printing the `WOLM1 boot` line.
pub(crate) fn boot_script() -> String {
    wrap("boot", &[BOOT_BODY])
}

/// Script printing the uid / user / groups lines.
pub(crate) fn id_script() -> String {
    wrap("id", &[ID_BODY])
}

/// Script for [`crate::ConnInfo`]: boot + id + OS facts.
pub(crate) fn info_script() -> String {
    wrap("info", &[BOOT_BODY, ID_BODY, OS_BODY])
}

/// Script printing network facts (`hdr`, `route`, `if`, `inet`, `end`).
pub(crate) fn net_script() -> String {
    wrap("net", &[NET_BODY])
}

/// Lines starting with the marker, without the marker (CR stripped).
pub(crate) fn marker_lines(stdout: &str) -> impl Iterator<Item = &str> {
    stdout
        .lines()
        .filter_map(|l| l.trim_end_matches('\r').strip_prefix(MARKER))
}

/// A privileged one-liner must survive every login shell inside `'...'`.
pub(crate) fn check_one_line(script: &str) -> Result<()> {
    if script.contains(['\'', '\\', '!', '\n', '\r', '\0']) {
        return Err(SshError::Internal(
            "privileged script is not login-shell safe".into(),
        ));
    }
    Ok(())
}

/// The exec string for a privileged one-liner.
pub(crate) fn privileged_command(script: &str, elevation: Elevation) -> Result<String> {
    check_one_line(script)?;
    let inner = format!("/bin/sh -c '{script}'");
    Ok(match elevation {
        Elevation::Direct => inner,
        Elevation::SudoNoPasswd => format!("env LC_ALL=C sudo -n -- {inner}"),
        Elevation::SudoPassword => format!("env LC_ALL=C sudo -k -S -p '{SUDO_PROMPT}' -- {inner}"),
    })
}

/// stdin for `sudo -S`: the password and one `\n`, in a buffer that never reallocates (so this
/// buffer leaves no un-zeroized copy behind). Sending it still copies it into non-zeroized
/// russh buffers; see the crate docs, "Secrets".
pub(crate) fn sudo_stdin(password: &str) -> Result<Zeroizing<Vec<u8>>> {
    if password.contains(['\n', '\r', '\0']) {
        return Err(SshError::InvalidInput(
            "the sudo password contains a line break or NUL".into(),
        ));
    }
    let mut v = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    v.extend_from_slice(password.as_bytes());
    v.push(b'\n');
    Ok(v)
}

/// Interface name accepted for "arm WoL before shutdown": 1..=15 bytes of `[A-Za-z0-9_.-]`,
/// not starting with `-` (option injection).
pub(crate) fn valid_ifname(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 15
        && b[0] != b'-'
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// Characters a power command override may not contain: it is embedded in `"..."` inside a
/// `'...'` one-liner parsed by any login shell.
const OVERRIDE_FORBIDDEN: &[char] = &['\'', '"', '\\', '!', '$', '`'];
/// Maximum override length in bytes.
pub(crate) const OVERRIDE_MAX: usize = 512;

/// Validate a per-host reboot/shutdown command override. Allowed: printable ASCII except
/// `' " \ ! $` and backtick; at most [`OVERRIDE_MAX`] bytes; not blank.
pub(crate) fn validate_override(cmd: &str) -> Result<()> {
    if cmd.trim().is_empty() {
        return Err(SshError::InvalidInput(
            "the power command override is empty".into(),
        ));
    }
    if cmd.len() > OVERRIDE_MAX {
        return Err(SshError::InvalidInput(format!(
            "the power command override is longer than {OVERRIDE_MAX} bytes"
        )));
    }
    if let Some(c) = cmd
        .chars()
        .find(|c| !(' '..='~').contains(c) || OVERRIDE_FORBIDDEN.contains(c))
    {
        return Err(SshError::InvalidInput(format!(
            "the power command override contains a disallowed character {c:?} \
             (allowed: printable ASCII except ' \" \\ ! $ `)"
        )));
    }
    Ok(())
}

/// Build the privileged power one-liner.
pub(crate) fn power_script(
    action: PowerAction,
    overrides: &PowerOverrides,
    nonce: &str,
) -> Result<String> {
    let (word, over) = match action {
        PowerAction::Restart => ("reboot", overrides.reboot_command.as_deref()),
        PowerAction::Shutdown => ("poweroff", overrides.shutdown_command.as_deref()),
    };
    let over = over.map(str::trim).filter(|s| !s.is_empty());
    if let Some(o) = over {
        validate_override(o)?;
    }
    let wolif = match overrides
        .arm_wol_iface
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(i) if valid_ifname(i) => i,
        Some(i) => {
            return Err(SshError::InvalidInput(format!(
                "invalid network interface name {i:?}"
            )));
        }
        None => "",
    };
    if nonce.is_empty() || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SshError::Internal("invalid nonce".into()));
    }
    let script = POWER_TEMPLATE
        .replace("@A@", word)
        .replace("@W@", wolif)
        .replace("@O@", over.unwrap_or(""))
        .replace("@N@", nonce);
    check_one_line(&script)?;
    Ok(script)
}

/// 8 hex digits, different for every call (unit-name uniqueness only; not a secret).
pub(crate) fn nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.write_u32(std::process::id());
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.write_u128(d.as_nanos());
    }
    format!("{:08x}", h.finish() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_scripts_are_braced_and_tagged() {
        for (tag, s) in [
            ("boot", boot_script()),
            ("id", id_script()),
            ("info", info_script()),
            ("net", net_script()),
        ] {
            assert!(s.starts_with(&format!("{{\n# wolm:{tag} v1\nPATH=")), "{s}");
            assert!(s.ends_with("\n}\n"));
            assert!(s.contains("LC_ALL=C; export LC_ALL"));
            // Each line printed for Rust starts with the marker.
            for l in s.lines().filter(|l| l.contains("echo \"WOLM1")) {
                assert!(l.contains("\"WOLM1 "), "{l}");
            }
        }
        assert!(info_script().contains("WOLM1 boot") && info_script().contains("WOLM1 osrel"));
        // FreeBSD IFCAP_NV output ("options NAME,...") must be recognized too.
        assert!(
            net_script().contains("/^options(=|$)/")
                && net_script().contains("/^capabilities(=|$)/")
        );
    }

    #[test]
    fn marker_filter_ignores_noise() {
        let out = "Welcome!\r\nWOLM1 uid 0\r\nxWOLM1 fake\nWOLM1 user root\n";
        assert_eq!(
            marker_lines(out).collect::<Vec<_>>(),
            ["uid 0", "user root"]
        );
    }

    #[test]
    fn power_script_is_login_shell_safe() {
        for action in [PowerAction::Restart, PowerAction::Shutdown] {
            let s = power_script(action, &PowerOverrides::default(), "0badf00d").unwrap();
            assert!(!s.contains(['\'', '\\', '!', '\n', '\r']), "{s}");
            assert!(s.starts_with(match action {
                PowerAction::Restart => "a=reboot; w=; o=\"\"; n=0badf00d;",
                PowerAction::Shutdown => "a=poweroff; w=; o=\"\"; n=0badf00d;",
            }));
            assert!(
                s.contains("--unit=wolm-power-$n")
                    && s.contains("--timer-property=AccuracySec=100ms")
            );
            assert!(s.contains("WOLM1 power ok=systemd-run") && s.contains("WOLM1 power ok=nohup"));
            assert!(
                s.contains("shutdown -p now"),
                "FreeBSD must power off, not halt"
            );
            assert!(
                !s.contains("@A@")
                    && !s.contains("@W@")
                    && !s.contains("@O@")
                    && !s.contains("@N@")
            );
        }
        let o = PowerOverrides {
            reboot_command: Some("  /usr/local/bin/my-reboot --now || reboot  ".into()),
            shutdown_command: None,
            arm_wol_iface: Some("eno1".into()),
        };
        let s = power_script(PowerAction::Restart, &o, "1").unwrap();
        assert!(
            s.starts_with("a=reboot; w=eno1; o=\"/usr/local/bin/my-reboot --now || reboot\"; n=1;"),
            "{s}"
        );
        // The shutdown override is independent from the reboot override.
        let s = power_script(PowerAction::Shutdown, &o, "1").unwrap();
        assert!(s.starts_with("a=poweroff; w=eno1; o=\"\";"), "{s}");
    }

    #[test]
    fn power_script_rejects_bad_input() {
        for bad in [
            "echo 'x'",
            "echo \"x\"",
            "a\\b",
            "reboot!",
            "echo $HOME",
            "`id`",
            "a\nb",
            "日本",
            "   ",
        ] {
            let o = PowerOverrides {
                reboot_command: Some(bad.into()),
                ..Default::default()
            };
            let r = power_script(PowerAction::Restart, &o, "1");
            // Blank overrides are ignored (treated as "not set").
            if bad.trim().is_empty() {
                assert!(r.is_ok());
            } else {
                assert!(matches!(r, Err(SshError::InvalidInput(_))), "{bad:?}");
            }
        }
        let long = "x".repeat(OVERRIDE_MAX + 1);
        assert!(validate_override(&long).is_err());
        assert!(validate_override(&"x".repeat(OVERRIDE_MAX)).is_ok());
        for bad in [
            "-a",
            "--help",
            "eno1;reboot",
            "a b",
            "eno1.20@eno1",
            "0123456789abcdef",
        ] {
            let o = PowerOverrides {
                arm_wol_iface: Some(bad.into()),
                ..Default::default()
            };
            assert!(
                matches!(
                    power_script(PowerAction::Shutdown, &o, "1"),
                    Err(SshError::InvalidInput(_))
                ),
                "{bad}"
            );
        }
        assert!(power_script(PowerAction::Shutdown, &PowerOverrides::default(), "xyz").is_err());
    }

    #[test]
    fn privileged_prefixes() {
        let s = "echo hi";
        assert_eq!(
            privileged_command(s, Elevation::Direct).unwrap(),
            "/bin/sh -c 'echo hi'"
        );
        assert_eq!(
            privileged_command(s, Elevation::SudoNoPasswd).unwrap(),
            "env LC_ALL=C sudo -n -- /bin/sh -c 'echo hi'"
        );
        assert_eq!(
            privileged_command(s, Elevation::SudoPassword).unwrap(),
            "env LC_ALL=C sudo -k -S -p 'WOLM_SUDO_PROMPT:' -- /bin/sh -c 'echo hi'"
        );
        assert!(privileged_command("echo 'x'", Elevation::Direct).is_err());
        let full = privileged_command(
            &power_script(PowerAction::Restart, &PowerOverrides::default(), "ab").unwrap(),
            Elevation::SudoPassword,
        )
        .unwrap();
        assert_eq!(
            full.matches('\'').count(),
            4,
            "only the prompt and the script are quoted"
        );
    }

    #[test]
    fn sudo_stdin_is_exact_and_rejects_line_breaks() {
        let v = sudo_stdin("p@ss w0rd").unwrap();
        assert_eq!(&v[..], b"p@ss w0rd\n");
        assert_eq!(v.capacity(), v.len(), "no reallocation, no stray copy");
        assert!(sudo_stdin("a\nb").is_err());
        assert!(sudo_stdin("a\rb").is_err());
        assert!(sudo_stdin("a\0b").is_err());
    }

    #[test]
    fn nonces_differ_and_are_hex() {
        let (a, b) = (nonce(), nonce());
        assert_ne!(a, b);
        assert_eq!(a.len(), 8);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
