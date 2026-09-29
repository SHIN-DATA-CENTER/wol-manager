//! Boot time ([`BootInfo`]) and its parser.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Result, SshError, sanitize};
use crate::scripts::marker_lines;

/// Last boot of the remote host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootInfo {
    /// Boot time reported by the host, seconds since the Unix epoch on the REMOTE clock
    /// (`/proc/stat` btime or FreeBSD `kern.boottime`). Shifts when the remote clock is stepped.
    pub btime: i64,
    /// The remote clock's "now" when the facts were read (`date +%s`), if available.
    pub remote_now: Option<i64>,
    /// Time since boot: `remote_now - btime` (independent of clock skew between the hosts).
    /// When `remote_now` is unknown: `local_now - btime` and [`BootInfo::approximate`] is set.
    pub uptime: Duration,
    /// Boot time on the LOCAL clock: `local_now - uptime` (cancels remote clock skew).
    /// Display this one.
    pub boot_time_local: SystemTime,
    /// `true` when the remote "now" was unavailable, so `uptime` / `boot_time_local` include
    /// the clock skew between the two hosts.
    pub approximate: bool,
    /// Where btime came from: `"proc_stat"`, `"kern_boottime"` or `"proc_uptime"`.
    pub source: String,
    /// Linux `/proc/sys/kernel/random/boot_id`: a new random UUID on every boot (absent on
    /// FreeBSD). The most reliable "did it reboot?" signal.
    pub boot_id: Option<String>,
    /// Kernel name (`uname -s`), e.g. `"Linux"` or `"FreeBSD"`.
    pub kernel: String,
}

/// Largest epoch second accepted from a host (2^36 s, about the year 4147). Anything larger is
/// garbage, and every accepted value is representable as a [`SystemTime`] on all platforms.
const MAX_EPOCH: i64 = 1 << 36;
/// How far a boot time may lie after the host's own "now" (rounding, a clock stepped back
/// after boot) before the pair is rejected as garbage.
const MAX_BTIME_AHEAD: i64 = 86_400;
/// btime must move forward by more than this for [`BootInfo::rebooted_since`] without boot ids.
const REBOOT_MARGIN_SECS: i64 = 30;

impl BootInfo {
    /// `true` when `self` (read later) describes a different boot than `earlier`: the boot ids
    /// differ, or (without boot ids on both sides) btime moved forward by more than 30 s.
    /// Never panics, whatever the field values.
    pub fn rebooted_since(&self, earlier: &BootInfo) -> bool {
        match (&self.boot_id, &earlier.boot_id) {
            (Some(now), Some(before)) => now != before,
            _ => self.btime > earlier.btime.saturating_add(REBOOT_MARGIN_SECS),
        }
    }

    /// [`BootInfo::btime`] as a [`SystemTime`] (remote clock). Values parsed from a host are
    /// range-checked; for a hand-built `btime` that `SystemTime` cannot represent this returns
    /// [`UNIX_EPOCH`] instead of panicking.
    pub fn btime_utc(&self) -> SystemTime {
        epoch_to_system_time(self.btime)
    }
}

fn epoch_to_system_time(secs: i64) -> SystemTime {
    let d = Duration::from_secs(secs.unsigned_abs());
    if secs >= 0 {
        UNIX_EPOCH.checked_add(d)
    } else {
        UNIX_EPOCH.checked_sub(d)
    }
    .unwrap_or(UNIX_EPOCH)
}

fn system_time_to_epoch(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

pub(crate) fn kv_map(s: &str) -> HashMap<&str, &str> {
    s.split_whitespace()
        .filter_map(|t| t.split_once('='))
        .collect()
}

/// Parse the `WOLM1 boot ...` line. Pure; `local_now` is the local clock at receipt.
pub(crate) fn parse_boot(stdout: &str, local_now: SystemTime) -> Result<BootInfo> {
    let line = marker_lines(stdout)
        .find_map(|l| l.strip_prefix("boot "))
        .ok_or_else(|| SshError::UnexpectedOutput(no_marker_hint("boot", stdout)))?;
    let kv = kv_map(line);
    let num = |k: &str| kv.get(k).and_then(|v| v.parse::<i64>().ok());
    let btime = num("btime").filter(|b| *b > 0).ok_or_else(|| {
        SshError::UnexpectedOutput(format!(
            "the host reported no boot time: {}",
            sanitize(line, 200)
        ))
    })?;
    let implausible = || {
        SshError::UnexpectedOutput(format!(
            "the host reported an implausible boot time: {}",
            sanitize(line, 200)
        ))
    };
    if btime > MAX_EPOCH {
        return Err(implausible());
    }
    let remote_now = num("now").filter(|n| *n > 0);
    if let Some(rn) = remote_now
        && (rn > MAX_EPOCH || btime > rn.saturating_add(MAX_BTIME_AHEAD))
    {
        return Err(implausible());
    }
    let text = |k: &str| {
        kv.get(k)
            .map(|v| sanitize(v, 64))
            .filter(|v| !v.is_empty() && v != "-")
    };
    let local_epoch = system_time_to_epoch(local_now);
    let (uptime_secs, approximate) = match remote_now {
        Some(rn) => ((rn - btime).max(0), false),
        None => (local_epoch.saturating_sub(btime).max(0), true),
    };
    let uptime = Duration::from_secs(uptime_secs as u64);
    Ok(BootInfo {
        btime,
        remote_now,
        uptime,
        boot_time_local: local_now.checked_sub(uptime).unwrap_or(UNIX_EPOCH),
        approximate,
        source: text("src").unwrap_or_default(),
        boot_id: text("boot_id"),
        kernel: text("os").unwrap_or_default(),
    })
}

/// Explanation for a script that printed no marker line.
pub(crate) fn no_marker_hint(what: &str, stdout: &str) -> String {
    let snippet = sanitize(stdout, 160);
    if snippet.is_empty() {
        format!(
            "no {what} facts (WOLM1 lines) in the output; the account's login shell may not run \
             `sh -s` (nologin, restricted or appliance shell)"
        )
    } else {
        format!("no {what} facts (WOLM1 lines) in the output: {snippet:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn linux_with_skew() {
        // Remote clock is 100 s behind: boot time on the local clock cancels the skew.
        let out = "junk from .bashrc\nWOLM1 boot os=Linux btime=1000 now=5000 src=proc_stat boot_id=0f1e2d3c-aaaa-bbbb-cccc-0123456789ab\n";
        let b = parse_boot(out, at(5100)).unwrap();
        assert_eq!(b.btime, 1000);
        assert_eq!(b.remote_now, Some(5000));
        assert_eq!(b.uptime, Duration::from_secs(4000));
        assert_eq!(b.boot_time_local, at(1100));
        assert!(!b.approximate);
        assert_eq!(b.source, "proc_stat");
        assert_eq!(b.kernel, "Linux");
        assert_eq!(
            b.boot_id.as_deref(),
            Some("0f1e2d3c-aaaa-bbbb-cccc-0123456789ab")
        );
        assert_eq!(b.btime_utc(), at(1000));
    }

    #[test]
    fn freebsd_and_busybox_variants() {
        let b = parse_boot(
            "WOLM1 boot os=FreeBSD btime=1727581234 now=1727600000 src=kern_boottime boot_id=-\r\n",
            at(1727600000),
        )
        .unwrap();
        assert_eq!(b.boot_id, None);
        assert_eq!(b.source, "kern_boottime");
        assert_eq!(b.uptime, Duration::from_secs(1727600000 - 1727581234));
        let b = parse_boot(
            "WOLM1 boot os=Linux btime=900 now=1000 src=proc_uptime boot_id=-",
            at(1000),
        )
        .unwrap();
        assert_eq!(b.source, "proc_uptime");
        assert_eq!(b.uptime, Duration::from_secs(100));
    }

    #[test]
    fn missing_now_is_approximate() {
        let b = parse_boot(
            "WOLM1 boot os=Linux btime=1000 now=- src=proc_stat boot_id=-",
            at(1500),
        )
        .unwrap();
        assert!(b.approximate);
        assert_eq!(b.uptime, Duration::from_secs(500));
        assert_eq!(b.boot_time_local, at(1000));
        // A remote clock ahead of ours never yields a negative uptime.
        let b = parse_boot(
            "WOLM1 boot os=Linux btime=2000 now=- src=proc_stat boot_id=-",
            at(1500),
        )
        .unwrap();
        assert_eq!(b.uptime, Duration::ZERO);
    }

    #[test]
    fn errors() {
        assert!(matches!(
            parse_boot("", at(1)),
            Err(SshError::UnexpectedOutput(_))
        ));
        assert!(matches!(
            parse_boot("This account is currently not available.\n", at(1)),
            Err(SshError::UnexpectedOutput(m)) if m.contains("not available")
        ));
        assert!(matches!(
            parse_boot("WOLM1 boot os=Linux btime=- now=5 src=- boot_id=-", at(1)),
            Err(SshError::UnexpectedOutput(_))
        ));
    }

    #[test]
    fn implausible_values_are_rejected_not_panicking_later() {
        // Values a broken or hostile host could send (review probe r1).
        for line in [
            "WOLM1 boot os=Linux btime=100000000000000 now=100000000000000 src=proc_stat boot_id=-",
            "WOLM1 boot os=Linux btime=9223372036854775807 now=- src=proc_stat boot_id=-",
            "WOLM1 boot os=Linux btime=68719476737 now=68719476737 src=proc_stat boot_id=-",
            // now beyond the sane range
            "WOLM1 boot os=Linux btime=1000 now=100000000000000 src=proc_stat boot_id=-",
            // boot time far after the host's own now
            "WOLM1 boot os=Linux btime=1000000 now=900000 src=proc_stat boot_id=-",
        ] {
            assert!(
                matches!(parse_boot(line, at(1_727_600_000)), Err(SshError::UnexpectedOutput(ref m)) if m.contains("implausible")),
                "{line}"
            );
        }
        // The largest accepted values are usable without panics.
        let b = parse_boot(
            &format!(
                "WOLM1 boot os=Linux btime={MAX_EPOCH} now={MAX_EPOCH} src=proc_stat boot_id=-"
            ),
            at(1_727_600_000),
        )
        .unwrap();
        assert_eq!(b.btime_utc(), at(MAX_EPOCH as u64));
        assert!(!b.rebooted_since(&b));
        // Slightly ahead of the remote now (rounding): accepted, uptime 0.
        let b = parse_boot(
            "WOLM1 boot os=Linux btime=1100 now=1000 src=proc_stat boot_id=-",
            at(1000),
        )
        .unwrap();
        assert_eq!(b.uptime, Duration::ZERO);
    }

    #[test]
    fn hand_built_extremes_never_panic() {
        let mut a = parse_boot(
            "WOLM1 boot os=FreeBSD btime=1000 now=2000 src=kern_boottime boot_id=-",
            at(2000),
        )
        .unwrap();
        let mut b = a.clone();
        for (x, y) in [
            (i64::MAX, i64::MAX),
            (i64::MAX - 10, i64::MAX),
            (i64::MIN, i64::MAX),
            (i64::MAX, i64::MIN),
        ] {
            a.btime = x;
            b.btime = y;
            let _ = b.rebooted_since(&a);
            let _ = a.btime_utc();
            let _ = b.btime_utc();
        }
        a.btime = i64::MAX;
        b.btime = i64::MAX;
        assert!(!b.rebooted_since(&a), "no wrap-around into a false reboot");
        a.btime = i64::MAX - 10;
        assert!(!b.rebooted_since(&a));
        // Representable or not depends on the platform (Windows: FILETIME); never a panic.
        let _ = (
            epoch_to_system_time(i64::MAX),
            epoch_to_system_time(i64::MIN),
        );
        assert_eq!(
            epoch_to_system_time(-5),
            UNIX_EPOCH - Duration::from_secs(5)
        );
        assert_eq!(system_time_to_epoch(at(7)), 7);
    }

    #[test]
    fn reboot_detection() {
        let a = parse_boot(
            "WOLM1 boot os=Linux btime=1000 now=2000 src=proc_stat boot_id=aaa",
            at(2000),
        )
        .unwrap();
        let mut b = parse_boot(
            "WOLM1 boot os=Linux btime=1005 now=3000 src=proc_stat boot_id=bbb",
            at(3000),
        )
        .unwrap();
        assert!(
            b.rebooted_since(&a),
            "boot id changed even though btime barely moved"
        );
        b.boot_id = Some("aaa".into());
        b.btime = 5000;
        assert!(
            !b.rebooted_since(&a),
            "same boot id = same boot, even if the clock was stepped"
        );
        // FreeBSD: no boot id -> btime with a 30 s margin.
        let a = parse_boot(
            "WOLM1 boot os=FreeBSD btime=1000 now=2000 src=kern_boottime boot_id=-",
            at(2000),
        )
        .unwrap();
        let mut b = a.clone();
        b.btime = 1030;
        assert!(!b.rebooted_since(&a));
        b.btime = 1031;
        assert!(b.rebooted_since(&a));
    }
}
