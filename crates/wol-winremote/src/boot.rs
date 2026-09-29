//! Remote boot time over SMB (`NetRemoteTOD`, with the 49.7-day wrap resolved by remote
//! workstation statistics).
//!
//! # Blocking
//! [`boot_time`] makes two blocking NetAPI calls over SMB (`\PIPE\srvsvc`, `\PIPE\wkssvc`). With a
//! reachable host these return in well under a second; against an unreachable host the redirector
//! can block for **tens of seconds**, so callers should pre-probe TCP 445 and run this on a worker
//! thread.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use crate::error::{Error, Op, Result};

/// The last boot of a remote Windows host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootInfo {
    /// Kernel boot time, UTC, **on this PC's clock**: `local_now - uptime`, so a skewed remote clock
    /// does not shift it (same convention as the SSH backend). This is when the OS kernel started;
    /// Fast Startup (hybrid boot) does not reset it, but a full restart or a remote shutdown through
    /// this crate's [`crate::power()`] does.
    pub boot_time_utc: SystemTime,
    /// Time since boot at the moment the facts were read, measured entirely on the remote host
    /// (`tod_msecs` plus the resolved number of 49.7-day wraps).
    pub uptime: Duration,
    /// Where the value came from, e.g. `"NetRemoteTOD"` or `"NetRemoteTOD+NetStatisticsGet"`.
    pub source: String,
    /// `true` when the 49.7-day `tod_msecs` wrap could **not** be resolved with confidence
    /// (workstation statistics denied / unusable, or the statistics started long after boot), so
    /// `boot_time_utc` may be off by a whole multiple of ~49.7 days.
    pub approximate: bool,
    /// A per-boot identifier, when one is available. Always `None` on Windows (kept for parity with
    /// the SSH backend, which reads `/proc/sys/kernel/random/boot_id`).
    pub boot_id: Option<String>,
}

impl BootInfo {
    /// `true` when `self` (read later) describes a different boot than `earlier`: the resolved boot
    /// time moved forward by more than 30 seconds.
    pub fn rebooted_since(&self, earlier: &BootInfo) -> bool {
        match self.boot_time_utc.duration_since(earlier.boot_time_utc) {
            Ok(d) => d > Duration::from_secs(30),
            Err(_) => false,
        }
    }
}

/// A full `tod_msecs` wrap: `2^32` milliseconds (~49.7 days).
const WRAP_MS: i64 = 1 << 32;
/// The workstation statistics start this long after the kernel boot at most, for the wrap count to
/// count as *resolved* (observed: ~7 s; slow disks: minutes).
const RESOLVED_WINDOW_MS: i64 = 600_000;
/// Measurement slack: the boot estimate may land slightly after the statistics start.
const ORDER_TOLERANCE_MS: i64 = 60_000;
/// Wrap counts implying more than ~20 years of uptime are treated as garbage.
const MAX_WRAPS: i64 = 150;

/// Normalizes a `STAT_WORKSTATION_0.StatisticsStartTime` to Unix **milliseconds**.
///
/// MS-WKST documents this field as seconds since 1970, but Windows 11 actually returns a `FILETIME`
/// (100-ns ticks since 1601). Values above ~10^14 are treated as `FILETIME`; smaller positive values
/// are taken as Unix seconds. Zero / negative (unset) gives `None`.
pub(crate) fn normalize_stat_start_ms(raw: i64) -> Option<i64> {
    const FILETIME_THRESHOLD: i64 = 100_000_000_000_000;
    const FILETIME_UNIX_EPOCH_MS: i64 = 11_644_473_600_000;
    if raw > FILETIME_THRESHOLD {
        Some(raw / 10_000 - FILETIME_UNIX_EPOCH_MS)
    } else if raw > 0 {
        raw.checked_mul(1000)
    } else {
        None
    }
}

/// Resolves the `tod_msecs` 49.7-day wrap: returns `(wraps, approximate)` such that the uptime is
/// `tod_msecs + wraps * 2^32 ms`.
///
/// The candidate boot times are `tod_boot - k * 2^32 ms` for `k >= 0`, where
/// `tod_boot = remote_now - tod_msecs`. The workstation statistics start (`ws_start`) cannot be
/// earlier than the real boot, so the smallest `k` whose boot is not after `ws_start` (with a small
/// tolerance) is chosen. This is exact whenever the statistics started less than 49.7 days after
/// boot, and `approximate` is `false` only when they started within [`RESOLVED_WINDOW_MS`] of the
/// chosen boot (the normal case: the Workstation service starts seconds after the kernel). Without
/// statistics, `k = 0` and `approximate = true`.
pub(crate) fn resolve_wraps(
    remote_now_ms: i64,
    tod_msecs: u32,
    ws_start_ms: Option<i64>,
) -> (u64, bool) {
    let tod_boot = remote_now_ms - i64::from(tod_msecs);
    let Some(ws) = ws_start_ms else {
        return (0, true);
    };
    let excess = tod_boot - ws - ORDER_TOLERANCE_MS;
    let k = if excess <= 0 {
        0
    } else {
        (excess + WRAP_MS - 1) / WRAP_MS
    };
    if k > MAX_WRAPS {
        return (0, true);
    }
    let gap = ws - (tod_boot - k * WRAP_MS);
    (k as u64, gap > RESOLVED_WINDOW_MS)
}

/// Builds a [`BootInfo`] from the raw remote facts and the local clock at receipt.
///
/// Pure and unit-tested: the real NetAPI calls live in [`boot_time`].
pub(crate) fn build_boot_info(
    tod_elapsedt: u32,
    tod_hunds: u32,
    tod_msecs: u32,
    ws_start_raw: Option<i64>,
    local_now: SystemTime,
) -> BootInfo {
    let remote_now_ms = i64::from(tod_elapsedt) * 1000 + i64::from(tod_hunds.min(99)) * 10;
    // A statistics start in the remote future (beyond measurement slack) is unusable.
    let ws_start = ws_start_raw
        .and_then(normalize_stat_start_ms)
        .filter(|&ws| ws <= remote_now_ms + ORDER_TOLERANCE_MS);
    let (wraps, approximate) = resolve_wraps(remote_now_ms, tod_msecs, ws_start);
    let uptime = Duration::from_millis(u64::from(tod_msecs) + wraps * (WRAP_MS as u64));
    let boot_time_utc = local_now.checked_sub(uptime).unwrap_or(UNIX_EPOCH);
    let source = if ws_start.is_some() {
        "NetRemoteTOD+NetStatisticsGet".to_owned()
    } else {
        "NetRemoteTOD".to_owned()
    };
    BootInfo {
        boot_time_utc,
        uptime,
        source,
        approximate,
        boot_id: None,
    }
}

/// Raw `NetRemoteTOD` facts: `(tod_elapsedt, tod_hunds, tod_msecs)`.
///
/// Doubles as the reachability + authentication pre-check before a shutdown / abort: any
/// authenticated user may call it, so success proves the SMB path and the credentials, and a later
/// 5 / 53 means *rights* (see [`Error::from_win32_reachable`]).
#[cfg(windows)]
pub(crate) fn remote_tod(unc: &str) -> Result<(u32, u32, u32)> {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetRemoteTOD, TIME_OF_DAY_INFO,
    };
    let srv = crate::wide::wz(unc);
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: `srv` is NUL-terminated; `buf` receives a NetApiBufferFree-able block (or null).
    let rc = unsafe { NetRemoteTOD(srv.as_ptr(), &mut buf) };
    let facts = if rc == 0 && !buf.is_null() {
        // SAFETY: on success `buf` points to a TIME_OF_DAY_INFO owned by the API.
        let t = unsafe { &*(buf as *const TIME_OF_DAY_INFO) };
        Some((t.tod_elapsedt, t.tod_hunds, t.tod_msecs))
    } else {
        None
    };
    if !buf.is_null() {
        // SAFETY: `buf` was allocated by NetRemoteTOD; freed exactly once, after the last read.
        unsafe { NetApiBufferFree(buf.cast()) };
    }
    facts.ok_or_else(|| Error::from_win32(Op::BootTime, rc, format!("NetRemoteTOD({unc})")))
}

/// `STAT_WORKSTATION_0.StatisticsStartTime` of `unc`, or `None` when denied / failed (often
/// admin-only remotely, and UAC-filtered local admins are denied).
#[cfg(windows)]
fn workstation_stats_start(unc: &str) -> Option<i64> {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, SERVICE_WORKSTATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{NetStatisticsGet, STAT_WORKSTATION_0};

    let srv = crate::wide::wz(unc);
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: netapi32 exports only the Unicode NetStatisticsGet (LMSTR = LPWSTR); the metadata
    // types its strings as `*const i8`, so the NUL-terminated UTF-16 pointers (`srv` and the
    // `SERVICE_WORKSTATION` PCWSTR constant) are passed with a cast. `buf` receives an API block.
    let rc = unsafe {
        NetStatisticsGet(
            srv.as_ptr().cast(),
            SERVICE_WORKSTATION.cast(),
            0,
            0,
            &mut buf,
        )
    };
    let start = if rc == 0 && !buf.is_null() {
        // SAFETY: on success (level 0) `buf` points to a STAT_WORKSTATION_0.
        Some(unsafe { (*(buf as *const STAT_WORKSTATION_0)).StatisticsStartTime })
    } else {
        log::debug!("NetStatisticsGet({unc}, LanmanWorkstation) failed with {rc}");
        None
    };
    if !buf.is_null() {
        // SAFETY: allocated by NetStatisticsGet; freed exactly once, after the last read.
        unsafe { NetApiBufferFree(buf.cast()) };
    }
    start
}

/// Reads the remote host's kernel boot time over SMB.
///
/// `unc` is the `\\host` string (an IP literal or a name) that an IPC$ session was, or will be,
/// established with. An empty string reads the **local** machine (used only by the read-only local
/// verification, never for a managed host).
///
/// # Blocking
/// Two NetAPI round-trips; see the module note. Worst case is a redirector timeout of tens of
/// seconds against an unreachable host.
#[cfg(windows)]
pub fn boot_time(unc: &str) -> Result<BootInfo> {
    let (elapsedt, hunds, msecs) = remote_tod(unc)?;
    // Sample the local clock right after the TOD reply (before the second round trip).
    let local_now = SystemTime::now();
    let ws_start_raw = workstation_stats_start(unc);
    Ok(build_boot_info(
        elapsedt,
        hunds,
        msecs,
        ws_start_raw,
        local_now,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: i64 = 86_400_000;
    // 2026-09-29T02:37:14.6Z as FILETIME / Unix ms (from the research's local probe).
    const WS_FILETIME: i64 = 134_351_230_346_006_620;

    fn ms_to_ft(ms: i64) -> i64 {
        (ms + 11_644_473_600_000) * 10_000
    }

    #[test]
    fn normalize_handles_filetime_seconds_and_unset() {
        let n = normalize_stat_start_ms(WS_FILETIME).unwrap();
        assert!((1_790_649_434_000..1_790_649_435_000).contains(&n), "{n}");
        assert_eq!(
            normalize_stat_start_ms(1_790_649_434),
            Some(1_790_649_434_000)
        );
        assert_eq!(normalize_stat_start_ms(0), None);
        assert_eq!(normalize_stat_start_ms(-5), None);
    }

    #[test]
    fn no_stats_is_approximate_zero_wraps() {
        assert_eq!(resolve_wraps(1_790_000_000_000, 5_000, None), (0, true));
    }

    #[test]
    fn uptime_below_one_wrap() {
        // Booted 3 h ago; stats started 7 s after boot.
        let now = 1_790_660_000_000;
        let up = 3 * 3_600_000;
        let ws = now - up + 7_000;
        assert_eq!(resolve_wraps(now, up as u32, Some(ws)), (0, false));
    }

    #[test]
    fn exact_multiples_of_the_wrap() {
        let boot = 1_700_000_000_000i64;
        let ws = boot + 7_000;
        for k in 1..=5i64 {
            let real_up = k * WRAP_MS + 12_345_678;
            let now = boot + real_up;
            let tod_msecs = (real_up % WRAP_MS) as u32;
            assert_eq!(
                resolve_wraps(now, tod_msecs, Some(ws)),
                (k as u64, false),
                "k={k}"
            );
        }
    }

    #[test]
    fn uptime_just_below_and_above_a_wrap() {
        let boot = 1_700_000_000_000i64;
        let ws = boot + 5_000;
        // 1 s before the first wrap: tod_msecs is huge, k = 0.
        let up = WRAP_MS - 1_000;
        assert_eq!(resolve_wraps(boot + up, up as u32, Some(ws)), (0, false));
        // 1 s after it: tod_msecs is tiny, k = 1.
        let up = WRAP_MS + 1_000;
        assert_eq!(
            resolve_wraps(boot + up, (up % WRAP_MS) as u32, Some(ws)),
            (1, false)
        );
    }

    #[test]
    fn stats_started_long_after_boot_is_approximate_but_not_after_ws() {
        // Regression: the Workstation service was restarted 30 days after boot (more than half a
        // wrap) and the host has been up 60 days (one wrap). The old "nearest candidate" rule chose
        // k = 0, i.e. a boot 19.7 days AFTER the statistics started, which is impossible.
        let boot = 1_700_000_000_000i64;
        let ws = boot + 30 * DAY_MS;
        let real_up = 60 * DAY_MS;
        let (k, approx) = resolve_wraps(boot + real_up, (real_up % WRAP_MS) as u32, Some(ws));
        assert_eq!(k, 1, "the boot must not be later than the statistics start");
        assert!(approx, "a 30-day gap cannot be confirmed");

        // Same restart, but uptime below one wrap: k = 0, still flagged.
        let real_up = 40 * DAY_MS;
        let (k, approx) = resolve_wraps(boot + real_up, real_up as u32, Some(ws));
        assert_eq!(k, 0);
        assert!(approx);
    }

    #[test]
    fn garbage_stats_do_not_explode() {
        // A statistics start in 1970 would imply hundreds of wraps: ignored.
        assert_eq!(
            resolve_wraps(1_790_000_000_000, 1_000, Some(1_000)),
            (0, true)
        );
        // A start in the remote future is filtered out by build_boot_info.
        let now = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let bi = build_boot_info(
            1_790_000_000,
            0,
            3_600_000,
            Some(ms_to_ft(1_800_000_000_000)),
            now,
        );
        assert!(bi.approximate);
        assert_eq!(bi.source, "NetRemoteTOD");
    }

    #[test]
    fn build_boot_info_cancels_remote_clock_skew() {
        // Remote clock 10 minutes fast; up 1 h (no wrap). Boot time is anchored on OUR clock.
        let local_now_s = 1_790_649_428 + 3600;
        let local_now = UNIX_EPOCH + Duration::from_secs(local_now_s);
        let remote_now_s = (local_now_s + 600) as u32;
        let ws_ms = (i64::from(remote_now_s) - 3600) * 1000 + 7_000;
        let bi = build_boot_info(remote_now_s, 0, 3_600_000, Some(ms_to_ft(ws_ms)), local_now);
        assert!(!bi.approximate);
        assert_eq!(bi.source, "NetRemoteTOD+NetStatisticsGet");
        assert_eq!(bi.uptime, Duration::from_secs(3600));
        assert_eq!(
            bi.boot_time_utc,
            UNIX_EPOCH + Duration::from_secs(1_790_649_428)
        );
        assert!(bi.boot_id.is_none());
    }

    #[test]
    fn build_boot_info_resolves_one_wrap_end_to_end() {
        let boot_s = 1_700_000_000i64;
        let real_up_ms = WRAP_MS + 3_600_000;
        let remote_now_ms = boot_s * 1000 + real_up_ms;
        let local_now = UNIX_EPOCH + Duration::from_millis(remote_now_ms as u64);
        let bi = build_boot_info(
            (remote_now_ms / 1000) as u32,
            ((remote_now_ms % 1000) / 10) as u32,
            (real_up_ms % WRAP_MS) as u32,
            Some(ms_to_ft(boot_s * 1000 + 6_000)),
            local_now,
        );
        assert!(!bi.approximate);
        assert_eq!(bi.uptime, Duration::from_millis(real_up_ms as u64));
        assert_eq!(
            bi.boot_time_utc,
            UNIX_EPOCH + Duration::from_secs(boot_s as u64)
        );
    }

    #[test]
    fn rebooted_since_needs_more_than_30_s() {
        let now = UNIX_EPOCH + Duration::from_secs(1_790_649_428 + 3600);
        let a = build_boot_info(1_790_649_428 + 3600, 0, 3_600_000, None, now);
        let same = build_boot_info(
            1_790_649_428 + 3610,
            0,
            3_610_000,
            None,
            now + Duration::from_secs(10),
        );
        assert!(!same.rebooted_since(&a));
        let later = build_boot_info(
            1_790_649_428 + 3700,
            0,
            60_000,
            None,
            now + Duration::from_secs(100),
        );
        assert!(later.rebooted_since(&a));
        assert!(!a.rebooted_since(&later));
    }
}
