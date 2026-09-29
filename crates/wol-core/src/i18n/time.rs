//! Local date / time and the boot-time line (`起動 9/29 08:12（稼働 3時間12分）`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::Lang;

/// A local calendar time (minute resolution) for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct LocalTime {
    /// Year (e.g. 2026).
    pub year: u16,
    /// Month 1..=12.
    pub month: u8,
    /// Day 1..=31.
    pub day: u8,
    /// Hour 0..=23.
    pub hour: u8,
    /// Minute 0..=59.
    pub minute: u8,
}

impl LocalTime {
    /// `t` in the local time zone of this PC (DST included). Falls back to UTC when the
    /// conversion fails (times before 1601 / after 30827).
    pub fn from_system_time(t: SystemTime) -> LocalTime {
        to_local(t).unwrap_or_else(|| LocalTime::utc(t))
    }

    /// Now, local.
    pub fn now() -> LocalTime {
        LocalTime::from_system_time(SystemTime::now())
    }

    /// `t` in UTC (pure; times before 1970 clamp to 1970-01-01 00:00).
    pub fn utc(t: SystemTime) -> LocalTime {
        let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let (year, month, day) = civil_from_days(days as i64);
        LocalTime {
            year: u16::try_from(year).unwrap_or(u16::MAX),
            month,
            day,
            hour: (rem / 3600) as u8,
            minute: ((rem % 3600) / 60) as u8,
        }
    }
}

/// Days since 1970-01-01 → (year, month, day) (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn to_local(t: SystemTime) -> Option<LocalTime> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

    // FILETIME: 100 ns intervals since 1601-01-01 (UTC).
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    let d = t.duration_since(UNIX_EPOCH).ok()?;
    let ticks = u64::try_from(d.as_nanos() / 100)
        .ok()?
        .checked_add(EPOCH_DIFF_100NS)?;
    let ft = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    // SAFETY: plain FFI calls with valid pointers to initialized stack values; a null time
    // zone means "the currently active time zone".
    let ok = unsafe {
        FileTimeToSystemTime(&ft, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) != 0
    };
    ok.then_some(LocalTime {
        year: local.wYear,
        month: local.wMonth as u8,
        day: local.wDay as u8,
        hour: local.wHour as u8,
        minute: local.wMinute as u8,
    })
}

/// Uptime in words: ja `3時間12分` / `2日5時間` / `12分` / `1分未満`; en `3h 12m` / `2d 5h` /
/// `12m` / `<1m`.
pub fn format_uptime(lang: Lang, uptime: Duration) -> String {
    let mins = uptime.as_secs() / 60;
    let (d, h, m) = (mins / 1440, (mins / 60) % 24, mins % 60);
    match lang {
        Lang::Ja => match (d, h, m) {
            (0, 0, 0) => "1分未満".to_owned(),
            (0, 0, m) => format!("{m}分"),
            (0, h, 0) => format!("{h}時間"),
            (0, h, m) => format!("{h}時間{m}分"),
            (d, 0, _) => format!("{d}日"),
            (d, h, _) => format!("{d}日{h}時間"),
        },
        Lang::En => match (d, h, m) {
            (0, 0, 0) => "<1m".to_owned(),
            (0, 0, m) => format!("{m}m"),
            (0, h, m) => format!("{h}h {m}m"),
            (d, h, _) => format!("{d}d {h}h"),
        },
    }
}

/// One-line boot information for the host row and the CLI:
/// ja `起動 9/29 08:12（稼働 3時間12分）`, en `Up since 9/29 08:12 (3h 12m)`.
/// The year is shown when the host has been up for a year or more. `approximate` adds
/// `、概算` / `, approx.` inside the parentheses (Windows could not resolve its 49.7-day
/// counter wrap; pass `false` when the UI shows its own marker).
pub fn format_boot_line(
    lang: Lang,
    boot_local: &LocalTime,
    uptime: Duration,
    approximate: bool,
) -> String {
    let t = boot_local;
    let date = if uptime >= Duration::from_secs(365 * 86_400) {
        format!("{}/{}/{}", t.year, t.month, t.day)
    } else {
        format!("{}/{}", t.month, t.day)
    };
    let clock = format!("{:02}:{:02}", t.hour, t.minute);
    let up = format_uptime(lang, uptime);
    match (lang, approximate) {
        (Lang::Ja, false) => format!("起動 {date} {clock}（稼働 {up}）"),
        (Lang::Ja, true) => format!("起動 {date} {clock}（稼働 {up}、概算）"),
        (Lang::En, false) => format!("Up since {date} {clock} ({up})"),
        (Lang::En, true) => format!("Up since {date} {clock} ({up}, approx.)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lt(year: u16, month: u8, day: u8, hour: u8, minute: u8) -> LocalTime {
        LocalTime {
            year,
            month,
            day,
            hour,
            minute,
        }
    }

    #[test]
    fn boot_lines() {
        let t = lt(2026, 9, 29, 8, 12);
        let up = Duration::from_secs(3 * 3600 + 12 * 60 + 40);
        assert_eq!(
            format_boot_line(Lang::Ja, &t, up, false),
            "起動 9/29 08:12（稼働 3時間12分）"
        );
        assert_eq!(
            format_boot_line(Lang::En, &t, up, false),
            "Up since 9/29 08:12 (3h 12m)"
        );
        assert_eq!(
            format_boot_line(Lang::Ja, &t, up, true),
            "起動 9/29 08:12（稼働 3時間12分、概算）"
        );
        assert_eq!(
            format_boot_line(Lang::En, &t, up, true),
            "Up since 9/29 08:12 (3h 12m, approx.)"
        );
        let long = Duration::from_secs(400 * 86_400);
        assert_eq!(
            format_boot_line(Lang::En, &lt(2025, 8, 25, 23, 5), long, false),
            "Up since 2025/8/25 23:05 (400d 0h)"
        );
    }

    #[test]
    fn uptimes() {
        let s = Duration::from_secs;
        assert_eq!(format_uptime(Lang::Ja, s(59)), "1分未満");
        assert_eq!(format_uptime(Lang::Ja, s(12 * 60)), "12分");
        assert_eq!(format_uptime(Lang::Ja, s(3 * 3600)), "3時間");
        assert_eq!(format_uptime(Lang::Ja, s(3 * 3600 + 60)), "3時間1分");
        assert_eq!(
            format_uptime(Lang::Ja, s(2 * 86_400 + 5 * 3600 + 59)),
            "2日5時間"
        );
        assert_eq!(format_uptime(Lang::Ja, s(2 * 86_400 + 1800)), "2日");
        assert_eq!(format_uptime(Lang::En, s(0)), "<1m");
        assert_eq!(format_uptime(Lang::En, s(12 * 60)), "12m");
        assert_eq!(format_uptime(Lang::En, s(3 * 3600)), "3h 0m");
        assert_eq!(format_uptime(Lang::En, s(2 * 86_400 + 5 * 3600)), "2d 5h");
    }

    #[test]
    fn utc_calendar() {
        let t = UNIX_EPOCH + Duration::from_secs(1_790_669_520); // 2026-09-29 08:12 UTC
        assert_eq!(LocalTime::utc(t), lt(2026, 9, 29, 8, 12));
        assert_eq!(LocalTime::utc(UNIX_EPOCH), lt(1970, 1, 1, 0, 0));
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29 00:00 UTC
        assert_eq!(LocalTime::utc(leap), lt(2000, 2, 29, 0, 0));
    }

    #[test]
    fn local_conversion_is_close_to_utc() {
        // Whatever the time zone of the test machine: within ±14 h of UTC, same minute.
        let t = UNIX_EPOCH + Duration::from_secs(1_790_669_520);
        let local = LocalTime::from_system_time(t);
        let utc = LocalTime::utc(t);
        assert_eq!(local.minute % 15, utc.minute % 15);
        let to_min =
            |x: LocalTime| i64::from(x.day) * 1440 + i64::from(x.hour) * 60 + i64::from(x.minute);
        let diff = (to_min(local) - to_min(utc)).abs();
        assert!(diff <= 14 * 60, "{local:?} vs {utc:?}");
        let _ = LocalTime::now();
    }
}
