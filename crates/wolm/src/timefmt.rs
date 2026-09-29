//! Date / time text with seconds: ISO-8601 for `--json`, `2026-09-29 08:12:34` for people.
//! The local time zone (and its offset) comes from wol-core's `LocalTime` (this PC's zone,
//! DST included).

use std::time::{SystemTime, UNIX_EPOCH};

use wol_core::i18n::LocalTime;

/// Seconds since the Unix epoch (negative before 1970).
pub fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Milliseconds since the Unix epoch.
pub fn unix_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date of a day number (inverse of [`days_from_civil`]).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

struct Parts {
    y: i64,
    mo: u32,
    d: u32,
    h: u32,
    mi: u32,
    s: u32,
}

fn parts(secs: i64) -> Parts {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let (y, mo, d) = civil_from_days(days);
    Parts {
        y,
        mo,
        d,
        h: rem / 3600,
        mi: (rem % 3600) / 60,
        s: rem % 60,
    }
}

fn minutes(t: &LocalTime) -> i64 {
    days_from_civil(i64::from(t.year), u32::from(t.month), u32::from(t.day)) * 1440
        + i64::from(t.hour) * 60
        + i64::from(t.minute)
}

/// Offset of this PC's time zone from UTC at `t`, in minutes (Japan: +540).
pub fn offset_minutes(t: SystemTime) -> i64 {
    minutes(&LocalTime::from_system_time(t)) - minutes(&LocalTime::utc(t))
}

/// `2026-09-28T23:12:34Z`.
pub fn iso_utc(t: SystemTime) -> String {
    let p = parts(unix_secs(t));
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        p.y, p.mo, p.d, p.h, p.mi, p.s
    )
}

/// `2026-09-29T08:12:34+09:00` (this PC's time zone).
pub fn iso_local(t: SystemTime) -> String {
    let off = offset_minutes(t);
    let p = parts(unix_secs(t) + off * 60);
    let sign = if off < 0 { '-' } else { '+' };
    let a = off.abs();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
        p.y,
        p.mo,
        p.d,
        p.h,
        p.mi,
        p.s,
        a / 60,
        a % 60
    )
}

/// `2026-09-29 08:12:34` (this PC's time zone).
pub fn local_display(t: SystemTime) -> String {
    let p = parts(unix_secs(t) + offset_minutes(t) * 60);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        p.y, p.mo, p.d, p.h, p.mi, p.s
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn utc_text() {
        assert_eq!(iso_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // A leap day.
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400 + 3_723);
        assert_eq!(iso_utc(t), "2000-02-29T01:02:03Z");
        for days in [-1_000_i64, 0, 11_016, 20_725, 60_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn local_text_matches_wol_core() {
        let t = UNIX_EPOCH + Duration::from_secs(1_790_669_537);
        let l = LocalTime::from_system_time(t);
        let shown = local_display(t);
        assert_eq!(
            &shown[..16],
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}",
                l.year, l.month, l.day, l.hour, l.minute
            ),
            "{shown}"
        );
        assert!(shown.ends_with(":17"), "{shown}");
        let iso = iso_local(t);
        assert_eq!(&iso[..19], shown.replace(' ', "T"), "{iso}");
        let off = offset_minutes(t);
        assert!(off.abs() <= 14 * 60, "{off}");
        assert_eq!(unix_ms(t), 1_790_669_537_000);
    }
}
