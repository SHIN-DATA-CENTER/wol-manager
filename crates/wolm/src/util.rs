//! Flag value parsers. Everything goes through wol-core's normalization, so full-width
//! digits and IME dashes are accepted like in the GUI.

use std::ops::RangeInclusive;
use std::time::Duration;

use wol_core::addr::{self, Target};
use wol_core::model::ProbeMethod;
use wol_core::normalize::normalize_input;
use wol_core::{Error, Field, MacAddr, SecureOn};

fn bad(flag: &str, value: &str, expected: &str) -> Error {
    Error::InvalidSetting {
        key: flag.to_owned(),
        value: value.to_owned(),
        expected: expected.to_owned(),
    }
}

/// Unsigned integer in `range`.
pub fn parse_uint(flag: &str, value: &str, range: RangeInclusive<u64>) -> Result<u64, Error> {
    let n = normalize_input(value);
    let t = n.trim();
    let expected = format!("{}..={}", range.start(), range.end());
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(flag, value, &expected));
    }
    match t.parse::<u64>() {
        Ok(v) if range.contains(&v) => Ok(v),
        _ => Err(bad(flag, value, &expected)),
    }
}

/// Durations: `90` (seconds), `90s`, `1500ms`, `2m`, `1h`, `1.5s`, `2秒`, `3分`.
pub fn parse_duration(flag: &str, value: &str) -> Result<Duration, Error> {
    const EXPECTED: &str = "a duration such as 30s, 2m or 500ms";
    let n = normalize_input(value).trim().to_ascii_lowercase();
    let split = n
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(n.len());
    let (num, unit) = n.split_at(split);
    let num: f64 = match num.parse() {
        Ok(v) if f64::is_finite(v) && v >= 0.0 => v,
        _ => return Err(bad(flag, value, EXPECTED)),
    };
    let secs = match unit.trim() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" | "秒" => num,
        "ms" | "msec" | "millis" | "ミリ秒" => num / 1000.0,
        "m" | "min" | "mins" | "minute" | "minutes" | "分" => num * 60.0,
        "h" | "hr" | "hour" | "hours" | "時間" => num * 3600.0,
        _ => return Err(bad(flag, value, EXPECTED)),
    };
    if secs > 86_400.0 * 7.0 {
        return Err(bad(flag, value, EXPECTED));
    }
    Ok(Duration::from_secs_f64(secs))
}

/// [`parse_duration`] limited to `range` (`expected` describes it in the error).
pub fn parse_duration_in(
    flag: &str,
    value: &str,
    range: RangeInclusive<Duration>,
    expected: &str,
) -> Result<Duration, Error> {
    let d = parse_duration(flag, value)?;
    if range.contains(&d) {
        Ok(d)
    } else {
        Err(bad(flag, value, expected))
    }
}

/// `auto | icmp | tcp | none`.
pub fn parse_probe(flag: &str, value: &str) -> Result<ProbeMethod, Error> {
    value
        .parse::<ProbeMethod>()
        .map_err(|_| bad(flag, value, "auto | icmp | tcp | none"))
}

/// A port 1..=65535.
pub fn parse_port(value: &str) -> Result<u16, Error> {
    addr::parse_port(value).map_err(|i| Error::invalid(Field::Port, i, value))
}

/// A usable (unicast, non-zero) MAC address.
pub fn parse_mac(value: &str) -> Result<MacAddr, Error> {
    MacAddr::parse_usable(value).map_err(|i| Error::invalid(Field::Mac, i, value))
}

/// A SecureOn password.
pub fn parse_secureon(value: &str) -> Result<SecureOn, Error> {
    SecureOn::parse(value).map_err(|i| Error::invalid(Field::SecureOn, i, value))
}

/// `host[:port]`.
pub fn parse_target(value: &str) -> Result<Target, Error> {
    Target::parse(value).map_err(|i| Error::invalid(Field::Targets, i, value))
}

/// Repeated / comma separated ports.
pub fn parse_ports(values: &[String]) -> Result<Vec<u16>, Error> {
    let joined = values.join(",");
    addr::parse_port_list(&joined).map_err(|i| Error::invalid(Field::TcpPorts, i, joined.clone()))
}

/// An IPv4 address.
pub fn parse_ipv4(field: Field, value: &str) -> Result<std::net::Ipv4Addr, Error> {
    addr::parse_ipv4(value).map_err(|i| Error::invalid(field, i, value))
}

/// Makes this process's stdin / stdout / stderr handles non-inheritable. Call it before
/// starting a program that is not waited for (the app, Notepad). `std::process::Command`
/// lets children inherit every inheritable handle, even with `Stdio::null()`, so the child
/// would keep a caller's pipe open and the caller would wait for the child's end instead of
/// wolm's. Children that use `Stdio::inherit()` still get the console: std duplicates those
/// handles for them. Errors are ignored (nothing worse than before can happen).
pub fn keep_std_handles_from_children() {
    use windows_sys::Win32::Foundation::{
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle returns this process's handle (or null / invalid, which are
        // skipped); only its inherit flag is changed.
        unsafe {
            let h = GetStdHandle(id);
            if !h.is_null() && h != INVALID_HANDLE_VALUE {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(
            parse_duration("--t", "90").unwrap(),
            Duration::from_secs(90)
        );
        assert_eq!(parse_duration("--t", "2s").unwrap(), Duration::from_secs(2));
        assert_eq!(
            parse_duration("--t", "１５００ｍｓ").unwrap(),
            Duration::from_millis(1500)
        );
        assert_eq!(
            parse_duration("--t", "2m").unwrap(),
            Duration::from_secs(120)
        );
        assert_eq!(
            parse_duration("--t", "1.5s").unwrap(),
            Duration::from_millis(1500)
        );
        assert_eq!(
            parse_duration("--t", "3分").unwrap(),
            Duration::from_secs(180)
        );
        assert!(parse_duration("--t", "abc").is_err());
        assert!(parse_duration("--t", "-1").is_err());
        assert!(parse_duration("--t", "").is_err());
        assert!(parse_duration("--t", "5 parsecs").is_err());
        let r = Duration::from_millis(100)..=Duration::from_secs(30);
        assert!(parse_duration_in("--t", "0", r.clone(), "x").is_err());
        assert!(parse_duration_in("--t", "0.0001ms", r.clone(), "x").is_err());
        assert!(parse_duration_in("--t", "31s", r.clone(), "x").is_err());
        assert_eq!(
            parse_duration_in("--t", "100ms", r.clone(), "x").unwrap(),
            Duration::from_millis(100)
        );
        assert_eq!(
            parse_duration_in("--t", "30s", r, "x").unwrap(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn integers_and_flags() {
        assert_eq!(parse_uint("--repeat", "３", 1..=10).unwrap(), 3);
        assert!(parse_uint("--repeat", "11", 1..=10).is_err());
        assert!(parse_uint("--repeat", "-1", 1..=10).is_err());
        assert_eq!(parse_port("９").unwrap(), 9);
        assert!(parse_port("0").is_err());
        assert!(parse_mac("ＡＡ－ＢＢ－ＣＣ－ＤＤ－ＥＥ－ＦＦ").is_ok());
        assert!(parse_mac("FF:FF:FF:FF:FF:FF").is_err());
        assert_eq!(
            parse_probe("--probe", "ＩＣＭＰ").unwrap(),
            ProbeMethod::Icmp
        );
        assert!(parse_probe("--probe", "arp").is_err());
        assert_eq!(
            parse_ports(&["3389".into(), "22, 445".into()]).unwrap(),
            vec![3389, 22, 445]
        );
        assert_eq!(
            parse_target("127.0.0.1:40009").unwrap().to_string(),
            "127.0.0.1:40009"
        );
    }
}
