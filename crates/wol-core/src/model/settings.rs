//! `[settings]` of `config.toml`, the dotted keys used by `wolm config get/set`, and the
//! shared value ranges.
//!
//! Every struct has `#[serde(default)]` and a flattened `extra` table, so keys written by a
//! newer version survive a load / save round trip.

use std::fmt;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::addr;
use crate::consts::DEFAULT_WOL_PORT;
use crate::error::{Error, Result};
use crate::i18n::LangSetting;
use crate::normalize;

/// Value ranges shared by `wolm config set`, the GUI spin boxes and [`super::Config::validate`].
///
/// Out-of-range values found in a hand-edited file are reported by `validate` but never
/// clamped and written back; consumers use the `effective_*` getters when they need a usable
/// value.
pub mod limits {
    use std::ops::RangeInclusive;

    /// `wake.repeat`: number of send rounds.
    pub const REPEAT: RangeInclusive<u8> = 1..=10;
    /// `wake.interval_ms`: pause between rounds.
    pub const INTERVAL_MS: RangeInclusive<u32> = 0..=5000;
    /// `wake.verify_timeout_secs`: how long the GUI / `--wait` waits for the host.
    pub const VERIFY_TIMEOUT_SECS: RangeInclusive<u32> = 10..=3600;
    /// `gui.poll_interval_secs` when not 0 (0 = automatic checks off).
    pub const POLL_INTERVAL_SECS: RangeInclusive<u32> = 5..=3600;
    /// `probe.timeout_ms`: per-probe timeout.
    pub const PROBE_TIMEOUT_MS: RangeInclusive<u32> = 100..=30000;
    /// Ports (`wake.port`, TCP ports).
    pub const PORT: RangeInclusive<u16> = 1..=65535;
    /// Most TCP ports in one list (`probe.tcp_ports`, a host's `tcp_ports`). Every port is a
    /// connect attempt of its own at each status check.
    pub const TCP_PORTS_MAX: usize = 16;

    /// `true` when `v` is a valid `gui.poll_interval_secs` (0 or 5..=3600).
    pub fn poll_interval_ok(v: u32) -> bool {
        v == 0 || POLL_INTERVAL_SECS.contains(&v)
    }
}

macro_rules! str_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $text:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// All values, in display order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The lower-case name used in `config.toml` and on the command line.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $name::$variant => $text, )+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = String;
            fn from_str(s: &str) -> std::result::Result<Self, String> {
                let t = normalize::normalize_input(s).trim().to_ascii_lowercase();
                match t.as_str() {
                    $( $text => Ok($name::$variant), )+
                    _ => Err(format!(
                        "expected one of: {}",
                        [$($text),+].join(" | ")
                    )),
                }
            }
        }
    };
}

str_enum! {
    /// How to check whether a host is online (`probe.method`, per-host `probe`).
    ProbeMethod {
        /// ICMP echo first, then TCP connect (default).
        #[default]
        Auto => "auto",
        /// ICMP echo only.
        Icmp => "icmp",
        /// TCP connect only.
        Tcp => "tcp",
        /// No checks ("not monitored").
        None => "none",
    }
}

str_enum! {
    /// GUI color theme (`gui.theme`).
    Theme {
        /// Follow the OS setting (default).
        #[default]
        System => "system",
        /// Always light.
        Light => "light",
        /// Always dark.
        Dark => "dark",
    }
}

str_enum! {
    /// GUI renderer (`gui.renderer`).
    Renderer {
        /// Slint's default backend selection (default).
        #[default]
        Auto => "auto",
        /// Force the software renderer (`winit-software`).
        Software => "software",
    }
}

/// `[settings]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Settings {
    /// UI language (`auto` follows the OS locale).
    pub language: LangSetting,
    /// `[settings.wake]`.
    pub wake: WakeSettings,
    /// `[settings.probe]`.
    pub probe: ProbeSettings,
    /// `[settings.gui]`.
    pub gui: GuiSettings,
    /// Unknown keys, preserved.
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// `[settings.wake]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WakeSettings {
    /// Default UDP port (hosts may override).
    pub port: u16,
    /// Send rounds, `1..=10`.
    pub repeat: u8,
    /// Pause between rounds in ms, `0..=5000`.
    pub interval_ms: u32,
    /// Also send to 255.255.255.255 from every selected interface.
    pub limited_broadcast: bool,
    /// Also use VPN / tunnel / virtual adapters.
    pub include_virtual: bool,
    /// Pinned adapters (GUID preferred; friendly name, index or IPv4 also accepted).
    /// Empty = automatic selection.
    pub interfaces: Vec<String>,
    /// Wake verification timeout (GUI "waking" state and `wolm wake --wait`), `10..=3600`.
    pub verify_timeout_secs: u32,
    /// Unknown keys, preserved.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Default for WakeSettings {
    fn default() -> Self {
        Self {
            port: DEFAULT_WOL_PORT,
            repeat: 3,
            interval_ms: 100,
            limited_broadcast: true,
            include_virtual: false,
            interfaces: Vec::new(),
            verify_timeout_secs: 120,
            extra: toml::Table::new(),
        }
    }
}

impl WakeSettings {
    /// `repeat` clamped to [`limits::REPEAT`].
    pub fn effective_repeat(&self) -> u8 {
        self.repeat
            .clamp(*limits::REPEAT.start(), *limits::REPEAT.end())
    }

    /// `interval_ms` clamped to [`limits::INTERVAL_MS`], as a `Duration`.
    pub fn effective_interval(&self) -> Duration {
        Duration::from_millis(u64::from(self.interval_ms.min(*limits::INTERVAL_MS.end())))
    }

    /// `verify_timeout_secs` clamped to [`limits::VERIFY_TIMEOUT_SECS`], as a `Duration`.
    pub fn effective_verify_timeout(&self) -> Duration {
        Duration::from_secs(u64::from(self.verify_timeout_secs.clamp(
            *limits::VERIFY_TIMEOUT_SECS.start(),
            *limits::VERIFY_TIMEOUT_SECS.end(),
        )))
    }

    /// `port`, or the default 9 when the file contains 0.
    pub fn effective_port(&self) -> u16 {
        if self.port == 0 {
            DEFAULT_WOL_PORT
        } else {
            self.port
        }
    }
}

/// `[settings.probe]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProbeSettings {
    /// Default probe method (hosts may override).
    pub method: ProbeMethod,
    /// Per-probe timeout in ms.
    pub timeout_ms: u32,
    /// TCP ports tried by the TCP probe (in parallel).
    pub tcp_ports: Vec<u16>,
    /// Unknown keys, preserved.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Default for ProbeSettings {
    fn default() -> Self {
        Self {
            method: ProbeMethod::Auto,
            timeout_ms: 1000,
            tcp_ports: vec![3389, 445, 22],
            extra: toml::Table::new(),
        }
    }
}

impl ProbeSettings {
    /// `timeout_ms` clamped to [`limits::PROBE_TIMEOUT_MS`], as a `Duration`.
    pub fn effective_timeout(&self) -> Duration {
        Duration::from_millis(u64::from(self.timeout_ms.clamp(
            *limits::PROBE_TIMEOUT_MS.start(),
            *limits::PROBE_TIMEOUT_MS.end(),
        )))
    }
}

/// `[settings.gui]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuiSettings {
    /// Color theme.
    pub theme: Theme,
    /// Show the notification-area icon.
    pub show_tray: bool,
    /// The close button hides the window to the tray.
    pub close_to_tray: bool,
    /// Minimizing hides the window to the tray.
    pub minimize_to_tray: bool,
    /// Start hidden in the tray.
    pub start_in_tray: bool,
    /// Automatic status checks every N seconds; 0 = off; otherwise `5..=3600`.
    pub poll_interval_secs: u32,
    /// Renderer choice (applied at next start).
    pub renderer: Renderer,
    /// Unknown keys, preserved.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            show_tray: true,
            close_to_tray: false,
            minimize_to_tray: false,
            start_in_tray: false,
            poll_interval_secs: 30,
            renderer: Renderer::Auto,
            extra: toml::Table::new(),
        }
    }
}

impl GuiSettings {
    /// Polling interval, `None` when off. Values below 5 s are raised to 5 s.
    pub fn effective_poll_interval(&self) -> Option<Duration> {
        match self.poll_interval_secs {
            0 => None,
            v => Some(Duration::from_secs(u64::from(v.clamp(
                *limits::POLL_INTERVAL_SECS.start(),
                *limits::POLL_INTERVAL_SECS.end(),
            )))),
        }
    }
}

/// Type of a setting value (for help output and GUI binding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    /// `true` / `false`.
    Bool,
    /// Unsigned integer.
    Integer,
    /// One of a fixed set of words.
    Choice,
    /// Comma separated list.
    List,
}

/// Description of one dotted setting key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KeyInfo {
    /// Dotted key, e.g. `wake.repeat`.
    pub key: &'static str,
    /// Value type.
    pub value_type: ValueType,
    /// Accepted values in English (`1..=10`, `auto | ja | en`, ...).
    pub expected: &'static str,
}

const fn ki(key: &'static str, value_type: ValueType, expected: &'static str) -> KeyInfo {
    KeyInfo {
        key,
        value_type,
        expected,
    }
}

/// Every settable key with its type and accepted values, in file order.
pub const KEY_INFO: &[KeyInfo] = &[
    ki("language", ValueType::Choice, "auto | ja | en"),
    ki("wake.port", ValueType::Integer, "1..=65535"),
    ki("wake.repeat", ValueType::Integer, "1..=10"),
    ki("wake.interval_ms", ValueType::Integer, "0..=5000"),
    ki("wake.limited_broadcast", ValueType::Bool, "true | false"),
    ki("wake.include_virtual", ValueType::Bool, "true | false"),
    ki(
        "wake.interfaces",
        ValueType::List,
        "comma separated adapters: GUID, name or index (empty = automatic)",
    ),
    ki("wake.verify_timeout_secs", ValueType::Integer, "10..=3600"),
    ki(
        "probe.method",
        ValueType::Choice,
        "auto | icmp | tcp | none",
    ),
    ki("probe.timeout_ms", ValueType::Integer, "100..=30000"),
    ki(
        "probe.tcp_ports",
        ValueType::List,
        "up to 16 comma separated ports 1..=65535",
    ),
    ki("gui.theme", ValueType::Choice, "system | light | dark"),
    ki("gui.show_tray", ValueType::Bool, "true | false"),
    ki("gui.close_to_tray", ValueType::Bool, "true | false"),
    ki("gui.minimize_to_tray", ValueType::Bool, "true | false"),
    ki("gui.start_in_tray", ValueType::Bool, "true | false"),
    ki(
        "gui.poll_interval_secs",
        ValueType::Integer,
        "0 (off) or 5..=3600",
    ),
    ki("gui.renderer", ValueType::Choice, "auto | software"),
];

fn parse_bool(s: &str) -> Option<bool> {
    match normalize::normalize_input(s)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "true" | "on" | "yes" | "1" => Some(true),
        "false" | "off" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// Splits a list of adapter pins. Only `,` `;` and line breaks (also `、` `，` `；`) separate
/// items: adapter names contain spaces and Japanese text ("Ethernet 2",
/// "vEthernet (Default Switch)", "イーサネット 2"). Items are trimmed but otherwise kept as
/// typed ([`crate::netif::NetInterface::matches_pin`] width-folds names itself, and folding
/// here would turn `ー` into `-`). Case-insensitive duplicates are dropped.
fn split_interface_list(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in input.split([',', ';', '\r', '\n', '、', '､', '，', '；']) {
        let item = item.trim();
        if !item.is_empty() && !out.iter().any(|x| x.to_lowercase() == item.to_lowercase()) {
            out.push(item.to_owned());
        }
    }
    out
}

fn parse_uint<T: TryFrom<u64>>(s: &str, range: RangeInclusive<u64>) -> Option<T> {
    let n = normalize::normalize_input(s);
    let t = n.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: u64 = t.parse().ok()?;
    if !range.contains(&v) {
        return None;
    }
    T::try_from(v).ok()
}

impl Settings {
    /// All dotted keys accepted by [`Settings::get_key`] / [`Settings::set_key`], in file order.
    pub const KEYS: &'static [&'static str] = &[
        "language",
        "wake.port",
        "wake.repeat",
        "wake.interval_ms",
        "wake.limited_broadcast",
        "wake.include_virtual",
        "wake.interfaces",
        "wake.verify_timeout_secs",
        "probe.method",
        "probe.timeout_ms",
        "probe.tcp_ports",
        "gui.theme",
        "gui.show_tray",
        "gui.close_to_tray",
        "gui.minimize_to_tray",
        "gui.start_in_tray",
        "gui.poll_interval_secs",
        "gui.renderer",
    ];

    /// Type and accepted values of a key.
    pub fn key_info(key: &str) -> Option<&'static KeyInfo> {
        KEY_INFO.iter().find(|k| k.key == key.trim())
    }

    /// Returns a key's value as a typed TOML value (for JSON output). Lists are arrays.
    pub fn get_value(&self, key: &str) -> Result<toml::Value> {
        use toml::Value as V;
        let int = |v: u64| V::Integer(v as i64);
        Ok(match key.trim() {
            "language" => V::String(self.language.to_string()),
            "wake.port" => int(self.wake.port.into()),
            "wake.repeat" => int(self.wake.repeat.into()),
            "wake.interval_ms" => int(self.wake.interval_ms.into()),
            "wake.limited_broadcast" => V::Boolean(self.wake.limited_broadcast),
            "wake.include_virtual" => V::Boolean(self.wake.include_virtual),
            "wake.interfaces" => V::Array(
                self.wake
                    .interfaces
                    .iter()
                    .map(|s| V::String(s.clone()))
                    .collect(),
            ),
            "wake.verify_timeout_secs" => int(self.wake.verify_timeout_secs.into()),
            "probe.method" => V::String(self.probe.method.to_string()),
            "probe.timeout_ms" => int(self.probe.timeout_ms.into()),
            "probe.tcp_ports" => V::Array(
                self.probe
                    .tcp_ports
                    .iter()
                    .map(|p| int((*p).into()))
                    .collect(),
            ),
            "gui.theme" => V::String(self.gui.theme.to_string()),
            "gui.show_tray" => V::Boolean(self.gui.show_tray),
            "gui.close_to_tray" => V::Boolean(self.gui.close_to_tray),
            "gui.minimize_to_tray" => V::Boolean(self.gui.minimize_to_tray),
            "gui.start_in_tray" => V::Boolean(self.gui.start_in_tray),
            "gui.poll_interval_secs" => int(self.gui.poll_interval_secs.into()),
            "gui.renderer" => V::String(self.gui.renderer.to_string()),
            other => return Err(Error::UnknownSettingKey(other.to_owned())),
        })
    }

    /// Returns a key's value as display text (`true`, `3`, `3389, 445, 22`, `auto`).
    pub fn get_key(&self, key: &str) -> Result<String> {
        Ok(match self.get_value(key)? {
            toml::Value::String(s) => s,
            toml::Value::Array(a) => a
                .iter()
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(", "),
            other => other.to_string(),
        })
    }

    /// Sets a key from text as typed on the command line. Full-width input is accepted.
    /// `probe.tcp_ports` is comma / space separated. `wake.interfaces` is separated only by
    /// commas, semicolons or line breaks, because adapter names contain spaces and Japanese
    /// ("Ethernet 2", "イーサネット 2"). An empty string clears a list.
    ///
    /// Errors: [`Error::UnknownSettingKey`], [`Error::InvalidSetting`] (wrong type or out of
    /// range; nothing is changed).
    pub fn set_key(&mut self, key: &str, value: &str) -> Result<()> {
        let key = key.trim();
        let info = Self::key_info(key).ok_or_else(|| Error::UnknownSettingKey(key.to_owned()))?;
        let bad = || Error::InvalidSetting {
            key: key.to_owned(),
            value: value.to_owned(),
            expected: info.expected.to_owned(),
        };
        let b = || parse_bool(value).ok_or_else(bad);
        match key {
            "language" => self.language = value.parse().map_err(|_| bad())?,
            "wake.port" => self.wake.port = parse_uint(value, 1..=65535).ok_or_else(bad)?,
            "wake.repeat" => self.wake.repeat = parse_uint(value, 1..=10).ok_or_else(bad)?,
            "wake.interval_ms" => {
                self.wake.interval_ms = parse_uint(value, 0..=5000).ok_or_else(bad)?
            }
            "wake.limited_broadcast" => self.wake.limited_broadcast = b()?,
            "wake.include_virtual" => self.wake.include_virtual = b()?,
            "wake.interfaces" => self.wake.interfaces = split_interface_list(value),
            "wake.verify_timeout_secs" => {
                self.wake.verify_timeout_secs = parse_uint(value, 10..=3600).ok_or_else(bad)?
            }
            "probe.method" => self.probe.method = value.parse().map_err(|_| bad())?,
            "probe.timeout_ms" => {
                self.probe.timeout_ms = parse_uint(value, 100..=30000).ok_or_else(bad)?
            }
            "probe.tcp_ports" => {
                self.probe.tcp_ports = addr::parse_port_list(value).map_err(|_| bad())?
            }
            "gui.theme" => self.gui.theme = value.parse().map_err(|_| bad())?,
            "gui.show_tray" => self.gui.show_tray = b()?,
            "gui.close_to_tray" => self.gui.close_to_tray = b()?,
            "gui.minimize_to_tray" => self.gui.minimize_to_tray = b()?,
            "gui.start_in_tray" => self.gui.start_in_tray = b()?,
            "gui.poll_interval_secs" => {
                let v: u32 = parse_uint(value, 0..=3600).ok_or_else(bad)?;
                if !limits::poll_interval_ok(v) {
                    return Err(bad());
                }
                self.gui.poll_interval_secs = v;
            }
            "gui.renderer" => self.gui.renderer = value.parse().map_err(|_| bad())?,
            other => return Err(Error::UnknownSettingKey(other.to_owned())),
        }
        Ok(())
    }

    /// Keys whose current value is outside the accepted range, with the value and the
    /// accepted range. Used by [`super::Config::validate`].
    pub fn out_of_range(&self) -> Vec<(&'static str, String, &'static str)> {
        let mut v = Vec::new();
        let mut check = |key: &'static str, ok: bool, value: String| {
            if !ok {
                let expected = Self::key_info(key).map(|k| k.expected).unwrap_or("");
                v.push((key, value, expected));
            }
        };
        check("wake.port", self.wake.port != 0, self.wake.port.to_string());
        check(
            "wake.repeat",
            limits::REPEAT.contains(&self.wake.repeat),
            self.wake.repeat.to_string(),
        );
        check(
            "wake.interval_ms",
            limits::INTERVAL_MS.contains(&self.wake.interval_ms),
            self.wake.interval_ms.to_string(),
        );
        check(
            "wake.verify_timeout_secs",
            limits::VERIFY_TIMEOUT_SECS.contains(&self.wake.verify_timeout_secs),
            self.wake.verify_timeout_secs.to_string(),
        );
        check(
            "probe.timeout_ms",
            limits::PROBE_TIMEOUT_MS.contains(&self.probe.timeout_ms),
            self.probe.timeout_ms.to_string(),
        );
        check(
            "probe.tcp_ports",
            addr::check_port_list(&self.probe.tcp_ports).is_ok(),
            addr::format_port_list(&self.probe.tcp_ports),
        );
        check(
            "gui.poll_interval_secs",
            limits::poll_interval_ok(self.gui.poll_interval_secs),
            self.gui.poll_interval_secs.to_string(),
        );
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_info_agree() {
        assert_eq!(Settings::KEYS.len(), KEY_INFO.len());
        for (k, i) in Settings::KEYS.iter().zip(KEY_INFO) {
            assert_eq!(*k, i.key);
        }
        let s = Settings::default();
        for k in Settings::KEYS {
            s.get_key(k).unwrap();
        }
    }

    #[test]
    fn get_set_round_trip() {
        let mut s = Settings::default();
        assert_eq!(s.get_key("wake.repeat").unwrap(), "3");
        assert_eq!(s.get_key("probe.tcp_ports").unwrap(), "3389, 445, 22");
        assert_eq!(s.get_key("language").unwrap(), "auto");
        s.set_key("wake.repeat", "５").unwrap();
        assert_eq!(s.wake.repeat, 5);
        s.set_key("probe.tcp_ports", "22、80").unwrap();
        assert_eq!(s.probe.tcp_ports, vec![22, 80]);
        s.set_key("probe.tcp_ports", "").unwrap();
        assert!(s.probe.tcp_ports.is_empty());
        s.set_key("gui.theme", "Dark").unwrap();
        assert_eq!(s.gui.theme, Theme::Dark);
        s.set_key("wake.include_virtual", "on").unwrap();
        assert!(s.wake.include_virtual);
        s.set_key("wake.interfaces", "{A}, {B}").unwrap();
        assert_eq!(s.wake.interfaces, vec!["{A}", "{B}"]);
        s.set_key("language", "ja").unwrap();
        assert_eq!(s.language, LangSetting::Ja);
        s.set_key("gui.poll_interval_secs", "0").unwrap();
        assert_eq!(s.gui.effective_poll_interval(), None);
    }

    /// Adapter names with spaces or Japanese are one pin each, not split on spaces.
    #[test]
    fn interface_pins_keep_spaces_and_japanese() {
        let mut s = Settings::default();
        for (input, want) in [
            ("Ethernet 2", vec!["Ethernet 2"]),
            (
                "vEthernet (Default Switch)",
                vec!["vEthernet (Default Switch)"],
            ),
            ("イーサネット 2", vec!["イーサネット 2"]),
            (" {A} , {B};{C}\r\n{D} ", vec!["{A}", "{B}", "{C}", "{D}"]),
            ("Ethernet 2、Wi-Fi，13", vec!["Ethernet 2", "Wi-Fi", "13"]),
            ("Ethernet 2, ethernet 2", vec!["Ethernet 2"]),
            ("", vec![]),
        ] {
            s.set_key("wake.interfaces", input).unwrap();
            assert_eq!(s.wake.interfaces, want, "{input:?}");
        }
        s.set_key("wake.interfaces", "Ethernet 2").unwrap();
        assert_eq!(s.get_key("wake.interfaces").unwrap(), "Ethernet 2");

        // The pin selects exactly that adapter, not "Ethernet" plus index 2.
        let nic = |index, name: &str, ip: &str| {
            crate::netif::NetInterface::new(
                index,
                format!("{{{index}}}"),
                name,
                "NIC",
                6,
                true,
                None,
                vec![ip.parse().unwrap()],
            )
        };
        let ifaces = [
            nic(13, "Ethernet", "192.0.2.10/24"),
            nic(2, "Ethernet 2", "198.51.100.10/24"),
            nic(5, "イーサネット 2", "203.0.113.10/24"),
        ];
        let names = |s: &Settings| -> Vec<String> {
            crate::netif::select(
                &ifaces,
                &crate::netif::InterfaceFilter::from_settings(&s.wake),
            )
            .into_iter()
            .map(|x| x.name)
            .collect()
        };
        assert_eq!(names(&s), vec!["Ethernet 2"]);
        s.set_key("wake.interfaces", "イーサネット 2").unwrap();
        assert_eq!(names(&s), vec!["イーサネット 2"]);
    }

    #[test]
    fn set_rejects_out_of_range() {
        let mut s = Settings::default();
        for (k, v) in [
            ("wake.repeat", "0"),
            ("wake.repeat", "11"),
            ("wake.interval_ms", "5001"),
            ("wake.verify_timeout_secs", "9"),
            ("gui.poll_interval_secs", "3"),
            ("gui.poll_interval_secs", "3601"),
            ("wake.port", "0"),
            ("wake.limited_broadcast", "maybe"),
            ("probe.method", "arp"),
            ("probe.tcp_ports", "22,0"),
            (
                "probe.tcp_ports",
                "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17",
            ),
        ] {
            let err = s.set_key(k, v).unwrap_err();
            assert!(
                matches!(err, Error::InvalidSetting { .. }),
                "{k}={v}: {err}"
            );
        }
        assert!(matches!(
            s.set_key("nope", "1").unwrap_err(),
            Error::UnknownSettingKey(_)
        ));
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn out_of_range_reports() {
        let mut s = Settings::default();
        assert!(s.out_of_range().is_empty());
        s.wake.repeat = 50;
        s.gui.poll_interval_secs = 2;
        let r = s.out_of_range();
        assert_eq!(r.len(), 2);
        assert_eq!(s.wake.effective_repeat(), 10);
        assert_eq!(
            s.gui.effective_poll_interval(),
            Some(Duration::from_secs(5))
        );
    }
}
