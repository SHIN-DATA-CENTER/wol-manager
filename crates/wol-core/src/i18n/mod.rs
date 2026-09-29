//! Runtime messages in Japanese and English.
//!
//! The GUI keeps its UI text in `.slint` files (`@tr`); Rust-side text (toasts, CLI output,
//! error descriptions) comes from [`Msg`]. Every message is translated in an exhaustive
//! `match` per language, so a missing translation is a compile error.
//!
//! Language resolution: [`resolve_lang`] (GUI: `WOL_MANAGER_LANG`, then `settings.language`,
//! then the OS) and [`resolve_lang_chain`] (CLI: `--lang`, then the env var, then the config).

mod msg;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub use msg::{Header, Msg, StatusLabel};

use crate::consts;
use crate::error::Error;

/// A concrete UI language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    /// 日本語.
    Ja,
    /// English.
    En,
}

impl Lang {
    /// `"ja"` / `"en"` (also the Slint bundled-translation name for Japanese).
    pub const fn code(self) -> &'static str {
        match self {
            Lang::Ja => "ja",
            Lang::En => "en",
        }
    }
}

impl fmt::Display for Lang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// The `language` setting / `--lang` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LangSetting {
    /// Follow the OS (Japanese when the locale starts with `ja`).
    #[default]
    Auto,
    /// Japanese.
    Ja,
    /// English.
    En,
}

impl LangSetting {
    /// All values in display order.
    pub const ALL: &'static [LangSetting] = &[LangSetting::Auto, LangSetting::Ja, LangSetting::En];

    /// `"auto"` / `"ja"` / `"en"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            LangSetting::Auto => "auto",
            LangSetting::Ja => "ja",
            LangSetting::En => "en",
        }
    }

    /// The concrete language, if not `Auto`.
    pub const fn fixed(self) -> Option<Lang> {
        match self {
            LangSetting::Auto => None,
            LangSetting::Ja => Some(Lang::Ja),
            LangSetting::En => Some(Lang::En),
        }
    }

    /// Value of `WOL_MANAGER_LANG`, if set and valid.
    pub fn from_env() -> Option<LangSetting> {
        std::env::var(consts::ENV_LANG).ok()?.parse().ok()
    }
}

impl fmt::Display for LangSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LangSetting {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match crate::normalize::normalize_input(s)
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "auto" => Ok(LangSetting::Auto),
            "ja" | "jp" | "ja-jp" | "japanese" => Ok(LangSetting::Ja),
            "en" | "en-us" | "english" => Ok(LangSetting::En),
            _ => Err("expected one of: auto | ja | en".to_owned()),
        }
    }
}

/// Language from a BCP 47 locale string: `ja*` → Japanese, anything else → English.
pub fn lang_from_locale(locale: &str) -> Lang {
    if locale.trim().to_ascii_lowercase().starts_with("ja") {
        Lang::Ja
    } else {
        Lang::En
    }
}

/// OS UI language (via `sys-locale`).
pub fn detect_os_lang() -> Lang {
    sys_locale::get_locale()
        .map(|l| lang_from_locale(&l))
        .unwrap_or(Lang::En)
}

/// GUI rule: a valid `env_override` (value of `WOL_MANAGER_LANG`, `ja` / `en`) wins, then
/// `setting`, then the OS language.
pub fn resolve_lang(setting: LangSetting, env_override: Option<&str>) -> Lang {
    let env = env_override.and_then(|e| e.parse::<LangSetting>().ok());
    resolve_lang_chain(&[env.unwrap_or_default(), setting])
}

/// First non-`Auto` value wins; the OS language otherwise. CLI:
/// `resolve_lang_chain(&[flag, LangSetting::from_env().unwrap_or_default(), config])`.
pub fn resolve_lang_chain(chain: &[LangSetting]) -> Lang {
    chain
        .iter()
        .find_map(|s| s.fixed())
        .unwrap_or_else(detect_os_lang)
}

/// User-facing description of an error.
pub fn describe_error(err: &Error, lang: Lang) -> String {
    msg::describe_error(err, lang)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lang_setting_parse_display_serde() {
        assert_eq!("JA".parse::<LangSetting>(), Ok(LangSetting::Ja));
        assert_eq!("ａｕｔｏ".parse::<LangSetting>(), Ok(LangSetting::Auto));
        assert!("fr".parse::<LangSetting>().is_err());
        assert_eq!(LangSetting::En.to_string(), "en");
        assert_eq!(serde_json::to_string(&LangSetting::Ja).unwrap(), "\"ja\"");
        assert_eq!(
            serde_json::from_str::<LangSetting>("\"auto\"").unwrap(),
            LangSetting::Auto
        );
    }

    #[test]
    fn locale_rule() {
        assert_eq!(lang_from_locale("ja-JP"), Lang::Ja);
        assert_eq!(lang_from_locale("JA"), Lang::Ja);
        assert_eq!(lang_from_locale("en-US"), Lang::En);
        assert_eq!(lang_from_locale("jv-ID"), Lang::En);
        let _ = detect_os_lang();
    }

    #[test]
    fn resolution_order() {
        assert_eq!(resolve_lang(LangSetting::Ja, Some("en")), Lang::En);
        assert_eq!(resolve_lang(LangSetting::Ja, Some("auto")), Lang::Ja);
        assert_eq!(resolve_lang(LangSetting::Ja, Some("bogus")), Lang::Ja);
        assert_eq!(resolve_lang(LangSetting::En, None), Lang::En);
        assert_eq!(resolve_lang(LangSetting::Auto, None), detect_os_lang());
        assert_eq!(
            resolve_lang_chain(&[LangSetting::Auto, LangSetting::En, LangSetting::Ja]),
            Lang::En
        );
    }
}
