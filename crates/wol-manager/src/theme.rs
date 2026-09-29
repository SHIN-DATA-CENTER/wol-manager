//! Colour scheme (plan §7.4, contract §9.3).
//!
//! * `system` at startup: `Palette.color-scheme` is **not** assigned, so the fluent style and
//!   `AboutSlint` follow the OS by themselves.
//! * `light` / `dark`: `AppWindow.set-color-scheme(dark)`.
//! * Back to `system` at runtime (after an explicit assignment broke the default binding):
//!   read `HKCU\…\Themes\Personalize\AppsUseLightTheme`, assign it, and keep following it.

use wol_core::model::Theme;

/// What to do with `Palette.color-scheme`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Leave the OS-following default binding alone.
    Untouched,
    /// Assign light (`false`) or dark (`true`).
    Assign(bool),
}

/// Tracks whether the palette was ever assigned (then "system" must be emulated).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThemeState {
    /// `set-color-scheme` was called at least once.
    pub assigned: bool,
    /// Emulating "system": the OS value is re-read periodically.
    pub following_os: bool,
    /// Last OS value assigned while following.
    pub last_os_dark: Option<bool>,
}

/// Decision at startup.
pub fn startup(theme: Theme) -> Scheme {
    match theme {
        Theme::System => Scheme::Untouched,
        Theme::Light => Scheme::Assign(false),
        Theme::Dark => Scheme::Assign(true),
    }
}

/// Decision when the setting changes at runtime. `os_dark` = current OS app mode, if known.
pub fn on_change(state: &mut ThemeState, theme: Theme, os_dark: Option<bool>) -> Scheme {
    match theme {
        Theme::Light | Theme::Dark => {
            state.following_os = false;
            state.last_os_dark = None;
            state.assigned = true;
            Scheme::Assign(theme == Theme::Dark)
        }
        Theme::System if !state.assigned => Scheme::Untouched,
        Theme::System => {
            let dark = os_dark.unwrap_or(false);
            state.following_os = true;
            state.last_os_dark = Some(dark);
            Scheme::Assign(dark)
        }
    }
}

/// Periodic re-check while emulating "system": assigns only when the OS value changed.
pub fn follow(state: &mut ThemeState, os_dark: Option<bool>) -> Scheme {
    match (state.following_os, os_dark) {
        (true, Some(dark)) if state.last_os_dark != Some(dark) => {
            state.last_os_dark = Some(dark);
            Scheme::Assign(dark)
        }
        _ => Scheme::Untouched,
    }
}

/// Records a startup assignment.
pub fn note_startup(state: &mut ThemeState, s: Scheme) {
    if let Scheme::Assign(_) = s {
        state.assigned = true;
    }
}

/// `true` when Windows apps use the dark mode (`AppsUseLightTheme` = 0); `None` if unknown.
pub fn os_apps_dark() -> Option<bool> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        .ok()?;
    let light: u32 = key.get_value("AppsUseLightTheme").ok()?;
    Some(light == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_leaves_system_alone() {
        assert_eq!(startup(Theme::System), Scheme::Untouched);
        assert_eq!(startup(Theme::Light), Scheme::Assign(false));
        assert_eq!(startup(Theme::Dark), Scheme::Assign(true));
    }

    #[test]
    fn runtime_switch_back_to_system_follows_os() {
        let mut st = ThemeState::default();
        // System -> System without assignment: nothing to do.
        assert_eq!(
            on_change(&mut st, Theme::System, Some(true)),
            Scheme::Untouched
        );
        assert!(!st.following_os);
        // Dark, then back to system while the OS is light.
        assert_eq!(
            on_change(&mut st, Theme::Dark, Some(false)),
            Scheme::Assign(true)
        );
        assert!(st.assigned);
        assert_eq!(
            on_change(&mut st, Theme::System, Some(false)),
            Scheme::Assign(false)
        );
        assert!(st.following_os);
        // OS unchanged: nothing; OS switches to dark: assign dark.
        assert_eq!(follow(&mut st, Some(false)), Scheme::Untouched);
        assert_eq!(follow(&mut st, Some(true)), Scheme::Assign(true));
        assert_eq!(follow(&mut st, None), Scheme::Untouched);
        // Explicit light stops following.
        assert_eq!(
            on_change(&mut st, Theme::Light, Some(true)),
            Scheme::Assign(false)
        );
        assert_eq!(follow(&mut st, Some(false)), Scheme::Untouched);
    }

    #[test]
    fn startup_assignment_is_remembered() {
        let mut st = ThemeState::default();
        note_startup(&mut st, startup(Theme::Light));
        assert_eq!(
            on_change(&mut st, Theme::System, None),
            Scheme::Assign(false)
        );
        let mut st2 = ThemeState::default();
        note_startup(&mut st2, startup(Theme::System));
        assert_eq!(
            on_change(&mut st2, Theme::System, Some(true)),
            Scheme::Untouched
        );
    }
}
