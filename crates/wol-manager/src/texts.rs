//! Rust-side texts of the GUI.
//!
//! Almost all UI text lives in the `.slint` files (`@tr`). Rust renders only toasts, notice
//! details and the tray tooltip. Those come from [`wol_core::i18n::Msg`]; the few messages
//! that exist only in the GUI (clipboard, "could not save", …) are in [`GuiText`].
//!
//! Every Rust-made string that stays on screen is kept as a [`Text`] so that it can be
//! rendered again after a runtime language switch (contract §9.4).

use wol_core::i18n::{Lang, Msg};

/// Messages that only the GUI needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuiText {
    /// A MAC address was copied.
    CopiedMac(String),
    /// An address was copied.
    CopiedAddress(String),
    /// The clipboard could not be opened.
    ClipboardFailed,
    /// Saving a host failed (detail: the error).
    SaveFailed,
    /// Deleting a host failed (detail: the error).
    DeleteFailed,
    /// Saving a setting failed (detail: the error).
    SettingFailed,
    /// Reloading the settings file failed (detail: the error).
    ReloadFailed,
    /// Switching portable mode failed (detail: the error).
    PortableFailed,
    /// The settings location was changed outside the app (detail: the new folder).
    LocationChanged,
    /// Changing PATH failed (detail: the error).
    PathFailed,
    /// Opening a file, folder or link failed.
    OpenFailed(String),
    /// Tray tooltip while hosts are waking.
    TrayTipWaking(usize),
    /// Panic message box.
    Crashed(String),
    /// Startup failure message box.
    StartFailed(String),
    /// Shutdown-block reason while settings are saved at logoff / shutdown.
    SavingOnExit,
}

impl GuiText {
    /// Text in `lang`.
    pub fn text(&self, lang: Lang) -> String {
        match lang {
            Lang::Ja => self.ja(),
            Lang::En => self.en(),
        }
    }

    fn ja(&self) -> String {
        match self {
            GuiText::CopiedMac(m) => format!("MAC アドレス {m} をコピーしました"),
            GuiText::CopiedAddress(a) => format!("アドレス {a} をコピーしました"),
            GuiText::ClipboardFailed => "クリップボードにコピーできませんでした".to_owned(),
            GuiText::SaveFailed => "ホストを保存できませんでした".to_owned(),
            GuiText::DeleteFailed => "ホストを削除できませんでした".to_owned(),
            GuiText::SettingFailed => "設定を保存できませんでした".to_owned(),
            GuiText::ReloadFailed => "設定ファイルを読み込めませんでした".to_owned(),
            GuiText::PortableFailed => "ポータブルモードを切り替えられませんでした".to_owned(),
            GuiText::LocationChanged => {
                "ポータブルモードがアプリの外で切り替えられました。次の設定フォルダーを使います:"
                    .to_owned()
            }
            GuiText::PathFailed => "PATH を変更できませんでした".to_owned(),
            GuiText::OpenFailed(what) => format!("{what} を開けませんでした"),
            GuiText::TrayTipWaking(n) => format!("WoL Manager – {n} 台を起動中"),
            GuiText::Crashed(log) => format!(
                "WoL Manager で予期しないエラーが発生しました。\n\n詳細はログを確認してください:\n{log}"
            ),
            GuiText::StartFailed(detail) => {
                format!("WoL Manager を起動できませんでした。\n\n{detail}")
            }
            GuiText::SavingOnExit => "WoL Manager の設定を保存しています".to_owned(),
        }
    }

    fn en(&self) -> String {
        match self {
            GuiText::CopiedMac(m) => format!("Copied MAC address {m}"),
            GuiText::CopiedAddress(a) => format!("Copied address {a}"),
            GuiText::ClipboardFailed => "Could not copy to the clipboard".to_owned(),
            GuiText::SaveFailed => "Could not save the host".to_owned(),
            GuiText::DeleteFailed => "Could not delete the host".to_owned(),
            GuiText::SettingFailed => "Could not save the setting".to_owned(),
            GuiText::ReloadFailed => "Could not read the settings file".to_owned(),
            GuiText::PortableFailed => "Could not switch portable mode".to_owned(),
            GuiText::LocationChanged => {
                "Portable mode was switched outside the app. Now using this settings folder:"
                    .to_owned()
            }
            GuiText::PathFailed => "Could not change PATH".to_owned(),
            GuiText::OpenFailed(what) => format!("Could not open {what}"),
            GuiText::TrayTipWaking(n) => format!("WoL Manager – waking {n}"),
            GuiText::Crashed(log) => format!(
                "WoL Manager ran into an unexpected error.\n\nSee the log for details:\n{log}"
            ),
            GuiText::StartFailed(detail) => format!("WoL Manager could not start.\n\n{detail}"),
            GuiText::SavingOnExit => "WoL Manager is saving its settings".to_owned(),
        }
    }
}

/// A Rust-made string that can be rendered in either language.
#[derive(Debug, Clone, PartialEq)]
pub enum Text {
    /// Nothing ("").
    Empty,
    /// Language-independent data (paths, names, OS messages).
    Data(String),
    /// A wol-core message.
    Msg(Box<Msg>),
    /// A GUI message.
    Gui(GuiText),
    /// Pre-rendered in both languages (e.g. `describe_error` output).
    Pair {
        /// Japanese.
        ja: String,
        /// English.
        en: String,
    },
}

impl Text {
    /// A wol-core message.
    pub fn msg(m: Msg) -> Text {
        Text::Msg(Box::new(m))
    }

    /// The user-facing description of an error in both languages.
    pub fn error(e: &wol_core::Error) -> Text {
        Text::Pair {
            ja: wol_core::i18n::describe_error(e, Lang::Ja),
            en: wol_core::i18n::describe_error(e, Lang::En),
        }
    }

    /// Renders the text.
    pub fn render(&self, lang: Lang) -> String {
        match self {
            Text::Empty => String::new(),
            Text::Data(s) => s.clone(),
            Text::Msg(m) => m.text(lang),
            Text::Gui(g) => g.text(lang),
            Text::Pair { ja, en } => match lang {
                Lang::Ja => ja.clone(),
                Lang::En => en.clone(),
            },
        }
    }
}

impl From<GuiText> for Text {
    fn from(g: GuiText) -> Text {
        Text::Gui(g)
    }
}

impl From<Msg> for Text {
    fn from(m: Msg) -> Text {
        Text::msg(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts_render_in_both_languages() {
        let t = Text::from(GuiText::CopiedMac("AA:BB:CC:DD:EE:FF".into()));
        assert!(t.render(Lang::Ja).contains("コピー"));
        assert!(t.render(Lang::En).starts_with("Copied"));
        let m = Text::from(Msg::HostAdded { name: "PC".into() });
        assert_ne!(m.render(Lang::Ja), m.render(Lang::En));
        assert_eq!(Text::Data("x".into()).render(Lang::Ja), "x");
        assert_eq!(Text::Empty.render(Lang::En), "");
    }

    #[test]
    fn english_gui_texts_are_ascii_or_dash() {
        for g in [
            GuiText::ClipboardFailed,
            GuiText::SaveFailed,
            GuiText::DeleteFailed,
            GuiText::SettingFailed,
            GuiText::ReloadFailed,
            GuiText::PortableFailed,
            GuiText::LocationChanged,
            GuiText::PathFailed,
            GuiText::SavingOnExit,
        ] {
            assert!(g.text(Lang::En).is_ascii(), "{g:?}");
            assert!(!g.text(Lang::Ja).is_empty());
        }
    }
}
