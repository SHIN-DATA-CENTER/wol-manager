//! Rust-side texts of the GUI.
//!
//! Almost all UI text lives in the `.slint` files (`@tr`). Rust renders only toasts, notice
//! details and the tray tooltip. Those come from [`wol_core::i18n::Msg`]; the few messages
//! that exist only in the GUI (clipboard, "could not save", …) are in [`GuiText`].
//!
//! Every Rust-made string that stays on screen is kept as a [`Text`] so that it can be
//! rendered again after a runtime language switch (contract §9.4).

use wol_core::i18n::{Lang, Msg};
use wol_core::secret::SecretKind;

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
    /// Trusting / forgetting an SSH host key could not be saved (detail: the error).
    HostKeySaveFailed,
    /// A password could not be saved in / deleted from Credential Manager (detail: the error).
    SecretSaveFailed,
    /// A saved password belongs to another connection (kind / account / address / port) and
    /// is not used until it is entered again.
    SecretStale {
        /// Which secret.
        kind: SecretKind,
        /// What it was saved for ("" = unknown).
        stored_for: String,
        /// Shown in the open editor ("enter it again") rather than after saving ("edit the
        /// host").
        in_editor: bool,
    },
    /// The host's remote management was set up by a newer version (kept, not usable here).
    RemoteFromNewerVersion,
    /// A user action confirmed the use of the current Windows sign-in for a host without a
    /// saved password (once; cross review X2).
    SignInConfirmed {
        /// Host name.
        label: String,
        /// The account ("" = unknown).
        account: String,
    },
    /// The editor's SSH key file is on a network path: not saved (cross review m3 / m4).
    KeyFileOnNetwork(String),
    /// The saved SSH key file looks like a public key.
    KeyFileIsPublic(String),
    /// The saved SSH key file does not exist.
    KeyFileMissing(String),
    /// The host's management address, kind or custom command changed while the power dialog
    /// was open: nothing was sent (review S1 / C9).
    PowerHostChanged {
        /// Host name.
        label: String,
    },
    /// A menu action was refused: another operation or a restart / shutdown verification
    /// of the host runs (review C8).
    RemoteBusy {
        /// Host name.
        label: String,
    },
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
            GuiText::HostKeySaveFailed => "ホスト鍵の設定を保存できませんでした".to_owned(),
            GuiText::SecretSaveFailed => {
                "資格情報マネージャーのパスワードを更新できませんでした".to_owned()
            }
            GuiText::SecretStale {
                kind,
                stored_for,
                in_editor,
            } => {
                let what = Msg::SecretKindName(*kind).text(Lang::Ja);
                let head = if stored_for.is_empty() {
                    format!("保存されている{what}は別の接続先用のため、使用されません。")
                } else {
                    format!("保存されている{what}は {stored_for} 用のため、使用されません。")
                };
                if *in_editor {
                    format!("{head}もう一度入力してください。")
                } else {
                    format!("{head}ホストを編集して、もう一度入力してください。")
                }
            }
            GuiText::RemoteFromNewerVersion => {
                "このホストのリモート管理は新しいバージョンの WoL Manager で設定されているため、このバージョンでは使えません。ここで設定すると、その設定は置き換えられます。"
                    .to_owned()
            }
            GuiText::SignInConfirmed { label, account } => {
                let who = if account.is_empty() {
                    String::new()
                } else {
                    format!("（{account}）")
                };
                format!(
                    "{label} にはパスワードが保存されていないため、現在の Windows サインイン{who}で接続します。これ以降、起動時刻の自動取得でも使われます。"
                )
            }
            GuiText::KeyFileOnNetwork(path) => format!(
                "鍵ファイル {path} はネットワーク上にあるため使えません（読み込むと、その PC に Windows の資格情報でログオンすることになります）。この PC のフォルダーにコピーして指定してください。"
            ),
            GuiText::KeyFileIsPublic(path) => format!(
                "{path} は公開鍵のようです。秘密鍵（.pub の付かないファイル）を指定してください。"
            ),
            GuiText::KeyFileMissing(path) => format!("鍵ファイル {path} が見つかりません。"),
            GuiText::PowerHostChanged { label } => format!(
                "{label} の設定（管理用アドレス・種類・独自のコマンド）が確認画面を開いている間に変更されたため、実行しませんでした。内容を確認して、もう一度操作してください。"
            ),
            GuiText::RemoteBusy { label } => format!(
                "{label} では別の操作（再起動・シャットダウンの確認など）を実行中です。終わってからもう一度操作してください。"
            ),
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
            GuiText::HostKeySaveFailed => "Could not save the host key setting".to_owned(),
            GuiText::SecretSaveFailed => {
                "Could not update the password in Credential Manager".to_owned()
            }
            GuiText::SecretStale {
                kind,
                stored_for,
                in_editor,
            } => {
                let what = Msg::SecretKindName(*kind).text(Lang::En);
                let head = if stored_for.is_empty() {
                    format!("The saved {what} is for another connection and is not used.")
                } else {
                    format!("The saved {what} is for {stored_for} and is not used.")
                };
                if *in_editor {
                    format!("{head} Enter it again.")
                } else {
                    format!("{head} Edit the host and enter it again.")
                }
            }
            GuiText::RemoteFromNewerVersion => {
                "Remote management of this host was set up by a newer version of WoL Manager and cannot be used here. Setting it up here replaces that setting."
                    .to_owned()
            }
            GuiText::SignInConfirmed { label, account } => {
                let who = if account.is_empty() {
                    String::new()
                } else {
                    format!(" ({account})")
                };
                format!(
                    "No password is saved for {label}, so it connects with your Windows sign-in{who}. Automatic boot-time checks use it from now on too."
                )
            }
            GuiText::KeyFileOnNetwork(path) => format!(
                "The key file {path} is on the network and cannot be used (reading it would log on to that computer with your Windows credentials). Copy it to a folder on this PC."
            ),
            GuiText::KeyFileIsPublic(path) => format!(
                "{path} looks like a public key; choose the private key (the file without .pub)."
            ),
            GuiText::KeyFileMissing(path) => format!("The key file {path} does not exist."),
            GuiText::PowerHostChanged { label } => format!(
                "The settings of {label} (management address, kind or custom command) changed while the confirmation was open, so nothing was sent. Check them and try again."
            ),
            GuiText::RemoteBusy { label } => format!(
                "Another operation of {label} is still running (e.g. checking a restart or shutdown). Try again when it has finished."
            ),
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
            GuiText::HostKeySaveFailed,
            GuiText::SecretSaveFailed,
            GuiText::SecretStale {
                kind: SecretKind::Login,
                stored_for: "root@192.168.1.20:22 (SSH)".into(),
                in_editor: true,
            },
            GuiText::SecretStale {
                kind: SecretKind::Sudo,
                stored_for: String::new(),
                in_editor: false,
            },
            GuiText::RemoteFromNewerVersion,
            GuiText::SignInConfirmed {
                label: "PC".into(),
                account: r"DESK\me".into(),
            },
            GuiText::SignInConfirmed {
                label: "PC".into(),
                account: String::new(),
            },
            GuiText::KeyFileOnNetwork(r"\\srv\k\id".into()),
            GuiText::KeyFileIsPublic(r"C:\k\id.pub".into()),
            GuiText::KeyFileMissing(r"C:\k\id".into()),
            GuiText::PowerHostChanged { label: "PC".into() },
            GuiText::RemoteBusy { label: "PC".into() },
        ] {
            assert!(g.text(Lang::En).is_ascii(), "{g:?}");
            assert!(!g.text(Lang::Ja).is_empty());
        }
    }
}
