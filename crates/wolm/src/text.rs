//! CLI-only messages that `wol_core::i18n::Msg` does not cover. Same rule as `Msg`: one
//! exhaustive `match` per language, English texts ASCII-only (tested).

use wol_core::i18n::Lang;

/// A CLI message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Text<'a> {
    /// Prefix of error lines.
    ErrorPrefix,
    /// Prefix of warning lines.
    WarningPrefix,
    /// Prefix of note lines.
    NotePrefix,
    /// `wake` without anything to wake.
    NothingToWake,
    /// `--wait` but no host can be checked.
    WaitNeedsAddress,
    /// A host that `--wait` cannot check.
    WaitNotMonitored {
        /// Label.
        label: &'a str,
    },
    /// `wolm gui` without the app.
    GuiNotFound {
        /// Folder searched.
        dir: &'a str,
    },
    /// `wolm gui` started the app.
    GuiStarted {
        /// Exe path.
        path: &'a str,
    },
    /// `config show` without a file.
    ConfigMissing {
        /// config.toml path.
        path: &'a str,
    },
    /// `config open` created the file.
    ConfigCreated {
        /// config.toml path.
        path: &'a str,
    },
    /// `config open` starts an editor.
    OpeningEditor {
        /// config.toml path.
        path: &'a str,
        /// Editor command.
        editor: &'a str,
    },
    /// Field label: broadcast.
    Broadcast,
    /// "(default)" suffix.
    Default,
    /// Dry-run: packet heading.
    Packet,
    /// `listen` timed out.
    ListenTimeout {
        /// Packets received.
        received: usize,
    },
    /// `listen -v`: a datagram that is not a magic packet.
    NotMagic {
        /// Sender.
        from: &'a str,
        /// Length.
        len: usize,
    },
    /// `export` wrote SecureOn passwords.
    SecureOnExported,
    /// `import`: a skipped record.
    ImportSkipped {
        /// Record location.
        location: &'a str,
        /// Reason.
        reason: &'a str,
    },
    /// `import`: hosts that did not change.
    ImportUnchanged {
        /// Count.
        count: usize,
    },
    /// Internal error.
    Internal {
        /// Panic message.
        message: &'a str,
    },
    /// Label: local data folder.
    LocalData,
    /// Label: portable root.
    PortableRoot,
    /// Label: data folder.
    DataFolder,
    /// Label: portable marker.
    Marker,
    /// Label: installed copy.
    Installed,
    /// Label: writable.
    Writable,
    /// Label: exists.
    Exists,
    /// Portable mode is on but a flag / env var chooses another folder.
    PortableOverridden {
        /// The folder in use.
        dir: &'a str,
    },
    /// `config validate`: newer schema / not writable note.
    Summary {
        /// Count.
        count: usize,
    },
    /// `path`: DIR still contains a quote (an escaped closing quote swallowed arguments).
    PathQuoteHint,
    /// `config open`: VISUAL / EDITOR could not be started; Notepad is used instead.
    EditorFailed {
        /// Editor command.
        editor: &'a str,
        /// OS error.
        error: &'a str,
    },
    /// `import`: a CSV row number as location.
    Row {
        /// 1-based row number (the header is row 1).
        n: &'a str,
    },
    /// `path add`: every user of the computer may change the files in DIR.
    PathSharedFolder {
        /// The folder.
        dir: &'a str,
    },
    /// `path add --scope machine` without `--force` for such a folder.
    PathSharedFolderRefused {
        /// The folder.
        dir: &'a str,
    },
    /// `portable enable`: every user may read and change the data folder.
    PortableSharedFolder {
        /// The data folder.
        dir: &'a str,
    },
    /// `listen`: a datagram larger than the receive buffer.
    Oversized,
}

impl Text<'_> {
    /// Text in `lang`.
    pub fn text(&self, lang: Lang) -> String {
        match lang {
            Lang::Ja => self.ja(),
            Lang::En => self.en(),
        }
    }

    fn ja(&self) -> String {
        use Text::*;
        match *self {
            ErrorPrefix => "エラー:".to_owned(),
            WarningPrefix => "警告:".to_owned(),
            NotePrefix => "注意:".to_owned(),
            NothingToWake => {
                "起動する対象を指定してください（HOST、MAC、--mac、--group、--all）".to_owned()
            }
            WaitNeedsAddress => "--wait で起動を確認するには、アドレスが登録されたホストが必要です（wolm edit HOST --address ...）".to_owned(),
            WaitNotMonitored { label } => {
                format!("{label} はアドレスが無いか状態確認が無効のため、起動を確認できません")
            }
            GuiNotFound { dir } => format!("wol-manager.exe が見つかりません（{dir}）"),
            GuiStarted { path } => format!("WoL Manager を起動しました: {path}"),
            ConfigMissing { path } => {
                format!("設定ファイルはまだありません（{path}）。既定値を表示します。")
            }
            ConfigCreated { path } => format!("設定ファイルを作成しました: {path}"),
            OpeningEditor { path, editor } => format!("{editor} で {path} を開きます"),
            Broadcast => "ブロードキャスト".to_owned(),
            Default => "（既定）".to_owned(),
            Packet => "パケット".to_owned(),
            ListenTimeout { received } => {
                format!("時間切れで終了しました（受信 {received} 件）")
            }
            NotMagic { from, len } => {
                format!("{from} から {len} バイト（マジックパケットではありません）")
            }
            SecureOnExported => {
                "SecureOn パスワードは平文で書き出されています。ファイルの扱いに注意してください。"
                    .to_owned()
            }
            ImportSkipped { location, reason } => format!("スキップ（{location}）: {reason}"),
            ImportUnchanged { count } => format!("変更なし {count} 台"),
            Internal { message } => format!("内部エラーが発生しました: {message}"),
            LocalData => "ローカルデータ".to_owned(),
            PortableRoot => "アプリのフォルダー".to_owned(),
            DataFolder => "data フォルダー".to_owned(),
            Marker => "マーカー".to_owned(),
            Installed => "インストール版".to_owned(),
            Writable => "書き込み可能".to_owned(),
            Exists => "存在する".to_owned(),
            PortableOverridden { dir } => format!(
                "--config-dir または WOL_MANAGER_CONFIG_DIR が指定されているため、今回は {dir} を使います"
            ),
            Summary { count } => format!("問題 {count} 件"),
            PathQuoteHint => concat!(
                r#"DIR に引用符 (") が含まれています。引用符で囲んだフォルダーが \ で終わると、"#,
                r#"\" が閉じる引用符ではなく文字の " になり、後ろの引数（--scope や --json など）"#,
                r#"まで DIR に入ってしまいます。末尾の \ を付けないか、\\ と重ねてください"#,
                r#"（例: "C:\Tools\bin" または "C:\Tools\bin\\"）。"#
            )
            .to_owned(),
            EditorFailed { editor, error } => {
                format!("{editor} を起動できません（{error}）。メモ帳で開きます。")
            }
            Row { n } => format!("{n} 行目"),
            PathSharedFolder { dir } => format!(
                "{dir} の中のファイルは、このコンピューターのすべてのユーザーが変更できます（wolm.exe を置き換えることもできます）。PATH に入れるプログラムは、自分と管理者だけが変更できるフォルダー（例: %LOCALAPPDATA%\\Programs）に置いてください。"
            ),
            PathSharedFolderRefused { dir } => format!(
                "{dir} はシステムの PATH に追加しません。このフォルダーのファイルはすべてのユーザーが変更でき、そのプログラムを管理者を含む全員が実行することになるためです。Program Files の下に移すか、それでも追加する場合は --force を付けてください。"
            ),
            PortableSharedFolder { dir } => format!(
                "{dir} は、このコンピューターのすべてのユーザーが読み書きできます（ホストの一覧や SecureOn パスワードも含みます）。共用の PC では、自分だけが使えるフォルダー（例: %LOCALAPPDATA%\\Programs）かリムーバブル ドライブに置いてください。"
            ),
            Oversized => "受信バッファーより大きいデータグラムを無視しました".to_owned(),
        }
    }

    fn en(&self) -> String {
        use Text::*;
        match *self {
            ErrorPrefix => "error:".to_owned(),
            WarningPrefix => "warning:".to_owned(),
            NotePrefix => "note:".to_owned(),
            NothingToWake => "Specify what to wake: HOST, MAC, --mac, --group or --all".to_owned(),
            WaitNeedsAddress => {
                "--wait needs a host with an address to check (wolm edit HOST --address ...)"
                    .to_owned()
            }
            WaitNotMonitored { label } => format!(
                "{label} has no address or its status check is off; cannot check whether it comes online"
            ),
            GuiNotFound { dir } => format!("wol-manager.exe was not found ({dir})"),
            GuiStarted { path } => format!("Started WoL Manager: {path}"),
            ConfigMissing { path } => {
                format!("The settings file does not exist yet ({path}); showing the defaults.")
            }
            ConfigCreated { path } => format!("Created the settings file: {path}"),
            OpeningEditor { path, editor } => format!("Opening {path} with {editor}"),
            Broadcast => "Broadcast".to_owned(),
            Default => " (default)".to_owned(),
            Packet => "Packet".to_owned(),
            ListenTimeout { received } => format!("Timed out ({received} received)"),
            NotMagic { from, len } => format!("{len} bytes from {from} (not a magic packet)"),
            SecureOnExported => {
                "SecureOn passwords are exported in plain text; keep the file safe.".to_owned()
            }
            ImportSkipped { location, reason } => format!("Skipped ({location}): {reason}"),
            ImportUnchanged { count } => format!("{count} unchanged"),
            Internal { message } => format!("Internal error: {message}"),
            LocalData => "Local data".to_owned(),
            PortableRoot => "App folder".to_owned(),
            DataFolder => "Data folder".to_owned(),
            Marker => "Marker".to_owned(),
            Installed => "Installed copy".to_owned(),
            Writable => "Writable".to_owned(),
            Exists => "Exists".to_owned(),
            PortableOverridden { dir } => {
                format!("--config-dir or WOL_MANAGER_CONFIG_DIR is set, so {dir} is used this time")
            }
            Summary { count } => format!("{count} problem(s)"),
            PathQuoteHint => concat!(
                r#"DIR contains a quote ("). When a quoted folder ends with \, the \" is read "#,
                r#"as a literal quote instead of the closing one, so the arguments after it "#,
                r#"(--scope, --json, ...) become part of DIR. Leave out the trailing \ or "#,
                r#"double it (e.g. "C:\Tools\bin" or "C:\Tools\bin\\")."#
            )
            .to_owned(),
            EditorFailed { editor, error } => {
                format!("Cannot start {editor} ({error}); opening Notepad instead.")
            }
            Row { n } => format!("row {n}"),
            PathSharedFolder { dir } => format!(
                "Every user of this computer can change the files in {dir} (and replace wolm.exe). Keep programs that are on PATH in a folder that only you and administrators can change, such as %LOCALAPPDATA%\\Programs."
            ),
            PathSharedFolderRefused { dir } => format!(
                "{dir} is not added to the system PATH: every user of this computer can change its files, and everyone, administrators included, would run them. Move the folder under Program Files, or add --force to add it anyway."
            ),
            PortableSharedFolder { dir } => format!(
                "Every user of this computer can read and change {dir} (the host list and SecureOn passwords included). On a shared computer, keep the app in a folder only you can use (such as %LOCALAPPDATA%\\Programs) or on a removable drive."
            ),
            Oversized => "Ignored a datagram larger than the receive buffer".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every() -> Vec<Text<'static>> {
        use Text::*;
        vec![
            ErrorPrefix,
            WarningPrefix,
            NotePrefix,
            NothingToWake,
            WaitNeedsAddress,
            WaitNotMonitored { label: "PC" },
            GuiNotFound { dir: "C:\\x" },
            GuiStarted { path: "C:\\x" },
            ConfigMissing { path: "C:\\x" },
            ConfigCreated { path: "C:\\x" },
            OpeningEditor {
                path: "C:\\x",
                editor: "notepad",
            },
            Broadcast,
            Default,
            Packet,
            ListenTimeout { received: 1 },
            NotMagic {
                from: "1.2.3.4",
                len: 3,
            },
            SecureOnExported,
            ImportSkipped {
                location: "row 2",
                reason: "bad",
            },
            ImportUnchanged { count: 1 },
            Internal { message: "x" },
            LocalData,
            PortableRoot,
            DataFolder,
            Marker,
            Installed,
            Writable,
            Exists,
            PortableOverridden { dir: "C:\\x" },
            Summary { count: 2 },
            PathQuoteHint,
            EditorFailed {
                editor: "code",
                error: "not found",
            },
            Row { n: "3" },
            PathSharedFolder { dir: "C:\\x" },
            PathSharedFolderRefused { dir: "C:\\x" },
            PortableSharedFolder { dir: "C:\\x" },
            Oversized,
        ]
    }

    #[test]
    fn english_is_ascii_and_nothing_is_empty() {
        for t in every() {
            let en = t.text(Lang::En);
            let ja = t.text(Lang::Ja);
            assert!(en.is_ascii(), "{en}");
            assert!(!en.is_empty() && !ja.is_empty());
        }
    }
}
