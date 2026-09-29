//! CLI-only messages that `wol_core::i18n::Msg` does not cover. Same rule as `Msg`: one
//! exhaustive `match` per language, English texts ASCII-only (tested).

use wol_core::i18n::{Lang, Msg};
use wol_core::remote::{PowerAction, SHUTDOWN_FAILURES};
use wol_core::secret::SecretKind;

use crate::prompt::StdinSecretError;

/// A CLI message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Text<'a> {
    // ---- remote management (v0.2.0) ----
    /// Prefix of hint lines after an error.
    HintPrefix,
    /// Unknown SSH host key: how to trust it.
    TrustHint {
        /// Host argument.
        host: &'a str,
    },
    /// Changed SSH host key: how to replace it (after checking).
    ForgetHint {
        /// Host argument.
        host: &'a str,
    },
    /// A stored password was not used / is missing: how to store it (again).
    CredSetHint {
        /// Host argument.
        host: &'a str,
        /// Which secret.
        kind: SecretKind,
    },
    /// A stored password belongs to another connection (after `remote set`).
    SecretStale {
        /// Host label.
        label: &'a str,
        /// Secret kind.
        kind: SecretKind,
        /// What it was stored for (`""` = unknown).
        stored_for: &'a str,
    },
    /// `remote show` / `cred list`: stored, but for another connection.
    StoredForOther {
        /// What it was stored for (`""` = unknown).
        stored_for: &'a str,
    },
    /// `cred set` for a host whose id is not in config.toml yet, and the file cannot be written
    /// (read-only folder, newer version); a writable file gets its ids written instead.
    HostIdNotSaved {
        /// Host label.
        label: &'a str,
    },
    /// Marker of an approximate boot time.
    Approximate,
    /// A confirmation is needed but stdin is not a console.
    ConfirmNeedsYes,
    /// y/N question.
    ContinuePrompt,
    /// The user answered no.
    Declined,
    /// `boot-time` without hosts, and no host is managed.
    NoManagedHosts,
    /// `remote set --key-file` with a `.pub` file.
    KeyFileIsPublic {
        /// Path.
        path: &'a str,
    },
    /// `remote set --key-file` with a missing file.
    KeyFileMissing {
        /// Path.
        path: &'a str,
    },
    /// `remote set` without `--kind` on an unmanaged host.
    RemoteSetNeedsKind {
        /// Host label.
        label: &'a str,
    },
    /// SSH-only flags for a Windows host.
    SshOnlyFlags,
    /// Next step: trust the host key.
    NextTrust {
        /// Host argument.
        host: &'a str,
    },
    /// Next step: store the SSH password.
    NextCredSet {
        /// Host argument.
        host: &'a str,
    },
    /// Next step: store the Windows password (else the current sign-in is used).
    NextCredSetWindows {
        /// Host argument.
        host: &'a str,
        /// The current Windows sign-in ("" = unknown).
        account: &'a str,
    },
    /// Next step: store the password of the configured Windows account (required).
    NextCredSetAccount {
        /// The account.
        account: &'a str,
        /// Host argument.
        host: &'a str,
    },
    /// A host whose remote management a newer version configured.
    RemoteFromNewerVersion {
        /// Host label.
        label: &'a str,
    },
    /// `import`: matched hosts whose connection changed (passwords must be entered again).
    ImportRemoteChanged {
        /// Host names.
        names: &'a str,
    },
    /// `import`: the file had another SSH host key for the same server; the local one is kept.
    ImportHostKeysKept {
        /// Host names.
        names: &'a str,
    },
    /// `import`: re-pointed hosts whose SSH host key is not trusted for the new server.
    ImportHostKeysCleared {
        /// Host names.
        names: &'a str,
    },
    /// Next step: test the connection.
    NextTest {
        /// Host argument.
        host: &'a str,
    },
    /// Windows user when none is configured.
    DefaultWindowsUser,
    /// Windows user when none is configured: the account stored with the password.
    WindowsUserStored {
        /// The account.
        account: &'a str,
    },
    /// Windows user when none is configured and no password is stored: this PC's sign-in.
    WindowsUserSignIn {
        /// The account.
        account: &'a str,
    },
    /// Management address = the host's address.
    SameAsAddress {
        /// The address.
        address: &'a str,
    },
    /// No key file.
    PasswordLogin,
    /// No pinned host key.
    NotTrustedYet,
    /// A secret is stored.
    Stored,
    /// A secret is not stored.
    NotStored,
    /// Unknown (with the reason).
    Unknown {
        /// Why.
        reason: &'a str,
    },
    /// `remote clear` with nothing to clear.
    NothingToClear {
        /// Host label.
        label: &'a str,
    },
    /// `remote clear` question.
    RemoteClearConfirm {
        /// Host label.
        label: &'a str,
    },
    /// `remote clear` done.
    RemoteCleared {
        /// Host label.
        label: &'a str,
    },
    /// Stored passwords were deleted.
    SecretsDeleted {
        /// How many.
        count: usize,
    },
    /// Label: kernel.
    Kernel,
    /// Label: user.
    UserLabel,
    /// Label: boot time.
    BootedLabel,
    /// Label: uptime.
    UptimeLabel,
    /// Label: where the boot time came from.
    SourceLabel,
    /// Power question heading.
    PowerConfirmHeader {
        /// The action.
        action: PowerAction,
    },
    /// Power question: one host.
    PowerConfirmHost {
        /// Host label.
        label: &'a str,
        /// Management address.
        address: &'a str,
        /// Kind name.
        kind: &'a str,
    },
    /// Power question: Windows countdown.
    WindowsDelay {
        /// Seconds (0 = now).
        secs: u32,
    },
    /// Power question: Windows force option.
    WindowsForce {
        /// Close applications without asking.
        force: bool,
    },
    /// Power question: Windows message.
    WindowsMessage {
        /// The message.
        message: &'a str,
    },
    /// Power question: how SSH hosts do it.
    SshPowerNote,
    /// Power question: warning.
    UnsavedWorkWarning,
    /// Windows options given for an SSH host.
    SshIgnoresWindowsOptions {
        /// Host label.
        label: &'a str,
    },
    /// `shutdown --wait`: failed probes so far.
    VerifyNoAnswerCount {
        /// Host label.
        label: &'a str,
        /// Failed probes in a row.
        failures: u32,
    },
    /// `restart --wait`: the host is down.
    VerifyNoAnswer {
        /// Host label.
        label: &'a str,
    },
    /// `restart --wait`: the host answers, the new boot is not seen yet.
    VerifyUpOldBoot {
        /// Host label.
        label: &'a str,
    },
    /// `shutdown --wait`: the host still answers.
    VerifyStillUp {
        /// Host label.
        label: &'a str,
    },
    /// `shutdown --wait`: no answer, and the host was not seen answering yet (does not count).
    VerifyNotSeenYet {
        /// Host label.
        label: &'a str,
    },
    /// `--wait`: the first Ctrl+C (the verification stops; a second one quits at once).
    VerifyCancelling,
    /// `add --arp` for an address ARP cannot reach: how to register a VPN host.
    AddVpnHostSteps {
        /// Host argument.
        name: &'a str,
        /// The address as given.
        address: &'a str,
    },
    /// `edit --arp` of a host without remote management that ARP cannot reach.
    EditVpnHostSteps {
        /// Host argument.
        name: &'a str,
    },
    /// `mac --save` for an address.
    MacSaveNeedsHost,
    /// `mac --pick` beyond the list.
    MacPickOutOfRange {
        /// The number given.
        n: usize,
        /// Candidates.
        count: usize,
    },
    /// `mac --save` question.
    MacPickPrompt {
        /// Candidates.
        count: usize,
    },
    /// `mac --save` needs `--pick` (not a console); two or more candidates.
    MacPickNeeded {
        /// Candidates (at least 2).
        count: usize,
        /// Why the best one is not chosen (`None`: several fit equally well).
        caveat: Option<MacCaveat>,
    },
    /// `edit --arp`: several adapters, none chosen automatically.
    ArpSeveralAdapters {
        /// Candidates (at least 2).
        count: usize,
        /// Host argument.
        host: &'a str,
        /// Why the best one is not chosen (`None`: several fit equally well).
        caveat: Option<MacCaveat>,
    },
    /// `--password-stdin` input refused.
    StdinSecret {
        /// Why.
        error: StdinSecretError,
    },
    /// `cred set` without a console and without `--password-stdin`.
    PasswordNeedsConsole,
    /// Hidden password prompt.
    PasswordPrompt {
        /// Host label.
        label: &'a str,
        /// Secret kind.
        kind: SecretKind,
        /// The account it is stored for ("" = none, e.g. a key passphrase).
        account: &'a str,
    },
    /// `cred set` succeeded.
    CredSaved {
        /// Host label.
        label: &'a str,
        /// Secret kind.
        kind: SecretKind,
        /// The account it is stored for ("" = none).
        account: &'a str,
    },
    /// `cred set` for a Windows host without a remote user: the account used.
    CredDefaultAccount {
        /// This PC's sign-in account.
        account: &'a str,
        /// Host argument.
        host: &'a str,
    },
    /// `cred list`: stored for a host that has no remote management.
    StoredUnmanaged {
        /// Host argument.
        host: &'a str,
    },
    /// Second password prompt.
    PasswordAgain,
    /// The two entries differ.
    PasswordMismatch,
    /// `cred set --kind key-passphrase|sudo` for a Windows host.
    CredKindNeedsSsh {
        /// Host label.
        label: &'a str,
        /// Secret kind.
        kind: SecretKind,
    },
    /// `cred set --user` differs from the host's remote user.
    CredUserIgnored {
        /// The host's remote user.
        user: &'a str,
    },
    /// A sudo password that the sudo mode does not use.
    SudoSecretUnused {
        /// Mode name.
        mode: &'a str,
    },
    /// A key passphrase without key file.
    PassphraseUnused,
    /// `cred delete`: nothing stored for the host.
    NoSecretsFor {
        /// Host label.
        label: &'a str,
    },
    /// `cred list`: the host was removed.
    RemovedHost,
    /// `cred list`: empty.
    NoSecretsStored,
    /// `cred prune` without a settings file.
    PruneNoSettings {
        /// config.toml path.
        path: &'a str,
    },
    /// `cred prune`: nothing to delete.
    NothingToPrune,
    /// `cred prune` question.
    PruneConfirm {
        /// How many.
        count: usize,
    },
    /// `cred prune`: other settings folders share the passwords.
    PruneSharedNote,
    /// `ssh trust`: the key is pinned already.
    HostKeyAlreadyTrusted {
        /// Host label.
        label: &'a str,
    },
    /// `ssh trust`: the presented key.
    HostKeyShow {
        /// Host label.
        label: &'a str,
        /// Algorithm.
        algorithm: &'a str,
        /// `SHA256:...`.
        fingerprint: &'a str,
    },
    /// `ssh trust` without a console and without flags.
    TrustNeedsFlag,
    /// `ssh trust`: OpenSSH knows the key.
    HostKeyInKnownHosts,
    /// `ssh trust` question.
    TrustPrompt,
    /// A user action confirmed the use of the current Windows sign-in for a host (once).
    SignInConfirmed {
        /// Host label.
        label: &'a str,
        /// The account ("" = unknown).
        account: &'a str,
    },
    /// `SignInNotConfirmed` (automatic / all-hosts runs): how to confirm it.
    SignInConfirmHint {
        /// Host argument.
        host: &'a str,
    },
    /// Power question / `--yes` run: the host runs a custom command instead of the default.
    CustomPowerCommand {
        /// Host label.
        label: &'a str,
        /// The command.
        command: &'a str,
    },
    /// `import`: the file's power commands were not applied to existing hosts.
    ImportCommandsKept {
        /// Host names.
        names: &'a str,
    },
    /// `import`: added hosts bring custom power commands.
    ImportCommandsImported {
        /// Host names.
        names: &'a str,
    },
    /// `remote set --key-file` with a network (UNC) path: refused.
    KeyFileOnNetwork {
        /// Path.
        path: &'a str,
    },
    /// `remote set` on a host whose remote table a newer version wrote: question.
    RemoteSetReplacesNewer {
        /// Host label.
        label: &'a str,
    },
    /// `remote clear` of a host with a newer version's table: only the passwords go.
    RemoteClearSecretsOnly {
        /// Host label.
        label: &'a str,
    },
    /// `mac --save` / `edit --arp`: the only candidate is not chosen automatically.
    MacSingleNeedsPick {
        /// Adapter name.
        iface: &'a str,
        /// Why.
        caveat: MacCaveat,
        /// `edit --arp`: the host argument (`None` for `mac --save`).
        host: Option<&'a str>,
    },
    /// The chosen adapter may not wake the host.
    MacChosenCaveat {
        /// Adapter name.
        iface: &'a str,
        /// Why.
        caveat: MacCaveat,
    },

    // ---- v0.1 ----
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

/// Why a MAC candidate is not chosen automatically / may not wake the host (cross review m5,
/// m6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacCaveat {
    /// The host reported Wake-on-LAN as disabled on it.
    WolDisabled,
    /// A Wi-Fi adapter.
    Wifi,
    /// Not connected (link down).
    LinkDown,
    /// Not a physical adapter.
    NotPhysical,
}

impl MacCaveat {
    /// Japanese, to be followed by "ため".
    fn ja(self) -> &'static str {
        match self {
            MacCaveat::WolDisabled => "Wake-on-LAN が無効な",
            MacCaveat::Wifi => "Wi-Fi のアダプターの",
            MacCaveat::LinkDown => "未接続の",
            MacCaveat::NotPhysical => "物理アダプターではない",
        }
    }

    /// English clause.
    fn en(self) -> &'static str {
        match self {
            MacCaveat::WolDisabled => "Wake-on-LAN is disabled on it",
            MacCaveat::Wifi => "it is a Wi-Fi adapter",
            MacCaveat::LinkDown => "it is not connected",
            MacCaveat::NotPhysical => "it is not a physical adapter",
        }
    }
}

/// ` --kind sudo` etc. for a `wolm cred set` hint (nothing for the login password).
fn kind_flag(kind: SecretKind) -> String {
    match kind {
        SecretKind::Login => String::new(),
        k => format!(" --kind {}", k.as_str()),
    }
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
            HintPrefix => "ヒント:".to_owned(),
            TrustHint { host } => {
                format!("フィンガープリントを確かめて信頼するには: wolm ssh trust {host}")
            }
            ForgetHint { host } => format!(
                "鍵が変わった理由を確かめた場合に限り: wolm ssh forget {host} の後に wolm ssh trust {host}"
            ),
            CredSetHint { host, kind } => format!(
                "パスワードを保存し直すには: wolm cred set {host}{}",
                kind_flag(kind)
            ),
            SecretStale {
                label,
                kind,
                stored_for,
            } => {
                let name = Msg::SecretKindName(kind).text(Lang::Ja);
                let host = crate::exit::shell_arg(label);
                if stored_for.is_empty() {
                    format!(
                        "{label} の保存済みの{name}は、接続先が変わったため使われません。もう一度保存してください: wolm cred set {host}{}",
                        kind_flag(kind)
                    )
                } else {
                    format!(
                        "{label} の保存済みの{name}は {stored_for} 用のため、使われません。もう一度保存してください: wolm cred set {host}{}",
                        kind_flag(kind)
                    )
                }
            }
            StoredForOther { stored_for: "" } => {
                "保存済み（別の接続用のため使われません。wolm cred set で保存し直してください）"
                    .to_owned()
            }
            StoredForOther { stored_for } => format!(
                "保存済み（{stored_for} 用のため使われません。wolm cred set で保存し直してください）"
            ),
            HostIdNotSaved { label } => format!(
                "ホスト「{label}」の ID が config.toml に保存されておらず（手で編集した設定ファイル）、この設定ファイルには書き込めません（読み取り専用のフォルダー、または新しいバージョンで作成されたファイル）。パスワードはホストの ID に結び付けて保存するため、書き込める状態でこのホストを保存してから（または id を手で追加してから）、もう一度実行してください。"
            ),
            Approximate => "（概算）".to_owned(),
            ConfirmNeedsYes => "確認が必要ですが、標準入力がコンソールではないため確認できません。実行してよい場合は --yes を付けてください。".to_owned(),
            ContinuePrompt => "続行しますか? [y/N]: ".to_owned(),
            Declined => "中止しました（何も変更していません）".to_owned(),
            NoManagedHosts => {
                "リモート管理が設定されたホストがありません（wolm remote set で設定できます）"
                    .to_owned()
            }
            KeyFileIsPublic { path } => format!(
                "{path} は公開鍵のようです。秘密鍵（.pub の付かないファイル）を指定してください。"
            ),
            KeyFileMissing { path } => format!("鍵ファイル {path} が見つかりません。"),
            RemoteSetNeedsKind { label } => format!(
                "{label} にはまだリモート管理がありません。--kind windows か --kind ssh を指定してください。"
            ),
            SshOnlyFlags => "--port、--key-file、--sudo、--reboot-command、--shutdown-command は SSH のホスト（--kind ssh）用です。".to_owned(),
            NextTrust { host } => {
                format!("最初に SSH ホスト鍵を確かめて信頼してください: wolm ssh trust {host}")
            }
            NextCredSet { host } => {
                format!("パスワードでログインする場合は保存してください: wolm cred set {host}")
            }
            NextCredSetWindows { host, account } => {
                let who = if account.is_empty() {
                    String::new()
                } else {
                    format!("（{account}）")
                };
                format!(
                    "パスワードが保存されていないため、現在の Windows サインイン{who}で接続します。相手の PC の管理者アカウントを使うには、アカウントを設定してからパスワードを保存してください: wolm remote set {host} --user PC名\\ユーザー名（Microsoft アカウントはメール アドレス）、続けて wolm cred set {host}"
                )
            }
            NextCredSetAccount { account, host } => format!(
                "{account} のパスワードを保存してください（保存するまで接続できません）: wolm cred set {host}"
            ),
            RemoteFromNewerVersion { label } => format!(
                "{label} のリモート管理は新しいバージョンの WoL Manager で設定されたため、このバージョンでは使えません（設定はそのまま残ります）"
            ),
            ImportRemoteChanged { names } => format!(
                "接続先（種類・アドレス・ポート・ユーザー名）が変わったため、保存したパスワードをもう一度入力する必要があります（wolm cred set）: {names}"
            ),
            ImportHostKeysKept { names } => format!(
                "同じサーバーの別の SSH ホスト鍵がファイルにありましたが、信頼済みの鍵をそのまま使います: {names}"
            ),
            ImportHostKeysCleared { names } => format!(
                "接続先が変わったため、SSH ホスト鍵（ファイルの鍵も以前の鍵も）は信頼していません。次の接続でフィンガープリントを確かめてください（wolm ssh trust）: {names}"
            ),
            NextTest { host } => format!("接続を確かめるには: wolm remote test {host}"),
            DefaultWindowsUser => {
                "（パスワードと一緒に保存したアカウント、なければ現在の Windows サインイン）"
                    .to_owned()
            }
            WindowsUserStored { account } => {
                format!("{account}（パスワードと一緒に保存したアカウント）")
            }
            WindowsUserSignIn { account } => {
                format!("{account}（現在の Windows サインイン。パスワードは保存されていません）")
            }
            SameAsAddress { address } => format!("{address}（ホストのアドレス）"),
            PasswordLogin => "なし（パスワードでログイン）".to_owned(),
            NotTrustedYet => "未確認（wolm ssh trust で確かめて信頼します）".to_owned(),
            Stored => "保存済み".to_owned(),
            NotStored => "なし".to_owned(),
            Unknown { reason } => format!("不明（{reason}）"),
            NothingToClear { label } => {
                format!("{label} にはリモート管理も保存されたパスワードもありません")
            }
            RemoteClearConfirm { label } => format!(
                "{label} のリモート管理を解除し、保存されているパスワードと信頼済みの SSH ホスト鍵を削除します。"
            ),
            RemoteCleared { label } => format!("{label} のリモート管理を解除しました"),
            SecretsDeleted { count } => {
                format!("保存されていたパスワードを {count} 件削除しました")
            }
            Kernel => "カーネル".to_owned(),
            UserLabel => "ユーザー".to_owned(),
            BootedLabel => "起動時刻".to_owned(),
            UptimeLabel => "稼働時間".to_owned(),
            SourceLabel => "取得元".to_owned(),
            PowerConfirmHeader { action } => format!(
                "次のホストを{}します:",
                Msg::PowerActionName(action).text(Lang::Ja)
            ),
            PowerConfirmHost {
                label,
                address,
                kind,
            } => format!("  {label}（{address}、{kind}）"),
            WindowsDelay { secs: 0 } => "Windows: すぐに実行します（取り消せません）".to_owned(),
            WindowsDelay { secs } => format!(
                "Windows: {secs} 秒後に実行します（それまでは wolm abort で取り消せます）"
            ),
            WindowsForce { force: true } => {
                "Windows: 開いているアプリは保存の確認なしで閉じられます".to_owned()
            }
            WindowsForce { force: false } => {
                "Windows: アプリが保存を求めると、実行されないことがあります".to_owned()
            }
            WindowsMessage { message } => format!("Windows: 表示するメッセージ: {message}"),
            SshPowerNote => "SSH: 約 2 秒後に root 権限で実行します".to_owned(),
            UnsavedWorkWarning => "保存されていない作業は失われる可能性があります。".to_owned(),
            SshIgnoresWindowsOptions { label } => format!(
                "{label} は SSH で管理しているため、--delay、--now、--force、--no-force、--message は使われません"
            ),
            VerifyNoAnswerCount { label, failures } => {
                format!("{label}: 応答なし（{failures}/{SHUTDOWN_FAILURES}）")
            }
            VerifyNoAnswer { label } => format!("{label}: 応答なし（再起動中）"),
            VerifyUpOldBoot { label } => {
                format!("{label}: 応答あり（新しい起動を確認しています）")
            }
            VerifyStillUp { label } => format!("{label}: まだ応答しています"),
            VerifyNotSeenYet { label } => {
                format!("{label}: 応答なし（まだ一度も応答を確認できていません）")
            }
            VerifyCancelling => "Ctrl+C: 確認を中止しています（応答を待っている接続が終わるまで、最大 1 分ほどかかることがあります）。もう一度 Ctrl+C を押すと、すぐに終了します。".to_owned(),
            AddVpnHostSteps { name, address } => format!(
                "新しいホストの MAC アドレスを相手から取得するには、仮の MAC アドレスで登録してからリモート管理を設定し、MAC アドレスを取得して保存します: wolm add {name} --address {address} --mac 02-00-00-00-00-01、wolm remote set {name} --kind windows（または ssh）…、必要なら wolm cred set {name}、最後に wolm mac {name} --save"
            ),
            EditVpnHostSteps { name } => format!(
                "リモート管理を設定してから、もう一度実行してください: wolm remote set {name} --kind windows（または ssh）…、必要なら wolm cred set {name}"
            ),
            MacSaveNeedsHost => {
                "--save には登録済みのホストを指定してください（アドレスには保存できません）"
                    .to_owned()
            }
            MacPickOutOfRange { n, count } => format!("--pick {n}: 候補は {count} 個です"),
            MacPickPrompt { count } => format!("保存する番号（1-{count}、空欄で中止）: "),
            MacPickNeeded {
                count,
                caveat: None,
            } => format!(
                "候補が {count} 個あり、どれを使うか決められません。--pick N で選んでください。"
            ),
            MacPickNeeded {
                count,
                caveat: Some(c),
            } => format!(
                "候補が {count} 個ありますが、最も適したアダプターは、{}ため自動では選びません。--pick N で選んでください。",
                c.ja()
            ),
            ArpSeveralAdapters {
                count,
                host,
                caveat: None,
            } => format!(
                "ホストから {count} 個のネットワーク アダプターが見つかりました。wolm mac {host} で一覧を表示し、--save --pick N で選んでください。"
            ),
            ArpSeveralAdapters {
                count,
                host,
                caveat: Some(c),
            } => format!(
                "ホストから {count} 個のネットワーク アダプターが見つかりましたが、最も適したアダプターは、{}ため自動では選びません。wolm mac {host} で一覧を表示し、--save --pick N で選んでください。",
                c.ja()
            ),
            StdinSecret { error } => match error {
                StdinSecretError::TooLong => "標準入力が長すぎます（64 KiB まで）",
                StdinSecretError::NotText => "標準入力を UTF-8 のテキストとして読めません",
                StdinSecretError::Empty => "パスワードが空です",
                StdinSecretError::LineBreak => {
                    "パスワードに改行が含まれています（取り除かれるのは末尾の改行 1 つだけです）"
                }
                StdinSecretError::Io => "標準入力を読めません",
            }
            .to_owned(),
            PasswordNeedsConsole => "標準入力がコンソールではありません。パスワードは --password-stdin で標準入力から渡してください（コマンドの引数では渡せません）。".to_owned(),
            PasswordPrompt {
                label,
                kind,
                account: "",
            } => format!("{label} の{}: ", Msg::SecretKindName(kind).text(Lang::Ja)),
            PasswordPrompt {
                label,
                kind,
                account,
            } => format!(
                "{label} の{}（{account}）: ",
                Msg::SecretKindName(kind).text(Lang::Ja)
            ),
            CredSaved {
                label,
                kind,
                account: "",
            } => Msg::SecretSaved {
                label: label.to_owned(),
                kind,
            }
            .text(Lang::Ja),
            CredSaved {
                label,
                kind,
                account,
            } => format!(
                "{label} の{}を保存しました（アカウント: {account}）",
                Msg::SecretKindName(kind).text(Lang::Ja)
            ),
            CredDefaultAccount { account, host } => format!(
                "このホストのリモート管理にユーザー名がないため、この PC のサインイン アカウント（{account}）のパスワードとして保存します。相手の PC の別のアカウントを使う場合は、先に wolm remote set {host} --user PC名\\ユーザー名（Microsoft アカウントはメール アドレス）を実行するか、--user を指定してください。"
            ),
            StoredUnmanaged { host } => format!(
                "保存済み（このホストにはリモート管理が設定されていないため使われません。不要なら wolm cred delete {host}）"
            ),
            PasswordAgain => "もう一度入力してください: ".to_owned(),
            PasswordMismatch => "2 回の入力が一致しません。何も保存していません。".to_owned(),
            CredKindNeedsSsh { label, kind } => format!(
                "{}は SSH のホスト用です（{label} は Windows のホストです）",
                Msg::SecretKindName(kind).text(Lang::Ja)
            ),
            CredUserIgnored { user } => format!(
                "このホストのリモート管理のユーザー（{user}）が使われます。ここで指定したユーザー名はパスワードと一緒に保存されるだけです。"
            ),
            SudoSecretUnused { mode } => format!(
                "sudo 方式が「{mode}」のため、この sudo パスワードは使われません（wolm remote set HOST --sudo separate で使われます）。"
            ),
            PassphraseUnused => "鍵ファイルが設定されていないため、このパスフレーズは使われません（wolm remote set HOST --key-file PATH）。".to_owned(),
            NoSecretsFor { label } => format!("{label} のパスワードは保存されていません"),
            RemovedHost => "（削除されたホスト）".to_owned(),
            NoSecretsStored => "保存されているパスワードはありません".to_owned(),
            PruneNoSettings { path } => format!(
                "設定ファイルがありません（{path}）。ほかの設定フォルダーで使っているパスワードを消さないよう、中止しました。"
            ),
            NothingToPrune => "削除するパスワードはありません".to_owned(),
            PruneConfirm { count } => format!("上の {count} 件のパスワードを削除します。"),
            PruneSharedNote => "ポータブル版や --config-dir など、ほかの設定フォルダーだけにあるホストのパスワードも含まれます。".to_owned(),
            HostKeyAlreadyTrusted { label } => {
                format!("{label} のこのホスト鍵は既に信頼されています")
            }
            HostKeyShow {
                label,
                algorithm,
                fingerprint,
            } => format!("{label} のホスト鍵: {algorithm} {fingerprint}"),
            TrustNeedsFlag => "標準入力がコンソールではないため確認できません。確かめた値を --fingerprint SHA256:... で指定するか、--accept-new を付けてください。".to_owned(),
            HostKeyInKnownHosts => "この鍵は ~/.ssh/known_hosts にも登録されています。".to_owned(),
            TrustPrompt => "この鍵を信頼しますか? [y/N]: ".to_owned(),
            SignInConfirmed { label, account } => {
                let who = if account.is_empty() {
                    String::new()
                } else {
                    format!("（{account}）")
                };
                format!(
                    "{label}: パスワードが保存されていないため、現在の Windows サインイン{who}で接続します。このホストとアドレスへの使用を確認済みとして記録しました（アプリの起動時刻の自動取得でも使われます）。"
                )
            }
            SignInConfirmHint { host } => format!(
                "このホストに現在の Windows サインインを使ってよい場合は、ホストを指定して一度実行してください: wolm remote test {host}"
            ),
            CustomPowerCommand { label, command } => format!(
                "  {label}: 既定のコマンドの代わりに、設定されたコマンドを root 権限で実行します: {command}"
            ),
            ImportCommandsKept { names } => format!(
                "ファイルの再起動・シャットダウン用のコマンドは、既存のホストには適用していません（この PC の設定のまま。必要なら wolm remote set で設定してください）: {names}"
            ),
            ImportCommandsImported { names } => format!(
                "追加したホストに再起動・シャットダウン用の独自のコマンドが設定されています（root 権限で実行され、再起動・シャットダウンの確認のたびに表示されます。wolm remote show で確認してください）: {names}"
            ),
            KeyFileOnNetwork { path } => format!(
                "{path} はネットワーク上のパスです。鍵ファイルをネットワークから読むと、その PC に Windows の資格情報でログオンすることになるため使いません。この PC のフォルダーにコピーして指定してください。"
            ),
            RemoteSetReplacesNewer { label } => format!(
                "{label} のリモート管理は新しいバージョンの WoL Manager で設定されています。続けると、その設定はここで指定した設定に置き換えられます。"
            ),
            RemoteClearSecretsOnly { label } => format!(
                "{label} の保存されているパスワードを削除します。リモート管理の設定は新しいバージョンの WoL Manager のものなので、そのまま残ります。"
            ),
            MacSingleNeedsPick {
                iface,
                caveat,
                host: None,
            } => format!(
                "見つかったアダプターは {iface} だけですが、{}ため自動では選びません。使う場合は --pick 1 を付けてください。",
                caveat.ja()
            ),
            MacSingleNeedsPick {
                iface,
                caveat,
                host: Some(host),
            } => format!(
                "ホストから見つかったアダプターは {iface} だけですが、{}ため自動では選びません。wolm mac {host} で確かめてから、--save --pick 1 で保存してください。",
                caveat.ja()
            ),
            MacChosenCaveat { iface, caveat } => format!(
                "{iface} は、{}ため Wake-on-LAN で起動できないことがあります。",
                caveat.ja()
            ),
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
            HintPrefix => "hint:".to_owned(),
            TrustHint { host } => {
                format!("To check the fingerprint and trust the key: wolm ssh trust {host}")
            }
            ForgetHint { host } => format!(
                "Only after confirming why the key changed: wolm ssh forget {host}, then wolm ssh trust {host}"
            ),
            CredSetHint { host, kind } => format!(
                "To store the password again: wolm cred set {host}{}",
                kind_flag(kind)
            ),
            SecretStale {
                label,
                kind,
                stored_for,
            } => {
                let name = Msg::SecretKindName(kind).text(Lang::En);
                let host = crate::exit::shell_arg(label);
                if stored_for.is_empty() {
                    format!(
                        "The saved {name} of {label} is not used any more because the connection changed. Store it again: wolm cred set {host}{}",
                        kind_flag(kind)
                    )
                } else {
                    format!(
                        "The saved {name} of {label} is not used because it was saved for {stored_for}. Store it again: wolm cred set {host}{}",
                        kind_flag(kind)
                    )
                }
            }
            StoredForOther { stored_for: "" } => {
                "stored, but for another connection (not used; store it again with wolm cred set)"
                    .to_owned()
            }
            StoredForOther { stored_for } => format!(
                "stored for {stored_for} (not used; store it again with wolm cred set)"
            ),
            HostIdNotSaved { label } => format!(
                "The id of \"{label}\" is not saved in config.toml (a hand-edited settings file), and this file cannot be written (read-only folder, or created by a newer version). Passwords are stored under the host's id: save the host where the file can be written (or add an id to it by hand), then try again."
            ),
            Approximate => " (approx.)".to_owned(),
            ConfirmNeedsYes => {
                "This needs a confirmation, but stdin is not a console. Add --yes to go ahead."
                    .to_owned()
            }
            ContinuePrompt => "Continue? [y/N]: ".to_owned(),
            Declined => "Cancelled; nothing was changed.".to_owned(),
            NoManagedHosts => {
                "No host has remote management (set it up with wolm remote set)".to_owned()
            }
            KeyFileIsPublic { path } => format!(
                "{path} looks like a public key; use the private key (the file without .pub)."
            ),
            KeyFileMissing { path } => format!("The key file {path} does not exist."),
            RemoteSetNeedsKind { label } => format!(
                "{label} has no remote management yet; add --kind windows or --kind ssh."
            ),
            SshOnlyFlags => "--port, --key-file, --sudo, --reboot-command and --shutdown-command are for SSH hosts (--kind ssh).".to_owned(),
            NextTrust { host } => {
                format!("First check and trust the SSH host key: wolm ssh trust {host}")
            }
            NextCredSet { host } => {
                format!("To log in with a password, store it: wolm cred set {host}")
            }
            NextCredSetWindows { host, account } => {
                let who = if account.is_empty() {
                    String::new()
                } else {
                    format!(" ({account})")
                };
                format!(
                    "No password is stored, so the current Windows sign-in{who} is used. To use an administrator account of the target, set the account, then store its password: wolm remote set {host} --user PC\\user (a Microsoft account: its e-mail address), then wolm cred set {host}"
                )
            }
            NextCredSetAccount { account, host } => format!(
                "Store the password of {account} (nothing connects until then): wolm cred set {host}"
            ),
            RemoteFromNewerVersion { label } => format!(
                "The remote management of {label} was set up by a newer version of WoL Manager and cannot be used by this one (the settings are kept)"
            ),
            ImportRemoteChanged { names } => format!(
                "The connection (kind, address, port or user name) changed, so the saved passwords must be entered again (wolm cred set): {names}"
            ),
            ImportHostKeysKept { names } => format!(
                "The file had another SSH host key for the same server; the trusted key is kept: {names}"
            ),
            ImportHostKeysCleared { names } => format!(
                "The connection target changed, so no SSH host key (neither the file's nor the old one) is trusted for it; check the fingerprint on the next connection (wolm ssh trust): {names}"
            ),
            NextTest { host } => format!("To check the connection: wolm remote test {host}"),
            DefaultWindowsUser => {
                "(the account stored with the password, else the current Windows sign-in)"
                    .to_owned()
            }
            WindowsUserStored { account } => {
                format!("{account} (the account stored with the password)")
            }
            WindowsUserSignIn { account } => {
                format!("{account} (the current Windows sign-in; no password is stored)")
            }
            SameAsAddress { address } => format!("{address} (the host's address)"),
            PasswordLogin => "none (password login)".to_owned(),
            NotTrustedYet => "not trusted yet (check and trust it with wolm ssh trust)".to_owned(),
            Stored => "stored".to_owned(),
            NotStored => "not stored".to_owned(),
            Unknown { reason } => format!("unknown ({reason})"),
            NothingToClear { label } => {
                format!("{label} has neither remote management nor stored passwords")
            }
            RemoteClearConfirm { label } => format!(
                "This turns off the remote management of {label} and deletes its stored passwords and trusted SSH host key."
            ),
            RemoteCleared { label } => format!("Remote management of {label} is off"),
            SecretsDeleted { count } => format!("Deleted {count} stored password(s)"),
            Kernel => "Kernel".to_owned(),
            UserLabel => "User".to_owned(),
            BootedLabel => "Booted".to_owned(),
            UptimeLabel => "Uptime".to_owned(),
            SourceLabel => "Source".to_owned(),
            PowerConfirmHeader { action } => match action {
                PowerAction::Restart => "About to restart:",
                PowerAction::Shutdown => "About to shut down:",
            }
            .to_owned(),
            PowerConfirmHost {
                label,
                address,
                kind,
            } => format!("  {label} ({address}, {kind})"),
            WindowsDelay { secs: 0 } => "Windows: right away (cannot be cancelled)".to_owned(),
            WindowsDelay { secs } => {
                format!("Windows: in {secs} s (wolm abort cancels it until then)")
            }
            WindowsForce { force: true } => {
                "Windows: open applications are closed without asking to save".to_owned()
            }
            WindowsForce { force: false } => {
                "Windows: applications may ask to save, and then it may not happen".to_owned()
            }
            WindowsMessage { message } => format!("Windows: message: {message}"),
            SshPowerNote => "SSH: runs with root rights about 2 s later".to_owned(),
            UnsavedWorkWarning => "Unsaved work may be lost.".to_owned(),
            SshIgnoresWindowsOptions { label } => format!(
                "{label} is managed over SSH: --delay, --now, --force, --no-force and --message do not apply"
            ),
            VerifyNoAnswerCount { label, failures } => {
                format!("{label}: no answer ({failures}/{SHUTDOWN_FAILURES})")
            }
            VerifyNoAnswer { label } => format!("{label}: no answer (restarting)"),
            VerifyUpOldBoot { label } => format!("{label}: answering (checking for a new boot)"),
            VerifyStillUp { label } => format!("{label}: still answering"),
            VerifyNotSeenYet { label } => {
                format!("{label}: no answer (not seen answering yet)")
            }
            VerifyCancelling => "Ctrl+C: stopping the check (a connection that is still waiting for an answer can take up to about a minute). Press Ctrl+C again to quit at once.".to_owned(),
            AddVpnHostSteps { name, address } => format!(
                "To read a new host's MAC address from the host itself, register it with a placeholder MAC address, set up its remote management, then read and save the MAC address: wolm add {name} --address {address} --mac 02-00-00-00-00-01, wolm remote set {name} --kind windows (or ssh) ..., wolm cred set {name} if needed, and finally wolm mac {name} --save"
            ),
            EditVpnHostSteps { name } => format!(
                "Set up remote management, then run it again: wolm remote set {name} --kind windows (or ssh) ..., and wolm cred set {name} if needed"
            ),
            MacSaveNeedsHost => "--save needs a registered host, not an address".to_owned(),
            MacPickOutOfRange { n, count } => {
                format!("--pick {n}: there are {count} candidate(s)")
            }
            MacPickPrompt { count } => format!("Number to save (1-{count}, empty = cancel): "),
            MacPickNeeded {
                count,
                caveat: None,
            } => format!("{count} candidates fit equally well; choose one with --pick N."),
            MacPickNeeded {
                count,
                caveat: Some(c),
            } => format!(
                "There are {count} candidates, and the best one is not chosen automatically ({}); choose one with --pick N.",
                c.en()
            ),
            ArpSeveralAdapters {
                count,
                host,
                caveat: None,
            } => format!(
                "The host reported {count} network adapters that fit equally well. List them with wolm mac {host} and choose one with --save --pick N."
            ),
            ArpSeveralAdapters {
                count,
                host,
                caveat: Some(c),
            } => format!(
                "The host reported {count} network adapters, and the best one is not chosen automatically ({}). List them with wolm mac {host} and choose one with --save --pick N.",
                c.en()
            ),
            StdinSecret { error } => match error {
                StdinSecretError::TooLong => "stdin is too long (at most 64 KiB)",
                StdinSecretError::NotText => "stdin is not UTF-8 text",
                StdinSecretError::Empty => "The password is empty",
                StdinSecretError::LineBreak => {
                    "The password contains a line break (only one trailing line break is removed)"
                }
                StdinSecretError::Io => "Cannot read stdin",
            }
            .to_owned(),
            PasswordNeedsConsole => "stdin is not a console. Pass the password on stdin with --password-stdin (it is never accepted as an argument).".to_owned(),
            PasswordPrompt {
                label,
                kind,
                account: "",
            } => format!("{} for {label}: ", Msg::SecretKindName(kind).text(Lang::En)),
            PasswordPrompt {
                label,
                kind,
                account,
            } => format!(
                "{} of {account} for {label}: ",
                Msg::SecretKindName(kind).text(Lang::En)
            ),
            CredSaved {
                label,
                kind,
                account: "",
            } => Msg::SecretSaved {
                label: label.to_owned(),
                kind,
            }
            .text(Lang::En),
            CredSaved {
                label,
                kind,
                account,
            } => format!(
                "Saved the {} of {label} (account: {account})",
                Msg::SecretKindName(kind).text(Lang::En)
            ),
            CredDefaultAccount { account, host } => format!(
                "The host's remote management has no user name, so the password is stored for this PC's sign-in account ({account}). To use another account of the target, first run wolm remote set {host} --user PC\\user (a Microsoft account: its e-mail address), or give --user."
            ),
            StoredUnmanaged { host } => format!(
                "stored (not used: the host has no remote management; delete it with wolm cred delete {host} if you do not need it)"
            ),
            PasswordAgain => "Again, to confirm: ".to_owned(),
            PasswordMismatch => "The two entries differ; nothing was stored.".to_owned(),
            CredKindNeedsSsh { label, kind } => format!(
                "The {} is for SSH hosts ({label} is a Windows host)",
                Msg::SecretKindName(kind).text(Lang::En)
            ),
            CredUserIgnored { user } => format!(
                "The host's remote user ({user}) is used; the user name given here is only stored with the password."
            ),
            SudoSecretUnused { mode } => format!(
                "The sudo mode is \"{mode}\", so this sudo password is not used (it is with wolm remote set HOST --sudo separate)."
            ),
            PassphraseUnused => "No key file is set, so this passphrase is not used (wolm remote set HOST --key-file PATH).".to_owned(),
            NoSecretsFor { label } => format!("No passwords are stored for {label}"),
            RemovedHost => "(removed host)".to_owned(),
            NoSecretsStored => "No passwords are stored".to_owned(),
            PruneNoSettings { path } => format!(
                "There is no settings file ({path}). Stopped so that passwords used by other settings folders are not deleted."
            ),
            NothingToPrune => "No passwords to delete".to_owned(),
            PruneConfirm { count } => format!("This deletes the {count} password(s) above."),
            PruneSharedNote => "Passwords of hosts that only other settings folders have (portable copies, --config-dir) are included.".to_owned(),
            HostKeyAlreadyTrusted { label } => {
                format!("This host key of {label} is already trusted")
            }
            HostKeyShow {
                label,
                algorithm,
                fingerprint,
            } => format!("Host key of {label}: {algorithm} {fingerprint}"),
            TrustNeedsFlag => "stdin is not a console, so it cannot ask. Give the checked value with --fingerprint SHA256:..., or add --accept-new.".to_owned(),
            HostKeyInKnownHosts => "This key is also in ~/.ssh/known_hosts.".to_owned(),
            TrustPrompt => "Trust this key? [y/N]: ".to_owned(),
            SignInConfirmed { label, account } => {
                let who = if account.is_empty() {
                    String::new()
                } else {
                    format!(" ({account})")
                };
                format!(
                    "{label}: no password is saved, so it connects with your Windows sign-in{who}. Recorded as confirmed for this host and address (the app's automatic boot time may use it too)."
                )
            }
            SignInConfirmHint { host } => format!(
                "If this host may use your Windows sign-in, run a command that names it once: wolm remote test {host}"
            ),
            CustomPowerCommand { label, command } => format!(
                "  {label}: runs its custom command with root rights instead of the default: {command}"
            ),
            ImportCommandsKept { names } => format!(
                "The file's restart / shutdown commands were not applied to existing hosts (this PC's settings are kept; set them with wolm remote set if wanted): {names}"
            ),
            ImportCommandsImported { names } => format!(
                "Added hosts come with custom restart / shutdown commands (they run with root rights and are shown before every restart / shutdown; check them with wolm remote show): {names}"
            ),
            KeyFileOnNetwork { path } => format!(
                "{path} is a network path. Reading a key file from the network would log on to that computer with your Windows credentials, so it is not used. Copy the key to a folder on this PC."
            ),
            RemoteSetReplacesNewer { label } => format!(
                "The remote management of {label} was set up by a newer version of WoL Manager. Continuing replaces those settings with the ones given here."
            ),
            RemoteClearSecretsOnly { label } => format!(
                "This deletes the saved passwords of {label}. Its remote management settings come from a newer version of WoL Manager and are kept."
            ),
            MacSingleNeedsPick {
                iface,
                caveat,
                host: None,
            } => format!(
                "The only adapter found, {iface}, is not chosen automatically ({}). To use it anyway, add --pick 1.",
                caveat.en()
            ),
            MacSingleNeedsPick {
                iface,
                caveat,
                host: Some(host),
            } => format!(
                "The host reported only {iface}, which is not chosen automatically ({}). Check it with wolm mac {host}, then save it with --save --pick 1.",
                caveat.en()
            ),
            MacChosenCaveat { iface, caveat } => format!(
                "{iface}: {}, so Wake-on-LAN may not wake the host through it.",
                caveat.en()
            ),
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
            HintPrefix,
            TrustHint { host: "nas" },
            ForgetHint { host: "nas" },
            CredSetHint {
                host: "nas",
                kind: SecretKind::Login,
            },
            CredSetHint {
                host: "nas",
                kind: SecretKind::Sudo,
            },
            SecretStale {
                label: "nas",
                kind: SecretKind::Login,
                stored_for: "root@192.0.2.1:22 (SSH)",
            },
            SecretStale {
                label: "nas",
                kind: SecretKind::Sudo,
                stored_for: "",
            },
            StoredForOther { stored_for: "" },
            StoredForOther {
                stored_for: "root@192.0.2.1:22 (SSH)",
            },
            HostIdNotSaved { label: "nas" },
            Approximate,
            ConfirmNeedsYes,
            ContinuePrompt,
            Declined,
            NoManagedHosts,
            KeyFileIsPublic { path: "C:\\k.pub" },
            KeyFileMissing { path: "C:\\k" },
            RemoteSetNeedsKind { label: "PC" },
            SshOnlyFlags,
            NextTrust { host: "nas" },
            NextCredSet { host: "nas" },
            NextCredSetWindows {
                host: "pc",
                account: "",
            },
            NextCredSetWindows {
                host: "pc",
                account: "me",
            },
            NextTest { host: "pc" },
            NextCredSetAccount {
                account: "PC\\admin",
                host: "pc",
            },
            RemoteFromNewerVersion { label: "pc" },
            ImportRemoteChanged { names: "a, b" },
            ImportHostKeysKept { names: "a" },
            ImportHostKeysCleared { names: "a" },
            DefaultWindowsUser,
            WindowsUserStored { account: "admin" },
            WindowsUserSignIn { account: "me" },
            SameAsAddress { address: "1.2.3.4" },
            PasswordLogin,
            NotTrustedYet,
            Stored,
            NotStored,
            Unknown { reason: "x" },
            NothingToClear { label: "PC" },
            RemoteClearConfirm { label: "PC" },
            RemoteCleared { label: "PC" },
            SecretsDeleted { count: 2 },
            Kernel,
            UserLabel,
            BootedLabel,
            UptimeLabel,
            SourceLabel,
            PowerConfirmHeader {
                action: PowerAction::Restart,
            },
            PowerConfirmHeader {
                action: PowerAction::Shutdown,
            },
            PowerConfirmHost {
                label: "PC",
                address: "1.2.3.4",
                kind: "Windows",
            },
            WindowsDelay { secs: 0 },
            WindowsDelay { secs: 30 },
            WindowsForce { force: true },
            WindowsForce { force: false },
            WindowsMessage { message: "m" },
            SshPowerNote,
            UnsavedWorkWarning,
            SshIgnoresWindowsOptions { label: "nas" },
            VerifyNoAnswerCount {
                label: "PC",
                failures: 1,
            },
            VerifyNoAnswer { label: "PC" },
            VerifyUpOldBoot { label: "PC" },
            VerifyStillUp { label: "PC" },
            VerifyNotSeenYet { label: "PC" },
            VerifyCancelling,
            AddVpnHostSteps {
                name: "PC",
                address: "100.105.1.2",
            },
            EditVpnHostSteps { name: "PC" },
            MacSaveNeedsHost,
            MacPickOutOfRange { n: 3, count: 2 },
            MacPickPrompt { count: 2 },
            MacPickNeeded {
                count: 2,
                caveat: None,
            },
            MacPickNeeded {
                count: 2,
                caveat: Some(MacCaveat::Wifi),
            },
            ArpSeveralAdapters {
                count: 2,
                host: "PC",
                caveat: None,
            },
            ArpSeveralAdapters {
                count: 3,
                host: "PC",
                caveat: Some(MacCaveat::LinkDown),
            },
            SignInConfirmed {
                label: "PC",
                account: r"DESK\me",
            },
            SignInConfirmed {
                label: "PC",
                account: "",
            },
            SignInConfirmHint { host: "PC" },
            CustomPowerCommand {
                label: "NAS",
                command: "/sbin/reboot",
            },
            ImportCommandsKept { names: "a, b" },
            ImportCommandsImported { names: "c" },
            KeyFileOnNetwork {
                path: r"\\srv\k\id",
            },
            RemoteSetReplacesNewer { label: "BMC" },
            RemoteClearSecretsOnly { label: "BMC" },
            MacSingleNeedsPick {
                iface: "Wi-Fi",
                caveat: MacCaveat::Wifi,
                host: None,
            },
            MacSingleNeedsPick {
                iface: "eth0",
                caveat: MacCaveat::WolDisabled,
                host: Some("PC"),
            },
            MacChosenCaveat {
                iface: "eth1",
                caveat: MacCaveat::NotPhysical,
            },
            StdinSecret {
                error: StdinSecretError::TooLong,
            },
            StdinSecret {
                error: StdinSecretError::NotText,
            },
            StdinSecret {
                error: StdinSecretError::Empty,
            },
            StdinSecret {
                error: StdinSecretError::LineBreak,
            },
            StdinSecret {
                error: StdinSecretError::Io,
            },
            PasswordNeedsConsole,
            PasswordPrompt {
                label: "PC",
                kind: SecretKind::Login,
                account: "",
            },
            PasswordPrompt {
                label: "PC",
                kind: SecretKind::Login,
                account: r"PCdmin",
            },
            CredSaved {
                label: "PC",
                kind: SecretKind::Login,
                account: "",
            },
            CredSaved {
                label: "PC",
                kind: SecretKind::Login,
                account: "me",
            },
            CredDefaultAccount {
                account: "me",
                host: "PC",
            },
            StoredUnmanaged { host: "PC" },
            PasswordAgain,
            PasswordMismatch,
            CredKindNeedsSsh {
                label: "PC",
                kind: SecretKind::Sudo,
            },
            CredUserIgnored { user: "admin" },
            SudoSecretUnused { mode: "root" },
            PassphraseUnused,
            NoSecretsFor { label: "PC" },
            RemovedHost,
            NoSecretsStored,
            PruneNoSettings { path: "C:\\x" },
            NothingToPrune,
            PruneConfirm { count: 2 },
            PruneSharedNote,
            HostKeyAlreadyTrusted { label: "nas" },
            HostKeyShow {
                label: "nas",
                algorithm: "ssh-ed25519",
                fingerprint: "SHA256:x",
            },
            TrustNeedsFlag,
            HostKeyInKnownHosts,
            TrustPrompt,
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
