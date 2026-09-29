//! User texts of remote-management errors ([`crate::i18n::describe_error`]).

use super::Lang;
use crate::error::{HostKeyProblem, SecretStoreFailure};
use crate::model::RemoteKind;
use crate::remote::{RemoteError, RemoteFailure, RemoteHint, RemoteOp, RemoteStage};

/// `ssh-keygen -lf /etc/ssh/ssh_host_<type>_key.pub` for an algorithm name.
pub(super) fn keygen_hint(algorithm: &str) -> String {
    let t = if algorithm.contains("ed25519") {
        "ed25519"
    } else if algorithm.contains("rsa") {
        "rsa"
    } else {
        "ecdsa"
    };
    format!("ssh-keygen -lf /etc/ssh/ssh_host_{t}_key.pub")
}

pub(super) fn kind_name(kind: RemoteKind, lang: Lang) -> &'static str {
    match (kind, lang) {
        (RemoteKind::Windows, _) => "Windows",
        (RemoteKind::Ssh, _) => "Linux (SSH)",
    }
}

fn op_failed(op: RemoteOp, lang: Lang) -> &'static str {
    match (op, lang) {
        (RemoteOp::BootTime, Lang::Ja) => "起動時刻を取得できませんでした",
        (RemoteOp::Restart, Lang::Ja) => "再起動を要求できませんでした",
        (RemoteOp::Shutdown, Lang::Ja) => "シャットダウンを要求できませんでした",
        (RemoteOp::AbortShutdown, Lang::Ja) => "シャットダウンを取り消せませんでした",
        (RemoteOp::MacCandidates, Lang::Ja) => "MAC アドレスを取得できませんでした",
        (RemoteOp::TestConnection, Lang::Ja) => "接続テストに失敗しました",
        (RemoteOp::ScanHostKey, Lang::Ja) => "ホスト鍵を取得できませんでした",
        (RemoteOp::HostKey, Lang::Ja) => "ホスト鍵を変更できませんでした",
        (RemoteOp::BootTime, Lang::En) => "Could not read the boot time",
        (RemoteOp::Restart, Lang::En) => "The restart request failed",
        (RemoteOp::Shutdown, Lang::En) => "The shutdown request failed",
        (RemoteOp::AbortShutdown, Lang::En) => "Could not cancel the shutdown",
        (RemoteOp::MacCandidates, Lang::En) => "Could not read the MAC addresses",
        (RemoteOp::TestConnection, Lang::En) => "The connection test failed",
        (RemoteOp::ScanHostKey, Lang::En) => "Could not read the host key",
        (RemoteOp::HostKey, Lang::En) => "Could not change the host key",
    }
}

pub(super) fn op_name(op: RemoteOp, lang: Lang) -> &'static str {
    match (op, lang) {
        (RemoteOp::BootTime, Lang::Ja) => "起動時刻の取得",
        (RemoteOp::Restart, Lang::Ja) => "再起動",
        (RemoteOp::Shutdown, Lang::Ja) => "シャットダウン",
        (RemoteOp::AbortShutdown, Lang::Ja) => "シャットダウンの取り消し",
        (RemoteOp::MacCandidates, Lang::Ja) => "MAC アドレスの取得",
        (RemoteOp::TestConnection, Lang::Ja) => "接続テスト",
        (RemoteOp::ScanHostKey, Lang::Ja) => "ホスト鍵の取得",
        (RemoteOp::HostKey, Lang::Ja) => "ホスト鍵の信頼",
        (RemoteOp::BootTime, Lang::En) => "reading the boot time",
        (RemoteOp::Restart, Lang::En) => "restart",
        (RemoteOp::Shutdown, Lang::En) => "shutdown",
        (RemoteOp::AbortShutdown, Lang::En) => "cancelling a shutdown",
        (RemoteOp::MacCandidates, Lang::En) => "reading the MAC addresses",
        (RemoteOp::TestConnection, Lang::En) => "the connection test",
        (RemoteOp::ScanHostKey, Lang::En) => "reading the host key",
        (RemoteOp::HostKey, Lang::En) => "trusting a host key",
    }
}

fn stage(s: RemoteStage, lang: Lang) -> &'static str {
    match (s, lang) {
        (RemoteStage::Resolve, Lang::Ja) => "名前解決",
        (RemoteStage::Connect, Lang::Ja) => "TCP 接続",
        (RemoteStage::Handshake, Lang::Ja) => "SSH のハンドシェイク",
        (RemoteStage::Authentication, Lang::Ja) => "SSH の認証",
        (RemoteStage::Command, Lang::Ja) => "リモート コマンドの実行",
        (RemoteStage::Resolve, Lang::En) => "name resolution",
        (RemoteStage::Connect, Lang::En) => "TCP connect",
        (RemoteStage::Handshake, Lang::En) => "SSH handshake",
        (RemoteStage::Authentication, Lang::En) => "SSH authentication",
        (RemoteStage::Command, Lang::En) => "remote command",
    }
}

/// The sentence for a failure (without host / operation).
pub(super) fn failure_text(e: &RemoteError, lang: Lang) -> String {
    use RemoteFailure as F;
    let ja = lang == Lang::Ja;
    let windows = e.backend == RemoteKind::Windows;
    match (&e.failure, ja) {
        (F::Unreachable, true) => {
            "接続できません。ホストの電源とネットワーク（VPN）を確認してください。".to_owned()
        }
        (F::Unreachable, false) => {
            "Cannot connect. Check that the host is on and reachable (VPN).".to_owned()
        }
        (F::Timeout { stage: s }, true) => {
            format!("応答がありません（{}でタイムアウト）。", stage(*s, lang))
        }
        (F::Timeout { stage: s }, false) => {
            format!("No response (timed out during {}).", stage(*s, lang))
        }
        (F::Disconnected, true) => "接続が切断されました。".to_owned(),
        (F::Disconnected, false) => "The connection was lost.".to_owned(),
        (F::AuthFailed { .. }, true) if windows => {
            "ユーザー名またはパスワードが正しくないか、アカウントを使用できません。".to_owned()
        }
        (F::AuthFailed { .. }, false) if windows => {
            "The user name or password is wrong, or the account cannot be used.".to_owned()
        }
        (F::AuthFailed { server_methods }, true) => {
            let m = if server_methods.is_empty() {
                String::new()
            } else {
                format!("（サーバーが受け付ける方式: {}）", server_methods.join(", "))
            };
            format!("SSH の認証に失敗しました。ユーザー名、パスワード、鍵ファイルを確認してください{m}。")
        }
        (F::AuthFailed { server_methods }, false) => {
            let m = if server_methods.is_empty() {
                String::new()
            } else {
                format!(" (the server accepts: {})", server_methods.join(", "))
            };
            format!("SSH authentication failed. Check the user name, password and key file{m}.")
        }
        (F::AccessDenied, true) => "アクセスが拒否されました。".to_owned(),
        (F::AccessDenied, false) => "Access denied.".to_owned(),
        (F::CredentialConflict, true) => format!(
            "この PC は既に別の資格情報で {} に接続しています（Windows エラー 1219）。エクスプローラーのウィンドウやネットワーク ドライブ（net use）の接続を閉じるか、ホストを別の名前・IP アドレスで登録してください。",
            e.address
        ),
        (F::CredentialConflict, false) => format!(
            "This PC is already connected to {} with other credentials (Windows error 1219). Close that connection (Explorer window, mapped drive, net use) or register the host under another name or IP address.",
            e.address
        ),
        (F::NoCredentials, true) => {
            "SSH の鍵ファイルもパスワードも設定されていません。どちらかを設定してください。"
                .to_owned()
        }
        (F::NoCredentials, false) => {
            "Neither an SSH key file nor a password is set. Set one of them.".to_owned()
        }
        (F::KeyFile { path }, true) => format!(
            "鍵ファイル {path} を使えません。秘密鍵のファイルを指定してください（.pub は公開鍵です）。"
        ),
        (F::KeyFile { path }, false) => format!(
            "The key file {path} cannot be used. Select the private key file (.pub is the public key)."
        ),
        (F::KeyPassphraseRequired { path }, true) => format!(
            "鍵ファイル {path} はパスフレーズで保護されています。鍵のパスフレーズを保存してください。"
        ),
        (F::KeyPassphraseRequired { path }, false) => format!(
            "The key file {path} is protected by a passphrase. Store the key passphrase."
        ),
        (F::KeyPassphraseWrong { path }, true) => format!(
            "鍵ファイル {path} のパスフレーズが違うか、対応していない形式です（`ssh-keygen -p -f` で OpenSSH 形式に変換できます）。"
        ),
        (F::KeyPassphraseWrong { path }, false) => format!(
            "Wrong passphrase for the key file {path}, or an unsupported key format (`ssh-keygen -p -f` converts it to the OpenSSH format)."
        ),
        (F::AuthPartial { methods }, true) => format!(
            "サーバーが追加の認証（{}）を求めています。2 段階認証には対応していません。",
            methods.join(", ")
        ),
        (F::AuthPartial { methods }, false) => format!(
            "The server requires additional authentication ({}). Two-factor authentication is not supported.",
            methods.join(", ")
        ),
        (F::AuthPromptUnsupported { prompt }, true) => format!(
            "サーバーがパスワード以外の入力（「{prompt}」）を求めました。ワンタイム コードなどには対応していません。"
        ),
        (F::AuthPromptUnsupported { prompt }, false) => format!(
            "The server asked for something other than a password (\"{prompt}\"). One-time codes are not supported."
        ),
        (F::NotRoot, true) => {
            "root 権限が必要です。root でログインするか、sudo の方式を変更してください。".to_owned()
        }
        (F::NotRoot, false) => {
            "Root rights are required. Log in as root or change the sudo mode.".to_owned()
        }
        (F::SudoPasswordRequired, true) => {
            "sudo にパスワードが必要です。sudo のパスワード（またはログイン パスワード）を保存するか、sudoers で NOPASSWD を設定してください。"
                .to_owned()
        }
        (F::SudoPasswordRequired, false) => {
            "sudo needs a password. Store the sudo (or login) password, or configure NOPASSWD in sudoers."
                .to_owned()
        }
        (F::SudoWrongPassword, true) => {
            "sudo がパスワードを受け付けませんでした（再試行はしていません）。保存したパスワードを確認してください。"
                .to_owned()
        }
        (F::SudoWrongPassword, false) => {
            "sudo rejected the password (not retried). Check the stored password.".to_owned()
        }
        (F::SudoNotAllowed, true) => {
            "このユーザーには sudo でコマンドを実行する権限がありません（sudoers を確認してください）。"
                .to_owned()
        }
        (F::SudoNotAllowed, false) => {
            "This user may not run the command with sudo (check sudoers).".to_owned()
        }
        (F::SudoNeedsTty, true) => {
            "sudoers に requiretty が設定されているため、sudo を使えません。".to_owned()
        }
        (F::SudoNeedsTty, false) => {
            "sudo cannot be used because sudoers sets requiretty.".to_owned()
        }
        (F::SudoMissing, true) => {
            "ホストに sudo がインストールされていません（Proxmox VE などでは root でログインしてください）。"
                .to_owned()
        }
        (F::SudoMissing, false) => {
            "sudo is not installed on the host (log in as root, e.g. on Proxmox VE).".to_owned()
        }
        (F::LocalTarget, true) => {
            "この PC 自身を再起動・シャットダウンすることはできません。".to_owned()
        }
        (F::LocalTarget, false) => "This PC itself cannot be restarted or shut down here.".to_owned(),
        (F::InvalidInput, true) => {
            "リモート管理の設定または入力に誤りがあります（アドレス、メッセージ、パスワードの改行など）。"
                .to_owned()
        }
        (F::InvalidInput, false) => {
            "The remote management settings or the input are invalid (address, message, a line break in a password...)."
                .to_owned()
        }
        (F::Unsupported, true) => "ホストがこの操作に対応していません。".to_owned(),
        (F::Unsupported, false) => "The host does not support this operation.".to_owned(),
        (F::ShutdownInProgress, true) => {
            "ホストでは既にシャットダウンまたは再起動が進行中です。".to_owned()
        }
        (F::ShutdownInProgress, false) => {
            "A shutdown or restart is already in progress on the host.".to_owned()
        }
        (F::NotReady, true) => {
            "ホストはまだ操作を受け付けられる状態ではありません（サインイン画面など）。".to_owned()
        }
        (F::NotReady, false) => {
            "The host is not ready yet (e.g. at the sign-in screen).".to_owned()
        }
        (F::UsersLoggedOn, true) => {
            "ほかのユーザーがサインインしています。アプリを強制的に終了する設定でやり直してください（GUI では「アプリを強制的に終了する」をオン、wolm では --no-force を付けない）。"
                .to_owned()
        }
        (F::UsersLoggedOn, false) => {
            "Other users are signed in. Try again with applications forced to close (GUI: turn on \"Force apps to close\"; wolm: without --no-force)."
                .to_owned()
        }
        (F::NoShutdownInProgress, true) => {
            "取り消せるシャットダウンや再起動はありません。".to_owned()
        }
        (F::NoShutdownInProgress, false) => {
            "There is no pending shutdown or restart to cancel.".to_owned()
        }
        (F::SecretStoreUnavailable, true) => {
            "このログオン セッション（SSH などのネットワーク ログオン）では Windows 資格情報マネージャーを使えないため、保存したパスワードを読めません。デスクトップにサインインして実行してください。"
                .to_owned()
        }
        (F::SecretStoreUnavailable, false) => {
            "Windows Credential Manager is not available in this logon session (e.g. an SSH / network logon), so the saved password cannot be read. Run it from a desktop session."
                .to_owned()
        }
        (F::SecretMismatch {
            secret,
            stored_for,
            expected_for,
        }, true) => {
            let name = super::Msg::SecretKindName(*secret).text(lang);
            let now = if expected_for.is_empty() {
                String::new()
            } else {
                format!("{expected_for} 用に")
            };
            if stored_for.is_empty() {
                format!(
                    "保存されている{name}には保存先の接続情報がないため（以前のバージョンで保存されたか、WoL Manager 以外で変更されています）、使用しませんでした。{now}もう一度入力してください。"
                )
            } else {
                format!(
                    "保存されている{name}は {stored_for} 用のため、使用しませんでした（接続先の種類・アドレス・ポートまたはユーザー名が変わっています）。{now}もう一度入力してください。"
                )
            }
        }
        (F::SecretMismatch {
            secret,
            stored_for,
            expected_for,
        }, false) => {
            let name = super::Msg::SecretKindName(*secret).text(lang);
            let now = if expected_for.is_empty() {
                String::new()
            } else {
                format!(" for {expected_for}")
            };
            if stored_for.is_empty() {
                format!(
                    "The saved {name} was not used because it does not record what it was saved for (saved by an older version or changed outside WoL Manager). Enter it again{now}."
                )
            } else {
                format!(
                    "The saved {name} was not used because it was saved for {stored_for} (the kind, address, port or user name changed). Enter it again{now}."
                )
            }
        }
        (F::PasswordRequired { account }, true) => format!(
            "{account} のパスワードが保存されていません。パスワードを保存するか、ユーザー名を空欄にして現在の Windows ユーザーで接続してください。"
        ),
        (F::PasswordRequired { account }, false) => format!(
            "No password is stored for {account}. Store the password, or leave the user name empty to connect as the current Windows user."
        ),
        (F::SignInNotConfirmed, true) => {
            "パスワードが保存されていないため、このホストには現在の Windows サインインで接続します。このホストとアドレスへのサインインの使用がこの PC でまだ確認されていないため（インポートで追加・変更されたホストなど）、自動では接続しませんでした（何も送信していません）。一度手動で操作するか（起動時刻の取得など）、ホストの設定を保存すると確認済みになります。"
                .to_owned()
        }
        (F::SignInNotConfirmed, false) => {
            "No password is saved, so this host would use your Windows sign-in, which has not been confirmed for this host and address on this PC yet (for example, an import added or changed the host). It was not contacted automatically; nothing was sent. Run an operation for it by hand once (such as getting the boot time), or save its settings, to confirm it."
                .to_owned()
        }
        (F::Local, true) => match &e.code {
            Some(c) => format!("この PC で内部エラーが発生しました（{c}）。"),
            None => "この PC で内部エラーが発生しました。".to_owned(),
        },
        (F::Local, false) => match &e.code {
            Some(c) => format!("An internal error occurred on this PC ({c})."),
            None => "An internal error occurred on this PC.".to_owned(),
        },
        (F::Protocol, true) => {
            "SSH の通信でエラーが発生しました（SSH サーバーではないか、共通の暗号方式がありません）。"
                .to_owned()
        }
        (F::Protocol, false) => {
            "SSH protocol error (not an SSH server, or no common algorithm).".to_owned()
        }
        (F::ExecRefused, true) => {
            "サーバーがコマンドの実行を拒否しました（制限付きのアカウントなど）。".to_owned()
        }
        (F::ExecRefused, false) => {
            "The server refused to run the command (restricted account?).".to_owned()
        }
        (F::CommandFailed {
            exit_status,
            stderr,
        }, true) => {
            let code = exit_status.map(|c| format!("終了コード {c}")).unwrap_or_else(|| "終了コード不明".to_owned());
            let err = stderr.trim();
            if err.is_empty() {
                format!("ホストでのコマンドの実行に失敗しました（{code}）。")
            } else {
                format!("ホストでのコマンドの実行に失敗しました（{code}）: {err}")
            }
        }
        (F::CommandFailed {
            exit_status,
            stderr,
        }, false) => {
            let code = exit_status.map(|c| format!("exit status {c}")).unwrap_or_else(|| "no exit status".to_owned());
            let err = stderr.trim();
            if err.is_empty() {
                format!("The command failed on the host ({code}).")
            } else {
                format!("The command failed on the host ({code}): {err}")
            }
        }
        (F::PowerUnconfirmed, true) => {
            "要求がホストで受け付けられたかどうかを確認できませんでした。実際に再起動・シャットダウンするかもしれないので、しばらく状態を確認してください（自動ではやり直しません）。"
                .to_owned()
        }
        (F::PowerUnconfirmed, false) => {
            "Could not confirm that the host accepted the request. It may still restart or shut down: watch its status for a while (the request is not repeated automatically)."
                .to_owned()
        }
        (F::UnexpectedOutput, true) => {
            "ホストから予期しない応答がありました（ログイン シェルが sh を実行できないアカウントの可能性があります）。"
                .to_owned()
        }
        (F::UnexpectedOutput, false) => {
            "The host answered unexpectedly (the account's login shell may not be able to run sh)."
                .to_owned()
        }
        (F::NoCandidates, true) => {
            "ホストに物理ネットワーク アダプターが見つかりませんでした。".to_owned()
        }
        (F::NoCandidates, false) => "No physical network adapter was found on the host.".to_owned(),
        (F::Other, true) => match &e.code {
            Some(c) => format!("エラーが発生しました（{c}）。"),
            None => "エラーが発生しました。".to_owned(),
        },
        (F::Other, false) => match &e.code {
            Some(c) => format!("An error occurred ({c})."),
            None => "An error occurred.".to_owned(),
        },
    }
}

/// The advice for a hint.
pub(super) fn hint_text(h: RemoteHint, lang: Lang) -> &'static str {
    match (h, lang) {
        (RemoteHint::UacRemoteRestriction, Lang::Ja) => {
            "Windows のローカル アカウント（Microsoft アカウントを含む）の管理者は、UAC のリモート制限（KB951016）により、ネットワーク経由では管理者として扱われません。ドメインの管理者アカウントか組み込みの Administrator を使うか、影響を理解したうえで相手の PC のレジストリ値 LocalAccountTokenFilterPolicy を 1 にしてください（詳しくは README）。"
        }
        (RemoteHint::UacRemoteRestriction, Lang::En) => {
            "Administrators that are local accounts (including Microsoft accounts) are not treated as administrators over the network because of UAC remote restrictions (KB951016). Use a domain administrator or the built-in Administrator, or, knowing the security impact, set LocalAccountTokenFilterPolicy to 1 on the target (see the README)."
        }
        (RemoteHint::SmbFirewall, Lang::Ja) => {
            "相手の PC のファイアウォールで「ファイルとプリンターの共有 (SMB 受信)」（TCP 445）がこの PC から（VPN 経由なら VPN のアドレス範囲からも）許可されているか確認してください。"
        }
        (RemoteHint::SmbFirewall, Lang::En) => {
            "Check that the target's firewall allows \"File and Printer Sharing (SMB-In)\" (TCP 445) from this PC (and from the VPN address range when connecting over a VPN)."
        }
        (RemoteHint::WmiFirewall, Lang::Ja) => {
            "MAC アドレスの取得には WMI を使います。相手の PC のファイアウォールで「Windows Management Instrumentation (WMI)」の受信規則を有効にしてください。"
        }
        (RemoteHint::WmiFirewall, Lang::En) => {
            "Reading the MAC address uses WMI. Enable the \"Windows Management Instrumentation (WMI)\" inbound rules in the target's firewall."
        }
        (RemoteHint::RemoteShutdownFirewall, Lang::Ja) => {
            "ファイル共有 (SMB) には接続できましたが、リモート シャットダウンの要求が届きません。相手の PC のファイアウォールで「リモート シャットダウン」または「リモート サービス管理」の受信規則を確認してください。"
        }
        (RemoteHint::RemoteShutdownFirewall, Lang::En) => {
            "File sharing (SMB) works but the remote shutdown request does not get through. Check the \"Remote Shutdown\" or \"Remote Service Management\" inbound rules in the target's firewall."
        }
        (RemoteHint::WmiAccessDenied, Lang::Ja) => {
            "ユーザー名とパスワードを確認してください。正しい場合は、UAC のリモート制限（KB951016）か DCOM / WMI の権限が原因です。"
        }
        (RemoteHint::WmiAccessDenied, Lang::En) => {
            "Check the user name and password. If they are right, UAC remote restrictions (KB951016) or DCOM / WMI permissions are the cause."
        }
        (RemoteHint::CheckCredentials, Lang::Ja) => {
            "ユーザー名とパスワードを確認してください。ローカル アカウントは「PC名\\ユーザー名」、ドメインは「ドメイン\\ユーザー名」、Microsoft アカウントはメール アドレスとアカウントのパスワード（PIN ではありません）です。"
        }
        (RemoteHint::CheckCredentials, Lang::En) => {
            "Check the user name and password: local accounts as PCNAME\\user, domain accounts as DOMAIN\\user, Microsoft accounts as the e-mail address with the account password (not the PIN)."
        }
        (RemoteHint::StoreCredentials, Lang::Ja) => {
            "現在の Windows ユーザーでは接続できません。このホストの管理者アカウントとパスワードを保存してください。"
        }
        (RemoteHint::StoreCredentials, Lang::En) => {
            "The current Windows user was not accepted. Store an administrator account and password for this host."
        }
        (RemoteHint::CloseOtherConnections, Lang::Ja) => {
            "同じホストへのほかの接続（エクスプローラー、ネットワーク ドライブ）を閉じてからやり直してください。"
        }
        (RemoteHint::CloseOtherConnections, Lang::En) => {
            "Close other connections to the same host (Explorer, mapped drives) and try again."
        }
        (RemoteHint::RetryLater, Lang::Ja) => "しばらくしてからやり直してください。",
        (RemoteHint::RetryLater, Lang::En) => "Try again later.",
        (RemoteHint::PasswordAuthDisabled, Lang::Ja) => {
            "このサーバーは公開鍵認証しか受け付けません。鍵ファイルを設定してください。"
        }
        (RemoteHint::PasswordAuthDisabled, Lang::En) => {
            "This server accepts public keys only. Set a key file."
        }
        (RemoteHint::SecretStoreUnavailable, Lang::Ja) => {
            "このログオン セッション（SSH などのネットワーク ログオン）では Windows 資格情報マネージャーを使えないため、保存したパスワードを使えませんでした。デスクトップにサインインして実行してください。"
        }
        (RemoteHint::SecretStoreUnavailable, Lang::En) => {
            "Saved passwords could not be used because Windows Credential Manager is not available in this logon session (e.g. an SSH / network logon). Run it from a desktop session."
        }
        (RemoteHint::StoredSecretNotUsed, Lang::Ja) => {
            "保存されているパスワードは別の接続先またはユーザー用のため、使用していません。必要ならもう一度入力してください。"
        }
        (RemoteHint::StoredSecretNotUsed, Lang::En) => {
            "A saved password was not used because it belongs to another address or user. Enter it again if it is needed."
        }
        (RemoteHint::CheckPort, Lang::Ja) => "ポート番号が SSH サーバーのものか確認してください。",
        (RemoteHint::CheckPort, Lang::En) => "Check that the port is the SSH server's port.",
    }
}

/// Full text of [`crate::Error::Remote`].
pub(super) fn describe_remote(e: &RemoteError, lang: Lang) -> String {
    let who = match lang {
        Lang::Ja => format!("{}（{}）", e.host, e.address),
        Lang::En => format!("{} ({})", e.host, e.address),
    };
    let standalone = matches!(
        e.failure,
        RemoteFailure::PowerUnconfirmed
            | RemoteFailure::NoShutdownInProgress
            | RemoteFailure::LocalTarget
    );
    // Hints that repeat the failure text.
    let redundant_hint = matches!(
        (&e.failure, e.hint),
        (
            RemoteFailure::SecretStoreUnavailable,
            Some(RemoteHint::SecretStoreUnavailable)
        )
    );
    let mut s = if standalone {
        format!("{who}: {}", failure_text(e, lang))
    } else {
        match lang {
            Lang::Ja => format!(
                "{who}: {}。{}",
                op_failed(e.op, lang),
                failure_text(e, lang)
            ),
            Lang::En => format!(
                "{who}: {}. {}",
                op_failed(e.op, lang),
                failure_text(e, lang)
            ),
        }
    };
    // The 1219 text already says how to fix it.
    let redundant = matches!(
        (&e.failure, e.hint),
        (
            RemoteFailure::CredentialConflict,
            Some(RemoteHint::CloseOtherConnections)
        )
    );
    if let Some(h) = e.hint.filter(|_| !redundant && !redundant_hint) {
        if lang == Lang::En {
            s.push(' ');
        }
        s.push_str(hint_text(h, lang));
    }
    s
}

/// Text of [`crate::Error::UnknownHostKey`].
pub(super) fn describe_unknown_key(p: &HostKeyProblem, lang: Lang) -> String {
    let hint = keygen_hint(&p.algorithm);
    let mut s = match lang {
        Lang::Ja => format!(
            "{}（{}）の SSH ホスト鍵はまだ信頼されていません。フィンガープリント: {}（{}）。相手のホストで `{hint}` を実行して一致することを確かめてから信頼してください。",
            p.host, p.address, p.fingerprint, p.algorithm
        ),
        Lang::En => format!(
            "The SSH host key of {} ({}) is not trusted yet. Fingerprint: {} ({}). Run `{hint}` on the host and trust the key only if it matches.",
            p.host, p.address, p.fingerprint, p.algorithm
        ),
    };
    if p.in_known_hosts {
        s.push_str(match lang {
            Lang::Ja => "この鍵は ~/.ssh/known_hosts にも登録されています。",
            Lang::En => " This key is also in ~/.ssh/known_hosts.",
        });
    }
    s
}

/// Text of [`crate::Error::HostKeyMismatch`].
pub(super) fn describe_mismatch(p: &HostKeyProblem, lang: Lang) -> String {
    let expected = p.expected_fingerprint.as_deref().unwrap_or("?");
    match (lang, p.fingerprint.is_empty()) {
        (Lang::Ja, false) => format!(
            "警告: {}（{}）の SSH ホスト鍵が、信頼済みの鍵と一致しません（信頼済み: {expected}、受信: {}）。なりすましの可能性があります。OS の再インストールなどで鍵が変わったことを確かめた場合に限り、ホスト鍵の信頼を解除してください。",
            p.host, p.address, p.fingerprint
        ),
        (Lang::Ja, true) => format!(
            "警告: {}（{}）が、信頼済みの種類（{}）のホスト鍵を提示しなくなりました（信頼済み: {expected}）。鍵が変わったことを確かめた場合に限り、ホスト鍵の信頼を解除してください。",
            p.host, p.address, p.algorithm
        ),
        (Lang::En, false) => format!(
            "WARNING: the SSH host key of {} ({}) does not match the trusted key (trusted: {expected}, received: {}). Someone may be impersonating the host. Forget the trusted key only after confirming that the key really changed (e.g. the OS was reinstalled).",
            p.host, p.address, p.fingerprint
        ),
        (Lang::En, true) => format!(
            "WARNING: {} ({}) no longer offers a host key of the trusted type {} (trusted: {expected}). Forget the trusted key only after confirming that the key really changed.",
            p.host, p.address, p.algorithm
        ),
    }
}

/// Text of [`crate::Error::SecretStore`].
pub(super) fn describe_secret_store(
    failure: SecretStoreFailure,
    detail: &str,
    lang: Lang,
) -> String {
    match (failure, lang) {
        (SecretStoreFailure::Unavailable, Lang::Ja) => {
            "このログオン セッション（SSH などのネットワーク ログオン）では Windows 資格情報マネージャーを使えません。デスクトップにサインインして実行してください。"
                .to_owned()
        }
        (SecretStoreFailure::Unavailable, Lang::En) => {
            "Windows Credential Manager is not available in this logon session (e.g. an SSH / network logon). Run it from a desktop session."
                .to_owned()
        }
        (SecretStoreFailure::TooLong, Lang::Ja) => format!(
            "パスワードまたはユーザー名が長すぎます（パスワードは {} 文字まで）。",
            crate::secret::MAX_SECRET_UNITS
        ),
        (SecretStoreFailure::TooLong, Lang::En) => format!(
            "The password or user name is too long (passwords: at most {} characters).",
            crate::secret::MAX_SECRET_UNITS
        ),
        (SecretStoreFailure::Other, Lang::Ja) => {
            format!("Windows 資格情報マネージャーの操作に失敗しました: {detail}")
        }
        (SecretStoreFailure::Other, Lang::En) => {
            format!("Windows Credential Manager failed: {detail}")
        }
    }
}
