//! The message table. Each language is one exhaustive `match`.

use std::net::Ipv4Addr;

use serde::Serialize;

use super::Lang;
use crate::error::{Error, Field, FieldError, FieldIssue};
use crate::model::{ConfigIssue, ParseNote};
use crate::netif::{AddrNote, IfKind, Reason};
use crate::pathenv::{PathChange, Scope};
use crate::probe::{HostState, ProbeVia};
use crate::send::{PlanNote, SendKind, WakeOutcome};
use crate::store::{ConfigSource, LoadWarning, ReadOnlyReason};

/// Host status names used by the GUI (and CLI status output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusLabel {
    /// Not checked yet.
    Unknown,
    /// Probe in progress.
    Checking,
    /// Answered.
    Online,
    /// Did not answer.
    Offline,
    /// Magic packet sent, waiting for the host.
    Waking,
    /// Did not come up within the verification timeout.
    Timeout,
    /// No address or probe method `none`.
    NotMonitored,
}

/// Table column headers (CLI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Header {
    /// Status.
    Status,
    /// Name.
    Name,
    /// MAC.
    Mac,
    /// Address.
    Address,
    /// Group.
    Group,
    /// Notes.
    Notes,
    /// Id.
    Id,
    /// Port.
    Port,
    /// Interface.
    Interface,
    /// Adapter type.
    Kind,
    /// IPv4 addresses.
    Ipv4,
    /// Used or not.
    Used,
    /// Reason.
    Reason,
    /// Route.
    Via,
    /// Destination.
    Destination,
    /// Number sent.
    Sent,
    /// Result.
    Result,
    /// Round-trip time.
    Rtt,
    /// Setting key.
    Key,
    /// Setting value.
    Value,
    /// Adapter GUID.
    Guid,
    /// PATH scope.
    Scope,
    /// File path.
    Path,
    /// Settings source.
    Source,
}

/// A translatable runtime message.
#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    // ---- wake ----
    /// Every destination got the packet.
    WakeSent {
        /// Host label.
        label: String,
    },
    /// Some sends failed.
    WakePartial {
        /// Host label.
        label: String,
        /// Datagrams sent.
        sent: u32,
        /// Sends that failed.
        failed: u32,
    },
    /// Nothing could be sent.
    WakeFailed {
        /// Host label.
        label: String,
    },
    /// No interface / target to send to.
    WakeNoDestinations {
        /// Host label.
        label: String,
    },
    /// Summary of a batch wake (GUI toast).
    WakeBatch {
        /// Hosts.
        total: usize,
        /// Fully sent.
        ok: usize,
        /// Partially sent.
        partial: usize,
        /// Failed.
        failed: usize,
    },
    /// Reminder that sending is not waking.
    WakeNotGuaranteed,
    /// Waiting for the host (`--wait`).
    Waiting {
        /// Host label.
        label: String,
        /// Timeout in seconds.
        secs: u64,
    },
    /// The host answered after a wake.
    CameOnline {
        /// Host label.
        label: String,
    },
    /// The host did not answer in time.
    WakeTimeout {
        /// Host label.
        label: String,
        /// Timeout in seconds.
        secs: u64,
    },
    /// Waiting was cancelled.
    WaitCancelled,
    /// Default name of a duplicated host.
    CopyOf {
        /// Original name.
        name: String,
    },
    /// Outcome word.
    Outcome(WakeOutcome),
    /// Send kind word.
    SendKind(SendKind),
    /// "via `interface` (`addr`)".
    ViaInterface {
        /// Interface name.
        name: String,
        /// Source address.
        addr: Ipv4Addr,
    },
    /// "routed by the OS".
    ViaRouted,
    /// "routed by the OS (via `name`)": a routed send whose egress interface is known
    /// ([`crate::send::PlannedSend::interface`]).
    ViaRoutedThrough {
        /// Interface name.
        name: String,
    },
    /// A plan note.
    PlanNote(PlanNote),
    /// Dry-run heading for one host.
    DryRunHeader {
        /// Host label.
        label: String,
        /// MAC text.
        mac: String,
        /// Packet length.
        bytes: usize,
        /// Rounds.
        repeat: u8,
        /// Pause in ms.
        interval_ms: u64,
    },
    /// A target that could not be resolved.
    PlanFailure {
        /// Target.
        target: String,
        /// Error.
        error: String,
    },

    // ---- status ----
    /// Probe result.
    HostState(HostState),
    /// GUI status name.
    Status(StatusLabel),
    /// Probe method that answered.
    ProbeVia(ProbeVia),
    /// "N of M online".
    SummaryUp {
        /// Online hosts.
        up: usize,
        /// Checked hosts.
        total: usize,
    },

    // ---- PATH ----
    /// Result of add / remove.
    PathChange {
        /// What happened.
        change: PathChange,
        /// Folder.
        dir: String,
        /// Scope.
        scope: Scope,
    },
    /// Result of status.
    PathStatus {
        /// On PATH.
        present: bool,
        /// Folder.
        dir: String,
        /// Scope.
        scope: Scope,
    },
    /// Open a new terminal.
    PathOpenNewTerminal,
    /// Elevated process changing the user PATH.
    PathElevatedUserScope,
    /// Scope name.
    Scope(Scope),

    // ---- storage / config ----
    /// Storage mode name.
    LocationSource(ConfigSource),
    /// Marker ignored in an installed copy.
    MarkerIgnored {
        /// Marker path.
        marker: String,
    },
    /// Why the config is read-only.
    ReadOnly(ReadOnlyReason),
    /// A load warning.
    LoadWarning(LoadWarning),
    /// A validation issue.
    ConfigIssue(ConfigIssue),
    /// No validation problems.
    ConfigValid,
    /// Saved.
    ConfigSaved,
    /// Nothing changed.
    NoChanges,

    // ---- hosts ----
    /// Host added.
    HostAdded {
        /// Name.
        name: String,
    },
    /// Host updated.
    HostUpdated {
        /// Name.
        name: String,
    },
    /// Host removed.
    HostRemoved {
        /// Name.
        name: String,
    },
    /// Empty list.
    NoHosts,
    /// SecureOn shown as "set".
    SecureOnSet,
    /// "not set".
    NotSet,
    /// Field label.
    Field(Field),
    /// Field issue text.
    FieldIssue(FieldIssue),
    /// "label: issue".
    FieldError(FieldError),

    // ---- interfaces / ARP ----
    /// Interface verdict.
    IfReason(Reason),
    /// Adapter type.
    IfKind(IfKind),
    /// Address remark.
    AddrNote(AddrNote),
    /// ARP result.
    ArpFound {
        /// IP.
        ip: Ipv4Addr,
        /// MAC text.
        mac: String,
    },

    // ---- portable ----
    /// Enabled.
    PortableEnabled {
        /// Data folder.
        dir: String,
    },
    /// Disabled.
    PortableDisabled,
    /// Status: active.
    PortableActive {
        /// Data folder.
        dir: String,
    },
    /// Status: inactive.
    PortableInactive,
    /// Installed copy.
    PortableInstalled,
    /// Settings were copied.
    PortableCopied,
    /// Existing data kept.
    PortableKeptExisting,

    // ---- transfer ----
    /// Export done.
    Exported {
        /// Hosts written.
        count: usize,
        /// Destination.
        path: String,
    },
    /// Import counts.
    ImportSummary {
        /// Added.
        added: usize,
        /// Updated.
        updated: usize,
        /// Skipped.
        skipped: usize,
        /// Removed (replace mode).
        removed: usize,
    },
    /// Dry-run notice.
    ImportDryRun,

    // ---- listen ----
    /// Listening.
    Listening {
        /// Port.
        port: u16,
    },
    /// Packet received.
    PacketReceived {
        /// MAC text.
        mac: String,
        /// Sender.
        from: String,
        /// Length.
        len: usize,
    },

    // ---- misc ----
    /// Double-click pause.
    PressEnter,
    /// Shown when `wolm` is double-clicked.
    CliDoubleClickHint,
    /// GUI: another instance runs as a different user / elevated.
    AlreadyRunningElsewhere,
    /// Yes.
    Yes,
    /// No.
    No,
    /// Column header.
    Header(Header),
}

impl Msg {
    /// Text in `lang`.
    pub fn text(&self, lang: Lang) -> String {
        match lang {
            Lang::Ja => self.ja(),
            Lang::En => self.en(),
        }
    }

    fn ja(&self) -> String {
        use Msg::*;
        match self {
            WakeSent { label } => format!("{label} にマジックパケットを送信しました"),
            WakePartial {
                label,
                sent,
                failed,
            } => format!(
                "{label} にマジックパケットを送信しました（{sent} 件成功、{failed} 件失敗）"
            ),
            WakeFailed { label } => format!("{label} にマジックパケットを送信できませんでした"),
            WakeNoDestinations { label } => {
                format!("{label}: 送信に使えるネットワークや送信先がありません")
            }
            WakeBatch {
                total,
                ok,
                partial,
                failed,
            } => format!(
                "{total} 台に送信しました（成功 {ok}、一部失敗 {partial}、失敗 {failed}）"
            ),
            WakeNotGuaranteed => {
                "送信できても、相手が起動したとは限りません。".to_owned()
            }
            Waiting { label, secs } => {
                format!("{label} の起動を待っています（最大 {secs} 秒）…")
            }
            CameOnline { label } => format!("{label} がオンラインになりました"),
            WakeTimeout { label, secs } => {
                format!("{label} は {secs} 秒以内に応答しませんでした")
            }
            WaitCancelled => "待機を中止しました".to_owned(),
            CopyOf { name } => format!("{name} のコピー"),
            Outcome(o) => match o {
                WakeOutcome::Ok => "送信済み",
                WakeOutcome::Partial => "一部失敗",
                WakeOutcome::Failed => "失敗",
            }
            .to_owned(),
            SendKind(k) => match k {
                crate::send::SendKind::DirectedBroadcast => "サブネットのブロードキャスト",
                crate::send::SendKind::LimitedBroadcast => "ブロードキャスト (255.255.255.255)",
                crate::send::SendKind::Unicast => "ユニキャスト",
                crate::send::SendKind::Target => "指定した送信先",
            }
            .to_owned(),
            ViaInterface { name, addr } => format!("{name} ({addr}) 経由"),
            ViaRouted => "OS のルーティングに従う".to_owned(),
            ViaRoutedThrough { name } => format!("OS のルーティングに従う（{name} 経由）"),
            PlanNote(n) => match n {
                crate::send::PlanNote::NoInterfaces => {
                    "使えるネットワークインターフェースがありません".to_owned()
                }
                crate::send::PlanNote::NoDirectedBroadcast { interface, subnet } => format!(
                    "{interface} ({subnet}) はポイントツーポイントのため、サブネットのブロードキャストは送りません"
                ),
                crate::send::PlanNote::AddressOffSubnet { address } => format!(
                    "{address} はローカルのサブネット外のため、ユニキャストは送りません（送る場合は送信先に追加してください）"
                ),
                crate::send::PlanNote::AddressUnresolved { address, error } => {
                    format!("{address} の名前を解決できません: {error}")
                }
                crate::send::PlanNote::ViaVirtual { target, interface } => format!(
                    "{target} 宛ては VPN・仮想アダプター「{interface}」から送られる可能性があります"
                ),
                crate::send::PlanNote::NoDestinations => "送信先がありません".to_owned(),
            },
            DryRunHeader {
                label,
                mac,
                bytes,
                repeat,
                interval_ms,
            } => format!(
                "{label} ({mac}): {bytes} バイト × {repeat} 回（間隔 {interval_ms} ms）"
            ),
            PlanFailure { target, error } => {
                format!("送信先 {target} を解決できません: {error}")
            }
            HostState(s) => match s {
                crate::probe::HostState::Up { via, rtt, .. } => format!(
                    "オンライン（{}、{} ms）",
                    Msg::ProbeVia(*via).ja(),
                    rtt.as_millis()
                ),
                crate::probe::HostState::Down { .. } => "オフライン".to_owned(),
                crate::probe::HostState::Unresolved { name, .. } => {
                    format!("名前を解決できません（{name}）")
                }
                crate::probe::HostState::Unknown => "監視なし".to_owned(),
                crate::probe::HostState::Error { message } => {
                    format!("確認できません: {message}")
                }
            },
            Status(s) => match s {
                StatusLabel::Unknown => "未確認",
                StatusLabel::Checking => "確認中…",
                StatusLabel::Online => "オンライン",
                StatusLabel::Offline => "オフライン",
                StatusLabel::Waking => "起動中…",
                StatusLabel::Timeout => "応答なし",
                StatusLabel::NotMonitored => "監視なし",
            }
            .to_owned(),
            ProbeVia(v) => match v {
                crate::probe::ProbeVia::Icmp => "ping".to_owned(),
                crate::probe::ProbeVia::Tcp { port } => format!("TCP {port}"),
            },
            SummaryUp { up, total } => format!("オンライン {up} / {total} 台"),
            PathChange { change, dir, scope } => {
                let s = Msg::Scope(*scope).ja();
                match change {
                    crate::pathenv::PathChange::Added => {
                        format!("{s}の PATH に追加しました: {dir}")
                    }
                    crate::pathenv::PathChange::AlreadyPresent => {
                        format!("既に{s}の PATH にあります: {dir}")
                    }
                    crate::pathenv::PathChange::Removed => {
                        format!("{s}の PATH から削除しました: {dir}")
                    }
                    crate::pathenv::PathChange::NotPresent => {
                        format!("{s}の PATH にはありません: {dir}")
                    }
                }
            }
            PathStatus {
                present,
                dir,
                scope,
            } => {
                let s = Msg::Scope(*scope).ja();
                if *present {
                    format!("{s}の PATH に登録されています: {dir}")
                } else {
                    format!("{s}の PATH に登録されていません: {dir}")
                }
            }
            PathOpenNewTerminal => {
                "変更を反映するには、新しいターミナルを開いてください。".to_owned()
            }
            PathElevatedUserScope => {
                "管理者として実行中です。変更されるのは、この管理者アカウントのユーザー PATH です。"
                    .to_owned()
            }
            Scope(s) => match s {
                crate::pathenv::Scope::User => "ユーザー",
                crate::pathenv::Scope::Machine => "システム",
            }
            .to_owned(),
            LocationSource(s) => match s {
                ConfigSource::Flag | ConfigSource::Env => "カスタムの場所",
                ConfigSource::Portable => "ポータブル",
                ConfigSource::AppData => "標準 (AppData)",
            }
            .to_owned(),
            MarkerIgnored { marker } => format!(
                "インストール版のため、ポータブルマーカーを無視しました: {marker}"
            ),
            ReadOnly(r) => match r {
                ReadOnlyReason::NewerSchema { found, .. } => format!(
                    "新しいバージョンで作成された設定ファイル（schema {found}）のため、読み取り専用で開いています"
                ),
                ReadOnlyReason::NotWritable { dir } => format!(
                    "保存先 {} に書き込めないため、読み取り専用で開いています",
                    dir.display()
                ),
            },
            LoadWarning(w) => match w {
                crate::store::LoadWarning::Parse(ParseNote::AssignedIds { count }) => format!(
                    "{count} 台のホストに ID を割り当てました（次に保存するときに書き込みます）"
                ),
                crate::store::LoadWarning::Parse(ParseNote::DuplicateIdReplaced {
                    name, ..
                }) => format!("ホスト「{name}」の ID が重複していたため、新しい ID を割り当てました"),
                crate::store::LoadWarning::MarkerIgnored { marker } => {
                    Msg::MarkerIgnored {
                        marker: marker.display().to_string(),
                    }
                    .ja()
                }
                crate::store::LoadWarning::Issue(i) => Msg::ConfigIssue(i.clone()).ja(),
            },
            ConfigIssue(i) => match i {
                crate::model::ConfigIssue::Host {
                    name, field, issue, ..
                } => format!(
                    "ホスト「{name}」の{}: {}",
                    Msg::Field(*field).ja(),
                    Msg::FieldIssue(*issue).ja()
                ),
                crate::model::ConfigIssue::Setting {
                    key,
                    value,
                    expected,
                } => format!("設定 {key} = {value} は範囲外です（{expected}）"),
            },
            ConfigValid => "設定に問題はありません".to_owned(),
            ConfigSaved => "保存しました".to_owned(),
            NoChanges => "変更はありません".to_owned(),
            HostAdded { name } => format!("ホスト「{name}」を追加しました"),
            HostUpdated { name } => format!("ホスト「{name}」を更新しました"),
            HostRemoved { name } => format!(
                "ホスト「{name}」を削除しました（config.toml.bak から元に戻せます）"
            ),
            NoHosts => "ホストが登録されていません".to_owned(),
            SecureOnSet => "設定済み".to_owned(),
            NotSet => "未設定".to_owned(),
            Field(f) => match f {
                crate::error::Field::Name => "名前",
                crate::error::Field::Mac => "MAC アドレス",
                crate::error::Field::Address => "アドレス",
                crate::error::Field::Group => "グループ",
                crate::error::Field::Notes => "メモ",
                crate::error::Field::Port => "ポート",
                crate::error::Field::SecureOn => "SecureOn パスワード",
                crate::error::Field::Targets => "追加の送信先",
                crate::error::Field::Interfaces => "インターフェース",
                crate::error::Field::Probe => "状態確認の方法",
                crate::error::Field::TcpPorts => "TCP ポート",
            }
            .to_owned(),
            FieldIssue(i) => match i {
                crate::error::FieldIssue::Required => "入力してください",
                crate::error::FieldIssue::InvalidMac => {
                    "MAC アドレスの形式が正しくありません（例: 00:11:22:33:44:55）"
                }
                crate::error::FieldIssue::MacNotUnicast => {
                    "マルチキャスト・ブロードキャスト・すべて 0 の MAC アドレスは起動の対象にできません（1 バイト目は偶数です。例: 00:11:22:33:44:55）"
                }
                crate::error::FieldIssue::InvalidAddress => {
                    "IPv4 アドレスかホスト名を入力してください"
                }
                crate::error::FieldIssue::InvalidPort => {
                    "1〜65535 のポート番号を入力してください"
                }
                crate::error::FieldIssue::InvalidPortList => {
                    "ポート番号（1〜65535）をカンマ区切りで入力してください"
                }
                crate::error::FieldIssue::TooManyPorts => "ポートは 16 個までにしてください",
                crate::error::FieldIssue::InvalidSecureOn => {
                    "SecureOn パスワードは 6 バイトで入力してください（例: 01:23:45:67:89:AB）"
                }
                crate::error::FieldIssue::InvalidTarget => {
                    "送信先は「ホスト[:ポート]」の形式で入力してください"
                }
                crate::error::FieldIssue::DuplicateName => "同じ名前のホストが既にあります",
                crate::error::FieldIssue::NameLooksLikeMac => {
                    "MAC アドレスと区別できない名前は使えません"
                }
                crate::error::FieldIssue::NameTooLong => "名前は 64 文字以内にしてください",
                crate::error::FieldIssue::ImeKana => {
                    "日本語入力（IME）をオフにして入力してください"
                }
            }
            .to_owned(),
            FieldError(e) => format!(
                "{}: {}",
                Msg::Field(e.field).ja(),
                Msg::FieldIssue(e.issue).ja()
            ),
            IfReason(r) => match r {
                Reason::Auto => "使用（自動）",
                Reason::VirtualIncluded => "使用（仮想アダプターも使う設定）",
                Reason::Pinned => "使用（固定）",
                Reason::Down => "未使用: 接続されていません",
                Reason::Loopback => "未使用: ループバック",
                Reason::NoIpv4 => "未使用: IPv4 アドレスがありません",
                Reason::Virtual => {
                    "未使用: VPN・仮想アダプター（wake.include_virtual を有効にするか、固定すると使えます）"
                }
                Reason::UnsupportedType => "未使用: 対応していない種類です（固定すると使えます）",
                Reason::NotPinned => "未使用: 他のアダプターが固定されています",
                Reason::LinkLocalOnly => "未使用: 169.254.x.x のアドレスしかありません",
            }
            .to_owned(),
            IfKind(k) => match k {
                crate::netif::IfKind::Ethernet => "有線",
                crate::netif::IfKind::Wireless => "無線",
                crate::netif::IfKind::Loopback => "ループバック",
                crate::netif::IfKind::Tunnel => "トンネル",
                crate::netif::IfKind::Ppp => "PPP",
                crate::netif::IfKind::Virtual => "仮想",
                crate::netif::IfKind::Other => "その他",
            }
            .to_owned(),
            AddrNote(n) => match n {
                crate::netif::AddrNote::LinkLocalSkipped => "169.254.x.x のため使いません",
                crate::netif::AddrNote::NoDirectedBroadcast => {
                    "/31・/32 のためサブネットのブロードキャストなし"
                }
            }
            .to_owned(),
            ArpFound { ip, mac } => format!("{ip} の MAC アドレス: {mac}"),
            PortableEnabled { dir } => {
                format!("ポータブルモードを有効にしました。設定の保存先: {dir}")
            }
            PortableDisabled => {
                "ポータブルモードを無効にしました（data フォルダーは残っています）".to_owned()
            }
            PortableActive { dir } => format!("ポータブルモード: 有効（{dir}）"),
            PortableInactive => "ポータブルモード: 無効".to_owned(),
            PortableInstalled => {
                "インストール版のため、ポータブルモードは使えません".to_owned()
            }
            PortableCopied => "現在の設定をコピーしました".to_owned(),
            PortableKeptExisting => "data フォルダーにある設定をそのまま使います".to_owned(),
            Exported { count, path } => format!("{count} 台のホストを書き出しました: {path}"),
            ImportSummary {
                added,
                updated,
                skipped,
                removed,
            } => format!(
                "追加 {added} 台、更新 {updated} 台、スキップ {skipped} 件、削除 {removed} 台"
            ),
            ImportDryRun => "（確認のみです。まだ保存していません）".to_owned(),
            Listening { port } => {
                format!("UDP {port} 番ポートで待ち受けています（Ctrl+C で終了）")
            }
            PacketReceived { mac, from, len } => {
                format!("{from} から {mac} 宛てのマジックパケット（{len} バイト）")
            }
            PressEnter => "Enter キーを押すと閉じます".to_owned(),
            CliDoubleClickHint => "wolm はコマンドラインツールです。コマンドプロンプトか PowerShell で `wolm --help` を実行してください。".to_owned(),
            AlreadyRunningElsewhere => {
                "WoL Manager は別のユーザーまたは管理者として既に実行中です。".to_owned()
            }
            Yes => "はい".to_owned(),
            No => "いいえ".to_owned(),
            Header(h) => match h {
                super::Header::Status => "状態",
                super::Header::Name => "名前",
                super::Header::Mac => "MAC",
                super::Header::Address => "アドレス",
                super::Header::Group => "グループ",
                super::Header::Notes => "メモ",
                super::Header::Id => "ID",
                super::Header::Port => "ポート",
                super::Header::Interface => "インターフェース",
                super::Header::Kind => "種類",
                super::Header::Ipv4 => "IPv4",
                super::Header::Used => "使用",
                super::Header::Reason => "理由",
                super::Header::Via => "経路",
                super::Header::Destination => "送信先",
                super::Header::Sent => "送信数",
                super::Header::Result => "結果",
                super::Header::Rtt => "応答時間",
                super::Header::Key => "キー",
                super::Header::Value => "値",
                super::Header::Guid => "GUID",
                super::Header::Scope => "範囲",
                super::Header::Path => "パス",
                super::Header::Source => "保存モード",
            }
            .to_owned(),
        }
    }

    fn en(&self) -> String {
        use Msg::*;
        match self {
            WakeSent { label } => format!("Magic packet sent to {label}"),
            WakePartial {
                label,
                sent,
                failed,
            } => format!("Magic packet sent to {label} ({sent} sent, {failed} failed)"),
            WakeFailed { label } => format!("Could not send the magic packet to {label}"),
            WakeNoDestinations { label } => {
                format!("{label}: no usable network or target to send to")
            }
            WakeBatch {
                total,
                ok,
                partial,
                failed,
            } => format!("Sent to {total} hosts ({ok} ok, {partial} partial, {failed} failed)"),
            WakeNotGuaranteed => {
                "A sent packet does not guarantee that the computer wakes up.".to_owned()
            }
            Waiting { label, secs } => {
                format!("Waiting for {label} to come online (up to {secs} s)...")
            }
            CameOnline { label } => format!("{label} is online"),
            WakeTimeout { label, secs } => format!("{label} did not respond within {secs} s"),
            WaitCancelled => "Waiting cancelled".to_owned(),
            CopyOf { name } => format!("Copy of {name}"),
            Outcome(o) => match o {
                WakeOutcome::Ok => "sent",
                WakeOutcome::Partial => "partially sent",
                WakeOutcome::Failed => "failed",
            }
            .to_owned(),
            SendKind(k) => match k {
                crate::send::SendKind::DirectedBroadcast => "subnet broadcast",
                crate::send::SendKind::LimitedBroadcast => "broadcast (255.255.255.255)",
                crate::send::SendKind::Unicast => "unicast",
                crate::send::SendKind::Target => "explicit target",
            }
            .to_owned(),
            ViaInterface { name, addr } => format!("via {name} ({addr})"),
            ViaRouted => "routed by the OS".to_owned(),
            ViaRoutedThrough { name } => format!("routed by the OS (via {name})"),
            PlanNote(n) => match n {
                crate::send::PlanNote::NoInterfaces => "No usable network interface".to_owned(),
                crate::send::PlanNote::NoDirectedBroadcast { interface, subnet } => {
                    format!("{interface} ({subnet}) is point-to-point: no subnet broadcast is sent")
                }
                crate::send::PlanNote::AddressOffSubnet { address } => format!(
                    "{address} is not on a local subnet, so no unicast is sent (add it as a target to send it anyway)"
                ),
                crate::send::PlanNote::AddressUnresolved { address, error } => {
                    format!("Cannot resolve {address}: {error}")
                }
                crate::send::PlanNote::ViaVirtual { target, interface } => format!(
                    "{target} will probably be sent through the VPN / virtual adapter \"{interface}\""
                ),
                crate::send::PlanNote::NoDestinations => "Nothing to send to".to_owned(),
            },
            DryRunHeader {
                label,
                mac,
                bytes,
                repeat,
                interval_ms,
            } => format!("{label} ({mac}): {bytes} bytes x {repeat} (every {interval_ms} ms)"),
            PlanFailure { target, error } => format!("Cannot resolve target {target}: {error}"),
            HostState(s) => match s {
                crate::probe::HostState::Up { via, rtt, .. } => format!(
                    "online ({}, {} ms)",
                    Msg::ProbeVia(*via).en(),
                    rtt.as_millis()
                ),
                crate::probe::HostState::Down { .. } => "offline".to_owned(),
                crate::probe::HostState::Unresolved { name, .. } => {
                    format!("cannot resolve name ({name})")
                }
                crate::probe::HostState::Unknown => "not monitored".to_owned(),
                crate::probe::HostState::Error { message } => {
                    format!("cannot check: {message}")
                }
            },
            Status(s) => match s {
                StatusLabel::Unknown => "Unknown",
                StatusLabel::Checking => "Checking...",
                StatusLabel::Online => "Online",
                StatusLabel::Offline => "Offline",
                StatusLabel::Waking => "Waking...",
                StatusLabel::Timeout => "No response",
                StatusLabel::NotMonitored => "Not monitored",
            }
            .to_owned(),
            ProbeVia(v) => match v {
                crate::probe::ProbeVia::Icmp => "ping".to_owned(),
                crate::probe::ProbeVia::Tcp { port } => format!("TCP {port}"),
            },
            SummaryUp { up, total } => format!("{up} of {total} online"),
            PathChange { change, dir, scope } => {
                let s = Msg::Scope(*scope).en();
                match change {
                    crate::pathenv::PathChange::Added => format!("Added to the {s} PATH: {dir}"),
                    crate::pathenv::PathChange::AlreadyPresent => {
                        format!("Already on the {s} PATH: {dir}")
                    }
                    crate::pathenv::PathChange::Removed => {
                        format!("Removed from the {s} PATH: {dir}")
                    }
                    crate::pathenv::PathChange::NotPresent => {
                        format!("Not on the {s} PATH: {dir}")
                    }
                }
            }
            PathStatus {
                present,
                dir,
                scope,
            } => {
                let s = Msg::Scope(*scope).en();
                if *present {
                    format!("On the {s} PATH: {dir}")
                } else {
                    format!("Not on the {s} PATH: {dir}")
                }
            }
            PathOpenNewTerminal => "Open a new terminal to use the updated PATH.".to_owned(),
            PathElevatedUserScope => {
                "Running elevated: the user PATH of the elevated account is changed.".to_owned()
            }
            Scope(s) => match s {
                crate::pathenv::Scope::User => "user",
                crate::pathenv::Scope::Machine => "system",
            }
            .to_owned(),
            LocationSource(s) => match s {
                ConfigSource::Flag | ConfigSource::Env => "Custom location",
                ConfigSource::Portable => "Portable",
                ConfigSource::AppData => "Standard (AppData)",
            }
            .to_owned(),
            MarkerIgnored { marker } => {
                format!("Installed copy: the portable marker is ignored: {marker}")
            }
            ReadOnly(r) => match r {
                ReadOnlyReason::NewerSchema { found, .. } => format!(
                    "The settings file was written by a newer version (schema {found}) and is open read-only"
                ),
                ReadOnlyReason::NotWritable { dir } => format!(
                    "The settings folder {} is not writable; the settings are read-only",
                    dir.display()
                ),
            },
            LoadWarning(w) => match w {
                crate::store::LoadWarning::Parse(ParseNote::AssignedIds { count }) => {
                    format!("Assigned ids to {count} host(s); they are written at the next save")
                }
                crate::store::LoadWarning::Parse(ParseNote::DuplicateIdReplaced {
                    name, ..
                }) => format!("Host \"{name}\" had a duplicate id and got a new one"),
                crate::store::LoadWarning::MarkerIgnored { marker } => Msg::MarkerIgnored {
                    marker: marker.display().to_string(),
                }
                .en(),
                crate::store::LoadWarning::Issue(i) => Msg::ConfigIssue(i.clone()).en(),
            },
            ConfigIssue(i) => match i {
                crate::model::ConfigIssue::Host {
                    name, field, issue, ..
                } => format!(
                    "Host \"{name}\", {}: {}",
                    Msg::Field(*field).en(),
                    Msg::FieldIssue(*issue).en()
                ),
                crate::model::ConfigIssue::Setting {
                    key,
                    value,
                    expected,
                } => format!("Setting {key} = {value} is out of range ({expected})"),
            },
            ConfigValid => "The settings are valid".to_owned(),
            ConfigSaved => "Saved".to_owned(),
            NoChanges => "No changes".to_owned(),
            HostAdded { name } => format!("Added host \"{name}\""),
            HostUpdated { name } => format!("Updated host \"{name}\""),
            HostRemoved { name } => {
                format!("Removed host \"{name}\" (config.toml.bak has the previous version)")
            }
            NoHosts => "No hosts registered".to_owned(),
            SecureOnSet => "set".to_owned(),
            NotSet => "not set".to_owned(),
            Field(f) => match f {
                crate::error::Field::Name => "Name",
                crate::error::Field::Mac => "MAC address",
                crate::error::Field::Address => "Address",
                crate::error::Field::Group => "Group",
                crate::error::Field::Notes => "Notes",
                crate::error::Field::Port => "Port",
                crate::error::Field::SecureOn => "SecureOn password",
                crate::error::Field::Targets => "Additional targets",
                crate::error::Field::Interfaces => "Interfaces",
                crate::error::Field::Probe => "Status check",
                crate::error::Field::TcpPorts => "TCP ports",
            }
            .to_owned(),
            FieldIssue(i) => match i {
                crate::error::FieldIssue::Required => "Required",
                crate::error::FieldIssue::InvalidMac => {
                    "Not a valid MAC address (e.g. 00:11:22:33:44:55)"
                }
                crate::error::FieldIssue::MacNotUnicast => {
                    "Multicast, broadcast and all-zero MAC addresses cannot be woken (the first byte must be even, e.g. 00:11:22:33:44:55)"
                }
                crate::error::FieldIssue::InvalidAddress => "Enter an IPv4 address or a host name",
                crate::error::FieldIssue::InvalidPort => "Enter a port number from 1 to 65535",
                crate::error::FieldIssue::InvalidPortList => {
                    "Enter port numbers (1-65535) separated by commas"
                }
                crate::error::FieldIssue::TooManyPorts => "Enter at most 16 ports",
                crate::error::FieldIssue::InvalidSecureOn => {
                    "Enter a 6-byte SecureOn password (e.g. 01:23:45:67:89:AB)"
                }
                crate::error::FieldIssue::InvalidTarget => "Targets must look like host[:port]",
                crate::error::FieldIssue::DuplicateName => "A host with this name already exists",
                crate::error::FieldIssue::NameLooksLikeMac => {
                    "The name must not look like a MAC address"
                }
                crate::error::FieldIssue::NameTooLong => "Use at most 64 characters",
                crate::error::FieldIssue::ImeKana => {
                    "Turn off the Japanese input method (IME) and type again"
                }
            }
            .to_owned(),
            FieldError(e) => format!(
                "{}: {}",
                Msg::Field(e.field).en(),
                Msg::FieldIssue(e.issue).en()
            ),
            IfReason(r) => match r {
                Reason::Auto => "used (automatic)",
                Reason::VirtualIncluded => "used (virtual adapters included)",
                Reason::Pinned => "used (pinned)",
                Reason::Down => "not used: not connected",
                Reason::Loopback => "not used: loopback",
                Reason::NoIpv4 => "not used: no IPv4 address",
                Reason::Virtual => {
                    "not used: VPN / virtual adapter (enable wake.include_virtual or pin it)"
                }
                Reason::UnsupportedType => "not used: unsupported adapter type (pin it to use it)",
                Reason::NotPinned => "not used: other adapters are pinned",
                Reason::LinkLocalOnly => "not used: only a 169.254.x.x address",
            }
            .to_owned(),
            IfKind(k) => match k {
                crate::netif::IfKind::Ethernet => "Ethernet",
                crate::netif::IfKind::Wireless => "Wi-Fi",
                crate::netif::IfKind::Loopback => "Loopback",
                crate::netif::IfKind::Tunnel => "Tunnel",
                crate::netif::IfKind::Ppp => "PPP",
                crate::netif::IfKind::Virtual => "Virtual",
                crate::netif::IfKind::Other => "Other",
            }
            .to_owned(),
            AddrNote(n) => match n {
                crate::netif::AddrNote::LinkLocalSkipped => "link-local 169.254.x.x, not used",
                crate::netif::AddrNote::NoDirectedBroadcast => "/31 or /32: no subnet broadcast",
            }
            .to_owned(),
            ArpFound { ip, mac } => format!("MAC address of {ip}: {mac}"),
            PortableEnabled { dir } => {
                format!("Portable mode enabled. Settings are stored in {dir}")
            }
            PortableDisabled => "Portable mode disabled (the data folder is kept)".to_owned(),
            PortableActive { dir } => format!("Portable mode: on ({dir})"),
            PortableInactive => "Portable mode: off".to_owned(),
            PortableInstalled => {
                "This is an installed copy; portable mode is not available".to_owned()
            }
            PortableCopied => "Copied the current settings".to_owned(),
            PortableKeptExisting => "Keeping the settings already in the data folder".to_owned(),
            Exported { count, path } => format!("Exported {count} host(s) to {path}"),
            ImportSummary {
                added,
                updated,
                skipped,
                removed,
            } => format!("{added} added, {updated} updated, {skipped} skipped, {removed} removed"),
            ImportDryRun => "(dry run: nothing was saved)".to_owned(),
            Listening { port } => format!("Listening on UDP port {port} (Ctrl+C to stop)"),
            PacketReceived { mac, from, len } => {
                format!("Magic packet for {mac} from {from} ({len} bytes)")
            }
            PressEnter => "Press Enter to close".to_owned(),
            CliDoubleClickHint => {
                "wolm is a command-line tool. Run `wolm --help` in Command Prompt or PowerShell."
                    .to_owned()
            }
            AlreadyRunningElsewhere => {
                "WoL Manager is already running as another user or as administrator.".to_owned()
            }
            Yes => "yes".to_owned(),
            No => "no".to_owned(),
            Header(h) => match h {
                super::Header::Status => "STATUS",
                super::Header::Name => "NAME",
                super::Header::Mac => "MAC",
                super::Header::Address => "ADDRESS",
                super::Header::Group => "GROUP",
                super::Header::Notes => "NOTES",
                super::Header::Id => "ID",
                super::Header::Port => "PORT",
                super::Header::Interface => "INTERFACE",
                super::Header::Kind => "TYPE",
                super::Header::Ipv4 => "IPV4",
                super::Header::Used => "USED",
                super::Header::Reason => "REASON",
                super::Header::Via => "VIA",
                super::Header::Destination => "DESTINATION",
                super::Header::Sent => "SENT",
                super::Header::Result => "RESULT",
                super::Header::Rtt => "RTT",
                super::Header::Key => "KEY",
                super::Header::Value => "VALUE",
                super::Header::Guid => "GUID",
                super::Header::Scope => "SCOPE",
                super::Header::Path => "PATH",
                super::Header::Source => "MODE",
            }
            .to_owned(),
        }
    }
}

fn io_hint(hint: Option<&'static str>, lang: Lang) -> String {
    match (hint, lang) {
        (None, _) => String::new(),
        (Some(_), Lang::Ja) => {
            "（ウイルス対策ソフト、同期クライアント、コントロールされたフォルダー アクセスがファイルをロックしている可能性があります）"
                .to_owned()
        }
        (Some(h), Lang::En) => format!(" ({h})"),
    }
}

fn join_lines(lines: impl IntoIterator<Item = String>, lang: Lang) -> String {
    let sep = match lang {
        Lang::Ja => "、",
        Lang::En => "; ",
    };
    lines.into_iter().collect::<Vec<_>>().join(sep)
}

/// See [`super::describe_error`].
pub(super) fn describe_error(err: &Error, lang: Lang) -> String {
    let ja = lang == Lang::Ja;
    let t = |m: Msg| m.text(lang);
    match err {
        Error::InvalidFields(v) => join_lines(v.iter().map(|e| t(Msg::FieldError(*e))), lang),
        Error::InvalidValue {
            field,
            issue,
            input,
        } => {
            if ja {
                format!(
                    "{}「{input}」: {}",
                    t(Msg::Field(*field)),
                    t(Msg::FieldIssue(*issue))
                )
            } else {
                format!(
                    "{} \"{input}\": {}",
                    t(Msg::Field(*field)),
                    t(Msg::FieldIssue(*issue))
                )
            }
        }
        Error::UnknownSettingKey(k) => {
            if ja {
                format!("不明な設定キーです: {k}")
            } else {
                format!("Unknown setting key: {k}")
            }
        }
        Error::InvalidSetting {
            key,
            value,
            expected,
        } => {
            if ja {
                format!("{key} に「{value}」は設定できません（指定できる値: {expected}）")
            } else {
                format!("Invalid value \"{value}\" for {key} (expected {expected})")
            }
        }
        Error::Validation(issues) => {
            let list = join_lines(issues.iter().map(|i| t(Msg::ConfigIssue(i.clone()))), lang);
            if ja {
                format!("この変更は保存できません: {list}")
            } else {
                format!("The change cannot be saved: {list}")
            }
        }
        Error::HostNotFound(q) => {
            if ja {
                format!("ホストが見つかりません: {q}")
            } else {
                format!("Host not found: {q}")
            }
        }
        Error::HostIdNotFound(_) => {
            if ja {
                "編集中のホストは、他のプログラムで削除されました".to_owned()
            } else {
                "The host being edited was deleted by another program".to_owned()
            }
        }
        Error::GroupNotFound(g) => {
            if ja {
                format!("グループ「{g}」にホストがありません")
            } else {
                format!("No hosts in group \"{g}\"")
            }
        }
        Error::AmbiguousHost { query, candidates } => {
            let list = candidates.join(", ");
            if ja {
                format!("「{query}」に一致するホストが複数あります: {list}")
            } else {
                format!("\"{query}\" matches several hosts: {list}")
            }
        }
        Error::LockTimeout { path } => {
            if ja {
                format!(
                    "設定ファイルが他のプログラムで使用中です（5 秒待ちました）: {}",
                    path.display()
                )
            } else {
                format!(
                    "The settings are in use by another program (waited 5 s): {}",
                    path.display()
                )
            }
        }
        Error::WaitTimeout { label, secs } => t(Msg::WakeTimeout {
            label: label.clone(),
            secs: *secs,
        }),
        Error::ConfigParse {
            path,
            line,
            column,
            message,
        } => {
            let file = path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let pos = match (line, column, ja) {
                (Some(l), Some(c), true) => format!("{l} 行 {c} 列"),
                (Some(l), None, true) => format!("{l} 行"),
                (Some(l), Some(c), false) => format!("line {l}, column {c}"),
                (Some(l), None, false) => format!("line {l}"),
                (None, _, _) => String::new(),
            };
            let msg = message.trim();
            match (ja, pos.is_empty()) {
                (true, false) => format!("設定ファイルを読み込めません（{file} の {pos}）: {msg}"),
                (true, true) => format!("設定ファイルを読み込めません（{file}）: {msg}"),
                (false, false) => format!("Cannot read the settings file ({file}, {pos}): {msg}"),
                (false, true) => format!("Cannot read the settings file ({file}): {msg}"),
            }
        }
        Error::NewerSchema { found, supported } => {
            if ja {
                format!(
                    "この設定ファイルは新しいバージョン（schema {found}、対応は {supported} まで）で作成されたため、変更できません"
                )
            } else {
                format!(
                    "The settings file was written by a newer version (schema {found}, supported up to {supported}) and cannot be changed"
                )
            }
        }
        Error::PortableNotWritable { dir } => {
            if ja {
                format!("保存先に書き込めません: {}", dir.display())
            } else {
                format!("Cannot write to the settings folder: {}", dir.display())
            }
        }
        Error::ElevationRequired => {
            if ja {
                "管理者権限が必要です。管理者として実行してください。".to_owned()
            } else {
                "Administrator rights are required. Run as administrator.".to_owned()
            }
        }
        Error::PathTooLong { len, max } => {
            if ja {
                format!("PATH が長すぎます（{len} 文字、上限 {max} 文字）")
            } else {
                format!("PATH would be too long ({len} characters, maximum {max})")
            }
        }
        Error::InvalidPathEntry { dir, reason } => {
            if ja {
                format!("このフォルダーは PATH に追加できません: {dir}（{reason}）")
            } else {
                format!("This folder cannot be put on PATH: {dir} ({reason})")
            }
        }
        Error::NoDestinations => {
            if ja {
                "送信に使えるネットワークインターフェースや送信先がありません".to_owned()
            } else {
                "No usable network interface or target to send to".to_owned()
            }
        }
        Error::InstalledCopyRefusesPortable { root } => {
            if ja {
                format!(
                    "インストール版ではポータブルモードを使えません: {}",
                    root.display()
                )
            } else {
                format!(
                    "Portable mode is not available for an installed copy: {}",
                    root.display()
                )
            }
        }
        Error::NotOnLocalSubnet { ip } => {
            if ja {
                format!("{ip} はローカルのサブネット外のため、MAC アドレスを取得できません")
            } else {
                format!("{ip} is not on a local subnet; its MAC address cannot be looked up")
            }
        }
        Error::ArpNoReply { ip } => {
            if ja {
                format!("{ip} から ARP の応答がありません（電源とネットワークを確認してください）")
            } else {
                format!("No ARP reply from {ip} (check that it is powered on and connected)")
            }
        }
        Error::Resolve { name, message } => {
            if ja {
                format!("名前を解決できません: {name}（{message}）")
            } else {
                format!("Cannot resolve {name} ({message})")
            }
        }
        Error::Network { op, source } => {
            if ja {
                format!("ネットワークエラー（{op}）: {source}")
            } else {
                format!("Network error ({op}): {source}")
            }
        }
        Error::Io {
            op,
            path,
            source,
            hint,
        } => {
            let p = path
                .as_ref()
                .map(|p| format!(" {}", p.display()))
                .unwrap_or_default();
            if ja {
                format!(
                    "ファイル操作に失敗しました（{op}{p}）: {source}{}",
                    io_hint(*hint, lang)
                )
            } else {
                format!(
                    "File operation failed ({op}{p}): {source}{}",
                    io_hint(*hint, lang)
                )
            }
        }
        Error::Registry { op, source } => {
            if ja {
                format!("レジストリの操作に失敗しました（{op}）: {source}")
            } else {
                format!("Registry operation failed ({op}): {source}")
            }
        }
        Error::Import { location, message } => {
            let loc = location.clone().unwrap_or_default();
            match (ja, loc.is_empty()) {
                (true, false) => format!("インポートできません（{loc}）: {message}"),
                (true, true) => format!("インポートできません: {message}"),
                (false, false) => format!("Cannot import ({loc}): {message}"),
                (false, true) => format!("Cannot import: {message}"),
            }
        }
        Error::Serialize(m) => {
            if ja {
                format!("設定を書き出せません: {m}")
            } else {
                format!("Cannot serialize the settings: {m}")
            }
        }
        Error::NoConfigDir => {
            if ja {
                "AppData フォルダーを特定できません".to_owned()
            } else {
                "Cannot determine the AppData folder".to_owned()
            }
        }
        Error::Unsupported(m) => {
            if ja {
                format!("この操作は使えません: {m}")
            } else {
                format!("Not supported: {m}")
            }
        }
        Error::AppRunningWithOtherSettings { running, requested } => {
            if ja {
                format!(
                    "WoL Manager は {} の設定で既に実行中です。{} の設定で使うには、実行中の WoL Manager を終了（通知領域のアイコンのメニュー > 終了）してから、もう一度起動してください。",
                    running.display(),
                    requested.display()
                )
            } else {
                format!(
                    "WoL Manager is already running with the settings in {}. To use the settings in {}, exit the running WoL Manager first (notification area icon menu > Exit), then start it again.",
                    running.display(),
                    requested.display()
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::describe_error;

    fn every_msg() -> Vec<Msg> {
        use crate::netif::Ipv4Subnet;
        let subnet: Ipv4Subnet = "10.0.0.1/31".parse().unwrap();
        vec![
            Msg::WakeSent { label: "PC".into() },
            Msg::WakePartial {
                label: "PC".into(),
                sent: 3,
                failed: 1,
            },
            Msg::WakeFailed { label: "PC".into() },
            Msg::WakeNoDestinations { label: "PC".into() },
            Msg::WakeBatch {
                total: 3,
                ok: 1,
                partial: 1,
                failed: 1,
            },
            Msg::WakeNotGuaranteed,
            Msg::Waiting {
                label: "PC".into(),
                secs: 120,
            },
            Msg::CameOnline { label: "PC".into() },
            Msg::WakeTimeout {
                label: "PC".into(),
                secs: 120,
            },
            Msg::WaitCancelled,
            Msg::CopyOf { name: "PC".into() },
            Msg::Outcome(WakeOutcome::Partial),
            Msg::SendKind(SendKind::LimitedBroadcast),
            Msg::ViaInterface {
                name: "Ethernet".into(),
                addr: Ipv4Addr::LOCALHOST,
            },
            Msg::ViaRouted,
            Msg::ViaRoutedThrough {
                name: "Ethernet".into(),
            },
            Msg::PlanNote(PlanNote::NoDirectedBroadcast {
                interface: "x".into(),
                subnet,
            }),
            Msg::DryRunHeader {
                label: "PC".into(),
                mac: "00:11:22:33:44:55".into(),
                bytes: 102,
                repeat: 3,
                interval_ms: 100,
            },
            Msg::PlanFailure {
                target: "a".into(),
                error: "b".into(),
            },
            Msg::HostState(HostState::Up {
                via: ProbeVia::Tcp { port: 3389 },
                rtt: std::time::Duration::from_millis(3),
                ip: Ipv4Addr::LOCALHOST,
            }),
            Msg::Status(StatusLabel::Waking),
            Msg::ProbeVia(ProbeVia::Icmp),
            Msg::SummaryUp { up: 1, total: 2 },
            Msg::PathChange {
                change: PathChange::Added,
                dir: "C:\\x".into(),
                scope: Scope::User,
            },
            Msg::PathStatus {
                present: false,
                dir: "C:\\x".into(),
                scope: Scope::Machine,
            },
            Msg::PathOpenNewTerminal,
            Msg::PathElevatedUserScope,
            Msg::Scope(Scope::User),
            Msg::LocationSource(ConfigSource::Env),
            Msg::MarkerIgnored { marker: "m".into() },
            Msg::ReadOnly(ReadOnlyReason::NewerSchema {
                found: 2,
                supported: 1,
            }),
            Msg::LoadWarning(LoadWarning::Parse(ParseNote::AssignedIds { count: 2 })),
            Msg::ConfigIssue(ConfigIssue::Setting {
                key: "wake.repeat",
                value: "0".into(),
                expected: "1..=10",
            }),
            Msg::ConfigValid,
            Msg::ConfigSaved,
            Msg::NoChanges,
            Msg::HostAdded { name: "a".into() },
            Msg::HostUpdated { name: "a".into() },
            Msg::HostRemoved { name: "a".into() },
            Msg::NoHosts,
            Msg::SecureOnSet,
            Msg::NotSet,
            Msg::Field(Field::TcpPorts),
            Msg::FieldIssue(FieldIssue::ImeKana),
            Msg::FieldError(FieldError::new(Field::Mac, FieldIssue::InvalidMac)),
            Msg::FieldIssue(FieldIssue::MacNotUnicast),
            Msg::FieldIssue(FieldIssue::TooManyPorts),
            Msg::IfReason(Reason::Virtual),
            Msg::IfKind(IfKind::Virtual),
            Msg::AddrNote(AddrNote::LinkLocalSkipped),
            Msg::ArpFound {
                ip: Ipv4Addr::LOCALHOST,
                mac: "x".into(),
            },
            Msg::PortableEnabled { dir: "d".into() },
            Msg::PortableDisabled,
            Msg::PortableActive { dir: "d".into() },
            Msg::PortableInactive,
            Msg::PortableInstalled,
            Msg::PortableCopied,
            Msg::PortableKeptExisting,
            Msg::Exported {
                count: 1,
                path: "p".into(),
            },
            Msg::ImportSummary {
                added: 1,
                updated: 2,
                skipped: 3,
                removed: 0,
            },
            Msg::ImportDryRun,
            Msg::Listening { port: 9 },
            Msg::PacketReceived {
                mac: "m".into(),
                from: "f".into(),
                len: 102,
            },
            Msg::PressEnter,
            Msg::CliDoubleClickHint,
            Msg::AlreadyRunningElsewhere,
            Msg::Yes,
            Msg::No,
            Msg::Header(Header::Rtt),
        ]
    }

    #[test]
    fn every_message_has_both_languages() {
        for m in every_msg() {
            let ja = m.text(Lang::Ja);
            let en = m.text(Lang::En);
            assert!(!ja.is_empty() && !en.is_empty(), "{m:?}");
            assert!(en.is_ascii(), "English text must be ASCII: {en}");
        }
        assert_eq!(
            Msg::CopyOf { name: "PC".into() }.text(Lang::Ja),
            "PC のコピー"
        );
        assert_eq!(
            Msg::CopyOf { name: "PC".into() }.text(Lang::En),
            "Copy of PC"
        );
    }

    #[test]
    fn describes_errors() {
        let errors = vec![
            Error::InvalidFields(vec![
                FieldError::new(Field::Name, FieldIssue::Required),
                FieldError::new(Field::Mac, FieldIssue::InvalidMac),
            ]),
            Error::invalid(Field::Port, FieldIssue::InvalidPort, "0"),
            Error::HostNotFound("x".into()),
            Error::AmbiguousHost {
                query: "q".into(),
                candidates: vec!["a".into(), "b".into()],
            },
            Error::ConfigParse {
                path: Some("C:\\c.toml".into()),
                line: Some(3),
                column: Some(1),
                message: "bad".into(),
            },
            Error::ElevationRequired,
            Error::NoDestinations,
            Error::Io {
                op: "replace",
                path: None,
                source: std::io::Error::from_raw_os_error(5),
                hint: Some("hint"),
            },
            Error::AppRunningWithOtherSettings {
                running: "C:\\a".into(),
                requested: "D:\\b".into(),
            },
        ];
        for e in &errors {
            let ja = describe_error(e, Lang::Ja);
            let en = describe_error(e, Lang::En);
            assert!(!ja.is_empty() && !en.is_empty());
        }
        assert_eq!(
            describe_error(&errors[0], Lang::En),
            "Name: Required; MAC address: Not a valid MAC address (e.g. 00:11:22:33:44:55)"
        );
        assert!(describe_error(&errors[4], Lang::Ja).contains("3 行 1 列"));
    }
}
