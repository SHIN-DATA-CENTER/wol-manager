# WoL Manager

Windows 用の Wake-on-LAN ツールです。GUI（`wol-manager.exe`）とコマンドライン（`wolm`）の両方から、登録した PC をネットワーク経由で起動できます。

[![Made with Slint](https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-whitebg.png)](https://slint.dev)

*English summary is at the [end of this file](#english).*

## 特徴

- ホスト（MAC アドレス・IP アドレス・グループ・メモ）を登録して、ワンクリックで起動
- 起動後にオンラインになるまで自動で確認（Ping / TCP）し、状態を一覧に表示
- **複数の NIC や VPN があっても確実に届く送信方式**: 使用するネットワークアダプターごとにソケットを bind して、そのサブネットのブロードキャストと 255.255.255.255 に送ります。VPN（WireGuard など）の方が優先される環境でも、LAN 側から送信されます
- IP アドレスから MAC アドレスを自動取得（ARP）
- SecureOn パスワード、送信先・ポート・使用アダプターの個別指定
- 通知領域（タスクトレイ）への格納、日本語 / 英語、ライト / ダークテーマ
- コマンドライン `wolm`: PATH に登録してスクリプトやタスク スケジューラから利用可能
- 設定はユーザーごとに `%APPDATA%\wol-manager\config.toml` に保存（GUI と CLI で共有）
- インストーラー版（「自分のみ」/「すべてのユーザー」を選択）とポータブル版（ZIP）

## ダウンロードとインストール

[Releases](https://github.com/SHIN-DATA-CENTER/wol-manager/releases) から次のいずれかを入手してください。

| ファイル | 内容 |
|---|---|
| `wol-manager-<バージョン>-setup-x64.exe` | インストーラー |
| `wol-manager-<バージョン>-x86_64-pc-windows-msvc.zip` | ポータブル版 |
| `*.sha256` / `SHA256SUMS.txt` | ハッシュ値（`Get-FileHash` や `certutil -hashfile <file> SHA256` で確認） |

動作環境: Windows 10 / 11（x64）

### インストーラー

実行するとインストールの範囲を選べます。

- **自分のみ**（既定）: `%LOCALAPPDATA%\Programs\WoL Manager` にインストール。管理者権限は不要で、`wolm` はユーザーの PATH に追加されます。
- **すべてのユーザー**: `C:\Program Files\WoL Manager` にインストール。開始時に一度だけ UAC の確認が表示され、`wolm` はシステムの PATH に追加されます。

「wolm コマンドを PATH に追加」を選ぶと `bin\` フォルダーだけが PATH に入ります。**PATH の変更は新しく開いたターミナルから有効**になります。

サイレントインストールも可能です。

```text
wol-manager-0.1.0-setup-x64.exe /S /CurrentUser
wol-manager-0.1.0-setup-x64.exe /S /AllUsers /NoPath /DesktopShortcut /D=C:\Program Files\WoL Manager
```

| スイッチ | 意味 |
|---|---|
| `/S` | サイレント |
| `/CurrentUser` / `/AllUsers` | インストール範囲 |
| `/NoPath` | PATH に追加しない |
| `/DesktopShortcut` | デスクトップにショートカットを作成 |
| `/AllowOutsideProgramFiles` | 「すべてのユーザー」で Program Files 以外のフォルダーにインストールする場合に必要（サイレント時） |
| `/D=<フォルダー>` | インストール先（最後に、引用符なしで指定） |

「すべてのユーザー」を Program Files 以外（例: `C:\` 直下に作ったフォルダー）にインストールすると、そのフォルダーとその中のファイルを変更できるのは管理者だけになるようにアクセス許可を設定します。そのままでは管理者権限のないユーザーでもプログラムを書き換えられ、管理者が実行したとき（アンインストールや PATH 経由の `wolm`）に悪用されるためです。ウィザードでは確認が表示され、サイレントでは `/AllowOutsideProgramFiles` がないと終了コード 2 で中止します。

終了コード: 0 成功 / 1 キャンセル / 2 失敗 / 3 WoL Manager が実行中・ファイル使用中 / 4 別の範囲にインストール済み / 5 UAC が拒否された

アンインストールは「設定 > アプリ」から行えます。**設定（ホスト一覧）は既定で残ります**。「自分のみ」の場合はアンインストーラーの「設定も削除する」（サイレントでは `/PURGE`）で削除できます。

### ポータブル版（ZIP）

任意のフォルダーに展開して `wol-manager.exe` を実行します（例: `%LOCALAPPDATA%\Programs\wol-manager`）。設定は既定ではインストーラー版と同じ `%APPDATA%\wol-manager` に保存されます。複数の人が使う PC では、`C:\Tools` のように `C:\` 直下に作ったフォルダーは避けてください。そこにあるファイルはすべてのユーザーが変更できます（`wolm portable enable` と `wolm path add` はその場合に警告し、`wolm path add --scope machine` は `--force` なしでは追加しません）。

USB メモリなどで持ち運ぶ場合は、**`wol-manager.exe` と同じフォルダーに空のファイル `wol-manager.portable` を置く**と、設定がそのフォルダーの `data\` に保存されるようになります（GUI の「設定 > 保存場所とコマンドライン」や `wolm portable enable` でも切り替えられます）。WoL Manager の起動中にマーカーを置いたり消したりした場合（`wolm portable enable|disable` を含む）も、数秒以内に新しい保存先へ切り替わります。インストール版ではこのマーカーは無視されます。

ポータブル版の `wolm` を PATH に登録するには:

```text
bin\wolm.exe path add --scope user
```

フォルダーを削除する前に `bin\wolm.exe path remove --scope user` を実行してください。

## 使い方（GUI）

- 「ホストを追加」で名前と MAC アドレスを登録します。IP アドレスを入力して「IP から取得」を押すと、同じネットワーク上の機器なら MAC アドレスを自動で取得できます。
- 「起動」ボタンでマジックパケットを送信します。状態が「起動中」→「オンライン」に変わるまで自動で確認します。
- 検索（Ctrl+F）とグループで絞り込めます。右クリックメニューから編集・複製・コピー・削除ができます。
- 「設定」で言語・テーマ・通知領域の動作・状態確認の間隔・送信回数などを変更できます。
- ヘルプ > WoL Manager について: バージョン、ライセンス、クレジット

起動オプション: `--config-dir <フォルダー>`（設定の保存先を指定）、`--tray`（通知領域に格納した状態で起動）、`--safe-mode`（ソフトウェア描画で起動）

WoL Manager は同時に 1 つしか起動しません。もう一度起動すると、実行中のウィンドウが表示されます。ただし実行中のものと別の保存先（`--config-dir`、環境変数 `WOL_MANAGER_CONFIG_DIR`、別のポータブル版）を指定した場合は、その旨を表示して終了します（`wolm gui` は終了コード 7）。先に通知領域のアイコンから「終了」してください。

## コマンドライン（wolm）

```text
wolm wake NAS                     # 登録ホストを起動（名前・ID・MAC で指定）
wolm wake NAS --wait              # 起動するまで待つ（タイムアウトは exit 4）
wolm wake --group Lab             # グループ全体を起動
wolm wake AA-BB-CC-DD-EE-FF --to 10.0.20.255   # 未登録の MAC を送信先指定で起動
wolm wake NAS --dry-run           # 送信経路（どの NIC / VPN か）とパケットを確認するだけ
wolm status                       # 全ホストの状態（ダウンがあれば exit 1）
wolm list / wolm show NAS         # 一覧・詳細（SecureOn は「設定済み」とだけ表示）
wolm add NAS --mac 00:11:22:33:44:55 --address 192.168.1.10 --group Home
wolm add NAS --address 192.168.1.10 --arp      # MAC を ARP で取得して登録
wolm edit NAS --group Lab --clear-notes        # 指定した項目だけ変更
wolm rm NAS                       # 削除（config.toml.bak から戻せます）
wolm interfaces                   # NIC ごとの使用・不使用と理由
wolm export -o hosts.csv / wolm import hosts.csv   # CSV は Shift_JIS も読めます
wolm config get / wolm config set wake.repeat 5 / wolm config open
wolm path add --scope user        # bin フォルダーをユーザー PATH に追加（新しいターミナルで有効）
wolm portable enable --copy-settings           # ZIP 版をポータブル化
wolm completions | Out-String | Invoke-Expression   # PowerShell の補完
wolm listen --port 40009          # 届いたマジックパケットを表示（検証用）
wolm gui                          # GUI を起動
```

共通オプション: `--config-dir`、`--lang auto|ja|en`、`--json`（ASCII のみの JSON を 1 つ出力）、`-q`、`--no-color`、`-v`

| 終了コード | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 否定的な結果（変更なし、ダウンしているホストがある など） |
| 2 | 使い方・入力の誤り |
| 3 | 見つからない |
| 4 | `--wait` のタイムアウト |
| 5 | ネットワークエラー |
| 6 | 設定・ファイル・レジストリのエラー |
| 7 | 権限不足・書き込めない |
| 10 | 内部エラー（Ctrl+C で中断した場合は 130） |

PowerShell 5.1 でパイプ先に日本語を渡す場合は、`--json` を使うか `[Console]::OutputEncoding = [Text.Encoding]::UTF8` を設定してください。

## 設定ファイル

保存先は次の順で決まります。

1. `--config-dir <フォルダー>`
2. 環境変数 `WOL_MANAGER_CONFIG_DIR`
3. ポータブルマーカー（`wol-manager.portable`）があれば `<exe のフォルダー>\data\`
4. `%APPDATA%\wol-manager\`（ウィンドウ位置とログは `%LOCALAPPDATA%\wol-manager\`）

`config.toml` は GUI・CLI・テキストエディターのどれで編集してもかまいません（`wolm config open`）。保存の直前に `config.toml.bak` が作られます。

## ネットワークについての注意

- Wake-on-LAN は通常、**同じネットワーク（サブネット）内**でのみ届きます。ルーターは別サブネット宛てのブロードキャストをほとんど転送しません。
- Wi-Fi 接続の PC は多くの場合 WoL に対応していません。BIOS/UEFI と NIC の設定で WoL を有効にしてください。
- Windows は既定で Ping（ICMP）に応答しないことが多いため、状態確認は「自動（Ping → TCP）」を推奨します（TCP の既定ポート: 3389, 445, 22）。
- `wolm interfaces` で、どのネットワークアダプターから送信するかを確認できます。VPN・仮想アダプターは既定で使いません（設定で変更可能）。

## トラブルシューティング

- **「Windows によって PC が保護されました」と表示される**: 配布ファイルはコード署名されていません。発行元とハッシュ値を確認のうえ「詳細情報 > 実行」を選んでください。ZIP 版は展開前にプロパティで「ブロックの解除」を行ってください。Windows 11 の「スマート アプリ コントロール」が有効な場合は、署名のないプログラムとして実行がブロックされることがあります。
- **`wolm` が見つからない**: PATH の変更は新しく開いたターミナルにだけ反映されます。
- **画面が表示されない・真っ白になる**（仮想マシンやリモートデスクトップなど）: `wol-manager.exe --safe-mode` で起動するか、「設定 > 詳細」で描画方式を「ソフトウェア」にしてください。
- **起動しない**: `wolm wake <host> --dry-run` で送信経路を確認してください。ログは `%LOCALAPPDATA%\wol-manager\logs\gui.log` にあります。

## ソースからのビルド

必要なもの: Rust 1.98.1（`rust-toolchain.toml` で固定）、Visual Studio 2022 Build Tools（MSVC + Windows SDK）、NSIS 3.12 以降（インストーラーを作る場合）、[cargo-about](https://github.com/EmbarkStudios/cargo-about) 0.9.2（`cargo install cargo-about --locked --version 0.9.2 --features cli`）

```powershell
# 1. アイコン（coolicons v4.1）を取得する。リポジトリには含まれていません（下記「ライセンス」参照）
powershell -ExecutionPolicy Bypass -File scripts\fetch-coolicons.ps1

# 2. ビルドとテスト
cargo build --workspace
cargo test --workspace

# 3. 配布物（インストーラー・ZIP・ハッシュ）を dist\ に作成
powershell -ExecutionPolicy Bypass -File scripts\build.ps1

# 開発用: 本物の AppData と PATH を使わずに起動（設定は .cache\dev-config、PATH の変更は .cache\dev-path.json）
powershell -ExecutionPolicy Bypass -File scripts\dev-run.ps1
powershell -ExecutionPolicy Bypass -File scripts\dev-run.ps1 -Cli list
```

アイコンは `COOLICONS_DIR`（既定は `coolicons.v4.1\`）からビルド時にだけ読み込まれ、実行ファイルに埋め込まれます。開発の詳しい決まりは [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## ライセンスとクレジット

- WoL Manager のソースコード: [Apache License 2.0](LICENSE)
- アイコン: [coolicons](https://coolicons.cool/) v4.1 by Kryston Schwarze — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)（[GitHub](https://github.com/krystonschwarze/coolicons)）。一部を着色・プレートへの配置・ラスタライズして使用しています。**アイコンには Apache License 2.0 は適用されません。** アイコンのデータはこのリポジトリには含まれていません。
- GUI: [Slint](https://slint.dev) を [Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0](https://github.com/slint-ui/slint/blob/master/LICENSES/LicenseRef-Slint-Royalty-free-2.0.md) で使用しています。
- 依存クレートのライセンスは、配布物に同梱の `THIRD-PARTY-NOTICES.txt` を参照してください。

---

## English

**WoL Manager** is a Wake-on-LAN tool for Windows 10/11 with a GUI (`wol-manager.exe`, built with Slint) and a command-line tool (`wolm`).

- Register hosts (MAC, IP address, group, notes) and wake them with one click; the app then checks (ICMP / TCP) until they come online.
- Magic packets are sent from a socket bound to each suitable network adapter (directed broadcast + 255.255.255.255), so they leave through the LAN even when a VPN adapter has a lower route metric.
- Settings are stored per user in `%APPDATA%\wol-manager\config.toml` and shared by the GUI and the CLI. The portable ZIP switches to a `data\` folder next to the exe when an empty `wol-manager.portable` file is placed there.
- Installer: choose "Just me" (no admin, user PATH) or "All users" (Program Files, system PATH). Silent: `/S /CurrentUser|/AllUsers [/NoPath] [/DesktopShortcut] [/AllowOutsideProgramFiles] [/D=<dir>]`. An "All users" installation outside Program Files (where every user could otherwise replace programs that administrators run) needs a confirmation in the wizard or `/AllowOutsideProgramFiles` when silent, and the folder is then made changeable by administrators only.
- Portable ZIP: extract it to a folder of your own, such as `%LOCALAPPDATA%\Programs\wol-manager` (on a shared PC, not a folder created directly under `C:\`, which every user can change). A running app follows a portable-mode switch (`wolm portable enable|disable`, or the marker file placed or removed by hand) within a few seconds.
- The app runs once per session. Starting it again shows the running window; starting it for other settings (`--config-dir`, `WOL_MANAGER_CONFIG_DIR`, another portable copy) shows a message instead (`wolm gui`: exit code 7). Exit the running app first (notification area icon > Exit).
- CLI examples: `wolm wake NAS --wait`, `wolm wake --group Lab`, `wolm status`, `wolm add NAS --address 192.168.1.10 --arp`, `wolm path add --scope user`, `wolm completions | Out-String | Invoke-Expression`. Run `wolm --help` for everything; `--json` prints ASCII-only JSON.
- Build from source: `scripts\fetch-coolicons.ps1`, then `cargo build --workspace` or `scripts\build.ps1` for the installer and ZIP. `scripts\dev-run.ps1` runs the app with `.cache\dev-config` and a JSON file instead of the real PATH.

### Network notes

- Wake-on-LAN normally works only **within the same network (subnet)**: routers rarely forward broadcasts to other subnets.
- PCs on Wi-Fi usually cannot be woken. Enable Wake-on-LAN in the BIOS / UEFI and in the network adapter settings.
- Windows often does not answer ping (ICMP) by default, so use the "Auto" status check (ping, then TCP; default TCP ports 3389, 445, 22).
- `wolm interfaces` shows which network adapters the magic packets are sent from. VPN and virtual adapters are not used by default (configurable).

### Troubleshooting

- **"Windows protected your PC" (SmartScreen)**: the programs are not code-signed. Check the publisher and the SHA-256 hash, then choose "More info" > "Run anyway". Unblock the ZIP (Properties > Unblock) before extracting it. With Smart App Control enabled on Windows 11, the unsigned programs may be blocked.
- **`wolm` is not found**: PATH changes apply only to terminal windows opened afterwards.
- **The window stays blank or does not appear** (virtual machines, Remote Desktop): start `wol-manager.exe --safe-mode`, or choose the "Software" renderer in Settings > Advanced.
- **A PC does not wake**: check the route and the packet with `wolm wake <host> --dry-run`. The app's log is `%LOCALAPPDATA%\wol-manager\logs\gui.log`.

Licenses: source code under Apache-2.0. Icons: coolicons v4.1 by Kryston Schwarze, CC BY 4.0 (not covered by Apache-2.0, not included in this repository; fetched at build time). GUI built with Slint under the Slint Royalty-free License 2.0.
