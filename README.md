# WoL Manager

Windows 用の Wake-on-LAN ツールです。GUI（`wol-manager.exe`）とコマンドライン（`wolm`）の両方から、登録した PC をネットワーク経由で起動できます。

[![Made with Slint](https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-whitebg.png)](https://slint.dev)

*English summary is at the [end of this file](#english).*

## 特徴

- ホスト（MAC アドレス・IP アドレス・グループ・メモ）を登録して、ワンクリックで起動
- 起動後にオンラインになるまで自動で確認（Ping / TCP）し、状態を一覧に表示
- **複数の NIC や VPN があっても確実に届く送信方式**: 使用するネットワークアダプターごとにソケットを bind して、そのサブネットのブロードキャストと 255.255.255.255 に送ります。VPN（WireGuard など）の方が優先される環境でも、LAN 側から送信されます
- IP アドレスから MAC アドレスを自動取得（同じ LAN なら ARP、VPN 越しのホストはリモート管理で相手の物理 NIC から取得）
- **リモート管理**（v0.2.0〜）: 登録ホストの**再起動・シャットダウン・起動時刻の取得**（Windows / Linux・Proxmox・NAS）
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
| 1 | 否定的な結果（変更なし、ダウンしているホストがある、確認で「いいえ」を選んだ、ホスト側で操作が拒否された など） |
| 2 | 使い方・入力の誤り |
| 3 | 見つからない |
| 4 | `--wait` のタイムアウト（起動・再起動・シャットダウンの確認） |
| 5 | ネットワークエラー |
| 6 | 設定・ファイル・レジストリのエラー |
| 7 | 権限不足・書き込めない・認証の失敗・SSH ホスト鍵の問題 |
| 10 | 内部エラー（Ctrl+C で中断した場合は 130） |

PowerShell 5.1 でパイプ先に日本語を渡す場合は、`--json` を使うか `[Console]::OutputEncoding = [Text.Encoding]::UTF8` を設定してください。

## リモート管理（再起動・シャットダウン・起動時刻）

ホストに「リモート管理」を設定すると、起動以外に **再起動・シャットダウン・起動時刻（最後に起動した時刻と稼働時間）の取得** ができます。VPN（NetBird・WireGuard など）越しのホストの MAC アドレスも、相手の物理 NIC から取得できるようになります（VPN は L3 トンネルのため ARP では取得できません）。

GUI ではホストの編集画面の「リモート管理」で設定し、「接続テスト」で確認できます。操作は行の ⋮ メニュー（右クリック）と「ホスト」メニューから行います。再起動・シャットダウンは必ず確認画面が表示されます。

GUI は、リモート管理を設定したホストがオンラインになると、**起動時刻を自動で取得**します（「設定 > リモート管理 > 起動時刻を自動で取得する」でオフにできます）。パスワードを保存していない Windows のホストへの自動の接続には、後述の「Windows サインインの確認」が必要です。

### Windows のホスト

- 接続方式: Windows 標準のリモート管理（SMB 445 番 / RPC。`shutdown /m` と同じ仕組み）。MAC アドレスの取得には WMI を使います。
- **管理者アカウント**が必要です。ホストごとにユーザー名とパスワードを保存できます（未設定の場合は、今ログオンしている Windows ユーザーで接続します。ただし自動の接続でこれを使うのは、そのホストを確認した後だけです。下の「Windows サインインの確認」を参照）。
  - ローカルアカウント: `PC名\ユーザー名`（例: `DESKTOP-ABC\admin`）、ドメイン: `DOMAIN\user` または `user@domain`
  - Microsoft アカウント: **メール アドレス**（例: `taro@outlook.jp`）と、Microsoft アカウントのパスワード（サインインに使う PIN ではありません）
  - ユーザー名を空欄のまま `wolm cred set` でパスワードを保存すると、**この PC のサインイン アカウント名**のパスワードとして保存されます（確認画面と `wolm remote show` に表示されます）。相手の PC のアカウント名が違う場合は、先にユーザー名を設定してください（`wolm remote set PC --user PC名\ユーザー名`）。
- 相手の PC で次を許可してください（送信元の VPN のアドレス範囲も含めて）:
  - Windows ファイアウォールの「ファイルとプリンターの共有（SMB 受信）」（再起動・シャットダウン・起動時刻）
  - 「Windows Management Instrumentation (WMI)」（MAC アドレスの取得）
- **ワークグループ（ドメインに参加していない）PC のローカル管理者アカウント（Microsoft アカウントを含む）**は、UAC のリモート制限によりネットワーク経由では管理者として扱われず、「アクセスが拒否されました」になります（Microsoft KB951016）。接続テストでは「WMI への接続が拒否された」という警告になります。相手の PC で `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` の `LocalAccountTokenFilterPolicy`（DWORD）を `1` にすると許可されますが、セキュリティ上の保護を弱める設定です。WoL Manager がこの設定を自動で変更することはありません。
- シャットダウン・再起動は既定で 30 秒後に実行され、その間は相手の画面にメッセージが表示されます（取り消しも可能）。保存していない作業は失われることがあります。
- **起動時刻は、Windows が最後に完全に起動した時刻**です（タスク マネージャーの「稼働時間」と同じ）。Windows 10/11 の既定で有効な**高速スタートアップ**では、スタート メニューの「シャットダウン」の後の起動は完全な起動ではないため、起動時刻が更新されません（「再起動」では更新されます）。WoL Manager からの再起動・シャットダウンは完全なシャットダウンなので、その後の起動で更新されます。
- WoL Manager からのシャットダウンは**完全なシャットダウン（S5）**です。PC によっては、この状態からは WoL で起動できません。下の「WoL を有効にしておく（Windows）」を確認してください。

### Linux / Proxmox VE / NAS のホスト（SSH）

- 接続方式: SSH（WoL Manager に組み込み。OpenSSH などの追加インストールは不要）。認証は**鍵ファイル（ed25519 / ECDSA / RSA、パスフレーズ付き可）またはパスワード**です。
- 再起動・シャットダウンには root 権限が必要です。root でログインするか、`sudo` を使えるユーザーを指定してください（sudo の方式: 自動 / root / NOPASSWD / ログインと同じパスワード / 別のパスワード）。
  - Proxmox VE: `root` で接続します（sudo は標準では入っていません）。
  - Synology DSM: 管理者グループのユーザーと sudo のパスワード。TrueNAS SCALE: `truenas_admin` など sudo を許可したユーザー。
- 初めて接続するときは、**相手のホスト鍵のフィンガープリント（SHA256）を確認して信頼**します。相手のコンソールで `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` を実行して一致を確認してください。以降に鍵が変わった場合は接続を拒否します（再インストールなどで変わった場合のみ「信頼を解除」してください）。
- 起動時刻は `/proc/stat`（FreeBSD 系は `kern.boottime`）から取得します。
- 標準のコマンドで再起動・シャットダウンできない NAS などには、独自のコマンドを設定できます（`wolm remote set NAS --reboot-command ... / --shutdown-command ...`）。このコマンドは root 権限で実行されるため、**再起動・シャットダウンの確認画面に必ず表示されます**（`--yes` の場合は標準エラー出力に表示）。GUI の編集画面にも表示され、「標準に戻す」で削除できます。インポートでは、既存のホストの独自コマンドは変更されません（新しく追加されるホストのものは取り込まれ、インポート時と確認画面で表示されます）。

### コマンドラインでの操作

```text
# リモート管理の設定
wolm remote set PC --kind windows --user PC\admin [--address 100.105.1.2]
wolm remote set NAS --kind ssh --user admin [--port 22] [--key-file C:\Users\me\.ssh\id_ed25519] [--sudo auto|root|nopasswd|password|separate]
wolm remote show PC            # 設定と保存済みパスワードの状態（パスワード自体は表示しない）
wolm remote test PC            # 接続テスト（OS・起動時刻・管理者権限）
wolm remote clear PC [-y]      # リモート管理を解除（保存したパスワードと SSH ホスト鍵も削除）

# パスワード（Windows 資格情報マネージャー。引数では渡せません）
wolm cred set PC                               # コンソールで入力（2 回）
Get-Content pw.txt | wolm cred set PC --password-stdin
wolm cred set NAS --kind key-passphrase        # 鍵のパスフレーズ（sudo 用は --kind sudo）
wolm cred list / wolm cred delete PC [--kind sudo] / wolm cred prune [-n] [-y]

# SSH ホスト鍵
wolm ssh trust NAS [--fingerprint SHA256:... | --accept-new]
wolm ssh forget NAS

# VPN 越しの新しいホストを登録して、相手の物理 NIC の MAC アドレスを取得する
# （ARP が届かないため add --arp は使えません。仮の MAC アドレスで登録してから置き換えます）
wolm add PC --address 100.105.1.2 --mac 02-00-00-00-00-01
wolm remote set PC --kind windows --user PC\admin
wolm cred set PC
wolm mac PC --save

# 操作
wolm boot-time PC NAS          # 別名 uptime。引数なしでリモート管理のある全ホスト（パスワード未保存の Windows ホストは確認済みのものだけ）
wolm restart PC [--delay 60 | --now] [--no-force] [--message "メンテナンス"] [--wait [--timeout 10m]] [-y]
wolm shutdown PC --yes --wait
wolm abort PC                  # Windows のカウントダウンを取り消す
wolm mac PC [--save] [--pick N]   # LAN は ARP、VPN 越しはリモート管理で物理 NIC の MAC を取得
```

- 確認（y/N）が表示されるのは、`restart` / `shutdown` / `remote clear` / `cred prune`、および新しいバージョンで設定されたリモート管理を `remote set` で置き換える場合です（`abort` は確認しません）。スクリプトからは `--yes` が必要です（ない場合は終了コード 2）。`ssh trust` もフィンガープリントの確認を求めます。スクリプトからは `--fingerprint SHA256:...`（一致した場合だけ信頼）か `--accept-new` を指定してください（ない場合は終了コード 2）。
- `restart` / `shutdown` の `--wait` 中に Ctrl+C を押すと確認を中止します（応答を待っている接続が終わるまで最大 1 分ほどかかることがあります）。もう一度押すとすぐに終了します。
- 終了コード 7 には、認証の失敗・権限不足・SSH ホスト鍵の問題・確認されていない Windows サインイン（下記）も含まれます。
- `wolm mac` は、候補が Wi-Fi のアダプター・WoL が無効なアダプター・未接続のアダプターだけの場合は自動で選ばず、`--pick 1` などで指定します。
- 鍵ファイル（`--key-file`）にネットワーク上のパス（`\\server\share\...`）は指定できません（読み込むと、その PC に Windows の資格情報でログオンすることになるため）。パスの `%USERPROFILE%` などの環境変数と先頭の `~`（ユーザー プロファイル）は展開して保存します（PowerShell では `$env:USERPROFILE` も使えます）。
- Windows PowerShell 5.1 では、`--password-stdin` にパイプした日本語などの非 ASCII 文字が `?` に置き換わります。コンソールでの入力か PowerShell 7 を使ってください（UTF-16LE の BOM 付きで渡した入力も受け付けます）。

### 資格情報とセキュリティ

- パスワード・パスフレーズは **Windows の資格情報マネージャー**（この PC・この Windows ユーザー専用、DPAPI で暗号化）に保存され、`config.toml`、エクスポート、ポータブル版の `data` フォルダーには含まれません。別の PC や別のユーザーで使う場合は入力し直してください。
- 保存したパスワードは、**保存したときの接続先（種類・アカウント・管理用アドレス・ポート）にだけ使われます**。インポートなどで接続先が変わった場合は送信せず、パスワードの再入力を求めます。
- インポートで既存のホストの接続先（種類・管理用アドレス・SSH ポート）が変わった場合、そのホストの SSH ホスト鍵は信頼しません（ファイルの鍵も以前の鍵も使いません）。次の接続でフィンガープリントを確認してください。接続先が同じ場合は、この PC で信頼済みの鍵をそのまま使います。
- 資格情報は同じ Windows ユーザーで動くすべての WoL Manager（インストール版・ポータブル版・`--config-dir` を指定したもの）で共有されます。
- 保存した資格情報は「コントロール パネル > 資格情報マネージャー > Windows 資格情報 > 汎用資格情報」（`wol-manager/host/…`）で確認・削除できます。ホストを削除すると、そのホストの資格情報も削除されます。

### Windows サインインの確認

- パスワードを保存していない Windows のホストには、**今サインインしている Windows ユーザーの資格情報**（シングル サインオン）で接続します。
- 起動時刻の自動取得など、**自分で操作していない接続でこれを使うのは、そのホストを確認した後だけ**です。次の操作をすると、そのホストと管理用アドレスについて確認済みになります:
  - GUI: そのホストへの操作（起動時刻の取得・再起動・シャットダウン・シャットダウンの取り消し）、編集画面での保存、保存済みの接続先での接続テスト・「IP から取得」
  - CLI: `wolm remote set`、ホスト名を指定した `wolm remote test` / `boot-time` / `restart` / `shutdown` / `abort` / `mac`、管理用アドレスを変える `wolm edit`
- 確認は、パスワードを含まない印として資格情報マネージャー（`wol-manager/host/<ID>/sign-in`）に保存され、`config.toml` やエクスポートには含まれません。**インポートで追加されたホストや、インポートで管理用アドレスが変わったホスト**は、確認するまで自動では接続しません（GUI はログに記録するだけで、何も送信しません）。`wolm boot-time` をホスト名なしで実行した場合も同じで、確認されていないホストは終了コード 7 と、確認の方法（`wolm remote test HOST`）を表示します。
- 確認の印はホストを削除すると一緒に削除されます（`wolm cred list` / `prune` には表示されません）。

### WoL を有効にしておく（Windows）

WoL Manager からのシャットダウンは完全なシャットダウン（S5）で、高速スタートアップの休止状態とは異なります。S5 から WoL で起動するには、次を確認してください。

- BIOS/UEFI: 「Wake on LAN」「Power On By PCI-E」などを有効にし、「ErP」「Deep Sleep」などの省電力設定を無効にする
- デバイス マネージャー > ネットワーク アダプター > プロパティ: 「詳細設定」の「Wake on Magic Packet」「シャットダウン後の Wake on LAN」など（名前はドライバーによって異なります）を有効にし、「電源の管理」の「このデバイスで、コンピューターのスタンバイ状態を解除できるようにする」をオンにする

### WoL を有効にしておく（Linux）

シャットダウンした PC を WoL で起動するには、NIC の WoL を有効にしておく必要があります（BIOS/UEFI の設定も必要です）。

| 環境 | 設定例 |
|---|---|
| Proxmox VE / Debian（ifupdown） | 物理 NIC のスタンザに `post-up /usr/sbin/ethtool -s eno1 wol g` |
| systemd-networkd | `.link` ファイルに `WakeOnLan=magic` |
| NetworkManager | `nmcli connection modify <接続名> 802-3-ethernet.wake-on-lan magic` |
| OpenMediaVault | ネットワーク設定の「WOL」を有効化 |
| Synology DSM | コントロール パネル > ハードウェアと電源 > Wake on LAN |
| FreeBSD / TrueNAS CORE | `ifconfig <if> wol_magic`（`rc.conf` にも設定） |

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
- **Remote management** (since 0.2.0): restart, shut down and read the last boot time of registered hosts — Windows hosts over the standard Windows remote management (SMB 445 / RPC like `shutdown /m`, WMI for the MAC; an administrator account, "File and Printer Sharing" and "WMI" firewall rules; local accounts on workgroup PCs are subject to UAC remote restrictions, KB951016), Linux / Proxmox VE / NAS hosts over the built-in SSH client (key file or password, root or sudo, host key fingerprint confirmed on first use and pinned). Passwords are stored per host in Windows Credential Manager, never in `config.toml` or exports. Hosts behind a VPN (e.g. NetBird, an L3 tunnel without ARP) get their physical NIC's MAC through remote management.
  - The app fetches the boot time automatically when a managed host comes online (Settings > Remote management > "Get the boot time automatically").
  - Windows hosts without a saved password connect with your current Windows sign-in (single sign-on), and automatic connections (the automatic boot time, `wolm boot-time` without host names) use it only after you confirmed the host: an operation you started for it, saving it in the editor, `wolm remote set`, or a `wolm` command that names it (e.g. `wolm remote test HOST`). The confirmation is kept in Credential Manager (no secret) for the host and its management address, so hosts that an import added or pointed to another address are not contacted automatically until you confirm them.
  - A custom SSH restart / shutdown command (`wolm remote set --reboot-command / --shutdown-command`, run with root rights) is shown before every restart / shutdown (on stderr with `--yes`) and in the host editor; an import never changes it on an existing host.
  - Windows accounts: local `PCNAME\user`, domain `DOMAIN\user` or `user@domain`, **Microsoft accounts as the e-mail address with the account password (not the PIN)**. Workgroup PCs apply UAC remote restrictions (KB951016) to local administrators, Microsoft accounts included; "Test connection" then warns that WMI refused the account. With an empty user name, `wolm cred set` stores the password for this PC's sign-in name (shown when asking and in `wolm remote show`); set the target's account first (`wolm remote set PC --user PC\admin`) if it differs.
  - Windows boot time is the last full start of the kernel (as in Task Manager). With Fast Startup (the Windows 10/11 default) a start after Start > Shut down is not a full start, so the boot time is not updated; restarts and the app's own restart / shutdown are. A shutdown from the app is a full shutdown (S5): check that the PC can wake from S5 (BIOS/UEFI "Wake on LAN" / "Power On By PCI-E", ErP or Deep Sleep off, and the adapter's "Wake on Magic Packet" settings).
  - A new host behind a VPN: `wolm add --arp` cannot read its MAC (no ARP), so add it with a placeholder MAC, set up remote management, then read the real one: `wolm add PC --address 100.105.1.2 --mac 02-00-00-00-00-01`, `wolm remote set PC --kind windows --user PC\admin`, `wolm cred set PC`, `wolm mac PC --save`.
  - An import that points an existing host to another endpoint (kind, management address, SSH port) leaves it without a trusted SSH host key (neither the file's nor the old one): check the fingerprint on the next connection. `wolm ssh trust` asks too; scripts pass `--fingerprint SHA256:...` or `--accept-new`.
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
