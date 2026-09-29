WoL Manager {{VERSION}} - ZIP 版 / ZIP edition (x86_64-pc-windows-msvc)
==============================================================================

English follows the Japanese text.

------------------------------------------------------------------------------
日本語
------------------------------------------------------------------------------

WoL Manager は、Wake on LAN のマジックパケットで PC を起動するための Windows 用
アプリです。GUI（wol-manager.exe）とコマンドライン（wolm）のどちらからでも使えます。

■ 同梱ファイル
  wol-manager.exe           GUI
  bin\wolm.exe              コマンドライン版（wolm）
  LICENSE.txt               WoL Manager のライセンス（Apache License 2.0）
  THIRD-PARTY-NOTICES.txt   サードパーティのライセンス（coolicons、Slint、Rust クレート）
  README.txt                このファイル

■ 使い始める前に
  1. ダウンロードした ZIP のブロックを解除してから展開してください。
     ZIP を右クリック → [プロパティ] → [全般] の「許可する」にチェック → [OK]
     （PowerShell の場合: Unblock-File .\wol-manager-{{VERSION}}-x86_64-pc-windows-msvc.zip）
  2. 展開したフォルダーを、書き込みのできる場所に置きます
     （例: %LOCALAPPDATA%\Programs\wol-manager）。
     OneDrive などで同期されるフォルダー（「ドキュメント」「デスクトップ」など）は
     避けてください。同期中にファイルがロックされ、設定の保存に失敗することがあります。
     複数の人が使う PC では、C:\Tools のように C:\ の直下に作ったフォルダーも
     避けてください。そこにあるファイル（wolm.exe や data\ の設定）は、すべての
     ユーザーが変更できます。
  3. wol-manager.exe を起動します。

■ 設定の保存場所
  既定では、インストール版と同じくユーザーごとの AppData に保存します。
    %APPDATA%\wol-manager\config.toml     ホストの一覧と設定
    %LOCALAPPDATA%\wol-manager\           ウィンドウの位置、ログ
  現在の保存先は bin\wolm.exe config path で確認できます。

■ 完全ポータブルにする（USB メモリなどで持ち運ぶ場合）
  wol-manager.exe と同じフォルダーに、空のファイル wol-manager.portable を置きます。
  設定は <このフォルダー>\data\ に保存されるようになります。
  （拡張子が表示されない環境で作ってしまった wol-manager.portable.txt も有効です）
  次の方法でも切り替えられます。
    - GUI: [設定] → [保存場所とコマンドライン] の「ポータブル」スイッチ
    - コマンド: bin\wolm.exe portable enable
      （今の設定をコピーするには bin\wolm.exe portable enable --copy-settings）
  元に戻す: bin\wolm.exe portable disable
  注意:
    - WoL Manager の起動中に切り替えた場合（マーカーを置く・消す、portable
      enable / disable）も、数秒以内に新しい保存先に切り替わります。
    - 読み取り専用の場所でも起動と閲覧はできますが、保存しようとするとエラーになります。
    - インストール版のフォルダー（uninstall.exe があるフォルダー）ではマーカーは無視されます。

■ リモート管理とパスワード（0.2.0 以降）
  登録したホストの再起動・シャットダウン・起動時刻の取得と、VPN 越しのホストの
  MAC アドレスの取得ができます（ホストの編集画面の「リモート管理」、または
  bin\wolm.exe remote set）。前提条件などは GitHub の README を参照してください。
  保存したパスワードは、この PC の Windows 資格情報マネージャー（この Windows
  ユーザー専用）に保存され、data\ フォルダー・config.toml・エクスポートには
  含まれません。USB メモリなどで別の PC に持って行った場合は、パスワードを
  入力し直してください。パスワードを保存していない Windows のホストに現在の
  Windows サインインを使うことの確認も、この PC にだけ記録されます。

■ wolm コマンドを PATH に追加する
  このフォルダーで次を実行します。
    bin\wolm.exe path add --scope user
  実行した後は、新しいターミナル（コマンドプロンプト、PowerShell、Windows Terminal）を
  開いてください。すでに開いているターミナルには反映されません。
  確認: wolm --version
  状態: bin\wolm.exe path status --scope user
  すべてのユーザーが変更できるフォルダーの場合は警告が表示されます。システムの
  PATH（--scope machine）には、--force を付けない限り追加しません。

■ フォルダーを削除・移動する前に
  先に次を実行して、PATH から外してください。
    bin\wolm.exe path remove --scope user
  移動した場合は、移動先で改めて path add を実行します。
  完全ポータブルにしている場合、設定は data\ フォルダーにあります。

■ ダウンロードしたファイルの確認
  配布ページの .sha256 ファイル、または SHA256SUMS.txt の値と比較してください。
    PowerShell:          Get-FileHash .\wol-manager-{{VERSION}}-x86_64-pc-windows-msvc.zip -Algorithm SHA256
    コマンドプロンプト:  certutil -hashfile wol-manager-{{VERSION}}-x86_64-pc-windows-msvc.zip SHA256

■ SmartScreen の警告について
  このプログラムはコード署名をしていません。初めて起動したときに「Windows によって
  PC が保護されました」と表示された場合は、上の方法でハッシュ値を確認したうえで
  [詳細情報] → [実行] を選んでください。Windows 11 の「スマート アプリ コントロール」
  が有効な場合は、実行がブロックされることがあります。

■ クレジット
  アイコン: coolicons v4.1 by Kryston Schwarze（CC BY 4.0）
    https://github.com/krystonschwarze/coolicons
    https://creativecommons.org/licenses/by/4.0/
    着色、プレートへの配置、線幅の調整、ラスタライズを加えて使用しています。
    アイコンには Apache License 2.0 は適用されません。
  GUI: Slint（https://slint.dev）
    Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0 で使用しています。
  詳しくは THIRD-PARTY-NOTICES.txt を参照してください。

■ ライセンスとサポート
  WoL Manager は Apache License 2.0 で提供しています（LICENSE.txt）。
  https://github.com/SHIN-DATA-CENTER/wol-manager

------------------------------------------------------------------------------
English
------------------------------------------------------------------------------

WoL Manager wakes up PCs with Wake-on-LAN magic packets. It can be used from a
GUI (wol-manager.exe) and from the command line (wolm).

* Contents
  wol-manager.exe           GUI
  bin\wolm.exe              command-line tool (wolm)
  LICENSE.txt               WoL Manager license (Apache License 2.0)
  THIRD-PARTY-NOTICES.txt   third-party licenses (coolicons, Slint, Rust crates)
  README.txt                this file

* Before you start
  1. Unblock the downloaded ZIP before extracting it:
     right-click the ZIP -> Properties -> General -> check "Unblock" -> OK
     (PowerShell: Unblock-File .\wol-manager-{{VERSION}}-x86_64-pc-windows-msvc.zip)
  2. Put the extracted folder in a writable location, e.g.
     %LOCALAPPDATA%\Programs\wol-manager.
     Avoid folders synchronized by OneDrive or similar (Documents, Desktop, ...):
     the sync client can lock files and make saving the settings fail.
     On a computer shared by several people, also avoid folders created
     directly under C:\ (such as C:\Tools): every user can change the files
     there (wolm.exe, and the settings in data\).
  3. Start wol-manager.exe.

* Where the settings are stored
  By default the settings are stored per user in AppData, exactly like the
  installed version:
    %APPDATA%\wol-manager\config.toml     host list and settings
    %LOCALAPPDATA%\wol-manager\           window position, logs
  "bin\wolm.exe config path" shows the location in use.

* Fully portable mode (e.g. on a USB stick)
  Put an empty file named wol-manager.portable next to wol-manager.exe. The
  settings are then stored in <this folder>\data\ instead.
  (wol-manager.portable.txt, as created by Explorer with hidden file name
  extensions, works as well.)
  You can also switch with:
    - GUI: Settings -> Storage and command line -> "Portable" switch
    - command: bin\wolm.exe portable enable
      (add --copy-settings to copy the current settings)
  Switch back: bin\wolm.exe portable disable
  Notes:
    - A running WoL Manager follows a switch made while it runs (marker placed
      or removed, portable enable / disable) within a few seconds.
    - In a read-only location WoL Manager starts and shows the hosts, but saving
      reports an error.
    - The marker is ignored in an installed copy (a folder with uninstall.exe).

* Remote management and passwords (0.2.0 and later)
  Registered hosts can be restarted, shut down and asked for their boot
  time, and hosts behind a VPN report the MAC address of their physical
  adapter (host editor -> "Remote management", or bin\wolm.exe remote set).
  See the README on GitHub for the requirements.
  Saved passwords are kept in this PC's Windows Credential Manager (for this
  Windows user only), never in the data\ folder, config.toml or exports.
  After taking the portable folder to another PC (e.g. on a USB stick),
  enter the passwords again. The confirmation to use your current Windows
  sign-in for a Windows host without a saved password is kept on this PC
  only as well.

* Adding the wolm command to PATH
  Run this in the extracted folder:
    bin\wolm.exe path add --scope user
  Then open a NEW terminal window (Command Prompt, PowerShell or Windows
  Terminal). Terminals that are already open do not see the change.
  Check:  wolm --version
  Status: bin\wolm.exe path status --scope user
  A folder that every user can change gets a warning, and is not added to
  the system PATH (--scope machine) without --force.

* Before deleting or moving the folder
  First remove it from PATH:
    bin\wolm.exe path remove --scope user
  After moving the folder, run "path add" again from the new location.
  In fully portable mode the settings are in the data\ folder.

* Verifying the download
  Compare the hash with the published .sha256 file or SHA256SUMS.txt:
    PowerShell:      Get-FileHash .\wol-manager-{{VERSION}}-x86_64-pc-windows-msvc.zip -Algorithm SHA256
    Command Prompt:  certutil -hashfile wol-manager-{{VERSION}}-x86_64-pc-windows-msvc.zip SHA256

* SmartScreen warning
  The programs are not code-signed. If Windows shows "Windows protected your
  PC" on the first start, verify the hash as described above and then choose
  "More info" -> "Run anyway". With Smart App Control enabled on Windows 11,
  the programs may be blocked.

* Credits
  Icons: coolicons v4.1 by Kryston Schwarze, licensed under CC BY 4.0
    https://github.com/krystonschwarze/coolicons
    https://creativecommons.org/licenses/by/4.0/
    The icons were recolored, placed on plates, had their stroke width
    adjusted and were rasterized. The Apache License 2.0 does not apply to
    the icons.
  GUI: Slint (https://slint.dev), used under the Slint Royalty-free Desktop,
    Mobile, and Web Applications License 2.0.
  See THIRD-PARTY-NOTICES.txt for details.

* License and support
  WoL Manager is licensed under the Apache License 2.0 (LICENSE.txt).
  https://github.com/SHIN-DATA-CENTER/wol-manager
