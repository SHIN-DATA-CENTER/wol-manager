[![Made with Slint](https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-whitebg.png)](https://slint.dev)

## What's new / 主な変更点

<!-- Update this section for every release. -->

- **Remote management**: restart, shut down and read the boot time of registered hosts, both
  Windows hosts (SMB / RPC, WMI) and Linux / Proxmox VE / NAS hosts (built-in SSH), from the
  app and from `wolm`.
- **Fixed**: "Get from IP" (MAC address) for hosts behind a VPN such as NetBird. With remote
  management set up, the MAC address of the host's physical adapter is read from the host.
- **リモート管理**: 登録ホストの再起動・シャットダウン・起動時刻の取得（Windows: SMB / RPC・WMI、
  Linux / Proxmox VE / NAS: 組み込みの SSH）。GUI と `wolm` の両方から使えます。
- **修正**: NetBird などの VPN 越しのホストで「IP から取得」（MAC アドレス）ができなかった問題。
  リモート管理を設定すると、相手の物理 NIC の MAC アドレスを取得します。

Upgrade notes and all changes / アップグレード時の注意と変更の一覧:
[CHANGELOG.md](https://github.com/SHIN-DATA-CENTER/wol-manager/blob/v<version>/CHANGELOG.md)

Saved passwords stay in Windows Credential Manager on each PC; they are not in the portable
`data` folder or in exports. / 保存したパスワードは各 PC の Windows 資格情報マネージャーに
保存され、ポータブル版の `data` フォルダーやエクスポートには含まれません。

## Downloads / ダウンロード

| File | |
|---|---|
| `wol-manager-<version>-setup-x64.exe` | Installer: "Just me" (no administrator rights) or "All users" / インストーラー（「自分のみ」または「すべてのユーザー」） |
| `wol-manager-<version>-x86_64-pc-windows-msvc.zip` | Portable ZIP (see `README.txt` inside) / ポータブル版（同梱の `README.txt` を参照） |
| `*.sha256`, `SHA256SUMS.txt` | SHA-256 checksums / チェックサム |

Requirements: 64-bit Windows 10 or later (x64), or Windows 11 on ARM64.
動作環境: 64 ビット版 Windows 10 以降（x64）、または ARM64 版 Windows 11。

## Verify the download / ダウンロードの確認

```powershell
Get-FileHash .\wol-manager-<version>-setup-x64.exe -Algorithm SHA256
```

```bat
certutil -hashfile wol-manager-<version>-setup-x64.exe SHA256
```

Compare the result with the `.sha256` file or `SHA256SUMS.txt`.
表示された値を `.sha256` ファイルまたは `SHA256SUMS.txt` と比較してください。

## SmartScreen

The binaries are not code-signed. Windows SmartScreen may show "Windows protected your PC";
verify the hash, then choose "More info" → "Run anyway". Smart App Control on Windows 11 may
block unsigned programs.

実行ファイルにはコード署名をしていません。「Windows によって PC が保護されました」と表示された場合は、
ハッシュ値を確認したうえで [詳細情報] → [実行] を選んでください。Windows 11 の「スマート アプリ コントロール」
が有効な場合はブロックされることがあります。

## Credits / クレジット

- Icons: [coolicons](https://github.com/krystonschwarze/coolicons) v4.1 by Kryston Schwarze,
  licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (recolored, placed on
  plates and rasterized; not covered by the Apache License 2.0).
- GUI: [Slint](https://slint.dev), used under the Slint Royalty-free Desktop, Mobile, and Web
  Applications License 2.0.
- Full license texts: `THIRD-PARTY-NOTICES.txt` in the installer and in the ZIP.
