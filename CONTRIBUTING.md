# Contributing / 開発メモ

## Layout

| Path | What |
|---|---|
| `crates/wol-core` | Library shared by GUI and CLI: config store, magic packets, interface selection, probing (ICMP/TCP), ARP, PATH editing, i18n, import/export. No UI code. |
| `crates/wolm` | CLI (`wolm.exe`, console subsystem). Must not depend on Slint. |
| `crates/wol-manager` | GUI (`wol-manager.exe`, Slint 1.18, fluent style). `ui/**.slint` + `lang/` translations. |
| `crates/wol-build` | Build-script helpers: coolicons lookup, icon rendering, generated Slint globals, Windows resources. |
| `installer/` | NSIS installer (Unicode, stock plugins only). |
| `packaging/` | cargo-about config, notice texts, portable README. |
| `scripts/` | `fetch-coolicons.ps1`, `build.ps1`, `dev-run.ps1`, `check-repo-hygiene.ps1`, `check-translations.ps1`, `smoke-installer.ps1`. |

Shared identifiers (AppData folder, mutex / event names, portable marker, uninstall key, exe and `bin` names, and the uninstaller name `uninstall.exe`, whose presence marks an installed copy) live in `crates/wol-core/src/consts.rs` and in `[workspace.metadata.wol]` of the root `Cargo.toml`. `crates/wol-core/tests/consts.rs` keeps them in sync and checks that the installer scripts use the defines (`${UNINSTALLER_EXE}`, `${CLI_SUBDIR}`, `${CLI_EXE}`) instead of the literal names; `scripts/build.ps1` passes them to NSIS.

## Rule 1: never commit coolicons data

coolicons (CC BY 4.0) is third-party material. **Nothing from it may be committed** — not the SVGs, not converted `.ico`/`.png` files, not generated `.slint` files, not inline path data, not screenshots that show the icons.

- Get the icons with `scripts\fetch-coolicons.ps1` (hash-verified release zip → `coolicons.v4.1\`, gitignored).
- `build.rs` reads them from `COOLICONS_DIR` at build time and writes everything derived into `OUT_DIR`, from where it is embedded into the executables.
- `scripts\check-repo-hygiene.ps1` enforces this (CI runs it first, and again after fetching the icons). Run it before every commit. It rejects image / font files by extension (also `*.svg.*`) and by content signature, and scans every text file, whatever its extension, for SVG markup, `data:` images, `currentColor` strokes, SVG path data and base64 that decodes to any of these. With `coolicons.v4.1\` present it also compares every file with the real icons (path data, file hashes, also inside base64). Only `crates/wol-build/src/icon.rs` and `coolicons.rs` may mention the markup tokens, with tiny synthetic test shapes (at most 8 path commands).
- New icons: add them to `UI_ICONS` in `crates/wol-manager/build.rs` and use `CoolIcons.<name>` in Slint, always tinted (`colorize-icon: true` / `colorize:`).

## Development

- Toolchain: `rust-toolchain.toml` pins 1.98.1. `.cargo/config.toml` sets `+crt-static` and `/STACK:8000000` for `x86_64-pc-windows-msvc`; do not set `RUSTFLAGS` (it would silently replace them).
- Run the app without touching your real settings: `scripts\dev-run.ps1` (uses `.cache\dev-config`, and `.cache\dev-path.json` instead of the registry for PATH changes in debug builds; `-RealPath` or `-Release` change the real user PATH). `-Software` forces the software renderer, `-Cli <args>` runs `wolm`. It runs cargo in the repository root, so `.cargo\config.toml` and `rust-toolchain.toml` apply from any current folder. The GUI is a single instance: while another WoL Manager runs (e.g. the installed one in the tray), the dev build shows a message and exits instead of opening that window.
- Tests must never touch the real `%APPDATA%\wol-manager`, `%LOCALAPPDATA%\wol-manager` or the registry PATH. Use `WOL_MANAGER_CONFIG_DIR` and, in debug builds, `WOL_MANAGER_PATH_BACKEND_FILE` (JSON file instead of the registry).
- Before pushing: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, `scripts\check-repo-hygiene.ps1`, `scripts\check-translations.ps1`.

## Translations

UI strings are written in English inside `@tr("...")` in the `.slint` files. Japanese lives in `crates/wol-manager/lang/ja/LC_MESSAGES/wol-manager.po` (bundled at build time; the gettext domain is the package name `wol-manager`, translation context is disabled).

```powershell
cargo install slint-tr-extractor --version 1.18.1 --locked
cd crates\wol-manager
slint-tr-extractor --no-default-translation-context -o lang/wol-manager.pot (Get-ChildItem ui -Recurse -Filter *.slint | Resolve-Path -Relative)
```

Then add the new entries to the `.po` file (no fuzzy or empty entries) and run `scripts\check-translations.ps1`. Runtime messages produced in Rust (CLI output, toasts) are in `crates/wol-core/src/i18n` (`Msg`, exhaustive match per language).

## Releases

1. Bump `version` in `[workspace.package]` of the root `Cargo.toml`.
2. `scripts\build.ps1` locally (optional) — produces `dist\` with the installer, ZIP, `.sha256` and `SHA256SUMS.txt`.
3. Push a tag `v<version>`; the release job checks that the tag matches the Cargo version and publishes the assets (versions containing `-` become pre-releases).

Binaries are not code-signed; SmartScreen warnings are expected.
