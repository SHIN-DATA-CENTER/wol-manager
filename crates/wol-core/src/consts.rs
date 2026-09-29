//! Identifiers shared by the GUI, the CLI and the installer.
//!
//! These values are duplicated in `[workspace.metadata.wol]` of the root `Cargo.toml`
//! (read by `scripts/build.ps1` and passed to NSIS). `tests/consts.rs` keeps them in sync.

/// Product name shown to users.
pub const PRODUCT_NAME: &str = "WoL Manager";
/// Publisher / company name.
pub const PUBLISHER: &str = "SHIN DATA CENTER";

/// Folder name under `%APPDATA%` / `%LOCALAPPDATA%`.
pub const APP_DIR_NAME: &str = "wol-manager";
/// Default folder name under Program Files / `%LOCALAPPDATA%\Programs`.
pub const INSTALL_DIR_NAME: &str = "WoL Manager";
/// Key name under `...\CurrentVersion\Uninstall`.
pub const UNINSTALL_KEY_NAME: &str = "wol-manager";

/// GUI executable file name.
pub const GUI_EXE: &str = "wol-manager.exe";
/// CLI executable file name.
pub const CLI_EXE: &str = "wolm.exe";
/// Sub-folder (relative to the install / portable root) that holds the CLI and goes on PATH.
pub const CLI_SUBDIR: &str = "bin";

/// Settings file name.
pub const CONFIG_FILE: &str = "config.toml";
/// Sidecar lock file used for read-modify-write of the settings file.
pub const LOCK_FILE: &str = "config.lock";
/// Backup of the previous settings file.
pub const BACKUP_FILE: &str = "config.toml.bak";
/// Per-machine GUI state (window geometry) file name.
pub const GUI_STATE_FILE: &str = "gui-state.toml";
/// Log folder name (inside the local data folder).
pub const LOG_DIR: &str = "logs";

/// Portable-mode marker file placed next to `wol-manager.exe`.
pub const PORTABLE_MARKER: &str = "wol-manager.portable";
/// Also accepted, because Explorer with hidden extensions easily creates this name.
pub const PORTABLE_MARKER_ALT: &str = "wol-manager.portable.txt";
/// Settings folder used in portable mode (next to `wol-manager.exe`).
pub const PORTABLE_DATA_DIR: &str = "data";
/// File whose presence marks an installed copy (portable markers are ignored there): the
/// uninstaller that the NSIS installer writes (`UNINSTALLER_EXE` there).
pub const INSTALLED_SENTINEL: &str = "uninstall.exe";

/// Overrides the settings folder (highest priority after `--config-dir`).
pub const ENV_CONFIG_DIR: &str = "WOL_MANAGER_CONFIG_DIR";
/// Overrides the UI language (`auto` | `ja` | `en`).
pub const ENV_LANG: &str = "WOL_MANAGER_LANG";
/// GUI log level (`error` | `warn` | `info` | `debug` | `trace`).
pub const ENV_LOG: &str = "WOL_MANAGER_LOG";
/// Debug builds only: JSON file used instead of the registry for PATH operations (tests).
pub const ENV_PATH_BACKEND_FILE: &str = "WOL_MANAGER_PATH_BACKEND_FILE";

/// Named mutex held by the running GUI (also probed by the installer).
pub const GUI_MUTEX: &str = r"Local\wol-manager.gui.8d3c5f2a-7b41-4e9a-a6c2-1f0e9b7d4c35";
/// Auto-reset event: a second GUI instance asks the first one to show its window.
pub const GUI_SHOW_EVENT: &str = r"Local\wol-manager.gui.8d3c5f2a-7b41-4e9a-a6c2-1f0e9b7d4c35.show";
/// Auto-reset event: the installer asks the running GUI to quit (even when in the tray).
pub const GUI_QUIT_EVENT: &str = r"Local\wol-manager.gui.8d3c5f2a-7b41-4e9a-a6c2-1f0e9b7d4c35.quit";
/// Named shared memory in which the running GUI publishes its settings folder (read by a
/// second GUI instance and by `wolm gui`; see [`crate::instance`]).
pub const GUI_SETTINGS_MAP: &str =
    r"Local\wol-manager.gui.8d3c5f2a-7b41-4e9a-a6c2-1f0e9b7d4c35.settings";

/// Default Wake-on-LAN UDP port.
pub const DEFAULT_WOL_PORT: u16 = 9;
