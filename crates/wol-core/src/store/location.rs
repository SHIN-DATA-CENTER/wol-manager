//! Where the settings live. Shared by the GUI and the CLI; never creates directories.
//!
//! Resolution order:
//! 1. `--config-dir <DIR>` ([`ConfigSource::Flag`]; relative paths are made absolute)
//! 2. `WOL_MANAGER_CONFIG_DIR` when non-empty ([`ConfigSource::Env`])
//! 3. Portable marker ([`ConfigSource::Portable`]):
//!    * root = the exe's folder; for `wolm.exe` in a folder named `bin` (any case) whose
//!      parent contains `wol-manager.exe`, the parent folder;
//!    * `<root>\wol-manager.portable` (or `.portable.txt`) → `<root>\data\`;
//!    * ignored, with [`ConfigLocation::marker_ignored`] set, when `<root>\uninstall.exe`
//!      exists (installed copy).
//! 4. `dirs::config_dir()\wol-manager` = `%APPDATA%\wol-manager` ([`ConfigSource::AppData`]).
//!
//! | File | AppData mode | Portable | Flag / Env |
//! |---|---|---|---|
//! | `config.toml`, `config.lock`, `config.toml.bak` | `%APPDATA%\wol-manager` | `<root>\data` | the folder |
//! | `gui-state.toml`, `logs\gui.log` | `%LOCALAPPDATA%\wol-manager` | `<root>\data` | the folder |

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::consts;
use crate::error::{Error, Result};
use crate::sys;

/// How the settings folder was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    /// `--config-dir` (shown as "custom location").
    Flag,
    /// `WOL_MANAGER_CONFIG_DIR` (shown as "custom location").
    Env,
    /// Portable marker next to the exe.
    Portable,
    /// `%APPDATA%\wol-manager` (standard).
    AppData,
}

/// The resolved settings location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigLocation {
    /// Folder of `config.toml`, `config.lock`, `config.toml.bak`.
    pub dir: PathBuf,
    /// Folder of machine-local files (`gui-state.toml`, `logs\`).
    pub local_dir: PathBuf,
    /// How `dir` was chosen.
    pub source: ConfigSource,
    /// Portable root derived from the exe path (also when not in portable mode).
    pub portable_root: Option<PathBuf>,
    /// Marker file found in the portable root (even when ignored or overridden).
    pub marker_path: Option<PathBuf>,
    /// A marker exists but `uninstall.exe` marks an installed copy, so it was ignored.
    /// Show a warning (`wolm config path`, GUI info bar).
    pub marker_ignored: bool,
}

impl ConfigLocation {
    /// A custom location (as with `--config-dir`): both folders are `dir`. Handy for tests.
    pub fn custom(dir: impl Into<PathBuf>) -> ConfigLocation {
        let dir = dir.into();
        ConfigLocation {
            local_dir: dir.clone(),
            dir,
            source: ConfigSource::Flag,
            portable_root: None,
            marker_path: None,
            marker_ignored: false,
        }
    }

    /// `config.toml`.
    pub fn config_file(&self) -> PathBuf {
        self.dir.join(consts::CONFIG_FILE)
    }

    /// `config.lock`.
    pub fn lock_file(&self) -> PathBuf {
        self.dir.join(consts::LOCK_FILE)
    }

    /// `config.toml.bak`.
    pub fn backup_file(&self) -> PathBuf {
        self.dir.join(consts::BACKUP_FILE)
    }

    /// `config.toml.tmp` (written, synced, then renamed over `config.toml`).
    pub fn temp_file(&self) -> PathBuf {
        self.dir.join(format!("{}.tmp", consts::CONFIG_FILE))
    }

    /// `gui-state.toml` (window geometry) in the local folder.
    pub fn gui_state_file(&self) -> PathBuf {
        self.local_dir.join(consts::GUI_STATE_FILE)
    }

    /// `logs\` in the local folder.
    pub fn log_dir(&self) -> PathBuf {
        self.local_dir.join(consts::LOG_DIR)
    }

    /// `logs\gui.log`.
    pub fn gui_log_file(&self) -> PathBuf {
        self.log_dir().join("gui.log")
    }

    /// `%TEMP%\wol-manager`: where the GUI logs when the local folder is not writable.
    pub fn fallback_log_dir() -> PathBuf {
        std::env::temp_dir().join(consts::APP_DIR_NAME)
    }

    /// Portable mode is active.
    pub fn is_portable(&self) -> bool {
        self.source == ConfigSource::Portable
    }

    /// `--config-dir` or `WOL_MANAGER_CONFIG_DIR` ("custom location").
    pub fn is_custom(&self) -> bool {
        matches!(self.source, ConfigSource::Flag | ConfigSource::Env)
    }
}

/// Inputs of [`resolve_with`]; [`resolve`] fills them from the process environment.
pub struct ResolveInputs<'a> {
    /// `--config-dir`.
    pub flag: Option<&'a Path>,
    /// Value of `WOL_MANAGER_CONFIG_DIR`.
    pub env: Option<&'a OsStr>,
    /// Path of the running exe.
    pub exe: Option<&'a Path>,
    /// `dirs::config_dir()` (Roaming AppData).
    pub config_dir: Option<PathBuf>,
    /// `dirs::data_local_dir()` (Local AppData).
    pub local_dir: Option<PathBuf>,
    /// Current directory, for relative `flag` / `env` values.
    pub cwd: Option<PathBuf>,
    /// File-existence test (the real file system, or a fake in tests).
    pub exists: &'a dyn Fn(&Path) -> bool,
}

fn absolutize(p: &Path, cwd: Option<&Path>) -> PathBuf {
    let p = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match cwd {
            Some(c) => c.join(p),
            None => p.to_path_buf(),
        }
    };
    sys::strip_verbatim(&p)
}

/// Portable root for an exe path: the exe's folder, or for `wolm.exe` inside `bin\` next to
/// `wol-manager.exe`, the parent folder. Pure (uses `exists`).
pub fn portable_root(exe: &Path, exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let dir = exe.parent()?;
    let is_cli = exe
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|n| n.eq_ignore_ascii_case(consts::CLI_EXE));
    if is_cli {
        let in_bin = dir
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|n| n.eq_ignore_ascii_case(consts::CLI_SUBDIR));
        if in_bin
            && let Some(parent) = dir.parent()
            && exists(&parent.join(consts::GUI_EXE))
        {
            return Some(parent.to_path_buf());
        }
    }
    Some(dir.to_path_buf())
}

/// The marker file in `root`, if any (`wol-manager.portable` preferred over `.portable.txt`).
pub fn find_marker(root: &Path, exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    [consts::PORTABLE_MARKER, consts::PORTABLE_MARKER_ALT]
        .iter()
        .map(|m| root.join(m))
        .find(|p| exists(p))
}

/// Resolves the location from explicit inputs. Pure. Errors: [`Error::NoConfigDir`] when
/// AppData is needed but unknown.
pub fn resolve_with(inp: &ResolveInputs<'_>) -> Result<ConfigLocation> {
    let cwd = inp.cwd.as_deref();
    let root = inp.exe.and_then(|e| portable_root(e, inp.exists));
    let marker = root.as_deref().and_then(|r| find_marker(r, inp.exists));
    let installed = root
        .as_deref()
        .is_some_and(|r| (inp.exists)(&r.join(consts::INSTALLED_SENTINEL)));

    let custom = |dir: PathBuf, source| ConfigLocation {
        local_dir: dir.clone(),
        dir,
        source,
        portable_root: root.clone(),
        marker_path: marker.clone(),
        marker_ignored: false,
    };

    if let Some(f) = inp.flag.filter(|f| !f.as_os_str().is_empty()) {
        return Ok(custom(absolutize(f, cwd), ConfigSource::Flag));
    }
    if let Some(e) = inp.env
        && !e.to_string_lossy().trim().is_empty()
    {
        let p = PathBuf::from(e.to_string_lossy().trim());
        return Ok(custom(absolutize(&p, cwd), ConfigSource::Env));
    }
    if let (Some(r), Some(_)) = (&root, &marker)
        && !installed
    {
        let data = r.join(consts::PORTABLE_DATA_DIR);
        return Ok(ConfigLocation {
            local_dir: data.clone(),
            dir: data,
            source: ConfigSource::Portable,
            portable_root: root.clone(),
            marker_path: marker.clone(),
            marker_ignored: false,
        });
    }
    let dir = inp
        .config_dir
        .as_ref()
        .ok_or(Error::NoConfigDir)?
        .join(consts::APP_DIR_NAME);
    let local_dir = inp
        .local_dir
        .as_ref()
        .map(|d| d.join(consts::APP_DIR_NAME))
        .unwrap_or_else(|| dir.clone());
    Ok(ConfigLocation {
        dir,
        local_dir,
        source: ConfigSource::AppData,
        portable_root: root.clone(),
        marker_ignored: marker.is_some() && installed,
        marker_path: marker,
    })
}

/// Resolves the location for this process: `flag`, then `WOL_MANAGER_CONFIG_DIR`, then the
/// portable marker next to the running exe, then AppData. Touches the file system only to
/// test for the marker / `uninstall.exe` / `wol-manager.exe`; creates nothing.
pub fn resolve(flag: Option<&Path>) -> Result<ConfigLocation> {
    let env = std::env::var_os(consts::ENV_CONFIG_DIR);
    let exe = sys::exe_path().ok();
    let exists = |p: &Path| p.exists();
    resolve_with(&ResolveInputs {
        flag,
        env: env.as_deref(),
        exe: exe.as_deref(),
        config_dir: dirs::config_dir(),
        local_dir: dirs::data_local_dir(),
        cwd: std::env::current_dir().ok(),
        exists: &exists,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    struct Fs(HashSet<PathBuf>);
    impl Fs {
        fn new(files: &[&str]) -> Fs {
            Fs(files.iter().map(PathBuf::from).collect())
        }
        fn exists(&self, p: &Path) -> bool {
            self.0.contains(p)
        }
    }

    fn inputs<'a>(
        fs: &'a dyn Fn(&Path) -> bool,
        exe: &'a Path,
        flag: Option<&'a Path>,
        env: Option<&'a OsStr>,
    ) -> ResolveInputs<'a> {
        ResolveInputs {
            flag,
            env,
            exe: Some(exe),
            config_dir: Some(PathBuf::from(r"C:\Users\u\AppData\Roaming")),
            local_dir: Some(PathBuf::from(r"C:\Users\u\AppData\Local")),
            cwd: Some(PathBuf::from(r"C:\work")),
            exists: fs,
        }
    }

    #[test]
    fn appdata_by_default() {
        let fs = Fs::new(&[]);
        let ex = |p: &Path| fs.exists(p);
        let exe = Path::new(r"D:\Tools\wol\wol-manager.exe");
        let l = resolve_with(&inputs(&ex, exe, None, None)).unwrap();
        assert_eq!(l.source, ConfigSource::AppData);
        assert_eq!(
            l.dir,
            PathBuf::from(r"C:\Users\u\AppData\Roaming\wol-manager")
        );
        assert_eq!(
            l.local_dir,
            PathBuf::from(r"C:\Users\u\AppData\Local\wol-manager")
        );
        assert_eq!(l.portable_root, Some(PathBuf::from(r"D:\Tools\wol")));
        assert!(!l.marker_ignored);
        assert_eq!(
            l.config_file(),
            PathBuf::from(r"C:\Users\u\AppData\Roaming\wol-manager\config.toml")
        );
        assert_eq!(
            l.gui_state_file(),
            PathBuf::from(r"C:\Users\u\AppData\Local\wol-manager\gui-state.toml")
        );
    }

    #[test]
    fn order_flag_env_portable_appdata() {
        let fs = Fs::new(&[r"D:\Tools\wol\wol-manager.portable"]);
        let ex = |p: &Path| fs.exists(p);
        let exe = Path::new(r"D:\Tools\wol\wol-manager.exe");
        let env = OsStr::new(r"E:\env-dir");
        let flag = Path::new(r"F:\flag-dir");

        let l = resolve_with(&inputs(&ex, exe, Some(flag), Some(env))).unwrap();
        assert_eq!(
            (l.source, l.dir.clone()),
            (ConfigSource::Flag, PathBuf::from(r"F:\flag-dir"))
        );
        assert_eq!(l.local_dir, l.dir);
        assert!(l.is_custom());

        let l = resolve_with(&inputs(&ex, exe, None, Some(env))).unwrap();
        assert_eq!(
            (l.source, l.dir.clone()),
            (ConfigSource::Env, PathBuf::from(r"E:\env-dir"))
        );

        let blank = OsStr::new("  ");
        let l = resolve_with(&inputs(&ex, exe, None, Some(blank))).unwrap();
        assert_eq!(l.source, ConfigSource::Portable);
        assert_eq!(l.dir, PathBuf::from(r"D:\Tools\wol\data"));
        assert_eq!(l.local_dir, l.dir);
        assert!(l.is_portable());

        let fs2 = Fs::new(&[]);
        let ex2 = |p: &Path| fs2.exists(p);
        let l = resolve_with(&inputs(&ex2, exe, None, None)).unwrap();
        assert_eq!(l.source, ConfigSource::AppData);
    }

    #[test]
    fn relative_flag_is_made_absolute() {
        let fs = Fs::new(&[]);
        let ex = |p: &Path| fs.exists(p);
        let exe = Path::new(r"D:\Tools\wol\wol-manager.exe");
        let l = resolve_with(&inputs(&ex, exe, Some(Path::new(r".cache\dev")), None)).unwrap();
        assert_eq!(l.dir, PathBuf::from(r"C:\work\.cache\dev"));
    }

    #[test]
    fn txt_marker_is_accepted() {
        let fs = Fs::new(&[r"D:\Tools\wol\wol-manager.portable.txt"]);
        let ex = |p: &Path| fs.exists(p);
        let exe = Path::new(r"D:\Tools\wol\wol-manager.exe");
        let l = resolve_with(&inputs(&ex, exe, None, None)).unwrap();
        assert_eq!(l.source, ConfigSource::Portable);
        assert_eq!(
            l.marker_path,
            Some(PathBuf::from(r"D:\Tools\wol\wol-manager.portable.txt"))
        );
    }

    #[test]
    fn wolm_in_bin_uses_parent_root() {
        let fs = Fs::new(&[
            r"D:\Tools\wol\wol-manager.exe",
            r"D:\Tools\wol\wol-manager.portable",
        ]);
        let ex = |p: &Path| fs.exists(p);
        let exe = Path::new(r"D:\Tools\wol\BIN\wolm.exe");
        let l = resolve_with(&inputs(&ex, exe, None, None)).unwrap();
        assert_eq!(l.source, ConfigSource::Portable);
        assert_eq!(l.dir, PathBuf::from(r"D:\Tools\wol\data"));
        assert_eq!(l.portable_root, Some(PathBuf::from(r"D:\Tools\wol")));
    }

    #[test]
    fn wolm_in_bin_without_gui_uses_own_folder() {
        let fs = Fs::new(&[r"D:\Tools\wol\wol-manager.portable"]);
        let ex = |p: &Path| fs.exists(p);
        let exe = Path::new(r"D:\Tools\wol\bin\wolm.exe");
        let l = resolve_with(&inputs(&ex, exe, None, None)).unwrap();
        assert_eq!(l.portable_root, Some(PathBuf::from(r"D:\Tools\wol\bin")));
        assert_eq!(l.source, ConfigSource::AppData);
    }

    #[test]
    fn wolm_outside_bin_uses_own_folder() {
        let fs = Fs::new(&[
            r"D:\Tools\wol-manager.exe",
            r"D:\Tools\cli\wol-manager.portable",
        ]);
        let ex = |p: &Path| fs.exists(p);
        let exe = Path::new(r"D:\Tools\cli\wolm.exe");
        let l = resolve_with(&inputs(&ex, exe, None, None)).unwrap();
        assert_eq!(l.portable_root, Some(PathBuf::from(r"D:\Tools\cli")));
        assert_eq!(l.dir, PathBuf::from(r"D:\Tools\cli\data"));
    }

    #[test]
    fn gui_exe_in_bin_does_not_use_parent() {
        let fs = Fs::new(&[r"D:\x\wol-manager.exe"]);
        let ex = |p: &Path| fs.exists(p);
        let root = portable_root(Path::new(r"D:\x\bin\wol-manager.exe"), &ex);
        assert_eq!(root, Some(PathBuf::from(r"D:\x\bin")));
    }

    #[test]
    fn installed_copy_ignores_marker() {
        let fs = Fs::new(&[
            r"C:\Program Files\WoL Manager\wol-manager.exe",
            r"C:\Program Files\WoL Manager\uninstall.exe",
            r"C:\Program Files\WoL Manager\wol-manager.portable",
        ]);
        let ex = |p: &Path| fs.exists(p);
        for exe in [
            r"C:\Program Files\WoL Manager\wol-manager.exe",
            r"C:\Program Files\WoL Manager\bin\wolm.exe",
        ] {
            let l = resolve_with(&inputs(&ex, Path::new(exe), None, None)).unwrap();
            assert_eq!(l.source, ConfigSource::AppData, "{exe}");
            assert!(l.marker_ignored, "{exe}");
        }
        // Flag still wins and no warning is raised.
        let l = resolve_with(&inputs(
            &ex,
            Path::new(r"C:\Program Files\WoL Manager\wol-manager.exe"),
            Some(Path::new(r"D:\cfg")),
            None,
        ))
        .unwrap();
        assert_eq!(l.source, ConfigSource::Flag);
        assert!(!l.marker_ignored);
    }

    #[test]
    fn missing_appdata_is_an_error() {
        let fs = Fs::new(&[]);
        let ex = |p: &Path| fs.exists(p);
        let exe = Path::new(r"D:\wol-manager.exe");
        let mut i = inputs(&ex, exe, None, None);
        i.config_dir = None;
        assert!(matches!(resolve_with(&i), Err(Error::NoConfigDir)));
        i.config_dir = Some(PathBuf::from(r"C:\R"));
        i.local_dir = None;
        let l = resolve_with(&i).unwrap();
        assert_eq!(l.local_dir, l.dir);
    }

    #[test]
    fn real_resolve_with_flag_touches_nothing() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("not-created");
        let l = resolve(Some(&target)).unwrap();
        assert_eq!(l.dir, target);
        assert!(!target.exists());
    }
}
