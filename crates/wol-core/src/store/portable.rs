//! Portable mode: the `wol-manager.portable` marker next to `wol-manager.exe` moves the
//! settings to `<root>\data\`. Installed copies (`uninstall.exe` present) refuse it.
//!
//! After [`enable`] / [`disable`], re-resolve the location ([`super::location::resolve`]) and
//! create a new [`super::Store`]. The GUI runs these on its store thread after pending writes.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{ConfigLocation, lock_dir, write_error, write_file_atomic};
use crate::consts;
use crate::error::{Error, Result};
use crate::pathenv::Scope;
use crate::sys;

use super::location;

/// Portable-mode facts about an exe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortableStatus {
    /// Portable root (exe folder, or the parent of `bin\` for `wolm.exe`).
    pub root: PathBuf,
    /// A marker file exists in `root`.
    pub marker_present: bool,
    /// The marker file found, if any.
    pub marker_path: Option<PathBuf>,
    /// `uninstall.exe` exists in `root` (installed copy; portable mode unavailable).
    pub installed: bool,
    /// Install scope from the uninstall registry key, for installed copies.
    pub install_scope: Option<Scope>,
    /// `<root>\data`.
    pub data_dir: PathBuf,
    /// `data_dir` exists.
    pub data_exists: bool,
    /// `data_dir` (or `root` when `data` does not exist yet) is writable. Always `false` for
    /// installed copies (not probed).
    pub data_writable: bool,
    /// Marker present and not installed: settings are in `data_dir`, unless a flag or
    /// `WOL_MANAGER_CONFIG_DIR` overrides it.
    pub active: bool,
}

impl PortableStatus {
    /// Portable mode can be switched on or off here (the GUI switch's enabled state).
    pub fn can_toggle(&self) -> bool {
        !self.installed && self.data_writable
    }
}

/// Reads the install scope of an installed copy from
/// `HKCU|HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\wol-manager` (value
/// `InstallLocation` equal to `root`). Read-only registry access.
pub fn install_scope(root: &Path) -> Option<Scope> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    let key = format!(
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{}",
        consts::UNINSTALL_KEY_NAME
    );
    let norm = |p: &str| {
        p.trim()
            .trim_matches('"')
            .trim_end_matches('\\')
            .to_lowercase()
    };
    let want = norm(&root.to_string_lossy());
    for (hive, scope) in [
        (HKEY_CURRENT_USER, Scope::User),
        (HKEY_LOCAL_MACHINE, Scope::Machine),
    ] {
        let Ok(k) = RegKey::predef(hive).open_subkey_with_flags(&key, KEY_READ) else {
            continue;
        };
        if let Ok(loc) = k.get_value::<String, _>("InstallLocation")
            && norm(&loc) == want
        {
            return Some(scope);
        }
    }
    None
}

fn status_with(exe_path: &Path, probe_registry: bool) -> PortableStatus {
    let exists = |p: &Path| p.exists();
    let root = location::portable_root(exe_path, &exists).unwrap_or_else(|| exe_path.to_path_buf());
    let marker_path = location::find_marker(&root, &exists);
    let installed = root.join(consts::INSTALLED_SENTINEL).exists();
    let data_dir = root.join(consts::PORTABLE_DATA_DIR);
    let data_exists = data_dir.is_dir();
    let data_writable = !installed
        && if data_exists {
            sys::dir_is_writable(&data_dir)
        } else {
            sys::dir_is_writable(&root)
        };
    PortableStatus {
        install_scope: if installed && probe_registry {
            install_scope(&root)
        } else {
            None
        },
        marker_present: marker_path.is_some(),
        active: marker_path.is_some() && !installed,
        marker_path,
        installed,
        data_dir,
        data_exists,
        data_writable,
        root,
    }
}

/// Portable facts for an exe (usually [`sys::exe_path`]). **Blocking** briefly (file
/// checks, a write test in the root, a registry read for installed copies).
pub fn status(exe_path: &Path) -> PortableStatus {
    status_with(exe_path, true)
}

/// Whether to bring the current settings into `data\` when enabling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopySettings {
    /// Do not copy.
    No,
    /// Copy `config.toml` from this folder unless `data\config.toml` already exists.
    IfMissing(PathBuf),
    /// Copy `config.toml` from this folder, replacing an existing `data\config.toml`
    /// (the old one goes to `config.toml.bak`).
    Overwrite(PathBuf),
}

/// Result of [`enable`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnableReport {
    /// Status after enabling.
    pub status: PortableStatus,
    /// The marker written.
    pub marker: PathBuf,
    /// Settings were copied into `data\`.
    pub copied: bool,
    /// `data\config.toml` already existed and was kept (with [`CopySettings::IfMissing`]).
    pub kept_existing: bool,
}

/// Copies `config.toml` from `src_dir` to `dst_dir` under both locks. Returns whether it
/// copied.
fn copy_config(src_dir: &Path, dst_dir: &Path, overwrite: bool) -> Result<(bool, bool)> {
    let src = ConfigLocation::custom(src_dir);
    let dst = ConfigLocation::custom(dst_dir);
    if !src.config_file().is_file() {
        return Ok((false, false));
    }
    if src_dir == dst_dir {
        return Ok((false, true));
    }
    let _dst_lock = lock_dir(dst_dir, &dst.lock_file())?;
    let dst_exists = dst.config_file().is_file();
    if dst_exists && !overwrite {
        return Ok((false, true));
    }
    // Lock the source when possible (it may be on read-only media).
    let _src_lock = lock_dir(src_dir, &src.lock_file()).ok();
    let bytes = fs::read(src.config_file()).map_err(|e| Error::io("read", src.config_file(), e))?;
    if dst_exists {
        let _ = fs::copy(dst.config_file(), dst.backup_file());
    }
    write_file_atomic(&dst.config_file(), &bytes)?;
    Ok((true, false))
}

/// Turns portable mode on: creates `<root>\data`, optionally copies the settings, then
/// writes the canonical marker `wol-manager.portable` (last, so a failure leaves no marker).
///
/// Errors: [`Error::InstalledCopyRefusesPortable`], [`Error::PortableNotWritable`],
/// [`Error::LockTimeout`], [`Error::Io`]. **Blocking** (file I/O, lock waits).
pub fn enable(exe_path: &Path, copy: CopySettings) -> Result<EnableReport> {
    let st = status_with(exe_path, false);
    if st.installed {
        return Err(Error::InstalledCopyRefusesPortable { root: st.root });
    }
    fs::create_dir_all(&st.data_dir)
        .map_err(|e| write_error("create folder", &st.root, &st.data_dir, e))?;
    let (copied, kept_existing) = match &copy {
        CopySettings::No => (false, false),
        CopySettings::IfMissing(src) => copy_config(src, &st.data_dir, false)?,
        CopySettings::Overwrite(src) => copy_config(src, &st.data_dir, true)?,
    };
    let marker = st.root.join(consts::PORTABLE_MARKER);
    if !marker.exists() {
        fs::write(&marker, b"").map_err(|e| write_error("write", &st.root, &marker, e))?;
    }
    Ok(EnableReport {
        status: status_with(exe_path, false),
        marker,
        copied,
        kept_existing,
    })
}

/// Turns portable mode off by deleting both marker names. `data\` is kept. Returns `true`
/// when a marker was removed.
///
/// Errors: [`Error::PortableNotWritable`], [`Error::Io`].
pub fn disable(exe_path: &Path) -> Result<bool> {
    let st = status_with(exe_path, false);
    let mut removed = false;
    for name in [consts::PORTABLE_MARKER, consts::PORTABLE_MARKER_ALT] {
        let p = st.root.join(name);
        match fs::remove_file(&p) {
            Ok(()) => removed = true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(write_error("delete", &st.root, &p, e)),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn layout(installed: bool) -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("wol");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("wol-manager.exe"), b"").unwrap();
        fs::write(root.join("bin").join("wolm.exe"), b"").unwrap();
        if installed {
            fs::write(root.join("uninstall.exe"), b"").unwrap();
        }
        (t, root)
    }

    #[test]
    fn status_enable_disable() {
        let (_t, root) = layout(false);
        let gui = root.join("wol-manager.exe");
        let cli = root.join("bin").join("wolm.exe");
        let st = status(&cli);
        assert_eq!(st.root, root);
        assert!(!st.marker_present && !st.active && !st.installed);
        assert!(st.data_writable);
        assert!(st.can_toggle());

        let rep = enable(&cli, CopySettings::No).unwrap();
        assert!(rep.status.active);
        assert_eq!(rep.marker, root.join("wol-manager.portable"));
        assert!(root.join("data").is_dir());
        assert!(status(&gui).active);

        assert!(disable(&gui).unwrap());
        assert!(!disable(&gui).unwrap());
        assert!(!status(&gui).marker_present);
        assert!(root.join("data").is_dir(), "data is kept");
    }

    #[test]
    fn disable_removes_txt_marker_too() {
        let (_t, root) = layout(false);
        fs::write(root.join("wol-manager.portable.txt"), b"").unwrap();
        assert!(status(&root.join("wol-manager.exe")).active);
        assert!(disable(&root.join("wol-manager.exe")).unwrap());
        assert!(!root.join("wol-manager.portable.txt").exists());
    }

    #[test]
    fn installed_copy_refuses() {
        let (_t, root) = layout(true);
        let gui = root.join("wol-manager.exe");
        // No registry lookup in tests (status() would read the uninstall key).
        let st = status_with(&gui, false);
        assert!(st.installed);
        assert_eq!(st.install_scope, None);
        assert!(!st.data_writable);
        assert!(!st.can_toggle());
        let e = enable(&gui, CopySettings::No).unwrap_err();
        assert!(matches!(e, Error::InstalledCopyRefusesPortable { .. }));
        assert_eq!(e.kind(), crate::ErrorKind::Unsupported);
        assert!(!root.join("wol-manager.portable").exists());
        assert!(!root.join("data").exists());
    }

    #[test]
    fn enable_copies_settings() {
        let (t, root) = layout(false);
        let appdata = t.path().join("appdata");
        let src = Store::new(ConfigLocation::custom(&appdata));
        src.update(|c| {
            c.settings.wake.repeat = 7;
            Ok(())
        })
        .unwrap();
        let rep = enable(
            &root.join("wol-manager.exe"),
            CopySettings::IfMissing(appdata.clone()),
        )
        .unwrap();
        assert!(rep.copied);
        let dst = Store::new(ConfigLocation::custom(root.join("data")));
        assert_eq!(dst.load().unwrap().config.settings.wake.repeat, 7);

        // Existing data is kept with IfMissing, replaced with Overwrite.
        src.update(|c| {
            c.settings.wake.repeat = 2;
            Ok(())
        })
        .unwrap();
        let rep = enable(
            &root.join("wol-manager.exe"),
            CopySettings::IfMissing(appdata.clone()),
        )
        .unwrap();
        assert!(!rep.copied && rep.kept_existing);
        assert_eq!(dst.load().unwrap().config.settings.wake.repeat, 7);
        let rep = enable(
            &root.join("wol-manager.exe"),
            CopySettings::Overwrite(appdata),
        )
        .unwrap();
        assert!(rep.copied);
        assert_eq!(dst.load().unwrap().config.settings.wake.repeat, 2);
        assert!(root.join("data").join("config.toml.bak").exists());
    }
}
