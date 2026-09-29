//! Which settings folder the running GUI uses.
//!
//! The GUI is a single instance per session ([`consts::GUI_MUTEX`]). A second start only
//! brings up the running window, so a start that asks for another settings folder
//! (`--config-dir`, `WOL_MANAGER_CONFIG_DIR`, another portable copy) would silently show
//! other settings. The first instance therefore publishes its folder in a small named
//! shared-memory block ([`consts::GUI_SETTINGS_MAP`]); a second instance and `wolm gui`
//! compare it with their own folder and refuse to go on when they differ.
//!
//! Layout of the block: `u32` length in UTF-16 units, then the path (no terminator). The
//! block is created with the default security of the process, so only the same account can
//! read it; for another account the folder is simply unknown.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    OpenFileMappingW, PAGE_READWRITE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

use crate::consts;
use crate::sys::{self, to_wide};

/// Longest path that fits (UTF-16 units).
const MAX_UNITS: usize = 32_767;
/// Size of the shared block.
const MAP_BYTES: usize = 4 + MAX_UNITS * 2;

/// `true` while a WoL Manager GUI runs in this session (also one of another account or an
/// elevated one, whose mutex this process may not open).
pub fn gui_running() -> bool {
    let name = to_wide(consts::GUI_MUTEX);
    // SAFETY: valid name; the handle is closed right away.
    unsafe {
        let h = OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr());
        if !h.is_null() {
            CloseHandle(h);
            return true;
        }
        GetLastError() == ERROR_ACCESS_DENIED
    }
}

/// A mapped view of the shared block (unmapped and closed on drop).
struct View {
    map: HANDLE,
    addr: MEMORY_MAPPED_VIEW_ADDRESS,
}

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: both come from a successful MapViewOfFile / Create/OpenFileMappingW.
        unsafe {
            UnmapViewOfFile(self.addr);
            CloseHandle(self.map);
        }
    }
}

// SAFETY: the view is plain shared memory; access goes through `&mut self` (writer) or a
// short-lived local view (reader).
unsafe impl Send for View {}

impl View {
    fn write(&mut self, dir: &Path) {
        let units: Vec<u16> = dir.as_os_str().encode_wide().take(MAX_UNITS).collect();
        let base = self.addr.Value.cast::<u8>();
        // SAFETY: the view is MAP_BYTES long; `units` has at most MAX_UNITS entries. The
        // length is cleared first and written last, so a reader never sees a length that
        // runs past the path being written.
        unsafe {
            base.cast::<u32>().write_unaligned(0);
            std::ptr::copy_nonoverlapping(
                units.as_ptr().cast::<u8>(),
                base.add(4),
                units.len() * 2,
            );
            base.cast::<u32>().write_unaligned(units.len() as u32);
        }
    }

    fn read(&self) -> Option<PathBuf> {
        let base = self.addr.Value.cast::<u8>();
        // SAFETY: the view is MAP_BYTES long and the length is checked against it.
        unsafe {
            let len = base.cast::<u32>().read_unaligned() as usize;
            if len == 0 || len > MAX_UNITS {
                return None;
            }
            let mut units = vec![0u16; len];
            std::ptr::copy_nonoverlapping(base.add(4), units.as_mut_ptr().cast::<u8>(), len * 2);
            Some(PathBuf::from(OsString::from_wide(&units)))
        }
    }
}

/// Held by the running GUI: publishes its settings folder until dropped.
pub struct SettingsBeacon {
    view: View,
}

impl SettingsBeacon {
    /// Creates the shared block and writes `dir` into it. `None` when it cannot be created
    /// (then other starts cannot tell which folder is in use and behave as before).
    pub fn create(dir: &Path) -> Option<SettingsBeacon> {
        let name = to_wide(consts::GUI_SETTINGS_MAP);
        // SAFETY: a pagefile-backed mapping of MAP_BYTES with a valid name; the handle and
        // the view are owned by `View`.
        let view = unsafe {
            let map = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                MAP_BYTES as u32,
                name.as_ptr(),
            );
            if map.is_null() {
                return None;
            }
            let addr = MapViewOfFile(map, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, MAP_BYTES);
            if addr.Value.is_null() {
                CloseHandle(map);
                return None;
            }
            View { map, addr }
        };
        let mut beacon = SettingsBeacon { view };
        beacon.update(dir);
        Some(beacon)
    }

    /// Publishes a new folder (after a portable-mode switch).
    pub fn update(&mut self, dir: &Path) {
        self.view.write(&normalize(dir));
    }
}

/// Settings folder of the running GUI, when one runs in this session for this account and
/// publishes it.
pub fn running_gui_settings_dir() -> Option<PathBuf> {
    let name = to_wide(consts::GUI_SETTINGS_MAP);
    // SAFETY: valid name; the handle and the view are owned by `View`.
    let view = unsafe {
        let map = OpenFileMappingW(FILE_MAP_READ, 0, name.as_ptr());
        if map.is_null() {
            return None;
        }
        let addr = MapViewOfFile(map, FILE_MAP_READ, 0, 0, MAP_BYTES);
        if addr.Value.is_null() {
            CloseHandle(map);
            return None;
        }
        View { map, addr }
    };
    view.read()
}

/// Absolute, without a verbatim prefix and trailing separators.
fn normalize(dir: &Path) -> PathBuf {
    let abs = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let s = sys::strip_verbatim(&abs);
    let text = s.to_string_lossy();
    let trimmed = text.trim_end_matches(['\\', '/']);
    // Keep "C:\" (a bare "C:" would mean the current folder of drive C).
    if trimmed.len() == 2 && trimmed.ends_with(':') {
        return s;
    }
    PathBuf::from(trimmed)
}

/// `true` when `a` and `b` name the same folder: the same file-system object when both
/// exist, else the same absolute path compared case-insensitively.
pub fn same_dir(a: &Path, b: &Path) -> bool {
    if let (Ok(ca), Ok(cb)) = (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        return ca == cb;
    }
    let (na, nb) = (normalize(a), normalize(b));
    na.to_string_lossy().to_lowercase() == nb.to_string_lossy().to_lowercase()
}

/// The settings folder a new start would use, compared with the running GUI's: `Err` with
/// [`crate::Error::AppRunningWithOtherSettings`] when a GUI runs with another folder.
pub fn check_running_gui(requested: &Path) -> crate::Result<()> {
    match running_gui_settings_dir() {
        Some(running) if !same_dir(&running, requested) => {
            Err(crate::Error::AppRunningWithOtherSettings {
                running,
                requested: normalize(requested),
            })
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_compare_by_identity_or_by_path() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("A");
        std::fs::create_dir(&a).unwrap();
        assert!(same_dir(&a, &t.path().join("a")));
        assert!(same_dir(&a, &PathBuf::from(format!("{}\\", a.display()))));
        assert!(!same_dir(&a, t.path()));
        // Missing folders: by path, case-insensitively.
        assert!(same_dir(
            Path::new(r"C:\Missing\Wol"),
            Path::new(r"c:\missing\wol\")
        ));
        assert!(!same_dir(
            Path::new(r"C:\Missing\A"),
            Path::new(r"C:\Missing\B")
        ));
        assert_eq!(normalize(Path::new(r"C:\")), PathBuf::from(r"C:\"));
    }

    /// The block round-trips a Japanese path with spaces. Uses the real name only when no
    /// GUI runs (the tests never touch a running app).
    #[test]
    fn beacon_round_trip() {
        if gui_running() || running_gui_settings_dir().is_some() {
            return;
        }
        let dir = std::env::temp_dir().join("設定 フォルダ (テスト)");
        let mut b = SettingsBeacon::create(&dir).expect("create the shared block");
        assert_eq!(running_gui_settings_dir(), Some(normalize(&dir)));
        assert!(check_running_gui(&dir).is_ok());
        let other = std::env::temp_dir().join("other");
        assert!(matches!(
            check_running_gui(&other),
            Err(crate::Error::AppRunningWithOtherSettings { .. })
        ));
        b.update(&other);
        assert!(check_running_gui(&other).is_ok());
        drop(b);
        assert_eq!(running_gui_settings_dir(), None);
    }
}
