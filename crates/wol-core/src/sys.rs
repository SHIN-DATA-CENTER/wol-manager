//! Small Windows helpers shared by the GUI and the CLI.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetTokenInformation, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
    TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Console::GetConsoleProcessList;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// NUL-terminated UTF-16 for Win32 `PCWSTR` parameters.
pub fn to_wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// `true` when the current process token is elevated (UAC "Run as administrator", or UAC
/// disabled for an administrator). `false` if the token cannot be queried.
pub fn is_elevated() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle; `token` receives a real handle
    // that is closed below.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elev as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

/// Removes a `\\?\` (or `\\?\UNC\`) verbatim prefix, which `cmd.exe`, PowerShell and PATH
/// entries cannot use. Other paths are returned unchanged.
pub fn strip_verbatim(path: &Path) -> PathBuf {
    let is_verbatim = matches!(
        path.components().next(),
        Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(..))
    );
    if !is_verbatim {
        return path.to_path_buf();
    }
    let Some(s) = path.to_str() else {
        return path.to_path_buf();
    };
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => path.to_path_buf(),
    }
}

/// Absolute path of the running executable, without a verbatim prefix.
pub fn exe_path() -> io::Result<PathBuf> {
    std::env::current_exe().map(|p| strip_verbatim(&p))
}

/// Folder of the running executable (the default `wolm path add` directory).
pub fn exe_dir() -> io::Result<PathBuf> {
    let p = exe_path()?;
    p.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "executable has no parent folder"))
}

/// `wol-manager.exe` next to a `wolm.exe` (for `wolm gui`): `<dir>\..\wol-manager.exe` when
/// the CLI lives in `bin\`, else `<dir>\wol-manager.exe`. `None` when neither exists.
pub fn gui_exe_near(cli_exe: &Path) -> Option<PathBuf> {
    let dir = cli_exe.parent()?;
    let mut candidates = Vec::new();
    let in_bin = dir
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|n| n.eq_ignore_ascii_case(crate::consts::CLI_SUBDIR));
    if in_bin && let Some(parent) = dir.parent() {
        candidates.push(parent.join(crate::consts::GUI_EXE));
    }
    candidates.push(dir.join(crate::consts::GUI_EXE));
    candidates.into_iter().find(|p| p.is_file())
}

/// Number of processes attached to the current console (0 when there is no console).
/// `wolm` pauses on double-click only when this is 1, there are no arguments and stdin is a
/// console.
pub fn console_process_count() -> u32 {
    let mut ids = [0u32; 4];
    // SAFETY: the buffer holds 4 ids; the API returns the total count.
    unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) }
}

/// `true` when this process is the only one attached to its console (started by
/// double-click in Explorer).
pub fn console_is_exclusive() -> bool {
    console_process_count() == 1
}

/// `true` when `dir` exists and a file can be created in it. Creates and deletes a small
/// probe file (`.wol-manager-write-test-<pid>.tmp`). Does not create `dir`.
pub fn dir_is_writable(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!(
        ".wol-manager-write-test-{}.tmp",
        std::process::id()
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(f) => {
            drop(f);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Groups that stand for "every user of this computer": Everyone, Authenticated Users,
/// BUILTIN\Users, INTERACTIVE.
const ALL_USERS_SIDS: [&str; 4] = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4"];

/// Rights on a folder that let a user put, remove or rename files in it, or take it over:
/// FILE_ADD_FILE, FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL,
/// GENERIC_WRITE.
const DIR_WRITE_MASK: u32 = 0x2 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;
/// The same for the files inherited by the folder's new files: FILE_WRITE_DATA,
/// FILE_APPEND_DATA, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
const FILE_WRITE_MASK: u32 = 0x2 | 0x4 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;
/// `ACCESS_ALLOWED_ACE_TYPE`.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

/// `true` when every user of this computer may change the programs in `dir`: the folder has
/// no DACL (e.g. FAT32 / exFAT media), or an allow entry for Everyone, Authenticated Users,
/// Users or INTERACTIVE grants a right to add, delete or replace files in the folder, or one
/// that its new files inherit (the typical `Authenticated Users: Modify` of a folder created
/// directly under `C:\` or `D:\`). A folder that does not exist yet is judged by its nearest
/// existing parent. Deny entries and single accounts are not considered. `false` when the
/// permissions cannot be read.
pub fn writable_by_all_users(dir: &Path) -> bool {
    let Some(existing) = dir.ancestors().find(|p| p.exists()) else {
        return false;
    };
    let wide = to_wide(existing);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid path; `sd` owns the returned buffer (`dacl` points into it) and is freed
    // below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return false;
    }
    let sids: Vec<PSID> = ALL_USERS_SIDS
        .iter()
        .filter_map(|s| {
            let w = to_wide(s);
            let mut sid: PSID = std::ptr::null_mut();
            // SAFETY: valid string; the SID is freed with LocalFree below.
            (unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut sid) } != 0).then_some(sid)
        })
        .collect();
    // SAFETY: `dacl` is null (no DACL: everyone has full access) or a valid ACL inside `sd`;
    // GetAce returns pointers into it; SidStart is the start of the variable-length SID.
    let writable = dacl.is_null()
        || unsafe {
            (0..u32::from((*dacl).AceCount)).any(|i| {
                let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace) == 0 || ace.is_null() {
                    return false;
                }
                let header = &*(ace as *const ACE_HEADER);
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                    return false;
                }
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                let flags = u32::from(header.AceFlags);
                let on_dir = flags & INHERIT_ONLY_ACE == 0 && allowed.Mask & DIR_WRITE_MASK != 0;
                let on_files =
                    flags & OBJECT_INHERIT_ACE != 0 && allowed.Mask & FILE_WRITE_MASK != 0;
                if !on_dir && !on_files {
                    return false;
                }
                let ace_sid: PSID = (&allowed.SidStart as *const u32).cast_mut().cast();
                sids.iter().any(|s| EqualSid(ace_sid, *s) != 0)
            })
        };
    // SAFETY: allocated by the calls above.
    unsafe {
        for s in sids {
            LocalFree(s);
        }
        LocalFree(sd);
    }
    writable
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary folder in the user profile is private; granting Authenticated Users
    /// Modify (what folders directly under C:\ inherit) makes it shared.
    #[test]
    fn shared_folders_are_detected() {
        let t = tempfile::tempdir().unwrap();
        let private = t.path().join("private");
        std::fs::create_dir(&private).unwrap();
        assert!(!writable_by_all_users(&private));
        assert!(!writable_by_all_users(&private.join("not yet").join("bin")));
        let shared = t.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let st = std::process::Command::new("icacls")
            .arg(&shared)
            .args(["/grant", "*S-1-5-11:(OI)(CI)(IO)M", "/Q"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success());
        assert!(writable_by_all_users(&shared));
        assert!(writable_by_all_users(&shared.join("bin")));
    }

    #[test]
    fn verbatim_prefix_is_removed() {
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\C:\Program Files\WoL Manager\bin")),
            PathBuf::from(r"C:\Program Files\WoL Manager\bin")
        );
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\UNC\server\share\dir")),
            PathBuf::from(r"\\server\share\dir")
        );
        assert_eq!(
            strip_verbatim(Path::new(r"D:\x\y")),
            PathBuf::from(r"D:\x\y")
        );
    }

    #[test]
    fn wide_is_nul_terminated() {
        assert_eq!(to_wide("ab"), vec![b'a' as u16, b'b' as u16, 0]);
    }

    #[test]
    fn helpers_do_not_panic() {
        let _ = is_elevated();
        let _ = console_process_count();
        assert!(exe_dir().unwrap().is_dir());
        let t = tempfile::tempdir().unwrap();
        assert!(dir_is_writable(t.path()));
        assert!(!dir_is_writable(&t.path().join("missing")));
    }

    #[test]
    fn gui_exe_lookup() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        let cli = root.join("bin").join("wolm.exe");
        assert_eq!(gui_exe_near(&cli), None);
        std::fs::write(root.join("wol-manager.exe"), b"").unwrap();
        assert_eq!(gui_exe_near(&cli), Some(root.join("wol-manager.exe")));
        let flat = root.join("wolm.exe");
        assert_eq!(gui_exe_near(&flat), Some(root.join("wol-manager.exe")));
    }
}
