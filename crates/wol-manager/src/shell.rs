//! Small Windows helpers: opening folders / URLs / files without blocking the UI, message
//! boxes, the clipboard, and the window handle (bring to front).

use std::path::PathBuf;

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FLASHW_ALL, FLASHW_TIMERNOFG, FLASHWINFO, FlashWindowEx, IsIconic, MB_ICONERROR,
    MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND, MessageBoxW, SW_RESTORE, SW_SHOWNORMAL,
    SetForegroundWindow, ShowWindow,
};
use wol_core::sys::to_wide;

/// Modal message box (no owner window). Used before the UI exists and by the panic hook.
pub fn message_box(text: &str, error: bool) {
    let text = to_wide(text);
    let title = to_wide(wol_core::consts::PRODUCT_NAME);
    let icon = if error {
        MB_ICONERROR
    } else {
        MB_ICONINFORMATION
    };
    // SAFETY: valid NUL-terminated UTF-16 strings.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | icon | MB_SETFOREGROUND,
        );
    }
}

/// What to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A folder (Explorer).
    Folder(PathBuf),
    /// A file with its associated program.
    File(PathBuf),
    /// An http(s) URL in the default browser.
    Url(String),
}

/// `true` for URLs the GUI may open (http / https only).
pub fn is_web_url(url: &str) -> bool {
    let u = url.trim().to_ascii_lowercase();
    (u.starts_with("https://") || u.starts_with("http://")) && !u.contains(char::is_whitespace)
}

/// Opens `target` on a short-lived thread (ShellExecute may block on slow shell extensions
/// or network paths). `on_error` runs on that thread when opening failed.
pub fn open(target: Target, on_error: impl FnOnce() + Send + 'static) {
    let spawned = std::thread::Builder::new()
        .name("shell-open".into())
        .spawn(move || {
            if !open_blocking(&target) {
                log::warn!("could not open {target:?}");
                on_error();
            }
        });
    if let Err(e) = spawned {
        log::warn!("cannot start shell thread: {e}");
    }
}

fn open_blocking(target: &Target) -> bool {
    use windows_sys::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx,
    };
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let (verb, file) = match target {
        Target::Folder(p) => {
            if !p.is_dir() {
                let _ = std::fs::create_dir_all(p);
            }
            ("explore", p.as_os_str().to_owned())
        }
        Target::File(p) => ("open", p.as_os_str().to_owned()),
        Target::Url(u) => {
            if !is_web_url(u) {
                return false;
            }
            ("open", std::ffi::OsString::from(u.trim()))
        }
    };
    let verb = to_wide(verb);
    let file = to_wide(file);
    // SAFETY: COM init for this thread (ShellExecute may use COM); valid wide strings.
    unsafe {
        let _ = CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        );
        let r = ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
        // > 32 means success.
        r as isize > 32
    }
}

/// Copies text to the clipboard (UI thread only; arboard requirement on Windows).
pub fn copy_text(text: &str) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(text.to_owned()).map_err(|e| e.to_string())
}

/// HWND of a Slint window (after it was created by the event loop).
pub fn hwnd_of(window: &slint::Window) -> Option<HWND> {
    let handle = window.window_handle();
    let wh = handle.window_handle().ok()?;
    match wh.as_raw() {
        RawWindowHandle::Win32(w) => Some(w.hwnd.get() as HWND),
        _ => None,
    }
}

/// Restores and activates a window; flashes the taskbar button when Windows refuses the
/// foreground change. Returns `true` when it became the foreground window.
pub fn bring_to_front(hwnd: HWND) -> bool {
    // SAFETY: plain user32 calls on a window of this process.
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }
        if SetForegroundWindow(hwnd) != 0 {
            return true;
        }
        let fi = FLASHWINFO {
            cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
            hwnd,
            dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
            uCount: 3,
            dwTimeout: 0,
        };
        FlashWindowEx(&fi);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_web_urls() {
        assert!(is_web_url(
            "https://github.com/SHIN-DATA-CENTER/wol-manager"
        ));
        assert!(is_web_url("http://example.com"));
        assert!(!is_web_url("file:///C:/Windows"));
        assert!(!is_web_url("C:\\Windows\\notepad.exe"));
        assert!(!is_web_url("https://a b"));
        assert!(!is_web_url("javascript:alert(1)"));
    }
}
