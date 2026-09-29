//! Single instance (plan §7.4).
//!
//! * `CreateMutexW(GUI_MUTEX)` decides who is first.
//! * Both instances create the auto-reset events `GUI_SHOW_EVENT` / `GUI_QUIT_EVENT` with
//!   the SDDL `D:(A;;GA;;;OW)(A;;0x00100002;;;BA)(A;;0x00100002;;;SY)` so that elevated
//!   installers (Administrators, SYSTEM) may signal them (SYNCHRONIZE | EVENT_MODIFY_STATE).
//! * A second instance allows the first one to take the foreground, sets `show` (retrying
//!   20 × 100 ms) and exits; when it cannot, it tells the user.
//! * The first instance publishes its settings folder ([`publish_settings_dir`],
//!   `wol_core::instance`); a second instance for another folder tells the user and exits
//!   instead of showing the first one (main.rs).
//! * The first instance waits for `show` / `quit` on a thread and forwards them to the UI.

use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError, HANDLE, LocalFree,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateMutexW, EVENT_MODIFY_STATE, INFINITE, OpenEventW, SetEvent,
    WaitForMultipleObjects,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow};
use wol_core::consts::{GUI_MUTEX, GUI_QUIT_EVENT, GUI_SHOW_EVENT};
use wol_core::sys::to_wide;

/// DACL of the show / quit events.
pub const EVENT_SDDL: &str = "D:(A;;GA;;;OW)(A;;0x00100002;;;BA)(A;;0x00100002;;;SY)";

/// An owned kernel handle.
struct Handle(HANDLE);

// SAFETY: kernel object handles may be used from any thread.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: we own the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Result of [`acquire`].
pub enum Instance {
    /// This is the first instance; keep the guard alive until exit.
    First(Guard),
    /// Another instance runs (maybe as another user / elevated).
    Second,
}

/// Held by the first instance: the mutex and both events.
pub struct Guard {
    _mutex: Handle,
    show: Handle,
    quit: Handle,
    stop: Handle,
    waiter: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn create_event(name: Option<&str>) -> Option<Handle> {
    let wide = name.map(to_wide);
    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let sddl = to_wide(EVENT_SDDL);
    // SAFETY: valid strings; `psd` is freed with LocalFree after CreateEventW copied it.
    unsafe {
        let have_sd = name.is_some()
            && ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            ) != 0;
        if name.is_some() && !have_sd {
            log::warn!(
                "SDDL conversion failed ({}); using the default DACL",
                GetLastError()
            );
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        let h = CreateEventW(
            if have_sd { &sa } else { std::ptr::null() },
            0, // auto-reset (the stop event is only set once, at exit)
            0,
            wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr()),
        );
        if !psd.is_null() {
            LocalFree(psd);
        }
        (!h.is_null()).then_some(Handle(h))
    }
}

/// Decides whether this process is the first GUI instance.
pub fn acquire() -> Instance {
    let name = to_wide(GUI_MUTEX);
    // SAFETY: valid name; the handle is owned by the guard.
    let (h, err) = unsafe {
        let h = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
        (h, GetLastError())
    };
    if h.is_null() {
        // ERROR_ACCESS_DENIED: the mutex exists but belongs to another security context.
        log::info!("CreateMutexW failed ({err}); another instance is running");
        return Instance::Second;
    }
    let mutex = Handle(h);
    if err == ERROR_ALREADY_EXISTS {
        return Instance::Second;
    }
    let (Some(show), Some(quit), Some(stop)) = (
        create_event(Some(GUI_SHOW_EVENT)),
        create_event(Some(GUI_QUIT_EVENT)),
        create_event(None),
    ) else {
        // Still the only instance; it just cannot be signalled.
        log::warn!("cannot create the show / quit events");
        let dummy = || create_event(None).unwrap_or(Handle(std::ptr::null_mut()));
        return Instance::First(Guard {
            _mutex: mutex,
            show: dummy(),
            quit: dummy(),
            stop: dummy(),
            waiter: Default::default(),
        });
    };
    Instance::First(Guard {
        _mutex: mutex,
        show,
        quit,
        stop,
        waiter: Default::default(),
    })
}

/// The published settings folder of this (first) instance; lives until the process exits.
static BEACON: std::sync::Mutex<Option<wol_core::instance::SettingsBeacon>> =
    std::sync::Mutex::new(None);

/// First instance: publishes (or updates, after a portable-mode switch) the settings folder
/// in use, so that a start for other settings is refused instead of showing this window.
pub fn publish_settings_dir(dir: &std::path::Path) {
    let mut b = BEACON.lock().unwrap_or_else(|p| p.into_inner());
    match b.as_mut() {
        Some(beacon) => beacon.update(dir),
        None => {
            *b = wol_core::instance::SettingsBeacon::create(dir);
            if b.is_none() {
                log::warn!("cannot publish the settings folder for other instances");
            }
        }
    }
}

/// Second instance: asks the first one to show its window. Returns `false` when it could not
/// be signalled (then tell the user: it runs as another user or elevated).
pub fn signal_first() -> bool {
    let name = to_wide(GUI_SHOW_EVENT);
    // SAFETY: plain calls.
    unsafe { AllowSetForegroundWindow(ASFW_ANY) };
    for attempt in 0..20 {
        // Like the installer: open with EVENT_MODIFY_STATE only.
        // SAFETY: valid name; the handle is closed by `Handle`.
        let opened = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
        // SAFETY: plain call.
        let err = unsafe { GetLastError() };
        let ev = if !opened.is_null() {
            Some(Handle(opened))
        } else if err == ERROR_FILE_NOT_FOUND {
            // The first instance has not created it yet: create it; it stays signalled.
            create_event(Some(GUI_SHOW_EVENT))
        } else {
            None
        };
        // SAFETY: valid handle.
        if let Some(ev) = ev
            && unsafe { SetEvent(ev.0) } != 0
        {
            return true;
        }
        log::debug!("signalling the first instance failed (attempt {attempt}, error {err})");
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// What the waiter thread observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Show the window.
    Show,
    /// Quit (installer).
    Quit,
}

impl Guard {
    /// Starts the waiter thread; `on_signal` runs on that thread for each signal.
    pub fn spawn_waiter(&self, on_signal: impl Fn(Signal) + Send + 'static) {
        let handles = [
            self.show.0 as usize,
            self.quit.0 as usize,
            self.stop.0 as usize,
        ];
        if handles.contains(&0) {
            return;
        }
        let r = std::thread::Builder::new()
            .name("instance-waiter".into())
            .spawn(move || {
                let hs: [HANDLE; 3] = handles.map(|h| h as HANDLE);
                loop {
                    // SAFETY: the handles stay open while the guard lives; the stop event is
                    // set before the guard is dropped.
                    let r = unsafe { WaitForMultipleObjects(3, hs.as_ptr(), 0, INFINITE) };
                    match r.wrapping_sub(WAIT_OBJECT_0) {
                        0 => on_signal(Signal::Show),
                        1 => {
                            on_signal(Signal::Quit);
                            break;
                        }
                        _ => break,
                    }
                }
            });
        match r {
            Ok(j) => {
                if let Ok(mut w) = self.waiter.lock() {
                    *w = Some(j);
                }
            }
            Err(e) => log::error!("cannot start the instance waiter: {e}"),
        }
    }

    /// Stops the waiter thread (call before dropping the guard).
    pub fn stop_waiter(&self) {
        if !self.stop.0.is_null() {
            // SAFETY: valid handle.
            unsafe { SetEvent(self.stop.0) };
            // Wait until the thread left WaitForMultipleObjects before the handles close.
            let j = self.waiter.lock().ok().and_then(|mut w| w.take());
            if let Some(j) = j {
                let _ = j.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_parses() {
        let sddl = to_wide(EVENT_SDDL);
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: test of the Win32 conversion; freed below.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
        assert!(!psd.is_null());
        // SAFETY: allocated by the call above.
        unsafe { LocalFree(psd) };
    }

    #[test]
    fn unnamed_events_work() {
        let e = create_event(None).unwrap();
        // SAFETY: valid handle.
        assert_ne!(unsafe { SetEvent(e.0) }, 0);
    }
}
