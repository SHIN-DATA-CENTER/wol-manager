//! Hidden top-level helper window: session end and Explorer restarts (plan §7.3, §7.4).
//!
//! * Windows ends a session (logoff, shutdown, restart, Restart Manager) with
//!   `WM_QUERYENDSESSION` / `WM_ENDSESSION` sent to top-level windows, never with `WM_CLOSE`.
//!   Neither winit nor Slint handles them, and hooking winit's window is no option: Slint
//!   creates it on demand, so a start-in-tray session may not have it.
//! * Explorer announces a new taskbar with the broadcast `TaskbarCreated`. Slint's tray
//!   window is message-only and never receives broadcasts, so the icon is not re-added.
//!
//! This window (own class, `WS_POPUP`, never shown) is created on the UI thread, so winit's
//! message pump (`PeekMessageW(NULL, ..)`) dispatches its messages like those of any other
//! window of the thread.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    ChangeWindowMessageFilterEx, CreateWindowExW, DefWindowProcW, DestroyWindow,
    ENDSESSION_CLOSEAPP, ENDSESSION_CRITICAL, ENDSESSION_LOGOFF, GUI_INMENUMODE, GUI_POPUPMENUMODE,
    GUITHREADINFO, GetGUIThreadInfo, MSGFLT_ALLOW, RegisterClassExW, RegisterWindowMessageW,
    WM_CLOSE, WM_ENDSESSION, WM_QUERYENDSESSION, WNDCLASSEXW, WS_POPUP,
};
use wol_core::sys::to_wide;

/// Window class of the helper window.
pub const CLASS_NAME: &str = "WoLManagerSessionWindow";

/// What the helper window observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// `WM_ENDSESSION` with `wParam = TRUE`: the session ends (the process may be terminated
    /// as soon as the handler returns). `flags` is `lParam` (`ENDSESSION_*`).
    Ending {
        /// `ENDSESSION_LOGOFF` / `ENDSESSION_CLOSEAPP` / `ENDSESSION_CRITICAL` (0 = shutdown or
        /// restart).
        flags: u32,
    },
    /// The taskbar was (re)created: tray icons must be added again.
    TaskbarCreated,
}

/// Human-readable reason of a session end (log).
pub fn describe_flags(flags: u32) -> &'static str {
    if flags & ENDSESSION_CLOSEAPP != 0 {
        "application close requested (Restart Manager)"
    } else if flags & ENDSESSION_LOGOFF != 0 {
        "logoff"
    } else if flags & ENDSESSION_CRITICAL != 0 {
        "critical shutdown"
    } else {
        "shutdown or restart"
    }
}

type Handler = Rc<dyn Fn(SessionEvent)>;

thread_local! {
    /// Handlers of the helper windows of this thread (normally one; tests create several).
    static HANDLERS: RefCell<Vec<(usize, Handler)>> = const { RefCell::new(Vec::new()) };
}

/// `RegisterWindowMessageW("TaskbarCreated")` (0 when it could not be registered).
pub fn taskbar_created_message() -> u32 {
    static MSG: OnceLock<u32> = OnceLock::new();
    *MSG.get_or_init(|| {
        let name = to_wide("TaskbarCreated");
        // SAFETY: valid NUL-terminated string.
        unsafe { RegisterWindowMessageW(name.as_ptr()) }
    })
}

/// `true` while a menu (the tray's context menu, the menu bar) runs its modal loop on this
/// thread. Messages dispatched from inside that loop must not destroy the menu's owner.
pub fn menu_open() -> bool {
    // SAFETY: plain call with a correctly sized struct.
    unsafe {
        let mut gti: GUITHREADINFO = std::mem::zeroed();
        gti.cbSize = std::mem::size_of::<GUITHREADINFO>() as u32;
        GetGUIThreadInfo(GetCurrentThreadId(), &mut gti) != 0
            && gti.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE) != 0
    }
}

fn register_class() -> Result<(), u32> {
    static REGISTERED: OnceLock<Result<(), u32>> = OnceLock::new();
    *REGISTERED.get_or_init(|| {
        let class = to_wide(CLASS_NAME);
        // SAFETY: the class name outlives the call (it is copied); `wnd_proc` is 'static.
        unsafe {
            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(wnd_proc),
                hInstance: GetModuleHandleW(std::ptr::null()),
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            if RegisterClassExW(&wc) == 0 {
                Err(GetLastError())
            } else {
                Ok(())
            }
        }
    })
}

fn handler_of(hwnd: HWND) -> Option<Handler> {
    HANDLERS.with(|h| {
        h.try_borrow().ok().and_then(|v| {
            v.iter()
                .find(|(w, _)| *w == hwnd as usize)
                .map(|(_, f)| f.clone())
        })
    })
}

fn dispatch(hwnd: HWND, ev: SessionEvent) {
    // The borrow of the handler list ends before the handler runs (it may pump messages).
    let Some(f) = handler_of(hwnd) else {
        return;
    };
    // A panic must not unwind into Windows (it would abort before anything is saved).
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(ev))).is_err() {
        log::error!("session event handler panicked ({ev:?})");
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        // Never veto: everything is saved in WM_ENDSESSION.
        WM_QUERYENDSESSION => return 1,
        // Only `Drop` destroys it (another program closing "WoL Manager" windows must not).
        WM_CLOSE => return 0,
        WM_ENDSESSION => {
            if wparam != 0 {
                dispatch(
                    hwnd,
                    SessionEvent::Ending {
                        flags: lparam as u32,
                    },
                );
            }
            return 0;
        }
        m if m != 0 && m == taskbar_created_message() => {
            dispatch(hwnd, SessionEvent::TaskbarCreated);
            return 0;
        }
        _ => {}
    }
    // SAFETY: default processing of a message for our own window.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// The helper window (UI thread only; destroyed on drop).
pub struct SessionWindow {
    hwnd: HWND,
    blocking: Cell<bool>,
}

impl SessionWindow {
    /// Creates the hidden window on the current thread; `handler` runs on this thread.
    /// Returns the Win32 error code on failure.
    pub fn create(handler: impl Fn(SessionEvent) + 'static) -> Result<SessionWindow, u32> {
        register_class()?;
        let taskbar = taskbar_created_message();
        let class = to_wide(CLASS_NAME);
        let title = to_wide(wol_core::consts::PRODUCT_NAME);
        // SAFETY: registered class, valid strings; a top-level (no parent) popup that is never
        // shown (so it is in no taskbar and no Alt+Tab list).
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                title.as_ptr(),
                WS_POPUP,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            )
        };
        if hwnd.is_null() {
            // SAFETY: plain call.
            return Err(unsafe { GetLastError() });
        }
        if taskbar != 0 {
            // An elevated instance would not get Explorer's broadcast through UIPI otherwise.
            // SAFETY: our window, registered message.
            unsafe {
                ChangeWindowMessageFilterEx(hwnd, taskbar, MSGFLT_ALLOW, std::ptr::null_mut())
            };
        }
        HANDLERS.with(|h| h.borrow_mut().push((hwnd as usize, Rc::new(handler))));
        Ok(SessionWindow {
            hwnd,
            blocking: Cell::new(false),
        })
    }

    /// Window handle.
    #[cfg(test)]
    pub fn hwnd(&self) -> HWND {
        self.hwnd
    }

    /// Shows `reason` in Windows' "apps are preventing shutdown" screen while it is `Some`
    /// (`ShutdownBlockReasonCreate`); `None` removes it.
    pub fn set_block_reason(&self, reason: Option<&str>) {
        match reason {
            Some(r) => {
                let w = to_wide(r);
                // SAFETY: our window, created on this thread; valid string.
                if unsafe { ShutdownBlockReasonCreate(self.hwnd, w.as_ptr()) } != 0 {
                    self.blocking.set(true);
                }
            }
            None => {
                if self.blocking.replace(false) {
                    // SAFETY: our window.
                    unsafe { ShutdownBlockReasonDestroy(self.hwnd) };
                }
            }
        }
    }
}

impl Drop for SessionWindow {
    fn drop(&mut self) {
        self.set_block_reason(None);
        let key = self.hwnd as usize;
        HANDLERS.with(|h| {
            if let Ok(mut v) = h.try_borrow_mut() {
                v.retain(|(w, _)| *w != key);
            }
        });
        // SAFETY: our window, destroyed on the thread that created it.
        unsafe { DestroyWindow(self.hwnd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GA_PARENT, GetAncestor, GetDesktopWindow, IsWindow, IsWindowVisible, SendMessageW,
    };

    fn recorder() -> (
        Rc<RefCell<Vec<SessionEvent>>>,
        impl Fn(SessionEvent) + 'static,
    ) {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let s = seen.clone();
        (seen, move |ev| s.borrow_mut().push(ev))
    }

    #[test]
    fn hidden_top_level_window() {
        let (_, f) = recorder();
        let w = SessionWindow::create(f).unwrap();
        // SAFETY: queries on our own window.
        unsafe {
            // Top-level (receives WM_QUERYENDSESSION and broadcasts), not message-only.
            assert_eq!(GetAncestor(w.hwnd(), GA_PARENT), GetDesktopWindow());
            assert_eq!(IsWindowVisible(w.hwnd()), 0);
            // Other programs cannot close it.
            SendMessageW(w.hwnd(), WM_CLOSE, 0, 0);
            assert_ne!(IsWindow(w.hwnd()), 0);
        }
    }

    #[test]
    fn session_end_is_reported_once_it_really_ends() {
        let (seen, f) = recorder();
        let w = SessionWindow::create(f).unwrap();
        let h = w.hwnd();
        // SAFETY: messages to our own window on this thread (dispatched synchronously).
        unsafe {
            // Never vetoes.
            assert_eq!(
                SendMessageW(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF as LPARAM),
                1
            );
            assert!(seen.borrow().is_empty());
            // Cancelled session end: nothing to do.
            SendMessageW(h, WM_ENDSESSION, 0, ENDSESSION_LOGOFF as LPARAM);
            assert!(seen.borrow().is_empty());
            SendMessageW(h, WM_ENDSESSION, 1, ENDSESSION_LOGOFF as LPARAM);
            SendMessageW(h, WM_ENDSESSION, 1, 0);
        }
        assert_eq!(
            *seen.borrow(),
            vec![
                SessionEvent::Ending {
                    flags: ENDSESSION_LOGOFF
                },
                SessionEvent::Ending { flags: 0 }
            ]
        );
    }

    #[test]
    fn taskbar_created_is_reported() {
        let msg = taskbar_created_message();
        assert_ne!(msg, 0);
        let (seen, f) = recorder();
        let w = SessionWindow::create(f).unwrap();
        let (seen2, f2) = recorder();
        let other = SessionWindow::create(f2).unwrap();
        // SAFETY: message to our own window on this thread.
        unsafe { SendMessageW(w.hwnd(), msg, 0, 0) };
        assert_eq!(*seen.borrow(), vec![SessionEvent::TaskbarCreated]);
        // Each window reports to its own handler only.
        assert!(seen2.borrow().is_empty());
        // Dropping a window unregisters its handler.
        let hwnd = other.hwnd();
        assert!(handler_of(hwnd).is_some());
        drop(other);
        assert!(handler_of(hwnd).is_none());
        assert!(handler_of(w.hwnd()).is_some());
    }

    #[test]
    fn a_panicking_handler_does_not_abort() {
        let w = SessionWindow::create(|_| panic!("boom")).unwrap();
        // SAFETY: message to our own window on this thread.
        unsafe { SendMessageW(w.hwnd(), WM_ENDSESSION, 1, 0) };
    }

    #[test]
    fn block_reason_round_trip() {
        let (_, f) = recorder();
        let w = SessionWindow::create(f).unwrap();
        w.set_block_reason(Some("saving"));
        w.set_block_reason(None);
        w.set_block_reason(None);
        assert!(!menu_open());
    }

    thread_local! {
        /// `menu_open()` as seen from inside a popup menu's modal loop.
        static SEEN_IN_MENU: Cell<Option<bool>> = const { Cell::new(None) };
    }

    unsafe extern "system" fn in_menu(_: HWND, _: u32, _: usize, _: u32) {
        use windows_sys::Win32::UI::WindowsAndMessaging::EndMenu;
        if SEEN_IN_MENU.with(|s| s.get()).is_none() {
            SEEN_IN_MENU.with(|s| s.set(Some(menu_open())));
        }
        // SAFETY: ends the menu of this thread.
        unsafe { EndMenu() };
    }

    #[test]
    fn menu_mode_is_detected() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            AppendMenuW, CreatePopupMenu, DestroyMenu, KillTimer, MF_STRING, SetTimer,
            TPM_RETURNCMD, TrackPopupMenu,
        };
        assert!(!menu_open());
        let (_, f) = recorder();
        let w = SessionWindow::create(f).unwrap();
        let item = to_wide("x");
        // SAFETY: a popup menu owned by our window; the timer (dispatched by the menu's modal
        // loop) records the state and ends the menu.
        unsafe {
            let menu = CreatePopupMenu();
            assert!(!menu.is_null());
            AppendMenuW(menu, MF_STRING, 1, item.as_ptr());
            SetTimer(w.hwnd(), 1, 30, Some(in_menu));
            TrackPopupMenu(menu, TPM_RETURNCMD, 0, 0, 0, w.hwnd(), std::ptr::null());
            KillTimer(w.hwnd(), 1);
            DestroyMenu(menu);
        }
        match SEEN_IN_MENU.with(|s| s.get()) {
            Some(seen) => assert!(seen, "menu mode not reported inside the menu loop"),
            // No interactive desktop: TrackPopupMenu returned at once.
            None => eprintln!("menu_mode_is_detected: no menu loop ran; skipped"),
        }
        assert!(!menu_open());
    }

    #[test]
    fn flag_descriptions() {
        assert_eq!(describe_flags(ENDSESSION_LOGOFF), "logoff");
        assert_eq!(
            describe_flags(ENDSESSION_CLOSEAPP),
            "application close requested (Restart Manager)"
        );
        assert_eq!(describe_flags(0), "shutdown or restart");
    }
}
