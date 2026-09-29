//! Notification-area icon (`AppTray`, plan §7.4, contract §8).
//!
//! Slint creates the Windows icon lazily (on the first event-loop iteration) and only logs
//! a failure, so availability is checked afterwards: the Shell's taskbar must exist and
//! Slint's hidden tray window (`SlintSystemTrayWindow`, created only when
//! `Shell_NotifyIconW(NIM_ADD)` succeeded) must belong to this process. That window is
//! message-only and misses the `TaskbarCreated` broadcast, so after an Explorer restart the
//! icon is created again from the session window (`crate::session`).

use std::rc::Rc;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, Timer, VecModel};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowExW, FindWindowW, GetSystemMetrics, GetWindowThreadProcessId, HWND_MESSAGE,
    SM_CXSMICON,
};
use wol_core::sys::to_wide;

use crate::app::{App, TrayState, with};
use crate::texts::Text;
use crate::{AppTray, NoticeKind, SettingsState, TrayHost};

/// How often and how long to wait for the icon (15 x 200 ms).
pub(crate) const TRAY_CHECKS: u32 = 15;
const TRAY_CHECK_INTERVAL: Duration = Duration::from_millis(200);

/// Maximum number of hosts in the "Wake host" submenu.
pub const MAX_TRAY_HOSTS: usize = 40;

/// `AppTray.icon-size` from `GetSystemMetrics(SM_CXSMICON)`; 16 when unknown.
pub fn icon_size_from_metric(metric: i32) -> i32 {
    if metric <= 0 { 16 } else { metric.min(256) }
}

/// The plated PNG the UI picks for an icon size (mirror of `tray.slint`).
pub fn art_size(icon_size: i32) -> u32 {
    match icon_size {
        ..=18 => 16,
        19..=22 => 20,
        23..=28 => 24,
        _ => 32,
    }
}

/// Current small-icon size in physical pixels.
pub fn small_icon_metric() -> i32 {
    // SAFETY: plain call.
    unsafe { GetSystemMetrics(SM_CXSMICON) }
}

/// The taskbar (Explorer) is running; without it no tray icon can be added.
pub fn shell_tray_present() -> bool {
    let class = to_wide("Shell_TrayWnd");
    // SAFETY: valid class name.
    !unsafe { FindWindowW(class.as_ptr(), std::ptr::null()) }.is_null()
}

/// Slint's tray message window exists in this process (the icon was added).
pub fn slint_tray_present() -> bool {
    let class = to_wide("SlintSystemTrayWindow");
    let me = std::process::id();
    let mut after = std::ptr::null_mut();
    // SAFETY: enumerating message-only windows by class name.
    unsafe {
        loop {
            let h = FindWindowExW(HWND_MESSAGE, after, class.as_ptr(), std::ptr::null());
            if h.is_null() {
                return false;
            }
            let mut pid = 0u32;
            GetWindowThreadProcessId(h, &mut pid);
            if pid == me {
                return true;
            }
            after = h;
        }
    }
}

/// A created tray icon and its submenu model.
pub struct Tray {
    /// The component (not a `ComponentHandle`; dropping it removes the icon).
    pub tray: AppTray,
    /// "Wake host ▸" entries.
    pub hosts: Rc<VecModel<TrayHost>>,
}

impl Tray {
    /// Creates the tray component (the icon appears on the next event-loop iteration).
    pub fn create() -> Result<Tray, slint::PlatformError> {
        let tray = AppTray::new()?;
        let size = icon_size_from_metric(small_icon_metric());
        tray.set_icon_size(size);
        let hosts = Rc::new(VecModel::<TrayHost>::default());
        tray.set_hosts(ModelRc::from(hosts.clone()));
        log::info!(
            "tray icon created (small icon {size} px, art {} px)",
            art_size(size)
        );
        Ok(Tray { tray, hosts })
    }
}

// ---------------------------------------------------------------------------------------------
// App glue

impl App {
    /// Shows (creates) or removes the tray icon (`gui.show_tray`).
    pub(crate) fn set_tray_shown(&self, show: bool) {
        if show {
            if self.tray.borrow().is_some() {
                return;
            }
            self.create_tray();
        } else {
            let old = self.tray.borrow_mut().take();
            let had = old.is_some();
            drop(old);
            self.tray_gen.set(self.tray_gen.get() + 1);
            self.tray_state.set(TrayState::Off);
            self.ui.global::<SettingsState>().set_tray_available(true);
            self.clear_notice(NoticeKind::TrayUnavailable);
            if had && !self.ui.window().is_visible() {
                // Never leave a hidden window without a way back.
                self.show_window();
            }
        }
    }

    /// Creates the icon (none exists) and starts checking that it appears.
    fn create_tray(&self) {
        if !shell_tray_present() {
            self.tray_unavailable(true);
            return;
        }
        match Tray::create() {
            Ok(t) => {
                crate::bind::wire_tray(&t.tray);
                *self.tray.borrow_mut() = Some(t);
                self.tray_gen.set(self.tray_gen.get() + 1);
                self.tray_state.set(TrayState::Checking(TRAY_CHECKS));
                self.update_tray_ui();
                self.schedule_tray_check();
            }
            Err(e) => {
                log::warn!("cannot create the tray icon: {e}");
                self.tray_unavailable(true);
            }
        }
    }

    /// `TaskbarCreated` (from the session window): Explorer started or restarted, and icons
    /// added before are gone. Slint's tray window is message-only and never gets this
    /// broadcast, so the icon is created again whenever it should be shown (also after it was
    /// unavailable, e.g. when Explorer was not running at startup).
    pub(crate) fn taskbar_created(&self) {
        log::info!("the taskbar was created (Explorer started or restarted)");
        if self.is_quitting() || !self.cfg.borrow().settings.gui.show_tray {
            return;
        }
        if self.tray_recreate_pending.replace(true) {
            return;
        }
        // Not from inside the window procedure: the message may have been dispatched by the
        // modal loop of the tray's own context menu, whose state dropping the tray frees.
        Timer::single_shot(Duration::ZERO, || {
            with(|a| a.recreate_tray());
        });
    }

    fn recreate_tray(&self) {
        if self.is_quitting() || !self.cfg.borrow().settings.gui.show_tray {
            self.tray_recreate_pending.set(false);
            return;
        }
        if crate::session::menu_open() {
            // Wait until the menu (tray menu or menu bar) is closed.
            Timer::single_shot(TRAY_CHECK_INTERVAL, || {
                with(|a| a.recreate_tray());
            });
            return;
        }
        self.tray_recreate_pending.set(false);
        log::info!("recreating the tray icon");
        let old = self.tray.borrow_mut().take();
        drop(old);
        self.create_tray();
    }

    /// Checks (again) whether the icon of the current generation was added.
    pub(crate) fn schedule_tray_check(&self) {
        let generation = self.tray_gen.get();
        Timer::single_shot(TRAY_CHECK_INTERVAL, move || {
            with(|a| a.check_tray(generation));
        });
    }

    fn check_tray(&self, generation: u64) {
        if generation != self.tray_gen.get() {
            // The icon was removed or created again meanwhile; its own checks run.
            return;
        }
        let TrayState::Checking(left) = self.tray_state.get() else {
            return;
        };
        if self.tray.borrow().is_none() {
            return;
        }
        if slint_tray_present() {
            log::info!("tray icon is shown");
            self.tray_state.set(TrayState::Available);
            self.ui.global::<SettingsState>().set_tray_available(true);
            self.clear_notice(NoticeKind::TrayUnavailable);
        } else if left == 0 {
            log::warn!("the tray icon did not appear");
            self.tray_unavailable(true);
        } else {
            self.tray_state.set(TrayState::Checking(left - 1));
            self.schedule_tray_check();
        }
    }

    /// The tray cannot be used: tell the user and make sure the window is visible.
    pub(crate) fn tray_unavailable(&self, show_window: bool) {
        self.tray_state.set(TrayState::Unavailable);
        let old = self.tray.borrow_mut().take();
        drop(old);
        self.tray_gen.set(self.tray_gen.get() + 1);
        self.ui.global::<SettingsState>().set_tray_available(false);
        self.set_notice(NoticeKind::TrayUnavailable, Text::Empty);
        if show_window && !self.ui.window().is_visible() {
            self.show_window();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_size_choice() {
        assert_eq!(icon_size_from_metric(0), 16);
        assert_eq!(icon_size_from_metric(-1), 16);
        assert_eq!(icon_size_from_metric(20), 20);
        // 100 % .. 200 % scaling.
        assert_eq!(art_size(16), 16);
        assert_eq!(art_size(20), 20);
        assert_eq!(art_size(24), 24);
        assert_eq!(art_size(32), 32);
        // In between: the closest one.
        assert_eq!(art_size(18), 16);
        assert_eq!(art_size(22), 20);
        assert_eq!(art_size(28), 24);
        assert_eq!(art_size(30), 32);
        assert_eq!(art_size(40), 32);
        assert!(small_icon_metric() > 0);
    }
}
