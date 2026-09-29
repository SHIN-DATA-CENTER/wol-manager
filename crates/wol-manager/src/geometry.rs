//! Window geometry in `gui-state.toml` (local folder, plan §3): position, size, maximized.
//!
//! Restored before the first `show()` only when the title bar would be reachable on a
//! monitor (`MonitorFromRect` + the monitor's work area), so a window saved on a
//! disconnected monitor comes back at the default position.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Smallest / largest accepted saved size (physical pixels).
const MIN_SIDE: u32 = 200;
const MAX_SIDE: u32 = 16384;
/// Height of the strip at the top of the window that must be on a monitor.
const TITLE_STRIP: i32 = 32;
/// How much of that strip must be visible.
const MIN_VISIBLE_W: i32 = 120;
const MIN_VISIBLE_H: i32 = 20;

/// Saved geometry (physical pixels; position includes the frame, size excludes it, as in
/// `slint::Window::position` / `size`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowGeometry {
    /// Left edge.
    pub x: i32,
    /// Top edge.
    pub y: i32,
    /// Inner width.
    pub width: u32,
    /// Inner height.
    pub height: u32,
    /// Maximized when closed.
    #[serde(default)]
    pub maximized: bool,
}

/// Contents of `gui-state.toml`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GuiState {
    /// Main window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<WindowGeometry>,
    /// Unknown keys (kept when rewriting).
    #[serde(flatten)]
    pub extra: toml::Table,
}

/// A screen rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// Left.
    pub left: i32,
    /// Top.
    pub top: i32,
    /// Right (exclusive).
    pub right: i32,
    /// Bottom (exclusive).
    pub bottom: i32,
}

impl Rect {
    fn intersect(&self, o: &Rect) -> Option<Rect> {
        let r = Rect {
            left: self.left.max(o.left),
            top: self.top.max(o.top),
            right: self.right.min(o.right),
            bottom: self.bottom.min(o.bottom),
        };
        (r.right > r.left && r.bottom > r.top).then_some(r)
    }
}

/// What to apply before `show()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Placement {
    /// Position, when it is on a monitor.
    pub position: Option<(i32, i32)>,
    /// Size, when sane.
    pub size: Option<(u32, u32)>,
    /// Maximize.
    pub maximized: bool,
}

/// The strip at the top of the window (title bar area).
pub fn title_strip(g: &WindowGeometry) -> Rect {
    let w = i32::try_from(g.width.min(MAX_SIDE)).unwrap_or(MAX_SIDE as i32);
    Rect {
        left: g.x,
        top: g.y,
        right: g.x.saturating_add(w),
        bottom: g.y.saturating_add(TITLE_STRIP),
    }
}

/// Validates saved geometry. `work_area_for(rect)` returns the work area of the monitor that
/// `rect` is on (`MonitorFromRect(.., MONITOR_DEFAULTTONULL)`), `None` when it is off-screen.
pub fn validate(g: &WindowGeometry, work_area_for: &dyn Fn(Rect) -> Option<Rect>) -> Placement {
    let size_ok =
        (MIN_SIDE..=MAX_SIDE).contains(&g.width) && (MIN_SIDE..=MAX_SIDE).contains(&g.height);
    let size = size_ok.then_some((g.width, g.height));
    let strip = title_strip(g);
    let visible = work_area_for(strip)
        .and_then(|work| strip.intersect(&work))
        .is_some_and(|v| {
            let need_w = MIN_VISIBLE_W.min(strip.right - strip.left);
            v.right - v.left >= need_w && v.bottom - v.top >= MIN_VISIBLE_H
        });
    Placement {
        position: (size_ok && visible).then_some((g.x, g.y)),
        size,
        maximized: g.maximized,
    }
}

/// The maximized state a window reports, when it can be trusted: a hidden window always
/// reports `false`, and a minimized one says nothing about how it will be restored.
pub fn observed_maximized(visible: bool, minimized: bool, maximized: bool) -> Option<bool> {
    (visible && !minimized).then_some(maximized)
}

/// What to save at exit: the last normal rectangle with the last known maximized state.
pub fn final_geometry(last: Option<WindowGeometry>, maximized: bool) -> Option<WindowGeometry> {
    last.map(|g| WindowGeometry { maximized, ..g })
}

/// Reads `gui-state.toml` (missing / broken → default, logged).
pub fn load(path: &Path) -> GuiState {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            log::warn!("ignoring {}: {e}", path.display());
            GuiState::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => GuiState::default(),
        Err(e) => {
            log::warn!("cannot read {}: {e}", path.display());
            GuiState::default()
        }
    }
}

/// Writes `gui-state.toml` atomically (creates the folder). Errors are returned for logging.
pub fn save(path: &Path, state: &GuiState) -> Result<(), String> {
    let text = toml::to_string(state).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    wol_core::store::write_file_atomic(path, text.as_bytes()).map_err(|e| e.to_string())
}

/// Work area of the monitor `r` is on (`None` when `r` touches no monitor).
pub fn work_area_for(r: Rect) -> Option<Rect> {
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MONITOR_DEFAULTTONULL, MONITORINFO, MonitorFromRect,
    };
    let rc = RECT {
        left: r.left,
        top: r.top,
        right: r.right,
        bottom: r.bottom,
    };
    // SAFETY: plain Win32 calls with valid pointers to stack values.
    unsafe {
        let mon = MonitorFromRect(&rc, MONITOR_DEFAULTTONULL);
        if mon.is_null() {
            return None;
        }
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if GetMonitorInfoW(mon, &mut mi) == 0 {
            return None;
        }
        Some(Rect {
            left: mi.rcWork.left,
            top: mi.rcWork.top,
            right: mi.rcWork.right,
            bottom: mi.rcWork.bottom,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MON1: Rect = Rect {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1040,
    };
    const MON2: Rect = Rect {
        left: 1920,
        top: 0,
        right: 3840,
        bottom: 1080,
    };

    fn monitors(list: &'static [Rect]) -> impl Fn(Rect) -> Option<Rect> {
        move |r| list.iter().copied().find(|m| r.intersect(m).is_some())
    }

    fn g(x: i32, y: i32, w: u32, h: u32) -> WindowGeometry {
        WindowGeometry {
            x,
            y,
            width: w,
            height: h,
            maximized: false,
        }
    }

    #[test]
    fn on_screen_positions_are_restored() {
        let f = monitors(&[MON1, MON2]);
        let p = validate(&g(100, 100, 880, 560), &f);
        assert_eq!(p.position, Some((100, 100)));
        assert_eq!(p.size, Some((880, 560)));
        // Second monitor.
        assert_eq!(
            validate(&g(2000, 50, 880, 560), &f).position,
            Some((2000, 50))
        );
        // Mostly off the left edge, but the title bar still has 180 px on screen.
        assert_eq!(
            validate(&g(-700, 10, 880, 560), &f).position,
            Some((-700, 10))
        );
    }

    #[test]
    fn off_screen_positions_are_dropped() {
        let f = monitors(&[MON1]);
        // Monitor 2 disconnected.
        let p = validate(&g(2000, 50, 880, 560), &f);
        assert_eq!(p.position, None);
        assert_eq!(p.size, Some((880, 560)));
        // Title bar above the screen.
        assert_eq!(validate(&g(100, -500, 880, 560), &f).position, None);
        // Only a sliver visible.
        assert_eq!(validate(&g(1900, 100, 880, 560), &f).position, None);
        // Title bar hidden below the taskbar (work area ends at 1040).
        assert_eq!(validate(&g(100, 1030, 880, 560), &f).position, None);
    }

    #[test]
    fn insane_sizes_are_dropped() {
        let f = monitors(&[MON1]);
        let p = validate(&g(10, 10, 50, 50), &f);
        assert_eq!(p.size, None);
        assert_eq!(p.position, None);
        assert_eq!(validate(&g(10, 10, 100_000, 600), &f).size, None);
        let mut m = g(10, 10, 880, 560);
        m.maximized = true;
        assert!(validate(&m, &f).maximized);
    }

    /// Mirrors `App`: the known state starts from the file and is updated only by trusted
    /// observations; quitting saves it with the last normal rectangle.
    fn quit_after(saved_maximized: bool, observations: &[(bool, bool, bool)]) -> bool {
        let mut known = saved_maximized;
        for &(visible, minimized, maximized) in observations {
            if let Some(m) = observed_maximized(visible, minimized, maximized) {
                known = m;
            }
        }
        let mut saved = g(10, 10, 880, 560);
        saved.maximized = saved_maximized;
        final_geometry(Some(saved), known).unwrap().maximized
    }

    #[test]
    fn maximized_survives_hidden_and_minimized_windows() {
        // Started in the tray and quit without showing the window: hidden reports `false`.
        assert!(quit_after(true, &[(false, false, false)]));
        // Maximized, closed to the tray, quit from the tray.
        assert!(quit_after(
            false,
            &[(true, false, true), (false, false, false)]
        ));
        // Maximized, minimized, quit.
        assert!(quit_after(
            false,
            &[(true, false, true), (true, true, false)]
        ));
        // Restored by the user before hiding.
        assert!(!quit_after(
            true,
            &[
                (true, false, true),
                (true, false, false),
                (false, false, false)
            ]
        ));
        // Nothing saved and never shown: nothing to write.
        assert_eq!(final_geometry(None, true), None);
        // The rectangle is kept as it is.
        let r = final_geometry(Some(g(1, 2, 880, 560)), true).unwrap();
        assert_eq!(
            (r.x, r.y, r.width, r.height, r.maximized),
            (1, 2, 880, 560, true)
        );
    }

    #[test]
    fn file_round_trip_keeps_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("gui-state.toml");
        assert_eq!(load(&path), GuiState::default());
        let mut st = GuiState {
            window: Some(g(1, 2, 880, 560)),
            ..GuiState::default()
        };
        st.extra.insert("future".into(), toml::Value::Integer(7));
        save(&path, &st).unwrap();
        assert_eq!(load(&path), st);
        std::fs::write(&path, "not [toml").unwrap();
        assert_eq!(load(&path), GuiState::default());
    }
}
