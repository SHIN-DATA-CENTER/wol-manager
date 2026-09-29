//! Settings overlay: `SettingsState` ⇄ `Settings` mapping, range rules, debounce, and the
//! side effects of each key (contract §5).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use slint::{ComponentHandle, SharedString, TimerMode};
use wol_core::addr;
use wol_core::i18n::{LangSetting, Msg};
use wol_core::model::{ProbeMethod, Renderer, Settings, Theme, limits};
use wol_core::pathenv::{self, PathChange, Scope};
use wol_core::store::portable::{CopySettings, PortableStatus};
use wol_core::store::{ConfigLocation, Loaded};

use crate::app::{App, Pending, TrayState, with};
use crate::persist::{Op, PortableCmd, PortableDone};
use crate::texts::{GuiText, Text};
use crate::workers::post_ui;
use crate::{
    AppState, AppWindow, ConfirmKind, ConfirmRequest, NoticeKind, OverlayKind, PathMode, PathState,
    PortableBlock, SettingsState, ToastKind,
};

/// Preset values of `gui.poll_interval_secs` for poll-index 0..=4 (5 = custom).
pub const POLL_PRESETS: [u32; 5] = [0, 10, 30, 60, 300];
/// Index of the "custom (N s)" entry.
pub const POLL_CUSTOM_INDEX: i32 = 5;

/// Keys edited in spin boxes / text fields: saved ~500 ms after the last change.
pub const DEBOUNCED_KEYS: &[&str] = &[
    "wake.verify_timeout_secs",
    "wake.port",
    "wake.repeat",
    "wake.interval_ms",
    "probe.timeout_ms",
    "probe.tcp_ports",
];
/// Debounce delay.
pub const DEBOUNCE: Duration = Duration::from_millis(500);

/// Every key the settings overlay can change.
#[cfg(test)]
pub const UI_KEYS: &[&str] = &[
    "language",
    "gui.theme",
    "gui.show_tray",
    "gui.close_to_tray",
    "gui.minimize_to_tray",
    "gui.start_in_tray",
    "gui.poll_interval_secs",
    "probe.method",
    "probe.tcp_ports",
    "probe.timeout_ms",
    "wake.verify_timeout_secs",
    "wake.port",
    "wake.repeat",
    "wake.interval_ms",
    "wake.include_virtual",
    "gui.renderer",
];

/// `true` for keys that are debounced.
pub fn is_debounced(key: &str) -> bool {
    DEBOUNCED_KEYS.contains(&key)
}

/// The values of the settings overlay (mirror of `SettingsState`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SettingsView {
    /// 0 auto, 1 ja, 2 en.
    pub language_index: i32,
    /// 0 system, 1 light, 2 dark.
    pub theme_index: i32,
    /// gui.show_tray.
    pub show_tray: bool,
    /// gui.close_to_tray.
    pub close_to_tray: bool,
    /// gui.minimize_to_tray.
    pub minimize_to_tray: bool,
    /// gui.start_in_tray.
    pub start_in_tray: bool,
    /// 0..=4 presets, 5 custom.
    pub poll_index: i32,
    /// Value shown for the custom entry.
    pub poll_custom_secs: i32,
    /// 0 auto, 1 icmp, 2 tcp, 3 none.
    pub probe_method_index: i32,
    /// Display form "3389, 445, 22".
    pub probe_tcp_ports: String,
    /// probe.timeout_ms.
    pub probe_timeout_ms: i32,
    /// wake.verify_timeout_secs.
    pub verify_timeout_secs: i32,
    /// wake.port.
    pub default_port: i32,
    /// wake.repeat.
    pub repeat: i32,
    /// wake.interval_ms.
    pub interval_ms: i32,
    /// wake.include_virtual.
    pub include_virtual: bool,
    /// 0 auto, 1 software.
    pub renderer_index: i32,
}

fn clamp_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

/// `SettingsState` values for `s`. Out-of-range values of a hand-edited file are shown as
/// they are (the spin boxes clamp them only when the user edits).
pub fn view_of(s: &Settings) -> SettingsView {
    let poll = s.gui.poll_interval_secs;
    let poll_index = POLL_PRESETS
        .iter()
        .position(|p| *p == poll)
        .map_or(POLL_CUSTOM_INDEX, |i| i as i32);
    SettingsView {
        language_index: match s.language {
            LangSetting::Auto => 0,
            LangSetting::Ja => 1,
            LangSetting::En => 2,
        },
        theme_index: match s.gui.theme {
            Theme::System => 0,
            Theme::Light => 1,
            Theme::Dark => 2,
        },
        show_tray: s.gui.show_tray,
        close_to_tray: s.gui.close_to_tray,
        minimize_to_tray: s.gui.minimize_to_tray,
        start_in_tray: s.gui.start_in_tray,
        poll_index,
        poll_custom_secs: clamp_i32(poll),
        probe_method_index: match s.probe.method {
            ProbeMethod::Auto => 0,
            ProbeMethod::Icmp => 1,
            ProbeMethod::Tcp => 2,
            ProbeMethod::None => 3,
        },
        probe_tcp_ports: addr::format_port_list(&s.probe.tcp_ports),
        probe_timeout_ms: clamp_i32(s.probe.timeout_ms),
        verify_timeout_secs: clamp_i32(s.wake.verify_timeout_secs),
        default_port: i32::from(s.wake.port),
        repeat: i32::from(s.wake.repeat),
        interval_ms: clamp_i32(s.wake.interval_ms),
        include_virtual: s.wake.include_virtual,
        renderer_index: match s.gui.renderer {
            Renderer::Auto => 0,
            Renderer::Software => 1,
        },
    }
}

fn clamp_range<T: Copy + PartialOrd + Into<i64>>(v: i32, r: std::ops::RangeInclusive<T>) -> i64 {
    let lo: i64 = (*r.start()).into();
    let hi: i64 = (*r.end()).into();
    i64::from(v).clamp(lo, hi)
}

fn pick<'a>(index: i32, values: &[&'a str]) -> Option<&'a str> {
    usize::try_from(index)
        .ok()
        .and_then(|i| values.get(i).copied())
}

/// The `Settings::set_key` value for `key` from the overlay's values, applying the range
/// rules. `None` = nothing to write (unknown key, invalid index, or the custom poll entry,
/// which is never rewritten).
pub fn value_for(key: &str, v: &SettingsView) -> Option<String> {
    let b = |x: bool| Some(x.to_string());
    match key {
        "language" => pick(v.language_index, &["auto", "ja", "en"]).map(str::to_owned),
        "gui.theme" => pick(v.theme_index, &["system", "light", "dark"]).map(str::to_owned),
        "gui.show_tray" => b(v.show_tray),
        "gui.close_to_tray" => b(v.close_to_tray),
        "gui.minimize_to_tray" => b(v.minimize_to_tray),
        "gui.start_in_tray" => b(v.start_in_tray),
        "gui.poll_interval_secs" => usize::try_from(v.poll_index)
            .ok()
            .and_then(|i| POLL_PRESETS.get(i))
            .map(ToString::to_string),
        "probe.method" => {
            pick(v.probe_method_index, &["auto", "icmp", "tcp", "none"]).map(str::to_owned)
        }
        "probe.tcp_ports" => addr::parse_port_list(&v.probe_tcp_ports)
            .ok()
            .map(|p| addr::format_port_list(&p)),
        "probe.timeout_ms" => {
            Some(clamp_range(v.probe_timeout_ms, limits::PROBE_TIMEOUT_MS).to_string())
        }
        "wake.verify_timeout_secs" => {
            Some(clamp_range(v.verify_timeout_secs, limits::VERIFY_TIMEOUT_SECS).to_string())
        }
        "wake.port" => Some(clamp_range(v.default_port, limits::PORT).to_string()),
        "wake.repeat" => Some(clamp_range(v.repeat, limits::REPEAT).to_string()),
        "wake.interval_ms" => Some(clamp_range(v.interval_ms, limits::INTERVAL_MS).to_string()),
        "wake.include_virtual" => b(v.include_virtual),
        "gui.renderer" => pick(v.renderer_index, &["auto", "software"]).map(str::to_owned),
        _ => None,
    }
}

/// Applies `key` from the view to a copy of `current`. `Ok(None)` = nothing changes.
pub fn apply(
    key: &str,
    v: &SettingsView,
    current: &Settings,
) -> Result<Option<(String, Settings)>, wol_core::Error> {
    let Some(value) = value_for(key, v) else {
        return Ok(None);
    };
    let mut next = current.clone();
    next.set_key(key, &value)?;
    if next == *current {
        return Ok(None);
    }
    Ok(Some((value, next)))
}

/// Keys whose value differs between two settings (for side effects of external changes).
pub fn changed_keys(a: &Settings, b: &Settings) -> Vec<&'static str> {
    Settings::KEYS
        .iter()
        .copied()
        .filter(|k| a.get_key(k).ok() != b.get_key(k).ok())
        .collect()
}

/// Per-key debounce deadlines.
#[derive(Debug, Default)]
pub struct Debouncer {
    pending: BTreeMap<String, Instant>,
}

impl Debouncer {
    /// Records a change of `key` at `now`.
    pub fn touch(&mut self, key: &str, now: Instant) {
        self.pending.insert(key.to_owned(), now + DEBOUNCE);
    }

    /// Keys whose deadline passed (removed from the pending set).
    pub fn due(&mut self, now: Instant) -> Vec<String> {
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, d)| **d <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &due {
            self.pending.remove(k);
        }
        due
    }

    /// Every pending key (flush on close / shutdown).
    pub fn drain(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending).into_keys().collect()
    }

    /// Earliest deadline.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().min().copied()
    }

    /// `key` waits for its deadline.
    pub fn is_pending(&self, key: &str) -> bool {
        self.pending.contains_key(key)
    }
}

// ---------------------------------------------------------------------------------------------
// UI glue (App methods for the settings overlay)

/// Reads `SettingsState`.
pub fn read_view(ui: &AppWindow) -> SettingsView {
    let s = ui.global::<SettingsState>();
    SettingsView {
        language_index: s.get_language_index(),
        theme_index: s.get_theme_index(),
        show_tray: s.get_show_tray(),
        close_to_tray: s.get_close_to_tray(),
        minimize_to_tray: s.get_minimize_to_tray(),
        start_in_tray: s.get_start_in_tray(),
        poll_index: s.get_poll_index(),
        poll_custom_secs: s.get_poll_custom_secs(),
        probe_method_index: s.get_probe_method_index(),
        probe_tcp_ports: s.get_probe_tcp_ports().into(),
        probe_timeout_ms: s.get_probe_timeout_ms(),
        verify_timeout_secs: s.get_verify_timeout_secs(),
        default_port: s.get_default_port(),
        repeat: s.get_repeat(),
        interval_ms: s.get_interval_ms(),
        include_virtual: s.get_include_virtual(),
        renderer_index: s.get_renderer_index(),
    }
}

/// Writes `SettingsState`, except keys whose debounced change is still pending.
pub fn push_view(ui: &AppWindow, v: &SettingsView, pending: &Debouncer) {
    let s = ui.global::<SettingsState>();
    let set = |key: &str| !pending.is_pending(key);
    if set("language") {
        s.set_language_index(v.language_index);
    }
    if set("gui.theme") {
        s.set_theme_index(v.theme_index);
    }
    if set("gui.show_tray") {
        s.set_show_tray(v.show_tray);
    }
    if set("gui.close_to_tray") {
        s.set_close_to_tray(v.close_to_tray);
    }
    if set("gui.minimize_to_tray") {
        s.set_minimize_to_tray(v.minimize_to_tray);
    }
    if set("gui.start_in_tray") {
        s.set_start_in_tray(v.start_in_tray);
    }
    if set("gui.poll_interval_secs") {
        s.set_poll_custom_secs(v.poll_custom_secs);
        s.set_poll_index(v.poll_index);
    }
    if set("probe.method") {
        s.set_probe_method_index(v.probe_method_index);
    }
    if set("probe.tcp_ports") {
        s.set_probe_tcp_ports(v.probe_tcp_ports.as_str().into());
    }
    if set("probe.timeout_ms") {
        s.set_probe_timeout_ms(v.probe_timeout_ms);
    }
    if set("wake.verify_timeout_secs") {
        s.set_verify_timeout_secs(v.verify_timeout_secs);
    }
    if set("wake.port") {
        s.set_default_port(v.default_port);
    }
    if set("wake.repeat") {
        s.set_repeat(v.repeat);
    }
    if set("wake.interval_ms") {
        s.set_interval_ms(v.interval_ms);
    }
    if set("wake.include_virtual") {
        s.set_include_virtual(v.include_virtual);
    }
    if set("gui.renderer") {
        s.set_renderer_index(v.renderer_index);
    }
}

/// Portable / PATH facts for the "Storage & command line" page (computed on the io pool).
#[derive(Debug, Clone)]
pub struct EnvStatus {
    /// Portable status of this exe.
    pub portable: PortableStatus,
    /// `data\config.toml` exists (enabling asks whether to replace it).
    pub data_has_config: bool,
    /// Folder that would go on PATH (`<exe folder>\bin`).
    pub cli_dir: PathBuf,
    /// `wolm.exe` in that folder, if present.
    pub cli_path: Option<PathBuf>,
    /// Which PATH control to show.
    pub path_mode: PathMode,
    /// PATH status (user or machine scope) or the error.
    pub path: Option<Result<bool, Text>>,
}

impl EnvStatus {
    fn scope(&self) -> Option<Scope> {
        match self.path_mode {
            PathMode::User => Some(Scope::User),
            PathMode::Machine => Some(Scope::Machine),
            PathMode::Unavailable => None,
        }
    }
}

/// Collects [`EnvStatus`] (blocking: file system and registry reads).
pub fn env_status(exe: &Path) -> EnvStatus {
    let portable = wol_core::store::portable::status(exe);
    let data_has_config = portable
        .data_dir
        .join(wol_core::consts::CONFIG_FILE)
        .is_file();
    let cli_dir = pathenv::cli_dir_for(exe);
    let cli = cli_dir.join(wol_core::consts::CLI_EXE);
    let cli_path = cli.is_file().then_some(cli);
    let path_mode = if cli_path.is_none() {
        PathMode::Unavailable
    } else if portable.installed && portable.install_scope == Some(Scope::Machine) {
        PathMode::Machine
    } else {
        PathMode::User
    };
    let mut st = EnvStatus {
        portable,
        data_has_config,
        cli_dir,
        cli_path,
        path_mode,
        path: None,
    };
    if let Some(scope) = st.scope() {
        let backend = pathenv::backend_from_env();
        st.path = Some(
            pathenv::status(&*backend, scope, &st.cli_dir)
                .map(|s| s.present)
                .map_err(|e| Text::error(&e)),
        );
    }
    st
}

/// `%APPDATA%\wol-manager` (shown when portable mode is turned off).
fn appdata_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(wol_core::consts::APP_DIR_NAME)
}

impl App {
    /// `SettingsState.changed(key)`.
    pub fn setting_changed(&self, key: &str) {
        if is_debounced(key) {
            self.debounce.borrow_mut().touch(key, Instant::now());
            self.arm_debounce();
        } else {
            self.commit_setting(key);
        }
    }

    fn arm_debounce(&self) {
        let next = self.debounce.borrow().next_deadline();
        if let Some(deadline) = next {
            let delay = deadline.saturating_duration_since(Instant::now());
            self.debounce_timer.start(TimerMode::SingleShot, delay, || {
                with(|a| a.on_debounce());
            });
        }
    }

    fn on_debounce(&self) {
        let due = self.debounce.borrow_mut().due(Instant::now());
        for key in due {
            self.commit_setting(&key);
        }
        self.arm_debounce();
    }

    /// Saves every pending debounced change now (settings closed, shutdown).
    pub(crate) fn flush_debounce(&self) {
        let keys = self.debounce.borrow_mut().drain();
        for key in keys {
            self.commit_setting(&key);
        }
    }

    /// Applies one key from the overlay: local config + side effects at once, then the store.
    pub(crate) fn commit_setting(&self, key: &str) {
        let view = read_view(&self.ui);
        let current = self.cfg.borrow().settings.clone();
        match apply(key, &view, &current) {
            Ok(None) => {}
            Ok(Some((value, next))) => {
                log::info!("setting {key} = {value}");
                let mut cfg = self.cfg.borrow().clone();
                cfg.settings = next;
                self.reconcile_from(cfg);
                self.submit(
                    Op::SetSettings(vec![(key.to_owned(), value)]),
                    Pending::Settings,
                );
            }
            Err(e) => {
                log::warn!("setting {key}: {e}");
                self.toast(ToastKind::Error, GuiText::SettingFailed, Text::error(&e));
                push_view(&self.ui, &view_of(&current), &self.debounce.borrow());
            }
        }
    }

    /// Side effects of changed keys (own changes and external ones).
    pub(crate) fn apply_setting_effects(&self, keys: &[&str]) {
        let s = self.cfg.borrow().settings.clone();
        for key in keys {
            match *key {
                "language" => self.apply_language(s.language),
                "gui.theme" => self.apply_theme(s.gui.theme),
                "gui.show_tray" => self.set_tray_shown(s.gui.show_tray),
                "gui.renderer" => log::info!("renderer change takes effect after a restart"),
                _ => {}
            }
        }
    }

    fn apply_theme(&self, theme: wol_core::model::Theme) {
        log::info!("theme: {theme}");
        let mut st = self.theme.get();
        let scheme = crate::theme::on_change(&mut st, theme, crate::theme::os_apps_dark());
        self.theme.set(st);
        if let crate::theme::Scheme::Assign(dark) = scheme {
            self.ui.invoke_set_color_scheme(dark);
        }
    }

    /// Every 2 s: keep following the OS after switching back to "system".
    pub(crate) fn follow_os_theme(&self) {
        let mut st = self.theme.get();
        if !st.following_os {
            return;
        }
        let scheme = crate::theme::follow(&mut st, crate::theme::os_apps_dark());
        self.theme.set(st);
        if let crate::theme::Scheme::Assign(dark) = scheme {
            self.ui.invoke_set_color_scheme(dark);
        }
    }

    /// Toolbar gear, File > Settings, tray.
    pub fn open_settings(&self) {
        if !self.idle() {
            return;
        }
        let view = view_of(&self.cfg.borrow().settings);
        push_view(&self.ui, &view, &self.debounce.borrow());
        let s = self.ui.global::<SettingsState>();
        s.set_tray_available(self.tray_state.get() != TrayState::Unavailable);
        s.set_renderer_override(self.env.slint_backend.as_str().into());
        self.push_location();
        let cached = self.env_status.borrow().clone();
        match cached {
            Some(st) => self.push_env_status(&st),
            None => {
                s.set_portable_on(self.location.borrow().is_portable());
                s.set_path_state(PathState::Unknown);
                s.set_portable_block(self.portable_block(None));
            }
        }
        self.refresh_env_status();
        self.ui
            .global::<AppState>()
            .set_overlay(OverlayKind::Settings);
    }

    pub(crate) fn refresh_env_status(&self) {
        let exe = self.env.exe.clone();
        self.io_pool.spawn(move || {
            let st = env_status(&exe);
            post_ui(move |app| app.on_env_status(st));
        });
    }

    fn on_env_status(&self, st: EnvStatus) {
        self.push_env_status(&st);
        *self.env_status.borrow_mut() = Some(st);
    }

    fn portable_block(&self, st: Option<&EnvStatus>) -> PortableBlock {
        if self.portable_busy.get() {
            return PortableBlock::Busy;
        }
        if self.location.borrow().is_custom() {
            return PortableBlock::CustomLocation;
        }
        match st {
            Some(s) if s.portable.installed => PortableBlock::Installed,
            Some(s) if !s.portable.data_writable => PortableBlock::NotWritable,
            // Unknown for a moment (status still being read): a flip is reverted by
            // `portable_toggled` until the status arrived.
            _ => PortableBlock::None,
        }
    }

    fn push_env_status(&self, st: &EnvStatus) {
        let s = self.ui.global::<SettingsState>();
        s.set_portable_on(self.location.borrow().is_portable());
        s.set_portable_block(self.portable_block(Some(st)));
        s.set_cli_path(
            st.cli_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
                .into(),
        );
        s.set_path_mode(st.path_mode);
        match &st.path {
            Some(Ok(present)) => {
                s.set_path_state(if *present {
                    PathState::Registered
                } else {
                    PathState::NotRegistered
                });
                s.set_path_on(*present);
                s.set_path_error(SharedString::default());
            }
            Some(Err(t)) => {
                s.set_path_state(PathState::Error);
                s.set_path_error(self.text(t).into());
            }
            None => s.set_path_state(PathState::Unknown),
        }
    }

    /// Resets the portable switch to the real state.
    pub(crate) fn portable_reset_switch(&self) {
        self.ui
            .global::<SettingsState>()
            .set_portable_on(self.location.borrow().is_portable());
    }

    /// The portable switch was flipped.
    pub fn portable_toggled(&self, on: bool) {
        let st = self.env_status.borrow().clone();
        let usable = st
            .as_ref()
            .is_some_and(|s| self.portable_block(Some(s)) == PortableBlock::None);
        let Some(st) = st.filter(|_| usable) else {
            self.portable_reset_switch();
            return;
        };
        if on == self.location.borrow().is_portable() {
            return;
        }
        let req = if on {
            ConfirmRequest {
                kind: ConfirmKind::PortableEnable,
                path: st.portable.data_dir.display().to_string().into(),
                option: true,
                ..ConfirmRequest::default()
            }
        } else {
            ConfirmRequest {
                kind: ConfirmKind::PortableDisable,
                path: appdata_dir().display().to_string().into(),
                ..ConfirmRequest::default()
            }
        };
        self.confirm(req);
    }

    /// Confirmed portable switch (chains the "replace existing data" question).
    pub(crate) fn portable_confirmed(&self, req: &ConfirmRequest, alternate: bool) {
        let cur = self.location.borrow().dir.clone();
        let st = self.env_status.borrow().clone();
        match req.kind {
            ConfirmKind::PortableEnable => {
                let has_data = st.as_ref().is_some_and(|s| s.data_has_config);
                if req.option && has_data {
                    self.confirm(ConfirmRequest {
                        kind: ConfirmKind::PortableOverwrite,
                        path: req.path.clone(),
                        ..ConfirmRequest::default()
                    });
                } else if req.option {
                    self.run_portable(PortableCmd::Enable(CopySettings::IfMissing(cur)));
                } else {
                    self.run_portable(PortableCmd::Enable(CopySettings::No));
                }
            }
            ConfirmKind::PortableOverwrite => {
                let copy = if alternate {
                    CopySettings::No
                } else {
                    CopySettings::Overwrite(cur)
                };
                self.run_portable(PortableCmd::Enable(copy));
            }
            ConfirmKind::PortableDisable => self.run_portable(PortableCmd::Disable),
            _ => {}
        }
    }

    fn run_portable(&self, cmd: PortableCmd) {
        log::info!("portable: {cmd:?}");
        self.flush_debounce();
        self.portable_busy.set(true);
        self.ui
            .global::<SettingsState>()
            .set_portable_block(PortableBlock::Busy);
        self.store_portable(cmd);
    }

    /// The store thread switched (or failed to switch) the location.
    pub(crate) fn on_portable_done(
        &self,
        result: wol_core::Result<PortableDone>,
        location: ConfigLocation,
        loaded: Option<wol_core::Result<Box<Loaded>>>,
    ) {
        self.portable_busy.set(false);
        match result {
            Ok(done) => {
                log::info!("settings location is now {}", location.dir.display());
                crate::single_instance::publish_settings_dir(&location.dir);
                *self.location.borrow_mut() = location;
                self.push_location();
                match done {
                    PortableDone::Enabled(r) => {
                        let detail = if r.copied {
                            Text::msg(Msg::PortableCopied)
                        } else if r.kept_existing {
                            Text::msg(Msg::PortableKeptExisting)
                        } else {
                            Text::Empty
                        };
                        self.toast(
                            ToastKind::Success,
                            Msg::PortableEnabled {
                                dir: r.status.data_dir.display().to_string(),
                            },
                            detail,
                        );
                    }
                    PortableDone::Disabled(removed) => {
                        log::info!("portable marker removed: {removed}");
                        self.toast(ToastKind::Success, Msg::PortableDisabled, Text::Empty);
                    }
                }
                match loaded {
                    Some(Ok(l)) => self.on_loaded(*l, "settings location changed"),
                    Some(Err(e)) => {
                        self.set_notice(NoticeKind::ConfigLoadFailed, Text::error(&e));
                    }
                    None => {}
                }
            }
            Err(e) => {
                log::warn!("portable switch failed: {e}");
                self.toast(ToastKind::Error, GuiText::PortableFailed, Text::error(&e));
            }
        }
        self.portable_reset_switch();
        self.refresh_env_status();
    }

    /// The store thread followed a location change made outside the app (portable marker
    /// created or removed by `wolm portable` or by hand): show the new folder and its hosts.
    pub(crate) fn on_relocated(
        &self,
        location: ConfigLocation,
        loaded: wol_core::Result<Box<Loaded>>,
    ) {
        crate::single_instance::publish_settings_dir(&location.dir);
        let dir = location.dir.display().to_string();
        *self.location.borrow_mut() = location;
        self.push_location();
        self.toast(ToastKind::Info, GuiText::LocationChanged, Text::Data(dir));
        match loaded {
            Ok(l) => self.on_loaded(*l, "settings location changed outside the app"),
            Err(e) => self.set_notice(NoticeKind::ConfigLoadFailed, Text::error(&e)),
        }
        self.portable_reset_switch();
        self.refresh_env_status();
    }

    /// The PATH switch was flipped (user scope only).
    pub fn path_toggled(&self, on: bool) {
        let st = self.env_status.borrow().clone();
        let s = self.ui.global::<SettingsState>();
        let Some(st) = st.filter(|s| s.path_mode == PathMode::User) else {
            s.set_path_on(!on);
            return;
        };
        s.set_path_state(PathState::Busy);
        let dir = st.cli_dir.clone();
        log::info!(
            "PATH: {} {}",
            if on { "add" } else { "remove" },
            dir.display()
        );
        self.io_pool.spawn(move || {
            let backend = pathenv::backend_from_env();
            let r = if on {
                pathenv::add(&*backend, Scope::User, &dir)
            } else {
                pathenv::remove(&*backend, Scope::User, &dir)
            }
            .map_err(|e| Text::error(&e));
            let status = pathenv::status(&*backend, Scope::User, &dir)
                .map(|s| s.present)
                .map_err(|e| Text::error(&e));
            post_ui(move |app| app.on_path_done(on, dir, r, status));
        });
    }

    fn on_path_done(
        &self,
        on: bool,
        dir: PathBuf,
        r: Result<PathChange, Text>,
        status: Result<bool, Text>,
    ) {
        match &r {
            Ok(change) => {
                let detail = if change.changed() {
                    Text::msg(Msg::PathOpenNewTerminal)
                } else {
                    Text::Empty
                };
                self.toast(
                    ToastKind::Success,
                    Msg::PathChange {
                        change: *change,
                        dir: dir.display().to_string(),
                        scope: Scope::User,
                    },
                    detail,
                );
            }
            Err(t) => self.toast(ToastKind::Error, GuiText::PathFailed, t.clone()),
        }
        // Show the real state after the attempt.
        let updated = {
            let mut cached = self.env_status.borrow_mut();
            if let Some(c) = cached.as_mut() {
                c.path = Some(status.clone());
            }
            cached.clone()
        };
        if let Some(st) = updated {
            self.push_env_status(&st);
        }
        if let Err(t) = &r {
            let s = self.ui.global::<SettingsState>();
            s.set_path_on(status.as_ref().ok().copied().unwrap_or(!on));
            s.set_path_state(PathState::Error);
            s.set_path_error(self.text(t).into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_maps_defaults() {
        let v = view_of(&Settings::default());
        assert_eq!(v.language_index, 0);
        assert_eq!(v.theme_index, 0);
        assert!(v.show_tray);
        assert_eq!(v.poll_index, 2, "30 s preset");
        assert_eq!(v.probe_tcp_ports, "3389, 445, 22");
        assert_eq!(v.default_port, 9);
        assert_eq!(v.repeat, 3);
        assert_eq!(v.interval_ms, 100);
        assert_eq!(v.verify_timeout_secs, 120);
        assert_eq!(v.probe_timeout_ms, 1000);
        // Every key maps back to the same value: applying the unchanged view changes nothing.
        let s = Settings::default();
        for key in UI_KEYS {
            assert_eq!(apply(key, &v, &s).unwrap(), None, "{key}");
        }
    }

    #[test]
    fn custom_poll_value_is_never_rewritten() {
        let mut s = Settings::default();
        s.set_key("gui.poll_interval_secs", "45").unwrap();
        let v = view_of(&s);
        assert_eq!(v.poll_index, POLL_CUSTOM_INDEX);
        assert_eq!(v.poll_custom_secs, 45);
        assert_eq!(value_for("gui.poll_interval_secs", &v), None);
        assert_eq!(apply("gui.poll_interval_secs", &v, &s).unwrap(), None);
        // Picking a preset writes it.
        let mut v2 = v.clone();
        v2.poll_index = 0;
        let (val, next) = apply("gui.poll_interval_secs", &v2, &s).unwrap().unwrap();
        assert_eq!(val, "0");
        assert_eq!(next.gui.poll_interval_secs, 0);
    }

    #[test]
    fn ranges_are_enforced() {
        let s = Settings::default();
        let mut v = view_of(&s);
        v.repeat = 99;
        v.interval_ms = -5;
        v.verify_timeout_secs = 1;
        v.probe_timeout_ms = 100_000;
        v.default_port = 70000;
        assert_eq!(value_for("wake.repeat", &v).unwrap(), "10");
        assert_eq!(value_for("wake.interval_ms", &v).unwrap(), "0");
        assert_eq!(value_for("wake.verify_timeout_secs", &v).unwrap(), "10");
        assert_eq!(value_for("probe.timeout_ms", &v).unwrap(), "30000");
        assert_eq!(value_for("wake.port", &v).unwrap(), "65535");
        let (_, next) = apply("wake.repeat", &v, &s).unwrap().unwrap();
        assert_eq!(next.wake.repeat, 10);
    }

    #[test]
    fn choices_and_lists() {
        let s = Settings::default();
        let mut v = view_of(&s);
        v.language_index = 1;
        v.theme_index = 2;
        v.probe_method_index = 3;
        v.renderer_index = 1;
        v.probe_tcp_ports = "２２，８０".into();
        v.show_tray = false;
        assert_eq!(value_for("language", &v).unwrap(), "ja");
        assert_eq!(value_for("gui.theme", &v).unwrap(), "dark");
        assert_eq!(value_for("probe.method", &v).unwrap(), "none");
        assert_eq!(value_for("gui.renderer", &v).unwrap(), "software");
        assert_eq!(value_for("probe.tcp_ports", &v).unwrap(), "22, 80");
        assert_eq!(value_for("gui.show_tray", &v).unwrap(), "false");
        let (_, next) = apply("probe.tcp_ports", &v, &s).unwrap().unwrap();
        assert_eq!(next.probe.tcp_ports, vec![22, 80]);
        v.probe_tcp_ports = "abc".into();
        assert_eq!(value_for("probe.tcp_ports", &v), None);
        v.language_index = 7;
        assert_eq!(value_for("language", &v), None);
        assert_eq!(value_for("nope", &v), None);
    }

    #[test]
    fn out_of_range_file_values_are_shown_as_is() {
        let text = "[settings.wake]\nrepeat = 50\n[settings.gui]\npoll_interval_secs = 7\n";
        let (cfg, _) = wol_core::Config::from_toml(text).unwrap();
        let v = view_of(&cfg.settings);
        assert_eq!(v.repeat, 50);
        assert_eq!(v.poll_index, POLL_CUSTOM_INDEX);
        assert_eq!(v.poll_custom_secs, 7);
        // Untouched keys are not rewritten.
        assert_eq!(apply("gui.theme", &v, &cfg.settings).unwrap(), None);
    }

    #[test]
    fn changed_keys_lists_differences() {
        let a = Settings::default();
        let mut b = a.clone();
        b.set_key("gui.theme", "dark").unwrap();
        b.set_key("language", "en").unwrap();
        let mut k = changed_keys(&a, &b);
        k.sort();
        assert_eq!(k, vec!["gui.theme", "language"]);
    }

    #[test]
    fn debouncer() {
        let t0 = Instant::now();
        let mut d = Debouncer::default();
        assert!(is_debounced("wake.port"));
        assert!(!is_debounced("gui.theme"));
        d.touch("wake.port", t0);
        d.touch("wake.repeat", t0 + Duration::from_millis(300));
        assert_eq!(d.next_deadline(), Some(t0 + DEBOUNCE));
        assert!(d.due(t0 + Duration::from_millis(499)).is_empty());
        // Another keystroke restarts the delay.
        d.touch("wake.port", t0 + Duration::from_millis(400));
        assert!(d.due(t0 + Duration::from_millis(600)).is_empty());
        assert_eq!(d.due(t0 + Duration::from_millis(800)), vec!["wake.repeat"]);
        assert!(d.is_pending("wake.port"));
        assert_eq!(d.drain(), vec!["wake.port"]);
        assert_eq!(d.next_deadline(), None);
    }
}
