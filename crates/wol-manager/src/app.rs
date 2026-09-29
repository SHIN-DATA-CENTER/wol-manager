//! The application object. It lives on the UI thread in a thread-local and owns the models,
//! timers, worker pools and the store-thread handle (plan §7.3). Workers get only `Send`
//! data and report back through [`crate::workers::post_ui`].
//!
//! Borrow discipline: `RefCell` borrows are kept short and never held across calls that may
//! run Slint callbacks or model filters.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use slint::{
    CloseRequestResponse, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel,
};
use wol_core::i18n::{Lang, LangSetting, Msg};
use wol_core::netif::NetInterface;
use wol_core::probe::{self, ProbeSpec};
use wol_core::send::{self, WakeOutcome, WakeReport, WakeRequest};
use wol_core::store::{ConfigLocation, ConfigSource, LoadWarning, Loaded, ReadOnlyReason, Store};
use wol_core::{Config, Error, HostId};

use crate::editor::EditorSession;
use crate::geometry::{GuiState, WindowGeometry};
use crate::persist::{Op, OpOutput, StoreEvent, StoreHandle};
use crate::rows::{self, HostList};
use crate::scheduler::{self, Event, Job, Scheduler};
use crate::session::{SessionEvent, SessionWindow};
use crate::settings::{Debouncer, EnvStatus};
use crate::texts::{GuiText, Text};
use crate::theme::ThemeState;
use crate::tray::Tray;
use crate::workers::{Pool, post_ui};
use crate::{
    AboutInfo, AppState, AppWindow, ConfirmKind, ConfirmRequest, EditorMode, InterfaceOption,
    Notice, NoticeKind, OverlayKind, StorageMode, Toast, ToastKind,
};

thread_local! {
    static APP: RefCell<Option<Rc<App>>> = const { RefCell::new(None) };
}

/// Makes `app` reachable through [`with`].
pub fn install(app: Rc<App>) {
    APP.with(|a| *a.borrow_mut() = Some(app));
}

/// Removes the app from the thread-local (shutdown).
pub fn take() -> Option<Rc<App>> {
    APP.with(|a| a.borrow_mut().take())
}

/// Runs `f` with the app (UI thread only). `None` before `install` / after `take`.
pub fn with<R>(f: impl FnOnce(&App) -> R) -> Option<R> {
    let app = APP.with(|a| a.borrow().clone())?;
    Some(f(&app))
}

/// Toast lifetime by kind (contract §2).
pub fn toast_duration(kind: ToastKind) -> Duration {
    match kind {
        ToastKind::Info | ToastKind::Success => Duration::from_secs(4),
        ToastKind::Warning | ToastKind::Error => Duration::from_secs(8),
    }
}

/// Maximum number of toasts kept.
pub const MAX_TOASTS: usize = 3;

/// UI language and the name for `select_bundled_translation` ("" = English source strings).
pub fn ui_language(setting: LangSetting, env: Option<&str>) -> (Lang, &'static str) {
    let lang = wol_core::i18n::resolve_lang(setting, env);
    (lang, bundle_name(lang))
}

/// Bundled translation name for a language.
pub fn bundle_name(lang: Lang) -> &'static str {
    match lang {
        Lang::Ja => "ja",
        Lang::En => "",
    }
}

/// Status-bar storage mode for a location.
pub fn storage_mode(loc: &ConfigLocation) -> StorageMode {
    match loc.source {
        ConfigSource::Flag | ConfigSource::Env => StorageMode::Custom,
        ConfigSource::Portable => StorageMode::Portable,
        ConfigSource::AppData => StorageMode::Standard,
    }
}

/// Everything `main` prepared before the UI existed.
pub struct Startup {
    /// Resolved settings location.
    pub location: ConfigLocation,
    /// `--config-dir`.
    pub flag: Option<PathBuf>,
    /// Path of this exe.
    pub exe: PathBuf,
    /// Log file in use.
    pub log_file: Option<PathBuf>,
    /// The store (its poll baseline was set by `load`).
    pub store: Store,
    /// Result of the startup load.
    pub loaded: Result<Loaded, Error>,
    /// `WOL_MANAGER_LANG`.
    pub lang_env: Option<String>,
    /// `SLINT_BACKEND` ("" = not set).
    pub slint_backend: String,
    /// UI language chosen at startup.
    pub lang: Lang,
    /// Theme state after the startup decision.
    pub theme: ThemeState,
    /// The tray icon (when shown and creatable).
    pub tray: Option<Tray>,
    /// The tray could not be created at all.
    pub tray_failed: bool,
}

/// Tray availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    /// Not shown (setting off).
    Off,
    /// Created; waiting for the icon to appear (attempts left).
    Checking(u32),
    /// The icon is there.
    Available,
    /// It could not be created.
    Unavailable,
}

/// What a queued store update belongs to.
pub(crate) enum Pending {
    Save {
        token: u64,
        mode: EditorMode,
        name: String,
        id: HostId,
    },
    Delete {
        name: String,
    },
    Settings,
}

struct ToastEntry {
    id: i32,
    kind: ToastKind,
    text: Text,
    detail: Text,
}

struct NoticeEntry {
    kind: NoticeKind,
    detail: Text,
}

/// Static facts about the process.
pub struct Env {
    /// This exe.
    pub exe: PathBuf,
    /// Log file (for the settings page / crash box).
    pub log_file: Option<PathBuf>,
    /// `WOL_MANAGER_LANG`.
    pub lang_env: Option<String>,
    /// `SLINT_BACKEND`.
    pub slint_backend: String,
}

impl Env {
    /// Folder of the log file.
    pub fn log_dir(&self, loc: &ConfigLocation) -> PathBuf {
        self.log_file
            .as_ref()
            .and_then(|p| p.parent().map(PathBuf::from))
            .unwrap_or_else(|| loc.log_dir())
    }

    /// `THIRD-PARTY-NOTICES.txt` next to the exe.
    pub fn notices_file(&self) -> PathBuf {
        self.exe
            .parent()
            .map(|d| d.join("THIRD-PARTY-NOTICES.txt"))
            .unwrap_or_default()
    }
}

/// The application (UI thread only).
pub struct App {
    /// Main window.
    pub ui: AppWindow,
    pub(crate) tray: RefCell<Option<Tray>>,
    pub(crate) tray_state: Cell<TrayState>,
    pub(crate) list: HostList,
    groups: Rc<VecModel<SharedString>>,
    toasts_model: Rc<VecModel<Toast>>,
    notices_model: Rc<VecModel<Notice>>,
    pub(crate) ifaces_model: Rc<VecModel<InterfaceOption>>,
    pub(crate) cfg: RefCell<Config>,
    pub(crate) sched: RefCell<Scheduler>,
    toasts: RefCell<Vec<ToastEntry>>,
    next_toast: Cell<i32>,
    notices: RefCell<Vec<NoticeEntry>>,
    pub(crate) editor: RefCell<Option<EditorSession>>,
    next_token: Cell<u64>,
    pub(crate) ifaces: RefCell<Vec<NetInterface>>,
    pub(crate) env: Env,
    pub(crate) location: RefCell<ConfigLocation>,
    pub(crate) lang: Cell<Lang>,
    pub(crate) theme: Cell<ThemeState>,
    pending: RefCell<HashMap<u64, Pending>>,
    next_tag: Cell<u64>,
    deferred: RefCell<Option<Config>>,
    pub(crate) debounce: RefCell<Debouncer>,
    pub(crate) debounce_timer: Timer,
    tick_timer: Timer,
    ticks: Cell<u64>,
    pub(crate) probe_pool: Pool,
    pub(crate) io_pool: Pool,
    store: RefCell<Option<StoreHandle>>,
    last_geometry: Cell<Option<WindowGeometry>>,
    /// Last maximized state seen while the window was visible and not minimized (a hidden
    /// window reports `false`); seeded from `gui-state.toml`.
    last_maximized: Cell<bool>,
    pending_geometry: Cell<Option<crate::geometry::Placement>>,
    gui_state: RefCell<GuiState>,
    quitting: Cell<bool>,
    /// Settings, geometry and the store were saved (session end or shutdown).
    state_saved: Cell<bool>,
    /// Hidden top-level window for session end and `TaskbarCreated` (`crate::session`).
    session: Option<SessionWindow>,
    /// Bumped whenever a tray icon is created or removed; stale availability checks stop.
    pub(crate) tray_gen: Cell<u64>,
    /// A tray re-creation after `TaskbarCreated` is scheduled.
    pub(crate) tray_recreate_pending: Cell<bool>,
    pub(crate) env_status: RefCell<Option<EnvStatus>>,
    pub(crate) portable_busy: Cell<bool>,
}

fn parse_id(id: &str) -> Option<HostId> {
    HostId::parse_str(id.trim()).ok()
}

impl App {
    /// Builds the app, starts the worker pools and the store thread, and pushes the initial
    /// state into the UI (no callbacks are wired yet; see `bind`).
    pub fn new(ui: AppWindow, s: Startup) -> Rc<App> {
        let (cfg, load_error, loaded_meta) = match s.loaded {
            Ok(l) => {
                let meta = (l.read_only_reason.clone(), l.warnings.clone());
                (l.config, None, Some(meta))
            }
            Err(e) => (Config::default(), Some(e), None),
        };
        let poll = cfg.settings.gui.effective_poll_interval();
        let tray_state = match (&s.tray, s.tray_failed) {
            (_, true) => TrayState::Unavailable,
            (Some(_), false) => TrayState::Checking(crate::tray::TRAY_CHECKS),
            (None, false) => TrayState::Off,
        };
        let store = StoreHandle::start(s.store, s.flag.clone(), |ev| {
            post_ui(move |app| app.on_store_event(ev));
        });
        let gui_state = crate::geometry::load(&s.location.gui_state_file());
        let session = match SessionWindow::create(|ev| {
            with(|a| a.on_session_event(ev));
        }) {
            Ok(w) => Some(w),
            Err(e) => {
                log::warn!(
                    "cannot create the session window (error {e}); state is not saved at logoff"
                );
                None
            }
        };
        let app = Rc::new(App {
            ui,
            tray: RefCell::new(s.tray),
            tray_state: Cell::new(tray_state),
            list: HostList::new(),
            groups: Rc::new(VecModel::default()),
            toasts_model: Rc::new(VecModel::default()),
            notices_model: Rc::new(VecModel::default()),
            ifaces_model: Rc::new(VecModel::default()),
            // Settings are already applied (language, theme, tray) by `main`: start from them so
            // that the first reconcile has no setting side effects.
            cfg: RefCell::new(Config {
                settings: cfg.settings.clone(),
                ..Config::default()
            }),
            sched: RefCell::new(Scheduler::new(poll)),
            toasts: RefCell::new(Vec::new()),
            next_toast: Cell::new(1),
            notices: RefCell::new(Vec::new()),
            editor: RefCell::new(None),
            next_token: Cell::new(1),
            ifaces: RefCell::new(Vec::new()),
            env: Env {
                exe: s.exe,
                log_file: s.log_file,
                lang_env: s.lang_env,
                slint_backend: s.slint_backend,
            },
            location: RefCell::new(s.location),
            lang: Cell::new(s.lang),
            theme: Cell::new(s.theme),
            pending: RefCell::new(HashMap::new()),
            next_tag: Cell::new(1),
            deferred: RefCell::new(None),
            debounce: RefCell::new(Debouncer::default()),
            debounce_timer: Timer::default(),
            tick_timer: Timer::default(),
            ticks: Cell::new(0),
            probe_pool: Pool::new("probe", 8),
            io_pool: Pool::new("io", 2),
            store: RefCell::new(Some(store)),
            last_geometry: Cell::new(None),
            last_maximized: Cell::new(false),
            pending_geometry: Cell::new(None),
            gui_state: RefCell::new(gui_state),
            quitting: Cell::new(false),
            state_saved: Cell::new(false),
            session,
            tray_gen: Cell::new(0),
            tray_recreate_pending: Cell::new(false),
            env_status: RefCell::new(None),
            portable_busy: Cell::new(false),
        });
        app.init_ui(cfg);
        if let Some(e) = load_error {
            log::warn!("config could not be loaded: {e}");
            app.set_notice(NoticeKind::ConfigLoadFailed, Text::error(&e));
        }
        if let Some((reason, warnings)) = loaded_meta {
            app.apply_load_meta(reason.as_ref(), &warnings);
        }
        if tray_state == TrayState::Unavailable {
            // `main` shows the window (the tray is not usable).
            app.tray_unavailable(false);
        }
        app
    }

    fn init_ui(&self, cfg: Config) {
        let about = self.ui.global::<AboutInfo>();
        about.set_version(env!("CARGO_PKG_VERSION").into());
        about.set_notices_available(self.env.notices_file().is_file());

        let st = self.ui.global::<AppState>();
        st.set_hosts(self.list.model());
        st.set_groups(ModelRc::from(self.groups.clone()));
        st.set_toasts(ModelRc::from(self.toasts_model.clone()));
        st.set_notices(ModelRc::from(self.notices_model.clone()));
        st.set_lang_ja(self.lang.get() == Lang::Ja);
        self.ui
            .global::<crate::EditorState>()
            .set_interfaces(ModelRc::from(self.ifaces_model.clone()));
        self.push_location();
        self.reconcile_from(cfg);
        crate::settings::push_view(
            &self.ui,
            &crate::settings::view_of(&self.cfg.borrow().settings),
            &Debouncer::default(),
        );
        self.update_tray_ui();
        self.refresh_interfaces();
        // Portable / PATH facts for the settings page (read-only; ready before it opens).
        self.refresh_env_status();
    }

    /// Starts the 1 s scheduler timer and the tray check.
    pub fn start_timers(&self) {
        self.tick_timer
            .start(TimerMode::Repeated, Duration::from_secs(1), || {
                with(|a| a.on_tick());
            });
        if matches!(self.tray_state.get(), TrayState::Checking(_)) {
            self.schedule_tray_check();
        }
        // First round right away instead of after one second.
        self.on_tick();
    }

    // ---------------------------------------------------------------------------------------
    // Language / texts

    /// Selects the UI language for `setting` and re-renders Rust-made texts.
    pub(crate) fn apply_language(&self, setting: LangSetting) {
        let (lang, name) = ui_language(setting, self.env.lang_env.as_deref());
        let old = self.lang.replace(lang);
        if let Err(e) = slint::select_bundled_translation(name) {
            log::warn!("select_bundled_translation({name:?}): {e}");
        }
        self.ui.global::<AppState>().set_lang_ja(lang == Lang::Ja);
        if old != lang {
            log::info!("language: {}", lang.code());
            self.push_toasts();
            self.push_notices();
            self.update_tray_ui();
            self.retranslate_editor(old);
        }
    }

    pub(crate) fn text(&self, t: &Text) -> String {
        t.render(self.lang.get())
    }

    // ---------------------------------------------------------------------------------------
    // Toasts and notices

    /// Shows a toast (cap 3, expires after 4 s / 8 s).
    pub(crate) fn toast(&self, kind: ToastKind, text: impl Into<Text>, detail: Text) {
        let id = self.next_toast.get();
        self.next_toast.set(id.wrapping_add(1).max(1));
        {
            let mut t = self.toasts.borrow_mut();
            t.push(ToastEntry {
                id,
                kind,
                text: text.into(),
                detail,
            });
            let excess = t.len().saturating_sub(MAX_TOASTS);
            t.drain(..excess);
        }
        self.push_toasts();
        Timer::single_shot(toast_duration(kind), move || {
            with(|a| a.dismiss_toast(id));
        });
    }

    fn push_toasts(&self) {
        let lang = self.lang.get();
        let v: Vec<Toast> = self
            .toasts
            .borrow()
            .iter()
            .map(|t| Toast {
                id: t.id,
                kind: t.kind,
                text: t.text.render(lang).into(),
                detail: t.detail.render(lang).into(),
            })
            .collect();
        self.toasts_model.set_vec(v);
    }

    /// Removes a toast.
    pub fn dismiss_toast(&self, id: i32) {
        let removed = {
            let mut t = self.toasts.borrow_mut();
            let n = t.len();
            t.retain(|e| e.id != id);
            n != t.len()
        };
        if removed {
            self.push_toasts();
        }
    }

    /// Shows / replaces a notice (one per kind).
    pub(crate) fn set_notice(&self, kind: NoticeKind, detail: Text) {
        {
            let mut n = self.notices.borrow_mut();
            match n.iter_mut().find(|e| e.kind == kind) {
                Some(e) => e.detail = detail,
                None => n.push(NoticeEntry { kind, detail }),
            }
        }
        self.push_notices();
    }

    /// Removes a notice.
    pub(crate) fn clear_notice(&self, kind: NoticeKind) {
        let removed = {
            let mut n = self.notices.borrow_mut();
            let len = n.len();
            n.retain(|e| e.kind != kind);
            len != n.len()
        };
        if removed {
            self.push_notices();
        }
    }

    fn push_notices(&self) {
        let lang = self.lang.get();
        let v: Vec<Notice> = self
            .notices
            .borrow()
            .iter()
            .map(|n| Notice {
                kind: n.kind,
                detail: n.detail.render(lang).into(),
            })
            .collect();
        self.notices_model.set_vec(v);
    }

    fn apply_load_meta(&self, reason: Option<&ReadOnlyReason>, warnings: &[LoadWarning]) {
        match reason {
            Some(ReadOnlyReason::NotWritable { dir }) => {
                self.set_notice(
                    NoticeKind::ConfigReadOnly,
                    Text::Data(dir.display().to_string()),
                );
                self.clear_notice(NoticeKind::ConfigNewerVersion);
            }
            Some(ReadOnlyReason::NewerSchema { found, supported }) => {
                self.set_notice(
                    NoticeKind::ConfigNewerVersion,
                    Text::Data(format!("schema_version = {found} (> {supported})")),
                );
                self.clear_notice(NoticeKind::ConfigReadOnly);
            }
            None => {
                self.clear_notice(NoticeKind::ConfigReadOnly);
                self.clear_notice(NoticeKind::ConfigNewerVersion);
            }
        }
        let marker = warnings.iter().find_map(|w| match w {
            LoadWarning::MarkerIgnored { marker } => Some(marker.display().to_string()),
            _ => None,
        });
        match marker {
            Some(m) => self.set_notice(NoticeKind::PortableMarkerIgnored, Text::Data(m)),
            None => self.clear_notice(NoticeKind::PortableMarkerIgnored),
        }
        for w in warnings {
            log::info!("load: {w:?}");
        }
    }

    /// InfoBar action (only "Reload" of `ConfigLoadFailed`).
    pub fn notice_action(&self, kind: NoticeKind) {
        if kind == NoticeKind::ConfigLoadFailed {
            self.request_reload();
        }
    }

    /// InfoBar close button.
    pub fn dismiss_notice(&self, kind: NoticeKind) {
        if kind != NoticeKind::ConfigLoadFailed {
            self.clear_notice(kind);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Model sync

    pub(crate) fn push_location(&self) {
        let loc = self.location.borrow().clone();
        let st = self.ui.global::<AppState>();
        st.set_storage_mode(storage_mode(&loc));
        st.set_storage_path(loc.dir.display().to_string().into());
        st.set_portable(loc.is_portable());
        self.ui
            .global::<crate::SettingsState>()
            .set_log_dir(self.env.log_dir(&loc).display().to_string().into());
    }

    /// Makes `cfg` the current config: rows (status kept by id), groups, counts, tray menu,
    /// settings UI and side effects of changed settings.
    pub(crate) fn reconcile_from(&self, cfg: Config) {
        let now = Instant::now();
        let old_settings = std::mem::replace(&mut *self.cfg.borrow_mut(), cfg).settings;
        let changed = {
            let cfg = self.cfg.borrow();
            crate::settings::changed_keys(&old_settings, &cfg.settings)
        };
        {
            let cfg = self.cfg.borrow();
            let mut sched = self.sched.borrow_mut();
            sched.set_poll(cfg.settings.gui.effective_poll_interval(), now);
            if sched.sync(&cfg, now) {
                self.ui
                    .global::<AppState>()
                    .set_last_check(crate::logging::clock().into());
            }
        }
        {
            let cfg = self.cfg.borrow();
            let sched = self.sched.borrow();
            self.list.reconcile(&cfg, |h| sched.row_state(h.id));
            let groups: Vec<SharedString> = cfg.groups().into_iter().map(Into::into).collect();
            if self.groups.iter().ne(groups.iter().cloned()) {
                self.groups.set_vec(groups);
            }
        }
        self.ensure_group_filter();
        self.sync_selection();
        self.rebuild_tray_hosts();
        self.update_status_ui();
        let st = self.ui.global::<AppState>();
        st.set_host_count(i32::try_from(self.list.total()).unwrap_or(i32::MAX));
        st.set_auto_check_off(self.cfg.borrow().settings.gui.poll_interval_secs == 0);
        if !changed.is_empty() {
            self.apply_setting_effects(&changed);
            let view = crate::settings::view_of(&self.cfg.borrow().settings);
            crate::settings::push_view(&self.ui, &view, &self.debounce.borrow());
        }
    }

    fn ensure_group_filter(&self) {
        let st = self.ui.global::<AppState>();
        let g = st.get_group_filter();
        if g.is_empty() {
            return;
        }
        let key = wol_core::normalize::name_key(&g);
        let exists = self
            .groups
            .iter()
            .any(|x| wol_core::normalize::name_key(&x) == key);
        if !exists {
            st.set_group_filter(SharedString::default());
            self.list.set_group("");
        }
    }

    /// Re-syncs `selected-row` with `selected-id` (contract §9.2).
    pub(crate) fn sync_selection(&self) {
        let st = self.ui.global::<AppState>();
        let sel = st.get_selected_id();
        let (row, id) = rows::sync_selection(&self.list.visible_ids(), &sel);
        if st.get_selected_row() != row {
            st.set_selected_row(row);
        }
        if id != sel {
            st.set_selected_id(id);
        }
    }

    /// Search box changed.
    pub fn search_changed(&self, text: &str) {
        self.list.set_query(text);
        self.sync_selection();
    }

    /// Group filter changed.
    pub fn group_filter_changed(&self, group: &str) {
        self.list.set_group(group);
        self.sync_selection();
    }

    fn refresh_row(&self, id: HostId) {
        let st = self.sched.borrow().row_state(id);
        let sid = id.to_string();
        self.list.set_state(&sid, st);
        if let Some(t) = self.tray.borrow().as_ref()
            && let Some(i) = t.hosts.iter().position(|h| h.id == sid.as_str())
            && let Some(mut h) = t.hosts.row_data(i)
            && h.status != st.status
        {
            h.status = st.status;
            t.hosts.set_row_data(i, h);
        }
    }

    /// Counts, `checking`, `animating` and the tray tooltip.
    pub(crate) fn update_status_ui(&self) {
        let visible = self.window_visible();
        let (online, checking, animating, waking) = {
            let s = self.sched.borrow();
            (
                s.online_count(),
                s.checking(),
                scheduler::animating(visible, &s),
                s.waking_count(),
            )
        };
        let st = self.ui.global::<AppState>();
        st.set_online_count(i32::try_from(online).unwrap_or(i32::MAX));
        if st.get_checking() != checking {
            st.set_checking(checking);
        }
        if st.get_animating() != animating {
            st.set_animating(animating);
        }
        if let Some(t) = self.tray.borrow().as_ref() {
            let tip = if waking > 0 {
                GuiText::TrayTipWaking(waking).text(self.lang.get())
            } else {
                String::new()
            };
            if t.tray.get_tip() != tip.as_str() {
                t.tray.set_tip(tip.into());
            }
        }
    }

    fn rebuild_tray_hosts(&self) {
        let tray = self.tray.borrow();
        let Some(t) = tray.as_ref() else {
            return;
        };
        let cfg = self.cfg.borrow();
        let sched = self.sched.borrow();
        let v = rows::tray_hosts(&cfg, crate::tray::MAX_TRAY_HOSTS, |h| sched.row_state(h.id));
        if t.hosts.iter().ne(v.iter().cloned()) {
            t.hosts.set_vec(v);
        }
    }

    pub(crate) fn update_tray_ui(&self) {
        self.rebuild_tray_hosts();
        self.update_status_ui();
    }

    // ---------------------------------------------------------------------------------------
    // Store

    fn next_tag(&self) -> u64 {
        let t = self.next_tag.get();
        self.next_tag.set(t + 1);
        t
    }

    /// Queues a store update.
    pub(crate) fn submit(&self, op: Op, pending: Pending) {
        let tag = self.next_tag();
        self.pending.borrow_mut().insert(tag, pending);
        match self.store.borrow().as_ref() {
            Some(s) => s.update(tag, op),
            None => {
                self.pending.borrow_mut().remove(&tag);
            }
        }
    }

    pub(crate) fn request_reload(&self) {
        if let Some(s) = self.store.borrow().as_ref() {
            s.reload();
        }
    }

    pub(crate) fn store_portable(&self, cmd: crate::persist::PortableCmd) {
        if let Some(s) = self.store.borrow().as_ref() {
            s.portable(&self.env.exe, cmd);
        }
    }

    fn pending_count(&self) -> usize {
        self.pending.borrow().len()
    }

    /// Reconciles with a config from disk, or defers it while own updates are queued (their
    /// results carry newer content).
    fn accept_disk_config(&self, cfg: Config) {
        if self.pending_count() > 0 {
            *self.deferred.borrow_mut() = Some(cfg);
        } else {
            self.deferred.borrow_mut().take();
            self.reconcile_from(cfg);
        }
    }

    pub(crate) fn on_loaded(&self, loaded: Loaded, why: &str) {
        log::info!(
            "{why}: {} host(s) from {}",
            loaded.config.hosts.len(),
            self.location.borrow().config_file().display()
        );
        self.clear_notice(NoticeKind::ConfigLoadFailed);
        self.apply_load_meta(loaded.read_only_reason.as_ref(), &loaded.warnings);
        self.accept_disk_config(loaded.config);
    }

    /// Everything the store thread reports.
    pub fn on_store_event(&self, ev: StoreEvent) {
        match ev {
            StoreEvent::Changed(loaded) => {
                self.on_loaded(*loaded, "config.toml changed externally; reloaded")
            }
            StoreEvent::Reloaded(Ok(loaded)) => self.on_loaded(*loaded, "config.toml reloaded"),
            StoreEvent::Reloaded(Err(e)) | StoreEvent::PollFailed(e) => {
                log::warn!("config.toml could not be read: {e}");
                if matches!(e, Error::ConfigParse { .. }) {
                    self.set_notice(NoticeKind::ConfigLoadFailed, Text::error(&e));
                } else {
                    self.toast(ToastKind::Error, GuiText::ReloadFailed, Text::error(&e));
                }
            }
            StoreEvent::Updated { tag, result } => {
                let pending = self.pending.borrow_mut().remove(&tag);
                match result {
                    Ok(updated) => {
                        if let Some(p) = pending {
                            self.on_op_done(p, &updated.value);
                        }
                        if self.pending_count() == 0 {
                            self.deferred.borrow_mut().take();
                            self.reconcile_from(updated.config);
                        } else {
                            *self.deferred.borrow_mut() = Some(updated.config);
                        }
                    }
                    Err(e) => {
                        if let Some(p) = pending {
                            self.on_op_failed(p, &e);
                        }
                        match &e {
                            Error::NewerSchema { found, supported } => self.set_notice(
                                NoticeKind::ConfigNewerVersion,
                                Text::Data(format!("schema_version = {found} (> {supported})")),
                            ),
                            Error::PortableNotWritable { dir } => self.set_notice(
                                NoticeKind::ConfigReadOnly,
                                Text::Data(dir.display().to_string()),
                            ),
                            Error::ConfigParse { .. } => {
                                self.set_notice(NoticeKind::ConfigLoadFailed, Text::error(&e))
                            }
                            _ => {}
                        }
                        // Undo the optimistic change.
                        self.request_reload();
                    }
                }
            }
            StoreEvent::Portable {
                result,
                location,
                loaded,
            } => self.on_portable_done(result, *location, loaded),
            StoreEvent::Relocated { location, loaded } => self.on_relocated(*location, loaded),
        }
    }

    fn on_op_done(&self, p: Pending, out: &OpOutput) {
        match p {
            Pending::Save {
                token,
                mode,
                name,
                id,
            } => {
                let saved_id = match out {
                    OpOutput::Saved(i) => *i,
                    _ => id,
                };
                self.close_editor_after_save(token);
                let msg = match mode {
                    EditorMode::Edit => Msg::HostUpdated { name },
                    EditorMode::Add | EditorMode::Duplicate => Msg::HostAdded { name },
                };
                self.toast(ToastKind::Success, msg, Text::Empty);
                let st = self.ui.global::<AppState>();
                st.set_selected_id(saved_id.to_string().into());
            }
            Pending::Delete { name } => {
                self.toast(ToastKind::Success, Msg::HostRemoved { name }, Text::Empty);
            }
            Pending::Settings => {}
        }
    }

    fn on_op_failed(&self, p: Pending, e: &Error) {
        match p {
            Pending::Save { token, id, .. } => self.editor_save_failed(token, id, e),
            Pending::Delete { .. } => {
                self.toast(ToastKind::Error, GuiText::DeleteFailed, Text::error(e));
            }
            Pending::Settings => {
                self.toast(ToastKind::Error, GuiText::SettingFailed, Text::error(e));
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Status checks

    pub(crate) fn window_visible(&self) -> bool {
        let w = self.ui.window();
        w.is_visible() && !w.is_minimized()
    }

    fn on_tick(&self) {
        if self.quitting.get() {
            return;
        }
        let now = Instant::now();
        let visible = self.window_visible();
        let (jobs, events) = self.sched.borrow_mut().tick(now, visible);
        for ev in events {
            self.on_sched_event(ev);
        }
        self.dispatch(jobs);
        self.update_status_ui();
        self.track_geometry();
        let n = self.ticks.get() + 1;
        self.ticks.set(n);
        if n.is_multiple_of(2) {
            self.follow_os_theme();
        }
    }

    pub(crate) fn dispatch(&self, jobs: Vec<Job>) {
        if jobs.is_empty() {
            return;
        }
        let specs: Vec<(Job, ProbeSpec)> = {
            let cfg = self.cfg.borrow();
            jobs.into_iter()
                .filter_map(|j| {
                    let h = cfg.get(j.id)?;
                    Some((j, ProbeSpec::for_host(h, &cfg.settings)))
                })
                .collect()
        };
        for (job, spec) in specs {
            self.refresh_row(job.id);
            self.probe_pool.spawn(move || {
                let state = probe::probe(&spec);
                log::debug!("probe {}: {state:?}", spec.label);
                post_ui(move |app| app.on_probe_result(job, state));
            });
        }
    }

    fn on_probe_result(&self, job: Job, state: probe::HostState) {
        let applied =
            self.sched
                .borrow_mut()
                .on_result(job.id, job.generation, &state, Instant::now());
        let Some(a) = applied else {
            log::debug!("dropped stale probe result for {}", job.id);
            return;
        };
        self.refresh_row(job.id);
        if a.round_done {
            self.ui
                .global::<AppState>()
                .set_last_check(crate::logging::clock().into());
        }
        if let Some(ev) = a.event {
            self.on_sched_event(ev);
        }
        self.update_status_ui();
    }

    fn host_name(&self, id: HostId) -> Option<String> {
        self.cfg.borrow().get(id).map(|h| h.name.clone())
    }

    fn on_sched_event(&self, ev: Event) {
        match ev {
            Event::CameOnline(id) => {
                self.refresh_row(id);
                if let Some(label) = self.host_name(id) {
                    self.toast(ToastKind::Success, Msg::CameOnline { label }, Text::Empty);
                }
            }
            Event::WakeTimedOut(id, secs) => {
                self.refresh_row(id);
                if let Some(label) = self.host_name(id) {
                    self.toast(
                        ToastKind::Warning,
                        Msg::WakeTimeout { label, secs },
                        Text::Empty,
                    );
                }
            }
        }
    }

    /// No overlay and no confirm dialog is open.
    pub(crate) fn idle(&self) -> bool {
        let st = self.ui.global::<AppState>();
        st.get_overlay() == OverlayKind::None && !st.get_confirm_open()
    }

    /// F5 / Refresh.
    pub fn refresh(&self) {
        if !self.idle() {
            return;
        }
        let jobs = self.sched.borrow_mut().refresh_all();
        self.dispatch(jobs);
        self.update_status_ui();
    }

    // ---------------------------------------------------------------------------------------
    // Wake

    /// Wake one host (row button, menu, tray).
    pub fn wake(&self, id: &str, from_tray: bool) {
        if !from_tray && !self.idle() {
            return;
        }
        let Some(hid) = parse_id(id) else {
            return;
        };
        self.wake_ids(vec![hid], false);
    }

    fn wake_ids(&self, ids: Vec<HostId>, batch: bool) {
        let now = Instant::now();
        let (reqs, ids): (Vec<WakeRequest>, Vec<HostId>) = {
            let cfg = self.cfg.borrow();
            ids.into_iter()
                .filter_map(|id| {
                    cfg.get(id)
                        .map(|h| (WakeRequest::for_host(h, &cfg.settings), id))
                })
                .unzip()
        };
        if reqs.is_empty() {
            return;
        }
        let verify = self.cfg.borrow().settings.wake.effective_verify_timeout();
        for id in &ids {
            self.sched.borrow_mut().wake_started(*id, now, verify);
            self.refresh_row(*id);
        }
        self.update_status_ui();
        log::info!("waking {} host(s)", reqs.len());
        self.io_pool.spawn(move || {
            let reports = send::wake_many(&reqs);
            post_ui(move |app| app.on_wake_done(ids, reports, batch));
        });
    }

    fn on_wake_done(&self, ids: Vec<HostId>, reports: Vec<WakeReport>, batch: bool) {
        let (mut ok, mut partial, mut failed) = (0usize, 0usize, 0usize);
        for (id, r) in ids.iter().zip(&reports) {
            let outcome = r.outcome();
            log::info!(
                "wake {}: {:?}, {} sent, {} failed, notes {:?}",
                r.label,
                outcome,
                r.sent_count(),
                r.failed_count(),
                r.notes
            );
            match outcome {
                WakeOutcome::Ok => ok += 1,
                WakeOutcome::Partial => partial += 1,
                WakeOutcome::Failed => {
                    failed += 1;
                    self.sched.borrow_mut().wake_failed(*id);
                    self.refresh_row(*id);
                }
            }
        }
        self.update_status_ui();
        if batch {
            let kind = if failed == 0 && partial == 0 {
                ToastKind::Success
            } else if ok + partial == 0 {
                ToastKind::Error
            } else {
                ToastKind::Warning
            };
            let msg = Msg::WakeBatch {
                total: reports.len(),
                ok,
                partial,
                failed,
            };
            self.toast(kind, msg, Text::Empty);
            return;
        }
        let (Some(id), Some(r)) = (ids.first(), reports.first()) else {
            return;
        };
        let label = r.label.clone();
        let first_error = r
            .attempts
            .iter()
            .find_map(|a| a.last_error.clone())
            .or_else(|| {
                r.failures
                    .first()
                    .map(|f| format!("{}: {}", f.target, f.error))
            });
        match r.outcome() {
            WakeOutcome::Ok => {
                let detail = if self.sched.borrow().is_monitored(*id) {
                    Text::Empty
                } else {
                    Text::msg(Msg::WakeNotGuaranteed)
                };
                self.toast(ToastKind::Success, Msg::WakeSent { label }, detail);
            }
            WakeOutcome::Partial => self.toast(
                ToastKind::Warning,
                Msg::WakePartial {
                    label,
                    sent: r.sent_count(),
                    failed: r.failed_count(),
                },
                first_error.map_or(Text::Empty, Text::Data),
            ),
            WakeOutcome::Failed if r.no_destinations() => self.toast(
                ToastKind::Error,
                Msg::WakeNoDestinations { label },
                Text::Empty,
            ),
            WakeOutcome::Failed => self.toast(
                ToastKind::Error,
                Msg::WakeFailed { label },
                first_error.map_or(Text::Empty, Text::Data),
            ),
        }
    }

    /// Host > Wake all visible: asks first.
    pub fn wake_all_visible(&self) {
        if !self.idle() {
            return;
        }
        let count = self.list.visible_count();
        if count == 0 {
            return;
        }
        self.confirm(ConfirmRequest {
            kind: ConfirmKind::WakeAll,
            count: i32::try_from(count).unwrap_or(i32::MAX),
            ..ConfirmRequest::default()
        });
    }

    // ---------------------------------------------------------------------------------------
    // Host actions

    /// Opens the confirm dialog.
    pub(crate) fn confirm(&self, req: ConfirmRequest) {
        let st = self.ui.global::<AppState>();
        if st.get_confirm_open() {
            return;
        }
        st.set_confirm(req);
        st.set_confirm_open(true);
    }

    /// Asks before deleting.
    pub fn delete_host(&self, id: &str) {
        if !self.idle() {
            return;
        }
        let Some(name) = parse_id(id).and_then(|i| self.host_name(i)) else {
            return;
        };
        self.confirm(ConfirmRequest {
            kind: ConfirmKind::DeleteHost,
            host_id: id.into(),
            subject: name.into(),
            ..ConfirmRequest::default()
        });
    }

    fn do_delete(&self, id: HostId) {
        let mut local = self.cfg.borrow().clone();
        let Ok(host) = local.remove_host(id) else {
            return;
        };
        self.sched.borrow_mut().remove(id);
        self.reconcile_from(local);
        self.submit(Op::DeleteHost { id }, Pending::Delete { name: host.name });
    }

    /// Ctrl+C / menu: copy the MAC.
    pub fn copy_mac(&self, id: &str) {
        if !self.idle() {
            return;
        }
        let Some(mac) = self.list.row(id).map(|r| r.mac.to_string()) else {
            return;
        };
        match crate::shell::copy_text(&mac) {
            Ok(()) => self.toast(ToastKind::Info, GuiText::CopiedMac(mac), Text::Empty),
            Err(e) => self.toast(ToastKind::Error, GuiText::ClipboardFailed, Text::Data(e)),
        }
    }

    /// Ctrl+Shift+C / menu: copy the address (ignored without one).
    pub fn copy_address(&self, id: &str) {
        if !self.idle() {
            return;
        }
        let Some(addr) = self
            .list
            .row(id)
            .map(|r| r.address.to_string())
            .filter(|a| !a.is_empty())
        else {
            return;
        };
        match crate::shell::copy_text(&addr) {
            Ok(()) => self.toast(ToastKind::Info, GuiText::CopiedAddress(addr), Text::Empty),
            Err(e) => self.toast(ToastKind::Error, GuiText::ClipboardFailed, Text::Data(e)),
        }
    }

    /// Confirm dialog: primary / alternate button.
    pub fn confirm_accepted(&self, req: ConfirmRequest, alternate: bool) {
        match req.kind {
            ConfirmKind::DeleteHost => {
                if let Some(id) = parse_id(&req.host_id) {
                    self.do_delete(id);
                }
            }
            ConfirmKind::WakeAll => {
                let ids: Vec<HostId> = self
                    .list
                    .visible_ids()
                    .iter()
                    .filter_map(|s| parse_id(s))
                    .collect();
                self.wake_ids(ids, true);
            }
            ConfirmKind::PortableEnable
            | ConfirmKind::PortableDisable
            | ConfirmKind::PortableOverwrite => self.portable_confirmed(&req, alternate),
            ConfirmKind::SaveAsNew => self.save_as_new(&req),
        }
    }

    /// Confirm dialog: Cancel / Esc.
    pub fn confirm_cancelled(&self, req: ConfirmRequest) {
        match req.kind {
            ConfirmKind::PortableEnable
            | ConfirmKind::PortableDisable
            | ConfirmKind::PortableOverwrite => self.portable_reset_switch(),
            ConfirmKind::SaveAsNew => {
                self.ui.global::<crate::EditorState>().set_saving(false);
            }
            ConfirmKind::DeleteHost | ConfirmKind::WakeAll => {}
        }
    }

    /// Overlay closed by the user.
    pub fn overlay_closed(&self, kind: OverlayKind) {
        match kind {
            OverlayKind::Editor => self.discard_editor(),
            OverlayKind::Settings => self.flush_debounce(),
            OverlayKind::About | OverlayKind::None => {}
        }
    }

    pub(crate) fn next_token(&self) -> u64 {
        let t = self.next_token.get();
        self.next_token.set(t + 1);
        t
    }

    /// Help > About.
    pub fn open_about(&self) {
        if !self.idle() {
            return;
        }
        self.ui.global::<AppState>().set_overlay(OverlayKind::About);
    }

    /// Opens something with the shell; a failure becomes a toast.
    pub(crate) fn open_target(&self, target: crate::shell::Target) {
        let what = match &target {
            crate::shell::Target::Folder(p) | crate::shell::Target::File(p) => {
                p.display().to_string()
            }
            crate::shell::Target::Url(u) => u.clone(),
        };
        crate::shell::open(target, move || {
            post_ui(move |app| {
                app.toast(ToastKind::Error, GuiText::OpenFailed(what), Text::Empty);
            });
        });
    }

    /// File > Open settings folder, InfoBar, settings page.
    pub fn open_config_folder(&self) {
        let dir = self.location.borrow().dir.clone();
        self.open_target(crate::shell::Target::Folder(dir));
    }

    /// Links.
    pub fn open_url(&self, url: &str) {
        if crate::shell::is_web_url(url) {
            self.open_target(crate::shell::Target::Url(url.to_owned()));
        } else {
            log::warn!("refusing to open {url:?}");
        }
    }

    /// About > third-party notices.
    pub fn open_notices(&self) {
        self.open_target(crate::shell::Target::File(self.env.notices_file()));
    }

    /// Settings > open log folder.
    pub fn open_log_folder(&self) {
        let dir = self.env.log_dir(&self.location.borrow());
        self.open_target(crate::shell::Target::Folder(dir));
    }

    // ---------------------------------------------------------------------------------------
    // Window, tray, quit

    /// The tray icon is shown and working (so hiding the window is safe).
    pub(crate) fn tray_usable(&self) -> bool {
        self.cfg.borrow().settings.gui.show_tray
            && self.tray.borrow().is_some()
            && matches!(
                self.tray_state.get(),
                TrayState::Available | TrayState::Checking(_)
            )
    }

    fn track_geometry(&self) {
        let w = self.ui.window();
        if let Some(m) =
            crate::geometry::observed_maximized(w.is_visible(), w.is_minimized(), w.is_maximized())
        {
            self.last_maximized.set(m);
        }
        if !w.is_visible() || w.is_minimized() || w.is_maximized() {
            return;
        }
        let pos = w.position();
        let size = w.size();
        if size.width == 0 || size.height == 0 {
            return;
        }
        self.last_geometry.set(Some(WindowGeometry {
            x: pos.x,
            y: pos.y,
            width: size.width,
            height: size.height,
            maximized: false,
        }));
    }

    /// Hides the window (to the tray).
    pub(crate) fn hide_window(&self) {
        self.track_geometry();
        if let Err(e) = self.ui.hide() {
            log::warn!("hide: {e}");
        }
        self.update_status_ui();
    }

    /// Shows, restores and activates the window (tray click, second instance).
    pub fn show_window(&self) {
        if self.quitting.get() {
            return;
        }
        let w = self.ui.window();
        w.set_minimized(false);
        if let Err(e) = self.ui.show() {
            log::warn!("show: {e}");
        }
        if self.idle() {
            self.ui.invoke_focus_list();
        }
        self.bring_to_front(4);
        self.finish_geometry(40);
        self.update_status_ui();
    }

    fn bring_to_front(&self, attempts: u32) {
        match crate::shell::hwnd_of(self.ui.window()) {
            Some(h) => {
                if !crate::shell::bring_to_front(h) {
                    log::debug!("SetForegroundWindow refused; flashing the taskbar button");
                }
            }
            None if attempts > 0 => {
                Timer::single_shot(Duration::from_millis(50), move || {
                    with(|a| a.bring_to_front(attempts - 1));
                });
            }
            None => log::debug!("no window handle yet"),
        }
    }

    /// Window close button.
    pub fn on_close_requested(&self) -> CloseRequestResponse {
        if self.cfg.borrow().settings.gui.close_to_tray && self.tray_usable() {
            self.track_geometry();
            let r = CloseRequestResponse::HideWindow;
            // Hidden by Slint after returning; refresh the animation flag afterwards.
            Timer::single_shot(Duration::ZERO, || {
                with(|a| a.update_status_ui());
            });
            return r;
        }
        self.request_quit();
        CloseRequestResponse::HideWindow
    }

    /// File > Close window (Ctrl+W).
    pub fn close_window(&self) {
        if self.tray_usable() {
            self.hide_window();
        } else {
            self.request_quit();
        }
    }

    /// The user minimized the window.
    pub fn window_minimized(&self) {
        if self.cfg.borrow().settings.gui.minimize_to_tray && self.tray_usable() {
            self.hide_window();
        } else {
            self.update_status_ui();
        }
    }

    /// Ends the event loop (the rest happens in [`App::shutdown`]). Ignores `close_to_tray`.
    pub fn request_quit(&self) {
        if self.quitting.replace(true) {
            return;
        }
        log::info!("quitting");
        // Before hiding: a hidden window reports neither its rectangle nor "maximized".
        self.record_final_geometry();
        self.tick_timer.stop();
        let _ = self.ui.hide();
        if let Some(t) = self.tray.borrow().as_ref() {
            let _ = t.tray.hide();
        }
        if let Err(e) = slint::quit_event_loop() {
            log::warn!("quit_event_loop: {e}");
        }
    }

    /// `true` once quitting started (quit request or session end).
    pub(crate) fn is_quitting(&self) -> bool {
        self.quitting.get()
    }

    /// Messages of the hidden session window.
    fn on_session_event(&self, ev: SessionEvent) {
        match ev {
            SessionEvent::Ending { flags } => self.end_session(flags),
            SessionEvent::TaskbarCreated => self.taskbar_created(),
        }
    }

    /// `WM_ENDSESSION` (logoff, shutdown, restart, Restart Manager). Session end never goes
    /// through [`App::request_quit`] and Windows may terminate the process as soon as the
    /// window procedure returns, so everything [`App::shutdown`] saves is saved right here.
    /// Then the event loop is asked to end, for the case that the process lives on.
    fn end_session(&self, flags: u32) {
        if self.state_saved.get() {
            return;
        }
        log::info!(
            "session ending ({}); saving",
            crate::session::describe_flags(flags)
        );
        self.quitting.set(true);
        self.tick_timer.stop();
        let busy = self.pending_count() > 0 || self.debounce.borrow().next_deadline().is_some();
        let session = self.session.as_ref();
        if busy && let Some(s) = session {
            s.set_block_reason(Some(&GuiText::SavingOnExit.text(self.lang.get())));
        }
        self.save_state();
        if let Some(s) = session {
            s.set_block_reason(None);
        }
        log::logger().flush();
        if let Err(e) = slint::quit_event_loop() {
            log::debug!("quit_event_loop: {e}");
        }
    }

    /// Remembers the geometry to save: the last normal rectangle and the last known maximized
    /// state (also when the window is hidden in the tray or was never shown).
    fn record_final_geometry(&self) {
        self.track_geometry();
        self.last_geometry.set(crate::geometry::final_geometry(
            self.last_geometry.get(),
            self.last_maximized.get(),
        ));
    }

    /// Pending settings, window geometry, store flush + join (≤ 5 s). Runs once: at session
    /// end or after the event loop.
    fn save_state(&self) {
        if self.state_saved.replace(true) {
            return;
        }
        self.quitting.set(true);
        self.flush_debounce();
        self.debounce_timer.stop();
        self.tick_timer.stop();
        self.record_final_geometry();
        if let Some(g) = self.last_geometry.get() {
            let path = self.location.borrow().gui_state_file();
            let mut st = self.gui_state.borrow_mut();
            st.window = Some(g);
            match crate::geometry::save(&path, &st) {
                Ok(()) => log::info!("window geometry saved to {}", path.display()),
                Err(e) => log::warn!("cannot save {}: {e}", path.display()),
            }
        }
        let store = self.store.borrow_mut().take();
        if let Some(store) = store {
            if store.shutdown(crate::persist::FLUSH_TIMEOUT) {
                log::info!("store thread finished");
            } else {
                log::warn!("store thread did not finish within 5 s");
            }
        }
    }

    /// After the event loop: [`App::save_state`] (unless the session end did it already),
    /// then the tray icon is removed.
    pub fn shutdown(&self) {
        self.save_state();
        let tray = self.tray.borrow_mut().take();
        drop(tray);
    }

    /// Applies geometry from `gui-state.toml` before the first `show()`.
    pub fn restore_geometry(&self) {
        let saved = self.gui_state.borrow().window;
        let Some(g) = saved else {
            return;
        };
        let p = crate::geometry::validate(&g, &crate::geometry::work_area_for);
        let w = self.ui.window();
        if let Some((width, height)) = p.size {
            w.set_size(slint::PhysicalSize::new(width, height));
        }
        if let Some((x, y)) = p.position {
            w.set_position(slint::PhysicalPosition::new(x, y));
        }
        // Size and maximize are finished once the window exists (see `finish_geometry`).
        self.pending_geometry.set(Some(p));
        // Keep the saved values until the window reports real ones (a start in the tray may
        // quit without ever showing it).
        self.last_geometry.set(Some(WindowGeometry {
            maximized: false,
            ..g
        }));
        self.last_maximized.set(g.maximized);
        log::debug!("geometry restored: {p:?}");
    }

    /// Completes the restore after the window was created. The native menu bar is attached
    /// after the window got its requested size and takes its height from the client area, so
    /// the size is requested again (winit accounts for the menu now); maximizing comes last
    /// so that the "normal" rectangle is the saved one. Retries until the window exists.
    pub(crate) fn finish_geometry(&self, attempts: u32) {
        let Some(p) = self.pending_geometry.get() else {
            return;
        };
        let w = self.ui.window();
        if !w.is_visible() || crate::shell::hwnd_of(w).is_none() {
            if attempts > 0 {
                Timer::single_shot(Duration::from_millis(30), move || {
                    with(|a| a.finish_geometry(attempts - 1));
                });
            }
            return;
        }
        self.pending_geometry.set(None);
        if let Some((width, height)) = p.size {
            let cur = w.size();
            if (cur.width, cur.height) != (width, height) {
                log::debug!(
                    "size {}x{} after creation; requesting {width}x{height} again",
                    cur.width,
                    cur.height
                );
                w.set_size(slint::PhysicalSize::new(width, height));
            }
        }
        if p.maximized {
            w.set_maximized(true);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Adapters

    /// Re-reads the adapter list on the io pool.
    pub(crate) fn refresh_interfaces(&self) {
        self.io_pool.spawn(|| {
            let list = wol_core::netif::list();
            post_ui(move |app| app.on_interfaces(list));
        });
    }

    fn on_interfaces(&self, list: Vec<NetInterface>) {
        *self.ifaces.borrow_mut() = list;
        self.editor_interfaces_updated();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_resolution() {
        assert_eq!(ui_language(LangSetting::Ja, None), (Lang::Ja, "ja"));
        assert_eq!(ui_language(LangSetting::En, None), (Lang::En, ""));
        // WOL_MANAGER_LANG wins over the setting; invalid values are ignored.
        assert_eq!(ui_language(LangSetting::Ja, Some("en")), (Lang::En, ""));
        assert_eq!(ui_language(LangSetting::En, Some("ja")), (Lang::Ja, "ja"));
        assert_eq!(ui_language(LangSetting::En, Some("xx")), (Lang::En, ""));
        // Auto: the OS language.
        let os = wol_core::i18n::detect_os_lang();
        assert_eq!(ui_language(LangSetting::Auto, None).0, os);
        assert_eq!(ui_language(LangSetting::Auto, Some("auto")).0, os);
    }

    #[test]
    fn toast_lifetimes() {
        assert_eq!(toast_duration(ToastKind::Success), Duration::from_secs(4));
        assert_eq!(toast_duration(ToastKind::Info), Duration::from_secs(4));
        assert_eq!(toast_duration(ToastKind::Warning), Duration::from_secs(8));
        assert_eq!(toast_duration(ToastKind::Error), Duration::from_secs(8));
    }

    #[test]
    fn storage_modes() {
        let mut loc = ConfigLocation::custom("C:\\x");
        assert_eq!(storage_mode(&loc), StorageMode::Custom);
        loc.source = ConfigSource::Env;
        assert_eq!(storage_mode(&loc), StorageMode::Custom);
        loc.source = ConfigSource::Portable;
        assert_eq!(storage_mode(&loc), StorageMode::Portable);
        loc.source = ConfigSource::AppData;
        assert_eq!(storage_mode(&loc), StorageMode::Standard);
    }
}
