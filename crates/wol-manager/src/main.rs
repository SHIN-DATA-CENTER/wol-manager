//! WoL Manager GUI (`wol-manager.exe`).
//!
//! Startup order (plan §7.4): arguments → settings location → logging → single instance →
//! load config → renderer → `AppWindow` + tray → translation → theme → wiring → geometry →
//! show (unless starting in the tray) → timers → event loop. Shutdown: geometry, store flush
//! and join (≤ 5 s), then the app is dropped explicitly. A session end (logoff, shutdown,
//! restart) does the same saving from `WM_ENDSESSION` (see `session`), because the event loop
//! is not left before Windows terminates the process.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

mod app;
mod bind;
mod editor;
mod geometry;
mod logging;
mod persist;
mod remote;
mod rows;
mod scheduler;
mod session;
mod settings;
mod shell;
mod single_instance;
mod texts;
mod theme;
mod tray;
mod workers;

use std::ffi::OsString;
use std::path::PathBuf;

use slint::ComponentHandle;
use wol_core::i18n::{self, LangSetting, Msg};
use wol_core::model::{Renderer, Settings};
use wol_core::store::Store;

use crate::single_instance::{Instance, Signal};
use crate::texts::GuiText;
use crate::theme::{Scheme, ThemeState};

/// Command line of the GUI.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    /// `--config-dir <DIR>` / `--config-dir=<DIR>`.
    config_dir: Option<PathBuf>,
    /// `--tray`: start hidden in the notification area (this time).
    tray: bool,
    /// `--safe-mode`: software renderer.
    safe_mode: bool,
    /// Anything else (logged, ignored).
    unknown: Vec<String>,
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Args {
    let mut out = Args::default();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--tray") => out.tray = true,
            Some("--safe-mode") => out.safe_mode = true,
            Some("--config-dir") => match it.next() {
                Some(v) => out.config_dir = Some(PathBuf::from(v)),
                None => out.unknown.push("--config-dir".into()),
            },
            Some(s) if s.starts_with("--config-dir=") => {
                out.config_dir = Some(PathBuf::from(&s["--config-dir=".len()..]));
            }
            _ => out.unknown.push(a.to_string_lossy().into_owned()),
        }
    }
    out
}

/// Whether to request the software renderer: `--safe-mode` or `gui.renderer = software`,
/// unless `SLINT_BACKEND` is set (it takes precedence).
fn wants_software_renderer(renderer: Renderer, safe_mode: bool, slint_backend: &str) -> bool {
    slint_backend.trim().is_empty() && (safe_mode || renderer == Renderer::Software)
}

fn select_renderer(settings: &Settings, safe_mode: bool, slint_backend: &str) {
    if !slint_backend.trim().is_empty() {
        log::info!("SLINT_BACKEND={slint_backend} overrides the renderer setting");
        return;
    }
    if !wants_software_renderer(settings.gui.renderer, safe_mode, slint_backend) {
        return;
    }
    match slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into())
        .select()
    {
        Ok(()) => log::info!("software renderer selected"),
        Err(e) => log::warn!("cannot select the software renderer ({e}); using the default"),
    }
}

fn fail(lang: i18n::Lang, detail: String) -> i32 {
    log::error!("startup failed: {detail}");
    shell::message_box(&GuiText::StartFailed(detail).text(lang), true);
    1
}

fn main() {
    let code = run();
    log::logger().flush();
    std::process::exit(code);
}

fn run() -> i32 {
    // 1. Arguments.
    let args = parse_args(std::env::args_os().skip(1));
    let lang_env = std::env::var(wol_core::consts::ENV_LANG).ok();
    let early_lang = i18n::resolve_lang(LangSetting::Auto, lang_env.as_deref());

    // 2. Settings location.
    let location = match wol_core::store::resolve(args.config_dir.as_deref()) {
        Ok(l) => l,
        Err(e) => return fail(early_lang, i18n::describe_error(&e, early_lang)),
    };

    // 3. Logging.
    let log_file = logging::init(&location.log_dir());
    logging::install_panic_hook(log_file.clone(), early_lang);
    log::info!(
        "WoL Manager {} starting (pid {}); settings: {} ({:?}); log: {}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        location.dir.display(),
        location.source,
        log_file
            .as_ref()
            .map_or_else(|| "-".to_owned(), |p| p.display().to_string())
    );
    if !args.unknown.is_empty() {
        log::warn!("ignored arguments: {:?}", args.unknown);
    }

    // 4. Single instance. The running instance publishes its settings folder: a start for
    // other settings (--config-dir, WOL_MANAGER_CONFIG_DIR, another portable copy) must not
    // silently show the window that uses them.
    let guard = match single_instance::acquire() {
        Instance::First(g) => {
            single_instance::publish_settings_dir(&location.dir);
            g
        }
        Instance::Second => {
            if let Err(e) = wol_core::instance::check_running_gui(&location.dir) {
                log::warn!("another instance is running with other settings: {e}");
                shell::message_box(&i18n::describe_error(&e, early_lang), false);
                return 1;
            }
            log::info!("another instance is running; asking it to show its window");
            if single_instance::signal_first() {
                return 0;
            }
            log::warn!("the running instance could not be signalled");
            shell::message_box(&Msg::AlreadyRunningElsewhere.text(early_lang), false);
            return 1;
        }
    };

    // 5. Settings.
    let store = Store::new(location.clone());
    let loaded = store.load();
    let settings = loaded
        .as_ref()
        .map(|l| l.config.settings.clone())
        .unwrap_or_default();

    // 6. Renderer (before the first component).
    let slint_backend = std::env::var("SLINT_BACKEND").unwrap_or_default();
    select_renderer(&settings, args.safe_mode, &slint_backend);

    // 7. Window and tray.
    let ui = match AppWindow::new() {
        Ok(ui) => ui,
        Err(e) => return fail(early_lang, e.to_string()),
    };
    let (tray, tray_failed) = if !settings.gui.show_tray {
        (None, false)
    } else if !tray::shell_tray_present() {
        log::warn!("no taskbar (Shell_TrayWnd); the tray icon is unavailable");
        (None, true)
    } else {
        match tray::Tray::create() {
            Ok(t) => (Some(t), false),
            Err(e) => {
                log::warn!("cannot create the tray icon: {e}");
                (None, true)
            }
        }
    };

    // 8. Translation (after the first component exists).
    let (lang, bundle) = app::ui_language(settings.language, lang_env.as_deref());
    if let Err(e) = slint::select_bundled_translation(bundle) {
        log::warn!("select_bundled_translation({bundle:?}): {e}");
    }

    // 9. Theme ("system" leaves Palette.color-scheme alone).
    let scheme = theme::startup(settings.gui.theme);
    let mut theme_state = ThemeState::default();
    theme::note_startup(&mut theme_state, scheme);
    if let Scheme::Assign(dark) = scheme {
        ui.invoke_set_color_scheme(dark);
    }

    // Wiring.
    let app = app::App::new(
        ui,
        app::Startup {
            location,
            flag: args.config_dir.clone(),
            exe: wol_core::sys::exe_path().unwrap_or_default(),
            log_file,
            store,
            loaded,
            lang_env,
            slint_backend,
            lang,
            theme: theme_state,
            tray,
            tray_failed,
        },
    );
    app::install(app.clone());
    bind::wire(&app);
    guard.spawn_waiter(|sig| {
        workers::post_ui(move |a| match sig {
            Signal::Show => {
                log::info!("show request from another instance");
                a.show_window();
            }
            Signal::Quit => {
                log::info!("quit request (quit event)");
                a.request_quit();
            }
        });
    });

    // 10. Geometry, 11. show.
    app.restore_geometry();
    let hidden = (args.tray || settings.gui.start_in_tray) && app.tray_usable();
    if hidden {
        log::info!("starting in the notification area");
    } else {
        if let Err(e) = app.ui.show() {
            drop(app);
            app::take();
            return fail(lang, e.to_string());
        }
        app.ui.invoke_focus_list();
        app.finish_geometry(40);
    }

    // 12. Timers and the event loop.
    app.start_timers();
    drop(app);
    if let Err(e) = slint::run_event_loop_until_quit() {
        log::error!("event loop: {e}");
    }

    // Shutdown.
    if let Some(app) = app::take() {
        app.shutdown();
        drop(app);
    }
    guard.stop_waiter();
    drop(guard);
    log::info!("exit");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Args {
        parse_args(v.iter().map(OsString::from))
    }

    #[test]
    fn command_line() {
        assert_eq!(args(&[]), Args::default());
        let a = args(&["--tray", "--config-dir", "C:\\x y", "--safe-mode"]);
        assert!(a.tray && a.safe_mode);
        assert_eq!(a.config_dir, Some(PathBuf::from("C:\\x y")));
        assert!(a.unknown.is_empty());
        let a = args(&["--config-dir=D:\\cfg", "--bogus"]);
        assert_eq!(a.config_dir, Some(PathBuf::from("D:\\cfg")));
        assert_eq!(a.unknown, vec!["--bogus".to_string()]);
        assert_eq!(
            args(&["--config-dir"]).unknown,
            vec!["--config-dir".to_string()]
        );
    }

    #[test]
    fn renderer_choice() {
        assert!(!wants_software_renderer(Renderer::Auto, false, ""));
        assert!(wants_software_renderer(Renderer::Software, false, ""));
        assert!(wants_software_renderer(Renderer::Auto, true, ""));
        assert!(!wants_software_renderer(
            Renderer::Software,
            true,
            "winit-femtovg"
        ));
        assert!(wants_software_renderer(Renderer::Software, false, "  "));
    }
}
