//! Per-invocation context: global flags, output language, printing helpers, store access.

use serde::Serialize;
use wol_core::Config;
use wol_core::i18n::{self, Lang, LangSetting, Msg};
use wol_core::store::{Loaded, Store};

use crate::cli::GlobalArgs;
use crate::exit::Failure;
use crate::output::{self, json, paint};
use crate::text::Text;

/// Global state of one `wolm` run.
#[derive(Debug)]
pub struct Ctx {
    /// Global flags.
    pub g: GlobalArgs,
    /// Output language.
    pub lang: Lang,
    env_lang: LangSetting,
}

impl Ctx {
    /// Language from `--lang`, then `WOL_MANAGER_LANG`, then the OS. Commands that load the
    /// settings refine it with `settings.language` (before the OS).
    pub fn new(g: GlobalArgs) -> Ctx {
        let env_lang = LangSetting::from_env().unwrap_or_default();
        let lang = i18n::resolve_lang_chain(&[g.lang.unwrap_or_default(), env_lang]);
        Ctx { g, lang, env_lang }
    }

    /// `--json`.
    pub fn json(&self) -> bool {
        self.g.json
    }

    /// `-q`.
    pub fn quiet(&self) -> bool {
        self.g.quiet
    }

    /// `-v` count.
    pub fn verbose(&self) -> u8 {
        self.g.verbose
    }

    /// Text of a wol-core message.
    pub fn t(&self, m: Msg) -> String {
        m.text(self.lang)
    }

    /// Text of a CLI message.
    pub fn tx(&self, t: Text<'_>) -> String {
        t.text(self.lang)
    }

    fn apply_settings_lang(&mut self, setting: LangSetting) {
        self.lang =
            i18n::resolve_lang_chain(&[self.g.lang.unwrap_or_default(), self.env_lang, setting]);
    }

    /// Store for `--config-dir` / env / portable / AppData. Touches nothing on disk.
    pub fn store(&self) -> Result<Store, Failure> {
        Ok(Store::open(self.g.config_dir.as_deref())?)
    }

    /// Opens and loads the settings (never creates files), applies `settings.language`
    /// and prints the load warnings.
    pub fn load(&mut self) -> Result<(Store, Loaded), Failure> {
        let (store, loaded) = self.load_silent()?;
        self.print_load_warnings(&loaded);
        Ok((store, loaded))
    }

    /// Like [`Ctx::load`] without printing warnings.
    pub fn load_silent(&mut self) -> Result<(Store, Loaded), Failure> {
        let store = self.store()?;
        let loaded = store.load()?;
        self.apply_settings_lang(loaded.config.settings.language);
        Ok((store, loaded))
    }

    /// For commands that do not need the settings: use `settings.language` when the file
    /// can be read, ignore every problem. Reads only.
    pub fn soft_lang(&mut self) {
        if self.g.lang.and_then(LangSetting::fixed).is_some() || self.env_lang.fixed().is_some() {
            return;
        }
        let Ok(store) = self.store() else { return };
        if let Ok(Some(text)) = store.read_raw()
            && let Ok((cfg, _)) = Config::from_toml(&text)
        {
            self.apply_settings_lang(cfg.settings.language);
        }
    }

    /// Prints `Msg::LoadWarning`s (stderr).
    pub fn print_load_warnings(&self, loaded: &Loaded) {
        for w in &loaded.warnings {
            self.warn(&self.t(Msg::LoadWarning(w.clone())));
        }
    }

    // ---- output ----

    /// Data line on stdout (human mode only).
    pub fn out(&self, line: &str) {
        if !self.json() {
            output::stdout_line(line);
        }
    }

    /// Progress / information on stderr (not with `-q` or `--json`).
    pub fn info(&self, line: &str) {
        if !self.quiet() && !self.json() {
            output::stderr_line(line);
        }
    }

    /// A note on stderr (not with `-q` or `--json`).
    pub fn note(&self, line: &str) {
        if !self.quiet() && !self.json() {
            let p = paint(output::NOTE, &self.tx(Text::NotePrefix));
            output::stderr_line(&format!("{p} {line}"));
        }
    }

    /// A warning on stderr (not with `-q`); with `--json` as one JSON line.
    pub fn warn(&self, line: &str) {
        if self.quiet() {
            return;
        }
        self.warn_always(line);
    }

    /// A warning that is printed even with `-q` (with `--json` as one JSON line): what a
    /// confirmation would have shown before something runs with root rights on a host, for
    /// runs that skip the question with `--yes`.
    pub fn warn_always(&self, line: &str) {
        if self.json() {
            #[derive(Serialize)]
            struct W<'a> {
                message: &'a str,
            }
            #[derive(Serialize)]
            struct Doc<'a> {
                warning: W<'a>,
            }
            output::stderr_line(&json::to_line(&Doc {
                warning: W { message: line },
            }));
        } else {
            let p = paint(output::WARNING, &self.tx(Text::WarningPrefix));
            output::stderr_line(&format!("{p} {line}"));
        }
    }

    /// The single JSON document of a `--json` run.
    pub fn print_json(&self, value: &impl Serialize) {
        output::stdout_line(&json::to_pretty(value));
    }

    /// Prints a failure on stderr (one JSON line with `--json`), with its hint.
    pub fn report(&self, f: &Failure) {
        let hint = f.hint(self.lang);
        if self.json() {
            output::stderr_line(&json::error_line_with(
                f.kind(),
                &f.message(self.lang),
                f.exit_code(),
                hint.as_deref(),
                f.host_key(),
            ));
        } else {
            let p = paint(output::ERROR, &self.tx(Text::ErrorPrefix));
            for line in f.lines(self.lang) {
                output::stderr_line(&format!("{p} {line}"));
            }
            if let Some(h) = hint {
                let p = paint(output::NOTE, &self.tx(Text::HintPrefix));
                output::stderr_line(&format!("{p} {h}"));
            }
        }
    }

    /// `true` when questions can be asked (stdin is a console).
    pub fn interactive(&self) -> bool {
        crate::prompt::stdin_is_console()
    }

    /// A line of a confirmation question on stderr: shown even with `-q` / `--json`, because
    /// the answer depends on it.
    pub fn ask_line(&self, line: &str) {
        output::stderr_line(line);
    }
}
