//! `config path|show|get|set|open|validate`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use wol_core::i18n::{Header, Msg};
use wol_core::model::{ConfigIssue, KEY_INFO};
use wol_core::store::{self, ConfigSource, ReadOnlyReason};
use wol_core::{Config, Error, Settings};

use crate::cli::ConfigCmd;
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult};
use crate::output::table::{Cell, key_values};
use crate::output::{self, Table};
use crate::text::Text;

pub fn run(ctx: &mut Ctx, c: &ConfigCmd) -> CmdResult {
    match c {
        ConfigCmd::Path => path(ctx),
        ConfigCmd::Show => show(ctx),
        ConfigCmd::Get { key } => get(ctx, key.as_deref()),
        // `--clear` = "" (non-list keys refuse it with exit 2).
        ConfigCmd::Set { key, value, clear } => {
            let value = if *clear {
                ""
            } else {
                value.as_deref().unwrap_or("")
            };
            set(ctx, key, value)
        }
        ConfigCmd::Open => open(ctx),
        ConfigCmd::Validate => validate(ctx),
    }
}

fn path(ctx: &mut Ctx) -> CmdResult {
    ctx.soft_lang();
    let st = ctx.store()?;
    let loc = st.location();
    let marker_warning = loc
        .marker_path
        .as_ref()
        .filter(|_| loc.marker_ignored)
        .map(|m| {
            ctx.t(Msg::MarkerIgnored {
                marker: m.display().to_string(),
            })
        });
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc<'a> {
            config_file: String,
            dir: &'a Path,
            local_dir: &'a Path,
            source: ConfigSource,
            mode: String,
            exists: bool,
            portable_root: Option<&'a Path>,
            marker_path: Option<&'a Path>,
            marker_ignored: bool,
        }
        ctx.print_json(&Doc {
            config_file: st.config_path().display().to_string(),
            dir: &loc.dir,
            local_dir: &loc.local_dir,
            source: loc.source,
            mode: ctx.t(Msg::LocationSource(loc.source)),
            exists: st.exists(),
            portable_root: loc.portable_root.as_deref(),
            marker_path: loc.marker_path.as_deref(),
            marker_ignored: loc.marker_ignored,
        });
    } else {
        ctx.out(&st.config_path().display().to_string());
        let mut pairs = vec![(
            ctx.t(Msg::Header(Header::Source)),
            ctx.t(Msg::LocationSource(loc.source)),
        )];
        if ctx.verbose() > 0 {
            pairs.push((ctx.tx(Text::LocalData), loc.local_dir.display().to_string()));
            pairs.push((
                ctx.tx(Text::Exists),
                ctx.t(if st.exists() { Msg::Yes } else { Msg::No }),
            ));
        }
        for l in key_values(&pairs, 0) {
            ctx.info(&l);
        }
    }
    if let Some(w) = marker_warning {
        ctx.warn(&w);
    }
    Ok(exit::OK)
}

fn show(ctx: &mut Ctx) -> CmdResult {
    if ctx.json() {
        let (st, loaded) = ctx.load()?;
        #[derive(Serialize)]
        struct Doc<'a> {
            path: String,
            exists: bool,
            read_only: bool,
            config: &'a Config,
        }
        ctx.print_json(&Doc {
            path: st.config_path().display().to_string(),
            exists: loaded.exists,
            read_only: loaded.read_only,
            config: &loaded.config,
        });
        return Ok(exit::OK);
    }
    ctx.soft_lang();
    let st = ctx.store()?;
    match st.read_raw()? {
        Some(text) => output::stdout_line(text.trim_end()),
        None => {
            ctx.note(&ctx.tx(Text::ConfigMissing {
                path: &st.config_path().display().to_string(),
            }));
            output::stdout_line(Config::default().to_toml()?.trim_end());
        }
    }
    Ok(exit::OK)
}

fn get(ctx: &mut Ctx, key: Option<&str>) -> CmdResult {
    let (_st, loaded) = ctx.load()?;
    let s: &Settings = &loaded.config.settings;
    match key {
        Some(k) => {
            let value = s.get_value(k)?;
            if ctx.json() {
                #[derive(Serialize)]
                struct Doc<'a, V: Serialize> {
                    key: &'a str,
                    value: V,
                }
                ctx.print_json(&Doc {
                    key: k.trim(),
                    value,
                });
            } else {
                ctx.out(&s.get_key(k)?);
            }
        }
        None => {
            if ctx.json() {
                let mut pairs = Vec::new();
                for info in KEY_INFO {
                    let v = serde_json::to_value(s.get_value(info.key)?)
                        .unwrap_or(serde_json::Value::Null);
                    pairs.push((info.key, v));
                }
                ctx.print_json(&Ordered(pairs));
            } else {
                let h = |x| ctx.t(Msg::Header(x));
                let verbose = ctx.verbose() > 0;
                let mut headers = vec![h(Header::Key), h(Header::Value)];
                if verbose {
                    headers.push(String::new());
                }
                let mut t = Table::new(headers);
                for info in KEY_INFO {
                    let mut row = vec![
                        Cell::styled(info.key, output::BOLD),
                        Cell::plain(s.get_key(info.key)?),
                    ];
                    if verbose {
                        row.push(Cell::styled(info.expected, output::DIM));
                    }
                    t.row(row);
                }
                for l in t.lines() {
                    ctx.out(&l);
                }
            }
        }
    }
    Ok(exit::OK)
}

/// A JSON object that keeps the key order (file order of the settings).
struct Ordered(Vec<(&'static str, serde_json::Value)>);

impl Serialize for Ordered {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

fn set(ctx: &mut Ctx, key: &str, value: &str) -> CmdResult {
    let (st, _loaded) = ctx.load()?;
    let up = st.update(|c| c.settings.set_key(key, value))?;
    let now = up.config.settings.get_key(key)?;
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc<'a, V: Serialize> {
            key: &'a str,
            value: V,
            changed: bool,
        }
        ctx.print_json(&Doc {
            key: key.trim(),
            value: up.config.settings.get_value(key)?,
            changed: up.written,
        });
    } else if up.written {
        ctx.info(&format!(
            "{}: {} = {now}",
            ctx.t(Msg::ConfigSaved),
            key.trim()
        ));
    } else {
        ctx.info(&format!(
            "{}: {} = {now}",
            ctx.t(Msg::NoChanges),
            key.trim()
        ));
    }
    Ok(if up.written { exit::OK } else { exit::NEGATIVE })
}

/// Splits `VISUAL` / `EDITOR` into program and arguments ("code --wait", "\"C:\\x y\\e.exe\" -n").
fn split_command(s: &str) -> Option<(String, Vec<String>)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (prog, rest) = if let Some(stripped) = s.strip_prefix('"') {
        let end = stripped.find('"')?;
        (stripped[..end].to_owned(), &stripped[end + 1..])
    } else {
        match s.find(char::is_whitespace) {
            Some(i) => (s[..i].to_owned(), &s[i..]),
            None => (s.to_owned(), ""),
        }
    };
    Some((prog, rest.split_whitespace().map(str::to_owned).collect()))
}

fn open(ctx: &mut Ctx) -> CmdResult {
    ctx.soft_lang();
    let st = ctx.store()?;
    let file = st.config_path();
    if !st.exists() {
        // Create the default file under the settings lock (an unchanged update writes
        // nothing by itself).
        let f = file.clone();
        st.update(|_| {
            if !f.exists() {
                store::write_file_atomic(&f, Config::default().to_toml()?.as_bytes())?;
            }
            Ok(())
        })?;
        ctx.info(&ctx.tx(Text::ConfigCreated {
            path: &file.display().to_string(),
        }));
    }
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find_map(|v| split_command(&v));
    let shown = file.display().to_string();
    // Notepad (plan §6), unless VISUAL / EDITOR names an editor that can be started.
    let mut used: Option<String> = None;
    if let Some((prog, args)) = editor {
        ctx.info(&ctx.tx(Text::OpeningEditor {
            path: &shown,
            editor: &prog,
        }));
        let program = find_program(&prog).unwrap_or_else(|| PathBuf::from(&prog));
        // Terminal editors need the console: wait for them. `.cmd` / `.bat` shims (VS Code's
        // `code`) are run through cmd.exe by std, with their arguments escaped.
        match Command::new(&program).args(&args).arg(&file).status() {
            Ok(status) => {
                if !status.success() {
                    ctx.warn(&format!("{prog}: {status}"));
                }
                used = Some(program.display().to_string());
            }
            Err(e) => ctx.warn(&ctx.tx(Text::EditorFailed {
                editor: &prog,
                error: &e.to_string(),
            })),
        }
    }
    let used = match used {
        Some(u) => u,
        None => {
            ctx.info(&ctx.tx(Text::OpeningEditor {
                path: &shown,
                editor: "notepad.exe",
            }));
            // Notepad from the Windows folder: a bare "notepad.exe" is looked up in wolm's
            // own folder first. Not waited for, so it must not keep a caller's pipe open.
            let notepad = system32().join("notepad.exe");
            crate::util::keep_std_handles_from_children();
            Command::new(&notepad)
                .arg(&file)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| Error::io("start", notepad.clone(), e))?;
            notepad.display().to_string()
        }
    };
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc {
            path: String,
            editor: String,
        }
        ctx.print_json(&Doc {
            path: shown,
            editor: used,
        });
    }
    Ok(exit::OK)
}

/// `%SystemRoot%\System32`.
fn system32() -> PathBuf {
    std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
}

/// Finds a program the way cmd.exe does, so that `EDITOR=code --wait` works although VS
/// Code's `code` is `code.cmd` (`Command::new` alone only tries `.exe`). A name with a folder
/// is taken as given, else the folders of PATH are searched (not the current folder); a name
/// without a PATHEXT extension gets each PATHEXT extension in turn.
fn find_program(prog: &str) -> Option<PathBuf> {
    let exts: Vec<String> = std::env::var("PATHEXT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_owned())
        .split(';')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| e.len() > 1 && e.starts_with('.'))
        .collect();
    let p = Path::new(prog);
    let has_ext = p
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| exts.contains(&format!(".{}", e.to_ascii_lowercase())));
    let with_exts = |base: PathBuf| -> Vec<PathBuf> {
        if has_ext {
            return vec![base];
        }
        exts.iter()
            .map(|e| {
                let mut s = base.clone().into_os_string();
                s.push(e);
                PathBuf::from(s)
            })
            .collect()
    };
    let bases: Vec<PathBuf> = if prog.contains(['\\', '/', ':']) {
        vec![p.to_path_buf()]
    } else {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .filter(|d| d.is_absolute())
            .map(|d| d.join(p))
            .collect()
    };
    bases.into_iter().flat_map(with_exts).find(|c| c.is_file())
}

fn validate(ctx: &mut Ctx) -> CmdResult {
    let (st, loaded) = ctx.load_silent()?;
    let issues: Vec<ConfigIssue> = loaded.config.validate();
    let mut notes: Vec<String> = Vec::new();
    if let Some(r) = &loaded.read_only_reason {
        notes.push(ctx.t(Msg::ReadOnly(r.clone())));
    }
    let loc = st.location();
    if loc.marker_ignored
        && let Some(m) = &loc.marker_path
    {
        notes.push(ctx.t(Msg::MarkerIgnored {
            marker: m.display().to_string(),
        }));
    }
    if ctx.json() {
        #[derive(Serialize)]
        struct IssueView<'a> {
            #[serde(flatten)]
            issue: &'a ConfigIssue,
            message: String,
        }
        #[derive(Serialize)]
        struct Doc<'a> {
            path: String,
            exists: bool,
            valid: bool,
            read_only: bool,
            read_only_reason: Option<&'a ReadOnlyReason>,
            issues: Vec<IssueView<'a>>,
            notes: &'a [String],
        }
        ctx.print_json(&Doc {
            path: st.config_path().display().to_string(),
            exists: loaded.exists,
            valid: issues.is_empty(),
            read_only: loaded.read_only,
            read_only_reason: loaded.read_only_reason.as_ref(),
            issues: issues
                .iter()
                .map(|i| IssueView {
                    issue: i,
                    message: ctx.t(Msg::ConfigIssue(i.clone())),
                })
                .collect(),
            notes: &notes,
        });
    } else {
        for i in &issues {
            ctx.out(&ctx.t(Msg::ConfigIssue(i.clone())));
        }
        for n in &notes {
            ctx.warn(n);
        }
        if issues.is_empty() {
            ctx.info(&output::paint(output::GREEN, &ctx.t(Msg::ConfigValid)));
        } else {
            ctx.info(&ctx.tx(Text::Summary {
                count: issues.len(),
            }));
        }
    }
    Ok(if issues.is_empty() {
        exit::OK
    } else {
        exit::NEGATIVE
    })
}

#[cfg(test)]
mod tests {
    use super::{find_program, split_command};

    #[test]
    fn programs_are_found_with_pathext_extensions() {
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("myed.cmd");
        std::fs::write(&shim, "@echo off\r\n").unwrap();
        let base = dir.path().join("myed");
        assert_eq!(find_program(base.to_str().unwrap()), Some(shim.clone()));
        assert_eq!(find_program(shim.to_str().unwrap()), Some(shim.clone()));
        let missing = dir.path().join("missing");
        assert_eq!(find_program(missing.to_str().unwrap()), None);
        // System programs are found on PATH without an extension.
        let cmd = find_program("cmd").expect("cmd.exe on PATH");
        assert!(
            cmd.to_string_lossy()
                .to_ascii_lowercase()
                .ends_with("cmd.exe"),
            "{}",
            cmd.display()
        );
        assert_eq!(find_program("no-such-editor-4f2a"), None);
    }

    #[test]
    fn editor_commands() {
        assert_eq!(
            split_command("code --wait"),
            Some(("code".into(), vec!["--wait".into()]))
        );
        assert_eq!(
            split_command("\"C:\\Program Files\\e.exe\" -n"),
            Some(("C:\\Program Files\\e.exe".into(), vec!["-n".into()]))
        );
        assert_eq!(split_command("  "), None);
        assert_eq!(split_command("vim"), Some(("vim".into(), vec![])));
    }
}
