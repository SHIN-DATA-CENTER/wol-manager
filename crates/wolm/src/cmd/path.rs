//! `path add|remove|status`: used by the NSIS installer, so it must stay fast and
//! non-interactive, and must never load, create or lock the settings.
//!
//! Installer contract (`wolm path <action> --scope user|machine --json --lang en "<dir>"`):
//! add 0 = added / 1 = already present; remove 0 = removed / 1 = not present; status 0 = on
//! PATH / 1 = not on PATH; 2 bad arguments, or a folder every user may change for the machine
//! PATH without `--force`; 6 registry error / too long; 7 elevation required.

use std::path::PathBuf;

use serde::Serialize;
use wol_core::i18n::Msg;
use wol_core::pathenv::{self, PathChange, PathStatus, Scope};
use wol_core::sys;

use crate::cli::{PathArgs, PathCmd};
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::text::Text;

/// Tolerates what installers and shells pass: surrounding whitespace, the stray quote left
/// by `"C:\dir\"` as the LAST argument (`\"` is an escaped quote in Windows argv parsing, so
/// the argument arrives as `C:\dir"`), and a literal pair of quotes around DIR.
///
/// Any other quote is kept, so `prepare_dir` refuses it (exit 2): it means that the escaped
/// quote swallowed the following arguments (`"C:\dir\" --scope machine` arrives as the one
/// argument `C:\dir" --scope machine`), which must neither end up on PATH nor be ignored.
/// The trailing backslash is removed by wol-core.
pub fn clean_dir_arg(raw: &str) -> String {
    let t = raw.trim();
    let t = match t.strip_suffix('"') {
        Some(rest) => rest.strip_prefix('"').unwrap_or(rest),
        None => t,
    };
    t.trim().to_owned()
}

#[derive(Serialize)]
struct ChangeDoc<'a> {
    action: &'static str,
    scope: Scope,
    dir: &'a str,
    result: PathChange,
    changed: bool,
    present: bool,
}

#[derive(Serialize)]
struct StatusDoc<'a> {
    action: &'static str,
    #[serde(flatten)]
    status: &'a PathStatus,
}

pub fn run(ctx: &mut Ctx, c: &PathCmd) -> CmdResult {
    // Language: --lang, then WOL_MANAGER_LANG, then the OS. The settings are not read.
    let (action, a, force): (&'static str, &PathArgs, bool) = match c {
        PathCmd::Add(a) => ("add", &a.path, a.force),
        PathCmd::Remove(a) => ("remove", a, false),
        PathCmd::Status(a) => ("status", a, false),
    };
    let dir: PathBuf = match &a.dir {
        Some(d) => {
            let cleaned = clean_dir_arg(d);
            if cleaned.contains('"') {
                // prepare_dir refuses it below; explain the usual cause first.
                ctx.warn(&ctx.tx(Text::PathQuoteHint));
            }
            PathBuf::from(cleaned)
        }
        None => pathenv::default_dir()?,
    };
    // Validates (';' / '"' / empty → exit 2) and gives the canonical spelling.
    let shown = pathenv::prepare_dir(&dir)?;
    if a.scope == Scope::User && action != "status" && sys::is_elevated() {
        ctx.warn(&ctx.t(Msg::PathElevatedUserScope));
    }
    // A folder on PATH whose programs every user may replace: on the system PATH they would
    // run for every user, administrators included.
    if action == "add" && sys::writable_by_all_users(&dir) {
        if a.scope == Scope::Machine && !force {
            return Err(Failure::Usage(
                ctx.tx(Text::PathSharedFolderRefused { dir: &shown }),
            ));
        }
        ctx.warn(&ctx.tx(Text::PathSharedFolder { dir: &shown }));
    }
    let backend = pathenv::backend_from_env();
    match action {
        "status" => {
            let st = pathenv::status(backend.as_ref(), a.scope, &dir)?;
            if ctx.json() {
                ctx.print_json(&StatusDoc {
                    action,
                    status: &st,
                });
            } else {
                ctx.out(&ctx.t(Msg::PathStatus {
                    present: st.present,
                    dir: st.dir.clone(),
                    scope: a.scope,
                }));
            }
            Ok(if st.present { exit::OK } else { exit::NEGATIVE })
        }
        _ => {
            let change = if action == "add" {
                pathenv::add(backend.as_ref(), a.scope, &dir)?
            } else {
                pathenv::remove(backend.as_ref(), a.scope, &dir)?
            };
            if ctx.json() {
                ctx.print_json(&ChangeDoc {
                    action,
                    scope: a.scope,
                    dir: &shown,
                    result: change,
                    changed: change.changed(),
                    present: matches!(change, PathChange::Added | PathChange::AlreadyPresent),
                });
            } else {
                ctx.out(&ctx.t(Msg::PathChange {
                    change,
                    dir: shown.clone(),
                    scope: a.scope,
                }));
                if change.changed() {
                    ctx.note(&ctx.t(Msg::PathOpenNewTerminal));
                }
            }
            Ok(if change.changed() {
                exit::OK
            } else {
                exit::NEGATIVE
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::clean_dir_arg;

    #[test]
    fn quotes_and_spaces_are_tolerated() {
        assert_eq!(
            clean_dir_arg(r#"C:\Program Files\WoL Manager\bin""#),
            r"C:\Program Files\WoL Manager\bin"
        );
        assert_eq!(clean_dir_arg(r#" "D:\x\bin\" "#), r"D:\x\bin\");
        assert_eq!(clean_dir_arg(r#""D:\x""#), r"D:\x");
        assert_eq!(clean_dir_arg(r"D:\x"), r"D:\x");
    }

    #[test]
    fn a_quote_that_swallowed_later_arguments_is_kept() {
        // `"D:\x\bin\" --scope machine --json` arrives as ONE argument.
        let swallowed = r#"D:\x\bin" --scope machine --json"#;
        let cleaned = clean_dir_arg(swallowed);
        assert_eq!(cleaned, swallowed);
        assert!(wol_core::pathenv::prepare_dir(std::path::Path::new(&cleaned)).is_err());
        assert!(clean_dir_arg(r#""D:\x\bin" --scope machine""#).contains('"'));
        assert!(clean_dir_arg(r#"D:\x"y"#).contains('"'));
        assert!(clean_dir_arg(r#""D:\x"#).contains('"'));
    }
}
