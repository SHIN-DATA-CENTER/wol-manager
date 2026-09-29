//! `portable status|enable|disable`.

use serde::Serialize;
use wol_core::i18n::Msg;
use wol_core::store::ConfigSource;
use wol_core::store::portable::{self, CopySettings, PortableStatus};
use wol_core::{Error, sys};

use crate::cli::PortableCmd;
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult};
use crate::output::table::key_values;
use crate::text::Text;

fn exe() -> Result<std::path::PathBuf, Error> {
    sys::exe_path().map_err(|e| Error::io("current_exe", None, e))
}

fn details(ctx: &Ctx, st: &PortableStatus) -> Vec<String> {
    let yn = |b: bool| ctx.t(if b { Msg::Yes } else { Msg::No });
    let mut pairs = vec![
        (ctx.tx(Text::PortableRoot), st.root.display().to_string()),
        (ctx.tx(Text::DataFolder), st.data_dir.display().to_string()),
        (
            ctx.tx(Text::Marker),
            st.marker_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".into()),
        ),
        (ctx.tx(Text::Installed), yn(st.installed)),
    ];
    if !st.installed {
        pairs.push((ctx.tx(Text::Writable), yn(st.data_writable)));
    }
    key_values(&pairs, 2)
}

fn status_line(ctx: &Ctx, st: &PortableStatus) -> String {
    if st.installed {
        ctx.t(Msg::PortableInstalled)
    } else if st.active {
        ctx.t(Msg::PortableActive {
            dir: st.data_dir.display().to_string(),
        })
    } else {
        ctx.t(Msg::PortableInactive)
    }
}

/// Portable mode is on, but `--config-dir` / `WOL_MANAGER_CONFIG_DIR` wins for this run.
fn warn_overridden(ctx: &Ctx, st: &PortableStatus) {
    if !st.active {
        return;
    }
    if let Ok(store) = ctx.store()
        && matches!(
            store.location().source,
            ConfigSource::Flag | ConfigSource::Env
        )
    {
        ctx.note(&ctx.tx(Text::PortableOverridden {
            dir: &store.location().dir.display().to_string(),
        }));
    }
}

pub fn run(ctx: &mut Ctx, c: &PortableCmd) -> CmdResult {
    ctx.soft_lang();
    let exe = exe()?;
    match c {
        PortableCmd::Status => {
            let st = portable::status(&exe);
            if ctx.json() {
                ctx.print_json(&st);
            } else {
                ctx.out(&status_line(ctx, &st));
                if ctx.verbose() > 0 {
                    for l in details(ctx, &st) {
                        ctx.out(&l);
                    }
                }
                warn_overridden(ctx, &st);
            }
            Ok(if st.active { exit::OK } else { exit::NEGATIVE })
        }
        PortableCmd::Enable { copy_settings } => {
            let before = portable::status(&exe);
            if before.installed {
                return Err(Error::InstalledCopyRefusesPortable { root: before.root }.into());
            }
            let copy = if *copy_settings {
                CopySettings::IfMissing(ctx.store()?.location().dir.clone())
            } else {
                CopySettings::No
            };
            let rep = portable::enable(&exe, copy)?;
            let changed = !before.marker_present || rep.copied;
            if ctx.json() {
                #[derive(Serialize)]
                struct Doc<'a> {
                    changed: bool,
                    #[serde(flatten)]
                    report: &'a portable::EnableReport,
                }
                ctx.print_json(&Doc {
                    changed,
                    report: &rep,
                });
            } else {
                ctx.info(&ctx.t(Msg::PortableEnabled {
                    dir: rep.status.data_dir.display().to_string(),
                }));
                if rep.copied {
                    ctx.info(&ctx.t(Msg::PortableCopied));
                }
                if rep.kept_existing {
                    ctx.info(&ctx.t(Msg::PortableKeptExisting));
                }
                // The data folder inherits the app folder's permissions (on a shared folder
                // such as C:\Tools every user could read the SecureOn passwords).
                if sys::writable_by_all_users(&rep.status.data_dir) {
                    ctx.note(&ctx.tx(Text::PortableSharedFolder {
                        dir: &rep.status.data_dir.display().to_string(),
                    }));
                }
                warn_overridden(ctx, &rep.status);
            }
            Ok(if changed { exit::OK } else { exit::NEGATIVE })
        }
        PortableCmd::Disable => {
            let removed = portable::disable(&exe)?;
            if ctx.json() {
                #[derive(Serialize)]
                struct Doc {
                    changed: bool,
                    status: PortableStatus,
                }
                ctx.print_json(&Doc {
                    changed: removed,
                    status: portable::status(&exe),
                });
            } else if removed {
                ctx.info(&ctx.t(Msg::PortableDisabled));
            } else {
                ctx.info(&ctx.t(Msg::PortableInactive));
            }
            Ok(if removed { exit::OK } else { exit::NEGATIVE })
        }
    }
}
