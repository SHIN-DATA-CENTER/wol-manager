//! `gui`: start wol-manager.exe (next to wolm.exe, or in the parent of `bin\`) without
//! waiting for it.

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::Serialize;
use wol_core::store::ConfigSource;
use wol_core::{Error, consts, instance, sys};

use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::text::Text;
use crate::util;

/// `CREATE_NEW_PROCESS_GROUP`: Ctrl+C in this console does not reach the app.
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

pub fn run(ctx: &mut Ctx) -> CmdResult {
    ctx.soft_lang();
    let exe = sys::exe_path().map_err(|e| Error::io("current_exe", None, e))?;
    let Some(gui) = sys::gui_exe_near(&exe) else {
        let dir = exe
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        return Err(Failure::NotFound(ctx.tx(Text::GuiNotFound { dir: &dir })));
    };
    let mut cmd = Command::new(&gui);
    // The app runs in its own folder, and `--config-dir` / WOL_MANAGER_CONFIG_DIR may be
    // relative to the current one: hand the folder this run resolved on as an absolute path
    // (a flag as the flag, the variable as the variable). Portable / AppData locations are
    // found by the app itself.
    let mut config_dir: Option<PathBuf> = None;
    if let Ok(store) = ctx.store() {
        let loc = store.location();
        // The app is a single instance: a running one with other settings would only show
        // its own window. Say so instead of reporting a start.
        instance::check_running_gui(&loc.dir)?;
        let abs = || std::path::absolute(&loc.dir).unwrap_or_else(|_| loc.dir.clone());
        match loc.source {
            ConfigSource::Flag => {
                let dir = abs();
                cmd.arg("--config-dir").arg(&dir);
                config_dir = Some(dir);
            }
            ConfigSource::Env => {
                let dir = abs();
                cmd.env(consts::ENV_CONFIG_DIR, &dir);
                config_dir = Some(dir);
            }
            _ => {}
        }
    }
    if let Some(lang) = ctx.g.lang.and_then(|l| l.fixed()) {
        cmd.env(consts::ENV_LANG, lang.code());
    }
    if let Some(parent) = gui.parent() {
        cmd.current_dir(parent);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NEW_PROCESS_GROUP);
    // Otherwise the app would also inherit wolm's own stdout / stderr: a caller that reads
    // them through a pipe (`$r = wolm gui --json`, `for /f`, CI logs) would wait until the
    // app exits, which can be never (notification area).
    util::keep_std_handles_from_children();
    let child = cmd
        .spawn()
        .map_err(|e| Error::io("start", gui.clone(), e))?;
    let shown = gui.display().to_string();
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc {
            path: String,
            pid: u32,
            /// Settings folder handed on (null: the app finds it itself).
            config_dir: Option<PathBuf>,
        }
        ctx.print_json(&Doc {
            path: shown,
            pid: child.id(),
            config_dir,
        });
    } else {
        ctx.info(&ctx.tx(Text::GuiStarted { path: &shown }));
    }
    Ok(exit::OK)
}
