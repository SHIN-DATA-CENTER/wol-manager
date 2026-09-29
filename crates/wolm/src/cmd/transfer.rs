//! `export`, `import`.

use std::io::Read;
use std::path::Path;

use serde::Serialize;
use wol_core::i18n::Msg;
use wol_core::store;
use wol_core::transfer::{
    self, Format, ImportMode, ImportOptions, ImportSkip, ImportSummary, RecordError,
};
use wol_core::{Error, Host};

use crate::cli::{ExportArgs, ImportArgs};
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::output;
use crate::text::Text;

pub fn export(ctx: &mut Ctx, a: &ExportArgs) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let format = a
        .format
        .or_else(|| a.output.as_deref().and_then(Format::from_path))
        .unwrap_or(if ctx.json() && a.output.is_none() {
            Format::Json
        } else {
            Format::Toml
        });
    let hosts: Vec<&Host> = match &a.group {
        Some(g) => {
            let v = cfg.hosts_in_group(g);
            if v.is_empty() {
                return Err(Error::GroupNotFound(g.clone()).into());
            }
            v
        }
        None => cfg.hosts.iter().collect(),
    };
    let settings = (a.include_settings && format != Format::Csv).then_some(&cfg.settings);
    let bytes = transfer::export_hosts(&hosts, settings, format)?;
    let has_secureon = hosts.iter().any(|h| h.secureon.is_some());
    match &a.output {
        Some(path) => {
            // The user's file: errors name it (not the settings folder), and an existing
            // "<name>.tmp" next to it is left alone.
            store::write_output_file(path, &bytes)?;
            let shown = std::path::absolute(path).unwrap_or_else(|_| path.clone());
            if ctx.json() {
                #[derive(Serialize)]
                struct Doc {
                    path: String,
                    format: Format,
                    count: usize,
                    bytes: usize,
                }
                ctx.print_json(&Doc {
                    path: shown.display().to_string(),
                    format,
                    count: hosts.len(),
                    bytes: bytes.len(),
                });
            } else {
                ctx.info(&ctx.t(Msg::Exported {
                    count: hosts.len(),
                    path: shown.display().to_string(),
                }));
            }
        }
        // `--json` promises ASCII-only JSON on stdout: escape the (UTF-8) export.
        None if ctx.json() && format == Format::Json => {
            let text = String::from_utf8_lossy(&bytes);
            output::stdout_bytes(output::json::escape_non_ascii(&text).as_bytes());
        }
        // TOML / CSV under `--json`: wrapped in a JSON document (like `completions --json`).
        // The CSV byte order mark belongs to files, not to the text.
        None if ctx.json() => {
            let text = String::from_utf8_lossy(&bytes);
            #[derive(Serialize)]
            struct Doc<'a> {
                format: Format,
                count: usize,
                content: &'a str,
            }
            ctx.print_json(&Doc {
                format,
                count: hosts.len(),
                content: text.strip_prefix('\u{feff}').unwrap_or(&text),
            });
        }
        None => output::stdout_bytes(&bytes),
    }
    if has_secureon {
        ctx.note(&ctx.tx(Text::SecureOnExported));
    }
    Ok(exit::OK)
}

fn record_error_text(ctx: &Ctx, e: &RecordError) -> String {
    match e {
        RecordError::Fields { name, errors } => {
            let list: Vec<String> = errors
                .iter()
                .map(|fe| ctx.t(Msg::FieldError(*fe)))
                .collect();
            match name {
                Some(n) => format!("{n}: {}", list.join(", ")),
                None => list.join(", "),
            }
        }
        RecordError::Malformed { message } => message.clone(),
    }
}

/// A record location from wol-core (`row 3`, `hosts[2]`) in the output language.
fn location_text(ctx: &Ctx, location: &str) -> String {
    match location.strip_prefix("row ") {
        Some(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            ctx.tx(Text::Row { n })
        }
        _ => location.to_owned(),
    }
}

/// An invalid record without `--skip-invalid` (exit 2), in the output language.
fn invalid_record(ctx: &Ctx, location: &str, e: &RecordError) -> Failure {
    Error::Import {
        location: Some(location_text(ctx, location)),
        message: record_error_text(ctx, e),
    }
    .into()
}

#[derive(Serialize)]
struct ImportDoc<'a> {
    dry_run: bool,
    written: bool,
    #[serde(flatten)]
    summary: &'a ImportSummary,
}

fn print_summary(ctx: &Ctx, s: &ImportSummary) {
    for n in &s.added {
        ctx.out(&output::paint(output::GREEN, &format!("+ {n}")));
    }
    for n in &s.updated {
        ctx.out(&output::paint(output::YELLOW, &format!("~ {n}")));
    }
    for n in &s.removed {
        ctx.out(&output::paint(output::RED, &format!("- {n}")));
    }
    for sk in &s.skipped {
        ctx.warn(&ctx.tx(Text::ImportSkipped {
            location: &location_text(ctx, &sk.location),
            reason: &record_error_text(ctx, &sk.error),
        }));
    }
    for w in &s.warnings {
        ctx.warn(w);
    }
    let mut line = ctx.t(Msg::ImportSummary {
        added: s.added.len(),
        updated: s.updated.len(),
        skipped: s.skipped.len(),
        removed: s.removed.len(),
    });
    if !s.unchanged.is_empty() {
        line = format!(
            "{line} / {}",
            ctx.tx(Text::ImportUnchanged {
                count: s.unchanged.len()
            })
        );
    }
    ctx.info(&line);
}

pub fn import(ctx: &mut Ctx, a: &ImportArgs) -> CmdResult {
    let from_stdin = a.file.as_os_str() == "-";
    let bytes = if from_stdin {
        let mut b = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut b)
            .map_err(|e| Error::io("read", None, e))?;
        b
    } else {
        std::fs::read(&a.file).map_err(|e| Error::io("read", a.file.clone(), e))?
    };
    let path: Option<&Path> = (!from_stdin).then_some(a.file.as_path());
    // wol-core stops at the first invalid record with an English message. Skip in wol-core
    // and refuse here instead, in the output language, before anything is written.
    let opts = ImportOptions {
        mode: if a.replace {
            ImportMode::Replace
        } else {
            ImportMode::Merge
        },
        format: a.format,
        skip_invalid: true,
        include_settings: a.include_settings,
    };
    let (store, loaded) = ctx.load()?;
    let data = transfer::parse_import(&bytes, a.format, path)?;
    if !a.skip_invalid
        && let Some((location, e)) = data
            .records
            .iter()
            .find_map(|r| r.host.as_ref().err().map(|e| (&r.location, e)))
    {
        return Err(invalid_record(ctx, location, e));
    }
    if a.dry_run {
        let mut preview = loaded.config.clone();
        let summary = transfer::apply_import(&mut preview, &data, &opts)?;
        if !a.skip_invalid
            && let Some(sk) = summary.skipped.first()
        {
            return Err(invalid_record(ctx, &sk.location, &sk.error));
        }
        // The same check as the real import: the result must be a readable config.toml.
        if preview != loaded.config {
            preview.to_toml_checked()?;
        }
        if ctx.json() {
            ctx.print_json(&ImportDoc {
                dry_run: true,
                written: false,
                summary: &summary,
            });
        } else {
            print_summary(ctx, &summary);
            ctx.info(&ctx.t(Msg::ImportDryRun));
        }
        return Ok(exit::OK);
    }
    // Records can also be refused while they are applied (a name used twice).
    let mut refused: Option<ImportSkip> = None;
    let result = store.update(|c| {
        let summary = transfer::apply_import(c, &data, &opts)?;
        if !a.skip_invalid
            && let Some(sk) = summary.skipped.first()
        {
            refused = Some(sk.clone());
            // Aborts the update: nothing is written.
            return Err(Error::Import {
                location: Some(sk.location.clone()),
                message: sk.error.to_string(),
            });
        }
        Ok(summary)
    });
    let up = match (result, refused) {
        (Ok(up), _) => up,
        (Err(_), Some(sk)) => return Err(invalid_record(ctx, &sk.location, &sk.error)),
        (Err(e), None) => return Err(e.into()),
    };
    if ctx.json() {
        ctx.print_json(&ImportDoc {
            dry_run: false,
            written: up.written,
            summary: &up.value,
        });
    } else {
        print_summary(ctx, &up.value);
        if !up.written {
            ctx.info(&ctx.t(Msg::NoChanges));
        }
    }
    Ok(if up.written { exit::OK } else { exit::NEGATIVE })
}
