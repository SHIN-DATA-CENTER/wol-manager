//! `wolm`: command-line interface of WoL Manager (plan §6).
//!
//! Data goes to stdout, progress / warnings / errors to stderr. `--json` prints exactly one
//! ASCII-only JSON document on stdout, and errors as one JSON line on stderr. Exit codes are
//! in [`exit`].

mod backend;
mod cli;
mod cmd;
mod ctrlc;
mod ctx;
mod exit;
mod output;
mod prompt;
mod text;
mod timefmt;
mod util;

use std::io::{BufRead, IsTerminal};
use std::panic::AssertUnwindSafe;
use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};
use wol_core::i18n::{self, LangSetting, Msg};

use crate::ctx::Ctx;
use crate::exit::Failure;
use crate::output::json;

fn main() -> ExitCode {
    if std::env::args_os().len() <= 1 {
        return ExitCode::from(no_arguments());
    }
    // `--no-color` must also apply to clap's own help and error output.
    let mut command = cli::Cli::command();
    if std::env::args_os().any(|a| a == "--no-color") {
        command = command.color(clap::ColorChoice::Never);
        anstream::ColorChoice::Never.write_global();
    }
    let cli = match command
        .try_get_matches()
        .and_then(|m| cli::Cli::from_arg_matches(&m))
    {
        Ok(c) => c,
        Err(e) => return ExitCode::from(clap_error(e)),
    };
    ExitCode::from(run(cli))
}

fn run(cli: cli::Cli) -> u8 {
    // Ctrl+C / closing the window: close the remote connections this process opened first.
    ctrlc::init();
    let mut ctx = Ctx::new(cli.global.clone());
    if ctx.g.no_color {
        anstream::ColorChoice::Never.write_global();
    }
    if ctx.json() {
        // The failure is reported as one JSON line below; keep stderr parseable.
        std::panic::set_hook(Box::new(|_| {}));
    }
    let result =
        std::panic::catch_unwind(AssertUnwindSafe(|| cmd::dispatch(&mut ctx, cli.command)));
    match result {
        Ok(Ok(code)) => code,
        Ok(Err(f)) => {
            ctx.report(&f);
            f.exit_code()
        }
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".to_owned());
            let f = Failure::Internal(msg);
            ctx.report(&f);
            f.exit_code()
        }
    }
}

/// `wolm` without arguments. Pauses with "Press Enter" only when it was most likely
/// double-clicked in Explorer: stdin is a console and this process is the console's only
/// process. Never in any other case (nsExec, pipes, scripts, terminals).
fn no_arguments() -> u8 {
    let lang = i18n::resolve_lang_chain(&[LangSetting::from_env().unwrap_or_default()]);
    let help = cli::Cli::command().render_help().ansi().to_string();
    let double_clicked = std::io::stdin().is_terminal() && wol_core::sys::console_is_exclusive();
    if double_clicked {
        output::stdout_line(&Msg::CliDoubleClickHint.text(lang));
        output::stdout_line("");
        output::stdout_line(help.trim_end());
        output::stdout_line("");
        output::stdout_line(&Msg::PressEnter.text(lang));
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        return exit::OK;
    }
    output::stderr_line(help.trim_end());
    exit::USAGE
}

/// clap errors: help / version exit 0, everything else is a usage error (exit 2). With
/// `--json` anywhere on the command line the error is one JSON line.
fn clap_error(e: clap::Error) -> u8 {
    use clap::error::ErrorKind as K;
    match e.kind() {
        K::DisplayHelp | K::DisplayVersion => {
            let _ = e.print();
            exit::OK
        }
        _ => {
            let wants_json = std::env::args_os().skip(1).any(|a| a == "--json");
            if wants_json {
                let message = if e.kind() == K::DisplayHelpOnMissingArgumentOrSubcommand {
                    "a subcommand or argument is missing (see --help)".to_owned()
                } else {
                    clap_message(&e.render().to_string())
                };
                output::stderr_line(&json::error_line("usage", &message, exit::USAGE));
            } else {
                let _ = e.print();
            }
            exit::USAGE
        }
    }
}

/// One-line message of a rendered clap error: its first paragraph, with the indented lines
/// under the header (the missing arguments of "the following required arguments were not
/// provided:") appended, comma separated. The usage and tips that follow are left out.
fn clap_message(rendered: &str) -> String {
    let mut lines = rendered.lines().skip_while(|l| l.trim().is_empty());
    let Some(first) = lines.next() else {
        return "usage error".to_owned();
    };
    let first = first.trim();
    let first = first.strip_prefix("error:").unwrap_or(first).trim();
    let rest: Vec<&str> = lines
        .take_while(|l| !l.trim().is_empty())
        .map(str::trim)
        .collect();
    if rest.is_empty() {
        first.to_owned()
    } else {
        format!("{first} {}", rest.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::clap_message;
    use clap::Parser;

    fn message(args: &[&str]) -> String {
        let e = crate::cli::Cli::try_parse_from(args).expect_err("a usage error");
        clap_message(&e.render().to_string())
    }

    #[test]
    fn json_usage_messages_name_the_missing_arguments() {
        assert_eq!(
            message(&["wolm", "wake", "PC1", "--timeout", "5"]),
            "the following required arguments were not provided: --wait"
        );
        let m = message(&["wolm", "show"]);
        assert!(m.ends_with("provided: <HOST>"), "{m}");
        let m = message(&["wolm", "config", "set", "wake.repeat"]);
        assert!(m.ends_with("provided: <VALUE>"), "{m}");
        let m = message(&["wolm", "add"]);
        assert!(m.ends_with("provided: <NAME>"), "{m}");
    }

    #[test]
    fn single_line_errors_stay_one_line() {
        let m = message(&["wolm", "path", "add", "--scope", "bogus"]);
        assert!(m.starts_with("invalid value 'bogus' for '--scope"), "{m}");
        assert!(!m.contains('\n') && !m.contains("Usage"), "{m}");
        let m = message(&["wolm", "frobnicate"]);
        assert!(m.starts_with("unrecognized subcommand 'frobnicate'"), "{m}");
        assert!(!m.contains("tip") && !m.contains("Usage"), "{m}");
        assert_eq!(clap_message(""), "usage error");
    }
}
